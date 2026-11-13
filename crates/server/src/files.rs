use super::*;
use axum::{body::Bytes, extract::Path as RoutePath};
use std::{fs, io::Write};

const CHUNK: u64 = 1_048_576;
const OVERHEAD: u64 = 17;
const MAX_FILE: u64 = 100_000_000;
const MAX_TOTAL: u64 = 1024 * 1024 * 1024;
const MAX_FILES: u64 = 1024;
const RESERVATION_SECONDS: u64 = 60 * 60;

pub fn epoch_blobs(base: &Path, epoch: u32) -> PathBuf {
    if epoch == 1 { base.to_path_buf() } else { base.join(format!("epoch-{epoch}")) }
}

pub(super) fn create_schema(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(
        "CREATE TABLE files (
            vault TEXT NOT NULL REFERENCES owner(vault),
            object TEXT NOT NULL,
            revision TEXT NOT NULL,
            size INTEGER NOT NULL,
            manifest TEXT NOT NULL,
            published INTEGER UNIQUE,
            PRIMARY KEY(vault, object)
        );
        PRAGMA user_version=3;",
    )
}

pub(super) fn add_reservations(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(
        "CREATE TABLE attachment_reservations (
            vault TEXT NOT NULL, object TEXT NOT NULL, expires INTEGER NOT NULL,
            PRIMARY KEY(vault,object),
            FOREIGN KEY(vault,object) REFERENCES files(vault,object) ON DELETE CASCADE
        );
        PRAGMA user_version=5;",
    )
}

pub(super) fn add_deletions(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch("CREATE TABLE attachment_deletions (
        vault TEXT NOT NULL REFERENCES owner(vault), object TEXT NOT NULL, revision TEXT NOT NULL,
        epoch INTEGER NOT NULL, proof TEXT NOT NULL, PRIMARY KEY(vault,object));
        PRAGMA user_version=7;")
}

fn prune_expired(db: &Connection, blobs: &Path, vault: &str, epoch: u32, time: u64) -> Result<(), ApiError> {
    let mut statement = db.prepare(
        "SELECT f.object FROM files f LEFT JOIN attachment_reservations r
         ON r.vault=f.vault AND r.object=f.object
         WHERE f.vault=?1 AND f.published IS NULL AND (r.expires IS NULL OR r.expires<=?2)",
    )?;
    let expired = statement.query_map(params![vault, time], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for object in expired {
        if !Uuid::parse_str(&object).is_ok_and(|id| id.to_string() == object) {
            return Err(ApiError::internal());
        }
        let path = epoch_blobs(blobs, epoch).join(&object);
        match fs::remove_dir_all(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(error)),
        }
        db.execute("DELETE FROM files WHERE vault=?1 AND object=?2", params![vault, object])?;
    }
    Ok(())
}

pub(super) fn routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/api/v1/files", post(begin))
        .route("/api/v1/files/{object}/finish", post(finish))
        .route("/api/v1/files/{object}/delete", post(delete_file))
        .route("/api/v1/files/{object}/chunks/{index}", post(upload)
            .layer(DefaultBodyLimit::max((CHUNK + OVERHEAD) as usize)))
        .route_layer(middleware::from_fn_with_state(state, writes::guard))
        .route("/api/v1/files/list", post(list))
        .route("/api/v1/files/deleted", post(list_deleted))
        .route("/api/v1/files/{object}/read/{index}", post(download))
}

#[derive(Deserialize, serde::Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    object_id: Uuid,
    revision_id: Uuid,
    size: u64,
    manifest: String,
    #[serde(default = "initial_epoch")]
    epoch: u32,
}

fn initial_epoch() -> u32 { 1 }
pub(super) fn count(size: u64) -> u64 { size.div_ceil(CHUNK).max(1) }
fn encrypted_size(size: u64, index: u64) -> Result<u64, ApiError> {
    if index >= count(size) { return Err(ApiError::bad()); }
    Ok((size - index * CHUNK).min(CHUNK) + OVERHEAD)
}
fn file_error() -> ApiError { ApiError(StatusCode::CONFLICT, "attachment_conflict") }
fn io_error(_: std::io::Error) -> ApiError { ApiError::internal() }

async fn begin(
    State(state): State<AppState>, headers: HeaderMap,
    body: Result<Json<Manifest>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let presented = zeroize::Zeroizing::new(credential(&headers, Method::POST)?);
    let Json(body) = body.map_err(|error| ApiError(error.status(), "invalid_request"))?;
    if body.object_id.is_nil() || body.revision_id.is_nil() || body.size > MAX_FILE
        || body.manifest.len() > 8192
        || STANDARD.decode(&body.manifest).map_err(|_| ApiError::bad())?.len() < 40
    { return Err(ApiError::bad()); }
    let time = (state.clock)();
    let blobs = state.blobs.clone();
    state.database(move |db| {
        let cleanup = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let auth = authorize(&cleanup, &presented, time)?;
        if body.epoch != auth.epoch {
            return Err(ApiError(StatusCode::CONFLICT, "vault_epoch_changed"));
        }
        prune_expired(&cleanup, &blobs, &auth.vault, auth.epoch, time)?;
        cleanup.commit()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let auth = authorize(&tx, &presented, time)?;
        if body.epoch != auth.epoch {
            return Err(ApiError(StatusCode::CONFLICT, "vault_epoch_changed"));
        }
        let object = body.object_id.to_string();
        if tx.query_row("SELECT 1 FROM attachment_deletions WHERE vault=?1 AND object=?2",
            params![auth.vault, object], |_| Ok(())).optional()?.is_some() {
            return Err(file_error());
        }
        let old: Option<(String, u64, String)> = tx.query_row(
            "SELECT revision,size,manifest FROM files WHERE vault=?1 AND object=?2",
            params![auth.vault, object], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).optional()?;
        let revision = body.revision_id.to_string();
        if let Some(old) = old {
            if old != (revision, body.size, body.manifest) { return Err(file_error()); }
            return Ok(StatusCode::NO_CONTENT);
        }
        let (files, bytes): (u64, u64) = tx.query_row(
            "SELECT count(*),COALESCE(sum(size),0) FROM files WHERE vault=?1",
            [&auth.vault], |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if files >= MAX_FILES || bytes + body.size > MAX_TOTAL {
            return Err(ApiError(StatusCode::INSUFFICIENT_STORAGE, "attachment_quota"));
        }
        tx.execute("INSERT INTO files VALUES(?1,?2,?3,?4,?5,NULL)",
            params![auth.vault, object, revision, body.size, body.manifest])?;
        tx.execute("INSERT INTO attachment_reservations VALUES(?1,?2,?3)",
            params![auth.vault, object, time.saturating_add(RESERVATION_SECONDS)])?;
        tx.commit()?;
        Ok(StatusCode::CREATED)
    }).await
}

fn lookup(db: &Connection, vault: &str, object: Uuid, time: u64) -> Result<(u64, bool), ApiError> {
    db.query_row("SELECT size,published IS NOT NULL FROM files f WHERE vault=?1 AND object=?2
        AND (published IS NOT NULL OR EXISTS(SELECT 1 FROM attachment_reservations r
            WHERE r.vault=f.vault AND r.object=f.object AND r.expires>?3))",
        params![vault, object.to_string(), time], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?.ok_or(ApiError(StatusCode::NOT_FOUND, "attachment_missing"))
}

async fn upload(
    State(state): State<AppState>, headers: HeaderMap,
    RoutePath((object, index)): RoutePath<(Uuid, u64)>, bytes: Bytes,
) -> Result<StatusCode, ApiError> {
    let presented = zeroize::Zeroizing::new(credential(&headers, Method::POST)?);
    let time = (state.clock)();
    let blobs = state.blobs.clone();
    state.database(move |db| {
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let auth = authorize(&tx, &presented, time)?;
        let (size, published) = lookup(&tx, &auth.vault, object, time)?;
        if bytes.len() as u64 != encrypted_size(size, index)? { return Err(ApiError::bad()); }
        let dir = epoch_blobs(&blobs, auth.epoch).join(object.to_string());
        let path = dir.join(index.to_string());
        match fs::read(&path) {
            Ok(existing) => return if existing.as_slice() == bytes.as_ref() { Ok(StatusCode::NO_CONTENT) } else { Err(file_error()) },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(error) => return Err(io_error(error)),
        }
        if published { return Err(file_error()); }
        fs::create_dir_all(&dir).map_err(io_error)?;
        let temp = dir.join("upload.tmp");
        let result = (|| -> std::io::Result<()> {
            let mut file = fs::File::create(&temp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temp, &path)?;
            #[cfg(unix)]
            {
                fs::File::open(&dir)?.sync_all()?;
                fs::File::open(epoch_blobs(&blobs, auth.epoch))?.sync_all()?;
                fs::File::open(blobs.as_ref())?.sync_all()?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            let _ = fs::remove_file(temp);
            return Err(io_error(error));
        }
        tx.execute("UPDATE attachment_reservations SET expires=?3 WHERE vault=?1 AND object=?2",
            params![auth.vault, object.to_string(), time.saturating_add(RESERVATION_SECONDS)])?;
        tx.commit()?;
        Ok(StatusCode::CREATED)
    }).await
}

async fn finish(
    State(state): State<AppState>, headers: HeaderMap, RoutePath(object): RoutePath<Uuid>,
) -> Result<StatusCode, ApiError> {
    let presented = zeroize::Zeroizing::new(credential(&headers, Method::POST)?);
    let time = (state.clock)();
    let blobs = state.blobs.clone();
    state.database(move |db| {
        let tx = db.transaction()?;
        let auth = authorize(&tx, &presented, time)?;
        let (size, published) = lookup(&tx, &auth.vault, object, time)?;
        if published { return Ok(StatusCode::NO_CONTENT); }
        let dir = epoch_blobs(&blobs, auth.epoch).join(object.to_string());
        for index in 0..count(size) {
            let path = dir.join(index.to_string());
            if fs::metadata(path).map(|m| m.len()).ok() != Some(encrypted_size(size, index)?) {
                return Err(ApiError(StatusCode::CONFLICT, "attachment_incomplete"));
            }
        }
        tx.execute("UPDATE files SET published=(SELECT COALESCE(MAX(published),0)+1 FROM files) WHERE vault=?1 AND object=?2",
            params![auth.vault, object.to_string()])?;
        tx.execute("DELETE FROM attachment_reservations WHERE vault=?1 AND object=?2",
            params![auth.vault, object.to_string()])?;
        tx.commit()?;
        Ok(StatusCode::NO_CONTENT)
    }).await
}

async fn list(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<Vec<Manifest>>, ApiError> {
    let presented = zeroize::Zeroizing::new(credential(&headers, Method::POST)?);
    let time = (state.clock)();
    state.database(move |db| {
        let tx = db.transaction()?;
        let auth = authorize(&tx, &presented, time)?;
        let mut stmt = tx.prepare("SELECT object,revision,size,manifest FROM files WHERE vault=?1 AND published IS NOT NULL ORDER BY published")?;
        let rows = stmt.query_map([auth.vault], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get(2)?, r.get(3)?)))?;
        let mut entries = Vec::new();
        for row in rows {
            let (object, revision, size, manifest) = row?;
            entries.push(Manifest {
                object_id: Uuid::parse_str(&object).map_err(|_| ApiError::internal())?,
                revision_id: Uuid::parse_str(&revision).map_err(|_| ApiError::internal())?,
                size, manifest, epoch: auth.epoch,
            });
        }
        Ok(Json(entries))
    }).await
}

#[derive(Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Deletion {
    object_id: Uuid,
    revision_id: Uuid,
    epoch: u32,
    proof: String,
}

async fn delete_file(
    State(state): State<AppState>, headers: HeaderMap, RoutePath(object): RoutePath<Uuid>,
    body: Result<Json<Deletion>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let presented = zeroize::Zeroizing::new(credential(&headers, Method::POST)?);
    let Json(body) = body.map_err(|error| ApiError(error.status(), "invalid_request"))?;
    if object.is_nil() || object != body.object_id || body.revision_id.is_nil() || body.proof.len() != 44
        || STANDARD.decode(&body.proof).map_err(|_| ApiError::bad())?.len() != 32 {
        return Err(ApiError::bad());
    }
    let time = (state.clock)();
    let blobs = state.blobs.clone();
    state.database(move |db| {
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let auth = authorize(&tx, &presented, time)?;
        if body.epoch != auth.epoch { return Err(file_error()); }
        let object = object.to_string();
        let revision = body.revision_id.to_string();
        let existing = tx.query_row("SELECT revision,epoch,proof FROM attachment_deletions WHERE vault=?1 AND object=?2",
            params![auth.vault, object], |r| Ok((r.get::<_, String>(0)?, r.get::<_, u32>(1)?, r.get::<_, String>(2)?))).optional()?;
        if let Some(prior) = existing {
            if prior != (revision, body.epoch, body.proof) { return Err(file_error()); }
        } else {
            let current = tx.query_row("SELECT revision FROM files WHERE vault=?1 AND object=?2",
                params![auth.vault, object], |r| r.get::<_, String>(0)).optional()?;
            match current {
                None => return Err(ApiError(StatusCode::NOT_FOUND, "attachment_missing")),
                Some(current) if current != revision => return Err(file_error()),
                Some(_) => {}
            }
            tx.execute("INSERT INTO attachment_deletions VALUES(?1,?2,?3,?4,?5)",
                params![auth.vault, object, revision, body.epoch, body.proof])?;
            tx.execute("DELETE FROM files WHERE vault=?1 AND object=?2", params![auth.vault, object])?;
        }
        tx.commit()?;
        // Metadata commits first: the file stays inaccessible if disk cleanup must be retried.
        match fs::remove_dir_all(epoch_blobs(&blobs, auth.epoch).join(object)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(error)),
        }
        Ok(StatusCode::NO_CONTENT)
    }).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeletionQuery { object_ids: Vec<Uuid> }

async fn list_deleted(
    State(state): State<AppState>, headers: HeaderMap, body: Result<Json<DeletionQuery>, JsonRejection>,
) -> Result<Json<Vec<Deletion>>, ApiError> {
    let presented = zeroize::Zeroizing::new(credential(&headers, Method::POST)?);
    let Json(body) = body.map_err(|error| ApiError(error.status(), "invalid_request"))?;
    if body.object_ids.len() > MAX_FILES as usize { return Err(ApiError::bad()); }
    let time = (state.clock)();
    state.database(move |db| {
        let auth = authorize(db, &presented, time)?;
        let mut query = db.prepare("SELECT revision,epoch,proof FROM attachment_deletions WHERE vault=?1 AND object=?2")?;
        let mut entries = Vec::new();
        for object_id in body.object_ids {
            if let Some((revision, epoch, proof)) = query.query_row(params![auth.vault, object_id.to_string()],
                |r| Ok((r.get::<_, String>(0)?, r.get(1)?, r.get(2)?))).optional()? {
                entries.push(Deletion { object_id, revision_id: Uuid::parse_str(&revision).map_err(|_| ApiError::internal())?, epoch, proof });
            }
        }
        Ok(Json(entries))
    }).await
}

async fn download(
    State(state): State<AppState>, headers: HeaderMap, RoutePath((object, index)): RoutePath<(Uuid, u64)>,
) -> Result<Bytes, ApiError> {
    let presented = zeroize::Zeroizing::new(credential(&headers, Method::POST)?);
    let time = (state.clock)();
    let blobs = state.blobs.clone();
    state.database(move |db| {
        let tx = db.transaction()?;
        let auth = authorize(&tx, &presented, time)?;
        let (size, published) = lookup(&tx, &auth.vault, object, time)?;
        if !published { return Err(ApiError(StatusCode::NOT_FOUND, "attachment_missing")); }
        let expected = encrypted_size(size, index)?;
        let bytes = fs::read(epoch_blobs(&blobs, auth.epoch).join(object.to_string()).join(index.to_string())).map_err(io_error)?;
        if bytes.len() as u64 != expected { return Err(ApiError::internal()); }
        Ok(Bytes::from(bytes))
    }).await
}
