use super::*;

pub(super) const MAX_ENVELOPE_BYTES: usize = 1_400_000;
const MAX_PARENTS: usize = 32;
pub(super) const MAX_VAULT_BYTES: u64 = 256 * 1024 * 1024;
pub const CREATE_GENERATION: &str = "
    CREATE TABLE IF NOT EXISTS sync_generation (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
        value TEXT NOT NULL CHECK(length(value)=32)
    );
    INSERT OR IGNORE INTO sync_generation VALUES(1,lower(hex(randomblob(16))));";

pub(super) fn create_schema(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(
        "CREATE TABLE revisions (
            seq INTEGER PRIMARY KEY,
            vault TEXT NOT NULL REFERENCES owner(vault),
            object TEXT NOT NULL,
            revision TEXT NOT NULL,
            mutation TEXT NOT NULL,
            envelope TEXT NOT NULL,
            UNIQUE(vault, revision),
            UNIQUE(vault, mutation)
        );
        CREATE INDEX revision_feed ON revisions(vault, seq);
        CREATE TABLE revision_heads (
            vault TEXT NOT NULL,
            object TEXT NOT NULL,
            revision TEXT NOT NULL,
            PRIMARY KEY(vault, object, revision),
            FOREIGN KEY(vault, revision) REFERENCES revisions(vault, revision)
        );
        PRAGMA user_version=2;",
    )
}

pub(super) fn routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/mutations",
            post(mutate).layer(DefaultBodyLimit::max(MAX_ENVELOPE_BYTES + 4096)),
        )
        .route_layer(middleware::from_fn_with_state(state, writes::guard))
        .route("/api/v1/changes", post(changes))
}

#[derive(Deserialize, serde::Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Mutation {
    version: u32,
    epoch: u32,
    object_id: Uuid,
    revision_id: Uuid,
    mutation_id: Uuid,
    parents: Vec<Uuid>,
    envelope: String,
}

impl Mutation {
    pub(super) fn is_rekey_of(&self, old: &Self, epoch: u32) -> bool {
        self.version == 1 && self.epoch == epoch
            && self.object_id == old.object_id && self.revision_id == old.revision_id
            && self.mutation_id == old.mutation_id && self.parents == old.parents
            && self.envelope != old.envelope && self.envelope.len() <= MAX_ENVELOPE_BYTES
            && STANDARD.decode(&self.envelope).is_ok_and(|data| data.len() >= 144)
    }
}

fn conflict() -> ApiError {
    ApiError(StatusCode::CONFLICT, "revision_conflict")
}

async fn mutate(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<Mutation>, JsonRejection>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let presented = zeroize::Zeroizing::new(credential(&headers, Method::POST)?);
    let Json(body) = body.map_err(|error| ApiError(error.status(), "invalid_request"))?;
    if body.version != 1
        || body.epoch == 0
        || [body.object_id, body.revision_id, body.mutation_id].iter().any(Uuid::is_nil)
        || body.parents.len() > MAX_PARENTS
        || body.parents.iter().enumerate().any(|(i, p)| p.is_nil() || *p == body.revision_id || body.parents[..i].contains(p))
        || body.envelope.len() > MAX_ENVELOPE_BYTES
        || STANDARD.decode(&body.envelope).map_err(|_| ApiError::bad())?.len() < 16
    {
        return Err(ApiError::bad());
    }
    let envelope = serde_json::to_string(&body).map_err(|_| ApiError::internal())?;
    let object = body.object_id.to_string();
    let revision = body.revision_id.to_string();
    let mutation = body.mutation_id.to_string();
    let time = (state.clock)();
    state.database(move |db| {
        let tx = db.transaction()?;
        let auth = authorize(&tx, &presented, time)?;
        if body.epoch != auth.epoch {
            return Err(ApiError(StatusCode::CONFLICT, "vault_epoch_changed"));
        }
        let existing: Option<(i64, String)> = tx.query_row(
            "SELECT seq,envelope FROM revisions WHERE vault=?1 AND mutation=?2",
            params![auth.vault, mutation], |r| Ok((r.get(0)?, r.get(1)?)),
        ).optional()?;
        if let Some((seq, stored)) = existing {
            if stored != envelope {
                return Err(conflict());
            }
            return Ok(Json(json!({"cursor":seq.to_string()})));
        }
        let reused: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM revisions WHERE vault=?1 AND revision=?2)",
            params![auth.vault, revision], |r| r.get(0),
        )?;
        if reused {
            return Err(conflict());
        }
        for parent in &body.parents {
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM revisions WHERE vault=?1 AND object=?2 AND revision=?3)",
                params![auth.vault, object, parent.to_string()], |r| r.get(0),
            )?;
            if !exists {
                return Err(conflict());
            }
        }
        let bytes: u64 = tx.query_row(
            "SELECT COALESCE(sum(length(envelope)),0) FROM revisions WHERE vault=?1",
            [&auth.vault], |r| r.get(0),
        )?;
        if bytes.saturating_add(envelope.len() as u64) > MAX_VAULT_BYTES {
            return Err(ApiError(StatusCode::INSUFFICIENT_STORAGE, "vault_quota"));
        }
        tx.execute(
            "INSERT INTO revisions(vault,object,revision,mutation,envelope) VALUES(?1,?2,?3,?4,?5)",
            params![auth.vault, object, revision, mutation, envelope],
        )?;
        let seq = tx.last_insert_rowid();
        for parent in body.parents {
            tx.execute(
                "DELETE FROM revision_heads WHERE vault=?1 AND object=?2 AND revision=?3",
                params![auth.vault, object, parent.to_string()],
            )?;
        }
        tx.execute(
            "INSERT INTO revision_heads VALUES(?1,?2,?3)",
            params![auth.vault, object, revision],
        )?;
        tx.commit()?;
        Ok(Json(json!({"cursor":seq.to_string()})))
    }).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FeedRequest {
    cursor: Option<String>,
    generation: Option<String>,
}

async fn changes(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<FeedRequest>, JsonRejection>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let presented = zeroize::Zeroizing::new(credential(&headers, Method::POST)?);
    let Json(body) = body.map_err(|error| ApiError(error.status(), "invalid_request"))?;
    let mut cursor = match body.cursor {
        Some(value) => value.parse::<i64>().ok().filter(|c| *c >= 0 && c.to_string() == value).ok_or_else(ApiError::bad)?,
        None => 0,
    };
    let time = (state.clock)();
    state.database(move |db| {
        let tx = db.transaction()?;
        let auth = authorize(&tx, &presented, time)?;
        let generation: String = tx.query_row(
            "SELECT value FROM sync_generation WHERE singleton=1", [], |row| row.get(0),
        )?;
        if body.generation.as_ref().is_some_and(|value| value != &generation) {
            return Err(ApiError(StatusCode::CONFLICT, "sync_generation_changed"));
        }
        let latest: i64 = tx.query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM revisions WHERE vault=?1",
            [&auth.vault], |row| row.get(0),
        )?;
        if cursor > latest {
            return Err(ApiError(StatusCode::CONFLICT, "sync_cursor_ahead"));
        }
        let mut stmt = tx.prepare(
            "SELECT seq,envelope FROM revisions WHERE vault=?1 AND seq>?2 ORDER BY seq LIMIT 9",
        )?;
        let mut rows = stmt.query(params![auth.vault, cursor])?;
        let mut revisions = Vec::with_capacity(8);
        let mut more = false;
        while let Some(row) = rows.next()? {
            if revisions.len() == 8 {
                more = true;
                break;
            }
            let envelope: String = row.get(1)?;
            revisions.push(serde_json::from_str::<Mutation>(&envelope).map_err(|_| ApiError::internal())?);
            cursor = row.get(0)?;
        }
        Ok(Json(json!({"cursor":cursor.to_string(),"generation":generation,"revisions":revisions,"more":more})))
    }).await
}
