use super::*;
use axum::extract::Path as RoutePath;

const REFRESH_SECONDS: u64 = 30 * 24 * 60 * 60;
const MAX_DEVICES: u32 = 32;
const MAX_RETAINED_REFRESHES: u32 = 100_000;

pub(super) fn add_schema(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch("CREATE TABLE sync_devices (
        id TEXT PRIMARY KEY, vault TEXT NOT NULL REFERENCES owner(vault),
        epoch INTEGER NOT NULL, issued INTEGER NOT NULL, expires INTEGER NOT NULL,
        verifier BLOB NOT NULL CHECK(length(verifier)=32));
      CREATE TABLE used_sync_refreshes (
        verifier BLOB PRIMARY KEY CHECK(length(verifier)=32),
        device TEXT NOT NULL REFERENCES sync_devices(id) ON DELETE CASCADE);
      CREATE INDEX used_sync_refreshes_device ON used_sync_refreshes(device);
      ALTER TABLE sessions ADD COLUMN device TEXT REFERENCES sync_devices(id) ON DELETE CASCADE;
      CREATE INDEX sessions_device ON sessions(device);
      PRAGMA user_version=8;")
}

pub(super) fn clear(db: &Connection) -> rusqlite::Result<()> {
    // Restore and rotation also accept pre-device-sync databases.
    if db.pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))? >= 8 {
        db.execute("DELETE FROM used_sync_refreshes", [])?;
        db.execute("DELETE FROM sync_devices", [])?;
    }
    Ok(())
}

pub(super) fn revoke_on_disk(directory: &Path, device: Uuid) -> rusqlite::Result<bool> {
    let db = Connection::open_with_flags(directory.join("vault.sqlite3"), rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    db.busy_timeout(Duration::from_secs(5))?;
    db.pragma_update(None, "foreign_keys", "ON")?;
    Ok(db.execute("DELETE FROM sync_devices WHERE id=?1", [device.to_string()])? == 1)
}

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/sync-devices/{device}", post(enroll).delete(revoke))
        .route("/api/v1/sync-devices/{device}/refresh", post(refresh))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Vault {
    vault_id: Uuid,
    key_epoch: u32,
}

fn windows_bearer(headers: &HeaderMap) -> Result<zeroize::Zeroizing<String>, ApiError> {
    if headers.get(header::ORIGIN).is_some_and(|origin| origin != DESKTOP_ORIGIN)
        || headers.contains_key(header::COOKIE) {
        return Err(ApiError::forbidden());
    }
    Ok(zeroize::Zeroizing::new(bearer(headers)?))
}

async fn enroll(State(state): State<AppState>, RoutePath(device): RoutePath<Uuid>, headers: HeaderMap,
    body: Result<Json<Vault>, JsonRejection>) -> Result<Json<serde_json::Value>, ApiError> {
    let presented = windows_bearer(&headers)?;
    let Json(vault) = body.map_err(|error| ApiError(error.status(), "invalid_request"))?;
    let time = (state.clock)();
    let expires = time.checked_add(REFRESH_SECONDS).ok_or_else(ApiError::internal)?;
    let token = SecretToken::generate().map_err(|_| ApiError::internal())?;
    let verifier = token.verifier(vault.vault_id.into_bytes(), Purpose::Refresh);
    let result = state.database(move |db| {
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if verify_account(&tx, vault.vault_id, &presented)? != vault.key_epoch {
            return Err(ApiError::unauthorized());
        }
        tx.execute("DELETE FROM sync_devices WHERE expires<=?1", [time])?;
        let count: u32 = tx.query_row("SELECT count(*) FROM sync_devices", [], |row| row.get(0))?;
        if count >= MAX_DEVICES { return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "device_limit")); }
        let inserted = tx.execute("INSERT OR IGNORE INTO sync_devices(id,vault,epoch,issued,expires,verifier)
            VALUES(?1,?2,?3,?4,?5,?6)", params![device.to_string(), vault.vault_id.to_string(), vault.key_epoch,
                time, expires, verifier.digest().as_slice()])?;
        if inserted != 1 { return Err(ApiError(StatusCode::CONFLICT, "device_exists")); }
        tx.commit()?;
        Ok(())
    }).await;
    if matches!(result, Err(ApiError(StatusCode::UNAUTHORIZED, _))) {
        state.allow_login(time)?;
        state.login_result(time, false)?;
    }
    result?;
    Ok(Json(json!({"refreshToken": token.encode().as_str(), "refreshExpiresAt": expires})))
}

async fn refresh(State(state): State<AppState>, RoutePath(device): RoutePath<Uuid>, headers: HeaderMap,
    body: Result<Json<Vault>, JsonRejection>) -> Result<Json<serde_json::Value>, ApiError> {
    let presented = windows_bearer(&headers)?;
    let Json(vault) = body.map_err(|error| ApiError(error.status(), "invalid_request"))?;
    let write_key = writes::login_key(&headers)?.ok_or_else(ApiError::forbidden)?;
    let time = (state.clock)();
    let expires = time.checked_add(SESSION_SECONDS).ok_or_else(ApiError::internal)?;
    let refresh_expires = time.checked_add(REFRESH_SECONDS).ok_or_else(ApiError::internal)?;
    let token = SecretToken::generate().map_err(|_| ApiError::internal())?;
    let refresh_token = SecretToken::generate().map_err(|_| ApiError::internal())?;
    let vault_id = vault.vault_id.into_bytes();
    let access = token.verifier(vault_id, Purpose::Access);
    let refresh = refresh_token.verifier(vault_id, Purpose::Refresh);
    let challenge = writes::encode(access.digest());
    let received = SecretToken::parse(&presented).map_err(|_| ApiError::unauthorized())?.verifier(vault_id, Purpose::Refresh);
    state.database(move |db| {
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let device = device.to_string();
        let record: Option<(u64, u64, Vec<u8>)> = tx.query_row(
            "SELECT d.issued,d.expires,d.verifier FROM sync_devices d JOIN owner o ON o.vault=d.vault
             WHERE d.id=?1 AND d.vault=?2 AND d.epoch=?3 AND d.epoch=o.key_epoch",
            params![device, vault.vault_id.to_string(), vault.key_epoch], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional()?;
        let (issued, previous_expiry, current) = record.ok_or_else(ApiError::unauthorized)?;
        if time < issued || time >= previous_expiry { return Err(ApiError::unauthorized()); }
        if Verifier::from_stored_digest(vault_id, Purpose::Refresh, digest(current)?)
            .verify(&presented, vault_id, Purpose::Refresh).is_err() {
            let replay = tx.prepare("SELECT 1 FROM used_sync_refreshes WHERE verifier=?1 AND device=?2")?
                .exists(params![received.digest().as_slice(), device])?;
            if replay {
                tx.execute("DELETE FROM sync_devices WHERE id=?1", [&device])?;
                tx.commit()?;
            }
            return Err(ApiError::unauthorized());
        }
        let count: u32 = tx.query_row("SELECT count(*) FROM used_sync_refreshes WHERE device=?1", [&device], |row| row.get(0))?;
        if count >= MAX_RETAINED_REFRESHES {
            tx.execute("DELETE FROM sync_devices WHERE id=?1", [&device])?;
            tx.commit()?;
            return Err(ApiError::unauthorized());
        }
        // A device keeps only its latest access session. The client serializes all operations using it.
        tx.execute("DELETE FROM sessions WHERE device=?1", [&device])?;
        insert_session(&tx, &access, vault.vault_id, time, expires, Some(&write_key), Some(&device))?;
        tx.execute("INSERT INTO used_sync_refreshes VALUES(?1,?2)", params![received.digest().as_slice(), device])?;
        tx.execute("UPDATE sync_devices SET verifier=?1,issued=?2,expires=?3 WHERE id=?4",
            params![refresh.digest().as_slice(), time, refresh_expires, device])?;
        tx.commit()?;
        Ok(())
    }).await?;
    Ok(Json(json!({"token":token.encode().as_str(), "expiresAt":expires, "writeChallenge":challenge,
        "refreshToken":refresh_token.encode().as_str(), "refreshExpiresAt":refresh_expires})))
}

async fn revoke(State(state): State<AppState>, RoutePath(device): RoutePath<Uuid>, headers: HeaderMap,
    body: Result<Json<Vault>, JsonRejection>) -> Result<StatusCode, ApiError> {
    let presented = windows_bearer(&headers)?;
    let Json(vault) = body.map_err(|error| ApiError(error.status(), "invalid_request"))?;
    let time = (state.clock)();
    state.database(move |db| {
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let device = device.to_string();
        let admin = verify_account(&tx, vault.vault_id, &presented).is_ok();
        if !admin {
            let digest = SecretToken::parse(&presented).map_err(|_| ApiError::unauthorized())?
                .verifier(vault.vault_id.into_bytes(), Purpose::Refresh);
            let active = tx.prepare("SELECT 1 FROM sync_devices WHERE id=?1 AND vault=?2
                AND epoch=?3 AND issued<=?4 AND expires>?4 AND (verifier=?5 OR EXISTS
                (SELECT 1 FROM used_sync_refreshes WHERE device=?1 AND verifier=?5))")?
                .exists(params![device, vault.vault_id.to_string(), vault.key_epoch, time, digest.digest().as_slice()])?;
            if !active { return Err(ApiError::unauthorized()); }
        }
        tx.execute("DELETE FROM sync_devices WHERE id=?1 AND vault=?2", params![device, vault.vault_id.to_string()])?;
        tx.commit()?;
        Ok(StatusCode::NO_CONTENT)
    }).await
}
