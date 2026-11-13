//! Private HTTPS-proxy backend. Bind only to loopback; never expose its HTTP
//! listener directly.
mod files;
pub use files::epoch_blobs;
pub mod rotation;
mod source_archives;
mod sync;
mod writes;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Request, State, rejection::JsonRejection},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;
use uuid::Uuid;
use voltura_server_auth::{Purpose, SecretToken, Session, Verifier};
use zeroize::Zeroize;

const ORIGIN: &str = "https://vault-api.test";
const DESKTOP_ORIGIN: &str = "https://tauri.localhost";
const UNIX_DESKTOP_ORIGIN: &str = "tauri://localhost";
const SEPARATE_WEB_ORIGIN: &str = "https://vault-ui.test";
const HOST: &str = "vault-api.test";
const COOKIE: &str = "__Host-vault_session";
const SESSION_SECONDS: u64 = 900;
const BOOTSTRAP_VAULT: [u8; 16] = [0; 16];

#[derive(Clone)]
pub struct AppState {
    db: Arc<Mutex<Connection>>,
    blobs: Arc<PathBuf>,
    jobs: Arc<Semaphore>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    failures: Arc<Mutex<Failures>>,
}

#[derive(Default)]
struct Failures {
    count: u32,
    started: u64,
    blocked_until: u64,
}

impl AppState {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        Self::open_at_least(path, 1)
    }

    pub fn open_at_least(path: &Path, minimum_epoch: u32) -> rusqlite::Result<Self> {
        Self::open_with_epoch(path, minimum_epoch, None)
    }

    pub fn open_with_epoch(path: &Path, minimum_epoch: u32, trusted_epoch: Option<u32>) -> rusqlite::Result<Self> {
        let mut db =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        let version: i64 = db.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if (1..=6).contains(&version) {
            let tx = db.transaction()?;
            if version == 1 {
                sync::create_schema(&tx)?;
            }
            if version <= 2 {
                files::create_schema(&tx)?;
            }
            if version <= 3 { add_key_epoch(&tx)?; }
            if version <= 4 { files::add_reservations(&tx)?; }
            if version <= 5 { writes::add_session_proof(&tx)?; }
            files::add_deletions(&tx)?;
            tx.commit()?;
        } else if version != 7 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let epoch = db.query_row("SELECT key_epoch FROM owner WHERE singleton=1", [], |r| r.get::<_, u32>(0)).optional()?;
        let epoch = epoch.unwrap_or(1);
        if minimum_epoch == 0 || epoch < minimum_epoch || trusted_epoch.is_some_and(|trusted| epoch != trusted) {
            return Err(rusqlite::Error::InvalidParameterName("Vault key epoch does not match the trusted deployment configuration".into()));
        }
        let blobs = path.with_extension("blobs");
        std::fs::create_dir_all(&blobs).map_err(|_| rusqlite::Error::InvalidPath(blobs.clone()))?;
        Self::from_connection(db, blobs)
    }

    fn from_connection(db: Connection, blobs: PathBuf) -> rusqlite::Result<Self> {
        db.busy_timeout(Duration::from_secs(5))?;
        db.pragma_update(None, "foreign_keys", "ON")?;
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        db.execute_batch(sync::CREATE_GENERATION)?;
        Ok(Self {
            db: Arc::new(Mutex::new(db)),
            blobs: Arc::new(blobs),
            jobs: Arc::new(Semaphore::new(8)),
            clock: Arc::new(now),
            failures: Arc::new(Mutex::new(Failures::default())),
        })
    }

    async fn database<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Connection) -> Result<T, ApiError> + Send + 'static,
    ) -> Result<T, ApiError> {
        let permit = self
            .jobs
            .clone()
            .try_acquire_owned()
            .map_err(|_| ApiError::unavailable())?;
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut db = db.lock().map_err(|_| ApiError::unavailable())?;
            f(&mut db)
        })
        .await
        .map_err(|_| ApiError::internal())?
    }

    fn allow_login(&self, time: u64) -> Result<(), ApiError> {
        let failures = self.failures.lock().map_err(|_| ApiError::unavailable())?;
        if time < failures.blocked_until {
            return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "try_later"));
        }
        Ok(())
    }

    fn login_result(&self, time: u64, accepted: bool) -> Result<(), ApiError> {
        let mut failures = self.failures.lock().map_err(|_| ApiError::unavailable())?;
        if accepted {
            *failures = Failures::default();
        } else {
            if time < failures.started || time.saturating_sub(failures.started) >= 900 {
                *failures = Failures {
                    started: time,
                    ..Default::default()
                };
            }
            failures.count = failures.count.saturating_add(1);
            if failures.count >= 5 {
                failures.blocked_until = time.saturating_add(300);
            }
        }
        Ok(())
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .unwrap_or(0)
}

fn add_key_epoch(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch("ALTER TABLE owner ADD COLUMN key_epoch INTEGER NOT NULL DEFAULT 1
        CHECK(key_epoch BETWEEN 1 AND 4294967295);
        PRAGMA user_version=4;")
}

/// Rotate the generation on a private restore copy before it can serve clients.
pub fn mark_restored(db: &mut Connection) -> rusqlite::Result<()> {
    let tx = db.transaction()?;
    tx.execute_batch(sync::CREATE_GENERATION)?;
    tx.execute("UPDATE sync_generation SET value=lower(hex(randomblob(16)))", [])?;
    tx.execute("DELETE FROM sessions", [])?;
    tx.execute("DELETE FROM files WHERE published IS NULL", [])?;
    tx.commit()
}

/// Called only by the local initialization command on a new database.
pub fn initialize(
    db: &mut Connection,
    bootstrap: &SecretToken,
    issued: u64,
) -> rusqlite::Result<()> {
    let tx = db.transaction()?;
    tx.execute_batch("CREATE TABLE owner (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1), vault TEXT NOT NULL UNIQUE,
        account BLOB NOT NULL CHECK(length(account)=32), recovery BLOB NOT NULL CHECK(length(recovery)=32),
        encrypted_config TEXT NOT NULL);
      CREATE TABLE bootstrap (singleton INTEGER PRIMARY KEY CHECK(singleton=1),
        digest BLOB NOT NULL CHECK(length(digest)=32), issued INTEGER NOT NULL, expires INTEGER NOT NULL);
      CREATE TABLE sessions (digest BLOB PRIMARY KEY CHECK(length(digest)=32),
        vault TEXT NOT NULL REFERENCES owner(vault), issued INTEGER NOT NULL, expires INTEGER NOT NULL,
        revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)));
      PRAGMA user_version=1;")?;
    sync::create_schema(&tx)?;
    files::create_schema(&tx)?;
    add_key_epoch(&tx)?;
    let verifier = bootstrap.verifier(BOOTSTRAP_VAULT, Purpose::Bootstrap);
    tx.execute(
        "INSERT INTO bootstrap VALUES(1, ?1, ?2, ?3)",
        params![
            verifier.digest().as_slice(),
            issued,
            issued.saturating_add(900)
        ],
    )?;
    tx.commit()
}

pub fn router(state: AppState) -> Router {
    router_with_unix_desktop(state, false)
}

pub fn router_with_unix_desktop(state: AppState, enable_unix_desktop: bool) -> Router {
    Router::new()
        .route("/health", get(|| async { Json(json!({"status":"ok"})) }))
        .route("/api/v1/bootstrap", post(bootstrap))
        .route("/api/v1/config", get(configuration))
        .route("/api/v1/sessions", post(login))
        .route("/api/v1/session", get(session_info).delete(logout))
        .layer(DefaultBodyLimit::max(96 * 1024))
        .merge(sync::routes(state.clone()))
        .merge(files::routes(state.clone()))
        .merge(source_archives::routes())
        .layer(middleware::from_fn(move |request, next| {
            boundary(request, next, enable_unix_desktop)
        }))
        .with_state(state)
}

#[derive(Debug)]
struct ApiError(StatusCode, &'static str);
impl ApiError {
    fn bad() -> Self {
        Self(StatusCode::BAD_REQUEST, "invalid_request")
    }
    fn unauthorized() -> Self {
        Self(StatusCode::UNAUTHORIZED, "sign_in_required")
    }
    fn forbidden() -> Self {
        Self(StatusCode::FORBIDDEN, "forbidden")
    }
    fn unavailable() -> Self {
        Self(StatusCode::SERVICE_UNAVAILABLE, "try_later")
    }
    fn internal() -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
    }
}
impl From<rusqlite::Error> for ApiError {
    fn from(_: rusqlite::Error) -> Self {
        Self::internal()
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error":self.1}))).into_response()
    }
}

async fn boundary(request: Request, next: Next, enable_unix_desktop: bool) -> Response {
    let origin = request.headers().get(header::ORIGIN);
    let separate_client = origin
        .filter(|value| {
            *value == DESKTOP_ORIGIN
                || *value == SEPARATE_WEB_ORIGIN
                || (enable_unix_desktop && *value == UNIX_DESKTOP_ORIGIN)
        })
        .cloned();
    let allowed = request.uri().path() == "/health"
        || (request
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|host| host.eq_ignore_ascii_case(HOST))
            && request.headers().get_all(header::HOST).iter().count() == 1
            && request.headers().get_all(header::ORIGIN).iter().count() <= 1
            && request.uri().query().is_none()
            && (separate_client.is_some() || origin.is_none_or(|v| v == ORIGIN))
            && (separate_client.is_none() || !request.headers().contains_key(header::COOKIE)));
    let mut response = if allowed {
        if separate_client.is_some()
            && request.method() == Method::OPTIONS
            && request.uri().path().starts_with("/api/v1/")
        {
            let mut response = StatusCode::NO_CONTENT.into_response();
            response.headers_mut().insert(
                header::ACCESS_CONTROL_ALLOW_METHODS,
                HeaderValue::from_static("GET, POST, DELETE"),
            );
            response.headers_mut().insert(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                HeaderValue::from_static("Authorization, Content-Type, X-Vault-Write-Key, X-Vault-Write-Proof"),
            );
            response
        } else {
            next.run(request).await
        }
    } else {
        ApiError::forbidden().into_response()
    };
    response
        .headers_mut()
        .append(header::VARY, HeaderValue::from_static("Origin"));
    if let Some(origin) = separate_client.filter(|_| allowed) {
        response
            .headers_mut()
            .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn bearer(headers: &HeaderMap) -> Result<String, ApiError> {
    if headers.get_all(header::AUTHORIZATION).iter().count() != 1 {
        return Err(ApiError::unauthorized());
    }
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(ApiError::unauthorized)?;
    let (scheme, token) = value.split_once(' ').ok_or_else(ApiError::unauthorized)?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return Err(ApiError::unauthorized());
    }
    let token = token.trim_start_matches(' ');
    SecretToken::parse(token).map_err(|_| ApiError::unauthorized())?;
    Ok(token.to_owned())
}

fn credential(headers: &HeaderMap, method: Method) -> Result<String, ApiError> {
    let mut cookies = vec![];
    for header in headers.get_all(header::COOKIE) {
        for pair in header
            .to_str()
            .map_err(|_| ApiError::unauthorized())?
            .split(';')
        {
            if let Some((name, value)) = pair.trim().split_once('=') {
                if name == COOKIE {
                    cookies.push(value);
                }
            }
        }
    }
    if headers.contains_key(header::AUTHORIZATION) {
        if !cookies.is_empty() {
            return Err(ApiError::bad());
        }
        return bearer(headers);
    }
    if cookies.len() != 1 {
        return Err(ApiError::unauthorized());
    }
    if method != Method::GET && headers.get(header::ORIGIN).is_none_or(|v| v != ORIGIN) {
        return Err(ApiError::forbidden());
    }
    SecretToken::parse(cookies[0]).map_err(|_| ApiError::unauthorized())?;
    Ok(cookies[0].to_owned())
}

fn digest(bytes: Vec<u8>) -> Result<[u8; 32], ApiError> {
    bytes.try_into().map_err(|_| ApiError::internal())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Bootstrap {
    vault_id: Uuid,
    account_token: String,
    recovery_token: String,
    encrypted_config: String,
}
impl Drop for Bootstrap {
    fn drop(&mut self) {
        self.account_token.zeroize();
        self.recovery_token.zeroize();
    }
}

async fn bootstrap(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<Bootstrap>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let time = (state.clock)();
    let Json(body) = body.map_err(|error| ApiError(error.status(), "invalid_request"))?;
    if body.vault_id.is_nil()
        || body.account_token == body.recovery_token
        || body.encrypted_config.len() > 88_000
    {
        return Err(ApiError::bad());
    }
    let config = STANDARD
        .decode(&body.encrypted_config)
        .map_err(|_| ApiError::bad())?;
    if !(16..=65_536).contains(&config.len()) {
        return Err(ApiError::bad());
    }
    let account = SecretToken::parse(&body.account_token)
        .map_err(|_| ApiError::bad())?
        .verifier(body.vault_id.into_bytes(), Purpose::Account);
    let recovery = SecretToken::parse(&body.recovery_token)
        .map_err(|_| ApiError::bad())?
        .verifier(body.vault_id.into_bytes(), Purpose::Recovery);
    let presented = zeroize::Zeroizing::new(bearer(&headers)?);
    let result = state
        .database(move |db| {
            let tx = db.transaction()?;
            let stored: Option<(Vec<u8>, u64, u64)> = tx
                .query_row(
                    "SELECT digest,issued,expires FROM bootstrap WHERE singleton=1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let (hash, issued, expires) = stored.ok_or_else(ApiError::unauthorized)?;
            let verifier =
                Verifier::from_stored_digest(BOOTSTRAP_VAULT, Purpose::Bootstrap, digest(hash)?);
            Session::new(verifier, issued, expires)
                .map_err(|_| ApiError::unauthorized())?
                .authorize(&presented, BOOTSTRAP_VAULT, Purpose::Bootstrap, time)
                .map_err(|_| ApiError::unauthorized())?;
            tx.execute(
                "INSERT INTO owner(singleton,vault,account,recovery,encrypted_config) VALUES(1,?1,?2,?3,?4)",
                params![
                    body.vault_id.to_string(),
                    account.digest().as_slice(),
                    recovery.digest().as_slice(),
                    body.encrypted_config
                ],
            )?;
            tx.execute("DELETE FROM bootstrap", [])?;
            tx.commit()?;
            Ok(StatusCode::CREATED)
        })
        .await;
    if matches!(&result, Err(ApiError(StatusCode::UNAUTHORIZED, _))) {
        state.allow_login(time)?;
        state.login_result(time, false)?;
    }
    result
}

async fn configuration(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .database(|db| {
            let config: Option<(String, String, u32)> = db
                .query_row(
                    "SELECT vault,encrypted_config,key_epoch FROM owner WHERE singleton=1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let (vault, config, epoch) =
                config.ok_or(ApiError(StatusCode::NOT_FOUND, "not_initialized"))?;
            Ok(Json(json!({"vaultId":vault,"encryptedConfig":config,"keyEpoch":epoch})))
        })
        .await
}

#[derive(Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Client {
    Browser,
    Native,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Login {
    vault_id: Uuid,
    client: Client,
}

async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<Login>, JsonRejection>,
) -> Result<Response, ApiError> {
    let time = (state.clock)();
    let Json(body) = body.map_err(|error| ApiError(error.status(), "invalid_request"))?;
    if body.client == Client::Browser && headers.get(header::ORIGIN).is_none_or(|v| v != ORIGIN) {
        return Err(ApiError::forbidden());
    }
    let presented = zeroize::Zeroizing::new(bearer(&headers)?);
    let session = SecretToken::generate().map_err(|_| ApiError::internal())?;
    let write_key = writes::login_key(&headers)?;
    let verifier = session.verifier(body.vault_id.into_bytes(), Purpose::Access);
    let challenge = write_key.map(|_| writes::encode(verifier.digest()));
    let vault = body.vault_id;
    let expires = time
        .checked_add(SESSION_SECONDS)
        .ok_or_else(ApiError::internal)?;
    let result = state
        .database(move |db| {
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let stored: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT account FROM owner WHERE vault=?1",
                    [vault.to_string()],
                    |r| r.get(0),
                )
                .optional()?;
            let verifier_account = Verifier::from_stored_digest(
                vault.into_bytes(),
                Purpose::Account,
                digest(stored.ok_or_else(ApiError::unauthorized)?)?,
            );
            verifier_account
                .verify(&presented, vault.into_bytes(), Purpose::Account)
                .map_err(|_| ApiError::unauthorized())?;
            tx.execute(
                "DELETE FROM sessions WHERE expires<=?1 OR revoked=1",
                [time],
            )?;
            let count: u32 = tx.query_row("SELECT count(*) FROM sessions", [], |r| r.get(0))?;
            if count >= 64 {
                return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "session_limit"));
            }
            tx.execute(
                "INSERT INTO sessions(digest,vault,issued,expires,revoked,write_key) VALUES(?1,?2,?3,?4,0,?5)",
                params![
                    verifier.digest().as_slice(),
                    vault.to_string(),
                    time,
                    expires,
                    write_key.as_ref().map(|key| key.as_slice())
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await;
    if matches!(&result, Err(ApiError(StatusCode::UNAUTHORIZED, _))) {
        state.allow_login(time)?;
        state.login_result(time, false)?;
    }
    result?;
    let encoded = session.encode();
    if body.client == Client::Browser {
        let mut response = Json(json!({"expiresAt":expires,"writeChallenge":challenge})).into_response();
        response.headers_mut().insert(
            header::SET_COOKIE,
            HeaderValue::from_str(&format!(
                "{COOKIE}={}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECONDS}",
                encoded.as_str()
            ))
            .map_err(|_| ApiError::internal())?,
        );
        Ok(response)
    } else {
        Ok(Json(json!({"token":encoded.as_str(),"expiresAt":expires,"writeChallenge":challenge})).into_response())
    }
}

struct Authorized {
    hash: [u8; 32],
    vault: String,
    epoch: u32,
    expires: u64,
}
fn authorize(db: &Connection, presented: &str, time: u64) -> Result<Authorized, ApiError> {
    let (vault, epoch): (String, u32) = db
        .query_row("SELECT vault,key_epoch FROM owner WHERE singleton=1", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .optional()?
        .ok_or_else(ApiError::unauthorized)?;
    let id = Uuid::parse_str(&vault)
        .map_err(|_| ApiError::internal())?
        .into_bytes();
    let verifier = SecretToken::parse(presented)
        .map_err(|_| ApiError::unauthorized())?
        .verifier(id, Purpose::Access);
    let stored: Option<(u64, u64, bool)> = db
        .query_row(
            "SELECT issued,expires,revoked FROM sessions WHERE digest=?1",
            [verifier.digest().as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let (issued, expires, revoked) = stored.ok_or_else(ApiError::unauthorized)?;
    let mut session =
        Session::new(verifier.clone(), issued, expires).map_err(|_| ApiError::unauthorized())?;
    if revoked {
        session.revoke();
    }
    session
        .authorize(presented, id, Purpose::Access, time)
        .map_err(|_| ApiError::unauthorized())?;
    Ok(Authorized {
        hash: *verifier.digest(),
        vault,
        epoch,
        expires,
    })
}

async fn session_info(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let presented = zeroize::Zeroizing::new(credential(&headers, Method::GET)?);
    let time = (state.clock)();
    state
        .database(move |db| {
            let tx = db.transaction()?;
            let s = authorize(&tx, &presented, time)?;
            Ok(Json(json!({"vaultId":s.vault,"expiresAt":s.expires})))
        })
        .await
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    let presented = zeroize::Zeroizing::new(credential(&headers, Method::DELETE)?);
    let time = (state.clock)();
    state
        .database(move |db| {
            let s = authorize(db, &presented, time)?;
            db.execute(
                "UPDATE sessions SET revoked=1 WHERE digest=?1",
                [s.hash.as_slice()],
            )?;
            Ok(())
        })
        .await?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "__Host-vault_session=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0",
        ),
    );
    Ok(response)
}
