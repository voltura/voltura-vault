//! Bind storage mutations to an ephemeral signing key registered at login.
use super::*;
use axum::body::{Body, to_bytes};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{ED25519, UnparsedPublicKey};
use sha2::{Digest, Sha256};

pub(super) const KEY: &str = "x-vault-write-key";
pub(super) const PROOF: &str = "x-vault-write-proof";
const MAX_WRITE_BODY: usize = sync::MAX_ENVELOPE_BYTES + 4096;

pub(super) fn add_session_proof(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch("ALTER TABLE sessions ADD COLUMN write_key BLOB CHECK(length(write_key)=32);
        PRAGMA user_version=6;")
}

pub(super) fn encode(bytes: &[u8]) -> String { URL_SAFE_NO_PAD.encode(bytes) }

fn decode_header<const N: usize>(headers: &HeaderMap, name: &str) -> Result<Option<[u8; N]>, ApiError> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else { return Ok(None) };
    if values.next().is_some() || value.as_bytes().len() != (N * 4).div_ceil(3) {
        return Err(ApiError::bad());
    }
    let decoded: [u8; N] = URL_SAFE_NO_PAD.decode(value.as_bytes()).ok()
        .and_then(|bytes| bytes.try_into().ok()).ok_or_else(ApiError::bad)?;
    if encode(&decoded).as_bytes() != value.as_bytes() { return Err(ApiError::bad()); }
    Ok(Some(decoded))
}

pub(super) fn login_key(headers: &HeaderMap) -> Result<Option<[u8; 32]>, ApiError> {
    decode_header(headers, KEY)
}

pub(super) async fn guard(State(state): State<AppState>, request: Request, next: Next) -> Response {
    match check(state, request).await {
        Ok(request) => next.run(request).await,
        Err(error) => error.into_response(),
    }
}

async fn check(state: AppState, request: Request) -> Result<Request, ApiError> {
    let token = zeroize::Zeroizing::new(credential(request.headers(), request.method().clone())?);
    let proof = decode_header::<96>(request.headers(), PROOF)?.ok_or_else(ApiError::forbidden)?;
    let time = (state.clock)();
    let (challenge, key) = state.database(move |db| {
        let auth = authorize(db, &token, time)?;
        let key: Option<Vec<u8>> = db.query_row("SELECT write_key FROM sessions WHERE digest=?1",
            [auth.hash.as_slice()], |row| row.get(0))?;
        Ok((auth.hash, digest(key.ok_or_else(ApiError::forbidden)?)?))
    }).await?;
    let message = format!("VolturaVault write v1\n{}\n{}\n{}\n{}",
        encode(&challenge), request.method(), request.uri().path(), encode(&proof[..32]));
    UnparsedPublicKey::new(&ED25519, key).verify(message.as_bytes(), &proof[32..])
        .map_err(|_| ApiError::forbidden())?;
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, MAX_WRITE_BODY).await
        .map_err(|_| ApiError(StatusCode::PAYLOAD_TOO_LARGE, "invalid_request"))?;
    if Sha256::digest(&body)[..] != proof[..32] { return Err(ApiError::forbidden()); }
    Ok(Request::from_parts(parts, Body::from(body)))
}
