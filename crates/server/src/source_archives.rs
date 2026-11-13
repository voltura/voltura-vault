use super::*;
use axum::{body::Bytes, extract::Path as RoutePath};
use std::{fs, io::{Read, Seek, SeekFrom}};

const CHUNK_BYTES: u64 = 1_048_576;
const ARCHIVE_LIMIT: u64 = 65 * CHUNK_BYTES;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/source-archives/list", post(list))
        .route("/api/v1/source-archives/{archive}/{index}", post(chunk))
        .route("/api/v1/recovery-kits/list", post(list_recovery))
        .route("/api/v1/recovery-kits/{archive}/{index}", post(chunk_recovery))
}

#[derive(Clone, Copy)]
enum Archive { Source, Recovery }
impl Archive {
    fn extension(self) -> &'static str {
        match self { Self::Source => "vvsa", Self::Recovery => "vvkr" }
    }
    fn directories(self, blobs: &Path) -> Result<Vec<PathBuf>, ApiError> {
        let kind = match self { Self::Source => "source-archives", Self::Recovery => "recovery-kits" };
        Ok(vec![
            Path::new("/var/lib/voltura-vault-published").join(kind),
            blobs.parent().ok_or_else(ApiError::internal)?.join(kind),
        ])
    }
    fn limit(self) -> u64 {
        match self { Self::Source => ARCHIVE_LIMIT, Self::Recovery => CHUNK_BYTES + 53 }
    }
}

async fn list(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<serde_json::Value>, ApiError> {
    list_archive(state, headers, Archive::Source).await
}
async fn list_recovery(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<serde_json::Value>, ApiError> {
    list_archive(state, headers, Archive::Recovery).await
}
async fn list_archive(state: AppState, headers: HeaderMap, kind: Archive) -> Result<Json<serde_json::Value>, ApiError> {
    let presented = zeroize::Zeroizing::new(credential(&headers, Method::POST)?);
    let time = (state.clock)();
    let directories = kind.directories(&state.blobs)?;
    state.database(move |db| {
        authorize(db, &presented, time)?;
        let mut archives = Vec::new();
        let mut ids = std::collections::HashSet::new();
        let suffix = format!(".{}", kind.extension());
        for path in directories {
            let dir = match fs::read_dir(path) {
                Ok(dir) => dir,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(ApiError::internal()),
            };
            for entry in dir {
                let entry = entry.map_err(|_| ApiError::internal())?;
                let name = entry.file_name();
                let Some(id) = name.to_str().and_then(|n| n.strip_suffix(&suffix)).and_then(|id| Uuid::parse_str(id).ok()) else { continue; };
                let metadata = entry.metadata().map_err(|_| ApiError::internal())?;
                if !metadata.is_file() || metadata.len() > kind.limit() || !ids.insert(id) { continue; }
                let created = metadata.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map_or(0, |d| d.as_secs());
                archives.push((created, id, metadata.len()));
            }
        }
        archives.sort_unstable_by(|a, b| b.cmp(a));
        Ok(Json(json!(archives.into_iter().take(512).map(|(created, id, size)| json!({"id":id,"created":created,"size":size})).collect::<Vec<_>>())))
    }).await
}

async fn chunk(State(state): State<AppState>, headers: HeaderMap, RoutePath((id, index)): RoutePath<(Uuid, u64)>) -> Result<Bytes, ApiError> {
    archive_chunk(state, headers, id, index, Archive::Source).await
}
async fn chunk_recovery(State(state): State<AppState>, headers: HeaderMap, RoutePath((id, index)): RoutePath<(Uuid, u64)>) -> Result<Bytes, ApiError> {
    archive_chunk(state, headers, id, index, Archive::Recovery).await
}
async fn archive_chunk(state: AppState, headers: HeaderMap, id: Uuid, index: u64, kind: Archive) -> Result<Bytes, ApiError> {
    let presented = zeroize::Zeroizing::new(credential(&headers, Method::POST)?);
    let time = (state.clock)();
    let directories = kind.directories(&state.blobs)?;
    state.database(move |db| {
        authorize(db, &presented, time)?;
        let name = format!("{id}.{}", kind.extension());
        let path = directories.iter().map(|directory| directory.join(&name))
            .find(|path| fs::symlink_metadata(path).is_ok_and(|m| m.is_file()))
            .ok_or(ApiError(StatusCode::NOT_FOUND, "archive_missing"))?;
        let mut archive = fs::File::open(path).map_err(|_| ApiError(StatusCode::NOT_FOUND, "archive_missing"))?;
        let size = archive.metadata().map_err(|_| ApiError::internal())?.len();
        let offset = index.checked_mul(CHUNK_BYTES).filter(|offset| *offset < size).ok_or_else(ApiError::bad)?;
        if size > kind.limit() { return Err(ApiError::bad()); }
        archive.seek(SeekFrom::Start(offset)).map_err(|_| ApiError::internal())?;
        let mut bytes = vec![0; (size - offset).min(CHUNK_BYTES) as usize];
        archive.read_exact(&mut bytes).map_err(|_| ApiError::internal())?;
        Ok(Bytes::from(bytes))
    }).await
}
