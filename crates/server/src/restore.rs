use rusqlite::{Connection, OpenFlags};
use std::{error::Error, fs, path::Path};
use uuid::Uuid;

const CHUNK_BYTES: u64 = 1_048_576;
const MAX_ATTACHMENT_BYTES: u64 = 100_000_000;

/// Check a private staging copy before it becomes the recovery instance's data.
pub fn prepare(directory: &Path, minimum_epoch: u32) -> Result<(), Box<dyn Error>> {
    let database = directory.join("vault.sqlite3");
    if !fs::symlink_metadata(&database)?.is_file() {
        return Err("Restore requires a regular database file".into());
    }
    let mut db = Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    db.pragma_update(None, "foreign_keys", "ON")?;
    let integrity: String = db.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" || db.prepare("PRAGMA foreign_key_check")?.exists([])? {
        return Err("Backup failed the SQLite integrity check".into());
    }
    let (mut files, mut chunks) = (0, 0);
    {
        let epoch = if db.pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))? >= 4 {
            db.query_row("SELECT key_epoch FROM owner WHERE singleton=1", [], |row| row.get(0))?
        } else { 1 };
        if epoch < minimum_epoch {
            return Err("Backup key epoch is below the trusted minimum".into());
        }
        let mut published = db.prepare("SELECT object, size FROM files WHERE published IS NOT NULL")?;
        let mut rows = published.query([])?;
        while let Some(row) = rows.next()? {
            let object: String = row.get(0)?;
            let size: u64 = row.get(1)?;
            if Uuid::parse_str(&object)?.to_string() != object || size > MAX_ATTACHMENT_BYTES {
                return Err("Backup has invalid attachment metadata".into());
            }
            let blobs = directory.join("vault.blobs");
            let epoch_root = voltura_vault_server::epoch_blobs(&blobs, epoch);
            let path = epoch_root.join(object);
            if !fs::symlink_metadata(&blobs)?.is_dir() || !fs::symlink_metadata(&epoch_root)?.is_dir()
                || !fs::symlink_metadata(&path)?.is_dir() {
                return Err("Backup has an invalid attachment directory".into());
            }
            for index in 0..size.div_ceil(CHUNK_BYTES).max(1) {
                let chunk = fs::symlink_metadata(path.join(index.to_string()))?;
                let expected = (size - index * CHUNK_BYTES).min(CHUNK_BYTES) + 17;
                if !chunk.is_file() || chunk.len() != expected {
                    return Err("Backup has a missing or truncated attachment chunk".into());
                }
                chunks += 1;
            }
            files += 1;
        }
    }
    let mode: String = db.query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))?;
    if mode != "delete" {
        return Err("Could not consolidate restored database".into());
    }
    voltura_vault_server::mark_restored(&mut db)?;
    println!("Validated database and {files} published files ({chunks} chunks). Cleared restored sessions.");
    Ok(())
}
