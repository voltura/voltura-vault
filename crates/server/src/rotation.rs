//! Local maintenance only. A sync session cannot replace the owner's credentials.
use super::{STANDARD, files, sync};
use base64::Engine;
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fs,
    io::{Read, Write},
    path::Path,
    time::Duration,
};
use uuid::Uuid;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RotationPoint {
    vault_id: String,
    epoch: u32,
    generation: String,
    last_revision: i64,
    last_attachment: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inventory: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    replacement_inventory: Option<String>,
}

fn point(db: &Connection) -> Result<RotationPoint> {
    Ok(db.query_row(
        "SELECT vault,key_epoch,(SELECT value FROM sync_generation WHERE singleton=1),
            (SELECT coalesce(max(seq),0) FROM revisions),
            (SELECT coalesce(max(published),0) FROM files) FROM owner WHERE singleton=1",
        [],
        |row| {
            Ok(RotationPoint {
                vault_id: row.get(0)?,
                epoch: row.get(1)?,
                generation: row.get(2)?,
                last_revision: row.get(3)?,
                last_attachment: row.get(4)?,
                inventory: None,
                replacement_inventory: None,
            })
        },
    )?)
}

pub fn inspect(directory: &Path) -> Result<RotationPoint> {
    let db = Connection::open_with_flags(
        directory.join("vault.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    point(&db)
}

pub fn inspect_quarantine(directory: &Path) -> Result<RotationPoint> {
    let db = Connection::open_with_flags(directory.join("vault.sqlite3"), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut state = point(&db)?;
    state.inventory = Some(inventory_digest(&db, directory, state.epoch)?);
    Ok(state)
}

pub fn read_epoch_floor(path: &Path) -> Result<u32> {
    if !fs::symlink_metadata(path)?.is_file() {
        return Err("Invalid vault key epoch floor file".into());
    }
    let mut text = String::new();
    fs::File::open(path)?.take(32).read_to_string(&mut text)?;
    let epoch: u32 = text.trim_end().parse()?;
    if epoch == 0 || text != format!("{epoch}\n") {
        return Err("Invalid vault key epoch floor".into());
    }
    Ok(epoch)
}

fn advance_epoch_floor(path: &Path, next: u32) -> Result<()> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or("Epoch floor requires a parent directory")?;
    let temporary = parent.join(format!(".vault-key-epoch-{}.tmp", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let result = (|| -> std::io::Result<()> {
        writeln!(file, "{next}")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o644))?;
        }
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        #[cfg(unix)]
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result?;
    Ok(())
}

/// The staging database contains a complete client-verified rewrite. Its files
/// are staged in the next epoch directory and can be accessed only after commit.
/// Old blob paths remain intact for a backup that started before activation.
pub fn activate(
    directory: &Path,
    replacement: &Path,
    expected: &RotationPoint,
    floor: &Path,
) -> Result<()> {
    activate_with_quarantine(directory, replacement, expected, floor, false)
}

pub fn activate_with_quarantine(
    directory: &Path,
    replacement: &Path,
    expected: &RotationPoint,
    floor: &Path,
    quarantine: bool,
) -> Result<()> {
    let path = directory.join("vault.sqlite3");
    let mut db = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    db.busy_timeout(Duration::from_secs(5))?;
    db.pragma_update(None, "foreign_keys", "ON")?;
    db.pragma_update(None, "trusted_schema", "OFF")?;
    db.pragma_update(None, "synchronous", "FULL")?;
    if !fs::symlink_metadata(replacement)?.is_file()
        || path.canonicalize()? == replacement.canonicalize()?
    {
        return Err("Rotation requires a separate regular staging database".into());
    }
    let replacement = replacement
        .to_str()
        .ok_or("Invalid staging database path")?;
    db.execute("ATTACH DATABASE ?1 AS staged", [replacement])?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    validate_stage_tables(&tx, quarantine)?;
    let mut live = point(&tx)?;
    if quarantine {
        live.inventory = Some(inventory_digest(&tx, directory, live.epoch)?);
    }
    live.replacement_inventory.clone_from(&expected.replacement_inventory);
    if live != *expected {
        return Err("Vault changed while rotation was staged. Re-sync before trying again".into());
    }
    let epoch = expected
        .epoch
        .checked_add(1)
        .ok_or("Vault key epoch limit reached")?;
    let floor_epoch = read_epoch_floor(floor)?;
    if floor_epoch != expected.epoch && floor_epoch != epoch {
        return Err("Trusted key epoch does not match the proposed rotation".into());
    }
    let (vault, account, recovery, config, staged_epoch): (String, Vec<u8>, Vec<u8>, String, u32) =
        tx.query_row("SELECT vault,account,recovery,encrypted_config,key_epoch FROM staged.owner WHERE singleton=1",
            [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))?;
    let (old_account, old_recovery): (Vec<u8>, Vec<u8>) = tx.query_row(
        "SELECT account,recovery FROM main.owner WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if vault != expected.vault_id
        || staged_epoch != epoch
        || account.len() != 32
        || recovery.len() != 32
        || account == old_account
        || recovery == old_recovery
        || config.len() > 88_000
    {
        return Err("Replacement vault identity, epoch, or credentials are invalid".into());
    }
    validate_envelope(&config, &vault, epoch)?;
    let replacement_inventory = expected.replacement_inventory.as_deref()
        .ok_or("Rotation requires the replacement inventory from the trusted staging record")?;

    let (old_count, new_count, bytes): (u64, u64, u64) = tx.query_row(
        "SELECT (SELECT count(*) FROM main.revisions),count(*),coalesce(sum(length(envelope)),0) FROM staged.revisions",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
    tx.execute_batch("CREATE TEMP TABLE rotation_excluded_revisions(seq INTEGER PRIMARY KEY);
                      CREATE TEMP TABLE rotation_excluded_files(published INTEGER PRIMARY KEY);")?;
    let (quarantined_revisions, quarantined_files) = if quarantine {
        validate_quarantine(&tx)?
    } else { (0, 0) };
    if old_count != new_count + quarantined_revisions || bytes > sync::MAX_VAULT_BYTES {
        return Err("Replacement records do not fit the live revision inventory".into());
    }
    {
        let mut statement = tx.prepare(
            "SELECT old.envelope,new.envelope FROM main.revisions old LEFT JOIN staged.revisions new
              ON new.seq=old.seq AND new.vault=old.vault AND new.object=old.object
              AND new.revision=old.revision AND new.mutation=old.mutation
              WHERE NOT ?1 OR NOT EXISTS (SELECT 1 FROM temp.rotation_excluded_revisions q WHERE q.seq=old.seq)")?;
        let mut rows = statement.query([quarantine])?;
        while let Some(row) = rows.next()? {
            let previous: sync::Mutation = serde_json::from_str(&row.get::<_, String>(0)?)?;
            let encoded = row
                .get::<_, Option<String>>(1)?
                .ok_or("Replacement is missing a revision")?;
            let rewritten: sync::Mutation = serde_json::from_str(&encoded)?;
            if !rewritten.is_rekey_of(&previous, epoch) {
                return Err("Replacement changed revision identity or ancestry".into());
            }
        }
    }
    validate_attachments(&tx, directory, epoch, quarantined_files)?;
    if inventory_digest_from(&tx, directory, epoch, true)? != replacement_inventory {
        return Err("Replacement inventory does not match the trusted staging record".into());
    }
    if quarantined_revisions != 0 {
        tx.execute_batch(
            "DELETE FROM main.revision_heads;
             DELETE FROM main.revisions WHERE seq IN (SELECT seq FROM temp.rotation_excluded_revisions);
             INSERT INTO main.revision_heads SELECT vault,object,revision FROM main.revisions;
             DELETE FROM main.revision_heads WHERE EXISTS (
                SELECT 1 FROM staged.revisions AS child, json_each(child.envelope,'$.parents') AS parent
                WHERE child.vault=revision_heads.vault AND child.object=revision_heads.object AND parent.value=revision_heads.revision
             );",
        )?;
    }
    if quarantined_files != 0 {
        tx.execute("DELETE FROM main.files WHERE published IN (SELECT published FROM temp.rotation_excluded_files)", [])?;
    }
    tx.execute_batch(
        "UPDATE main.revisions SET envelope=(SELECT envelope FROM staged.revisions WHERE seq=main.revisions.seq);
         DELETE FROM main.files WHERE published IS NULL;
         UPDATE main.files SET manifest=(SELECT manifest FROM staged.files
            WHERE staged.files.vault=main.files.vault AND staged.files.object=main.files.object);
         DELETE FROM main.sessions;
         UPDATE main.sync_generation SET value=lower(hex(randomblob(16))) WHERE singleton=1;",
    )?;
    tx.execute("UPDATE main.owner SET account=?1,recovery=?2,encrypted_config=?3,key_epoch=?4 WHERE singleton=1",
        params![account, recovery, config, epoch])?;
    // If the process stops before the SQL commit, startup fails closed at the
    // new floor. Retry with the same verified stage and rotation point.
    if floor_epoch != epoch {
        advance_epoch_floor(floor, epoch)?;
    }
    tx.commit()?;
    Ok(())
}

fn validate_stage_tables(db: &Connection, quarantine: bool) -> Result<()> {
    let mut table = db.prepare("SELECT 1 FROM pragma_table_list
        WHERE schema='staged' AND name=?1 AND type='table'")?;
    let required = ["owner", "revisions", "files"];
    let excluded = ["quarantined_revisions", "quarantined_files"];
    for name in required.iter().chain(excluded.iter().filter(|_| quarantine)) {
        if !table.exists([name])? {
            return Err("Replacement inventory requires regular staging tables".into());
        }
    }
    Ok(())
}

fn validate_envelope(config: &str, vault: &str, epoch: u32) -> Result<()> {
    let envelope: serde_json::Value = serde_json::from_slice(&STANDARD.decode(config)?)?;
    let context = &envelope["context"];
    let kdf = &envelope["kdf"];
    let exact_bytes = |value: &serde_json::Value, bytes| {
        value.as_str().is_some_and(|text| {
            STANDARD
                .decode(text)
                .is_ok_and(|decoded| decoded.len() == bytes)
        })
    };
    if envelope["version"].as_u64() != Some(1)
        || context["vaultId"].as_str() != Some(vault)
        || context["epoch"].as_u64() != Some(u64::from(epoch))
        || ["objectId", "revisionId"].iter().any(|id| {
            !context[id]
                .as_str()
                .and_then(|id| Uuid::parse_str(id).ok())
                .is_some_and(|id| !id.is_nil())
        })
        || kdf["algorithm"].as_str() != Some("argon2id13")
        || !matches!(kdf["memory"].as_u64(), Some(67_108_864 | 134_217_728))
        || !matches!(kdf["passes"].as_u64(), Some(3..=64))
        || !exact_bytes(&kdf["salt"], 16)
        || !exact_bytes(&envelope["identifiers"]["nonce"], 24)
        || !exact_bytes(&envelope["identifiers"]["ciphertext"], 112)
        || ["root", "account", "recoveryDevice"].iter().any(|key| {
            let value = &envelope[key];
            !exact_bytes(&value["nonce"], 24) || !exact_bytes(&value["ciphertext"], 48)
        })
    {
        return Err("Replacement envelope is not for the next protected vault epoch".into());
    }
    Ok(())
}

fn inventory_digest(db: &Connection, directory: &Path, epoch: u32) -> Result<String> {
    inventory_digest_from(db, directory, epoch, false)
}

fn inventory_digest_from(db: &Connection, directory: &Path, epoch: u32, replacement: bool) -> Result<String> {
    let mut digest = Sha256::new();
    let mut bind = |fields: &[String]| {
        for field in fields {
            digest.update(field.len().to_string());
            digest.update(b":");
            digest.update(field.as_bytes());
        }
    };
    let schema = if replacement { "staged" } else { "main" };
    if replacement {
        bind(&["voltura-vault:rotation-replacement:v1".into()]);
    }
    let owner = db.query_row(&format!("SELECT encrypted_config,hex(account),hex(recovery) FROM {schema}.owner WHERE singleton=1"), [],
        |row| Ok([row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?]))?;
    bind(&owner);
    let mut revisions = db.prepare(&format!("SELECT CAST(seq AS TEXT),vault,object,revision,mutation,envelope FROM {schema}.revisions ORDER BY seq"))?;
    let mut rows = revisions.query([])?;
    while let Some(row) = rows.next()? {
        bind(&["revision".into(), row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?]);
    }
    let base = files::epoch_blobs(&directory.join("vault.blobs"), epoch);
    let mut attachments = db.prepare(&format!("SELECT CAST(published AS TEXT),vault,object,revision,size,manifest FROM {schema}.files
        WHERE published IS NOT NULL ORDER BY published"))?;
    let mut rows = attachments.query([])?;
    while let Some(row) = rows.next()? {
        let object: String = row.get(2)?;
        let size: u64 = row.get(4)?;
        if Uuid::parse_str(&object)?.to_string() != object || size > 100_000_000 {
            return Err("Invalid published attachment inventory".into());
        }
        bind(&["file".into(), row.get(0)?, row.get(1)?, object.clone(), row.get(3)?, size.to_string(), row.get(5)?]);
        let path = base.join(object);
        if !fs::symlink_metadata(&base)?.is_dir() || !fs::symlink_metadata(&path)?.is_dir() {
            return Err("Invalid published attachment directory".into());
        }
        for index in 0..files::count(size) {
            let chunk = path.join(index.to_string());
            if !fs::symlink_metadata(&chunk)?.is_file() {
                return Err("Invalid published attachment chunk".into());
            }
            let mut bytes = Vec::new();
            fs::File::open(chunk)?.take(1_048_594).read_to_end(&mut bytes)?;
            if bytes.len() > 1_048_593 { return Err("Published attachment chunk is too large".into()); }
            bind(&[STANDARD.encode(Sha256::digest(bytes))]);
        }
    }
    Ok(STANDARD.encode(digest.finalize()))
}

fn validate_quarantine(db: &Connection) -> Result<(u64, u64)> {
    let counts = db.query_row(
        "SELECT (SELECT count(*) FROM staged.quarantined_revisions),
                (SELECT count(*) FROM staged.quarantined_files)", [],
        |row| Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?)),
    )?;
    let revisions = db.execute(
        "INSERT INTO temp.rotation_excluded_revisions
         SELECT old.seq FROM main.revisions old JOIN staged.quarantined_revisions q
           ON q.seq=old.seq AND q.vault=old.vault AND q.object=old.object
           AND q.revision=old.revision AND q.mutation=old.mutation AND q.envelope=old.envelope
         WHERE NOT EXISTS (SELECT 1 FROM staged.revisions r WHERE r.seq=old.seq)", [],
    )?;
    let files = db.execute(
        "INSERT INTO temp.rotation_excluded_files
         SELECT old.published FROM main.files old JOIN staged.quarantined_files q
           ON q.published=old.published AND q.vault=old.vault AND q.object=old.object
           AND q.revision=old.revision AND q.size=old.size AND q.manifest=old.manifest
         WHERE NOT EXISTS (SELECT 1 FROM staged.files f WHERE f.published=old.published)", [],
    )?;
    if counts != (revisions as u64, files as u64) {
        return Err("Quarantine does not match the live encrypted entries".into());
    }
    if db.prepare(
        "SELECT 1 FROM staged.revisions AS child, json_each(child.envelope,'$.parents') AS edge
         WHERE NOT EXISTS (SELECT 1 FROM staged.revisions AS parent WHERE parent.revision=edge.value
           AND parent.vault=child.vault AND parent.object=child.object AND parent.seq<child.seq) LIMIT 1",
    )?.exists([])? {
        return Err("Replacement revision ancestry is incomplete".into());
    }
    Ok(counts)
}

fn validate_attachments(db: &Connection, directory: &Path, epoch: u32, excluded: u64) -> Result<()> {
    let counts: (u64, u64) = db.query_row(
        "SELECT (SELECT count(*) FROM main.files WHERE published IS NOT NULL),count(*) FROM staged.files",
        [], |row| Ok((row.get(0)?, row.get(1)?)))?;
    if counts.0 != counts.1 + excluded {
        return Err("Replacement changed the published attachment inventory".into());
    }
    if counts.1 == 0 {
        return Ok(());
    }
    let base = directory.join("vault.blobs");
    let epoch_root = files::epoch_blobs(&base, epoch);
    if !fs::symlink_metadata(&base)?.is_dir() || !fs::symlink_metadata(&epoch_root)?.is_dir() {
        return Err("Replacement attachment directory is invalid".into());
    }
    let mut statement = db.prepare(
        "SELECT old.object,old.size,old.manifest,new.manifest FROM main.files old LEFT JOIN staged.files new
          ON new.vault=old.vault AND new.object=old.object AND new.revision=old.revision
          AND new.size=old.size AND new.published=old.published WHERE old.published IS NOT NULL
          AND NOT EXISTS (SELECT 1 FROM temp.rotation_excluded_files q WHERE q.published=old.published)")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let object: String = row.get(0)?;
        let size: u64 = row.get(1)?;
        let previous: String = row.get(2)?;
        let manifest: String = row
            .get::<_, Option<String>>(3)?
            .ok_or("Replacement is missing an attachment")?;
        if Uuid::parse_str(&object)?.to_string() != object
            || size > 100_000_000
            || manifest == previous
            || manifest.len() > 8192
            || STANDARD.decode(manifest)?.len() < 40
        {
            return Err("Replacement attachment metadata is invalid".into());
        }
        let path = epoch_root.join(object);
        if !fs::symlink_metadata(&path)?.is_dir() {
            return Err("Replacement attachment directory is invalid".into());
        }
        for index in 0..files::count(size) {
            let chunk = path.join(index.to_string());
            let metadata = fs::symlink_metadata(&chunk)?;
            let expected = (size - index * 1_048_576).min(1_048_576) + 17;
            if !metadata.is_file() || metadata.len() != expected {
                return Err("Replacement attachment chunk is incomplete".into());
            }
            fs::File::open(chunk)?.sync_all()?;
        }
        #[cfg(unix)]
        fs::File::open(path)?.sync_all()?;
    }
    #[cfg(unix)]
    {
        fs::File::open(epoch_root)?.sync_all()?;
        fs::File::open(base)?.sync_all()?;
    }
    Ok(())
}
