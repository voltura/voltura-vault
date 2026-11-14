use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use tower::ServiceExt;
use voltura_server_auth::SecretToken;
use voltura_vault_server::{AppState, initialize, now, router, router_with_unix_desktop};

const VAULT: &str = "00000000-0000-0000-0000-000000000001";
const HOST: &str = "vault-api.test";
const ORIGIN: &str = "https://vault-api.test";
static NEXT: AtomicU64 = AtomicU64::new(0);
const SYNC_DEVICE: &str = "40000000-0000-0000-0000-000000000001";

fn device_request(method: &str, device: &str, refresh: bool, token: &str) -> Request<Body> {
    let suffix = if refresh { "/refresh" } else { "" };
    let mut request = Fixture::request(method, &format!("/api/v1/sync-devices/{device}{suffix}"), Some(token),
        Some(json!({"vaultId":VAULT,"keyEpoch":1})));
    request.headers_mut().insert(header::ORIGIN, "https://tauri.localhost".parse().unwrap());
    if refresh { request.headers_mut().insert("x-vault-write-key", write_key().parse().unwrap()); }
    request
}

async fn response_json(response: Response) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap()
}

#[tokio::test]
async fn hello_sync_rotates_refreshes_and_revokes_on_replay_without_granting_account_access() {
    let f = Fixture::new();
    f.setup().await;
    let mut web = device_request("POST", SYNC_DEVICE, false, &f.account);
    web.headers_mut().insert(header::ORIGIN, "https://vault-ui.test".parse().unwrap());
    assert_eq!(f.call(web).await.status(), StatusCode::FORBIDDEN);
    let issued = response_json(f.call(device_request("POST", SYNC_DEVICE, false, &f.account)).await).await;
    let refresh = issued["refreshToken"].as_str().unwrap();
    assert_eq!(f.call(device_request("POST", SYNC_DEVICE, false, refresh)).await.status(), StatusCode::UNAUTHORIZED);
    let mut no_proof_key = device_request("POST", SYNC_DEVICE, true, refresh);
    no_proof_key.headers_mut().remove("x-vault-write-key");
    assert_eq!(f.call(no_proof_key).await.status(), StatusCode::FORBIDDEN);
    let renewed = response_json(f.call(device_request("POST", SYNC_DEVICE, true, refresh)).await).await;
    let access = renewed["token"].as_str().unwrap();
    let next = renewed["refreshToken"].as_str().unwrap();
    assert_ne!(refresh, next);
    assert_eq!(renewed["refreshExpiresAt"].as_u64().unwrap() - renewed["expiresAt"].as_u64().unwrap(), 30 * 86400 - 900);
    let changes = |token| Fixture::request("POST", "/api/v1/changes", Some(token), Some(json!({"cursor":"0"})));
    assert_eq!(f.call(changes(access)).await.status(), StatusCode::OK);
    assert_eq!(f.call(changes(next)).await.status(), StatusCode::UNAUTHORIZED);
    for path in ["/api/v1/source-archives/list", "/api/v1/recovery-kits/list",
        "/api/v1/source-archives/40000000-0000-0000-0000-000000000001/0", "/api/v1/recovery-kits/40000000-0000-0000-0000-000000000001/0"] {
        assert_eq!(f.call(Fixture::request("POST", path, Some(access), Some(json!({})))).await.status(), StatusCode::FORBIDDEN);
    }
    let mutation = json!({"version":1,"epoch":1,"objectId":"10000000-0000-0000-0000-000000000001",
        "revisionId":"20000000-0000-0000-0000-000000000001","mutationId":"30000000-0000-0000-0000-000000000001",
        "parents":[],"envelope":STANDARD.encode([1;144])});
    let submit = || Fixture::request("POST", "/api/v1/mutations", Some(access), Some(mutation.clone()));
    let mut unsigned = submit();
    unsigned.headers_mut().remove("x-vault-write-proof");
    assert_eq!(f.call(unsigned).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(f.call(submit()).await.status(), StatusCode::OK);
    let stranger = SecretToken::generate().unwrap().encode();
    assert_eq!(f.call(device_request("POST", SYNC_DEVICE, true, &stranger)).await.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(f.call(changes(access)).await.status(), StatusCode::OK);
    assert_eq!(f.call(device_request("POST", SYNC_DEVICE, true, refresh)).await.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(f.call(changes(access)).await.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(f.call(device_request("POST", SYNC_DEVICE, true, next)).await.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(f.call(changes(&f.login().await)).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn hello_sync_rejects_expired_devices_and_clears_access_on_disable_operator_revoke_or_restore() {
    let f = Fixture::new();
    f.setup().await;
    for action in ["expiry", "self revoke", "account revoke", "operator revoke", "restore"] {
        let issued = response_json(f.call(device_request("POST", SYNC_DEVICE, false, &f.account)).await).await;
        let refresh = issued["refreshToken"].as_str().unwrap();
        if action == "expiry" {
            let db = f.database();
            db.execute("UPDATE sync_devices SET expires=?1", [now()]).unwrap();
            assert_eq!(f.call(device_request("POST", SYNC_DEVICE, true, refresh)).await.status(), StatusCode::UNAUTHORIZED);
            continue;
        }
        let session = response_json(f.call(device_request("POST", SYNC_DEVICE, true, refresh)).await).await;
        match action {
            "self revoke" | "account revoke" => {
                let token = if action == "self revoke" { refresh } else { &f.account };
                assert_eq!(f.call(device_request("DELETE", SYNC_DEVICE, false, token)).await.status(), StatusCode::NO_CONTENT);
            }
            "operator revoke" => assert!(voltura_vault_server::revoke_sync_device(&f.directory, SYNC_DEVICE.parse().unwrap()).unwrap()),
            "restore" => voltura_vault_server::mark_restored(&mut f.database()).unwrap(),
            _ => unreachable!(),
        }
        assert_eq!(f.call(device_request("POST", SYNC_DEVICE, true, session["refreshToken"].as_str().unwrap())).await.status(), StatusCode::UNAUTHORIZED);
        let access = Fixture::request("GET", "/api/v1/session", session["token"].as_str(), None);
        assert_eq!(f.call(access).await.status(), StatusCode::UNAUTHORIZED);
        let db = f.database();
        assert_eq!(db.query_row("SELECT count(*) FROM used_sync_refreshes", [], |r| r.get::<_, u32>(0)).unwrap(), 0);
    }
}

#[tokio::test]
async fn schema_seven_migration_preserves_existing_access_and_writes() {
    let f = Fixture::new();
    f.setup().await;
    let token = f.login().await;
    let db = f.database();
    db.execute_batch("DROP INDEX sessions_device;
        ALTER TABLE sessions DROP COLUMN device;
        DROP TABLE used_sync_refreshes;
        DROP TABLE sync_devices;
        PRAGMA user_version=7;").unwrap();
    let upgraded = router(AppState::open(&f.directory.join("vault.sqlite3")).unwrap());
    let response = upgraded.oneshot(Fixture::request("POST", "/api/v1/mutations", Some(&token), Some(json!({
        "version":1,"epoch":1,"objectId":"10000000-0000-0000-0000-000000000001",
        "revisionId":"20000000-0000-0000-0000-000000000001","mutationId":"30000000-0000-0000-0000-000000000001",
        "parents":[],"envelope":STANDARD.encode([1;144])
    })))).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

fn write_pair() -> ring::signature::Ed25519KeyPair {
    ring::signature::Ed25519KeyPair::from_seed_unchecked(&[42; 32]).unwrap()
}

fn write_key() -> String {
    use ring::signature::KeyPair;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(write_pair().public_key())
}

fn proof(token: &str, method: &str, path: &str, body: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use voltura_server_auth::Purpose;
    let encode = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let vault = uuid::Uuid::parse_str(VAULT).unwrap().into_bytes();
    let verifier = SecretToken::parse(token).unwrap().verifier(vault, Purpose::Access);
    let hash = Sha256::digest(body);
    let message = format!("VolturaVault write v1\n{}\n{method}\n{path}\n{}",
        encode.encode(verifier.digest()), encode.encode(hash));
    encode.encode([&hash[..], write_pair().sign(message.as_bytes()).as_ref()].concat())
}


#[tokio::test]
async fn stolen_session_cannot_consume_storage_or_modify_an_active_upload() {
    let f = Fixture::new();
    f.setup().await;
    let token = f.login().await;
    let object = "10000000-0000-0000-0000-000000000001";
    let revision = "20000000-0000-0000-0000-000000000001";
    let manifest = json!({"objectId":object,"revisionId":revision,"size":0,"manifest":STANDARD.encode([42;96])});
    let mutation = json!({"version":1,"epoch":1,"objectId":object,"revisionId":revision,
        "mutationId":"30000000-0000-0000-0000-000000000001","parents":[],"envelope":STANDARD.encode([1;144])});
    for (path, body) in [("/api/v1/mutations", mutation.clone()), ("/api/v1/files", manifest.clone())] {
        let mut stolen = Fixture::request("POST", path, Some(&token), Some(body.clone()));
        stolen.headers_mut().remove("x-vault-write-proof");
        assert_eq!(f.call(stolen).await.status(), StatusCode::FORBIDDEN);
        let mut wrong = Fixture::request("POST", path, Some(&token), Some(body.clone()));
        let another = f.login().await;
        wrong.headers_mut().insert("x-vault-write-proof", proof(&another, "POST", path, body.to_string().as_bytes()).parse().unwrap());
        assert_eq!(f.call(wrong).await.status(), StatusCode::FORBIDDEN);
    }
    let db = f.database();
    for table in ["revisions", "files", "attachment_reservations"] {
        assert_eq!(db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get::<_, u32>(0)).unwrap(), 0);
    }
    let changes = Fixture::request("POST", "/api/v1/changes", Some(&token), Some(json!({"cursor":"0"})));
    assert_eq!(f.call(changes).await.status(), StatusCode::OK);
    assert_eq!(f.call(Fixture::request("POST", "/api/v1/mutations", Some(&token), Some(mutation))).await.status(), StatusCode::OK);
    assert_eq!(f.call(Fixture::request("POST", "/api/v1/files", Some(&token), Some(manifest))).await.status(), StatusCode::CREATED);

    let chunk = format!("/api/v1/files/{object}/chunks/0");
    let finish = format!("/api/v1/files/{object}/finish");
    let bytes = vec![0u8; 17];
    let upload = |signature: Option<String>, data: Vec<u8>| {
        let mut request = Fixture::request("POST", &chunk, Some(&token), None);
        request.headers_mut().remove("x-vault-write-proof");
        if let Some(signature) = signature {
            request.headers_mut().insert("x-vault-write-proof", signature.parse().unwrap());
        }
        *request.body_mut() = Body::from(data);
        request
    };
    let signed = proof(&token, "POST", &chunk, &bytes);
    assert_eq!(f.call(upload(None, bytes.clone())).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(f.call(upload(Some(signed.clone()), vec![1; 17])).await.status(), StatusCode::FORBIDDEN);
    let mut stolen_finish = Fixture::request("POST", &finish, Some(&token), None);
    stolen_finish.headers_mut().insert("x-vault-write-proof", signed.parse().unwrap());
    assert_eq!(f.call(stolen_finish).await.status(), StatusCode::FORBIDDEN);
    assert!(!f.directory.join("vault.blobs").join(object).exists());
    assert_eq!(f.call(upload(Some(proof(&token, "POST", &chunk, &bytes)), bytes)).await.status(), StatusCode::CREATED);
    assert_eq!(f.call(Fixture::request("POST", &finish, Some(&token), None)).await.status(), StatusCode::NO_CONTENT);
    assert_eq!(db.query_row("SELECT count(*) FROM files WHERE published IS NOT NULL", [], |r| r.get::<_, u32>(0)).unwrap(), 1);
}

#[tokio::test]
async fn deleting_a_file_requires_write_proof_and_prevents_reupload() {
    let f = Fixture::new();
    f.setup().await;
    let token = f.login().await;
    let object = "10000000-0000-0000-0000-000000000001";
    let revision = "20000000-0000-0000-0000-000000000001";
    let manifest = json!({"objectId":object,"revisionId":revision,"size":0,"manifest":STANDARD.encode([42;96])});
    let request = |path: &str, body| Fixture::request("POST", path, Some(&token), body);
    let delete = format!("/api/v1/files/{object}/delete");
    let deletion = json!({"objectId":object,"revisionId":revision,"epoch":1,"proof":STANDARD.encode([7;32])});
    assert_eq!(f.call(request("/api/v1/files", Some(manifest.clone()))).await.status(), StatusCode::CREATED);
    let chunk = format!("/api/v1/files/{object}/chunks/0");
    let mut upload = request(&chunk, None);
    upload.headers_mut().insert("x-vault-write-proof", proof(&token, "POST", &chunk, &[0; 17]).parse().unwrap());
    *upload.body_mut() = Body::from(vec![0; 17]);
    assert_eq!(f.call(upload).await.status(), StatusCode::CREATED);
    assert_eq!(f.call(request(&format!("/api/v1/files/{object}/finish"), None)).await.status(), StatusCode::NO_CONTENT);
    let mut stolen = request(&delete, Some(deletion.clone()));
    stolen.headers_mut().remove("x-vault-write-proof");
    assert_eq!(f.call(stolen).await.status(), StatusCode::FORBIDDEN);
    let mut wrong_revision = deletion.clone();
    wrong_revision["revisionId"] = json!(object);
    assert_eq!(f.call(request(&delete, Some(wrong_revision))).await.status(), StatusCode::CONFLICT);
    for _ in 0..2 {
        assert_eq!(f.call(request(&delete, Some(deletion.clone()))).await.status(), StatusCode::NO_CONTENT);
    }
    assert!(!f.directory.join("vault.blobs").join(object).exists());
    assert_eq!(f.call(request(&format!("/api/v1/files/{object}/read/0"), None)).await.status(), StatusCode::NOT_FOUND);
    assert_eq!(f.call(request("/api/v1/files", Some(manifest))).await.status(), StatusCode::CONFLICT);
    let inventory = f.call(request("/api/v1/files/list", None)).await;
    assert_eq!(to_bytes(inventory.into_body(), 4096).await.unwrap().as_ref(), b"[]");
    let changes = f.call(request("/api/v1/files/deleted", Some(json!({"objectIds":[object]})))).await;
    let body: Value = serde_json::from_slice(&to_bytes(changes.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(body, json!([deletion]));
}

#[tokio::test]
async fn expired_attachment_reservations_release_quota_and_remove_old_chunks() {
    let f = Fixture::new();
    f.setup().await;
    let token = f.login().await;
    let object = uuid::Uuid::from_u128(100 + NEXT.fetch_add(1, Ordering::Relaxed) as u128).to_string();
    let request = |path: &str, body| Fixture::request("POST", path, Some(&token), body);
    let begin = || json!({"objectId":object, "revisionId":uuid::Uuid::from_u128(100 + NEXT.fetch_add(1, Ordering::Relaxed) as u128),
        "size":100_000_000,"manifest":STANDARD.encode([42;96])});
    assert_eq!(f.call(request("/api/v1/files", Some(begin()))).await.status(), StatusCode::CREATED);
    let data = f.database();
    for _ in 0..9 {
        let id = uuid::Uuid::from_u128(100 + NEXT.fetch_add(1, Ordering::Relaxed) as u128).to_string();
        data.execute("INSERT INTO files VALUES(?1,?2,?3,100000000,?4,NULL)",
            rusqlite::params![VAULT, id, uuid::Uuid::from_u128(100 + NEXT.fetch_add(1, Ordering::Relaxed) as u128).to_string(), STANDARD.encode([42;96])]).unwrap();
        data.execute("INSERT INTO attachment_reservations VALUES(?1,?2,?3)", rusqlite::params![VAULT, id, now()+3600]).unwrap();
    }
    let oversized = json!({"objectId":uuid::Uuid::from_u128(100 + NEXT.fetch_add(1, Ordering::Relaxed) as u128), "revisionId":uuid::Uuid::from_u128(100 + NEXT.fetch_add(1, Ordering::Relaxed) as u128),
        "size":100_000_000,"manifest":STANDARD.encode([42;96])});
    assert_eq!(f.call(request("/api/v1/files", Some(oversized))).await.status(), StatusCode::INSUFFICIENT_STORAGE);
    let chunk = f.directory.join("vault.blobs").join(&object).join("0");
    std::fs::create_dir_all(chunk.parent().unwrap()).unwrap();
    std::fs::write(&chunk, [1;17]).unwrap();
    data.execute("UPDATE attachment_reservations SET expires=?1 WHERE object=?2",
        rusqlite::params![now(), object]).unwrap();
    assert_eq!(f.call(request(&format!("/api/v1/files/{object}/finish"), None)).await.status(), StatusCode::NOT_FOUND);
    assert_eq!(f.call(request("/api/v1/files", Some(begin()))).await.status(), StatusCode::CREATED);
    assert!(!chunk.exists());
}

#[tokio::test]
async fn rotation_guards_live_writes_and_atomically_replaces_credentials_and_files() {
    use voltura_server_auth::Purpose;
    use voltura_vault_server::rotation;
    use sha2::{Digest, Sha256};

    let f = Fixture::new();
    f.setup().await;
    let device = response_json(f.call(device_request("POST", SYNC_DEVICE, false, &f.account)).await).await;
    let refresh = device["refreshToken"].as_str().unwrap();
    let device_session = response_json(f.call(device_request("POST", SYNC_DEVICE, true, refresh)).await).await;
    let old_session = f.login().await;
    let old_point = rotation::inspect(&f.directory).unwrap();
    let object = "10000000-0000-0000-0000-000000000001";
    let revision = "20000000-0000-0000-0000-000000000001";
    let mutation = "30000000-0000-0000-0000-000000000001";
    let wire = |epoch, fill| json!({
        "version":1,"epoch":epoch,"objectId":object,"revisionId":revision,"mutationId":mutation,
        "parents":[],"envelope":STANDARD.encode([fill;144])
    });
    let request = |path, token, body| Fixture::request("POST", path, Some(token), body);
    assert_eq!(f.call(request("/api/v1/mutations", &old_session, Some(wire(1, 1)))).await.status(), StatusCode::OK);
    let db = f.database();
    db.execute("INSERT INTO files VALUES(?1,?2,?3,0,?4,1)",
        rusqlite::params![VAULT,object,revision,STANDARD.encode([1;40])]).unwrap();
    let old_blob = f.directory.join("vault.blobs").join(object).join("0");
    std::fs::create_dir(old_blob.parent().unwrap()).unwrap();
    std::fs::write(&old_blob, [1;17]).unwrap();
    let mut forged = wire(1, 8);
    let forged_revision = "20000000-0000-0000-0000-000000000002";
    forged["revisionId"] = json!(forged_revision);
    forged["mutationId"] = json!("30000000-0000-0000-0000-000000000002");
    forged["parents"] = json!([revision]);
    assert_eq!(f.call(request("/api/v1/mutations", &old_session, Some(forged))).await.status(), StatusCode::OK);
    let stage = f.directory.join("replacement.sqlite3");
    db.execute("VACUUM INTO ?1", [stage.to_str().unwrap()]).unwrap();
    let restored = f.directory.join("old-backup.sqlite3");
    db.execute("VACUUM INTO ?1", [restored.to_str().unwrap()]).unwrap();
    let stage_db = Connection::open(&stage).unwrap();
    let vault_id = uuid::Uuid::parse_str(VAULT).unwrap().into_bytes();
    let account = SecretToken::generate().unwrap();
    let recovery = SecretToken::generate().unwrap();
    let encrypted_box = json!({"nonce":STANDARD.encode([3;24]),"ciphertext":STANDARD.encode([4;48])});
    let config = STANDARD.encode(json!({"version":1,"context":{"vaultId":VAULT,"epoch":2,
        "objectId":object,"revisionId":revision}, "kdf":{"algorithm":"argon2id13",
        "memory":67108864,"passes":3,"salt":STANDARD.encode([5;16])},
        "root":encrypted_box,"account":encrypted_box,"recoveryDevice":encrypted_box,
        "identifiers":{"nonce":STANDARD.encode([6;24]),"ciphertext":STANDARD.encode([7;112])}}).to_string());
    let account_verifier = account.verifier(vault_id, Purpose::Account);
    let recovery_verifier = recovery.verifier(vault_id, Purpose::Recovery);
    stage_db.execute("UPDATE owner SET key_epoch=2,account=?1,recovery=?2,encrypted_config=?3",
        rusqlite::params![account_verifier.digest(), recovery_verifier.digest(), config]).unwrap();
    stage_db.execute_batch("CREATE TABLE quarantined_revisions AS SELECT * FROM revisions WHERE seq=2;
        CREATE TABLE quarantined_files AS SELECT * FROM files WHERE 0;
        DELETE FROM revision_heads;
        DELETE FROM revisions WHERE seq=2;").unwrap();
    let envelope = wire(2, 2).to_string();
    let manifest = STANDARD.encode([2;40]);
    stage_db.execute("UPDATE revisions SET envelope=?1", [&envelope]).unwrap();
    stage_db.execute("UPDATE files SET manifest=?1", [&manifest]).unwrap();
    drop(stage_db);

    let floor = f.directory.join("epoch-floor");
    std::fs::write(&floor, "1\n").unwrap();
    let shared = std::fs::File::create(f.directory.join("maintenance.lock")).unwrap();
    shared.lock_shared().unwrap();
    let point_path = f.directory.join("rotation-point.json");
    std::fs::write(&point_path, serde_json::to_vec(&old_point).unwrap()).unwrap();
    let executable = env!("CARGO_BIN_EXE_voltura-vault-server");
    let refused = std::process::Command::new(executable).arg("activate-rotation")
        .arg(&f.directory).arg(&stage).arg(&point_path).env("VOLTURA_KEY_EPOCH_FLOOR", &floor).output().unwrap();
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("Stop the Vault API"));
    drop(shared);
    assert!(rotation::activate(&f.directory, &stage, &old_point, &floor).unwrap_err().to_string().contains("changed"));
    let expected = rotation::inspect_quarantine(&f.directory).unwrap();
    let mut point = serde_json::to_value(&expected).unwrap();
    let mut digest = Sha256::new();
    let hex = |bytes: &[u8]| bytes.iter().map(|byte| format!("{byte:02X}")).collect::<String>();
    for field in ["voltura-vault:rotation-replacement:v1", &config, &hex(account_verifier.digest()),
        &hex(recovery_verifier.digest()), "revision", "1", VAULT, object, revision, mutation, &envelope,
        "file", "1", VAULT, object, revision, "0", &manifest, &STANDARD.encode(Sha256::digest([2;17]))] {
        digest.update(format!("{}:{field}", field.len()));
    }
    point["replacementInventory"] = json!(STANDARD.encode(digest.finalize()));
    let trusted = serde_json::from_value(point.clone()).unwrap();
    std::fs::write(&old_blob, [9;17]).unwrap();
    assert!(rotation::activate_with_quarantine(&f.directory, &stage, &trusted, &floor, true)
        .unwrap_err().to_string().contains("changed"));
    std::fs::write(&old_blob, [1;17]).unwrap();
    let blob = f.directory.join("vault.blobs").join("epoch-2").join(object).join("0");
    std::fs::create_dir_all(blob.parent().unwrap()).unwrap();
    std::fs::write(&blob, [2;16]).unwrap();
    assert!(rotation::activate(&f.directory, &stage, &expected, &floor).is_err());
    assert!(rotation::activate_with_quarantine(&f.directory, &stage, &trusted, &floor, true).unwrap_err().to_string().contains("incomplete"));
    assert_eq!(rotation::read_epoch_floor(&floor).unwrap(), 1);
    assert_eq!(rotation::inspect_quarantine(&f.directory).unwrap(), expected);
    assert_eq!(f.call(request("/api/v1/changes", &old_session, Some(json!({"cursor":"0"})))).await.status(), StatusCode::OK);
    std::fs::write(&blob, [9;17]).unwrap();
    assert!(rotation::activate_with_quarantine(&f.directory, &stage, &trusted, &floor, true)
        .unwrap_err().to_string().contains("Replacement inventory"));
    assert_eq!(rotation::read_epoch_floor(&floor).unwrap(), 1);
    std::fs::write(&blob, [2;17]).unwrap();
    assert!(rotation::activate_with_quarantine(&f.directory, &stage, &expected, &floor, true)
        .unwrap_err().to_string().contains("trusted staging record"));
    let stage_db = Connection::open(&stage).unwrap();
    stage_db.execute("UPDATE revisions SET envelope=?1", [wire(2, 9).to_string()]).unwrap();
    assert!(rotation::activate_with_quarantine(&f.directory, &stage, &trusted, &floor, true)
        .unwrap_err().to_string().contains("Replacement inventory"));
    assert_eq!(rotation::read_epoch_floor(&floor).unwrap(), 1);
    stage_db.execute("UPDATE revisions SET envelope=?1", [&envelope]).unwrap();
    stage_db.execute("UPDATE files SET manifest=?1", [STANDARD.encode([9;40])]).unwrap();
    assert!(rotation::activate_with_quarantine(&f.directory, &stage, &trusted, &floor, true)
        .unwrap_err().to_string().contains("Replacement inventory"));
    assert_eq!(rotation::read_epoch_floor(&floor).unwrap(), 1);
    stage_db.execute("UPDATE files SET manifest=?1", [&manifest]).unwrap();
    drop(stage_db);
    std::fs::write(&point_path, serde_json::to_vec(&trusted).unwrap()).unwrap();
    let activated = std::process::Command::new(executable).arg("activate-rotation")
        .arg(&f.directory).arg(&stage).arg(&point_path).arg("--quarantine-invalid")
        .env("VOLTURA_KEY_EPOCH_FLOOR", &floor).output().unwrap();
    assert!(activated.status.success(), "{}", String::from_utf8_lossy(&activated.stderr));
    assert_ne!(rotation::inspect_quarantine(&f.directory).unwrap(), expected);
    assert_eq!(std::fs::read(old_blob).unwrap(), [1;17]);
    let head: String = db.query_row("SELECT revision FROM revision_heads", [], |row| row.get(0)).unwrap();
    assert_eq!(head, revision);
    let minimum = rotation::read_epoch_floor(&floor).unwrap();
    assert_eq!(minimum, 2);
    assert!(AppState::open_at_least(&restored, minimum).is_err());
    let active_database = f.directory.join("vault.sqlite3");
    assert!(AppState::open_with_epoch(&active_database, 1, Some(minimum)).is_ok());
    assert!(AppState::open_with_epoch(&active_database, 1, Some(1)).is_err());
    assert_eq!(f.call(request("/api/v1/changes", &old_session, Some(json!({"cursor":"0"})))).await.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(f.call(device_request("POST", SYNC_DEVICE, true, device_session["refreshToken"].as_str().unwrap())).await.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(db.query_row("SELECT count(*) FROM sync_devices", [], |r| r.get::<_, u32>(0)).unwrap(), 0);
    let login = |token| request("/api/v1/sessions", token, Some(json!({"vaultId":VAULT,"client":"native"})));
    assert_eq!(f.call(login(&f.account)).await.status(), StatusCode::UNAUTHORIZED);
    let account_token = account.encode();
    let response = f.call(login(account_token.as_str())).await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
    let session: Value = serde_json::from_slice(&bytes).unwrap();
    let token = session["token"].as_str().unwrap();
    assert_eq!(f.call(request("/api/v1/mutations", token, Some(wire(1, 1)))).await.status(), StatusCode::CONFLICT);
    let response = f.call(request("/api/v1/changes", token, Some(json!({"cursor":"0"})))).await;
    let feed: Value = serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(feed["revisions"], json!([wire(2, 2)]));
    let response = f.call(request(&format!("/api/v1/files/{object}/read/0"), token, None)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(to_bytes(response.into_body(), 4096).await.unwrap().as_ref(), &[2;17]);
}

struct Fixture {
    app: Router,
    directory: PathBuf,
    bootstrap: String,
    account: String,
    recovery: String,
}
impl Fixture {
    fn new() -> Self {
        Self::with_unix_desktop(false)
    }

    fn with_unix_desktop(enable_unix_desktop: bool) -> Self {
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "voltura-http-test-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let bootstrap = SecretToken::generate().unwrap();
        let mut db = Connection::open(directory.join("vault.sqlite3")).unwrap();
        initialize(&mut db, &bootstrap, now()).unwrap();
        drop(db);
        let app = router_with_unix_desktop(
            AppState::open(&directory.join("vault.sqlite3")).unwrap(),
            enable_unix_desktop,
        );
        Self {
            app,
            directory,
            bootstrap: bootstrap.encode().to_string(),
            account: SecretToken::generate().unwrap().encode().to_string(),
            recovery: SecretToken::generate().unwrap().encode().to_string(),
        }
    }
    fn request(
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> Request<Body> {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, HOST);
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let body = match body {
            Some(value) => {
                request = request.header(header::CONTENT_TYPE, "application/json");
                value.to_string()
            }
            None => String::new(),
        };
        if path == "/api/v1/sessions" && method == "POST" {
            request = request.header("x-vault-write-key", write_key());
        }
        if method == "POST" && (path == "/api/v1/mutations" || path == "/api/v1/files"
            || path.ends_with("/finish") || path.ends_with("/delete") || path.contains("/chunks/")) {
            if let Some(token) = token {
                request = request.header("x-vault-write-proof", proof(token, method, path, body.as_bytes()));
            }
        }
        request.body(Body::from(body)).unwrap()
    }
    async fn call(&self, request: Request<Body>) -> Response {
        self.app.clone().oneshot(request).await.unwrap()
    }
    fn setup_body(&self) -> Value {
        json!({"vaultId":VAULT,"accountToken":self.account,"recoveryToken":self.recovery,"encryptedConfig":STANDARD.encode([42;64])})
    }
    async fn setup(&self) {
        assert_eq!(
            self.call(Self::request(
                "POST",
                "/api/v1/bootstrap",
                Some(&self.bootstrap),
                Some(self.setup_body())
            ))
            .await
            .status(),
            StatusCode::CREATED
        );
    }
    async fn login(&self) -> String {
        let response = self
            .call(Self::request(
                "POST",
                "/api/v1/sessions",
                Some(&self.account),
                Some(json!({"vaultId":VAULT,"client":"native"})),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        serde_json::from_slice::<Value>(&body).unwrap()["token"]
            .as_str()
            .unwrap()
            .to_owned()
    }
    fn database(&self) -> Connection {
        Connection::open(self.directory.join("vault.sqlite3")).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Only this fixture's fresh directory under the OS temporary directory.
        // On Windows an active SQLite connection may keep WAL files open; leave
        // them for OS temp cleanup instead of forcing deletion or hiding errors.
        let root = std::env::temp_dir().canonicalize().unwrap();
        if let Ok(path) = self.directory.canonicalize() {
            assert!(path.starts_with(&root) && path != root);
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

#[tokio::test]
async fn sync_preserves_concurrent_revisions_and_replays_across_restart() {
    let f = Fixture::new();
    f.setup().await;
    let session = f.login().await;
    let object = "10000000-0000-0000-0000-000000000001";
    let id = |n| format!("20000000-0000-0000-0000-{n:012}");
    let revision = |n, parents: Vec<String>| {
        json!({
            "version":1,"epoch":1,"objectId":object,
            "revisionId":id(n),"mutationId":id(n + 10),"parents":parents,
            "envelope":STANDARD.encode([n as u8; 96])
        })
    };
    let submit = |body| Fixture::request("POST", "/api/v1/mutations", Some(&session), Some(body));
    let original = revision(1, vec![]);
    assert_eq!(
        f.call(submit(original.clone())).await.status(),
        StatusCode::OK
    );
    for n in [2, 3] {
        assert_eq!(
            f.call(submit(revision(n, vec![id(1)]))).await.status(),
            StatusCode::OK
        );
    }
    let app = router(AppState::open(&f.directory.join("vault.sqlite3")).unwrap());
    assert_eq!(
        app.clone()
            .oneshot(submit(original.clone()))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let mut altered = original;
    altered["envelope"] = json!(STANDARD.encode([99; 96]));
    assert_eq!(f.call(submit(altered)).await.status(), StatusCode::CONFLICT);
    assert_eq!(
        f.call(submit(revision(4, vec![id(9)]))).await.status(),
        StatusCode::CONFLICT
    );
    let request = Fixture::request(
        "POST",
        "/api/v1/changes",
        Some(&session),
        Some(json!({"cursor":"1"})),
    );
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(body["cursor"], "3");
    assert_eq!(body["more"], false);
    assert_eq!(body["revisions"], json!([revision(2, vec![id(1)]),revision(3, vec![id(1)])]));
    let generation = body["generation"].as_str().unwrap();
    assert_eq!(generation.len(), 32);
    let db = f.database();
    let heads: Vec<String> = db
        .prepare("SELECT revision FROM revision_heads ORDER BY revision")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(heads, [id(2), id(3)]);
    assert_eq!(
        f.call(submit(revision(4, vec![id(2), id(3)])))
            .await
            .status(),
        StatusCode::OK
    );
    let head: String = db
        .query_row("SELECT revision FROM revision_heads", [], |r| r.get(0))
        .unwrap();
    assert_eq!(head, id(4));
    assert_eq!(
        f.call(Fixture::request(
            "POST",
            "/api/v1/changes",
            Some(&f.account),
            Some(json!({}))
        ))
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    voltura_vault_server::mark_restored(&mut f.database()).unwrap();
    let new_session = f.login().await;
    let stale = Fixture::request(
        "POST", "/api/v1/changes", Some(&new_session),
        Some(json!({"cursor":"3","generation":generation})),
    );
    let response = f.call(stale).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(body["error"], "sync_generation_changed");
}

#[tokio::test]
async fn file_chunks_are_immutable_and_hidden_until_publish() {
    let f = Fixture::new();
    f.setup().await;
    let token = f.login().await;
    let object = "10000000-0000-0000-0000-000000000001";
    let revision = "20000000-0000-0000-0000-000000000001";
    let begin = json!({"objectId":object,"revisionId":revision,"size":1_048_577,"manifest":STANDARD.encode([42;96])});
    let request = |path: &str, value| Fixture::request("POST", path, Some(&token), value);
    let upload = |index, bytes: Vec<u8>| {
        let path = format!("/api/v1/files/{object}/chunks/{index}");
        let signature = proof(&token, "POST", &path, &bytes);
        Request::builder()
            .method("POST")
            .uri(path)
            .header("x-vault-write-proof", signature)
            .header(header::HOST, HOST)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(Body::from(bytes))
            .unwrap()
    };
    let finish = format!("/api/v1/files/{object}/finish");
    let read = format!("/api/v1/files/{object}/read/1");
    let tail = vec![23u8; 18];
    assert_eq!(
        f.call(request("/api/v1/files", Some(begin.clone())))
            .await
            .status(),
        StatusCode::CREATED
    );
    assert_eq!(
        f.call(upload(1, tail.clone())).await.status(),
        StatusCode::CREATED
    );
    assert_eq!(
        f.call(upload(1, tail.clone())).await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.call(upload(1, vec![12u8; 18])).await.status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        f.call(request(&finish, None)).await.status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        f.call(request(&read, None)).await.status(),
        StatusCode::NOT_FOUND
    );
    let hidden = f.call(request("/api/v1/files/list", None)).await;
    assert_eq!(
        to_bytes(hidden.into_body(), 4096).await.unwrap().as_ref(),
        b"[]"
    );
    let reopened = router(AppState::open(&f.directory.join("vault.sqlite3")).unwrap());
    assert_eq!(
        reopened
            .clone()
            .oneshot(upload(0, vec![35u8; 1_048_593]))
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    assert_eq!(
        reopened
            .clone()
            .oneshot(request(&finish, None))
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    let response = reopened.oneshot(request(&read, None)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body(), 4096).await.unwrap().as_ref(),
        tail.as_slice()
    );
}

#[tokio::test]
async fn bootstrap_is_single_use_and_exposes_only_encrypted_configuration() {
    let f = Fixture::new();
    f.setup().await;
    assert_eq!(
        f.call(Fixture::request(
            "POST",
            "/api/v1/bootstrap",
            Some(&f.bootstrap),
            Some(f.setup_body())
        ))
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    let response = f
        .call(Fixture::request("GET", "/api/v1/config", None, None))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        !text.contains(&f.account) && !text.contains(&f.recovery) && !text.contains(&f.bootstrap)
    );
    let db = f.database();
    assert_eq!(
        db.query_row::<u32, _, _>("SELECT count(*) FROM bootstrap", [], |r| r.get(0))
            .unwrap(),
        0
    );
    let hashes: (Vec<u8>, Vec<u8>) = db
        .query_row("SELECT account,recovery FROM owner", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(hashes.0.len(), 32);
    assert_eq!(hashes.1.len(), 32);
}

#[tokio::test]
async fn session_sign_in_and_logout_survive_reopening_database() {
    let f = Fixture::new();
    f.setup().await;
    let token = f.login().await;
    let reopened = router(AppState::open(&f.directory.join("vault.sqlite3")).unwrap());
    assert_eq!(
        reopened
            .clone()
            .oneshot(Fixture::request(
                "GET",
                "/api/v1/session",
                Some(&token),
                None
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        f.call(Fixture::request(
            "DELETE",
            "/api/v1/session",
            Some(&token),
            None
        ))
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        reopened
            .oneshot(Fixture::request(
                "GET",
                "/api/v1/session",
                Some(&token),
                None
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn account_recovery_and_setup_tokens_cannot_act_as_sessions() {
    let f = Fixture::new();
    f.setup().await;
    for token in [&f.account, &f.recovery, &f.bootstrap] {
        assert_eq!(
            f.call(Fixture::request(
                "GET",
                "/api/v1/session",
                Some(token),
                None
            ))
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        f.call(Fixture::request(
            "POST",
            "/api/v1/sessions",
            Some(&f.recovery),
            Some(json!({"vaultId":VAULT,"client":"native"}))
        ))
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn separate_client_origins_have_bearer_access_without_browser_cookies() {
    const DESKTOP: &str = "https://tauri.localhost";
    const WEB: &str = "https://vault-ui.test";
    let f = Fixture::new();
    f.setup().await;
    for origin in [
        DESKTOP,
        WEB,
        "http://tauri.localhost",
        "tauri://localhost",
        "https://tauri.localhost.invalid",
        "https://vault-ui.test.invalid",
    ] {
        let mut request = Fixture::request("OPTIONS", "/api/v1/sessions", None, None);
        request
            .headers_mut()
            .insert(header::ORIGIN, origin.parse().unwrap());
        let response = f.call(request).await;
        if [DESKTOP, WEB].contains(&origin) {
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            assert_eq!(
                response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
                origin
            );
            assert!(
                !response
                    .headers()
                    .contains_key(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            );
        } else {
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert!(
                !response
                    .headers()
                    .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            );
        }
    }
    let token = f.login().await;
    for origin in [DESKTOP, WEB] {
        let mut request = Fixture::request("GET", "/api/v1/session", Some(&token), None);
        request
            .headers_mut()
            .insert(header::ORIGIN, origin.parse().unwrap());
        assert_eq!(f.call(request).await.status(), StatusCode::OK);
        let mut request = Fixture::request("GET", "/api/v1/session", None, None);
        request
            .headers_mut()
            .insert(header::ORIGIN, origin.parse().unwrap());
        request.headers_mut().insert(
            header::COOKIE,
            format!("__Host-vault_session={token}").parse().unwrap(),
        );
        assert_eq!(f.call(request).await.status(), StatusCode::FORBIDDEN);
    }
}

#[tokio::test]
async fn unix_desktop_is_opt_in_and_requires_bearer_access() {
    let f = Fixture::with_unix_desktop(true);
    f.setup().await;
    let token = f.login().await;
    for (origin, status) in [
        ("tauri://localhost", StatusCode::NO_CONTENT),
        ("null", StatusCode::FORBIDDEN),
        ("tauri://localhost.invalid", StatusCode::FORBIDDEN),
        ("tauri://localhost:443", StatusCode::FORBIDDEN),
    ] {
        let mut request = Fixture::request("OPTIONS", "/api/v1/session", None, None);
        request.headers_mut().insert(header::ORIGIN, origin.parse().unwrap());
        let response = f.call(request).await;
        assert_eq!(response.status(), status);
        if status == StatusCode::NO_CONTENT {
            assert_eq!(response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], origin);
            assert!(!response.headers().contains_key(header::ACCESS_CONTROL_ALLOW_CREDENTIALS));
        }
    }
    for (bearer, cookie, status) in [
        (Some(token.as_str()), false, StatusCode::OK),
        (None, false, StatusCode::UNAUTHORIZED),
        (None, true, StatusCode::FORBIDDEN),
    ] {
        let mut request = Fixture::request("GET", "/api/v1/session", bearer, None);
        request.headers_mut().insert(header::ORIGIN, "tauri://localhost".parse().unwrap());
        if cookie {
            request.headers_mut().insert(
                header::COOKIE,
                format!("__Host-vault_session={token}").parse().unwrap(),
            );
        }
        assert_eq!(f.call(request).await.status(), status);
    }
}

#[tokio::test]
async fn cookies_are_protected_and_mutations_require_the_exact_origin() {
    let f = Fixture::new();
    f.setup().await;
    let mut request = Fixture::request(
        "POST",
        "/api/v1/sessions",
        Some(&f.account),
        Some(json!({"vaultId":VAULT,"client":"browser"})),
    );
    request
        .headers_mut()
        .insert(header::ORIGIN, ORIGIN.parse().unwrap());
    let response = f.call(request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .to_owned();
    for flag in [
        "Secure",
        "HttpOnly",
        "SameSite=Strict",
        "Path=/",
        "Max-Age=900",
    ] {
        assert!(cookie.contains(flag));
    }
    let pair = cookie.split(';').next().unwrap();
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    assert!(
        serde_json::from_slice::<Value>(&body)
            .unwrap()
            .get("token")
            .is_none()
    );
    for origin in [None, Some("https://evil.invalid"), Some(ORIGIN)] {
        let mut request = Fixture::request("DELETE", "/api/v1/session", None, None);
        request
            .headers_mut()
            .insert(header::COOKIE, pair.parse().unwrap());
        if let Some(origin) = origin {
            request
                .headers_mut()
                .insert(header::ORIGIN, origin.parse().unwrap());
        }
        assert_eq!(
            f.call(request).await.status(),
            if origin == Some(ORIGIN) {
                StatusCode::NO_CONTENT
            } else {
                StatusCode::FORBIDDEN
            }
        );
    }
}

#[tokio::test]
async fn browser_login_cannot_skip_origin_and_credentials_cannot_be_ambiguous() {
    let f = Fixture::new();
    f.setup().await;
    assert_eq!(
        f.call(Fixture::request(
            "POST",
            "/api/v1/sessions",
            Some(&f.account),
            Some(json!({"vaultId":VAULT,"client":"browser"}))
        ))
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    let token = f.login().await;
    let mut both = Fixture::request("GET", "/api/v1/session", Some(&token), None);
    both.headers_mut().insert(
        header::COOKIE,
        format!("__Host-vault_session={token}").parse().unwrap(),
    );
    assert_eq!(f.call(both).await.status(), StatusCode::BAD_REQUEST);
    let mut duplicate = Fixture::request("GET", "/api/v1/session", None, None);
    duplicate.headers_mut().insert(
        header::COOKIE,
        format!("__Host-vault_session={token}; __Host-vault_session={token}")
            .parse()
            .unwrap(),
    );
    assert_eq!(f.call(duplicate).await.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn expired_or_not_yet_issued_sessions_are_rejected() {
    let f = Fixture::new();
    f.setup().await;
    let token = f.login().await;
    f.database()
        .execute("UPDATE sessions SET expires=?1", [now()])
        .unwrap();
    assert_eq!(
        f.call(Fixture::request(
            "GET",
            "/api/v1/session",
            Some(&token),
            None
        ))
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    f.database()
        .execute(
            "UPDATE sessions SET issued=?1,expires=?2",
            [now() + 60, now() + 900],
        )
        .unwrap();
    assert_eq!(
        f.call(Fixture::request(
            "GET",
            "/api/v1/session",
            Some(&token),
            None
        ))
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn expired_setup_token_cannot_create_an_owner() {
    let f = Fixture::new();
    f.database()
        .execute("UPDATE bootstrap SET expires=?1", [now()])
        .unwrap();
    assert_eq!(
        f.call(Fixture::request(
            "POST",
            "/api/v1/bootstrap",
            Some(&f.bootstrap),
            Some(f.setup_body())
        ))
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        f.database()
            .query_row::<u32, _, _>("SELECT count(*) FROM owner", [], |r| r.get(0))
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn host_origin_and_query_checks_block_untrusted_requests() {
    let f = Fixture::new();
    for (name, value) in [
        (header::HOST, "evil.invalid"),
        (header::ORIGIN, "https://evil.invalid"),
    ] {
        let mut request = Fixture::request("GET", "/api/v1/config", None, None);
        request.headers_mut().insert(name, value.parse().unwrap());
        assert_eq!(f.call(request).await.status(), StatusCode::FORBIDDEN);
    }
    let mut duplicate = Fixture::request("GET", "/api/v1/config", None, None);
    duplicate
        .headers_mut()
        .append(header::HOST, "evil.invalid".parse().unwrap());
    assert_eq!(f.call(duplicate).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        f.call(Fixture::request(
            "GET",
            "/api/v1/config?token=anything",
            None,
            None
        ))
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn repeated_wrong_credentials_cannot_block_owner_login() {
    let f = Fixture::new();
    f.setup().await;
    for _ in 0..5 {
        assert_eq!(
            f.call(Fixture::request(
                "POST",
                "/api/v1/sessions",
                Some(&f.recovery),
                Some(json!({"vaultId":VAULT,"client":"native"}))
            ))
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        f.call(Fixture::request(
            "POST",
            "/api/v1/sessions",
            Some(&f.recovery),
            Some(json!({"vaultId":VAULT,"client":"native"}))
        ))
        .await
        .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        f.call(Fixture::request(
            "POST",
            "/api/v1/sessions",
            Some(&f.account),
            Some(json!({"vaultId":VAULT,"client":"native"}))
        ))
        .await
        .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn malformed_or_oversized_setup_does_not_consume_the_token() {
    let f = Fixture::new();
    let mut shared = f.setup_body();
    shared["recoveryToken"] = json!(f.account);
    assert_eq!(
        f.call(Fixture::request(
            "POST",
            "/api/v1/bootstrap",
            Some(&f.bootstrap),
            Some(shared)
        ))
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    let mut huge = f.setup_body();
    huge["encryptedConfig"] = json!("A".repeat(100_000));
    assert_eq!(
        f.call(Fixture::request(
            "POST",
            "/api/v1/bootstrap",
            Some(&f.bootstrap),
            Some(huge)
        ))
        .await
        .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    f.setup().await;
}

#[tokio::test]
async fn configured_discovery_and_origin_boundary() {
    use voltura_vault_server::{Boundary, router_configured};
    let f = Fixture::new();
    let boundary = Boundary::configured("vault.example.test:8443", Some("https://ui.example.test")).unwrap();
    let app = router_configured(AppState::open(&f.directory.join("vault.sqlite3")).unwrap(), boundary);
    let query = |host: &str, origin: Option<&str>| {
        let mut req = Request::builder().uri("/api/v1/discovery").header("host", host);
        if let Some(origin) = origin { req = req.header("origin", origin); }
        req.body(Body::empty()).unwrap()
    };
    let host = "vault.example.test:8443";
    let call = |host, origin| app.clone().oneshot(query(host, origin));
    assert_eq!(call("vault.example.test", None).await.unwrap().status(), 403);
    assert_eq!(call(host, Some("https://tauri.localhost")).await.unwrap().status(), 403);
    let first = call(host, Some("https://ui.example.test")).await.unwrap();
    assert_eq!(first.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "https://ui.example.test");
    let read = |response: Response| async move {
        serde_json::from_slice::<Value>(&to_bytes(response.into_body(), 2048).await.unwrap()).unwrap()
    };
    assert_eq!(read(first).await, json!({"protocolVersion":1,"setupRequired":true}));
    f.setup().await;
    let second = call(host, None).await.unwrap();
    assert_eq!(read(second).await, json!({"protocolVersion":1,"setupRequired":false,"vaultId":VAULT}));
    let device = |token: &str, refresh: bool, origin: Option<&str>| {
        let mut request = device_request("POST", SYNC_DEVICE, refresh, token);
        request.headers_mut().insert(header::HOST, host.parse().unwrap());
        request.headers_mut().remove(header::ORIGIN);
        if let Some(origin) = origin { request.headers_mut().insert(header::ORIGIN, origin.parse().unwrap()); }
        request
    };
    let denied = app.clone().oneshot(device(&f.account, false, Some("https://ui.example.test"))).await.unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let enrolled = response_json(app.clone().oneshot(device(&f.account, false, None)).await.unwrap()).await;
    let refreshed = app.oneshot(device(enrolled["refreshToken"].as_str().unwrap(), true, None)).await.unwrap();
    assert_eq!(refreshed.status(), StatusCode::OK);
    assert!(Boundary::configured("vault.example.test/path", None).is_err());
    assert!(Boundary::configured(host, Some("https://ui.example.test/")).is_err());
}

#[test]
fn renew_setup_only_replaces_expired_code_on_empty_vault() {
    use voltura_vault_server::renew_expired_setup;
    let mut db = Connection::open_in_memory().unwrap();
    let first = SecretToken::generate().unwrap();
    let next = SecretToken::generate().unwrap();
    initialize(&mut db, &first, 100).unwrap();
    assert!(renew_expired_setup(&mut db, &next, 999).is_err());
    renew_expired_setup(&mut db, &next, 1000).unwrap();
    assert!(renew_expired_setup(&mut db, &first, 1001).is_err());
    db.execute("DELETE FROM bootstrap", []).unwrap();
    assert!(renew_expired_setup(&mut db, &first, 2000).is_err());
}
