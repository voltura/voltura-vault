use std::{
    error::Error,
    fs,
    io::{Read, Write},
    path::PathBuf,
    time::Duration,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::{Client, Method, Url, header::HeaderValue};
use serde::{Deserialize, Serialize};
use tauri::{Manager, WebviewWindow, ipc::Response};
use tokio::sync::Mutex;
use uuid::Uuid;

const MAX_CA: usize = 32 * 1024;
const MAX_PROFILE: usize = 50 * 1024;
const MAX_REQUEST: usize = 1_404_096;

#[derive(Default)]
pub struct Transport(Mutex<Option<Target>>);

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Profile {
    url: String,
    vault_id: Option<Uuid>,
    ca: Option<String>,
}

struct Target {
    profile: Profile,
    client: Client,
    saved: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Discovery {
    protocol_version: u32,
    setup_required: bool,
    vault_id: Option<Uuid>,
}

fn canonical(value: &str) -> Result<String, String> {
    let error = "Enter an HTTPS server URL without credentials, a path, query or fragment.";
    let authority = value.strip_prefix("https://").ok_or(error)?;
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    if authority.is_empty()
        || value.len() > 2048
        || authority
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "/\\@?#%".contains(c))
        || authority.ends_with(':')
    {
        return Err(error.into());
    }
    let url = Url::parse(value).map_err(|_| error)?;
    if url.scheme() != "https"
        || url.host().is_none()
        || url.port() == Some(0)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(error.into());
    }
    Ok(url.origin().ascii_serialization())
}

fn certificate(encoded: &str, check_time: bool) -> Result<reqwest::Certificate, String> {
    use x509_parser::prelude::*;
    let error = "Select one valid public CA certificate in PEM or DER format.";
    if encoded.len() > MAX_CA.div_ceil(3) * 4 {
        return Err(error.into());
    }
    let bytes = STANDARD.decode(encoded).map_err(|_| error)?;
    if bytes.len() > MAX_CA {
        return Err(error.into());
    }
    let der = if let Ok(text) = std::str::from_utf8(&bytes) {
        let text = text.trim();
        let data = text
            .strip_prefix("-----BEGIN CERTIFICATE-----")
            .and_then(|text| text.strip_suffix("-----END CERTIFICATE-----"))
            .ok_or(error)?;
        STANDARD
            .decode(data.split_ascii_whitespace().collect::<String>())
            .map_err(|_| error)?
    } else {
        bytes
    };
    let (rest, cert) = X509Certificate::from_der(&der).map_err(|_| error)?;
    if !rest.is_empty() || !cert.is_ca() {
        return Err(error.into());
    }
    if check_time && !cert.validity().is_valid() {
        return Err("The selected CA certificate is expired or not yet valid.".into());
    }
    reqwest::Certificate::from_der(&der).map_err(|_| error.into())
}

impl Target {
    fn new(profile: Profile, saved: bool) -> Result<Self, String> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        if canonical(&profile.url)? != profile.url || profile.vault_id.is_some_and(|id| id.is_nil())
        {
            return Err("Invalid saved Vault connection.".into());
        }
        let mut builder = Client::builder()
            .https_only(true)
            .no_proxy()
            .http1_only()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15));
        if let Some(ca) = &profile.ca {
            builder = builder.tls_certs_only([certificate(ca, false)?]);
        }
        let client = builder
            .build()
            .map_err(|_| "Could not initialize Vault HTTPS.")?;
        Ok(Self {
            profile,
            client,
            saved,
        })
    }

    fn check_ca_time(&self) -> Result<(), String> {
        if let Some(ca) = &self.profile.ca {
            certificate(ca, true)?;
        }
        Ok(())
    }

    async fn discover(&self) -> Result<Discovery, String> {
        self.check_ca_time()?;
        let response = checked_response(
            self.client
                .get(format!("{}/api/v1/discovery", self.profile.url)),
        )
        .await?;
        if !response.status().is_success() {
            return Err("This server does not support Vault protocol version 1.".into());
        }
        let data = bounded(response, 2048).await?;
        let found: Discovery = serde_json::from_slice(&data)
            .map_err(|_| "This server does not support Vault protocol version 1.")?;
        if found.protocol_version != 1
            || found.setup_required == found.vault_id.is_some()
            || found.vault_id.is_some_and(|id| id.is_nil())
        {
            return Err("This server does not support Vault protocol version 1.".into());
        }
        if self.profile.vault_id.is_some() && found.vault_id != self.profile.vault_id {
            return Err(
                "This server has a different vault. Your local data is still available.".into(),
            );
        }
        Ok(found)
    }
}

fn transport_error(error: reqwest::Error) -> String {
    let mut cause: Option<&(dyn Error + 'static)> = Some(&error);
    while let Some(error) = cause {
        // Some platform verifiers wrap the certificate error in an I/O error.
        if let Some(rustls::Error::InvalidCertificate(cert)) = error.downcast_ref::<rustls::Error>()
        {
            use rustls::CertificateError::*;
            return match cert {
                NotValidForName | NotValidForNameContext { .. } => "The certificate does not match the server hostname.",
                UnknownIssuer => "The certificate issuer is not trusted. Select the operator's public CA certificate.",
                Expired | ExpiredContext { .. } | NotValidYet | NotValidYetContext { .. } =>
                    "The server certificate is expired or not yet valid.",
                _ => "The server certificate failed validation.",
            }.into();
        }
        if let Some(inner) = error
            .downcast_ref::<std::io::Error>()
            .and_then(|io| io.get_ref())
        {
            cause = Some(inner);
        } else {
            cause = error.source();
        }
    }
    if error.is_timeout() {
        "The Vault server did not respond in time."
    } else if error.is_connect() {
        "Could not connect to the Vault server. Check the address, network and certificate."
    } else {
        "The Vault server connection failed."
    }
    .into()
}

async fn checked_response(request: reqwest::RequestBuilder) -> Result<reqwest::Response, String> {
    let response = request.send().await.map_err(transport_error)?;
    if response.status().is_redirection() {
        return Err("The Vault server returned a redirect. Check its HTTPS URL.".into());
    }
    Ok(response)
}

async fn bounded(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>, String> {
    let error = "The Vault server response exceeded the size limit.";
    if response
        .content_length()
        .is_some_and(|size| size > limit as u64)
    {
        return Err(error.into());
    }
    let mut data = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(transport_error)? {
        if chunk.len() > limit - data.len() {
            return Err(error.into());
        }
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}

fn profile_path(window: &WebviewWindow) -> Result<PathBuf, String> {
    if !super::trusted_window(window) {
        return Err("Vault commands require the bundled app.".into());
    }
    Ok(window
        .path()
        .app_local_data_dir()
        .map_err(|_| "Could not find the Vault profile directory.")?
        .join("vault-pairing-v1.json"))
}

fn load(target: &mut Option<Target>, path: &PathBuf) -> Result<(), String> {
    if target.is_some() {
        return Ok(());
    }
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("Could not read the saved Vault connection.".into()),
    };
    let mut data = Vec::new();
    file.take(MAX_PROFILE as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|_| "Could not read the saved Vault connection.")?;
    if data.len() > MAX_PROFILE {
        return Err("Invalid saved Vault connection.".into());
    }
    let profile: Profile =
        serde_json::from_slice(&data).map_err(|_| "Invalid saved Vault connection.")?;
    if profile.vault_id.is_none() {
        return Err("Invalid saved Vault connection.".into());
    }
    *target = Some(Target::new(profile, true)?);
    Ok(())
}

#[tauri::command]
pub async fn vault_profile(
    window: WebviewWindow,
    state: tauri::State<'_, Transport>,
) -> Result<Option<String>, String> {
    let path = profile_path(&window)?;
    let mut target = state.0.lock().await;
    load(&mut target, &path)?;
    Ok(target.as_ref().map(|target| target.profile.url.clone()))
}

#[tauri::command]
pub async fn vault_connect(
    window: WebviewWindow,
    state: tauri::State<'_, Transport>,
    url: String,
    ca: Option<String>,
) -> Result<Discovery, String> {
    let path = profile_path(&window)?;
    let mut target = state.0.lock().await;
    load(&mut target, &path)?;
    let url = canonical(&url)?;
    if let Some(prior) = target.as_ref().filter(|prior| prior.saved) {
        if url != prior.profile.url || ca.is_some() {
            return Err("This installation is already paired. Sync your changes before preparing a fresh pairing.".into());
        }
        return prior.discover().await;
    }
    // Invalidate an uncommitted target before trying a new address.
    *target = None;
    let mut next = Target::new(
        Profile {
            url,
            vault_id: None,
            ca,
        },
        false,
    )?;
    let found = next.discover().await?;
    next.profile.vault_id = found.vault_id;
    *target = Some(next);
    Ok(found)
}

#[tauri::command]
pub async fn vault_commit(
    window: WebviewWindow,
    state: tauri::State<'_, Transport>,
    vault_id: Uuid,
) -> Result<String, String> {
    let path = profile_path(&window)?;
    let mut guard = state.0.lock().await;
    load(&mut guard, &path)?;
    let target = guard.as_mut().ok_or("Connect to Vault first.")?;
    if target.profile.vault_id != Some(vault_id) {
        return Err(
            "This server has a different vault. Your local data is still available.".into(),
        );
    }
    if !target.saved {
        let data = serde_json::to_vec(&target.profile)
            .map_err(|_| "Could not save the Vault connection.")?;
        let error = "Could not save the Vault connection.";
        fs::create_dir_all(path.parent().ok_or(error)?).map_err(|_| error)?;
        let pending = path.with_extension(format!("{}.tmp", rand::random::<u64>()));
        let result = (|| {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&pending)?;
            file.write_all(&data)?;
            file.sync_all()?;
            // A second process must not be able to replace the first pairing.
            fs::hard_link(&pending, &path)
        })();
        let _ = fs::remove_file(&pending);
        result.map_err(|_| error)?;
        target.saved = true;
    }
    Ok(target.profile.url.clone())
}

fn uuid_segment(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}

fn index_segment(value: &str) -> bool {
    !value.is_empty() && value.len() <= 10 && value.bytes().all(|b| b.is_ascii_digit())
}

fn operation(method: &str, path: &str) -> Option<(Method, usize, bool)> {
    if path.len() > 100 {
        return None;
    }
    match (method, path) {
        ("GET", "config") => Some((Method::GET, 96 * 1024, false)),
        ("DELETE", "session") => Some((Method::DELETE, 4096, false)),
        ("DELETE", _) if sync_device_operation(method, path) => Some((Method::DELETE, 4096, false)),
        ("POST", "bootstrap" | "sessions" | "mutations" | "files" | "files/deleted") => {
            Some((Method::POST, 96 * 1024, false))
        }
        ("POST", "changes" | "files/list") => Some((Method::POST, 16 * 1024 * 1024, false)),
        ("POST", "source-archives/list" | "recovery-kits/list") => {
            Some((Method::POST, 1024 * 1024, false))
        }
        ("POST", _) if sync_device_operation(method, path) => Some((Method::POST, 4096, false)),
        ("POST", _) => match path.split('/').collect::<Vec<_>>().as_slice() {
            ["files", id, "finish" | "delete"] if uuid_segment(id) => {
                Some((Method::POST, 4096, false))
            }
            ["files", id, "chunks", index] if uuid_segment(id) && index_segment(index) => {
                Some((Method::POST, 4096, true))
            }
            ["files", id, "read", index] if uuid_segment(id) && index_segment(index) => {
                Some((Method::POST, 1024 * 1024 + 128, false))
            }
            ["source-archives" | "recovery-kits", id, index]
                if uuid_segment(id) && index_segment(index) =>
            {
                Some((Method::POST, 1024 * 1024 + 128, false))
            }
            _ => None,
        },
        _ => None,
    }
}

fn sync_device_operation(method: &str, path: &str) -> bool {
    match (method, path.split('/').collect::<Vec<_>>().as_slice()) {
        ("POST" | "DELETE", ["sync-devices", id]) | ("POST", ["sync-devices", id, "refresh"]) => uuid_segment(id),
        _ => false,
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Call {
    path: String,
    method: String,
    body: Option<String>,
    token: Option<String>,
    write_key: Option<String>,
    proof: Option<String>,
}

fn opaque(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[tauri::command]
pub async fn vault_request(
    window: WebviewWindow,
    state: tauri::State<'_, Transport>,
    call: Call,
) -> Result<Response, String> {
    let profile = profile_path(&window)?;
    let mut guard = state.0.lock().await;
    load(&mut guard, &profile)?;
    let target = guard.as_mut().ok_or("Connect to Vault first.")?;
    target.check_ca_time()?;
    let invalid = "Invalid Vault API operation.";
    let (method, limit, binary) = operation(&call.method, &call.path).ok_or(invalid)?;
    let device_sync = sync_device_operation(&call.method, &call.path);
    let refresh = device_sync && call.path.ends_with("/refresh");
    let length = call.body.as_ref().map_or(0, String::len);
    if (method == Method::POST || device_sync) != call.body.is_some()
        || length > MAX_REQUEST.div_ceil(3) * 4
        || call
            .token
            .as_deref()
            .is_some_and(|token| !opaque(token, 43))
        || (call.path == "config") != call.token.is_none()
        || call
            .write_key
            .as_deref()
            .is_some_and(|key| (call.path != "sessions" && !refresh) || !opaque(key, 43))
        || call
            .proof
            .as_deref()
            .is_some_and(|proof| !opaque(proof, 128))
    {
        return Err(invalid.into());
    }
    let body = call
        .body
        .as_deref()
        .map(|value| STANDARD.decode(value).map_err(|_| invalid))
        .transpose()?;
    if body
        .as_ref()
        .is_some_and(|body| body.len() > MAX_REQUEST || (binary && body.len() > 1024 * 1024 + 17))
    {
        return Err(invalid.into());
    }
    if call.path == "sessions" || call.path == "bootstrap" {
        // Check identity before putting any setup or account credential on the wire.
        let found = target.discover().await?;
        if call.path == "bootstrap"
            && (target.saved || target.profile.vault_id.is_some() || !found.setup_required)
        {
            return Err("The server no longer needs setup.".into());
        }
        if call.path == "sessions" {
            let login: serde_json::Value =
                serde_json::from_slice(body.as_deref().ok_or(invalid)?).map_err(|_| invalid)?;
            let requested = login
                .get("vaultId")
                .and_then(|id| id.as_str())
                .and_then(|id| Uuid::parse_str(id).ok());
            if requested.is_none()
                || requested != found.vault_id
                || requested != target.profile.vault_id
                || login.get("client").and_then(|value| value.as_str()) != Some("native")
            {
                return Err(
                    "This server has a different vault. Your local data is still available.".into(),
                );
            }
        }
    } else if !target.saved && call.path != "config" && call.path != "session" {
        return Err("Finish pairing before syncing Vault data.".into());
    }
    if device_sync {
        let input: serde_json::Value = serde_json::from_slice(body.as_deref().ok_or(invalid)?).map_err(|_| invalid)?;
        let requested = input.get("vaultId").and_then(|id| id.as_str()).and_then(|id| Uuid::parse_str(id).ok());
        let found = target.discover().await?;
        if requested.is_none() || requested != target.profile.vault_id || requested != found.vault_id {
            return Err("This server has a different vault. Your local data is still available.".into());
        }
    }
    let mut request = target.client.request(
        method,
        format!("{}/api/v1/{}", target.profile.url, call.path),
    );
    if let Some(token) = call.token {
        request = request.bearer_auth(token);
    }
    if let Some(key) = call.write_key {
        request = request.header(
            "X-Vault-Write-Key",
            HeaderValue::from_str(&key).map_err(|_| invalid)?,
        );
    }
    if let Some(proof) = call.proof {
        request = request.header(
            "X-Vault-Write-Proof",
            HeaderValue::from_str(&proof).map_err(|_| invalid)?,
        );
    }
    let created = if call.path == "bootstrap" {
        let decoded: serde_json::Value =
            serde_json::from_slice(body.as_deref().ok_or(invalid)?).map_err(|_| invalid)?;
        Some(
            decoded
                .get("vaultId")
                .and_then(|id| id.as_str())
                .and_then(|id| Uuid::parse_str(id).ok())
                .filter(|id| !id.is_nil())
                .ok_or(invalid)?,
        )
    } else {
        None
    };
    if let Some(body) = body {
        request = request
            .header(
                "Content-Type",
                if binary {
                    "application/octet-stream"
                } else {
                    "application/json"
                },
            )
            .body(body);
    }
    let response = checked_response(request).await?;
    let status = response.status();
    let bytes = bounded(response, limit).await?;
    if call.path == "config" && status.is_success() {
        let config: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| "Invalid Vault configuration.")?;
        let id = config
            .get("vaultId")
            .and_then(|id| id.as_str())
            .and_then(|id| Uuid::parse_str(id).ok());
        if id.is_none() || id != target.profile.vault_id {
            return Err(
                "This server has a different vault. Your local data is still available.".into(),
            );
        }
    }
    if let Some(id) = created.filter(|_| status == reqwest::StatusCode::CREATED) {
        if target.discover().await?.vault_id != Some(id) {
            return Err("The server did not confirm vault creation.".into());
        }
        target.profile.vault_id = Some(id);
    }
    let mut data = Vec::with_capacity(bytes.len() + 2);
    data.extend_from_slice(&status.as_u16().to_be_bytes());
    data.extend_from_slice(&bytes);
    Ok(Response::new(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_url_rejects_hidden_components() {
        assert_eq!(
            canonical("https://EXAMPLE.test:443/").unwrap(),
            "https://example.test"
        );
        assert_eq!(
            canonical("https://example.test:8443").unwrap(),
            "https://example.test:8443"
        );
        for value in [
            "http://example.test",
            "https://@example.test",
            "https://example.test/a/..",
            "https://example.test?",
            "https://example.test/#",
            "https://example.test\\",
            "https://example.test:0",
            "https://example.test:",
            "https://exam\tple.test",
        ] {
            assert!(canonical(value).is_err(), "{value}");
        }
    }

    #[test]
    fn transport_rejects_arbitrary_routes_and_methods() {
        assert!(
            operation(
                "POST",
                "files/00000000-0000-4000-8000-000000000001/chunks/0"
            )
            .is_some()
        );
        for path in [
            "discovery",
            "config",
            "files/../config",
            "files/%2f/finish",
            "sessions?",
            "//example.test",
            "bootstrap/",
        ] {
            assert!(operation("POST", path).is_none(), "{path}");
        }
        let device = "sync-devices/00000000-0000-4000-8000-000000000001";
        assert!(operation("POST", device).is_some());
        assert!(operation("DELETE", device).is_some());
        assert!(operation("POST", &format!("{device}/refresh")).is_some());
        assert!(operation("DELETE", &format!("{device}/refresh")).is_none());
        assert!(operation("GET", device).is_none());
    }
}
