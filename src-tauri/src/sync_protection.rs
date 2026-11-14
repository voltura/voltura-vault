use windows::{
    Win32::{
        Foundation::{HLOCAL, LocalFree},
        Security::Cryptography::{CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData},
    },
    core::PCWSTR,
};

const CAPSULE_BYTES: usize = 72; // XChaCha20 nonce, 32-byte ciphertext, and authentication tag.
const MAX_PROTECTED_BYTES: usize = 4096;
const ERROR: &str = "Windows could not protect this device's sync credential.";

fn dpapi(mut bytes: Vec<u8>, protect: bool) -> Result<Vec<u8>, String> {
    let valid = if protect { bytes.len() == CAPSULE_BYTES } else { (1..=MAX_PROTECTED_BYTES).contains(&bytes.len()) };
    if !valid { return Err(ERROR.into()); }
    let input = CRYPT_INTEGER_BLOB { cbData: bytes.len() as u32, pbData: bytes.as_mut_ptr() };
    let mut purpose = *b"VolturaVault:WindowsHelloSync:v1";
    let entropy = CRYPT_INTEGER_BLOB { cbData: purpose.len() as u32, pbData: purpose.as_mut_ptr() };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // No machine-wide flag or Windows prompt. The input is already Hello-encrypted.
    unsafe {
        if protect {
            CryptProtectData(&input, PCWSTR::null(), Some(&entropy), None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut output)
        } else {
            CryptUnprotectData(&input, None, Some(&entropy), None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut output)
        }
    }.map_err(|_| ERROR.to_string())?;
    let len = output.cbData as usize;
    let valid = if protect { (1..=MAX_PROTECTED_BYTES).contains(&len) } else { len == CAPSULE_BYTES };
    if output.pbData.is_null() { return Err(ERROR.into()); }
    let result = valid.then(|| unsafe { std::slice::from_raw_parts(output.pbData, len).to_vec() });
    unsafe { let _ = LocalFree(Some(HLOCAL(output.pbData.cast()))); }
    result.ok_or_else(|| ERROR.into())
}

#[tauri::command]
pub(crate) async fn protect_sync_capsule(window: tauri::WebviewWindow, bytes: Vec<u8>, protect: bool) -> Result<tauri::ipc::Response, String> {
    super::installed_window(&window)?;
    let protected = tauri::async_runtime::spawn_blocking(move || dpapi(bytes, protect))
        .await.map_err(|_| ERROR.to_string())??;
    Ok(tauri::ipc::Response::new(protected))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpapi_round_trip_and_rejects_modified_capsule() {
        let input = vec![42; CAPSULE_BYTES];
        let mut protected = dpapi(input.clone(), true).unwrap();
        assert_ne!(input, protected);
        assert_eq!(dpapi(protected.clone(), false).unwrap(), input);
        let middle = protected.len() / 2;
        protected[middle] ^= 1;
        assert!(dpapi(protected, false).is_err());
        assert!(dpapi(vec![0; CAPSULE_BYTES - 1], true).is_err());
    }
}
