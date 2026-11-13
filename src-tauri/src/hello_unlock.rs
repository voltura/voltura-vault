#[cfg(windows)]
mod win {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use rand::{rngs::OsRng, RngCore};
    use sha2::{Digest, Sha256};
    use std::{ptr, slice, sync::atomic::{AtomicBool, Ordering}};
    use windows::{core::w, Win32::{Foundation::HWND, Networking::WindowsWebServices::*}};
    use zeroize::{Zeroize, Zeroizing};

    const RP: &str = "vault-ui.test";
    // The windows crate binds the v7 options and v6 attestation. Extend the
    // Windows SDK's C layouts for PRF evaluation on credential creation.
    #[repr(C)]
    struct MakeCredentialOptionsV8 {
        base: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
        prf: *mut WEBAUTHN_HMAC_SECRET_SALT,
        hint_count: u32,
        hints: *const windows::core::PCWSTR,
        third_party_payment: windows::core::BOOL,
    }
    #[repr(C)]
    struct AttestationV7 {
        base: WEBAUTHN_CREDENTIAL_ATTESTATION,
        prf: *mut WEBAUTHN_HMAC_SECRET_SALT,
        third_party_payment: windows::core::BOOL,
    }
    static RUNNING: AtomicBool = AtomicBool::new(false);
    struct Running;
    impl Drop for Running { fn drop(&mut self) { RUNNING.store(false, Ordering::Release); } }
    struct Attestation(*mut WEBAUTHN_CREDENTIAL_ATTESTATION);
    impl Drop for Attestation {
        fn drop(&mut self) {
            unsafe {
                let value = &*self.0;
                if value.dwVersion >= 7 { wipe_output((*self.0.cast::<AttestationV7>()).prf); }
                WebAuthNFreeCredentialAttestation(Some(self.0));
            }
        }
    }
    struct Assertion(*mut WEBAUTHN_ASSERTION);
    impl Drop for Assertion {
        fn drop(&mut self) {
            unsafe {
                let value = &*self.0;
                if value.dwVersion >= 3 { wipe_output(value.pHmacSecret); }
                WebAuthNFreeAssertion(self.0);
            }
        }
    }
    unsafe fn wipe_output(secret: *const WEBAUTHN_HMAC_SECRET_SALT) {
        if let Some(secret) = unsafe { secret.as_ref() } {
            unsafe {
                if secret.cbFirst == 32 && !secret.pbFirst.is_null() { slice::from_raw_parts_mut(secret.pbFirst, 32).zeroize(); }
                if secret.cbSecond == 32 && !secret.pbSecond.is_null() { slice::from_raw_parts_mut(secret.pbSecond, 32).zeroize(); }
            }
        }
    }
    fn error(_: windows::core::Error) -> String { "Windows Hello did not complete. Try again or use your master password.".into() }
    fn json(kind: &str) -> Vec<u8> {
        let mut challenge = [0u8; 32]; OsRng.fill_bytes(&mut challenge);
        serde_json::json!({ "type": kind, "challenge": URL_SAFE_NO_PAD.encode(challenge), "origin": "https://vault-ui.test", "crossOrigin": false }).to_string().into_bytes()
    }
    fn client_data(json: &mut [u8]) -> WEBAUTHN_CLIENT_DATA {
        WEBAUTHN_CLIENT_DATA { dwVersion: 1, cbClientDataJSON: json.len() as u32, pbClientDataJSON: json.as_mut_ptr(), pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256 }
    }
    unsafe fn checked_auth(pointer: *const u8, len: u32, attestation: bool) -> Result<Vec<u8>, String> {
        if pointer.is_null() || len < if attestation { 55 } else { 37 } || len > 65_536 { return Err("Invalid authenticator data".into()); }
        let bytes = unsafe { slice::from_raw_parts(pointer, len as usize) };
        if bytes[..32] != Sha256::digest(RP.as_bytes())[..] { return Err("Authenticator returned the wrong vault identity".into()); }
        // Require presence and verification; reject backup-eligible or backed-up credentials.
        if bytes[32] & 5 != 5 { return Err("Windows Hello could not confirm your identity.".into()); }
        if bytes[32] & 0x18 != 0 { return Err("Choose Windows Hello on this PC to save the passkey locally.".into()); }
        if attestation && bytes[32] & 0x40 == 0 { return Err("Missing attested credential data".into()); }
        Ok(bytes.to_vec())
    }

    fn begin() -> Result<Running, String> {
        if unsafe { WebAuthNGetApiVersionNumber() } < 6 { return Err("This version of Windows does not support Hello vault unlock.".into()); }
        if RUNNING.swap(true, Ordering::AcqRel) { return Err("Windows Hello is already open.".into()); }
        Ok(Running)
    }

    pub fn enroll(window: isize, mut input: Vec<u8>) -> Result<String, String> {
        let _running = begin()?;
        if input.len() != 32 { return Err("Invalid Windows Hello enrollment.".into()); }
        let hwnd = HWND(window as *mut core::ffi::c_void);
        let mut user_id = [0u8; 32]; OsRng.fill_bytes(&mut user_id);
        let rp = WEBAUTHN_RP_ENTITY_INFORMATION { dwVersion: 1, pwszId: w!("vault-ui.test"), pwszName: w!("Voltura Vault"), ..Default::default() };
        let user = WEBAUTHN_USER_ENTITY_INFORMATION { dwVersion: 1, cbId: 32, pbId: user_id.as_mut_ptr(), pwszName: w!("voltura-vault"), pwszDisplayName: w!("Voltura Vault"), ..Default::default() };
        let mut parameter = WEBAUTHN_COSE_CREDENTIAL_PARAMETER { dwVersion: 1, pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY, lAlg: WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256 };
        let parameters = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS { cCredentialParameters: 1, pCredentialParameters: &mut parameter };
        let version = unsafe { WebAuthNGetApiVersionNumber() };
        let mut prf = WEBAUTHN_HMAC_SECRET_SALT { cbFirst: input.len() as u32, pbFirst: input.as_mut_ptr(), ..Default::default() };
        let base = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
            dwVersion: if version >= 8 { 8 } else { 6 },
            dwTimeoutMilliseconds: 60_000, dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
            bRequireResidentKey: true.into(), dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
            dwAttestationConveyancePreference: WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
            bEnablePrf: true.into(),
            ..Default::default()
        };
        let options = MakeCredentialOptionsV8 {
            base, prf: &mut prf, hint_count: 0, hints: ptr::null(), third_party_payment: false.into(),
        };
        let mut create_json = json("webauthn.create");
        let attestation_ptr = unsafe {
            WebAuthNAuthenticatorMakeCredential(hwnd, &rp, &user, &parameters, &client_data(&mut create_json), Some((&raw const options).cast()))
        }.map_err(error)?;
        if attestation_ptr.is_null() { return Err("Windows returned no credential".into()); }
        let attestation = Attestation(attestation_ptr);
        let value = unsafe { &*attestation.0 };
        // A successful assertion must return the unlock secret before the vault is enrolled.
        let auth = unsafe { checked_auth(value.pbAuthenticatorData, value.cbAuthenticatorData, true)? };
        let aaguid: String = auth[37..53].iter().map(|byte| format!("{byte:02x}")).collect();
        if !matches!(aaguid.as_str(), "08987058cadc4b81b6e130de50dcbe96" | "9ddd1817af5a4672a2b93e3dd95000a9" | "6028b017b1d44c02b4b3afcdafc96bb2") {
            return Err("Choose Windows Hello on this PC when saving the passkey.".into());
        }
        if value.pbCredentialId.is_null() || value.cbCredentialId == 0 || value.cbCredentialId > 1024 { return Err("Invalid credential identifier".into()); }
        Ok(URL_SAFE_NO_PAD.encode(unsafe { slice::from_raw_parts(value.pbCredentialId, value.cbCredentialId as usize) }))
    }

    pub fn evaluate(window: isize, credential_id: &str, mut input: Vec<u8>) -> Result<Zeroizing<Vec<u8>>, String> {
        let _running = begin()?;
        if credential_id.len() > 1366 || input.len() != 32 { return Err("Invalid Windows Hello enrollment.".into()); }
        let mut id = URL_SAFE_NO_PAD.decode(credential_id).map_err(|_| "Invalid Windows Hello enrollment.")?;
        if id.is_empty() || id.len() > 1024 { return Err("Invalid Windows Hello enrollment.".into()); }
        let hwnd = HWND(window as *mut core::ffi::c_void);
        let mut credential = WEBAUTHN_CREDENTIAL_EX { dwVersion: 1, cbId: id.len() as u32, pbId: id.as_mut_ptr(), pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY, dwTransports: WEBAUTHN_CTAP_TRANSPORT_INTERNAL };
        let mut credential_ptr = &mut credential as *mut _;
        let mut list = WEBAUTHN_CREDENTIAL_LIST { cCredentials: 1, ppCredentials: &mut credential_ptr };
        let mut salt = WEBAUTHN_HMAC_SECRET_SALT { cbFirst: input.len() as u32, pbFirst: input.as_mut_ptr(), cbSecond: 0, pbSecond: ptr::null_mut() };
        let mut salts = WEBAUTHN_HMAC_SECRET_SALT_VALUES { pGlobalHmacSalt: &mut salt, ..Default::default() };
        // dwFlags stays zero: Windows applies the standard WebAuthn PRF prefix/hash.
        let options = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS { dwVersion: 6, dwTimeoutMilliseconds: 60_000,
            dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
            dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
            pAllowCredentialList: &mut list, pHmacSecretSaltValues: &mut salts, ..Default::default() };
        let mut get_json = json("webauthn.get");
        let assertion_ptr = unsafe { WebAuthNAuthenticatorGetAssertion(hwnd, w!("vault-ui.test"), &client_data(&mut get_json), Some(&options)) }.map_err(error)?;
        if assertion_ptr.is_null() { return Err("Windows returned no assertion".into()); }
        let assertion = Assertion(assertion_ptr);
        let value = unsafe { &*assertion.0 };
        unsafe { checked_auth(value.pbAuthenticatorData, value.cbAuthenticatorData, false)?; }
        if value.Credential.cbId as usize != id.len() || value.Credential.pbId.is_null() || unsafe { slice::from_raw_parts(value.Credential.pbId, id.len()) } != id { return Err("Windows Hello returned a different passkey.".into()); }
        if value.dwVersion < 3 || value.pHmacSecret.is_null() {
            return Err("Windows Hello did not provide a vault unlock key. Use your master password.".into());
        }
        let secret = unsafe { &*value.pHmacSecret };
        if secret.cbFirst != 32 || secret.pbFirst.is_null() { return Err("This Windows Hello passkey cannot unlock the vault.".into()); }
        Ok(Zeroizing::new(unsafe { slice::from_raw_parts(secret.pbFirst, 32) }.to_vec()))
    }
}

#[cfg(windows)]
pub use win::{enroll, evaluate};
