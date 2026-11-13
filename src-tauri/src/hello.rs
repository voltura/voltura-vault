use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HelloStatus {
    api_version: u32,
    platform_authenticator_available: bool,
    prf_api_present: bool,
    prf_exercised: bool,
    note: &'static str,
}

pub fn status() -> Result<HelloStatus, String> {
    #[cfg(windows)]
    {
        use windows::Win32::Networking::WindowsWebServices::{
            WebAuthNGetApiVersionNumber, WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable,
        };
        // Read-only discovery. Never turn authenticator availability into a key-unlock claim.
        let version = unsafe { WebAuthNGetApiVersionNumber() };
        let available = unsafe { WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable() }
            .map_err(|e| format!("Windows authenticator query failed: {}", e.code()))?
            .as_bool();
        Ok(HelloStatus {
            api_version: version,
            platform_authenticator_available: available,
            prf_api_present: version >= 6,
            prf_exercised: false,
            note: "API presence only. Actual Windows Hello PRF and Chrome/native interoperability remain unverified.",
        })
    }
    #[cfg(not(windows))]
    Err("Windows Hello requires Windows".into())
}
