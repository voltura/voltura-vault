//! Server-side primitives for random bearer credentials, not password hashing.
//! HTTPS, private network access, rate limiting and route authorization belong
//! to the HTTP service. No master password or vault encryption key enters here.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub type VaultId = [u8; 16];
const DOMAIN: &[u8] = b"voltura-vault:token-verifier:v1\0";

/// Each capability gets independently generated secret material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Purpose {
    Account = 1,
    Recovery = 2,
    Access = 3,
    Refresh = 4,
    Administration = 5,
    BackupRead = 6,
    Bootstrap = 7,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidCredential;

/// Deliberately has no Debug, Display, Clone or serialization implementation.
pub struct SecretToken(Zeroizing<[u8; 32]>);

impl SecretToken {
    pub fn generate() -> Result<Self, rand::Error> {
        let mut bytes = Zeroizing::new([0; 32]);
        OsRng.try_fill_bytes(bytes.as_mut())?;
        Ok(Self(bytes))
    }

    /// Decode only this protocol's canonical 256-bit base64url representation.
    /// Size is checked before allocating or decoding attacker-controlled input.
    pub fn parse(encoded: &str) -> Result<Self, InvalidCredential> {
        if encoded.len() != 43 {
            return Err(InvalidCredential);
        }
        let mut bytes = Zeroizing::new([0; 32]);
        let count = URL_SAFE_NO_PAD
            .decode_slice(encoded, bytes.as_mut())
            .map_err(|_| InvalidCredential)?;
        if count != 32 {
            return Err(InvalidCredential);
        }
        Ok(Self(bytes))
    }

    /// For a protected request/cookie or encrypted client capsule only; never log.
    pub fn encode(&self) -> Zeroizing<String> {
        Zeroizing::new(URL_SAFE_NO_PAD.encode(self.0.as_ref()))
    }

    pub fn verifier(&self, vault: VaultId, purpose: Purpose) -> Verifier {
        let digest = Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(vault)
            .chain_update([purpose as u8])
            .chain_update(self.0.as_ref())
            .finalize()
            .into();
        Verifier {
            vault,
            purpose,
            digest,
        }
    }
}

/// Persist this digest and its server-owned context, never the bearer secret.
/// A digest is not accepted as a credential. Database write compromise remains
/// outside what one-way token storage can protect against.
#[derive(Clone)]
pub struct Verifier {
    vault: VaultId,
    purpose: Purpose,
    digest: [u8; 32],
}

impl Verifier {
    /// Rehydrate trusted server-owned database metadata, not an HTTP credential.
    pub fn from_stored_digest(vault: VaultId, purpose: Purpose, digest: [u8; 32]) -> Self {
        Self {
            vault,
            purpose,
            digest,
        }
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub fn verify(
        &self,
        presented: &str,
        expected_vault: VaultId,
        expected_purpose: Purpose,
    ) -> Result<(), InvalidCredential> {
        if self.vault != expected_vault || self.purpose != expected_purpose {
            return Err(InvalidCredential);
        }
        let candidate = SecretToken::parse(presented)?;
        let candidate_digest = candidate.verifier(expected_vault, expected_purpose).digest;
        if bool::from(self.digest.ct_eq(&candidate_digest)) {
            Ok(())
        } else {
            Err(InvalidCredential)
        }
    }
}

/// Session expiration is exclusive. A clock before issue time fails closed.
/// The eventual database must persist revocation and rotate refresh tokens
/// transactionally; this object alone is not a multi-process session store.
pub struct Session {
    verifier: Verifier,
    issued_at: u64,
    expires_at: u64,
    revoked: bool,
}

impl Session {
    pub fn new(
        verifier: Verifier,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, InvalidCredential> {
        if expires_at <= issued_at
            || !matches!(
                verifier.purpose,
                Purpose::Access
                    | Purpose::Refresh
                    | Purpose::Administration
                    | Purpose::BackupRead
                    | Purpose::Bootstrap
            )
        {
            return Err(InvalidCredential);
        }
        Ok(Self {
            verifier,
            issued_at,
            expires_at,
            revoked: false,
        })
    }

    pub fn authorize(
        &self,
        token: &str,
        vault: VaultId,
        purpose: Purpose,
        now: u64,
    ) -> Result<(), InvalidCredential> {
        if self.revoked || now < self.issued_at || now >= self.expires_at {
            return Err(InvalidCredential);
        }
        self.verifier.verify(token, vault, purpose)
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const VAULT: VaultId = [7; 16];

    #[test]
    fn generated_tokens_round_trip_without_persisting_the_secret() {
        let token = SecretToken::generate().unwrap();
        let encoded = token.encode();
        assert_eq!(encoded.len(), 43);
        assert_eq!(*SecretToken::parse(&encoded).unwrap().encode(), *encoded);
        let verifier = token.verifier(VAULT, Purpose::Account);
        assert_ne!(verifier.digest(), token.0.as_ref());
        assert!(verifier.verify(&encoded, VAULT, Purpose::Account).is_ok());
    }

    #[test]
    fn wrong_secret_and_stolen_database_digest_are_rejected() {
        let token = SecretToken::generate().unwrap();
        let verifier = token.verifier(VAULT, Purpose::Account);
        let wrong = SecretToken::generate().unwrap().encode();
        assert_eq!(
            verifier.verify(&wrong, VAULT, Purpose::Account),
            Err(InvalidCredential)
        );
        let encoded_digest = URL_SAFE_NO_PAD.encode(verifier.digest());
        assert_eq!(
            verifier.verify(&encoded_digest, VAULT, Purpose::Account),
            Err(InvalidCredential)
        );
    }

    #[test]
    fn vault_and_capability_are_not_interchangeable() {
        let token = SecretToken::generate().unwrap();
        let encoded = token.encode();
        let verifier = token.verifier(VAULT, Purpose::Access);
        assert_eq!(
            verifier.verify(&encoded, [8; 16], Purpose::Access),
            Err(InvalidCredential)
        );
        for scope in [
            Purpose::Account,
            Purpose::Recovery,
            Purpose::Refresh,
            Purpose::Administration,
            Purpose::BackupRead,
            Purpose::Bootstrap,
        ] {
            assert_eq!(
                verifier.verify(&encoded, VAULT, scope),
                Err(InvalidCredential)
            );
            assert_ne!(token.verifier(VAULT, scope).digest(), verifier.digest());
        }
    }

    #[test]
    fn malformed_overlong_and_noncanonical_tokens_are_rejected() {
        let valid = SecretToken(Zeroizing::new([0; 32])).encode();
        for invalid in [
            String::new(),
            valid[..42].into(),
            format!("{}=", valid.as_str()),
            format!(" {}", valid.as_str()),
            "x".repeat(1_000_000),
            "!".repeat(43),
            "å".repeat(43),
        ] {
            assert!(SecretToken::parse(&invalid).is_err());
        }
        // The final base64 character's unused bits must be zero.
        let mut noncanonical = valid.to_string();
        noncanonical.replace_range(42..43, "B");
        assert!(SecretToken::parse(&noncanonical).is_err());
    }

    #[test]
    fn sessions_expire_at_boundary_and_reject_clock_rollback() {
        let token = SecretToken::generate().unwrap();
        let session = Session::new(token.verifier(VAULT, Purpose::Access), 100, 1000).unwrap();
        let encoded = token.encode();
        assert!(
            session
                .authorize(&encoded, VAULT, Purpose::Access, 100)
                .is_ok()
        );
        assert!(
            session
                .authorize(&encoded, VAULT, Purpose::Access, 999)
                .is_ok()
        );
        for now in [99, 1000, u64::MAX] {
            assert_eq!(
                session.authorize(&encoded, VAULT, Purpose::Access, now),
                Err(InvalidCredential)
            );
        }
    }

    #[test]
    fn revoked_sessions_and_wrong_scope_cannot_authorize() {
        let token = SecretToken::generate().unwrap();
        let mut session = Session::new(token.verifier(VAULT, Purpose::Access), 100, 1000).unwrap();
        let encoded = token.encode();
        assert_eq!(
            session.authorize(&encoded, VAULT, Purpose::Administration, 101),
            Err(InvalidCredential)
        );
        session.revoke();
        assert_eq!(
            session.authorize(&encoded, VAULT, Purpose::Access, 101),
            Err(InvalidCredential)
        );
    }

    #[test]
    fn invalid_session_lifetimes_and_long_term_credentials_are_rejected() {
        let token = SecretToken::generate().unwrap();
        for (issued, expires) in [(100, 100), (100, 99)] {
            assert!(Session::new(token.verifier(VAULT, Purpose::Access), issued, expires).is_err());
        }
        for purpose in [Purpose::Account, Purpose::Recovery] {
            assert!(Session::new(token.verifier(VAULT, purpose), 100, 1000).is_err());
        }
    }

    #[test]
    fn verifier_matches_independent_fixed_fixture() {
        let token = SecretToken(Zeroizing::new([0; 32]));
        // Generated independently with Python hashlib; see docs/authentication.md.
        assert_eq!(token.verifier(VAULT, Purpose::Account).digest(), &FIXTURE);
    }
    const FIXTURE: [u8; 32] = [
        178, 245, 110, 96, 139, 30, 217, 36, 154, 217, 148, 73, 95, 57, 164, 134, 184, 244, 170,
        221, 42, 109, 227, 166, 73, 254, 196, 76, 113, 167, 113, 97,
    ];
}
