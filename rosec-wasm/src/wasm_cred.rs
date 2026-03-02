//! Host-side credential persistence for WASM providers.
//!
//! WASM guests cannot access the filesystem, so the host persists
//! registration credentials (e.g. Bitwarden API `client_id` / `client_secret`)
//! on their behalf.  This module derives a storage key from the user's
//! master password and the provider ID, then delegates to
//! [`rosec_core::credential`] for the actual AES-256-CBC + HMAC-SHA256
//! encrypt/decrypt and atomic file I/O.
//!
//! # Key derivation
//!
//! ```text
//! prk         = HKDF-Extract(salt = "rosec-wasm-cred-v1", ikm = password)
//! storage_key = HKDF-Expand(prk, info = provider_id, len = 64)
//! ```
//!
//! The provider ID is baked into the info string so that credentials for
//! different providers cannot be cross-decrypted.
//!
//! # Security
//!
//! - Key material is held in `Zeroizing` wrappers.
//! - The master password is never stored — wrong password = wrong key = MAC
//!   verification failure on load.
//! - All plaintext is zeroized before return.

use hkdf::Hkdf;
use rosec_core::credential::{self, StorageKey};
use rosec_core::oauth::OAuthCredential;
use sha2::Sha256;
use zeroize::Zeroizing;

/// HKDF salt — domain-separates WASM credential keys from other rosec keys.
const HKDF_SALT: &[u8] = b"rosec-wasm-cred-v1";

/// Derive a 64-byte `StorageKey` from the user's password and the provider ID.
fn derive_storage_key(password: &str, provider_id: &str) -> Result<StorageKey, String> {
    let (_, hkdf) = Hkdf::<Sha256>::extract(Some(HKDF_SALT), password.as_bytes());

    let mut key_material = Zeroizing::new(vec![0u8; 64]);
    hkdf.expand(provider_id.as_bytes(), &mut key_material)
        .map_err(|e| format!("HKDF expand: {e}"))?;

    StorageKey::from_bytes(&key_material)
}

/// Save registration credentials, encrypted with a key derived from the password.
///
/// `client_id` and `client_secret` correspond to the Bitwarden API key pair
/// (or equivalent for other WASM providers).
pub fn save(
    provider_id: &str,
    password: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<(), String> {
    let key = derive_storage_key(password, provider_id)?;
    credential::encrypt_and_save(provider_id, &key, client_id, client_secret)
}

/// Load and decrypt stored registration credentials.
///
/// Returns `None` if no credential file exists for this provider.
/// Returns `Err` if the file exists but decryption fails (wrong password
/// or tampered data).
pub fn load(provider_id: &str, password: &str) -> Result<Option<OAuthCredential>, String> {
    let key = derive_storage_key(password, provider_id)?;
    credential::load_and_decrypt(provider_id, &key)
}

/// Delete stored credentials for a provider.
pub fn clear(provider_id: &str) -> Result<bool, String> {
    rosec_core::oauth::clear(provider_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::Mutex;

    /// Serialize tests that manipulate XDG_DATA_HOME.
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    fn with_tmp_home(f: impl FnOnce()) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = env::temp_dir().join(format!("rosec-wasm-cred-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { env::set_var("XDG_DATA_HOME", &tmp) };
        f();
        unsafe { env::remove_var("XDG_DATA_HOME") };
        drop(_guard);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn roundtrip_save_load() {
        with_tmp_home(|| {
            save("test-prov", "hunter2", "user.abc", "s3cr3t").unwrap();
            let cred = load("test-prov", "hunter2").unwrap().unwrap();
            assert_eq!(cred.client_id, "user.abc");
            assert_eq!(cred.client_secret.as_str(), "s3cr3t");
        });
    }

    #[test]
    fn wrong_password_fails() {
        with_tmp_home(|| {
            save("test-prov", "correctpass", "user.abc", "s3cr3t").unwrap();
            assert!(load("test-prov", "wrongpass").is_err());
        });
    }

    #[test]
    fn different_providers_isolated() {
        with_tmp_home(|| {
            save("prov-a", "pass", "id-a", "secret-a").unwrap();
            save("prov-b", "pass", "id-b", "secret-b").unwrap();
            let a = load("prov-a", "pass").unwrap().unwrap();
            let b = load("prov-b", "pass").unwrap().unwrap();
            assert_eq!(a.client_id, "id-a");
            assert_eq!(b.client_id, "id-b");
        });
    }

    #[test]
    fn load_missing_returns_none() {
        with_tmp_home(|| {
            assert!(load("no-such", "pass").unwrap().is_none());
        });
    }

    #[test]
    fn clear_removes_credential() {
        with_tmp_home(|| {
            save("test-prov", "pass", "id", "secret").unwrap();
            assert!(load("test-prov", "pass").unwrap().is_some());
            assert!(clear("test-prov").unwrap());
            assert!(load("test-prov", "pass").unwrap().is_none());
        });
    }
}
