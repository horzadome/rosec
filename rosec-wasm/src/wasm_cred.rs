//! Host-side credential persistence for WASM providers.
//!
//! WASM guests cannot access the filesystem, so the host persists
//! registration credentials on their behalf.  All registration fields
//! (e.g. `access_token` for SM, `client_id`/`client_secret` for PM) are
//! serialised to JSON and encrypted as a single blob.  This avoids baking
//! any assumption about which field names a given provider uses.
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
//! # Storage format
//!
//! `$XDG_DATA_HOME/rosec/oauth/<provider-id>.toml` (via `rosec_core::credential`).
//! The stored `client_id` field is the sentinel `"__fields_v1__"` to
//! distinguish this format from an older single-secret encoding.  The
//! encrypted payload is `serde_json::to_string(&HashMap<String, String>)`.
//!
//! # Security
//!
//! - Key material is held in `Zeroizing` wrappers.
//! - The master password is never stored — wrong password = MAC failure on load.
//! - All plaintext is zeroized before return.

use std::collections::HashMap;

use hkdf::Hkdf;
use rosec_core::credential::{self, StorageKey};
use sha2::Sha256;
use zeroize::Zeroizing;

/// HKDF salt — domain-separates WASM credential keys from other rosec keys.
const HKDF_SALT: &[u8] = b"rosec-wasm-cred-v1";

/// Sentinel stored as `client_id` to identify the v1 generic-fields format.
const FIELDS_V1_SENTINEL: &str = "__fields_v1__";

/// Derive a 64-byte `StorageKey` from the user's password and the provider ID.
fn derive_storage_key(password: &str, provider_id: &str) -> Result<StorageKey, String> {
    let (_, hkdf) = Hkdf::<Sha256>::extract(Some(HKDF_SALT), password.as_bytes());

    let mut key_material = Zeroizing::new(vec![0u8; 64]);
    hkdf.expand(provider_id.as_bytes(), &mut key_material)
        .map_err(|e| format!("HKDF expand: {e}"))?;

    StorageKey::from_bytes(&key_material)
}

/// Save all registration fields, encrypted with a key derived from the password.
///
/// The entire `fields` map is serialised as JSON and stored as a single
/// encrypted blob — no assumption is made about which keys are present.
pub fn save(
    provider_id: &str,
    password: &str,
    fields: &HashMap<String, Zeroizing<String>>,
) -> Result<(), String> {
    let key = derive_storage_key(password, provider_id)?;

    // Convert Zeroizing<String> values to plain &str for serialisation.
    let plain_map: HashMap<&str, &str> = fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let json = Zeroizing::new(
        serde_json::to_string(&plain_map).map_err(|e| format!("JSON serialise fields: {e}"))?,
    );

    credential::encrypt_and_save(provider_id, &key, FIELDS_V1_SENTINEL, json.as_str())
}

/// Load and decrypt stored registration fields.
///
/// Returns `None` if no credential file exists for this provider.
/// Returns `Err` if the file exists but decryption fails (wrong password
/// or tampered data).
pub fn load(
    provider_id: &str,
    password: &str,
) -> Result<Option<HashMap<String, Zeroizing<String>>>, String> {
    let key = derive_storage_key(password, provider_id)?;
    let cred = credential::load_and_decrypt(provider_id, &key)?;

    let Some(cred) = cred else {
        return Ok(None);
    };

    // Verify sentinel — reject old-format files (client_id ≠ sentinel).
    if cred.client_id != FIELDS_V1_SENTINEL {
        return Err(format!(
            "unsupported credential format (client_id = {:?}); delete and re-register",
            cred.client_id
        ));
    }

    let map: HashMap<String, String> = serde_json::from_str(cred.client_secret.as_str())
        .map_err(|e| format!("JSON deserialise fields: {e}"))?;

    Ok(Some(
        map.into_iter()
            .map(|(k, v)| (k, Zeroizing::new(v)))
            .collect(),
    ))
}

/// Delete stored credentials for a provider.
///
/// Called when a provider is removed or its registration is explicitly reset.
#[allow(dead_code)]
pub fn clear(provider_id: &str) -> Result<bool, String> {
    rosec_core::oauth::clear(provider_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn with_tmp_home(f: impl FnOnce()) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = env::temp_dir().join(format!("rosec-wasm-cred-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let _guard = crate::TEST_ENV_MUTEX.lock().unwrap();
        unsafe { env::set_var("XDG_DATA_HOME", &tmp) };
        f();
        unsafe { env::remove_var("XDG_DATA_HOME") };
        drop(_guard);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    fn fields(pairs: &[(&str, &str)]) -> HashMap<String, Zeroizing<String>> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), Zeroizing::new(v.to_string())))
            .collect()
    }

    #[test]
    fn roundtrip_access_token() {
        with_tmp_home(|| {
            let f = fields(&[("access_token", "tok123")]);
            save("sm-prov", "hunter2", &f).unwrap();
            let loaded = load("sm-prov", "hunter2").unwrap().unwrap();
            assert_eq!(loaded["access_token"].as_str(), "tok123");
        });
    }

    #[test]
    fn roundtrip_client_id_secret() {
        with_tmp_home(|| {
            let f = fields(&[("client_id", "user.abc"), ("client_secret", "s3cr3t")]);
            save("pm-prov", "hunter2", &f).unwrap();
            let loaded = load("pm-prov", "hunter2").unwrap().unwrap();
            assert_eq!(loaded["client_id"].as_str(), "user.abc");
            assert_eq!(loaded["client_secret"].as_str(), "s3cr3t");
        });
    }

    #[test]
    fn wrong_password_fails() {
        with_tmp_home(|| {
            let f = fields(&[("access_token", "tok")]);
            save("test-prov", "correctpass", &f).unwrap();
            assert!(load("test-prov", "wrongpass").is_err());
        });
    }

    #[test]
    fn different_providers_isolated() {
        with_tmp_home(|| {
            save("prov-a", "pass", &fields(&[("access_token", "tok-a")])).unwrap();
            save("prov-b", "pass", &fields(&[("access_token", "tok-b")])).unwrap();
            let a = load("prov-a", "pass").unwrap().unwrap();
            let b = load("prov-b", "pass").unwrap().unwrap();
            assert_eq!(a["access_token"].as_str(), "tok-a");
            assert_eq!(b["access_token"].as_str(), "tok-b");
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
            let f = fields(&[("access_token", "tok")]);
            save("test-prov", "pass", &f).unwrap();
            assert!(load("test-prov", "pass").unwrap().is_some());
            assert!(clear("test-prov").unwrap());
            assert!(load("test-prov", "pass").unwrap().is_none());
        });
    }
}
