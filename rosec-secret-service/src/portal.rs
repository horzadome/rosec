//! XDG Desktop Portal Secret backend (`org.freedesktop.impl.portal.Secret`).
//!
//! Provides sandboxed Flatpak/Snap apps with a stable per-application secret
//! they can use to derive encryption keys for their own storage.
//!
//! The implementation follows the generate-and-store pattern used by
//! gnome-keyring, oo7-portal, and KWallet: on first request for an `app_id`,
//! generate 64 random bytes, store them as an item in the write-capable
//! provider, and return them.  Subsequent requests look up the stored item.

use std::collections::HashMap;
use std::sync::Arc;

use rand::Rng;
use zbus::fdo::Error as FdoError;
use zbus::interface;
use zbus::message::Header;
use zeroize::Zeroizing;
use zvariant::{ObjectPath, OwnedValue};

use rosec_core::{ItemType, NewItem, SecretBytes};

use crate::state::{ServiceState, map_provider_error};

/// Portal secret items are stored with this schema attribute so they can be
/// distinguished from regular user items.
const PORTAL_SCHEMA: &str = "org.freedesktop.portal.Secret";

/// The attribute key used to look up portal secrets by application ID.
const PORTAL_ATTR_APP_ID: &str = "app_id";

/// The attribute key for the XDG schema.
const PORTAL_ATTR_SCHEMA: &str = "xdg:schema";

/// Size of the per-app secret in bytes (matches gnome-keyring, oo7, and KWallet).
const SECRET_SIZE: usize = 64;

/// Result of looking up an existing portal secret.
enum PortalLookup {
    /// Secret found and readable.
    Found(Zeroizing<Vec<u8>>),
    /// Secret exists but the provider is locked — caller should not generate
    /// a replacement (that would silently overwrite the real secret).
    Locked,
}

pub struct PortalSecret {
    state: Arc<ServiceState>,
}

impl PortalSecret {
    pub fn new(state: Arc<ServiceState>) -> Self {
        Self { state }
    }
}

#[interface(name = "org.freedesktop.impl.portal.Secret")]
impl PortalSecret {
    /// Retrieve (or create) a stable per-application secret and write it to `fd`.
    ///
    /// If a secret for `app_id` already exists in the vault, it is returned.
    /// Otherwise a new 64-byte random secret is generated, stored, and returned.
    async fn retrieve_secret(
        &self,
        _handle: ObjectPath<'_>,
        app_id: &str,
        fd: zvariant::OwnedFd,
        _options: HashMap<String, OwnedValue>,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(u32, HashMap<String, OwnedValue>), FdoError> {
        crate::daemon::log_dbus_caller("portal", "RetrieveSecret", &header);
        self.state.touch_activity();

        tracing::info!(app_id, "portal: RetrieveSecret");

        // Defense-in-depth: xdg-desktop-portal validates app_id against the
        // sandbox, but direct D-Bus callers can pass anything.
        if app_id.is_empty() {
            tracing::warn!("portal: rejecting empty app_id");
            return Ok((2, HashMap::new()));
        }

        // Try to find an existing portal secret for this app_id.
        // Note: concurrent calls for the same app_id can race here — both see
        // None and both generate.  The second create_item(replace=true) wins,
        // which is acceptable: the first caller already wrote its secret to
        // its fd before the overwrite, and subsequent calls converge.
        let existing = self.find_portal_secret(app_id).await?;

        let secret = match existing {
            Some(PortalLookup::Found(bytes)) => {
                tracing::debug!(app_id, "portal: returning existing secret");
                bytes
            }
            Some(PortalLookup::Locked) => {
                tracing::info!(app_id, "portal: vault locked, cannot retrieve secret");
                return Ok((2, HashMap::new()));
            }
            None => {
                tracing::debug!(app_id, "portal: generating new secret");
                match self.generate_and_store(app_id).await {
                    Ok(s) => s,
                    Err(_) => return Ok((2, HashMap::new())),
                }
            }
        };

        // Write the secret to the file descriptor.
        if let Err(e) = self.write_to_fd(fd, &secret) {
            tracing::warn!(app_id, "portal: fd write failed: {e}");
            return Ok((2, HashMap::new()));
        }

        Ok((0, HashMap::new()))
    }

    /// The portal interface version.
    #[zbus(property)]
    fn version(&self) -> u32 {
        1
    }
}

impl PortalSecret {
    /// Search for an existing portal secret item matching `app_id`.
    ///
    /// Uses the metadata cache (survives lock/unlock cycles) so we never
    /// accidentally regenerate a secret just because the vault was locked
    /// between the store and the next lookup.
    async fn find_portal_secret(&self, app_id: &str) -> Result<Option<PortalLookup>, FdoError> {
        let mut search_attrs = HashMap::new();
        search_attrs.insert(PORTAL_ATTR_APP_ID.to_string(), app_id.to_string());
        search_attrs.insert(PORTAL_ATTR_SCHEMA.to_string(), PORTAL_SCHEMA.to_string());

        let (unlocked, locked) = self.state.search_metadata_cache(&search_attrs)?;

        // If the secret exists but its provider is locked, signal that to the
        // caller so it can return response code 2 rather than generating a new
        // (conflicting) secret.
        if let Some(path) = locked.first() {
            tracing::debug!(app_id, path, "portal: secret exists but provider is locked");
            return Ok(Some(PortalLookup::Locked));
        }

        let path = match unlocked.first() {
            Some(p) => p.clone(),
            None => return Ok(None),
        };

        let (provider, item_id) = self.state.provider_and_id_for_path(&path)?;

        let secret = self
            .state
            .run_on_tokio({
                let provider = Arc::clone(&provider);
                let item_id = item_id.to_string();
                async move { provider.get_secret_attr(&item_id, "secret").await }
            })
            .await?
            .map_err(map_provider_error)?;

        Ok(Some(PortalLookup::Found(Zeroizing::new(
            secret.as_slice().to_vec(),
        ))))
    }

    /// Generate a new 64-byte random secret and store it as an item.
    async fn generate_and_store(&self, app_id: &str) -> Result<Zeroizing<Vec<u8>>, FdoError> {
        let write_provider = self.state.write_provider().ok_or_else(|| {
            FdoError::Failed("no write-capable provider available — add a local vault first".into())
        })?;

        // Verify the provider is unlocked.
        let status = self
            .state
            .run_on_tokio({
                let provider = Arc::clone(&write_provider);
                async move { provider.status().await }
            })
            .await?
            .map_err(map_provider_error)?;

        if status.locked {
            return Err(FdoError::Failed(
                "vault is locked — unlock before retrieving portal secrets".into(),
            ));
        }

        // Generate 64 bytes of random data.
        let mut secret_bytes = Zeroizing::new(vec![0u8; SECRET_SIZE]);
        rand::rng().fill_bytes(&mut secret_bytes);

        // Build attributes.
        let mut attributes = HashMap::new();
        attributes.insert(PORTAL_ATTR_APP_ID.to_string(), app_id.to_string());
        attributes.insert(PORTAL_ATTR_SCHEMA.to_string(), PORTAL_SCHEMA.to_string());

        // Build secrets map — clone into SecretBytes via from_zeroizing to
        // avoid an intermediate plain Vec that wouldn't be zeroized on drop.
        let mut secrets = HashMap::new();
        secrets.insert(
            "secret".to_string(),
            SecretBytes::from_zeroizing(Zeroizing::new(secret_bytes.to_vec())),
        );

        let item = NewItem {
            label: format!("Portal secret for {app_id}"),
            item_type: Some(ItemType::Generic),
            attributes,
            secrets,
        };

        // Store the item.
        let item_path = self
            .state
            .run_on_tokio({
                let provider = Arc::clone(&write_provider);
                async move { provider.create_item(item, true).await }
            })
            .await?
            .map_err(map_provider_error)?;

        tracing::info!(app_id, path = %item_path, "portal: stored new secret");

        // Rebuild the item cache so subsequent lookups find it immediately.
        let _ = self.state.rebuild_cache().await;

        Ok(secret_bytes)
    }

    /// Write the secret bytes to the file descriptor and close it.
    fn write_to_fd(&self, fd: zvariant::OwnedFd, secret: &[u8]) -> Result<(), FdoError> {
        use std::io::Write;
        use std::os::unix::io::{AsRawFd, FromRawFd};

        // Duplicate with O_CLOEXEC so the fd isn't leaked to child processes
        // if a fork+exec happens concurrently on another thread.
        let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if raw < 0 {
            return Err(FdoError::Failed(format!(
                "fcntl(F_DUPFD_CLOEXEC) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: raw is a valid fd from fcntl(); we take full ownership.
        let mut file = unsafe { std::fs::File::from_raw_fd(raw) };
        file.write_all(secret)
            .map_err(|e| FdoError::Failed(format!("failed to write secret to fd: {e}")))?;
        // file is dropped here, closing the fd — signals EOF to the reader.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use rosec_core::router::{Router, RouterConfig};
    use rosec_core::{
        Attributes, Capability, DedupStrategy, DedupTimeFallback, ItemMeta, ProviderError,
        ProviderStatus, UnlockInput,
    };
    use zbus::Connection;

    use crate::session::SessionManager;
    use crate::state::ServiceState;

    /// Mock provider that supports Write + create_item for portal tests.
    #[derive(Debug)]
    struct WritableMock {
        items: std::sync::Mutex<Vec<ItemMeta>>,
        secrets: std::sync::Mutex<HashMap<String, Vec<u8>>>,
        next_id: std::sync::Mutex<u32>,
    }

    impl WritableMock {
        fn new(items: Vec<ItemMeta>) -> Self {
            Self {
                items: std::sync::Mutex::new(items),
                secrets: std::sync::Mutex::new(HashMap::new()),
                next_id: std::sync::Mutex::new(1),
            }
        }
    }

    #[async_trait::async_trait]
    impl rosec_core::Provider for WritableMock {
        fn id(&self) -> &str {
            "writable-mock"
        }
        fn name(&self) -> &str {
            "Writable Mock"
        }
        fn kind(&self) -> &str {
            "mock"
        }
        fn capabilities(&self) -> &'static [Capability] {
            &[Capability::Write]
        }

        async fn status(&self) -> Result<ProviderStatus, ProviderError> {
            Ok(ProviderStatus {
                locked: false,
                last_sync: None,
                cached: false,
                offline_cache: false,
                last_cache_write: None,
            })
        }

        async fn unlock(&self, _input: UnlockInput) -> Result<(), ProviderError> {
            Ok(())
        }
        async fn lock(&self) -> Result<(), ProviderError> {
            Ok(())
        }

        async fn list_items(&self) -> Result<Vec<ItemMeta>, ProviderError> {
            Ok(self.items.lock().unwrap().clone())
        }

        async fn search(&self, attrs: &Attributes) -> Result<Vec<ItemMeta>, ProviderError> {
            let items = self.items.lock().unwrap();
            Ok(items
                .iter()
                .filter(|item| attrs.iter().all(|(k, v)| item.attributes.get(k) == Some(v)))
                .cloned()
                .collect())
        }

        async fn get_item_attributes(
            &self,
            _id: &str,
        ) -> Result<rosec_core::ItemAttributes, ProviderError> {
            Ok(rosec_core::ItemAttributes {
                public: Attributes::new(),
                secret_names: vec!["secret".to_string()],
            })
        }

        async fn get_secret_attr(
            &self,
            id: &str,
            _attr: &str,
        ) -> Result<SecretBytes, ProviderError> {
            let secrets = self.secrets.lock().unwrap();
            secrets
                .get(id)
                .map(|v| SecretBytes::new(v.clone()))
                .ok_or(ProviderError::NotFound)
        }

        async fn create_item(
            &self,
            item: NewItem,
            _replace: bool,
        ) -> Result<String, ProviderError> {
            let mut counter = self.next_id.lock().unwrap();
            let id = format!("portal-{counter}");
            *counter += 1;

            // Store the secret bytes.
            if let Some(secret) = item.secrets.get("secret") {
                self.secrets
                    .lock()
                    .unwrap()
                    .insert(id.clone(), secret.as_slice().to_vec());
            }

            // Add to items list.
            let meta = ItemMeta {
                id: id.clone(),
                provider_id: "writable-mock".to_string(),
                label: item.label,
                attributes: item.attributes,
                created: None,
                modified: None,
                locked: false,
            };
            self.items.lock().unwrap().push(meta);

            let path = format!("/org/freedesktop/secrets/collection/default/writable_mock_{id}");
            Ok(path)
        }
    }

    async fn portal_state(items: Vec<ItemMeta>) -> (Arc<ServiceState>, Arc<WritableMock>) {
        let provider = Arc::new(WritableMock::new(items));
        let router = Arc::new(Router::new(RouterConfig {
            dedup_strategy: DedupStrategy::Newest,
            dedup_time_fallback: DedupTimeFallback::Created,
        }));
        let sessions = Arc::new(SessionManager::new());
        let conn = Connection::session()
            .await
            .expect("session bus required for tests");
        let state = Arc::new(ServiceState::new(
            vec![provider.clone() as Arc<dyn rosec_core::Provider>],
            router,
            sessions,
            conn,
            tokio::runtime::Handle::current(),
        ));
        (state, provider)
    }

    #[tokio::test]
    async fn find_returns_none_when_no_portal_secret_exists() {
        let (state, _provider) = portal_state(vec![]).await;
        // Populate cache.
        state
            .resolve_items(Some(HashMap::new()), None)
            .await
            .expect("cache");

        let portal = PortalSecret::new(state);
        let result = portal
            .find_portal_secret("org.test.NoSuchApp")
            .await
            .expect("find should not error");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn generate_and_store_creates_64_byte_secret() {
        let (state, provider) = portal_state(vec![]).await;
        state
            .resolve_items(Some(HashMap::new()), None)
            .await
            .expect("cache");

        let portal = PortalSecret::new(Arc::clone(&state));
        let secret = portal.generate_and_store("org.test.NewApp").await;
        assert!(secret.is_ok(), "generate_and_store failed: {secret:?}");
        let secret = secret.unwrap();
        assert_eq!(secret.len(), SECRET_SIZE);

        // Verify it was stored in the provider.
        let stored = provider.secrets.lock().unwrap();
        assert_eq!(stored.len(), 1);
        let stored_bytes = stored.values().next().unwrap();
        assert_eq!(stored_bytes.as_slice(), secret.as_slice());
    }

    #[tokio::test]
    async fn generate_produces_different_secrets_per_app() {
        let (state, _provider) = portal_state(vec![]).await;
        state
            .resolve_items(Some(HashMap::new()), None)
            .await
            .expect("cache");

        let portal = PortalSecret::new(Arc::clone(&state));
        let secret_a = portal.generate_and_store("org.test.AppA").await.unwrap();
        let secret_b = portal.generate_and_store("org.test.AppB").await.unwrap();
        assert_ne!(
            secret_a.as_slice(),
            secret_b.as_slice(),
            "different app_ids should get different secrets"
        );
    }

    #[tokio::test]
    async fn find_returns_stored_secret_after_generate() {
        let (state, _provider) = portal_state(vec![]).await;
        state
            .resolve_items(Some(HashMap::new()), None)
            .await
            .expect("cache");

        let portal = PortalSecret::new(Arc::clone(&state));
        let generated = portal.generate_and_store("org.test.Stable").await.unwrap();

        // The cache was rebuilt inside generate_and_store, so find should work.
        let found = portal
            .find_portal_secret("org.test.Stable")
            .await
            .expect("find should not error");
        match found {
            Some(PortalLookup::Found(bytes)) => {
                assert_eq!(
                    bytes.as_slice(),
                    generated.as_slice(),
                    "found secret should match generated"
                );
            }
            Some(PortalLookup::Locked) => panic!("expected Found, got Locked"),
            None => panic!("expected Found, got None"),
        }
    }

    #[test]
    fn write_to_fd_writes_exact_bytes() {
        use std::os::unix::io::FromRawFd;

        // Test the same dup+write+close logic used by PortalSecret::write_to_fd.
        let (r, w) = nix_pipe();
        let portal_secret = &[0xDE, 0xAD, 0xBE, 0xEF];

        // Wrap the write fd as a zvariant::OwnedFd (same type D-Bus passes).
        let owned: std::os::fd::OwnedFd = unsafe { std::os::fd::OwnedFd::from_raw_fd(w) };
        let zvar_fd = zvariant::OwnedFd::from(owned);

        // Replicate write_to_fd logic.
        {
            use std::io::Write;
            use std::os::unix::io::AsRawFd;
            let raw = unsafe { libc::dup(zvar_fd.as_raw_fd()) };
            assert!(raw >= 0);
            let mut file = unsafe { std::fs::File::from_raw_fd(raw) };
            file.write_all(portal_secret).unwrap();
        }
        drop(zvar_fd);

        let mut buf = [0u8; 16];
        let n = unsafe { libc::read(r, buf.as_mut_ptr().cast(), buf.len()) };
        unsafe { libc::close(r) };
        assert_eq!(n as usize, portal_secret.len());
        assert_eq!(&buf[..n as usize], portal_secret);
    }

    fn nix_pipe() -> (i32, i32) {
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        (fds[0], fds[1])
    }
}
