//! `WasmProvider` — wraps an Extism WASM plugin as a `rosec_core::Provider`.

use std::collections::HashMap;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine;
use extism::{Manifest, Plugin, Wasm};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::Mutex;
use tracing::{debug, error, warn};
use zeroize::{Zeroize, Zeroizing};

use rosec_core::{
    AttributeDescriptor, Attributes, AuthField, AuthFieldKind, Capability, ItemAttributes,
    ItemMeta, Provider, ProviderCallbacks, ProviderError, ProviderStatus, RegistrationInfo,
    SecretBytes, SshKeyMeta, SshPrivateKeyMaterial, UnlockInput,
};

use crate::protocol::{
    AuthFieldsResponse, CapabilitiesResponse, ErrorKind, InitRequest, InitResponse,
    ItemAttributesResponse, ItemIdRequest, ItemListResponse, RegistrationInfoResponse,
    SearchRequest, SecretAttrRequest, SecretAttrResponse, SimpleResponse, SshKeyListResponse,
    SshPrivateKeyRequest, SshPrivateKeyResponse, StatusResponse, UnlockRequest,
    WasmAttributeDescriptor, WasmSshKeyMeta,
};

// ── Configuration ────────────────────────────────────────────────

/// Default timeout for guest function calls (60 seconds).
///
/// This covers the worst-case network latency for operations like
/// `unlock` and `sync` that hit Bitwarden's API.  If a guest call
/// exceeds this duration the WASM execution is interrupted via
/// wasmtime epoch interruption, and the provider returns an error
/// instead of blocking indefinitely.
const GUEST_CALL_TIMEOUT: Duration = Duration::from_secs(60);

/// Configuration for constructing a `WasmProvider`.
#[derive(Debug, Clone)]
pub struct WasmProviderConfig {
    /// Unique provider ID (from config file).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Provider kind string (e.g. `"bitwarden-wasm"`).
    pub kind: String,
    /// Path to the `.wasm` file.
    pub wasm_path: String,
    /// Allowed HTTP hosts the plugin may contact (e.g. `["*.bitwarden.com"]`).
    pub allowed_hosts: Vec<String>,
    /// Filesystem paths the WASI sandbox may access.
    ///
    /// Each entry maps a host path to the guest-visible path.
    /// Prefix the host path with `ro:` for read-only access (recommended).
    /// Example: `("ro:/home/user/.local/share/keyrings", "/home/user/.local/share/keyrings")`
    pub allowed_paths: Vec<(String, std::path::PathBuf)>,
    /// Opaque key-value options forwarded to the guest `init` function.
    pub options: HashMap<String, serde_json::Value>,
}

// ── WasmProvider ─────────────────────────────────────────────────

/// A `Provider` backed by an Extism WASM plugin.
///
/// All plugin calls go through a `Mutex<Plugin>` because `extism::Plugin`
/// is `Send + Sync` but `call` takes `&mut self`.
pub struct WasmProvider {
    config: WasmProviderConfig,
    plugin: Mutex<Plugin>,
    /// Stored manifest for plugin recreation after a WASM trap.
    manifest: Manifest,
    /// Capabilities queried once from the guest at construction time.
    /// Leaked so we can return `&'static [Capability]` from the trait.
    capabilities: &'static [Capability],
    /// Attribute descriptors queried once from the guest at construction time.
    /// Leaked so we can return `&'static [AttributeDescriptor]` from the trait.
    attribute_descriptors: &'static [AttributeDescriptor],
    /// Auth fields queried once from the guest at construction time.
    auth_fields: &'static [AuthField],
    /// Registration info queried once from the guest at construction time.
    registration_info: Option<RegistrationInfo>,
    /// Readiness probes queried once from the guest after init.
    readiness_probes: Vec<crate::protocol::ReadinessProbe>,
    /// Callbacks registered by the daemon
    callbacks: std::sync::RwLock<ProviderCallbacks>,
    /// Cached timestamp of the last successful sync.
    last_sync_time: std::sync::Mutex<Option<chrono::DateTime<chrono::Utc>>>,
}

impl std::fmt::Debug for WasmProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmProvider")
            .field("id", &self.config.id)
            .field("name", &self.config.name)
            .field("wasm_path", &self.config.wasm_path)
            .finish()
    }
}

impl WasmProvider {
    /// Create a new `WasmProvider` from config.
    ///
    /// Loads the WASM module, creates the Extism plugin, calls the guest
    /// `init` function, and eagerly queries `capabilities`,
    /// `attribute_descriptors`, `auth_fields`, and `registration_info`.
    ///
    /// The static-lifetime slices are created via `Box::leak`; this is
    /// acceptable because providers live for the process lifetime.
    pub fn new(config: WasmProviderConfig) -> Result<Self, ProviderError> {
        // Warn if the allowed-hosts list grants unrestricted network access.
        for host in &config.allowed_hosts {
            if host.trim() == "*" {
                warn!(
                    provider = %config.id,
                    wasm = %config.wasm_path,
                    "WASM plugin has unrestricted network access (allowed_hosts contains '*'). \
                     Consider restricting to specific hosts for security.",
                );
                break;
            }
        }

        let wasm = Wasm::file(&config.wasm_path);
        let mut manifest = Manifest::new([wasm])
            .with_allowed_hosts(config.allowed_hosts.iter().cloned())
            .with_timeout(GUEST_CALL_TIMEOUT)
            // Limit WASM linear memory to 256 MiB (4096 pages × 64 KiB/page).
            // Prevents a misbehaving plugin from consuming unbounded host memory.
            .with_memory_max(4096);

        // Pre-open filesystem paths so the WASI sandbox can access them.
        if config.allowed_paths.is_empty() {
            debug!(provider = %config.id, "no WASI allowed_paths configured");
        }
        for (src, dest) in &config.allowed_paths {
            debug!(
                provider = %config.id,
                src = %src,
                dest = %dest.display(),
                "pre-opening WASI path",
            );
            manifest = manifest.with_allowed_path(src.clone(), dest);
        }

        debug!(
            provider = %config.id,
            allowed_hosts = ?config.allowed_hosts,
            allowed_paths = config.allowed_paths.len(),
            "WASM manifest configured",
        );

        // Clone the manifest before consuming it so we can recreate the
        // plugin after a WASM trap (which corrupts the instance).
        let manifest = manifest;
        let mut plugin = Plugin::new(&manifest, [], true).map_err(|e| {
            ProviderError::Other(anyhow::anyhow!(
                "failed to load WASM plugin '{}': {e}",
                config.wasm_path,
            ))
        })?;

        // Call init to let the guest set up its internal state.
        // Inject the host user's home directory into options so guests can
        // resolve default paths without relying on env vars (WASI sandbox
        // does not forward the host environment).
        let mut options = config.options.clone();
        if !options.contains_key("home_dir")
            && let Ok(home) = std::env::var("HOME")
        {
            debug!(provider = %config.id, home = %home, "injecting home_dir into guest options");
            options.insert("home_dir".into(), serde_json::Value::String(home));
        }

        // Log all options being sent to the guest (redact values that may be
        // sensitive — only log the keys and string lengths).
        for (key, val) in &options {
            match val {
                serde_json::Value::String(s) => {
                    debug!(
                        provider = %config.id,
                        key = %key,
                        value_len = s.len(),
                        value_preview = %if s.len() <= 60 { s.as_str() } else { &s[..60] },
                        "guest init option",
                    );
                }
                other => {
                    debug!(
                        provider = %config.id,
                        key = %key,
                        value = %other,
                        "guest init option",
                    );
                }
            }
        }

        let init_req = InitRequest {
            provider_id: config.id.clone(),
            provider_name: config.name.clone(),
            options,
        };
        let init_resp: InitResponse = call_guest_json(&mut plugin, "init", &init_req).0?;
        if !init_resp.ok {
            return Err(ProviderError::Other(anyhow::anyhow!(
                "WASM plugin init failed: {}",
                init_resp.error.unwrap_or_else(|| "unknown error".into()),
            )));
        }

        // ── Eagerly query static metadata from the guest ─────────

        let capabilities = query_capabilities(&mut plugin, &config.id);
        let attribute_descriptors = query_attribute_descriptors(&mut plugin, &config.id);
        let auth_fields = query_auth_fields(&mut plugin, &config.id);
        let registration_info = query_registration_info(&mut plugin, &config.id);
        let readiness_probes = query_readiness_probes(&mut plugin, &config.id);

        debug!(
            provider = %config.id,
            caps = ?capabilities,
            attrs = attribute_descriptors.len(),
            auth = auth_fields.len(),
            reg = registration_info.is_some(),
            probes = readiness_probes.len(),
            "WASM provider initialised",
        );

        Ok(Self {
            config,
            plugin: Mutex::new(plugin),
            manifest,
            capabilities,
            attribute_descriptors,
            auth_fields,
            registration_info,
            readiness_probes,
            callbacks: std::sync::RwLock::new(ProviderCallbacks::default()),
            last_sync_time: std::sync::Mutex::new(None),
        })
    }

    /// Recreate the WASM plugin from the stored manifest after a trap.
    ///
    /// After a WASM trap (timeout, OOM, host function error, guest panic),
    /// the plugin's linear memory and globals are left in a corrupted state.
    /// Extism's `Plugin::reset()` only clears allocation metadata, not the
    /// actual WASM memory.  The only reliable recovery is to create a fresh
    /// Plugin instance and re-run `init`.
    ///
    /// The recreated plugin starts in a locked state (no auth).
    fn recreate_plugin(
        manifest: &Manifest,
        config: &WasmProviderConfig,
    ) -> Result<Plugin, ProviderError> {
        let mut plugin = Plugin::new(manifest, [], true).map_err(|e| {
            ProviderError::Other(anyhow::anyhow!(
                "failed to recreate WASM plugin '{}': {e}",
                config.wasm_path,
            ))
        })?;

        // Re-run init with the same config.
        let mut options = config.options.clone();
        if !options.contains_key("home_dir")
            && let Ok(home) = std::env::var("HOME")
        {
            options.insert("home_dir".into(), serde_json::Value::String(home));
        }

        let init_req = crate::protocol::InitRequest {
            provider_id: config.id.clone(),
            provider_name: config.name.clone(),
            options,
        };
        let init_resp: crate::protocol::InitResponse =
            call_guest_json(&mut plugin, "init", &init_req).0?;
        if !init_resp.ok {
            return Err(ProviderError::Other(anyhow::anyhow!(
                "WASM plugin re-init failed: {}",
                init_resp.error.unwrap_or_else(|| "unknown error".into()),
            )));
        }

        Ok(plugin)
    }

    /// Recreate the plugin after a failed `plugin.call()`.
    ///
    /// In the Extism protocol, guest application errors (wrong password,
    /// not found, etc.) are returned as `Ok` responses with `resp.ok == false`
    /// in the JSON body.  An `Err` from `plugin.call()` only occurs when
    /// something went wrong at the WASM execution level: a trap (timeout,
    /// OOM, host function error, guest panic), a serialization failure, or
    /// a missing function.
    ///
    /// In all of these cases the plugin's linear memory and globals may be
    /// in an undefined state.  Rather than trying to classify which errors
    /// are "real" traps via brittle string matching on wasmtime internals,
    /// we unconditionally recreate the plugin after any `plugin.call()`
    /// failure.  This is safe because:
    ///
    /// - The plugin restarts in a clean locked state (same as fresh boot)
    /// - Serialization / missing-function errors won't be fixed by retrying
    ///   with the same plugin anyway
    /// - The cost (~50-100ms) is acceptable for an error path
    fn recreate_after_call_error(&self, plugin: &mut Plugin, err: &ProviderError) {
        warn!(
            provider = %self.config.id,
            error = %err,
            "WASM plugin call failed, recreating instance",
        );
        match Self::recreate_plugin(&self.manifest, &self.config) {
            Ok(new_plugin) => {
                *plugin = new_plugin;
                debug!(
                    provider = %self.config.id,
                    "plugin instance recreated successfully (now locked)",
                );
            }
            Err(recreate_err) => {
                error!(
                    provider = %self.config.id,
                    "failed to recreate plugin: {recreate_err}",
                );
            }
        }
    }

    /// Call a guest function with JSON input, recreating the plugin if
    /// `plugin.call()` failed (indicating a WASM trap or execution error).
    fn call_json<I: Serialize, O: serde::de::DeserializeOwned>(
        &self,
        plugin: &mut Plugin,
        func: &str,
        input: &I,
    ) -> Result<O, ProviderError> {
        let (result, outcome) = call_guest_json(plugin, func, input);
        if outcome == CallOutcome::PluginCallFailed
            && let Err(ref e) = result
        {
            self.recreate_after_call_error(plugin, e);
        }
        result
    }

    /// Call a guest function with sensitive JSON input, recreating the
    /// plugin if `plugin.call()` failed.  Zeroizes the serialized input
    /// regardless of success or failure.
    fn call_json_sensitive<I: Serialize, O: serde::de::DeserializeOwned>(
        &self,
        plugin: &mut Plugin,
        func: &str,
        input: &I,
    ) -> Result<O, ProviderError> {
        let (result, outcome) = call_guest_json_sensitive(plugin, func, input);
        if outcome == CallOutcome::PluginCallFailed
            && let Err(ref e) = result
        {
            self.recreate_after_call_error(plugin, e);
        }
        result
    }

    /// Call a guest function with no input, recreating the plugin if
    /// `plugin.call()` failed.
    fn call_json_no_input<O: serde::de::DeserializeOwned>(
        &self,
        plugin: &mut Plugin,
        func: &str,
    ) -> Result<O, ProviderError> {
        let (result, outcome) = call_guest_json_no_input(plugin, func);
        if outcome == CallOutcome::PluginCallFailed
            && let Err(ref e) = result
        {
            self.recreate_after_call_error(plugin, e);
        }
        result
    }

    /// Evaluate all readiness probes before attempting unlock.
    ///
    /// Each probe is checked against the manifest's `allowed_hosts` and
    /// executed natively (no WASM involvement).  Uses exponential backoff
    /// if any probe fails.
    ///
    /// Returns `Ok(())` when all probes pass, or `Err` if `max_attempts`
    /// is exhausted.
    async fn wait_for_readiness(&self) -> Result<(), ProviderError> {
        if self.readiness_probes.is_empty() {
            return Ok(());
        }

        const MAX_ATTEMPTS: u32 = 8;
        let initial_delay = Duration::from_millis(500);
        let max_delay = Duration::from_secs(30);
        let mut delay = initial_delay;

        let allowed_hosts = self.manifest.allowed_hosts.as_deref().unwrap_or_default();

        for attempt in 1..=MAX_ATTEMPTS {
            let mut all_ready = true;
            let mut last_failure = String::new();

            for probe in &self.readiness_probes {
                match evaluate_probe(probe, allowed_hosts) {
                    Ok(()) => {}
                    Err(reason) => {
                        all_ready = false;
                        last_failure = reason;
                        break;
                    }
                }
            }

            if all_ready {
                if attempt > 1 {
                    debug!(
                        provider = %self.config.id,
                        attempt,
                        "all readiness probes passed",
                    );
                }
                return Ok(());
            }

            debug!(
                provider = %self.config.id,
                attempt,
                delay_ms = delay.as_millis() as u64,
                reason = %last_failure,
                "readiness probe failed, backing off",
            );

            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(max_delay);
        }

        Err(ProviderError::Unavailable(format!(
            "readiness probes not satisfied after {MAX_ATTEMPTS} attempts"
        )))
    }
}

// ── Provider trait impl ──────────────────────────────────────────

#[async_trait]
impl Provider for WasmProvider {
    fn id(&self) -> &str {
        &self.config.id
    }

    fn name(&self) -> &str {
        &self.config.name
    }

    fn kind(&self) -> &str {
        &self.config.kind
    }

    fn capabilities(&self) -> &'static [Capability] {
        self.capabilities
    }

    fn available_attributes(&self) -> &'static [AttributeDescriptor] {
        self.attribute_descriptors
    }

    fn auth_fields(&self) -> &'static [AuthField] {
        self.auth_fields
    }

    fn registration_info(&self) -> Option<RegistrationInfo> {
        self.registration_info
    }

    fn set_event_callbacks(&self, callbacks: ProviderCallbacks) -> Result<(), ProviderError> {
        let mut cbs = self
            .callbacks
            .write()
            .map_err(|e| ProviderError::Other(anyhow::anyhow!("callback lock poisoned: {e}")))?;
        *cbs = callbacks;
        Ok(())
    }

    fn password_field(&self) -> AuthField {
        // If the guest declared auth fields, use the first password-kind
        // field; otherwise fall back to the default.
        self.auth_fields
            .iter()
            .find(|f| f.kind == AuthFieldKind::Password)
            .copied()
            .unwrap_or(AuthField {
                id: "password",
                label: "Master Password",
                placeholder: "Enter your master password",
                required: true,
                kind: AuthFieldKind::Password,
            })
    }

    async fn status(&self) -> Result<ProviderStatus, ProviderError> {
        let mut plugin = self.plugin.lock().await;
        let resp: StatusResponse = self.call_json_no_input(&mut plugin, "status")?;
        Ok(ProviderStatus {
            locked: resp.locked,
            last_sync: resp
                .last_sync_epoch_secs
                .map(|s| UNIX_EPOCH + Duration::from_secs(s)),
        })
    }

    async fn unlock(&self, input: UnlockInput) -> Result<(), ProviderError> {
        // Wait for readiness probes before attempting unlock.
        self.wait_for_readiness().await?;

        // Extract the password (needed for credential persistence key derivation).
        let password_ref: &Zeroizing<String> = match &input {
            UnlockInput::Password(pw) => pw,
            UnlockInput::WithRegistration { password, .. }
            | UnlockInput::WithAuth { password, .. } => password,
        };

        let mut req = match &input {
            UnlockInput::Password(pw) => UnlockRequest {
                password: pw.as_str().to_owned(),
                registration_fields: None,
                auth_fields: None,
            },
            UnlockInput::WithRegistration {
                password,
                registration_fields,
            } => UnlockRequest {
                password: password.as_str().to_owned(),
                registration_fields: Some(
                    registration_fields
                        .iter()
                        .map(|(k, v)| (k.clone(), v.as_str().to_owned()))
                        .collect(),
                ),
                auth_fields: None,
            },
            UnlockInput::WithAuth {
                password,
                auth_fields,
            } => UnlockRequest {
                password: password.as_str().to_owned(),
                registration_fields: None,
                auth_fields: Some(
                    auth_fields
                        .iter()
                        .map(|(k, v)| (k.clone(), v.as_str().to_owned()))
                        .collect(),
                ),
            },
        };

        let has_registration = req.registration_fields.is_some();
        let mut plugin = self.plugin.lock().await;

        let result: Result<SimpleResponse, ProviderError> =
            self.call_json_sensitive(&mut plugin, "unlock", &req);

        // If the guest requires registration and none was provided, try
        // loading stored credentials from a previous session.
        let result = match result {
            Ok(ref resp) if !resp.ok => {
                let is_reg_required = resp
                    .error_kind
                    .as_ref()
                    .is_some_and(|k| matches!(k, ErrorKind::RegistrationRequired));
                if is_reg_required && !has_registration {
                    match crate::wasm_cred::load(&self.config.id, password_ref.as_str()) {
                        Ok(Some(stored_fields)) => {
                            debug!(
                                provider = %self.config.id,
                                "loaded stored credentials, retrying unlock with registration"
                            );
                            // Pass the stored fields directly to the guest — they use
                            // whatever field names the provider registered with (e.g.
                            // "access_token" for SM, "client_id"/"client_secret" for PM).
                            let reg_fields_plain: HashMap<String, String> = stored_fields
                                .iter()
                                .map(|(k, v)| (k.clone(), v.as_str().to_owned()))
                                .collect();

                            let mut retry_req = UnlockRequest {
                                password: password_ref.as_str().to_owned(),
                                registration_fields: Some(reg_fields_plain),
                                auth_fields: None,
                            };

                            let retry_result: Result<SimpleResponse, ProviderError> =
                                self.call_json_sensitive(&mut plugin, "unlock", &retry_req);

                            retry_req.password.zeroize();
                            if let Some(ref mut fields) = retry_req.registration_fields {
                                for v in fields.values_mut() {
                                    v.zeroize();
                                }
                            }

                            retry_result
                        }
                        Ok(None) => {
                            debug!(
                                provider = %self.config.id,
                                "no stored credentials found"
                            );
                            result
                        }
                        Err(e) => {
                            // Decryption failed — most likely a wrong password.
                            // Do NOT clear stored credentials (the user may just
                            // have mistyped the password).  Return AuthFailed so
                            // the caller reports "wrong password" rather than
                            // entering the registration flow.
                            warn!(
                                provider = %self.config.id,
                                "failed to decrypt stored credentials: {e}"
                            );
                            Ok(SimpleResponse {
                                ok: false,
                                error: Some("wrong password".to_string()),
                                error_kind: Some(ErrorKind::AuthFailed),
                                two_factor_methods: None,
                            })
                        }
                    }
                } else {
                    result
                }
            }
            _ => result,
        };

        // Zeroize the original request fields.
        req.password.zeroize();
        if let Some(ref mut fields) = req.registration_fields {
            for v in fields.values_mut() {
                v.zeroize();
            }
        }

        let resp = result?;
        if resp.ok {
            // If registration fields were provided, persist them for next time.
            if has_registration
                && let UnlockInput::WithRegistration {
                    registration_fields,
                    ..
                } = &input
            {
                // Save all registration fields so we can restore them on the
                // next unlock without prompting the user again.
                match crate::wasm_cred::save(
                    &self.config.id,
                    password_ref.as_str(),
                    registration_fields,
                ) {
                    Ok(()) => {
                        debug!(
                            provider = %self.config.id,
                            "saved registration credentials"
                        );
                    }
                    Err(e) => {
                        warn!(
                            provider = %self.config.id,
                            "failed to save registration credentials: {e}"
                        );
                    }
                }
            }

            // Update the cached last-sync timestamp (unlock = first sync).
            if let Ok(mut guard) = self.last_sync_time.lock() {
                *guard = Some(chrono::Utc::now());
            }
            // Fire on_unlocked callback.
            if let Ok(cbs) = self.callbacks.read()
                && let Some(ref cb) = cbs.on_unlocked
            {
                cb();
            }
            Ok(())
        } else if resp
            .error_kind
            .as_ref()
            .is_some_and(|k| matches!(k, ErrorKind::TwoFactorRequired))
        {
            Err(map_guest_2fa_error(resp.error, resp.two_factor_methods))
        } else {
            Err(map_guest_error(resp.error, resp.error_kind))
        }
    }

    fn last_synced_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.last_sync_time.lock().ok().and_then(|g| *g)
    }

    async fn lock(&self) -> Result<(), ProviderError> {
        let mut plugin = self.plugin.lock().await;
        let resp: SimpleResponse = self.call_json_no_input(&mut plugin, "lock")?;
        if resp.ok {
            if let Ok(cbs) = self.callbacks.read()
                && let Some(ref cb) = cbs.on_locked
            {
                cb();
            }
            Ok(())
        } else {
            Err(map_guest_error(resp.error, resp.error_kind))
        }
    }

    async fn sync(&self) -> Result<(), ProviderError> {
        self.wait_for_readiness().await?;
        let mut plugin = self.plugin.lock().await;
        if !plugin.function_exists("sync") {
            return Err(ProviderError::NotSupported);
        }
        let resp: SimpleResponse = self.call_json_no_input(&mut plugin, "sync")?;
        if resp.ok {
            // Update the cached last-sync timestamp.
            if let Ok(mut guard) = self.last_sync_time.lock() {
                *guard = Some(chrono::Utc::now());
            }
            if let Ok(cbs) = self.callbacks.read()
                && let Some(ref cb) = cbs.on_sync_succeeded
            {
                cb(true);
            }
            Ok(())
        } else {
            if let Ok(cbs) = self.callbacks.read()
                && let Some(ref cb) = cbs.on_sync_failed
            {
                cb();
            }
            Err(map_guest_error(resp.error, resp.error_kind))
        }
    }

    async fn list_items(&self) -> Result<Vec<ItemMeta>, ProviderError> {
        let mut plugin = self.plugin.lock().await;
        let resp: ItemListResponse = self.call_json_no_input(&mut plugin, "list_items")?;
        if !resp.ok {
            return Err(map_guest_error(resp.error, resp.error_kind));
        }
        Ok(resp
            .items
            .into_iter()
            .map(|w| to_item_meta(w, &self.config.id))
            .collect())
    }

    async fn search(&self, attrs: &Attributes) -> Result<Vec<ItemMeta>, ProviderError> {
        let req = SearchRequest {
            attributes: attrs.clone(),
        };
        let mut plugin = self.plugin.lock().await;
        let resp: ItemListResponse = self.call_json(&mut plugin, "search", &req)?;
        if !resp.ok {
            return Err(map_guest_error(resp.error, resp.error_kind));
        }
        Ok(resp
            .items
            .into_iter()
            .map(|w| to_item_meta(w, &self.config.id))
            .collect())
    }

    async fn get_item_attributes(&self, id: &str) -> Result<ItemAttributes, ProviderError> {
        let req = ItemIdRequest { id: id.to_owned() };
        let mut plugin = self.plugin.lock().await;
        let resp: ItemAttributesResponse =
            self.call_json(&mut plugin, "get_item_attributes", &req)?;
        if !resp.ok {
            return Err(map_guest_error(resp.error, resp.error_kind));
        }
        Ok(ItemAttributes {
            public: resp.public,
            secret_names: resp.secret_names,
        })
    }

    async fn get_secret_attr(&self, id: &str, attr: &str) -> Result<SecretBytes, ProviderError> {
        let req = SecretAttrRequest {
            id: id.to_owned(),
            attr: attr.to_owned(),
        };
        let mut plugin = self.plugin.lock().await;
        let resp: SecretAttrResponse = self.call_json(&mut plugin, "get_secret_attr", &req)?;
        if !resp.ok {
            return Err(map_guest_error(resp.error, resp.error_kind));
        }
        let mut b64 = resp.value_b64.ok_or(ProviderError::NotFound)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .map_err(|e| ProviderError::Other(anyhow::anyhow!("invalid base64 from guest: {e}")));
        // Zeroize the base64 string — it contained the secret in encoded form.
        b64.zeroize();
        Ok(SecretBytes::new(bytes?))
    }

    async fn list_ssh_keys(&self) -> Result<Vec<SshKeyMeta>, ProviderError> {
        let mut plugin = self.plugin.lock().await;
        if !plugin.function_exists("list_ssh_keys") {
            return Ok(Vec::new());
        }
        let resp: SshKeyListResponse = self.call_json_no_input(&mut plugin, "list_ssh_keys")?;
        if !resp.ok {
            return Err(map_guest_error(resp.error, resp.error_kind));
        }
        Ok(resp
            .keys
            .into_iter()
            .map(|w| to_ssh_key_meta(w, &self.config.id))
            .collect())
    }

    async fn get_ssh_private_key(&self, id: &str) -> Result<SshPrivateKeyMaterial, ProviderError> {
        let req = SshPrivateKeyRequest {
            item_id: id.to_owned(),
        };
        let mut plugin = self.plugin.lock().await;
        if !plugin.function_exists("get_ssh_private_key") {
            return Err(ProviderError::NotSupported);
        }
        let resp: SshPrivateKeyResponse =
            self.call_json(&mut plugin, "get_ssh_private_key", &req)?;
        if !resp.ok {
            return Err(map_guest_error(resp.error, resp.error_kind));
        }
        let pem = resp.pem.ok_or(ProviderError::NotFound)?;
        Ok(SshPrivateKeyMaterial {
            pem: Zeroizing::new(pem),
        })
    }

    /// Check whether the remote has changed since the last sync.
    ///
    /// If the guest exports `check_remote_changed`, delegate to it with an
    /// ISO-8601 timestamp derived from `last_synced_at()`.  This allows
    /// SM guests to use the lightweight delta-sync endpoint instead of a
    /// full re-fetch.
    ///
    /// If the guest does not export the function, falls back to the trait
    /// default (`Ok(true)` — assume changed, trigger a full sync).
    async fn check_remote_changed(&self) -> Result<bool, ProviderError> {
        // Check if the guest supports this function (requires plugin lock).
        // Build the ISO-8601 timestamp from the cached last_sync_time before
        // acquiring the plugin lock to avoid holding two locks simultaneously.
        let iso8601 = match self.last_synced_at() {
            Some(dt) => dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            None => {
                // No prior sync — assume changed.
                return Ok(true);
            }
        };

        self.wait_for_readiness().await?;

        let mut plugin = self.plugin.lock().await;
        if !plugin.function_exists("check_remote_changed") {
            // No guest support — assume changed (safe default).
            return Ok(true);
        }

        let req = crate::protocol::CheckRemoteChangedRequest {
            last_synced_iso8601: iso8601,
        };

        let resp: crate::protocol::CheckRemoteChangedResponse =
            self.call_json(&mut plugin, "check_remote_changed", &req)?;

        if !resp.ok {
            // On guest error, assume changed so the host falls back to full sync.
            debug!(provider = %self.config.id, error = ?resp.error,
                "check_remote_changed guest error, assuming changed");
            return Ok(true);
        }

        Ok(resp.has_changes)
    }
}

// ── Eager metadata queries (called during new()) ─────────────────

/// Query capabilities from the guest, leak into `&'static [Capability]`.
fn query_capabilities(plugin: &mut Plugin, provider_id: &str) -> &'static [Capability] {
    if !plugin.function_exists("capabilities") {
        return &[];
    }
    match call_guest_json_no_input::<CapabilitiesResponse>(plugin, "capabilities").0 {
        Ok(resp) => {
            let caps: Vec<Capability> = resp
                .capabilities
                .iter()
                .filter_map(|s| parse_capability(s))
                .collect();
            if caps.is_empty() {
                &[]
            } else {
                Box::leak(caps.into_boxed_slice())
            }
        }
        Err(e) => {
            warn!(provider = %provider_id, "capabilities call failed: {e}");
            &[]
        }
    }
}

/// Query attribute descriptors from the guest, leak into `&'static [AttributeDescriptor]`.
fn query_attribute_descriptors(
    plugin: &mut Plugin,
    provider_id: &str,
) -> &'static [AttributeDescriptor] {
    if !plugin.function_exists("attribute_descriptors") {
        return &[];
    }
    match call_guest_json_no_input::<crate::protocol::AttributeDescriptorsResponse>(
        plugin,
        "attribute_descriptors",
    )
    .0
    {
        Ok(resp) => {
            let descs: Vec<AttributeDescriptor> = resp
                .descriptors
                .into_iter()
                .map(leak_attribute_descriptor)
                .collect();
            if descs.is_empty() {
                &[]
            } else {
                Box::leak(descs.into_boxed_slice())
            }
        }
        Err(e) => {
            warn!(provider = %provider_id, "attribute_descriptors call failed: {e}");
            &[]
        }
    }
}

/// Query auth fields from the guest, leak into `&'static [AuthField]`.
fn query_auth_fields(plugin: &mut Plugin, provider_id: &str) -> &'static [AuthField] {
    if !plugin.function_exists("auth_fields") {
        return &[];
    }
    match call_guest_json_no_input::<AuthFieldsResponse>(plugin, "auth_fields").0 {
        Ok(resp) => {
            let fields: Vec<AuthField> = resp.fields.into_iter().map(leak_auth_field).collect();
            if fields.is_empty() {
                &[]
            } else {
                Box::leak(fields.into_boxed_slice())
            }
        }
        Err(e) => {
            warn!(provider = %provider_id, "auth_fields call failed: {e}");
            &[]
        }
    }
}

/// Query registration info from the guest, leak strings into `&'static`.
fn query_registration_info(plugin: &mut Plugin, provider_id: &str) -> Option<RegistrationInfo> {
    if !plugin.function_exists("registration_info") {
        return None;
    }
    match call_guest_json_no_input::<RegistrationInfoResponse>(plugin, "registration_info").0 {
        Ok(resp) if resp.has_registration => {
            let instructions: &'static str = resp
                .instructions
                .map(|s| &*Box::leak(s.into_boxed_str()))
                .unwrap_or("");
            let fields: &'static [AuthField] = if resp.fields.is_empty() {
                &[]
            } else {
                let leaked: Vec<AuthField> = resp.fields.into_iter().map(leak_auth_field).collect();
                Box::leak(leaked.into_boxed_slice())
            };
            Some(RegistrationInfo {
                instructions,
                fields,
            })
        }
        Ok(_) => None,
        Err(e) => {
            warn!(provider = %provider_id, "registration_info call failed: {e}");
            None
        }
    }
}

/// Query readiness probes from the guest (called during `new()`).
fn query_readiness_probes(
    plugin: &mut Plugin,
    provider_id: &str,
) -> Vec<crate::protocol::ReadinessProbe> {
    if !plugin.function_exists("readiness_probes") {
        return Vec::new();
    }
    match call_guest_json_no_input::<crate::protocol::ReadinessProbesResponse>(
        plugin,
        "readiness_probes",
    )
    .0
    {
        Ok(resp) => {
            debug!(
                provider = %provider_id,
                count = resp.probes.len(),
                "queried readiness probes from guest",
            );
            resp.probes
        }
        Err(e) => {
            warn!(provider = %provider_id, "readiness_probes call failed: {e}");
            Vec::new()
        }
    }
}

// ── Readiness probe evaluation ───────────────────────────────────

/// Check whether a probe target's hostname is in the allowed hosts list.
///
/// Uses the same glob matching as Extism's built-in HTTP host function.
fn is_host_allowed(hostname: &str, allowed_hosts: &[String]) -> bool {
    allowed_hosts
        .iter()
        .any(|pattern| match glob::Pattern::new(pattern) {
            Ok(pat) => pat.matches(hostname),
            Err(_) => pattern == hostname,
        })
}

/// Evaluate a single readiness probe natively on the host.
///
/// Returns `Ok(())` if the probe passes, or `Err(reason)` with a
/// human-readable explanation of why it failed.
fn evaluate_probe(
    probe: &crate::protocol::ReadinessProbe,
    allowed_hosts: &[String],
) -> Result<(), String> {
    match probe {
        crate::protocol::ReadinessProbe::Http {
            url,
            method,
            expected_status,
            timeout_secs,
        } => {
            // Parse URL and enforce allowed_hosts.
            let parsed =
                url::Url::parse(url).map_err(|e| format!("invalid probe URL '{url}': {e}"))?;
            let host = parsed.host_str().unwrap_or_default();
            if !is_host_allowed(host, allowed_hosts) {
                return Err(format!("probe host '{host}' not in allowed_hosts"));
            }

            let timeout = Duration::from_secs(u64::from(*timeout_secs));
            let agent = ureq::agent();
            let req = ureq::http::request::Builder::new()
                .method(method.to_uppercase().as_str())
                .uri(url.as_str());
            let config = agent
                .configure_request(req.body(()).map_err(|e| format!("build request: {e}"))?)
                .http_status_as_error(false);
            let result = ureq::run(config.timeout_global(Some(timeout)).build());

            match result {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if status == *expected_status {
                        Ok(())
                    } else {
                        Err(format!(
                            "HTTP {method} {url}: got status {status}, expected {expected_status}"
                        ))
                    }
                }
                Err(e) => Err(format!("HTTP {method} {url}: {e}")),
            }
        }
        crate::protocol::ReadinessProbe::Tcp {
            host,
            port,
            timeout_secs,
        } => {
            // Enforce allowed_hosts.
            if !is_host_allowed(host, allowed_hosts) {
                return Err(format!("probe host '{host}' not in allowed_hosts"));
            }

            let timeout = Duration::from_secs(u64::from(*timeout_secs));
            let addr = format!("{host}:{port}");
            let socket_addr = addr
                .to_socket_addrs()
                .map_err(|e| format!("DNS resolution failed for {addr}: {e}"))?
                .next()
                .ok_or_else(|| format!("no addresses resolved for {addr}"))?;

            TcpStream::connect_timeout(&socket_addr, timeout)
                .map(|_| ())
                .map_err(|e| format!("TCP connect to {addr}: {e}"))
        }
    }
}

// ── Guest call helpers ───────────────────────────────────────────

/// Whether a `plugin.call()` failure occurred (as opposed to a
/// serialization/deserialization error).
///
/// When `plugin.call()` fails, the WASM instance may be in a corrupted
/// state (trap, timeout, OOM, host function error, guest panic).  The
/// plugin should be recreated.  Serialization failures happen before or
/// after the WASM call and do not affect the instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallOutcome {
    /// No WASM call failure — the error (if any) is from serialization.
    Clean,
    /// `plugin.call()` returned an error — the instance may be corrupted.
    PluginCallFailed,
}

/// Result of a guest call: the value or an error, plus whether the WASM
/// call itself failed (requiring plugin recreation).
type GuestCallResult<T> = (Result<T, ProviderError>, CallOutcome);

/// Call a guest function with JSON input, deserialize JSON output.
fn call_guest_json<I: Serialize, O: DeserializeOwned>(
    plugin: &mut Plugin,
    func: &str,
    input: &I,
) -> GuestCallResult<O> {
    let input_bytes = match serde_json::to_vec(input) {
        Ok(b) => b,
        Err(e) => {
            return (
                Err(ProviderError::Other(anyhow::anyhow!(
                    "failed to serialize input for {func}: {e}"
                ))),
                CallOutcome::Clean,
            );
        }
    };

    let output_bytes: &[u8] = match plugin.call(func, &input_bytes) {
        Ok(b) => b,
        Err(e) => {
            return (
                Err(ProviderError::Other(anyhow::anyhow!(
                    "WASM call to {func} failed: {e}"
                ))),
                CallOutcome::PluginCallFailed,
            );
        }
    };

    match serde_json::from_slice(output_bytes) {
        Ok(val) => (Ok(val), CallOutcome::Clean),
        Err(e) => (
            Err(ProviderError::Other(anyhow::anyhow!(
                "failed to deserialize output from {func}: {e}"
            ))),
            CallOutcome::Clean,
        ),
    }
}

/// Call a guest function with JSON input that may contain secrets.
///
/// Like [`call_guest_json`] but zeroizes the serialized input bytes after
/// the call completes, regardless of success or failure.  Use this for
/// any guest call whose input contains passwords or other sensitive data.
fn call_guest_json_sensitive<I: Serialize, O: DeserializeOwned>(
    plugin: &mut Plugin,
    func: &str,
    input: &I,
) -> GuestCallResult<O> {
    let mut input_bytes = match serde_json::to_vec(input) {
        Ok(b) => b,
        Err(e) => {
            return (
                Err(ProviderError::Other(anyhow::anyhow!(
                    "failed to serialize input for {func}: {e}"
                ))),
                CallOutcome::Clean,
            );
        }
    };

    let call_result = plugin.call(func, &input_bytes);
    // Zeroize the JSON buffer that contained the password / secrets.
    input_bytes.zeroize();

    let output_bytes: &[u8] = match call_result {
        Ok(b) => b,
        Err(e) => {
            return (
                Err(ProviderError::Other(anyhow::anyhow!(
                    "WASM call to {func} failed: {e}"
                ))),
                CallOutcome::PluginCallFailed,
            );
        }
    };

    match serde_json::from_slice(output_bytes) {
        Ok(val) => (Ok(val), CallOutcome::Clean),
        Err(e) => (
            Err(ProviderError::Other(anyhow::anyhow!(
                "failed to deserialize output from {func}: {e}"
            ))),
            CallOutcome::Clean,
        ),
    }
}

/// Call a guest function with no input (empty bytes), deserialize JSON output.
fn call_guest_json_no_input<O: DeserializeOwned>(
    plugin: &mut Plugin,
    func: &str,
) -> GuestCallResult<O> {
    let output_bytes: &[u8] = match plugin.call(func, &[] as &[u8]) {
        Ok(b) => b,
        Err(e) => {
            return (
                Err(ProviderError::Other(anyhow::anyhow!(
                    "WASM call to {func} failed: {e}"
                ))),
                CallOutcome::PluginCallFailed,
            );
        }
    };

    match serde_json::from_slice(output_bytes) {
        Ok(val) => (Ok(val), CallOutcome::Clean),
        Err(e) => (
            Err(ProviderError::Other(anyhow::anyhow!(
                "failed to deserialize output from {func}: {e}"
            ))),
            CallOutcome::Clean,
        ),
    }
}

/// Map a guest error response to a `ProviderError`.
///
/// For `TwoFactorRequired`, the caller must pass the methods separately
/// via [`map_guest_error_2fa`] since `SimpleResponse` carries them in a
/// dedicated field.
fn map_guest_error(message: Option<String>, kind: Option<ErrorKind>) -> ProviderError {
    let msg = message.unwrap_or_else(|| "unknown plugin error".into());
    match kind {
        Some(ErrorKind::Locked) => ProviderError::Locked,
        Some(ErrorKind::NotFound) => ProviderError::NotFound,
        Some(ErrorKind::NotSupported) => ProviderError::NotSupported,
        Some(ErrorKind::Unavailable) => ProviderError::Unavailable(msg),
        Some(ErrorKind::AlreadyExists) => ProviderError::AlreadyExists,
        Some(ErrorKind::InvalidInput) => ProviderError::InvalidInput(msg.into()),
        Some(ErrorKind::RegistrationRequired) => ProviderError::RegistrationRequired,
        Some(ErrorKind::AuthFailed) => ProviderError::AuthFailed,
        Some(ErrorKind::TwoFactorRequired) => {
            // Caller should use map_guest_2fa_error() for TwoFactorRequired
            // with the methods from SimpleResponse.  This fallback creates an
            // empty methods list.
            ProviderError::TwoFactorRequired { methods: vec![] }
        }
        Some(ErrorKind::Other) | None => ProviderError::Other(anyhow::anyhow!("{msg}")),
    }
}

/// Map a guest `TwoFactorRequired` response to a `ProviderError`, converting
/// the protocol `TwoFactorMethod` types to core types.
fn map_guest_2fa_error(
    message: Option<String>,
    methods: Option<Vec<crate::protocol::TwoFactorMethod>>,
) -> ProviderError {
    let core_methods: Vec<rosec_core::TwoFactorMethod> = methods
        .unwrap_or_default()
        .into_iter()
        .map(|m| rosec_core::TwoFactorMethod {
            id: m.id,
            label: m.label,
            prompt_kind: m.prompt_kind,
            challenge: m.challenge,
        })
        .collect();

    if core_methods.is_empty() {
        warn!("guest returned TwoFactorRequired but no methods");
    }

    let _msg = message.unwrap_or_else(|| "two-factor authentication required".into());
    ProviderError::TwoFactorRequired {
        methods: core_methods,
    }
}

// ── Conversion helpers ───────────────────────────────────────────

/// Convert a `WasmItemMeta` to a core `ItemMeta`.
fn to_item_meta(w: crate::protocol::WasmItemMeta, provider_id: &str) -> ItemMeta {
    ItemMeta {
        id: w.id,
        provider_id: provider_id.to_owned(),
        label: w.label,
        attributes: w.attributes,
        created: w
            .created_epoch_secs
            .map(|s| UNIX_EPOCH + Duration::from_secs(s)),
        modified: w
            .modified_epoch_secs
            .map(|s| UNIX_EPOCH + Duration::from_secs(s)),
        locked: false,
    }
}

/// Convert a `WasmSshKeyMeta` to a core `SshKeyMeta`.
fn to_ssh_key_meta(w: WasmSshKeyMeta, provider_id: &str) -> SshKeyMeta {
    SshKeyMeta {
        item_id: w.item_id,
        item_name: w.item_name,
        provider_id: provider_id.to_owned(),
        public_key_openssh: w.public_key_openssh,
        fingerprint: w.fingerprint,
        ssh_hosts: w.ssh_hosts,
        ssh_user: w.ssh_user,
        require_confirm: w.require_confirm,
        revision_date: w
            .revision_date_epoch_secs
            .map(|s| UNIX_EPOCH + Duration::from_secs(s)),
    }
}

/// Parse a capability string from the guest.
fn parse_capability(s: &str) -> Option<Capability> {
    match s {
        "sync" | "Sync" => Some(Capability::Sync),
        "write" | "Write" => Some(Capability::Write),
        "ssh" | "Ssh" => Some(Capability::Ssh),
        "key_wrapping" | "KeyWrapping" => Some(Capability::KeyWrapping),
        "password_change" | "PasswordChange" => Some(Capability::PasswordChange),
        _ => None,
    }
}

/// Convert a `WasmAttributeDescriptor` (owned strings) to a core
/// `AttributeDescriptor` (`&'static` strings) by leaking the allocations.
fn leak_attribute_descriptor(w: WasmAttributeDescriptor) -> AttributeDescriptor {
    let name: &'static str = Box::leak(w.name.into_boxed_str());
    let description: &'static str = Box::leak(w.description.into_boxed_str());
    let item_types: &'static [&'static str] = if w.item_types.is_empty() {
        &[]
    } else {
        let leaked: Vec<&'static str> = w
            .item_types
            .into_iter()
            .map(|s| &*Box::leak(s.into_boxed_str()))
            .collect();
        Box::leak(leaked.into_boxed_slice())
    };
    AttributeDescriptor {
        name,
        sensitive: w.sensitive,
        item_types,
        description,
    }
}

/// Convert a `WasmAuthField` (owned strings) to a core `AuthField`
/// (`&'static` strings) by leaking the allocations.
fn leak_auth_field(w: crate::protocol::WasmAuthField) -> AuthField {
    let id: &'static str = Box::leak(w.id.into_boxed_str());
    let label: &'static str = Box::leak(w.label.into_boxed_str());
    let placeholder: &'static str = Box::leak(w.placeholder.into_boxed_str());
    let kind = match w.kind.as_str() {
        "password" => AuthFieldKind::Password,
        "secret" => AuthFieldKind::Secret,
        _ => AuthFieldKind::Text,
    };
    AuthField {
        id,
        label,
        placeholder,
        required: w.required,
        kind,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ErrorKind, TwoFactorMethod as ProtoTwoFactorMethod};

    // ── map_guest_2fa_error: happy paths ──────────────────────────

    #[test]
    fn map_2fa_totp_method() {
        let methods = vec![ProtoTwoFactorMethod {
            id: "0".into(),
            label: "Authenticator app (TOTP)".into(),
            prompt_kind: "text".into(),
            challenge: None,
        }];
        let err = map_guest_2fa_error(Some("two-factor required".into()), Some(methods));
        let ProviderError::TwoFactorRequired { methods } = err else {
            panic!("expected TwoFactorRequired, got {err:?}");
        };
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0].id, "0");
        assert_eq!(methods[0].label, "Authenticator app (TOTP)");
        assert_eq!(methods[0].prompt_kind, "text");
        assert!(methods[0].challenge.is_none());
    }

    #[test]
    fn map_2fa_email_method_with_hint() {
        let methods = vec![ProtoTwoFactorMethod {
            id: "1".into(),
            label: "Email code (j***@example.com)".into(),
            prompt_kind: "text".into(),
            challenge: None,
        }];
        let err = map_guest_2fa_error(None, Some(methods));
        let ProviderError::TwoFactorRequired { methods } = err else {
            panic!("expected TwoFactorRequired, got {err:?}");
        };
        assert_eq!(methods[0].id, "1");
        assert!(methods[0].label.contains("j***@example.com"));
    }

    #[test]
    fn map_2fa_duo_method() {
        let methods = vec![ProtoTwoFactorMethod {
            id: "2".into(),
            label: "Duo (passcode)".into(),
            prompt_kind: "text".into(),
            challenge: None,
        }];
        let err = map_guest_2fa_error(None, Some(methods));
        let ProviderError::TwoFactorRequired { methods } = err else {
            panic!("expected TwoFactorRequired, got {err:?}");
        };
        assert_eq!(methods[0].id, "2");
        assert_eq!(methods[0].prompt_kind, "text");
    }

    #[test]
    fn map_2fa_yubikey_method() {
        let methods = vec![ProtoTwoFactorMethod {
            id: "3".into(),
            label: "YubiKey OTP (touch your key)".into(),
            prompt_kind: "text".into(),
            challenge: None,
        }];
        let err = map_guest_2fa_error(None, Some(methods));
        let ProviderError::TwoFactorRequired { methods } = err else {
            panic!("expected TwoFactorRequired, got {err:?}");
        };
        assert_eq!(methods[0].id, "3");
        assert_eq!(methods[0].prompt_kind, "text");
    }

    #[test]
    fn map_2fa_fido2_method() {
        let methods = vec![ProtoTwoFactorMethod {
            id: "4".into(),
            label: "FIDO2 / WebAuthn security key".into(),
            prompt_kind: "fido2".into(),
            challenge: Some(r#"{"publicKey":{}}"#.into()),
        }];
        let err = map_guest_2fa_error(None, Some(methods));
        let ProviderError::TwoFactorRequired { methods } = err else {
            panic!("expected TwoFactorRequired, got {err:?}");
        };
        assert_eq!(methods[0].id, "4");
        assert_eq!(methods[0].prompt_kind, "fido2");
        assert_eq!(methods[0].challenge.as_deref(), Some(r#"{"publicKey":{}}"#));
    }

    #[test]
    fn map_2fa_org_duo_method() {
        let methods = vec![ProtoTwoFactorMethod {
            id: "6".into(),
            label: "Organization Duo (passcode)".into(),
            prompt_kind: "text".into(),
            challenge: None,
        }];
        let err = map_guest_2fa_error(None, Some(methods));
        let ProviderError::TwoFactorRequired { methods } = err else {
            panic!("expected TwoFactorRequired, got {err:?}");
        };
        assert_eq!(methods[0].id, "6");
        assert_eq!(methods[0].prompt_kind, "text");
    }

    #[test]
    fn map_2fa_multiple_methods_preserves_order() {
        let methods = vec![
            ProtoTwoFactorMethod {
                id: "0".into(),
                label: "TOTP".into(),
                prompt_kind: "text".into(),
                challenge: None,
            },
            ProtoTwoFactorMethod {
                id: "1".into(),
                label: "Email".into(),
                prompt_kind: "text".into(),
                challenge: None,
            },
            ProtoTwoFactorMethod {
                id: "4".into(),
                label: "FIDO2".into(),
                prompt_kind: "fido2".into(),
                challenge: None,
            },
        ];
        let err = map_guest_2fa_error(None, Some(methods));
        let ProviderError::TwoFactorRequired { methods } = err else {
            panic!("expected TwoFactorRequired, got {err:?}");
        };
        assert_eq!(methods.len(), 3);
        assert_eq!(methods[0].id, "0");
        assert_eq!(methods[1].id, "1");
        assert_eq!(methods[2].id, "4");
    }

    // ── map_guest_2fa_error: unhappy paths ────────────────────────

    #[test]
    fn map_2fa_empty_methods_list() {
        let err = map_guest_2fa_error(Some("2fa required".into()), Some(vec![]));
        let ProviderError::TwoFactorRequired { methods } = err else {
            panic!("expected TwoFactorRequired, got {err:?}");
        };
        assert!(methods.is_empty());
    }

    #[test]
    fn map_2fa_none_methods() {
        let err = map_guest_2fa_error(Some("2fa required".into()), None);
        let ProviderError::TwoFactorRequired { methods } = err else {
            panic!("expected TwoFactorRequired, got {err:?}");
        };
        assert!(methods.is_empty());
    }

    #[test]
    fn map_2fa_none_message_and_methods() {
        let err = map_guest_2fa_error(None, None);
        let ProviderError::TwoFactorRequired { methods } = err else {
            panic!("expected TwoFactorRequired, got {err:?}");
        };
        assert!(methods.is_empty());
    }

    // ── map_guest_error: TwoFactorRequired fallback ───────────────

    #[test]
    fn map_error_twofactor_fallback_has_empty_methods() {
        let err = map_guest_error(
            Some("two-factor required".into()),
            Some(ErrorKind::TwoFactorRequired),
        );
        let ProviderError::TwoFactorRequired { methods } = err else {
            panic!("expected TwoFactorRequired, got {err:?}");
        };
        // Fallback path produces empty methods — caller should have
        // used map_guest_2fa_error() instead.
        assert!(methods.is_empty());
    }

    // ── map_guest_error: non-2FA variants ─────────────────────────

    #[test]
    fn map_error_auth_failed() {
        let err = map_guest_error(Some("bad creds".into()), Some(ErrorKind::AuthFailed));
        assert!(matches!(err, ProviderError::AuthFailed));
    }

    #[test]
    fn map_error_locked() {
        let err = map_guest_error(None, Some(ErrorKind::Locked));
        assert!(matches!(err, ProviderError::Locked));
    }

    #[test]
    fn map_error_not_found() {
        let err = map_guest_error(None, Some(ErrorKind::NotFound));
        assert!(matches!(err, ProviderError::NotFound));
    }

    #[test]
    fn map_error_not_supported() {
        let err = map_guest_error(None, Some(ErrorKind::NotSupported));
        assert!(matches!(err, ProviderError::NotSupported));
    }

    #[test]
    fn map_error_unavailable_carries_message() {
        let err = map_guest_error(Some("server down".into()), Some(ErrorKind::Unavailable));
        match err {
            ProviderError::Unavailable(msg) => assert_eq!(msg, "server down"),
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn map_error_already_exists() {
        let err = map_guest_error(None, Some(ErrorKind::AlreadyExists));
        assert!(matches!(err, ProviderError::AlreadyExists));
    }

    #[test]
    fn map_error_invalid_input() {
        let err = map_guest_error(Some("bad field".into()), Some(ErrorKind::InvalidInput));
        assert!(matches!(err, ProviderError::InvalidInput(_)));
    }

    #[test]
    fn map_error_registration_required() {
        let err = map_guest_error(None, Some(ErrorKind::RegistrationRequired));
        assert!(matches!(err, ProviderError::RegistrationRequired));
    }

    #[test]
    fn map_error_other_with_message() {
        let err = map_guest_error(Some("something broke".into()), Some(ErrorKind::Other));
        match err {
            ProviderError::Other(e) => assert!(e.to_string().contains("something broke")),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn map_error_none_kind_falls_to_other() {
        let err = map_guest_error(Some("mystery".into()), None);
        assert!(matches!(err, ProviderError::Other(_)));
    }

    #[test]
    fn map_error_none_kind_none_message_uses_default() {
        let err = map_guest_error(None, None);
        match err {
            ProviderError::Other(e) => assert_eq!(e.to_string(), "unknown plugin error"),
            other => panic!("expected Other, got {other:?}"),
        }
    }
}
