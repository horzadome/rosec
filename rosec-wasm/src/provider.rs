//! `WasmProvider` — wraps an Extism WASM plugin as a `rosec_core::Provider`.

use std::collections::HashMap;
use std::time::{Duration, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine;
use extism::{Manifest, Plugin, Wasm};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::Mutex;
use tracing::{debug, warn};
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
    /// Callbacks registered by the daemon — stored here so we can fire them
    /// from the host side when the guest reports state changes.
    callbacks: std::sync::RwLock<ProviderCallbacks>,
    /// Cached timestamp of the last successful sync.
    ///
    /// Updated after `unlock` and `sync` calls succeed.  Queried by
    /// `last_synced_at()` (synchronous) for the delta-sync check.
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
        for (src, dest) in &config.allowed_paths {
            debug!(
                provider = %config.id,
                src = %src,
                dest = %dest.display(),
                "pre-opening WASI path",
            );
            manifest = manifest.with_allowed_path(src.clone(), dest);
        }

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
            options.insert("home_dir".into(), serde_json::Value::String(home));
        }
        let init_req = InitRequest {
            provider_id: config.id.clone(),
            provider_name: config.name.clone(),
            options,
        };
        let init_resp: InitResponse = call_guest_json(&mut plugin, "init", &init_req)?;
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

        debug!(
            provider = %config.id,
            caps = ?capabilities,
            attrs = attribute_descriptors.len(),
            auth = auth_fields.len(),
            reg = registration_info.is_some(),
            "WASM provider initialised",
        );

        Ok(Self {
            config,
            plugin: Mutex::new(plugin),
            capabilities,
            attribute_descriptors,
            auth_fields,
            registration_info,
            callbacks: std::sync::RwLock::new(ProviderCallbacks::default()),
            last_sync_time: std::sync::Mutex::new(None),
        })
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
        let resp: StatusResponse = call_guest_json_no_input(&mut plugin, "status")?;
        Ok(ProviderStatus {
            locked: resp.locked,
            last_sync: resp
                .last_sync_epoch_secs
                .map(|s| UNIX_EPOCH + Duration::from_secs(s)),
        })
    }

    async fn unlock(&self, input: UnlockInput) -> Result<(), ProviderError> {
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
            call_guest_json_sensitive(&mut plugin, "unlock", &req);

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
                                call_guest_json_sensitive(&mut plugin, "unlock", &retry_req);

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
        let resp: SimpleResponse = call_guest_json_no_input(&mut plugin, "lock")?;
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
        let mut plugin = self.plugin.lock().await;
        if !plugin.function_exists("sync") {
            return Err(ProviderError::NotSupported);
        }
        let resp: SimpleResponse = call_guest_json_no_input(&mut plugin, "sync")?;
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
        let resp: ItemListResponse = call_guest_json_no_input(&mut plugin, "list_items")?;
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
        let resp: ItemListResponse = call_guest_json(&mut plugin, "search", &req)?;
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
            call_guest_json(&mut plugin, "get_item_attributes", &req)?;
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
        let resp: SecretAttrResponse = call_guest_json(&mut plugin, "get_secret_attr", &req)?;
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
        let resp: SshKeyListResponse = call_guest_json_no_input(&mut plugin, "list_ssh_keys")?;
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
            call_guest_json(&mut plugin, "get_ssh_private_key", &req)?;
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

        let mut plugin = self.plugin.lock().await;
        if !plugin.function_exists("check_remote_changed") {
            // No guest support — assume changed (safe default).
            return Ok(true);
        }

        let req = crate::protocol::CheckRemoteChangedRequest {
            last_synced_iso8601: iso8601,
        };

        let resp: crate::protocol::CheckRemoteChangedResponse =
            call_guest_json(&mut plugin, "check_remote_changed", &req)?;

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
    match call_guest_json_no_input::<CapabilitiesResponse>(plugin, "capabilities") {
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
    ) {
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
    match call_guest_json_no_input::<AuthFieldsResponse>(plugin, "auth_fields") {
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
    match call_guest_json_no_input::<RegistrationInfoResponse>(plugin, "registration_info") {
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

// ── Guest call helpers ───────────────────────────────────────────

/// Call a guest function with JSON input, deserialize JSON output.
fn call_guest_json<I: Serialize, O: DeserializeOwned>(
    plugin: &mut Plugin,
    func: &str,
    input: &I,
) -> Result<O, ProviderError> {
    let input_bytes = serde_json::to_vec(input).map_err(|e| {
        ProviderError::Other(anyhow::anyhow!("failed to serialize input for {func}: {e}"))
    })?;

    let output_bytes: &[u8] = plugin
        .call(func, &input_bytes)
        .map_err(|e| ProviderError::Other(anyhow::anyhow!("WASM call to {func} failed: {e}")))?;

    serde_json::from_slice(output_bytes).map_err(|e| {
        ProviderError::Other(anyhow::anyhow!(
            "failed to deserialize output from {func}: {e}"
        ))
    })
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
) -> Result<O, ProviderError> {
    let mut input_bytes = serde_json::to_vec(input).map_err(|e| {
        ProviderError::Other(anyhow::anyhow!("failed to serialize input for {func}: {e}"))
    })?;

    let result = plugin
        .call(func, &input_bytes)
        .map_err(|e| ProviderError::Other(anyhow::anyhow!("WASM call to {func} failed: {e}")))
        .and_then(|output_bytes: &[u8]| {
            serde_json::from_slice(output_bytes).map_err(|e| {
                ProviderError::Other(anyhow::anyhow!(
                    "failed to deserialize output from {func}: {e}"
                ))
            })
        });

    // Zeroize the JSON buffer that contained the password / secrets.
    input_bytes.zeroize();

    result
}

/// Call a guest function with no input (empty bytes), deserialize JSON output.
fn call_guest_json_no_input<O: DeserializeOwned>(
    plugin: &mut Plugin,
    func: &str,
) -> Result<O, ProviderError> {
    let output_bytes: &[u8] = plugin
        .call(func, &[] as &[u8])
        .map_err(|e| ProviderError::Other(anyhow::anyhow!("WASM call to {func} failed: {e}")))?;

    serde_json::from_slice(output_bytes).map_err(|e| {
        ProviderError::Other(anyhow::anyhow!(
            "failed to deserialize output from {func}: {e}"
        ))
    })
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
