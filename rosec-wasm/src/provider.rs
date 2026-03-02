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
use zeroize::Zeroizing;

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
        let wasm = Wasm::file(&config.wasm_path);
        let manifest =
            Manifest::new([wasm]).with_allowed_hosts(config.allowed_hosts.iter().cloned());

        let mut plugin = Plugin::new(&manifest, [], true).map_err(|e| {
            ProviderError::Other(anyhow::anyhow!(
                "failed to load WASM plugin '{}': {e}",
                config.wasm_path,
            ))
        })?;

        // Call init to let the guest set up its internal state.
        let init_req = InitRequest {
            provider_id: config.id.clone(),
            provider_name: config.name.clone(),
            options: config.options.clone(),
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
        let req = match &input {
            UnlockInput::Password(pw) => UnlockRequest {
                password: pw.as_str().to_owned(),
                registration_fields: None,
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
            },
        };

        let mut plugin = self.plugin.lock().await;
        let resp: SimpleResponse = call_guest_json(&mut plugin, "unlock", &req)?;
        if resp.ok {
            // Fire on_unlocked callback.
            if let Ok(cbs) = self.callbacks.read()
                && let Some(ref cb) = cbs.on_unlocked
            {
                cb();
            }
            Ok(())
        } else {
            Err(map_guest_error(resp.error, resp.error_kind))
        }
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
        let b64 = resp.value_b64.ok_or(ProviderError::NotFound)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .map_err(|e| ProviderError::Other(anyhow::anyhow!("invalid base64 from guest: {e}")))?;
        Ok(SecretBytes::new(bytes))
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
        Some(ErrorKind::Other) | None => ProviderError::Other(anyhow::anyhow!("{msg}")),
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
