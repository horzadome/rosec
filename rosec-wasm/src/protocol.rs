//! JSON protocol types for host ↔ guest communication.
//!
//! These types define the wire format between the WasmProvider host and
//! WASM guest plugins.  Both sides serialize/deserialize to JSON via
//! Extism byte buffers.
//!
//! The guest crate duplicates these definitions (it cannot share a crate
//! because it targets `wasm32-wasip1`).  Keep both copies in sync.

use std::{collections::HashMap, fmt};

use serde::{Deserialize, Serialize};

// ── Init / lifecycle ─────────────────────────────────────────────

/// Sent to `init` — one-time plugin configuration.
#[derive(Debug, Serialize, Deserialize)]
pub struct InitRequest {
    pub provider_id: String,
    pub provider_name: String,
    pub options: HashMap<String, serde_json::Value>,
}

/// Returned by `init`.
#[derive(Debug, Serialize, Deserialize)]
pub struct InitResponse {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
}

// ── Status ───────────────────────────────────────────────────────

/// Returned by `status`.
#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    pub locked: bool,
    pub last_sync_epoch_secs: Option<u64>,
}

// ── Unlock / Lock ────────────────────────────────────────────────

/// Sent to `unlock`.
///
/// `Debug` is manually implemented to redact `password` and
/// `registration_fields` (which may contain secrets).
#[derive(Serialize, Deserialize)]
pub struct UnlockRequest {
    /// The user's master password.
    pub password: String,
    /// Additional registration fields (for first-time setup).
    #[serde(default)]
    pub registration_fields: Option<HashMap<String, String>>,
}

impl fmt::Debug for UnlockRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockRequest")
            .field("password", &"[REDACTED]")
            .field(
                "registration_fields",
                &self.registration_fields.as_ref().map(|m| {
                    m.keys()
                        .map(|k| (k.as_str(), "[REDACTED]"))
                        .collect::<Vec<_>>()
                }),
            )
            .finish()
    }
}

/// Returned by `unlock`, `lock`, `sync`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SimpleResponse {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    /// Discriminates error kind for the host to map to ProviderError.
    #[serde(default)]
    pub error_kind: Option<ErrorKind>,
}

// ── Items ────────────────────────────────────────────────────────

/// Returned by `list_items` and `search`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ItemListResponse {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_kind: Option<ErrorKind>,
    #[serde(default)]
    pub items: Vec<WasmItemMeta>,
}

/// A single item's metadata — the WASM equivalent of `ItemMeta`.
#[derive(Debug, Serialize, Deserialize)]
pub struct WasmItemMeta {
    pub id: String,
    pub label: String,
    pub attributes: HashMap<String, String>,
    pub created_epoch_secs: Option<u64>,
    pub modified_epoch_secs: Option<u64>,
}

/// Sent to `search`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SearchRequest {
    pub attributes: HashMap<String, String>,
}

// ── Attributes ───────────────────────────────────────────────────

/// Sent to `get_item_attributes`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ItemIdRequest {
    pub id: String,
}

/// Returned by `get_item_attributes`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ItemAttributesResponse {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_kind: Option<ErrorKind>,
    #[serde(default)]
    pub public: HashMap<String, String>,
    #[serde(default)]
    pub secret_names: Vec<String>,
}

// ── Secrets ──────────────────────────────────────────────────────

/// Sent to `get_secret_attr`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SecretAttrRequest {
    pub id: String,
    pub attr: String,
}

/// Returned by `get_secret_attr`.
///
/// Secret bytes are base64-encoded for JSON transport.
/// `Debug` is manually implemented to redact `value_b64`.
#[derive(Serialize, Deserialize)]
pub struct SecretAttrResponse {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_kind: Option<ErrorKind>,
    /// Base64-encoded secret bytes.
    #[serde(default)]
    pub value_b64: Option<String>,
}

impl fmt::Debug for SecretAttrResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretAttrResponse")
            .field("ok", &self.ok)
            .field("error", &self.error)
            .field("error_kind", &self.error_kind)
            .field("value_b64", &self.value_b64.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

// ── SSH ──────────────────────────────────────────────────────────

/// Returned by `list_ssh_keys`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SshKeyListResponse {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_kind: Option<ErrorKind>,
    #[serde(default)]
    pub keys: Vec<WasmSshKeyMeta>,
}

/// A single SSH key's metadata — the WASM equivalent of `SshKeyMeta`.
#[derive(Debug, Serialize, Deserialize)]
pub struct WasmSshKeyMeta {
    pub item_id: String,
    pub item_name: String,
    pub public_key_openssh: Option<String>,
    pub fingerprint: Option<String>,
    pub ssh_hosts: Vec<String>,
    pub ssh_user: Option<String>,
    pub require_confirm: bool,
    pub revision_date_epoch_secs: Option<u64>,
}

/// Sent to `get_ssh_private_key`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SshPrivateKeyRequest {
    pub item_id: String,
}

/// Returned by `get_ssh_private_key`.
///
/// `Debug` is manually implemented to redact `pem`.
#[derive(Serialize, Deserialize)]
pub struct SshPrivateKeyResponse {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_kind: Option<ErrorKind>,
    /// PEM-encoded private key.
    #[serde(default)]
    pub pem: Option<String>,
}

impl fmt::Debug for SshPrivateKeyResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshPrivateKeyResponse")
            .field("ok", &self.ok)
            .field("error", &self.error)
            .field("error_kind", &self.error_kind)
            .field("pem", &self.pem.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

// ── Registration / Auth fields ───────────────────────────────────

/// Returned by `registration_info`.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationInfoResponse {
    pub has_registration: bool,
    #[serde(default)]
    pub instructions: Option<String>,
    #[serde(default)]
    pub fields: Vec<WasmAuthField>,
}

/// Returned by `auth_fields`.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthFieldsResponse {
    #[serde(default)]
    pub fields: Vec<WasmAuthField>,
}

/// An auth field descriptor.
#[derive(Debug, Serialize, Deserialize)]
pub struct WasmAuthField {
    pub id: String,
    pub label: String,
    pub placeholder: String,
    pub required: bool,
    pub kind: String, // "text", "password", "secret"
}

// ── Attribute descriptors ────────────────────────────────────────

/// Returned by `attribute_descriptors`.
#[derive(Debug, Serialize, Deserialize)]
pub struct AttributeDescriptorsResponse {
    pub descriptors: Vec<WasmAttributeDescriptor>,
}

/// An attribute descriptor.
#[derive(Debug, Serialize, Deserialize)]
pub struct WasmAttributeDescriptor {
    pub name: String,
    pub sensitive: bool,
    pub item_types: Vec<String>,
    pub description: String,
}

// ── Capabilities ─────────────────────────────────────────────────

/// Returned by `capabilities`.
#[derive(Debug, Serialize, Deserialize)]
pub struct CapabilitiesResponse {
    pub capabilities: Vec<String>,
}

// ── Plugin manifest (pre-init discovery) ─────────────────────────

/// Returned by `plugin_manifest` — called before `init` to discover
/// the plugin's kind, name, config requirements, and allowed hosts.
///
/// This enables automatic plugin discovery: the host scans `.wasm`
/// files in known directories, calls `plugin_manifest()` on each,
/// and registers the discovered kinds dynamically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// The provider kind string (e.g. `"bitwarden-pm"`).
    pub kind: String,
    /// Human-readable plugin name (e.g. `"Bitwarden Password Manager"`).
    pub name: String,
    /// Short description shown in `rosec provider kinds`.
    pub description: String,
    /// HTTP hosts the plugin needs access to (defaults).
    /// Users can override via config.
    #[serde(default)]
    pub default_allowed_hosts: Vec<String>,
    /// Config options the plugin requires.
    #[serde(default)]
    pub required_options: Vec<PluginOptionDescriptor>,
    /// Config options the plugin accepts but doesn't require.
    #[serde(default)]
    pub optional_options: Vec<PluginOptionDescriptor>,
    /// Which required option key to hash for auto-generating provider IDs.
    /// e.g. `"email"` for bitwarden-pm.  If `None`, falls back to the kind.
    #[serde(default)]
    pub id_derivation_key: Option<String>,
}

/// Describes a single config option a plugin accepts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginOptionDescriptor {
    /// Option key (e.g. `"email"`, `"region"`).
    pub key: String,
    /// Human-readable description for prompts.
    pub description: String,
    /// Input kind: `"text"`, `"password"`, or `"secret"`.
    #[serde(default = "default_option_kind")]
    pub kind: String,
}

fn default_option_kind() -> String {
    "text".into()
}

// ── Error classification ─────────────────────────────────────────

/// Allows the guest to communicate structured error kinds.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    Locked,
    NotFound,
    NotSupported,
    Unavailable,
    AlreadyExists,
    InvalidInput,
    RegistrationRequired,
    AuthFailed,
    Other,
}
