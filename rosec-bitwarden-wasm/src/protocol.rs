//! JSON protocol types for host ↔ guest communication.
//!
//! These types define the wire format between the WasmProvider host and
//! WASM guest plugins.  Both sides serialize/deserialize to JSON via
//! Extism byte buffers.
//!
//! This is a duplicate of `rosec-wasm/src/protocol.rs` (the host side).
//! Keep both copies in sync.

use std::collections::HashMap;

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
#[derive(Debug, Serialize, Deserialize)]
pub struct UnlockRequest {
    /// The user's master password.
    pub password: String,
    /// Additional registration fields (for first-time setup).
    #[serde(default)]
    pub registration_fields: Option<HashMap<String, String>>,
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
#[derive(Debug, Serialize, Deserialize)]
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
#[derive(Debug, Serialize, Deserialize)]
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
