//! WASM plugin host for rosec providers.
//!
//! This crate provides `WasmProvider`, which wraps an Extism WASM plugin
//! and exposes it as a native `rosec_core::Provider`.  Each Provider method
//! calls the corresponding guest function with JSON-serialized input and
//! deserializes the JSON response.
//!
//! # Guest function contract
//!
//! | Guest function           | Input type               | Output type                  |
//! |--------------------------|--------------------------|------------------------------|
//! | `plugin_manifest`        | *(empty)*                | `PluginManifest`             |
//! | `init`                   | `InitRequest`            | `InitResponse`               |
//! | `status`                 | *(empty)*                | `StatusResponse`             |
//! | `unlock`                 | `UnlockRequest`          | `SimpleResponse`             |
//! | `lock`                   | *(empty)*                | `SimpleResponse`             |
//! | `sync`                   | *(empty)*                | `SimpleResponse`             |
//! | `list_items`             | *(empty)*                | `ItemListResponse`           |
//! | `search`                 | `SearchRequest`          | `ItemListResponse`           |
//! | `get_item_attributes`    | `ItemIdRequest`          | `ItemAttributesResponse`     |
//! | `get_secret_attr`        | `SecretAttrRequest`      | `SecretAttrResponse`         |
//! | `list_ssh_keys`          | *(empty)*                | `SshKeyListResponse`         |
//! | `get_ssh_private_key`    | `SshPrivateKeyRequest`   | `SshPrivateKeyResponse`      |
//! | `registration_info`      | *(empty)*                | `RegistrationInfoResponse`   |
//! | `auth_fields`            | *(empty)*                | `AuthFieldsResponse`         |
//! | `attribute_descriptors`  | *(empty)*                | `AttributeDescriptorsResponse` |
//! | `capabilities`           | *(empty)*                | `CapabilitiesResponse`       |

pub mod discovery;
pub mod protocol;
mod provider;
mod wasm_cred;

pub use discovery::PluginRegistry;
pub use provider::{WasmProvider, WasmProviderConfig};
