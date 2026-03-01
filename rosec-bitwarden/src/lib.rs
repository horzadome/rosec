//! Bitwarden vault provider for rosec.
//!
//! Provides read-only access to a Bitwarden password vault through
//! the standard Bitwarden API, compatible with both official servers
//! and Vaultwarden.
//!
//! # Architecture
//!
//! - **`api`**: HTTP client for Bitwarden API endpoints (prelogin, login, sync)
//! - **`crypto`**: Key derivation (PBKDF2, Argon2id, HKDF) and encryption (AES-CBC, HMAC-SHA256, RSA-OAEP)
//! - **`cipher`**: Cipher string parsing and decryption (`2.iv|ct|mac` format)
//! - **`vault`**: Decrypted vault state management
//! - **`provider`**: `Provider` trait implementation
//!
//! # Usage
//!
//! ```rust,ignore
//! use rosec_bitwarden::{BitwardenProvider, BitwardenConfig};
//! use rosec_core::{UnlockInput, Provider};
//!
//! let config = BitwardenConfig {
//!     id: "personal".to_string(),
//!     email: "user@example.com".to_string(),
//!     region: None,    // default: official US cloud
//!     base_url: None,
//!     api_url: None,
//!     identity_url: None,
//! };
//!
//! let provider = BitwardenProvider::new(config)?;
//! provider.unlock(UnlockInput::Password(zeroize::Zeroizing::new("master_password".to_string()))).await?;
//!
//! let items = provider.list_items().await?;
//! ```

pub mod api;
pub mod cipher;
pub mod crypto;
pub mod error;
pub mod notifications;
pub mod oauth_cred;
pub mod provider;
pub mod vault;

pub use error::BitwardenError;
pub use provider::{BitwardenConfig, BitwardenProvider, BitwardenRegion};
