//! rosec D-Bus extension objects.
//!
//! Splits the rosec-specific daemon interface into focused objects:
//!
//! | Path                | Interface          | Purpose                                    |
//! |---------------------|--------------------|--------------------------------------------|
//! | `/org/rosec/Daemon` | `org.rosec.Daemon` | Management & auth (Status, Sync, AuthProvider, …) |
//! | `/org/rosec/Search` | `org.rosec.Search` | Glob item search (SearchItemsGlob)         |
//! | `/org/rosec/Secrets`| `org.rosec.Secrets`| Attribute-model extensions (GetSecretAttribute*) |
//! | `/org/rosec/Items`  | `org.rosec.Items`  | Item CRUD (CreateItemExtended, UpdateItem, …) |

pub mod items;
pub mod management;
pub mod search;
pub mod secrets;

// Flat re-exports so callers can use short names.
pub use items::RosecItems;
pub use management::{
    AuthFieldInfo, DaemonStatus, PasswordEntry, ProviderListEntry, RosecManagement,
};
pub use search::RosecSearch;
pub use secrets::RosecSecrets;

use tracing::debug;
use zbus::message::Header;

/// Log the D-Bus caller at debug level.
///
/// Shared across all daemon sub-interfaces to avoid per-module copies.
pub(crate) fn log_dbus_caller(context: &str, method: &str, header: &Header<'_>) {
    let sender = header.sender().map(|s| s.as_str()).unwrap_or("<unknown>");
    debug!(method, sender, context, "D-Bus call");
}
