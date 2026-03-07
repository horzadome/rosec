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
