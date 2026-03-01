use std::collections::HashMap;
use std::sync::Arc;

use rosec_core::Provider;
use rosec_core::config::{Config, PromptConfig};
use rosec_core::router::Router;
use zbus::Connection;

use crate::collection::{CollectionState, SecretCollection};
use crate::daemon::{RosecManagement, RosecSearch, RosecSecrets};
use crate::service::SecretService;
use crate::session::SessionManager;
use crate::state::ServiceState;

#[derive(Debug)]
pub struct ObjectPaths {
    pub service: String,
    pub collection_default: String,
}

impl ObjectPaths {
    pub fn new() -> Self {
        Self {
            service: "/org/freedesktop/secrets".to_string(),
            collection_default: "/org/freedesktop/secrets/collection/default".to_string(),
        }
    }
}

impl Default for ObjectPaths {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn register_objects(
    conn: &Connection,
    providers: Vec<Arc<dyn Provider>>,
    router: Arc<Router>,
    sessions: Arc<SessionManager>,
) -> zbus::Result<Arc<ServiceState>> {
    register_objects_with_config(conn, providers, router, sessions, HashMap::new()).await
}

/// Like `register_objects`, but also accepts per-provider `return_attr` patterns
/// and `PromptConfig` from the config.
/// `return_attr_map` maps provider ID → ordered glob patterns.
/// Providers not present in the map fall back to the service-level default.
pub async fn register_objects_with_config(
    conn: &Connection,
    providers: Vec<Arc<dyn Provider>>,
    router: Arc<Router>,
    sessions: Arc<SessionManager>,
    return_attr_map: HashMap<String, Vec<String>>,
) -> zbus::Result<Arc<ServiceState>> {
    register_objects_with_full_config(
        conn,
        providers,
        router,
        sessions,
        return_attr_map,
        HashMap::new(),
        PromptConfig::default(),
        Config::default(),
    )
    .await
}

/// Full constructor used by `rosecd` — passes `return_attr_map`, `collection_map`,
/// `PromptConfig`, and the full `Config` for live hot-reload support.
#[allow(clippy::too_many_arguments)]
pub async fn register_objects_with_full_config(
    conn: &Connection,
    providers: Vec<Arc<dyn Provider>>,
    router: Arc<Router>,
    sessions: Arc<SessionManager>,
    return_attr_map: HashMap<String, Vec<String>>,
    collection_map: HashMap<String, String>,
    prompt_config: PromptConfig,
    initial_config: Config,
) -> zbus::Result<Arc<ServiceState>> {
    let paths = ObjectPaths::new();
    // Keep a reference to all providers for the CollectionState before consuming `providers`
    let providers_for_collection: Vec<Arc<dyn Provider>> =
        providers.iter().map(Arc::clone).collect();
    let tokio_handle = tokio::runtime::Handle::current();
    let sessions_clone = Arc::clone(&sessions);
    let tokio_handle_clone = tokio_handle.clone();
    let state = Arc::new(ServiceState::new_with_config(
        providers,
        router,
        sessions,
        conn.clone(),
        tokio_handle,
        return_attr_map,
        collection_map,
        prompt_config,
        initial_config,
    ));
    let shared_items = Arc::clone(&state.items);

    let server = conn.object_server();
    server
        .at(
            paths.service.clone(),
            SecretService::new(Arc::clone(&state)),
        )
        .await?;
    server
        .at(
            "/org/rosec/Daemon",
            RosecManagement::new(Arc::clone(&state)),
        )
        .await?;
    server
        .at("/org/rosec/Search", RosecSearch::new(Arc::clone(&state)))
        .await?;
    server
        .at("/org/rosec/Secrets", RosecSecrets::new(Arc::clone(&state)))
        .await?;

    let collection_state = CollectionState {
        label: "default".to_string(),
        items: shared_items,
        providers: providers_for_collection,
        service_state: Arc::clone(&state),
        sessions: sessions_clone,
        tokio_handle: tokio_handle_clone,
    };
    server
        .at(
            paths.collection_default.clone(),
            SecretCollection::new(collection_state.clone()),
        )
        .await?;

    // Register the same collection at the standard alias path.
    // Per the Secret Service spec, /org/freedesktop/secrets/aliases/default
    // must resolve to the default collection.  Most clients (including
    // secret-tool from libsecret) access the default collection via this
    // alias path rather than calling ReadAlias first.
    server
        .at(
            "/org/freedesktop/secrets/aliases/default",
            SecretCollection::new(collection_state),
        )
        .await?;

    Ok(state)
}
