//! Provider discovery — scan directories for `.wasm` provider plugins and build
//! a registry of available provider kinds.
//!
//! # Search paths
//!
//! Providers are discovered from two locations (in order):
//!
//! 1. **System-wide**: `/usr/lib/rosec/providers/` — for distro packages
//! 2. **User-local**: `$XDG_DATA_HOME/rosec/providers/` (default
//!    `~/.local/share/rosec/providers/`) — for user-installed providers
//!
//! If the same `kind` appears in both directories the user-local copy
//! takes precedence, allowing users to override system-installed providers.
//!
//! # Discovery protocol
//!
//! Each `.wasm` file is loaded as a temporary Extism plugin and its
//! `plugin_manifest` export is called (no `init` required).  The
//! returned [`PluginManifest`] describes the plugin's kind, name,
//! config requirements, and allowed hosts.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use extism::{Manifest, Plugin, Wasm};
use tracing::{debug, info, warn};

use crate::protocol::{PluginManifest, PluginOptionDescriptor};

/// System-wide provider directory (for distro packages).
const SYSTEM_PLUGIN_DIR: &str = "/usr/lib/rosec/providers";

/// Subdirectory under `$XDG_DATA_HOME` for user-installed providers.
const USER_PLUGIN_SUBDIR: &str = "rosec/providers";

// ── PluginRegistry ───────────────────────────────────────────────

/// A discovered plugin: its manifest plus the resolved path to the
/// `.wasm` file.
#[derive(Debug, Clone)]
pub struct DiscoveredPlugin {
    /// Absolute path to the `.wasm` file.
    pub wasm_path: PathBuf,
    /// The manifest returned by `plugin_manifest()`.
    pub manifest: PluginManifest,
}

/// Registry of all discovered WASM plugins, keyed by kind.
#[derive(Debug, Clone, Default)]
pub struct PluginRegistry {
    plugins: HashMap<String, DiscoveredPlugin>,
}

impl PluginRegistry {
    /// Look up a discovered plugin by kind.
    pub fn get(&self, kind: &str) -> Option<&DiscoveredPlugin> {
        self.plugins.get(kind)
    }

    /// Iterate over all discovered plugins.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &DiscoveredPlugin)> {
        self.plugins.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// All discovered kind strings, sorted for deterministic output.
    pub fn kinds(&self) -> Vec<&str> {
        let mut kinds: Vec<&str> = self.plugins.keys().map(String::as_str).collect();
        kinds.sort_unstable();
        kinds
    }

    /// Whether the registry contains a given kind.
    pub fn contains_kind(&self, kind: &str) -> bool {
        self.plugins.contains_key(kind)
    }

    /// Number of discovered plugins.
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }
}

// ── Scanning ─────────────────────────────────────────────────────

/// Scan the standard provider directories and return a registry of
/// discovered providers.
///
/// Search order:
/// 1. System-wide (`/usr/lib/rosec/providers/`)
/// 2. User-local (`$XDG_DATA_HOME/rosec/providers/`)
///
/// User-local providers override system-wide providers with the same kind.
pub fn scan_plugins() -> PluginRegistry {
    let mut registry = PluginRegistry::default();

    // 1. System-wide directory.
    let system_dir = PathBuf::from(SYSTEM_PLUGIN_DIR);
    scan_directory(&system_dir, &mut registry);

    // 2. User-local directory.
    if let Some(user_dir) = user_plugin_dir() {
        scan_directory(&user_dir, &mut registry);
    }

    if registry.is_empty() {
        debug!("no WASM providers discovered");
    } else {
        info!(
            count = registry.len(),
            kinds = ?registry.kinds(),
            "discovered WASM providers",
        );
    }

    registry
}

/// Scan a single directory for `.wasm` files and register their
/// manifests.  Later calls with the same kind overwrite earlier ones
/// (user-local overrides system-wide).
fn scan_directory(dir: &Path, registry: &mut PluginRegistry) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            // Missing directories are normal (no system packages installed,
            // or user hasn't created the providers dir yet).
            debug!(dir = %dir.display(), "plugin directory not readable: {e}");
            return;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warn!("failed to read directory entry in {}: {e}", dir.display());
                continue;
            }
        };

        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("wasm") {
            continue;
        }

        match probe_plugin(&path) {
            Ok(manifest) => {
                let kind = manifest.kind.clone();
                if registry.plugins.contains_key(&kind) {
                    info!(
                        kind = %kind,
                        path = %path.display(),
                        "overriding previously discovered plugin",
                    );
                }
                debug!(
                    kind = %kind,
                    name = %manifest.name,
                    path = %path.display(),
                    "discovered plugin",
                );
                registry.plugins.insert(
                    kind,
                    DiscoveredPlugin {
                        wasm_path: path,
                        manifest,
                    },
                );
            }
            Err(e) => {
                warn!(
                    path = %path.display(),
                    "failed to probe plugin: {e}",
                );
            }
        }
    }
}

/// Load a `.wasm` file and call `plugin_manifest()` to extract its
/// metadata.  The plugin is discarded after probing.
fn probe_plugin(wasm_path: &Path) -> Result<PluginManifest, anyhow::Error> {
    let wasm = Wasm::file(wasm_path);
    // No allowed hosts for probing — we only call plugin_manifest which
    // should not make HTTP requests.
    let manifest = Manifest::new([wasm]);

    let mut plugin = Plugin::new(&manifest, [], true).map_err(|e| {
        anyhow::anyhow!("failed to load WASM plugin '{}': {e}", wasm_path.display(),)
    })?;

    if !plugin.function_exists("plugin_manifest") {
        return Err(anyhow::anyhow!(
            "'{}' does not export `plugin_manifest`",
            wasm_path.display(),
        ));
    }

    let output_bytes: &[u8] = plugin.call("plugin_manifest", &[] as &[u8]).map_err(|e| {
        anyhow::anyhow!(
            "plugin_manifest call failed for '{}': {e}",
            wasm_path.display(),
        )
    })?;

    let pm: PluginManifest = serde_json::from_slice(output_bytes).map_err(|e| {
        anyhow::anyhow!(
            "failed to deserialize plugin_manifest from '{}': {e}",
            wasm_path.display(),
        )
    })?;

    if pm.kind.is_empty() {
        return Err(anyhow::anyhow!(
            "plugin '{}' returned empty kind in manifest",
            wasm_path.display(),
        ));
    }

    Ok(pm)
}

/// Resolve the user-local provider directory.
///
/// Uses `$XDG_DATA_HOME/rosec/providers/` (default `~/.local/share/rosec/providers/`).
fn user_plugin_dir() -> Option<PathBuf> {
    // Check $XDG_DATA_HOME first.
    if let Ok(data_home) = std::env::var("XDG_DATA_HOME")
        && !data_home.is_empty()
    {
        return Some(PathBuf::from(data_home).join(USER_PLUGIN_SUBDIR));
    }

    // Fall back to $HOME/.local/share/rosec/providers/
    if let Ok(home) = std::env::var("HOME")
        && !home.is_empty()
    {
        return Some(
            PathBuf::from(home)
                .join(".local/share")
                .join(USER_PLUGIN_SUBDIR),
        );
    }

    warn!("cannot determine user provider directory: neither $XDG_DATA_HOME nor $HOME is set");
    None
}

// ── Helpers for consumers (daemon, CLI) ──────────────────────────

/// Return the required options for a discovered plugin kind.
///
/// Returns `None` if the kind is not in the registry.
pub fn required_options(
    registry: &PluginRegistry,
    kind: &str,
) -> Option<Vec<PluginOptionDescriptor>> {
    registry
        .get(kind)
        .map(|p| p.manifest.required_options.clone())
}

/// Return the optional options for a discovered plugin kind.
///
/// Returns `None` if the kind is not in the registry.
pub fn optional_options(
    registry: &PluginRegistry,
    kind: &str,
) -> Option<Vec<PluginOptionDescriptor>> {
    registry
        .get(kind)
        .map(|p| p.manifest.optional_options.clone())
}

/// Return the ID derivation key for a discovered plugin kind.
///
/// Returns `None` if the kind is not in the registry or the plugin
/// did not specify a derivation key.
pub fn id_derivation_key(registry: &PluginRegistry, kind: &str) -> Option<String> {
    registry
        .get(kind)
        .and_then(|p| p.manifest.id_derivation_key.clone())
}
