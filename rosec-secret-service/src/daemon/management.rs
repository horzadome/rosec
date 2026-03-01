use std::sync::Arc;
use std::time::SystemTime;

use tracing::debug;
use zbus::fdo::Error as FdoError;
use zbus::interface;
use zbus::message::Header;
use zvariant::OwnedFd;

use crate::state::ServiceState;
use crate::unlock::{UnlockResult, auth_provider_with_tty, unlock_with_tty};

/// Log the D-Bus caller at debug level for a management method.
fn log_caller(method: &str, header: &Header<'_>) {
    let sender = header.sender().map(|s| s.as_str()).unwrap_or("<unknown>");
    debug!(method, sender, "D-Bus management call");
}

pub struct RosecManagement {
    pub(super) state: Arc<ServiceState>,
}

impl RosecManagement {
    pub fn new(state: Arc<ServiceState>) -> Self {
        Self { state }
    }
}

#[interface(name = "org.rosec.Daemon")]
impl RosecManagement {
    fn status(&self, #[zbus(header)] header: Header<'_>) -> Result<DaemonStatus, FdoError> {
        log_caller("Status", &header);
        let cache_size = self
            .state
            .items
            .lock()
            .map(|items| items.len())
            .unwrap_or(0);

        let last_sync = self
            .state
            .last_sync
            .lock()
            .ok()
            .and_then(|guard| *guard)
            .map(|time| {
                time.duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            })
            .unwrap_or(0);

        let sessions_active = self.state.sessions.count().unwrap_or(0);

        Ok(DaemonStatus {
            cache_size: cache_size as u32,
            last_sync_epoch: last_sync,
            sessions_active: sessions_active as u32,
        })
    }

    /// Rebuild the item cache from whatever the providers currently hold in memory.
    ///
    /// Triggers a background sync for every unlocked provider so that
    /// `on_sync_succeeded` callbacks (e.g. SSH key rebuild) fire even when the
    /// caller only asks for a cache refresh.  Uses `try_sync_provider` so
    /// concurrent in-flight syncs are skipped rather than serialised.
    async fn refresh(&self, #[zbus(header)] header: Header<'_>) -> Result<u32, FdoError> {
        log_caller("Refresh", &header);

        // Kick off a sync for every unlocked provider so that lifecycle callbacks
        // (SSH key rebuild, etc.) are triggered.  Errors are logged but do not
        // fail the Refresh call — the cache is still rebuilt from in-memory state.
        for provider in self.state.providers_ordered() {
            let is_locked = provider.status().await.map(|s| s.locked).unwrap_or(true);
            if !is_locked {
                let id = provider.id().to_string();
                if let Err(e) = self.state.try_sync_provider(&id).await {
                    tracing::warn!(provider = %id, "Refresh: background sync failed: {e}");
                }
            }
        }

        let entries = self.state.rebuild_cache().await?;
        Ok(entries.len() as u32)
    }

    /// Pull fresh data from the remote server for a specific provider, then
    /// rebuild the item cache.
    ///
    /// Returns the number of items visible after the sync.
    /// Returns a D-Bus error if the provider is not found, is locked, or the
    /// network request fails.
    async fn sync_provider(
        &self,
        provider_id: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<u32, FdoError> {
        log_caller("SyncProvider", &header);
        self.state.sync_provider(provider_id).await
    }

    /// Return the full list of configured providers with kind and lock state.
    ///
    /// Lock state is derived from cached item metadata — an unlocked provider
    /// has at least one item without the locked flag set (or the cache is
    /// non-empty), while a locked provider has no accessible items.
    async fn provider_list(
        &self,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Vec<ProviderListEntry>, FdoError> {
        log_caller("ProviderList", &header);
        let providers = self.state.providers_ordered();
        let mut entries = Vec::with_capacity(providers.len());
        for p in providers {
            let id = p.id().to_string();
            let name = p.name().to_string();
            let kind = p.kind().to_string();
            let status = self
                .state
                .run_on_tokio(async move { p.status().await })
                .await?
                .map_err(|e| FdoError::Failed(format!("status error for {id}: {e}")))?;
            entries.push(ProviderListEntry {
                id,
                name,
                kind,
                locked: status.locked,
            });
        }
        Ok(entries)
    }

    /// Return the credential fields required by a provider.
    ///
    /// The list always starts with the password field (`provider.password_field()`)
    /// followed by any additional fields declared by `provider.auth_fields()`.
    ///
    /// Each element is a tuple `(id, label, kind, placeholder, required)` where
    /// `kind` is one of `"text"`, `"password"`, or `"secret"`.
    /// Returns at least one element (the password field) if the provider is found.
    fn get_auth_fields(
        &self,
        provider_id: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Vec<AuthFieldInfo>, FdoError> {
        log_caller("GetAuthFields", &header);
        use rosec_core::AuthFieldKind;

        let provider = match self.state.provider_by_id(provider_id) {
            Some(b) => b,
            None => {
                return Err(FdoError::Failed(format!(
                    "provider '{provider_id}' not found"
                )));
            }
        };

        let field_to_info = |f: &rosec_core::AuthField| AuthFieldInfo {
            id: f.id.to_string(),
            label: f.label.to_string(),
            kind: match f.kind {
                AuthFieldKind::Text => "text".to_string(),
                AuthFieldKind::Password => "password".to_string(),
                AuthFieldKind::Secret => "secret".to_string(),
            },
            placeholder: f.placeholder.to_string(),
            required: f.required,
        };

        // Always emit the password field first, then any additional auth fields.
        let pw = provider.password_field();
        let mut fields = vec![field_to_info(&pw)];
        fields.extend(provider.auth_fields().iter().map(field_to_info));

        Ok(fields)
    }

    /// Return registration info for a provider that requires device/API-key registration.
    ///
    /// Returns `(instructions, fields)` where `fields` has the same element layout
    /// as `GetAuthFields`.  Returns a D-Bus error with message `"no_registration_required"`
    /// if the provider does not support registration.
    fn get_registration_info(
        &self,
        provider_id: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(String, Vec<AuthFieldInfo>), FdoError> {
        log_caller("GetRegistrationInfo", &header);
        use rosec_core::AuthFieldKind;

        let provider = match self.state.provider_by_id(provider_id) {
            Some(b) => b,
            None => {
                return Err(FdoError::Failed(format!(
                    "provider '{provider_id}' not found"
                )));
            }
        };

        let info = provider
            .registration_info()
            .ok_or_else(|| FdoError::Failed("no_registration_required".to_string()))?;

        let fields = info
            .fields
            .iter()
            .map(|f| AuthFieldInfo {
                id: f.id.to_string(),
                label: f.label.to_string(),
                kind: match f.kind {
                    AuthFieldKind::Text => "text".to_string(),
                    AuthFieldKind::Password => "password".to_string(),
                    AuthFieldKind::Secret => "secret".to_string(),
                },
                placeholder: f.placeholder.to_string(),
                required: f.required,
            })
            .collect();

        Ok((info.instructions.to_string(), fields))
    }

    /// Unlock all locked providers using credentials prompted on the caller's TTY.
    ///
    /// The caller opens `/dev/tty` and passes the file descriptor via D-Bus
    /// fd-passing (SCM_RIGHTS, type signature `h`).  `dbus-monitor` sees only
    /// the fd number — never any credential.  All prompting happens inside the
    /// daemon process via the received fd.
    ///
    /// Returns a list of `(provider_id, success, message)` tuples — one per
    /// provider that was locked at the time of the call.
    async fn unlock_with_tty(
        &self,
        tty_fd: OwnedFd,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Vec<UnlockResultEntry>, FdoError> {
        log_caller("UnlockWithTty", &header);

        // Duplicate the fd so it survives the move into the Tokio task.
        // SAFETY: as_raw_fd() returns a valid fd owned by tty_fd (which is
        // kept alive until this function returns); dup() produces a new
        // independent fd that we own and close after the task completes.
        use std::os::unix::io::AsRawFd as _;
        let raw: libc::c_int = unsafe { libc::dup(tty_fd.as_raw_fd()) };
        if raw < 0 {
            return Err(FdoError::Failed(format!(
                "dup(tty_fd) failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let state = Arc::clone(&self.state);
        let results: Vec<UnlockResult> = self
            .state
            .run_on_tokio(async move {
                let res = unlock_with_tty(state, raw).await;
                // Close our dup'd fd after the unlock completes.
                unsafe { libc::close(raw) };
                res
            })
            .await?
            .map_err(|e| FdoError::Failed(format!("unlock_with_tty error: {e}")))?;

        Ok(results
            .into_iter()
            .map(|r| UnlockResultEntry {
                provider_id: r.provider_id,
                success: r.success,
                message: r.message,
            })
            .collect())
    }

    /// Authenticate a specific provider using credentials prompted on the caller's TTY.
    ///
    /// Like `UnlockWithTty` but targets a single provider by ID.  Used by
    /// `rosec provider auth` and `rosec provider add`.
    ///
    /// Credentials are prompted in-process on the fd received via fd-passing;
    /// they never appear in any D-Bus message payload.
    async fn auth_provider_with_tty(
        &self,
        provider_id: String,
        tty_fd: OwnedFd,
        force: bool,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), FdoError> {
        log_caller("AuthProviderWithTty", &header);

        use std::os::unix::io::AsRawFd as _;
        let raw: libc::c_int = unsafe { libc::dup(tty_fd.as_raw_fd()) };
        if raw < 0 {
            return Err(FdoError::Failed(format!(
                "dup(tty_fd) failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let state = Arc::clone(&self.state);
        self.state
            .run_on_tokio(async move {
                let res = auth_provider_with_tty(state, raw, &provider_id, force).await;
                unsafe { libc::close(raw) };
                res
            })
            .await?
            .map_err(|e| FdoError::Failed(format!("auth_provider_with_tty error: {e}")))
    }

    /// Authenticate a provider by reading a password from a pipe fd.
    ///
    /// The caller creates a pipe, writes the password to the write end (then
    /// closes it), and passes the read end via D-Bus fd-passing (SCM_RIGHTS).
    /// The daemon reads the password from the pipe, wraps it in `Zeroizing`,
    /// and calls `auth_provider`.
    ///
    /// This is the preferred method for PAM modules and other non-interactive
    /// callers that already have the password but want to avoid sending it as
    /// a plain D-Bus message payload (visible to `dbus-monitor`).
    ///
    /// **Access restricted**: The daemon resolves the caller's PID via
    /// `GetConnectionCredentials` and verifies that `/proc/<pid>/exe` matches
    /// one of the paths in `[service] pam_helper_paths`.  If the caller is
    /// not the PAM helper binary, the request is rejected.
    ///
    /// Returns `true` on success.  Returns a D-Bus error if the provider is not
    /// found, the password is wrong, or reading from the pipe fails.
    async fn auth_provider_from_pipe(
        &self,
        provider_id: String,
        pipe_fd: OwnedFd,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<bool, FdoError> {
        log_caller("AuthProviderFromPipe", &header);

        // --- Caller verification ---
        let allowed_paths = self.state.live_config().service.pam_helper_paths;
        if !allowed_paths.is_empty() {
            let sender = header.sender().ok_or_else(|| {
                FdoError::AccessDenied("AuthProviderFromPipe: missing D-Bus sender".into())
            })?;
            let dbus_proxy = zbus::fdo::DBusProxy::new(&self.state.conn)
                .await
                .map_err(|e| FdoError::Failed(format!("DBusProxy: {e}")))?;
            let pid = dbus_proxy
                .get_connection_unix_process_id(zbus::names::BusName::from(sender.clone()))
                .await
                .map_err(|e| {
                    FdoError::AccessDenied(format!(
                        "AuthProviderFromPipe: cannot resolve caller PID: {e}"
                    ))
                })?;
            let exe = std::fs::read_link(format!("/proc/{pid}/exe")).map_err(|e| {
                FdoError::AccessDenied(format!(
                    "AuthProviderFromPipe: cannot read /proc/{pid}/exe: {e}"
                ))
            })?;
            if !allowed_paths.iter().any(|p| exe == std::path::Path::new(p)) {
                return Err(FdoError::AccessDenied(format!(
                    "AuthProviderFromPipe: caller exe '{}' not in pam_helper_paths",
                    exe.display(),
                )));
            }
            debug!(
                pid,
                exe = %exe.display(),
                "AuthProviderFromPipe: caller verified"
            );
        }
        // --- End caller verification ---

        use std::os::unix::io::AsRawFd as _;
        let raw: libc::c_int = unsafe { libc::dup(pipe_fd.as_raw_fd()) };
        if raw < 0 {
            return Err(FdoError::Failed(format!(
                "dup(pipe_fd) failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let state = Arc::clone(&self.state);
        self.state
            .run_on_tokio(async move {
                // Read password from the pipe into a zeroizing buffer.
                let password = {
                    use std::io::Read as _;
                    // SAFETY: raw is a valid fd from dup() above.
                    let file = unsafe { std::os::unix::io::FromRawFd::from_raw_fd(raw) };
                    let mut file: std::fs::File = file;
                    let mut buf = zeroize::Zeroizing::new(Vec::with_capacity(256));
                    file.read_to_end(&mut buf)
                        .map_err(|e| FdoError::Failed(format!("read from pipe failed: {e}")))?;
                    // file is dropped here → fd closed

                    // Strip trailing null byte (pam_exec null-terminates).
                    if buf.last() == Some(&0) {
                        buf.pop();
                    }
                    // Strip trailing newline.
                    if buf.last() == Some(&b'\n') {
                        buf.pop();
                    }

                    if buf.is_empty() {
                        return Err(FdoError::Failed("pipe password is empty".to_string()));
                    }

                    // Convert to Zeroizing<String> for auth_provider.
                    let s = String::from_utf8(std::mem::take(&mut *buf)).map_err(|_| {
                        FdoError::Failed("pipe password is not valid UTF-8".to_string())
                    })?;
                    zeroize::Zeroizing::new(s)
                };

                // Look up the password field ID for this provider.
                let provider = state.provider_by_id(&provider_id).ok_or_else(|| {
                    FdoError::Failed(format!("provider '{provider_id}' not found"))
                })?;
                let pw_field_id = provider.password_field().id.to_string();

                let mut fields = std::collections::HashMap::new();
                fields.insert(pw_field_id, password);

                state.auth_provider(&provider_id, fields).await?;
                Ok(true)
            })
            .await?
    }

    // -----------------------------------------------------------------------
    // Password (wrapping entry) management
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Password (wrapping entry) management
    // -----------------------------------------------------------------------

    /// Add a password (wrapping entry) to a local vault provider.
    ///
    /// The provider must be unlocked.  The new password wraps the same vault key
    /// that existing entries protect, enabling multi-password unlock.
    ///
    /// `password` is the raw password bytes (caller collects from the user).
    /// `label` is an optional human-readable name for the entry (e.g. "login",
    /// "pam", "backup").
    ///
    /// Returns the wrapping entry ID on success.
    ///
    /// # Security
    ///
    /// The incoming `Vec<u8>` is wrapped in `Zeroizing` at the D-Bus boundary
    /// so the password bytes are scrubbed on drop.
    async fn add_password(
        &self,
        provider_id: String,
        password: Vec<u8>,
        label: String,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<String, FdoError> {
        log_caller("AddPassword", &header);

        // Wrap in Zeroizing at the D-Bus boundary so the password is scrubbed on drop.
        let password = zeroize::Zeroizing::new(password);

        let provider = self
            .state
            .provider_by_id(&provider_id)
            .ok_or_else(|| FdoError::Failed(format!("provider '{provider_id}' not found")))?;

        let label = if label.is_empty() {
            return Err(FdoError::Failed("password label cannot be empty".into()));
        } else {
            label
        };

        self.state
            .run_on_tokio(async move {
                provider
                    .add_password(&password, label)
                    .await
                    .map_err(|e| FdoError::Failed(format!("add_password failed: {e}")))
            })
            .await?
    }

    /// Remove a password (wrapping entry) from a local vault provider by entry ID.
    ///
    /// The provider must be unlocked and must have at least 2 wrapping entries
    /// (the last entry cannot be removed).
    async fn remove_password(
        &self,
        provider_id: String,
        entry_id: String,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), FdoError> {
        log_caller("RemovePassword", &header);

        let provider = self
            .state
            .provider_by_id(&provider_id)
            .ok_or_else(|| FdoError::Failed(format!("provider '{provider_id}' not found")))?;

        self.state
            .run_on_tokio(async move {
                provider
                    .remove_password(&entry_id)
                    .await
                    .map_err(|e| FdoError::Failed(format!("remove_password failed: {e}")))
            })
            .await?
    }

    /// List all wrapping entries (passwords) for a local vault provider.
    ///
    /// Returns `Vec<(entry_id, label)>` where `label` is empty if none was set.
    /// The provider must be unlocked.
    async fn list_passwords(
        &self,
        provider_id: String,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Vec<PasswordEntry>, FdoError> {
        log_caller("ListPasswords", &header);

        let provider = self
            .state
            .provider_by_id(&provider_id)
            .ok_or_else(|| FdoError::Failed(format!("provider '{provider_id}' not found")))?;

        let entries = self
            .state
            .run_on_tokio(async move {
                provider
                    .list_passwords()
                    .await
                    .map_err(|e| FdoError::Failed(format!("list_passwords failed: {e}")))
            })
            .await??;

        Ok(entries
            .into_iter()
            .map(|(id, label)| PasswordEntry {
                id,
                label: label.unwrap_or_default(),
            })
            .collect())
    }

    /// Cancel an active prompt subprocess by its D-Bus object path.
    ///
    /// Used by the `rosec` CLI (and other clients) to cleanly cancel a running
    /// `rosec-prompt` child when the user presses Ctrl+C.  After killing the
    /// child, the Prompt object is responsible for emitting `Completed(true, "")`.
    ///
    /// Returns `true` if a matching prompt was found and cancelled, `false` if
    /// the path was not in the active-prompt registry (already completed or invalid).
    fn cancel_prompt(
        &self,
        prompt_path: zvariant::ObjectPath<'_>,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<bool, FdoError> {
        log_caller("CancelPrompt", &header);
        // cancel_prompt() sends SIGTERM to the child and removes it from the registry.
        // We check whether the path existed before calling it.
        let prompt_path = prompt_path.as_str();
        let existed = self
            .state
            .active_prompts
            .lock()
            .map(|g| g.contains_key(prompt_path))
            .unwrap_or(false);
        self.state.cancel_prompt(prompt_path);
        Ok(existed)
    }

    /// Change the unlock password for a provider.
    ///
    /// The caller creates two pipes:
    /// - `old_password_fd`: write end has the current password, read end passed here
    /// - `new_password_fd`: write end has the new password, read end passed here
    ///
    /// Both fds are passed via D-Bus fd-passing (SCM_RIGHTS, type signature `h`).
    /// `dbus-monitor` sees only fd numbers — never any credential.
    ///
    /// Works for any provider that implements `change_password()` (local vaults
    /// and SM providers).  Returns a D-Bus error if the provider doesn't support
    /// password changes, the old password is wrong, or the provider is locked.
    async fn change_provider_password(
        &self,
        provider_id: String,
        old_password_fd: OwnedFd,
        new_password_fd: OwnedFd,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), FdoError> {
        log_caller("ChangeProviderPassword", &header);

        use std::os::unix::io::AsRawFd as _;
        let old_raw: libc::c_int = unsafe { libc::dup(old_password_fd.as_raw_fd()) };
        if old_raw < 0 {
            return Err(FdoError::Failed(format!(
                "dup(old_password_fd) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let new_raw: libc::c_int = unsafe { libc::dup(new_password_fd.as_raw_fd()) };
        if new_raw < 0 {
            unsafe { libc::close(old_raw) };
            return Err(FdoError::Failed(format!(
                "dup(new_password_fd) failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let state = Arc::clone(&self.state);
        self.state
            .run_on_tokio(async move {
                // Helper: read a password from a pipe fd into Zeroizing<String>.
                let read_pipe_password =
                    |raw_fd: libc::c_int,
                     name: &str|
                     -> Result<zeroize::Zeroizing<String>, FdoError> {
                        use std::io::Read as _;
                        let file: std::fs::File =
                            unsafe { std::os::unix::io::FromRawFd::from_raw_fd(raw_fd) };
                        let mut file = file;
                        let mut buf = zeroize::Zeroizing::new(Vec::with_capacity(256));
                        file.read_to_end(&mut buf).map_err(|e| {
                            FdoError::Failed(format!("read from {name} pipe failed: {e}"))
                        })?;
                        // file dropped here → fd closed

                        // Strip trailing null byte (pam_exec null-terminates).
                        if buf.last() == Some(&0) {
                            buf.pop();
                        }
                        // Strip trailing newline.
                        if buf.last() == Some(&b'\n') {
                            buf.pop();
                        }

                        if buf.is_empty() {
                            return Err(FdoError::Failed(format!("{name} password is empty")));
                        }

                        let s = String::from_utf8(std::mem::take(&mut *buf)).map_err(|_| {
                            FdoError::Failed(format!("{name} password is not valid UTF-8"))
                        })?;
                        Ok(zeroize::Zeroizing::new(s))
                    };

                let old_password = read_pipe_password(old_raw, "old")?;
                let new_password = read_pipe_password(new_raw, "new")?;

                let provider = state.provider_by_id(&provider_id).ok_or_else(|| {
                    FdoError::Failed(format!("provider '{provider_id}' not found"))
                })?;

                provider
                    .change_password(old_password, new_password)
                    .await
                    .map_err(|e| FdoError::Failed(format!("change_password failed: {e}")))
            })
            .await?
    }
}

// ---------------------------------------------------------------------------
// Return types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, zvariant::Type)]
pub struct DaemonStatus {
    pub cache_size: u32,
    pub last_sync_epoch: u64,
    pub sessions_active: u32,
}

/// A provider list entry returned by `ProviderList`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, zvariant::Type)]
pub struct ProviderListEntry {
    pub id: String,
    pub name: String,
    /// The provider type string (e.g. `"bitwarden"`, `"bitwarden-sm"`).
    pub kind: String,
    pub locked: bool,
}

/// A single auth-field descriptor returned by `GetAuthFields`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, zvariant::Type)]
pub struct AuthFieldInfo {
    pub id: String,
    pub label: String,
    /// One of "text", "password", or "secret".
    pub kind: String,
    pub placeholder: String,
    pub required: bool,
}

/// Result entry returned by `UnlockWithTty`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, zvariant::Type)]
pub struct UnlockResultEntry {
    pub provider_id: String,
    pub success: bool,
    /// Human-readable status message (e.g. "unlocked", "wrong password").
    pub message: String,
}

/// A wrapping entry (password) descriptor returned by `ListPasswords`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, zvariant::Type)]
pub struct PasswordEntry {
    /// Unique entry ID (UUID).
    pub id: String,
    /// Human-readable label (empty if none was set).
    pub label: String,
}
