# Provider Capabilities

Each provider declares a set of capabilities that describe what optional functionality it supports. The CLI shows these as compact single-letter codes in the **CAPS** column of `rosec provider list` and `rosec status`.

## Capability Reference

| Code | Capability | Description |
|:----:|---|---|
| `S` | Sync | Provider can sync with a remote source. Enables `rosec sync` and the `-s` flag on `rosec search`. |
| `W` | Write | Provider supports creating, updating, and deleting items via D-Bus `CreateItem` / `Delete`. Required for `rosec item add`, `rosec item edit`, `rosec item import`, and `rosec item delete`. |
| `s` | Ssh | Provider exposes SSH keys to the built-in SSH agent. Keys are loaded automatically on unlock. See [ssh-agent.md](../ssh-agent.md). |
| `K` | KeyWrapping | Provider supports key wrapping — multiple passwords can unlock the same vault. Enables `rosec provider add-password`, `remove-password`, and `list-passwords`. |
| `P` | PasswordChange | Provider supports changing the unlock password via `rosec provider change-password`. |
| `C` | OfflineCache | Provider supports offline cache export/restore. Previously synced data is available after reboot without network access. Requires both the provider capability and host-side `offline_cache = true` in config. |
| `N` | Notifications | Provider supports real-time push notifications via a WebSocket connection managed by the host. Enables immediate sync on remote vault changes. |

## Capabilities by Provider

### Local Vault (`local`)

**Codes:** `WsKP`

| Capability | Supported |
|---|:---:|
| Sync | -- |
| Write | yes |
| Ssh | yes |
| KeyWrapping | yes |
| PasswordChange | yes |
| OfflineCache | -- |
| Notifications | -- |

The local vault is a fully writable, offline-only provider. It supports multiple unlock passwords via key wrapping (used for PAM auto-unlock when the login password differs from the master password). No sync because all data is local.

### Bitwarden Password Manager (`bitwarden`)

**Codes:** `SsCN`

| Capability | Supported |
|---|:---:|
| Sync | yes |
| Write | -- |
| Ssh | yes |
| KeyWrapping | -- |
| PasswordChange | -- |
| OfflineCache | yes |
| Notifications | yes |

Read-only access to a Bitwarden (or Vaultwarden) account. Syncs from the Bitwarden API on a configurable interval and supports push notifications for immediate updates. SSH keys stored in Bitwarden are loaded into the agent. Offline cache allows access to previously synced data after reboot without network.

### Bitwarden Secrets Manager (`bitwarden-sm`)

**Codes:** `S`

| Capability | Supported |
|---|:---:|
| Sync | yes |
| Write | -- |
| Ssh | -- |
| KeyWrapping | -- |
| PasswordChange | -- |
| OfflineCache | -- |
| Notifications | -- |

Machine-to-machine provider for CI/CD and server use cases. Syncs secrets from a Bitwarden SM project using an access token. Password change for the key encryption password is handled host-side by the WASM runtime, not as a provider capability.

### GNOME Keyring (`gnome-keyring`)

**Codes:** *(empty)*

| Capability | Supported |
|---|:---:|
| Sync | -- |
| Write | -- |
| Ssh | -- |
| KeyWrapping | -- |
| PasswordChange | -- |
| OfflineCache | -- |
| Notifications | -- |

Read-only access to existing `~/.local/share/keyrings/*.keyring` files. No optional capabilities — items are loaded once at unlock time. Intended as a migration bridge: access old GNOME Keyring items while running rosec as the Secret Service daemon.
