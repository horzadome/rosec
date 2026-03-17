# CLI Reference

## Provider List

```bash
rosec provider list
```

Shows all configured providers with their status. The output includes a **CAPS** column showing a compact code for each provider's capabilities.

### Capability Codes

Each letter represents one capability the provider supports:

| Code | Capability | Description |
|:----:|---|---|
| `S` | Sync | Can sync with a remote source |
| `W` | Write | Supports creating, updating, and deleting items |
| `s` | Ssh | Exposes SSH keys to the built-in agent |
| `K` | KeyWrapping | Supports multiple unlock passwords |
| `P` | PasswordChange | Supports changing the unlock password |
| `C` | OfflineCache | Supports offline cache for use without network |
| `N` | Notifications | Supports real-time push notifications from the remote |

### Example

```
ID              NAME             KIND           CAPS     STATE     LAST SYNC
─────────────────────────────────────────────────────────────────────────────
local           My Vault         local          WsKP     unlocked  never
bitwarden       Bitwarden        bitwarden-pm   SsCN     unlocked  2m ago
gnome-keyring   GNOME Keyring    gnome-keyring           unlocked
```

- `WsKP` — local vault: write, SSH, key wrapping, password change
- `SsCN` — Bitwarden PM: sync, SSH, offline cache, notifications
- *(empty)* — gnome-keyring: read-only, no optional capabilities

The CAPS column also appears in `rosec status`.

See [docs/providers/capabilities.md](providers/capabilities.md) for which capabilities each provider type supports and what they mean in practice.

## Search

```bash
rosec search [key=value ...] [-s|--sync] [--format=table|kv|json|human]
```

Search for items across all providers. Attribute filters are `key=value` pairs; glob patterns (`*`, `?`, `[`) in values trigger glob matching.

The `-s` / `--sync` flag syncs all providers that support `Sync` before searching. Providers without the `Sync` capability are skipped silently.

## Sync

```bash
rosec sync
```

Triggers a sync on all providers that declare the `Sync` capability. Providers without it (e.g. `local`, `gnome-keyring`) are skipped.
