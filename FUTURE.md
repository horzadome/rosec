# rosec — Future Work & Integration Notes

Design notes, planned features, and integration guidance.

---

## Replacing gnome-keyring-daemon (drop-in activation)

### Background

gnome-keyring-daemon is commonly started via one of three mechanisms:

1. **D-Bus auto-activation** — the session bus starts it on first access to
   `org.freedesktop.secrets` (via `/usr/share/dbus-1/services/org.freedesktop.secrets.service`).
2. **XDG autostart** — `gnome-keyring-secrets.desktop` in `/etc/xdg/autostart/`
   starts it at login for GNOME-family desktops.
3. **Compositor `exec-once`** — explicit launch in e.g. `hyprland.conf`:
   `exec-once = eval $(gnome-keyring-daemon --start --components=secrets,ssh,pkcs11)`

For a compositor like Hyprland that is not a GNOME session, typically only (1)
and (3) are active.  rosecd replaces both.

### How D-Bus auto-activation works

When any process calls a D-Bus method on a name that is not currently owned
(e.g. `org.freedesktop.secrets`), the bus daemon looks up
`/usr/share/dbus-1/services/<name>.service` and launches the `Exec=` binary.
The launched process must claim the bus name within a timeout or the activation
fails.

User-level service files in `~/.local/share/dbus-1/services/` take precedence
over system-level files in `/usr/share/dbus-1/services/`.  This is the
mechanism used to override or mask system entries without root access.

### Activation via systemd (recommended)

The contrib files ship everything needed:

```
contrib/
  dbus/
    org.freedesktop.secrets.service   # D-Bus activation → delegates to systemd
    org.gnome.keyring.service          # Masks gnome-keyring auto-activation
  systemd/
    rosecd.service                     # systemd user unit
  autostart/
    rosecd.desktop                     # XDG autostart fallback (non-systemd)
```

**Install steps:**

```bash
# 1. Install the binary (or adjust paths below to ~/.cargo/bin/rosecd)
sudo install -m755 target/release/rosecd /usr/local/bin/rosecd
sudo install -m755 target/release/rosec  /usr/local/bin/rosec

# 2. Enable rosec (generates D-Bus, systemd, and gnome-keyring mask files)
rosec enable
```

With `Type=dbus` and `BusName=org.freedesktop.secrets` in the systemd unit,
systemd knows the service is ready once the bus name is claimed.  The D-Bus
activation file's `SystemdService=rosecd.service` line means the bus daemon
delegates to systemd rather than exec-ing rosecd directly — so systemd handles
restarts, logging, and sandboxing.

**Remove the compositor `exec-once` line** — systemd + D-Bus activation is
sufficient and more robust (handles restarts, correct ordering).

### Activation without systemd (XDG autostart)

For setups without systemd user sessions (e.g. openrc, runit):

```bash
rosec enable --no-systemd
```

This installs D-Bus activation files and the gnome-keyring mask, but skips
systemd units. You will need to arrange for `rosecd` to start at login via
your compositor's autostart mechanism (e.g. `exec-once = rosecd` in Hyprland).

Alternatively, add to `hyprland.conf`:
```ini
exec-once = rosecd
```
No `eval $(...)` is needed — rosecd does not print env vars to stdout (unlike
gnome-keyring-daemon, which prints `SSH_AUTH_SOCK` etc.).  libsecret-based apps
find the daemon purely by D-Bus name.

### Why gnome-keyring can win the race

Even with rosecd running, gnome-keyring can grab `org.freedesktop.secrets` if:

- It starts first (e.g. via PAM — `pam_gnome_keyring.so` in `/etc/pam.d/`)
- Its D-Bus service file is read before rosecd claims the name

Check for PAM activation:
```bash
grep -r "gnome.keyring\|gnome-keyring" /etc/pam.d/
```

If found, either remove the PAM module or ensure rosecd is started earlier
(systemd `After=` ordering or PAM replacement with `pam_exec.so`).

Check for conflicting system D-Bus service files:
```bash
ls /usr/share/dbus-1/services/ | grep -E "secrets|keyring"
# User files in ~/.local/share/dbus-1/services/ take precedence over these,
# so the masking files above are sufficient without root access.
```

### Verifying rosecd owns the name

```bash
# Confirm rosecd is the current owner
gdbus call --session \
  --dest org.freedesktop.DBus \
  --object-path /org/freedesktop/DBus \
  --method org.freedesktop.DBus.GetNameOwner \
  org.freedesktop.secrets

# Check which process owns it
rosec status
```

---

## XDG Desktop Portal Secret backend (`org.freedesktop.impl.portal.Secret`)

### Background

The [XDG Desktop Portal](https://flatpak.github.io/xdg-desktop-portal/) is a
D-Bus framework that lets sandboxed apps (Flatpak, Snap) access host services
through portal interfaces.  The `org.freedesktop.portal.Secret` portal
(frontend) delegates to an implementation backend
(`org.freedesktop.impl.portal.Secret`) to retrieve a per-application master
secret that apps use to derive their own encryption keys.

The portal interface has exactly one method:

```xml
org.freedesktop.impl.portal.Secret.RetrieveSecret(
    IN  handle      ObjectPath,
    IN  app_id      String,
    IN  fd          UnixFD,
    IN  options     Dict<String, Variant>,
    OUT response    UInt32,
    OUT results     Dict<String, Variant>
)
```

The implementation writes a stable, per-`app_id` secret to the passed file
descriptor.  The app never learns the master vault password — it only receives
a derived key unique to its `app_id`.

### Why rosec should implement this

- **Flatpak apps** (e.g. GNOME Secrets, Firefox Flatpak) use this portal to
  bootstrap their encrypted storage.  Without a portal backend, these apps
  either fall back to plaintext or fail to initialize their secret stores.
- gnome-keyring-daemon provides this via `oo7-portal` (a separate binary).
  Dropping gnome-keyring without replacing the portal backend breaks Flatpak
  apps that depend on it.
- The implementation is trivial: derive a stable per-app secret (e.g.
  `HKDF(vault_key, app_id)`) and write it to the file descriptor.  oo7's
  implementation is ~100 lines.
- `cargo:libsecret` (Cargo's built-in credential helper) already talks to
  `org.freedesktop.secrets` directly, so the portal is NOT needed for Cargo.
  This is specifically for sandboxed Flatpak/Snap apps.

### Implementation sketch

1. A new D-Bus interface `org.freedesktop.impl.portal.Secret` registered on
   the session bus (same `rosecd` process, or a small companion binary
   activated via D-Bus).
2. On `RetrieveSecret`: check that the vault is unlocked, derive
   `HKDF-SHA256(vault_key, info=app_id)` → 64-byte secret, write to `fd`.
3. Ship a `.portal` file so `xdg-desktop-portal` discovers rosec as the
   Secret portal backend:
   ```ini
   [portal]
   DBusName=org.freedesktop.secrets
   Interfaces=org.freedesktop.impl.portal.Secret
   ```

### Effort estimate

Low — single method, no complex state.  The HKDF derivation and fd write are
straightforward.  Main work is D-Bus activation plumbing and integration
testing with a Flatpak app.

### Status

- **Not started** — low priority, implement when Flatpak app compatibility
  becomes a user request.

---

## SSH Agent (`rosec-ssh-agent`)

### Motivation

`rosecd` already owns the secrets daemon role that gnome-keyring-daemon fills.
gnome-keyring also provides an SSH agent (`SSH_AUTH_SOCK`), so dropping it
entirely requires a replacement.  Rather than delegating to a separate
`ssh-agent` process (which has no awareness of the vault), rosecd can provide a
smarter agent that draws SSH keys directly from the vault and applies
policy-based key selection.

### Security model

The SSH agent protocol (`$SSH_AUTH_SOCK`, a Unix domain socket) exposes private
key material to any process that can connect to the socket.  A naive
implementation that loads all keys from the vault on unlock would replicate the
main risk of gnome-keyring: an attacker with code execution can enumerate and
exfiltrate all SSH private keys.

Mitigations to implement:

- **Socket permissions**: the socket must be `chmod 600`, owner = session user,
  placed under `$XDG_RUNTIME_DIR/rosec/ssh-agent.sock` (mode 0700 directory).
- **Per-key confirm flag**: support the `SSH_AGENT_CONSTRAIN_CONFIRM` constraint
  — any `sign` request for a key marked `confirm` triggers a GUI prompt before
  use, matching `ssh-add -c` semantics.  This prevents silent exfiltration.
- **Per-key lifetime constraints**: support `SSH_AGENT_CONSTRAIN_LIFETIME` to
  auto-remove keys after N seconds of being loaded, matching `ssh-add -t`.
- **Key material zeroization**: private key bytes must be held in
  `Zeroizing<Vec<u8>>` and never copied into plain `Vec<u8>` or `String`.
  Keys are dropped (and zeroized) on vault lock.
- **No persistent key storage**: keys are never written to disk by the agent;
  they live only in memory while the vault is unlocked.
- **Audit log**: every `sign` request should be logged (key fingerprint,
  requesting peer PID via `SO_PEERCRED`, timestamp) at `tracing::info` level
  so users can audit what used which key.

### Smart key selection (solving "too many keys")

The standard SSH agent presents all loaded keys to the server in sequence.
OpenSSH will abort with `Too many authentication failures` (default
`MaxAuthTries = 6`) before reaching the right key if many are loaded.

#### Proposed approach: URI-based key filtering

Each SSH key item in the vault carries a `uri` attribute (the login URI field,
or a custom field named `ssh_host`).  The agent can match the target hostname
from the SSH connection against vault item attributes before deciding which keys
to offer:

1. Client sends `SSH_AGENTC_SIGN_REQUEST` with a public key.
2. Agent checks whether the key's vault item has a `uri` / `ssh_host` attribute.
3. If present, the key is only offered to hosts that match the pattern.
4. Keys with no host restriction are offered last (fallback pool).

This is analogous to `~/.ssh/config`'s `IdentityFile` per-host, but
driven automatically from vault metadata.

#### Config knobs (under `[ssh_agent]` in `config.toml`)

```toml
[ssh_agent]
# Enable the SSH agent.  Default: false.
enabled = true

# Path for the Unix domain socket.
# Default: $XDG_RUNTIME_DIR/rosec/ssh-agent.sock
# socket = "/run/user/1000/rosec/ssh-agent.sock"

# Maximum number of keys to offer per connection attempt.
# Prevents MaxAuthTries failures when many keys are stored.
# Default: 5
max_keys_per_host = 5

# If true, require a GUI confirmation prompt for every sign() call.
# Equivalent to ssh-add -c for all keys.
# Per-key override via vault item custom field: confirm = "true"
confirm_all = false

# Auto-remove keys from the agent N seconds after vault unlock.
# 0 = no lifetime limit.  Equivalent to ssh-add -t.
# Per-key override via vault item custom field: lifetime_secs = "3600"
key_lifetime_secs = 0
```

### Vault item convention for SSH keys

Bitwarden's SSH Key cipher type (`CipherType::SshKey`) maps naturally:

| Vault field        | Agent use                                      |
|--------------------|------------------------------------------------|
| Private Key        | Loaded into agent on unlock                    |
| Public Key         | Used for key fingerprint / identity matching   |
| Fingerprint        | Displayed in confirm prompts and audit log     |
| Login URI / `ssh_host` custom field | Host pattern for smart selection |
| `confirm` custom field (text, "true") | Per-key confirm constraint  |
| `lifetime_secs` custom field (text, integer) | Per-key lifetime       |

Login-type items with a URI of `ssh://hostname` and a password that is a
PEM private key should also be supported for users who store SSH keys as
login items rather than the dedicated SSH Key type.

### Implementation sketch

A new workspace crate `rosec-ssh-agent` would:

1. Implement the SSH agent protocol (parse/serialise `ssh-agent` wire format,
   defined in `draft-miller-ssh-agent`).
2. Expose a `SshAgentBackend` that holds the loaded keys (drawn from the
   `VaultBackend` trait on unlock).
3. Bind a Unix socket under `$XDG_RUNTIME_DIR/rosec/` and `accept()` in a
   `tokio` task per connection.
4. On `LIST_IDENTITIES`: return keys filtered/ordered by host-match policy.
5. On `SIGN_REQUEST`: check confirm constraint → optional prompt → sign →
   return signature.  Log the event.
6. On vault lock: drop all `Zeroizing<>` key material, close the socket.

`rosecd` would spawn the agent task when `[ssh_agent] enabled = true` and
export `SSH_AUTH_SOCK` to child processes — but since `rosecd` is launched by
the compositor (not a shell), this env var needs to reach the rest of the
session.  Options:
- Write it to `$XDG_RUNTIME_DIR/rosec/env` and source it from shell init.
- Register it via `systemd --user set-environment SSH_AUTH_SOCK=...`.
- Emit `export SSH_AUTH_SOCK=...` to stdout so `eval $(rosecd)` works
  (matching gnome-keyring-daemon's interface).

### PKCS#11 / hardware token support

PKCS#11 is the standard C API for hardware cryptographic tokens (YubiKey,
smartcard, HSM).  When an SSH private key lives on hardware, the token performs
the signing operation internally — the raw key bytes never leave the device.

gnome-keyring's `--components=pkcs11` exposes a *software* PKCS#11 token that
bridges this interface for apps that expect it.  For the SSH agent specifically,
`ssh` can load a PKCS#11 module directly (`PKCS11Provider` in `~/.ssh/config`)
to use a hardware token without any agent involvement.

For rosecd, PKCS#11 matters in two ways:

1. **Hardware-backed SSH keys via the agent**: if a user's SSH key lives on a
   YubiKey rather than in Bitwarden, the agent needs to forward sign requests to
   the token's PKCS#11 interface.  The key selection policy (which token slot
   maps to which host) could be stored as vault metadata, giving rosecd the same
   host-filtering benefit for hardware keys.

2. **Software PKCS#11 token (lower priority)**: some apps (notably older GNOME
   apps and some browsers) expect a PKCS#11 token for certificate/key storage
   rather than the Secret Service API.  This is largely obsolete for the use
   cases rosecd targets.

Hardware token support for the SSH agent is worth implementing as a follow-on.
The relevant Rust crate is [`cryptoki`](https://crates.io/crates/cryptoki)
(Apache-2.0), the idiomatic PKCS#11 binding.  The signing path would be:
`sign_request → look up host policy in vault → identify token slot → cryptoki
sign → return signature`, with the private key never touching rosecd's memory.

### Relevant crates to evaluate

- [`ssh-agent-lib`](https://crates.io/crates/ssh-agent-lib) — async SSH agent
  protocol implementation (MIT).  Evaluating whether it covers the constraint
  extensions.
- [`ssh-key`](https://crates.io/crates/ssh-key) — pure Rust SSH key parsing and
  signing (Apache-2.0/MIT).  Already used transitively via some deps; worth
  depending on directly.
- [`russh`](https://crates.io/crates/russh) — full SSH implementation; likely
  too heavy for just the agent protocol.

### Open questions

- Should `rosec-ssh-agent` be gated behind a feature flag like `bitwarden-sm`,
  given it pulls in additional crypto deps?  Likely yes.
- How to handle ECDSA / Ed25519 / RSA signing without pulling in OpenSSL?
  `ssh-key` + `p256`/`ed25519-dalek`/`rsa` should cover this with pure Rust.
- Confirm prompt UX: reuse `rosec-prompt` (iced GUI) or a simpler
  notification-style dialog?  The latter is less intrusive for frequent
  operations.

---

## WASM backend host (`rosec-wasm`)

### Motivation

Several password managers (1Password, Proton Pass, Dashlane, etc.) either have
official Go SDKs or are best reached by community Go libraries.  Rather than
writing a bespoke Rust HTTP+crypto client for every provider, a WASM plugin host
would let backends be written in **any language that compiles to WASM** — Go
(via TinyGo), Rust, Python, or C — and loaded at runtime as sandboxed modules.

This gives rosec a general-purpose extension mechanism:

- Third-party backends without modifying the rosec source tree.
- Backend logic written in Go (e.g. wrapping the official 1Password Go SDK or
  the Proton Pass Go library) compiled to `.wasm` and dropped into a directory.
- Tight sandboxing: the WASM module cannot access the filesystem, network, or
  process memory beyond what the host explicitly grants through capabilities.
- ABI stability: the WIT interface between host and guest is versioned and
  language-agnostic.

### Two viable embedding approaches

#### Option A — WASI Component Model + wasmtime (recommended)

The [WebAssembly Component Model](https://component-model.bytecodealliance.org/)
(WASI Preview 2 / `wasip2`) is the emerging standard for polyglot WASM plugins.
Interfaces are defined in **WIT** (WASM Interface Type), and `wit-bindgen`
generates host and guest bindings automatically.

**How it works:**

1. Define a `vault-backend` WIT world in `rosec-wasm/wit/vault-backend.wit`:

```wit
package rosec:vault-backend@0.1.0;

world vault-backend {
    /// Called once with the raw TOML options table for this backend entry.
    export init: func(options: list<tuple<string, string>>) -> result<_, string>;

    /// Return current lock state.
    export is-locked: func() -> bool;

    /// Unlock with a password or token.
    export unlock: func(credential: string) -> result<_, string>;

    /// Lock and clear in-memory secrets.
    export lock: func();

    /// Return all vault items as a flat JSON array.
    export list-items: func() -> result<string, string>;

    /// Sync from the remote source.
    export sync: func() -> result<_, string>;
}
```

2. The host (`rosec-wasm`) embeds `wasmtime` and, on startup, instantiates each
   `.wasm` file found in the configured plugin directory.  Each instantiated
   component becomes a `VaultBackend` adaptor.

3. A Go backend author writes a TinyGo program, imports `wit-bindgen`-generated
   Go bindings, implements the exported functions, and compiles:

```bash
tinygo build -target=wasip2 -o 1password.wasm ./cmd/1password-plugin/
```

The resulting `.wasm` is placed in `~/.config/rosec/plugins/` and referenced
from `config.toml`:

```toml
[[backend]]
id   = "1password"
type = "wasm"

[backend.options]
plugin = "~/.config/rosec/plugins/1password.wasm"
connect_url = "https://op-connect.internal:8080"
token       = "..."     # stored encrypted by the host
```

**Go/TinyGo status (Feb 2026):**
TinyGo v0.34+ supports the `wasip2` target and the Component Model natively
(via `wasm-tools` component wrapping).  Standard Go (`GOOS=wasip1`) targets
WASI Preview 1 (core modules, not components); `GOOS=wasip2` is tracked in
[golang/go#65333](https://github.com/golang/go/issues/65333) and not yet
shipped.  TinyGo is therefore the recommended Go compiler for guest plugins
today; it supports most of the standard library needed for HTTP clients.

**Rust crates needed (host):**

| Crate | Role | License |
|---|---|---|
| `wasmtime` | WASM/WASI runtime + Component Model embedding | Apache-2.0 |
| `wasmtime-wasi` | WASI Preview 2 host implementation | Apache-2.0 |
| `wit-bindgen` | Generate Rust host bindings from WIT | Apache-2.0/MIT |

**Security properties:**
- The WASM sandbox prevents the plugin from reading `/proc`, opening arbitrary
  file descriptors, or forking processes.
- Network access is capability-gated: the host can grant the plugin a pre-opened
  `wasi:http/outgoing-handler` (HTTP client only, no raw sockets).
- Filesystem access: the host grants only an explicit pre-opened directory (for
  token cache), nothing else.
- Secrets returned from the guest (`list-items`) are JSON strings in guest
  memory; the host copies them out and then zeroizes the host-side buffer after
  parsing, before storing in `Zeroizing<Vec<u8>>`.

#### Option B — Extism (simpler, less formal)

[Extism](https://extism.org) is a higher-level plugin framework built on
Wasmtime.  It provides a unified host SDK and per-language PDKs (Plug-in
Development Kits) with a simple `input → output` call model.

**Advantages over raw Component Model:**
- Simpler API: no WIT file, no `wit-bindgen` step.
- Go PDK (`extism/go-pdk`) compiles via TinyGo to a working `.wasm` today.
- Host SDK (`extism` Rust crate) is a single dependency with an ergonomic API.
- Good documentation and a larger community of plugin authors.

**Disadvantages:**
- Uses a custom ABI (not the standard Component Model) — interoperability with
  non-Extism hosts is zero.
- Extism's data model is byte-buffer–based; structured types must be
  JSON-serialised manually (no generated type bindings).
- Less capability-granular than WASI Preview 2 — HTTP is allowed or not, rather
  than per-origin.

**Sketch:**

```rust
// Host (rosec-wasm/src/extism_backend.rs)
use extism::{Plugin, Manifest, Wasm};

let wasm = Wasm::file("~/.config/rosec/plugins/1password.wasm");
let manifest = Manifest::new([wasm]).with_allowed_host("op-connect.internal");
let mut plugin = Plugin::new(&manifest, [], true)?;

let items_json: String = plugin.call("list_items", options_json)?;
```

```go
// Guest (Go / TinyGo, compiled with extism/go-pdk)
package main

import (
    "github.com/extism/go-pdk"
    "encoding/json"
)

//go:export list_items
func listItems() int32 {
    cfg := pdk.GetConfig("connect_url")
    // ... fetch and decrypt items from 1Password Connect ...
    out, _ := json.Marshal(items)
    pdk.OutputString(string(out))
    return 0
}
func main() {}
```

### Recommended path

Start with **Extism** (Option B) to prove the concept quickly — the Go PDK
works today with TinyGo and the Rust host SDK is mature.  Migrate to the
**Component Model** (Option A) once `GOOS=wasip2` lands in standard Go (likely
Go 1.25–1.26) and the toolchain stabilises, giving a formally typed interface
and standard WASI capability model.

### Config sketch

```toml
[[backend]]
id   = "1password-wasm"
type = "wasm"

[backend.options]
# Path to the compiled .wasm plugin.  Relative paths are resolved from
# $XDG_CONFIG_HOME/rosec/plugins/.
plugin = "1password.wasm"

# All remaining options are forwarded to the plugin's init() call as a
# flat string→string map.  The plugin is responsible for interpreting them.
connect_url = "https://op-connect.internal:8080"
# token is stored encrypted by the host using the same credential store
# as the bitwarden backend; the plugin receives the decrypted value.
token       = "eyJ..."
```

### Security considerations

- **Plugin provenance**: plugins are unsigned arbitrary code.  The host must
  warn loudly if a plugin path is world-writable.  A future `plugin_sha256`
  config field could pin expected content hashes.
- **Secret exposure**: the host decrypts stored credentials before passing them
  to the plugin's `init()` call.  The decrypted bytes live in the host's
  address space only long enough to copy into WASM linear memory, then are
  zeroized.  The plugin itself never has access to the host's key material.
- **No `wasi:filesystem` for plugins**: plugins receive only a virtual temp
  directory and the specific HTTP hosts they declare.  They cannot read
  `~/.config/rosec/` or the host's secret store.
- **Output sanitisation**: JSON returned by the plugin is parsed by the host
  before being stored in the vault cache.  Malformed output returns an error;
  it does not crash the daemon.

### Relevant crates

| Crate | Purpose | License |
|---|---|---|
| `wasmtime` | WASI Component Model runtime | Apache-2.0 |
| `wasmtime-wasi` | WASI host implementation | Apache-2.0 |
| `extism` | Higher-level plugin host (Option B) | BSD-3 |
| `wit-bindgen` | WIT → Rust binding codegen (Option A) | Apache-2.0/MIT |

---

## 1Password backend (`rosec-1password`)

### Motivation

[1Password](https://1password.com) is one of the most widely used password
managers, particularly in team and enterprise contexts.  Adding a rosec backend
for it would let users access 1Password secrets through the standard Secret
Service API alongside Bitwarden or other backends.

Two integration paths exist, with very different trade-offs:

### Option A — 1Password Connect (recommended first target)

1Password Connect is a self-hosted REST server that exposes vault contents over
a simple, fully-documented HTTP API authenticated with a static bearer token.

**Requirements:**
- A 1Password Teams or Business plan (Connect is not available on Personal).
- A Connect server deployed on your own infrastructure (Docker image provided
  by 1Password).
- A Connect server access token scoped to the vaults you want to expose.

**Authentication:**
All requests carry an `Authorization: Bearer <token>` header.  There is no
session negotiation, no SRP, no KDF — the token is static and issued from the
1Password web portal.  The token is stored encrypted at rest (same pattern as
`rosec-bitwarden`'s OAuth credential store).

**Key API endpoints:**

| Endpoint | Purpose |
|---|---|
| `GET /v1/vaults` | List accessible vaults |
| `GET /v1/vaults/{vaultId}/items` | List items in a vault |
| `GET /v1/vaults/{vaultId}/items/{itemId}` | Fetch a single item (with fields) |
| `GET /v1/vaults/{vaultId}/items?filter=title eq "..."` | Server-side search |

The response schema is a well-documented JSON format.  Items have typed fields
(username, password, TOTP, URL, custom, etc.) that map cleanly onto the rosec
attribute model.

**Why this path is attractive:**
- The API is stable, publicly documented, and versioned.
- No proprietary binary is required.
- Pure HTTP — reqwest already a workspace dep, no new crypto.
- A Rust crate exists: [`connect-1password`](https://crates.io/crates/connect-1password)
  (Apache-2.0/MIT), though the implementation is simple enough to do directly
  from the published OpenAPI spec.
- `can_auto_unlock()` returns `true` — the bearer token IS the credential; no
  master-password prompt is needed.

**Limitations:**
- Requires a 1Password Business/Teams plan and self-hosted Connect server.
- Not usable for personal 1Password accounts on the cloud.
- Items are transmitted decrypted by the Connect server — the security boundary
  is the Connect server itself, not end-to-end encryption.

### Option B — Service Accounts / SDK (personal cloud accounts)

1Password Service Accounts are JWT-based machine credentials that authenticate
directly against the 1Password cloud.  The official 1Password SDKs (Go, JS,
Python) are thin wrappers around a proprietary core library (`libop_uniffi_core`)
that handles the end-to-end encrypted vault protocol client-side.

A community crate [`corteq-onepassword`](https://crates.io/crates/corteq-onepassword)
provides FFI bindings to this core library for Rust.  However:

- The underlying `libop_uniffi_core` is **proprietary** (1Password's own
  license, similar situation to Bitwarden's SM SDK).
- It ships as a pre-built binary (`libop_uniffi_core.so`) that must be linked
  at runtime — not a pure Rust solution.
- The license terms for redistribution and use in open-source projects are
  unclear.

For these reasons, Option B would follow the same pattern as `rosec-bitwarden-sm`:
a separate workspace crate (`rosec-1password-sa`) gated behind a feature flag,
with its own license declaration, letting packagers exclude it cleanly.

### Implementation plan (Option A first)

1. New workspace crate `rosec-1password` (MIT, no feature gate needed — pure HTTP).
2. `OnePasswordConfig` with `id`, `connect_url`, `token` (stored encrypted).
3. `OnePasswordBackend` implementing `VaultBackend`:
   - `can_auto_unlock() = true` (token-based, no interactive prompt).
   - `unlock()` validates the token against `GET /v1/vaults` and caches the
     vault list.
   - `sync()` re-fetches vault item lists.
   - `get_secret()` fetches the item and returns the primary secret field
     (password, or first secret-type field).
4. Field → attribute mapping:
   - `type` = item category (login, password, creditCard, identity, etc.)
   - `username`, `password`, `totp`, `uri` — standard Login fields
   - `custom.<field_label>` — custom fields (concealed → sensitive, text → public)
   - `notes` — always sensitive

### Relevant crates

- [`connect-1password`](https://crates.io/crates/connect-1password) — Rust
  Connect SDK (Apache-2.0/MIT); evaluating for reuse vs direct reqwest calls.
- [`corteq-onepassword`](https://crates.io/crates/corteq-onepassword) — FFI
  wrapper for the official SDK core (Option B only; proprietary core dep).
- [`reqwest`](https://crates.io/crates/reqwest) — already a workspace dep.

### Open questions

- Should `rosec-1password` support both Connect and Service Accounts in a single
  crate (distinguished by `type = "1password-connect"` vs `"1password-sa"`)?
  Probably yes for user clarity, but Option B needs a separate crate for the
  license isolation.
- Does 1Password Connect support a change-notification mechanism (webhooks or
  SSE) similar to Bitwarden's SignalR hub?  If so, a `notifications.rs` task
  could provide real-time sync.  Otherwise polling is sufficient given the
  Connect use case (infrastructure automation rather than interactive desktop
  use).

---

## Proton Pass backend (`rosec-proton-pass`)

### Motivation

[Proton Pass](https://proton.me/pass) is a privacy-focused password manager
from the team behind ProtonMail.  It stores vaults end-to-end encrypted on
Proton's servers and offers apps for all major platforms.  Adding it as a
rosec backend would let users who choose Proton's ecosystem access their
secrets through the standard Secret Service API — the same way the Bitwarden
backend works today.

### Authentication model

Proton Pass uses Proton's SRP-based authentication (Secure Remote Password
with an extra client-proof step).  The client derives a session key from the
user's password using PBKDF2 (or Argon2id on newer accounts), then exchanges
proofs with the identity server to obtain an access token.  Two-factor
authentication (TOTP or hardware key) is supported at this step.

The session token is short-lived.  The client must refresh it using a refresh
token, or re-authenticate when the session expires.  The device must be
registered (similar to Bitwarden's device verification flow) before it can
receive an access token.

### Vault encryption

Vault data is doubly encrypted:

1. **Address key**: derived from the primary key material, used to decrypt the
   vault "share" keys.
2. **Item keys**: per-item symmetric keys encrypted with the share key.  All
   cipher text uses PGP (OpenPGP message format) with the item key.

This means the Rust implementation needs:
- SRP proof computation (PBKDF2 / Argon2 + modular exponentiation)
- OpenPGP decryption for item content (the
  [`pgp`](https://crates.io/crates/pgp) crate, MIT)
- AES-GCM / AES-CBC for the inner share-key layer

The `rosec-proton-pass` crate would mirror the structure of `rosec-bitwarden`:
separate modules for the HTTP client, crypto, vault state, and
`VaultBackend` implementation.

### API surface

Proton Pass does not publish an official API specification, but the protocol
is partially documented by reverse engineering and community projects (notably
[pass-rust-core](https://github.com/ProtonMail/pass-rust-core) and the
[gopass-bridge](https://github.com/nicholasgasior/gopass-bridge) project).
The key endpoints are:

| Endpoint | Purpose |
|---|---|
| `POST /auth/v4/info` | SRP server challenge |
| `POST /auth/v4` | SRP proof exchange → access + refresh tokens |
| `GET /pass/v1/share` | List vault shares |
| `GET /pass/v1/share/{shareId}/item` | List encrypted items in a share |
| `GET /core/v4/keys` | Fetch user key material |

### Implementation considerations

- **License**: The `rosec-proton-pass` crate would be MIT-licensed (matching
  the rest of rosec).  The SRP and OpenPGP implementations it uses are all
  OSI-approved.  No proprietary SDK is required.
- **Feature flag**: gate behind `proton-pass` feature, same pattern as
  `bitwarden-sm`, so users who do not use Proton Pass incur no extra
  dependencies.
- **Credentials storage**: the session access/refresh token pair should be
  stored encrypted at rest using the same `oauth_cred` pattern used by the
  Bitwarden backend (derive a storage key from the master password, then
  HMAC-authenticated AES-CBC).
- **SRP crate**: [`srp`](https://crates.io/crates/srp) (MIT/Apache-2) handles
  the SRP proof computation; Proton uses a custom group (2048-bit MODP).
- **Two-factor**: TOTP tokens can be submitted as an additional field in the
  auth flow, using the same `TwoFactorSubmission` pattern as Bitwarden.
- **Read-only**: rosec is read-only; write operations (creating/updating items)
  are out of scope.

### Relevant crates

- [`pgp`](https://crates.io/crates/pgp) — pure Rust OpenPGP (MIT)
- [`srp`](https://crates.io/crates/srp) — SRP-6a implementation (MIT/Apache-2)
- [`aes-gcm`](https://crates.io/crates/aes-gcm) — AES-GCM (MIT/Apache-2)
- [`reqwest`](https://crates.io/crates/reqwest) — already a workspace dep

### Open questions

- Proton's API is not versioned in a stable, public way — the implementation
  would need to track API changes.  Community projects like
  [pass-rust-core](https://github.com/ProtonMail/pass-rust-core) are the
  primary reference.
- Does Proton Pass have a device-registration step analogous to Bitwarden's
  personal API key flow?  If so, the `RegistrationInfo` trait method covers it.
- Real-time sync: Proton Pass uses Server-Sent Events (SSE) rather than
  SignalR.  A similar `notifications.rs` task could listen on the SSE stream
  and call `try_sync_backend` on events.

---

## Real-time vault sync (SignalR / WebSocket)

### Background

rosec currently polls on a fixed `refresh_interval_secs` timer (default 60 s).
Bitwarden non-mobile clients use a persistent SignalR WebSocket connection to
`/notifications/hub` on the server.  The server pushes a lightweight
"something changed" notification; the client responds by calling `/api/sync` to
fetch the actual data.  This provides near-instant propagation of vault changes
without constant polling.

The flow:

1. Client establishes a WebSocket to `wss://<server>/notifications/hub`.
2. Server sends a SignalR handshake, then `SyncCipherUpdated` / `SyncVault` /
   `LogOut` messages as events occur.
3. On any sync notification the client calls `GET /api/sync` to refresh.
4. The WebSocket is kept alive with SignalR ping frames; the client reconnects
   on disconnect.

Vaultwarden supports the same protocol; the official Bitwarden cloud uses it
exclusively for non-mobile clients.

### Why it matters for rosec

With a 60 s poll interval, a password changed in the Bitwarden web vault takes
up to a minute to appear in rosec.  Applications that cache the secret (e.g.
`pass`, shell scripts) may use a stale value even longer.  Real-time sync
closes this window immediately.

### Implementation notes

- No mature Rust SignalR client crate exists.  The protocol is simple enough to
  implement directly: HTTP upgrade to WebSocket, send the SignalR handshake JSON
  (`{"protocol":"json","version":1}`), then read newline-delimited JSON frames.
  The [`tokio-tungstenite`](https://crates.io/crates/tokio-tungstenite) crate
  handles the WebSocket layer.
- Access token refresh must be wired into the WebSocket reconnect path: if the
  session token expires the server closes the connection, and the client must
  re-authenticate before reconnecting.
- The existing `refresh_interval_secs` timer becomes a fallback for servers
  that do not support SignalR (uncommon self-hosted deployments).
- On a `LogOut` notification the daemon should lock the vault immediately,
  matching the behaviour of the official client.

### Config sketch

No new top-level section is needed.  The feature is per-backend:

```toml
[[backend]]
id   = "bitwarden"
type = "bitwarden"

[backend.options]
email           = "user@example.com"
realtime_sync   = true   # default: true when server supports it
```

Disabling is useful if the WebSocket connection causes issues (e.g. aggressive
corporate proxies that terminate long-lived connections).

### Relevant crates

- [`tokio-tungstenite`](https://crates.io/crates/tokio-tungstenite) — async
  WebSocket client (MIT).  Already in the broader Rust ecosystem; lightweight.
- No SignalR crate is needed — the subset used by Bitwarden is simple enough to
  parse directly from newline-delimited JSON frames.

---

## Headless / container mode (private D-Bus socket)

### Background

`rosecd` currently requires a D-Bus session bus (`DBUS_SESSION_BUS_ADDRESS`).
In containers, SSH sessions, and CI environments there is often no session bus,
making the daemon unusable in those contexts.

gnome-keyring-daemon solves a related problem via
`/run/user/<uid>/keyring/control` — a Unix domain socket it listens on directly,
advertised to clients via `GNOME_KEYRING_CONTROL`.  This lets gnome-keyring work
without a session bus, but at the cost of a bespoke, non-standard protocol that
no other Secret Service implementation supports.

### Proposed approach

Rather than a gnome-keyring-style private protocol socket, rosecd should expose
the **same `org.freedesktop.secrets` D-Bus interface** over a private Unix socket
bus.  Clients connect by setting `DBUS_SESSION_BUS_ADDRESS=unix:path=<socket>`,
which is the standard mechanism — no client changes required.

```
rosecd --socket /run/user/1000/rosec/bus
export DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/rosec/bus
rosec search name=github
secret-tool search name github   # standard clients work unmodified
```

### Why not raw zbus peer-to-peer

The original plan assumed `ConnectionBuilder::unix_listener(listener)` exists in
zbus — it does not.  The actual API is `Builder::unix_stream(stream)`, which
takes a single already-connected stream.  In p2p mode each `accept()`ed client
gets its own `Connection` with its own `ObjectServer`; there is no shared bus.

Standard Secret Service clients (`secret-tool`, `libsecret`, `seahorse`) call
bus-level operations on connect: `Hello()`, `RequestName()`,
`GetNameOwner("org.freedesktop.secrets")`.  These operations only exist in a bus
broker — p2p connections have no name registry, no signal routing, and no match
rules.

Additionally, `ServiceState` stores a single `self.conn` and uses it to
dynamically register/deregister `SecretItem` D-Bus objects
(`rosec-secret-service/src/state.rs`).  This design requires a single bus
connection, not per-client p2p connections.

### Chosen approach: embedded busd

[`busd`](https://crates.io/crates/busd) (MIT license) is a D-Bus bus broker
written by the zbus author (zeenix).  It exposes a library API:

```rust
let bus = busd::bus::Bus::for_address(Some("unix:path=/run/user/1000/rosec/bus"))?;
bus.run().await?;  // accept loop — handles multi-client multiplexing
```

busd provides everything a real bus broker needs: multi-client multiplexing,
name registry (`Hello()`, `RequestName()`), signal routing/broadcasting, and
match rules.  It has 583 commits and is actively maintained.  6 of its 7 unique
dependencies are already in our `Cargo.lock` as transitive deps of zbus — only
`xdg-home` would be new.

**Architecture when `--socket` is given:**

```
┌───────────────────────────────────┐
│           rosecd process          │
│                                   │
│  ┌─────────────────────────────┐  │
│  │  busd::bus::Bus (tokio task)│  │
│  │  listening on /run/.../bus  │  │
│  └────────────┬────────────────┘  │
│               │ unix socket       │
│  ┌────────────▼────────────────┐  │
│  │  Connection::session()      │  │
│  │  (DBUS_SESSION_BUS_ADDRESS  │  │
│  │   = unix:path=.../bus)      │  │
│  └────────────┬────────────────┘  │
│               │                   │
│  ┌────────────▼────────────────┐  │
│  │  register_objects_with_     │  │
│  │  full_config() — unchanged  │  │
│  └─────────────────────────────┘  │
└───────────────────────────────────┘
         ▲            ▲
         │            │
    secret-tool    libsecret app
    (unmodified)   (unmodified)
```

**Zero changes to existing service code.** The daemon spawns busd in-process on
the private socket, sets `DBUS_SESSION_BUS_ADDRESS` to point to it, then
connects via `Connection::session()` as normal.  The same
`register_objects_with_full_config()`, same `ObjectServer`, same dynamic item
registration all work unchanged.

### Implementation details

- **Cargo feature:** `private-socket` in the `rosecd` crate, adding `busd` as
  an optional dependency.  Disabled by default — no impact on the normal
  session bus path.
- **Socket path:** defaults to `$XDG_RUNTIME_DIR/rosec/bus`; configurable via
  `--socket <path>` flag or `ROSEC_SOCKET` env var.
- **CLI auto-detection:** `rosec` CLI checks `ROSEC_SOCKET` env var, then
  `$XDG_RUNTIME_DIR/rosec/bus` (if the file exists), before falling back to
  the session bus.  This makes `eval $(rosecd --socket ...)` shell integration
  work naturally.
- **Logind watcher:** skipped in private socket mode — no system bus is
  available.  Lock-on-sleep would rely on idle timeouts instead.
- **Permissions:** the socket file is created with mode `0o600` and placed under
  the user's `XDG_RUNTIME_DIR` (which is itself `0o700`).

### Implementation phases

1. Add `--socket` flag to `rosecd` and embedded busd startup behind
   `private-socket` feature.
2. CLI auto-detection of `ROSEC_SOCKET` / `XDG_RUNTIME_DIR/rosec/bus`.
3. Config file `socket_path` option in `[daemon]` section.
4. Systemd integration documentation (`rosecd.socket` activation example).

### Why not the gnome-keyring control socket approach

- `GNOME_KEYRING_CONTROL` is a gnome-keyring private protocol — not the Secret
  Service spec.  No other implementation supports it.
- Exposing a raw socket with a bespoke framing would require maintaining a
  second protocol implementation in perpetuity.
- A private D-Bus socket via embedded busd is strictly superior: same protocol,
  zero changes to service code, and fully interoperable with any conforming
  Secret Service client.

---

## WebAuthn / FIDO2 / Passkey Two-Factor Authentication

### Background

rosec supports text-prompt 2FA methods (TOTP, email, YubiKey OTP, Duo
passcode) via the generic `TwoFactorMethod` protocol.  Each text-prompt
method works identically from the host's perspective: prompt a string on the
TTY, send it to the guest.

WebAuthn / FIDO2 (Bitwarden provider code 4) is fundamentally different.  It
requires a **host-mediated ceremony** where:

1. The guest returns a JSON challenge (from `TwoFactorProviders2`) containing
   `rpId`, `challenge`, `allowCredentials`, `userVerification`, etc.
2. The **host** communicates with a hardware authenticator (USB HID / NFC /
   BLE) to perform a `navigator.credentials.get()` equivalent.
3. The host sends the signed assertion response back to the guest.
4. The guest includes the assertion in the Bitwarden login request.

This cannot happen inside the WASM sandbox — the guest has no hardware access.

### Protocol support (already in place)

The `TwoFactorMethod` protocol type includes:

- `prompt_kind: "fido2"` — signals to the host that this is a host-mediated
  method, not a text prompt.
- `challenge: Option<String>` — carries the JSON challenge data from the
  server (currently `None` because the PM guest doesn't yet extract
  `TwoFactorProviders2` challenge data for WebAuthn).

The host (`unlock.rs`) currently filters to `prompt_kind == "text"` methods
only.  If only `fido2` methods are available, it returns an error:
"provider requires 2FA but no supported methods available".

### Implementation plan

#### Phase 1: Guest extracts WebAuthn challenge

- Deserialize `TwoFactorProviders2` in `rosec-bitwarden-pm/src/api.rs`
  (currently only `TwoFactorProviders` — the flat `Vec<u8>` — is parsed).
- For provider code 4, extract the `Challenges` array and serialize it as
  JSON into `TwoFactorMethod { challenge: Some(json_str), .. }`.
- The guest must also accept the assertion response back via `auth_fields`
  and format it into the `twoFactorToken` form parameter expected by the
  Bitwarden identity endpoint.

#### Phase 2: Host FIDO2 client

- Add a new crate `rosec-fido2` (or a module in `rosec-secret-service`)
  that wraps `libfido2` or the `ctap-hid-fido2` Rust crate.
- The host detects `prompt_kind == "fido2"`, parses the challenge JSON,
  performs the authenticator assertion, and puts the response into
  `auth_fields` (e.g. `__2fa_fido2_response`).
- Requires access to `/dev/hidraw*` — user must be in the `fido` group
  or have appropriate udev rules.

#### Phase 3: Passkey / discoverable credentials

- Some Bitwarden accounts may use passkeys (resident/discoverable
  credentials) for passwordless login.  This is a separate Bitwarden API
  flow (`grant_type: "webauthn"` rather than `"password"`).
- This would require a new `UnlockInput` variant or a separate
  `Provider::unlock_passkey()` method.
- Deferred until WebAuthn 2FA works, since the FIDO2 infrastructure is a
  prerequisite.

#### Platform considerations

| Platform | FIDO2 access | Notes |
|----------|-------------|-------|
| Linux | `libfido2` / `ctap-hid-fido2` via `/dev/hidraw*` | Needs udev rules or `fido` group |
| macOS | `libfido2` or Security.framework | Different transport |
| Windows | Windows Hello / WebAuthn API | Completely different surface |

For the initial implementation, Linux-only via `libfido2` is sufficient.

### Duo push / browser redirect

Full Duo push (provider 2/6) faces a similar problem: the Duo handshake
requires a browser redirect and callback.  The approach would be:

1. Guest extracts `Host`, `Signature`, `AuthUrl` from `TwoFactorProviders2`.
2. Host opens the URL via `xdg-open` (or equivalent).
3. Host polls or listens for the Duo callback to complete.
4. Host extracts the Duo auth token and sends it back to the guest.

This shares infrastructure with the "browser_redirect" `prompt_kind`.
Currently, only Duo passcode (plain text) is supported.

### Status

- Protocol types: **done** (`TwoFactorMethod.prompt_kind`, `.challenge`)
- Guest challenge extraction: **not started**
- Host FIDO2 client: **not started**
- Duo browser redirect: **not started**

---

## Cross-Platform Support

### Overview

rosec's architecture separates cleanly into platform-agnostic crates and
platform-specific ones.  The goal is not to port the entire stack to every OS,
but to ensure the core crates compile everywhere and platform-specific
functionality is properly gated behind `cfg` attributes.

### D-Bus dependency audit

| Crate | D-Bus? | Cross-platform? | Notes |
|-------|--------|-----------------|-------|
| `rosec-core` | No | Yes | Pure Rust, config/crypto/types |
| `rosec-vault` | No | Yes | Local encrypted storage |
| `rosec-wasm` | No | Yes | Extism host, provider trait bridge |
| WASM guests (bitwarden-pm, bitwarden-sm) | No | Yes | Pure Rust, compile to wasm32-wasi |
| `rosec-ssh-agent` | No | Mostly | Unix sockets need `cfg` gating |
| `rosec-fuse` | No | Linux-only | FUSE is Linux/macOS (macFUSE) |
| `rosec-prompt` | No | Mostly | Wayland-specific structs need gating |
| `rosec-secret-service` | **Yes** | Linux-only | Core D-Bus interface |
| `rosecd` | **Yes** | Linux-only | Daemon, logind integration |
| `rosec` (CLI) | **Yes** | Linux-only | D-Bus client connection |
| `rosec-pam` | No | Linux-only | PAM is Linux-specific |

### Compilation blockers

These are specific locations where ungated platform-specific code prevents
compilation on non-Linux targets.  All are fixable with `cfg` gates and
fallbacks.

| File | Line(s) | Issue | Fix |
|------|---------|-------|-----|
| `rosec-core/src/config_edit.rs` | 297 | Ungated `use std::os::unix::fs::OpenOptionsExt` + `.mode(0o600)` | `#[cfg(unix)]` gate; non-unix: rely on parent dir permissions |
| `rosec-prompt/src/main.rs` | 310, 374-377 | Ungated `PlatformSpecific { application_id, override_redirect }` (Wayland/X11) | `#[cfg(target_os = "linux")]` gate; other platforms: omit or use platform equivalent |
| `rosecd/src/bootstrap.rs` | 31-41 | `prctl` gated `#[cfg(unix)]` but `prctl` is Linux-only | Change to `#[cfg(target_os = "linux")]` |
| `rosec/src/main.rs` | 625 | `read_hidden()` is `#[cfg(unix)]` with no `#[cfg(not(unix))]` fallback | Add Windows fallback using `windows-sys` console mode APIs |
| `rosec-secret-service/src/daemon/management.rs` | 715-726 | `libc::pipe2` — Linux/Unix-specific, no cfg gate | Gate behind `#[cfg(unix)]`; alternative: `std::os::unix::net::UnixStream::pair()` |
| `rosec-secret-service/src/daemon/management.rs` | 390-400 | `/proc/<pid>/exe` readlink — Linux-only | `#[cfg(target_os = "linux")]`; macOS: `proc_pidpath`; others: skip |
| `rosecd/src/main.rs` | 374-405 | `/proc/<pid>/comm` read — Linux-only | `#[cfg(target_os = "linux")]` |
| `rosec-ssh-agent/src/session.rs` | 4, 32, 35 | Ungated `UnixListener`, `PermissionsExt`, `from_mode(0o600)` | `#[cfg(unix)]` + `#[cfg(windows)]` named pipe alternative |

### D-Bus connection sites

All current D-Bus connections use `Connection::session()` or
`Connection::system()`.  These are the sites that would need abstraction for
any non-D-Bus transport:

| File | Line | Bus | Purpose |
|------|------|-----|---------|
| `rosecd/src/main.rs` | 88 | session | Main daemon connection |
| `rosecd/src/main.rs` | 458 | system | logind sleep/lock watcher |
| `rosec-secret-service/src/state.rs` | 2211, 2344 | session | ServiceState operations |
| `rosec-secret-service/src/item.rs` | 304 | session | SecretItem registration |
| `rosec/src/main.rs` | 313 | session | CLI client |
| `rosec-pam/src/main.rs` | 135 | session | PAM unlock module |

### Platform abstractions needed

#### Directory and path handling

Use the [`directories`](https://crates.io/crates/directories) crate (or
`dirs`) for cross-platform config/data/runtime paths:

| Purpose | Linux | macOS | Windows |
|---------|-------|-------|---------|
| Config | `~/.config/rosec` | `~/Library/Application Support/rosec` | `%APPDATA%\rosec` |
| Data | `~/.local/share/rosec` | `~/Library/Application Support/rosec` | `%LOCALAPPDATA%\rosec` |
| Runtime | `$XDG_RUNTIME_DIR/rosec` | `$TMPDIR/rosec-<uid>` | Named pipes / temp |

#### Process introspection (`/proc` abstraction)

Two call sites read from `/proc`: peer exe path (`/proc/<pid>/exe`) for
D-Bus caller verification, and peer comm (`/proc/<pid>/comm`) for logging.
These are Linux-specific:

- **macOS:** `proc_pidpath()` from `libproc` for exe path.
- **Windows/other:** Skip caller verification or use platform-specific
  alternatives.
- Wrap in a `rosec_core::platform::peer_exe_path(pid) -> Option<PathBuf>`
  abstraction.

#### File permissions

`OpenOptionsExt::mode(0o600)` and `PermissionsExt::from_mode(0o600)` are
Unix-only.  On non-Unix platforms:

- Rely on the parent directory's permissions (user-only access).
- On Windows, use ACLs via `windows-sys` or accept default user-only
  permissions on `%LOCALAPPDATA%` paths.

### SSH agent cross-platform support

#### Current state

`rosec-ssh-agent` uses `ssh-agent-lib` v0.5.1 which has first-class Windows
named pipe support via `NamedPipeListener`.

#### Linux (current)

```rust
listen(UnixListener::bind(socket_path)?, agent).await?;
```

Plus optional FUSE mount for per-key `.pub` files in `~/.ssh/rosec/`.

#### Windows / WSL2

```rust
listen(NamedPipeListener::bind(r"\\.\pipe\rosec-agent")?, agent).await?;
```

Windows OpenSSH reads `SSH_AUTH_SOCK` but also supports named pipes natively.
WSL2 can bridge to Windows named pipes via `socat` or `npiperelay`.

#### Cross-platform SSH key export

`rosec ssh export <dir>` writes `.pub` files to a directory on disk.  This
works on all platforms and is the primary non-agent path for making SSH
public keys available.  FUSE remains a Linux-only convenience feature, gated
behind `#[cfg(target_os = "linux")]` (or a cargo feature).

### Lock / sleep event sources

| Platform | Events | Mechanism |
|----------|--------|-----------|
| Linux | Sleep, screen lock, session end | logind D-Bus: `PrepareForSleep`, `Lock`, `SessionRemoved` (implemented) |
| macOS | Sleep, screen lock | `NSWorkspace.willSleepNotification`, `com.apple.screenIsLocked` via `objc2` |
| Windows (native) | Sleep, session lock | `WM_POWERBROADCAST`, `WTS_SESSION_LOCK` via `windows-sys` |
| WSL2 | None | VM freezes silently; no events available. Rely on idle timeouts. |

For macOS, the event watcher would use Objective-C bridge crates (`objc2`,
`block2`) to subscribe to `NSDistributedNotificationCenter`.  This is a
separate `rosec-events-macos` crate or a `#[cfg(target_os = "macos")]` module
within `rosecd`.

### Phased implementation roadmap

#### Phase 1: Compilation fixes (no new features)

Fix all `cfg` gate issues from the compilation blockers table above.  Goal:
`cargo check --target x86_64-apple-darwin` and
`cargo check --target x86_64-pc-windows-msvc` pass for the core crates
(`rosec-core`, `rosec-vault`, `rosec-wasm`, WASM guests).

Estimated scope: ~8 targeted `cfg` additions, no architectural changes.

#### Phase 2: Platform abstraction layer

- Introduce `rosec-core::platform` module with cross-platform helpers:
  `config_dir()`, `data_dir()`, `runtime_dir()`, `peer_exe_path(pid)`,
  `set_file_permissions(path, user_only: bool)`.
- Migrate existing hardcoded paths to use these helpers.
- Add `directories` crate dependency.

#### Phase 3: Private socket mode (embedded busd)

See "Headless / container mode" section above.  This is a Linux feature but
the architecture (embedded bus broker) could theoretically work on macOS too,
since busd and zbus are cross-platform.

#### Phase 4: SSH agent cross-platform

- Gate `UnixListener` path behind `#[cfg(unix)]`.
- Add `#[cfg(windows)]` path using `NamedPipeListener`.
- Gate FUSE behind `#[cfg(target_os = "linux")]` cargo feature.
- `rosec ssh export` works everywhere already (writes files to disk).

#### Phase 5: macOS polish

- macOS sleep/lock event watcher (Objective-C bridge).
- macOS keychain integration as a potential provider (read-only bridge to
  Keychain items).
- macOS-specific prompt backend (if `rosec-prompt`'s current approach
  doesn't work with macOS window management).
- Code signing / notarization for distribution.

### Status

- Compilation audit: **done** (blockers identified above)
- D-Bus dependency map: **done**
- Platform abstraction design: **done** (documented above)
- Phase 1 implementation: **not started**
- Phase 2 implementation: **not started**
- Phase 3 implementation: **not started** (depends on busd evaluation)
- Phase 4 implementation: **not started**
- Phase 5 implementation: **not started**
