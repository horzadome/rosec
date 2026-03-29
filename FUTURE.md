# rosec — Future Work & Integration Notes

Design notes, planned features, and integration guidance.

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

- **Not started** — requested in [#6](https://github.com/jmylchreest/rosec/issues/6)
  (Flatpak Evolution cannot authenticate).

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
