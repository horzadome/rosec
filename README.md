# rosec

A [`org.freedesktop.secrets`](https://specifications.freedesktop.org/secret-service/) daemon for Linux. Any application that uses `libsecret` (GNOME Keyring, KWallet API) reads secrets from your configured providers transparently — no code changes required.

**Providers:** local encrypted vaults, Bitwarden Password Manager, Bitwarden Secrets Manager (more via WASM plugins)

**SSH agent:** SSH keys stored in any provider are exposed via a built-in SSH agent and optional FUSE mount with auto-generated `~/.ssh/config` snippets.

**PAM unlock:** Log in once; your vaults unlock automatically.

---

## Install

### From source

```bash
cargo build --release --workspace
sudo install -m755 target/release/rosecd              /usr/local/bin/
sudo install -m755 target/release/rosec               /usr/local/bin/
sudo install -m755 target/release/rosec-pam-unlock    /usr/lib/rosec/rosec-pam-unlock
sudo install -m755 target/release/rosec-prompt        /usr/local/bin/
```

### systemd + D-Bus activation (recommended)

```bash
cp contrib/systemd/rosecd.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now rosecd

mkdir -p ~/.local/share/dbus-1/services
cp contrib/dbus/org.freedesktop.secrets.service ~/.local/share/dbus-1/services/
cp contrib/dbus/org.gnome.keyring.service       ~/.local/share/dbus-1/services/
```

> If `gnome-keyring-daemon` keeps stealing `org.freedesktop.secrets`, see the [FAQ](#faq).

---

## Quick Start

### 1. Create a local vault

```bash
rosec provider add local
```

`rosecd` detects the new provider and prompts for a master password. Since the vault file doesn't exist yet, you'll be asked to confirm it:

```
Unlocking local  (Local Vault)

Master Password [Enter your master password]: ••••

This vault does not exist yet. It will be created with the password you provided.

Please confirm your password (it has not been verified yet):

Confirm Master Password: ••••
Provider 'local' authenticated.
```

### 2. Set up PAM auto-unlock

Add a second unlock password that matches your login password, so the vault unlocks automatically at login:

```bash
rosec provider add-password local --label pam
# Enter your login (PAM) password — NOT your vault master password
```

Then add one line to your PAM config (e.g. `/etc/pam.d/system-login`), after `pam_unix.so`:

```
auth  optional  pam_exec.so  expose_authtok quiet /usr/lib/rosec/rosec-pam-unlock
```

From your next login, the vault unlocks automatically. See [PAM auto-unlock](#pam-auto-unlock) for display manager setup and troubleshooting.

### 3. Use it

```bash
# Check status
rosec status

# Search and retrieve
rosec search type=login
rosec get name="My API Key"
```

---

## Providers

rosec supports multiple providers simultaneously. Each is independently locked and unlocked; all contribute items to a unified namespace on the D-Bus Secret Service.

| Kind | Description | Docs |
|---|---|---|
| `local` | Local encrypted vault (AES-256, PBKDF2, key wrapping) | [docs/providers/local.md](docs/providers/local.md) |
| `bitwarden` | Bitwarden Password Manager | [docs/providers/bitwarden.md](docs/providers/bitwarden.md) |
| `bitwarden-sm` | Bitwarden Secrets Manager | [docs/providers/bitwarden-sm.md](docs/providers/bitwarden-sm.md) |

### Managing providers

```bash
# List all providers and their lock state
rosec provider list

# Add a provider (prompts for config and credentials)
rosec provider add local
rosec provider add bitwarden
rosec provider add bitwarden-sm

# Authenticate / unlock a provider manually
rosec provider auth <id>

# Remove a provider
rosec provider remove <id>

# List available provider kinds (includes installed WASM plugins)
rosec provider kinds
```

### Local vault commands

```bash
# Add a second unlock password (e.g. for PAM, or a second machine)
rosec provider add-password <id> [--label <label>]

# List wrapping entries
rosec provider list-passwords <id>

# Remove a wrapping entry
rosec provider remove-password <id> <entry-id>

# Change the password for a wrapping entry
rosec provider change-password <id>

# Attach an existing vault file (e.g. shared via Syncthing)
rosec provider attach --path /path/to/file.vault [--id <id>]

# Detach from config without deleting the file
rosec provider detach <id>
```

---

## PAM auto-unlock

`rosec-pam-unlock` is a `pam_exec` hook. At login, PAM passes your login password to the helper via stdin (`expose_authtok`). The helper sends it to `rosecd` via Unix pipe fd-passing (SCM_RIGHTS) — it never appears on the D-Bus wire. Any vault with a matching wrapping entry unlocks silently. Vaults without a match are skipped; login is never blocked.

### Setup

**1.** Install the binary (see [Install](#install)).

**2.** If your login password differs from your vault master password, add it as a wrapping entry:

```bash
rosec provider add-password <vault-id> --label pam
```

Enter your **login password** when prompted. If it matches your vault master password, skip this step.

**3.** Add to your PAM config after `pam_unix.so`:

```
# /etc/pam.d/system-login  (or login, sddm, gdm-password, lightdm, etc.)
auth  optional  pam_exec.so  expose_authtok quiet /usr/lib/rosec/rosec-pam-unlock
```

**4.** If you install to a non-standard path, configure the allowed helper paths:

```toml
# ~/.config/rosec/config.toml
[service]
pam_helper_paths = ["/home/you/rosec/target/debug/rosec-pam-unlock"]
```

### Security

- Password sent via Unix pipe fd-passing — never a D-Bus string argument
- `AuthBackendFromPipe` only accepts calls from paths listed in `pam_helper_paths` (verified via `/proc/<pid>/exe`)
- Password buffers zeroized after use in both helper and daemon
- Configured `optional` — any failure exits with `PAM_IGNORE`, never blocking login

---

## SSH agent

SSH keys stored in any provider are loaded automatically:

```bash
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/rosec/agent.sock"
ssh-add -l
```

Tag items with a `custom.ssh_host` attribute to generate `~/.ssh/config` snippets automatically:

```
Include /run/user/1000/rosec/ssh/config.d/*
```

See [docs/ssh-agent.md](docs/ssh-agent.md) for full details.

---

## Configuration

`~/.config/rosec/config.toml`

```toml
[service]
refresh_interval_secs = 60

[autolock]
on_logout        = true
on_session_lock  = false
# idle_timeout_minutes = 15

[prompt]
backend = "builtin"   # or path to rosec-prompt binary

[[provider]]
id   = "local"
kind = "local"

[[provider]]
id   = "bitwarden"
kind = "bitwarden"

[provider.options]
email = "user@example.com"
```

Full reference: [docs/configuration.md](docs/configuration.md)

---

## FAQ

**`gnome-keyring-daemon` keeps stealing `org.freedesktop.secrets`**

```bash
systemctl --user mask gnome-keyring-daemon.service gnome-keyring-daemon.socket
```

Then override D-Bus activation using the contrib files (see [Install](#install)). User-level files in `~/.local/share/dbus-1/services/` take precedence over system files per the D-Bus spec.

**How do I update my Bitwarden master password?**

The master password is never stored. After changing it in the Bitwarden web vault, run `rosec provider auth <id>` and enter the new password.

**How do I rotate a Bitwarden Secrets Manager access token?**

Run `rosec provider auth <id> --force` and paste the new token when prompted.

**SSH agent fails with "Transport endpoint is not connected"**

`rosecd` cleans up stale FUSE mounts on startup — restart it. If that fails:

```bash
fusermount3 -uz "$XDG_RUNTIME_DIR/rosec/ssh"
```

---

## Development

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all
```

A `Justfile` is provided (`just build`, `just test`, `just lint`, `just release-patch`, etc.).

---

## Prior art

- [`secretsd`](https://github.com/grawity/secretsd) — Generic Secret Service backend
- [`oo7`](https://github.com/bilelmoussaoui/oo7) — Pure Rust Secret Service client
- [`pass-secret-service`](https://github.com/mdellweg/pass_secret_service) — Secret Service backed by pass

## License

MIT
