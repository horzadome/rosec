use std::collections::HashMap;
use std::io::{self, BufRead};
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use anyhow::{Result, bail};
use zbus::Connection;
use zeroize::Zeroizing;
use zvariant::{OwnedObjectPath, OwnedValue};

use rosec_core::config::Config;
use rosec_core::config_edit;

#[tokio::main]
async fn main() -> Result<()> {
    // Reset SIGPIPE to default so piping output to `head` etc. exits cleanly
    // instead of panicking with "broken pipe".
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");

    match cmd {
        // provider / providers are full aliases for the same subcommand tree
        "provider" | "providers" => cmd_provider(&args[1..]).await,
        "config" => cmd_config(&args[1..]),
        "status" => cmd_status().await,
        "sync" | "refresh" => cmd_sync().await,
        "search" => cmd_search(&args[1..]).await,
        "get" => cmd_get(&args[1..]).await,
        "inspect" => cmd_inspect(&args[1..]).await,
        "lock" => cmd_lock().await,
        "unlock" => cmd_unlock().await,
        "enable" => cmd_enable(&args[1..]),
        "disable" => cmd_disable(&args[1..]),
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        other => {
            print_help();
            bail!("unknown command: {other}");
        }
    }
}

fn print_help() {
    println!(
        "\
rosec - read-only secret service CLI

USAGE:
    rosec <command> [args...]

COMMANDS:
    provider <subcommand>               Manage providers (alias: providers)
      list                              List all configured providers and their state
      add <kind> [options]              Add a provider to the config file
      remove <id>                       Remove a provider (local vaults: offers to delete the file)
      attach --path <file> [--id <id>]  Attach an existing vault file to the config
      detach <id>                       Remove provider from config (file stays on disk)
      add-password <id>                 Add a new unlock password to a local vault provider
      remove-password <id> <entry-id>   Remove a password from a local vault provider
      list-passwords <id>               List unlock passwords for a local vault provider
      change-password <id>              Change the unlock password for a provider
      auth <id>                         Authenticate/unlock a provider
      kinds                             List available provider kinds

    config <subcommand>                 Read or modify config.toml
      show                              Print the current effective configuration
      get <key>                         Print the value of one setting (e.g. autolock.idle_timeout_minutes)
      set <key> <value>                 Update a setting in config.toml (daemon hot-reloads automatically)

    status                              Show daemon status
    sync                                Sync providers with remote servers (alias: refresh)
    search [-s] [--format=<fmt>] [--show-path] [key=value]...
                                        Search items by attributes (no args = list all)
    get <id>                            Print the secret value only (pipeable)
    inspect <id>                        Show full item detail: label, attributes, secret
    lock                                Lock all providers
    unlock                              Unlock (triggers GUI/TTY prompt)
    enable [flags]                      Activate rosec as the Secret Service provider
    disable [flags]                     Deactivate rosec (remove D-Bus overrides)
    help                                Show this help

PROVIDER KINDS:
    local                               Local encrypted vault (file on disk)
    bitwarden                           Bitwarden Password Manager
    bitwarden-sm                        Bitwarden Secrets Manager

OUTPUT FORMATS (--format):
    table                               Aligned columns: TYPE | NAME | USERNAME | URI | ID  [default]
    kv                                  Key=value pairs, one attribute per line per item
    json                                JSON array of objects (always includes full path)

FLAGS:
    --show-path                         Also print the full D-Bus object path for each item
                                        (useful when calling GetSecret directly via D-Bus/libsecret)

SEARCH FILTERS:
    Pass one or more key=value pairs to filter by public attributes:
      type=login                        Only login items
      username=alice                    Items with username 'alice'
      type=login username=alice         Combine filters (AND)
      uri=github.com                    Items with a matching URI attribute

    Common attribute names: type, username, uri, folder, name

NOTES:
    If a provider is locked when running 'search' or 'get', you will be
    prompted for credentials automatically and the operation retried.

    The 16-char hex ID shown in 'search' output is unique and stable.
    Pass it directly to 'rosec get'.

EXAMPLES:
    rosec provider add local                                # create a new local vault (auto ID + path)
    rosec provider add local --id work --path ~/vaults/work.vault
    rosec provider attach --path /mnt/shared/team.vault     # attach an existing vault file
    rosec provider list                                     # show all providers
    rosec provider auth personal                            # unlock a provider
    rosec provider add-password personal                    # add a second unlock password
    rosec provider remove-password personal <entry-id>      # remove a password
    rosec provider detach work                              # remove from config (file stays)
    rosec provider remove old-vault                         # remove provider (prompts to delete vault file)

    rosec provider add bitwarden email=you@example.com      # ID auto-generated from email
    rosec provider add bitwarden-sm organization_id=uuid
    rosec provider add bitwarden --id work email=work@corp.com region=eu
    rosec provider auth bitwarden-3f8a1c2d
    rosec provider remove bitwarden-3f8a1c2d
    rosec providers list       # 'providers' is a full alias for 'provider'

    rosec search                                            # list all items
    rosec search type=login                                 # only login items
    rosec search username=alice                             # search by username
    rosec search type=login username=alice                  # combine filters
    rosec search --format=json type=login                   # JSON output (includes path)
    rosec search --format=kv uri=github.com                 # key=value output
    rosec search --show-path type=login                     # table with D-Bus path column
    rosec search -s type=login                             # sync/unlock, then search

    rosec get a1b2c3d4e5f60718                              # print secret value only (pipeable)
    rosec get a1b2c3d4e5f60718 | xclip -sel clip            # copy secret to clipboard

    rosec inspect a1b2c3d4e5f60718                          # full label + attributes + secret
    rosec inspect -s a1b2c3d4e5f60718                       # sync/unlock then inspect
    rosec inspect -s --all-attrs a1b2c3d4e5f60718           # include sensitive attrs (password, totp…)
    rosec inspect --all-attrs --format=json a1b2c3d4e5f60718 # JSON with all attrs
    rosec inspect /org/freedesktop/secrets/collection/default/… # full D-Bus path

    rosec enable                                            # activate rosec as Secret Service
    rosec enable --no-mask                                  # don't mask gnome-keyring
    rosec enable --no-systemd                               # skip systemd enable/start
    rosec disable                                           # deactivate, restore gnome-keyring"
    );
}

fn print_search_help() {
    println!(
        "\
rosec search - search vault items by attribute

USAGE:
    rosec search [flags] [key=value]...

FLAGS:
    -s, --sync          Sync providers before searching; also unlocks if needed
    --format=<fmt>      Output format: table (default), kv, json
    --show-path         Include the full D-Bus object path in output
    --help, -h          Show this help

SEARCH FILTERS:
    Pass one or more key=value pairs to filter by public attributes (AND semantics).
    Glob metacharacters (*, ?, [...]) are accepted.
    The special key 'name' matches the item label.

EXAMPLES:
    rosec search                                    list all items
    rosec search -s                                 sync first, then list all
    rosec search type=login                         only login items
    rosec search username=alice                     items with username 'alice'
    rosec search rosec:provider=personal            items from 'personal' provider
    rosec search type=login username=alice          combine filters
    rosec search name=\"GitHub*\"                     glob on item name
    rosec search --format=json type=login           JSON output
    rosec search --format=kv uri=github.com         key=value output
    rosec search --show-path type=login             table with D-Bus path column"
    );
}

fn print_inspect_help() {
    println!(
        "\
rosec inspect - show full item detail

USAGE:
    rosec inspect [flags] <id>

ARGUMENTS:
    <id>                16-char hex item ID or full D-Bus object path

FLAGS:
    -a, --all-attrs     Also fetch and display sensitive attributes (password, totp,
                        notes, card number, custom fields, etc.)
    -s, --sync          Sync providers before inspecting; also unlocks if the item is
                        not yet in the cache (e.g. after a fresh daemon start)
    --format=<fmt>      Output format: human (default), kv, json
    --help, -h          Show this help

OUTPUT FORMATS:
    human               Labelled sections with public and (if --all-attrs) sensitive attrs
    kv                  Flat key=value pairs — one per line, pipe-friendly
    json                JSON object with 'attributes', 'sensitive_attributes', and 'secret'

EXAMPLES:
    rosec inspect a1b2c3d4e5f60718
    rosec inspect -s a1b2c3d4e5f60718
    rosec inspect -s --all-attrs a1b2c3d4e5f60718
    rosec inspect --all-attrs --format=kv a1b2c3d4e5f60718
    rosec inspect --all-attrs --format=json a1b2c3d4e5f60718"
    );
}

fn print_provider_help() {
    println!(
        "\
rosec provider - manage providers

USAGE:
    rosec provider <subcommand> [args...]
    rosec providers <subcommand> [args...]   (alias)

SUBCOMMANDS:
    list                              List all providers and their lock state
    kinds                             List available provider kinds
    auth <id> [--force]               Authenticate/unlock a provider
    add <kind> [options]              Add a provider to config.toml
    remove <id>                       Remove a provider (local vaults: offers to delete the file)
    enable <id>                       Enable a disabled provider
    disable <id>                      Temporarily disable a provider
    attach --path <file> [--id <id>]  Attach an existing vault file to the config
    detach <id>                       Remove provider from config (file stays on disk)
    add-password <id> [--label <l>]   Add a new unlock password to a local vault provider
    remove-password <id> <entry-id>   Remove a password from a local vault provider
    list-passwords <id>               List unlock passwords for a local vault provider
    change-password <id>              Change the unlock password for a provider

NOTE:
    Device registration (Bitwarden) and first-time token setup (SM) are handled
    automatically during 'auth' when the provider requires them.  Use --force
    to re-run registration even when stored credentials already exist (e.g. to
    replace a rotated SM access token or re-register a Bitwarden device).

OPTIONS for 'add':
    --id <id>                 Override auto-generated ID (default: derived from email/org or path)
    --path <path>             Path to the vault file (local vaults only)
    --collection <name>       Collection label for grouping items
    key=value ...             Provider options (email, region, base_url, etc.)
    --config <path>           Config file to edit (default: ~/.config/rosec/config.toml)"
    );
}

fn cmd_provider_kinds() {
    println!("Available provider kinds:\n");
    println!("  local");
    println!("    A local encrypted vault file on disk.");
    println!("    Options: --id <id>, --path <path>, --collection <name>");
    println!();
    for kind in config_edit::KNOWN_KINDS {
        // "local" is already printed above with its custom description.
        if *kind == "local" {
            continue;
        }
        let required = config_edit::required_options_for_kind(kind);
        let optional = config_edit::optional_options_for_kind(kind);
        println!("  {kind}");
        if !required.is_empty() {
            println!("    Required:");
            for (key, desc) in required {
                println!("      {key:<20}  {desc}");
            }
        }
        if !optional.is_empty() {
            println!("    Optional:");
            for (key, desc) in optional {
                println!("      {key:<20}  {desc}");
            }
        }
        println!();
    }

    // List dynamically discovered WASM plugin kinds.
    let registry = rosec_wasm::discovery::scan_plugins();
    for kind in registry.kinds() {
        let plugin = registry
            .get(kind)
            .expect("kind from registry.kinds() must exist");
        println!("  {kind}");
        println!("    {}", plugin.manifest.description);
        if !plugin.manifest.required_options.is_empty() {
            println!("    Required:");
            for opt in &plugin.manifest.required_options {
                println!("      {:<20}  {}", opt.key, opt.description);
            }
        }
        if !plugin.manifest.optional_options.is_empty() {
            println!("    Optional:");
            for opt in &plugin.manifest.optional_options {
                println!("      {:<20}  {}", opt.key, opt.description);
            }
        }
        println!();
    }
}

async fn conn() -> Result<Connection> {
    Ok(Connection::session().await?)
}

/// Poll rosecd's `ProviderList` until `id` appears (max 3 s, 200 ms intervals).
///
/// Returns `Some(proxy)` if the daemon is running and the provider appeared,
/// `None` if the daemon isn't running or the provider didn't appear in time.
async fn wait_for_daemon_reload(id: &str) -> Option<zbus::Proxy<'static>> {
    let conn = conn().await.ok()?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await
    .ok()?;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        if let Ok(entries) = proxy
            .call::<_, _, Vec<(String, String, String, bool)>>("ProviderList", &())
            .await
            && entries.iter().any(|(bid, ..)| bid == id)
        {
            return Some(proxy);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

/// Generate a default password label: `user@hostname`.
fn default_password_label() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "unknown".into());

    let host = {
        let mut buf = [0u8; 256];
        // SAFETY: gethostname writes into a fixed-size buffer we own.
        let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
        if rc == 0 {
            let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            String::from_utf8_lossy(&buf[..len]).into_owned()
        } else {
            "localhost".into()
        }
    };

    format!("{user}@{host}")
}

/// Resolve the config file path from `--config <path>` flag or XDG default.
fn config_path() -> PathBuf {
    let args: Vec<String> = std::env::args().collect();
    for i in 0..args.len().saturating_sub(1) {
        if args[i] == "--config" || args[i] == "-c" {
            return PathBuf::from(&args[i + 1]);
        }
        if let Some(p) = args[i].strip_prefix("--config=") {
            return PathBuf::from(p);
        }
    }
    default_config_path()
}

fn default_config_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("rosec").join("config.toml")
}

fn load_config() -> Config {
    let path = config_path();
    if !path.exists() {
        return Config::default();
    }
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| toml::from_str(&s).ok())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Prompt helpers (local config-value collection only — not credentials)
// ---------------------------------------------------------------------------
//
// These functions are used by `cmd_provider_add` to collect non-secret
// configuration values (email address, region, base_url, etc.) that go into
// config.toml.  Credential prompting (passwords, tokens) is handled entirely
// inside `rosecd` via `UnlockWithTty` / `AuthProviderWithTty` — the TTY fd is
// passed via D-Bus fd-passing so credentials never appear in any D-Bus message.

// ---------------------------------------------------------------------------
// Lazy-unlock: detect "locked::<provider_id>" D-Bus errors and prompt
// ---------------------------------------------------------------------------

/// Extract a `"locked::<provider_id>"` provider ID from a `zbus::Error`, if present.
///
/// The daemon returns `org.freedesktop.DBus.Error.Failed("locked::<id>")` when
/// a provider needs interactive authentication.  This helper parses that sentinel
/// and returns `Some(provider_id)` or `None`.
fn extract_locked_provider(err: &zbus::Error) -> Option<String> {
    if let zbus::Error::MethodError(_, Some(detail), _) = err {
        let msg = detail.as_str();
        if let Some(id) = msg.strip_prefix("locked::") {
            return Some(id.to_string());
        }
    }
    None
}

/// Attempt to interactively unlock a provider after receiving a `"locked::<id>"`
/// D-Bus error.
///
/// This function implements the Secret Service spec Prompt flow:
///   1. Call `Service.Unlock([collection])` — the daemon allocates a Prompt object.
///   2. Subscribe to `Prompt.Completed` on that path.
///   3. Call `Prompt.Prompt("")` to tell the daemon to show the credential dialog.
///   4. Await the `Completed` signal; race against Ctrl+C.
///   5. On Ctrl+C: call `org.rosec.Daemon.CancelPrompt(prompt_path)` then exit.
///
/// Credentials never cross D-Bus — the daemon handles everything internally.
///
/// Returns `Ok(true)` if the provider was successfully unlocked (caller should
/// retry the original operation).  Returns `Ok(false)` if the error was not a
/// locked sentinel (caller should propagate the original error).
async fn try_lazy_unlock(conn: &Connection, err: &zbus::Error) -> Result<bool> {
    // Only trigger for the locked sentinel — not for generic errors.
    if extract_locked_provider(err).is_none() {
        return Ok(false);
    }

    trigger_unlock(conn).await?;
    Ok(true)
}

/// Trigger the spec-compliant Unlock → Prompt → Completed flow.
///
/// Calls `Service.Unlock([default_collection])`.  If a prompt is required,
/// subscribes to `Prompt.Completed`, fires `Prompt.Prompt("")`, and awaits the
/// signal.  On success, triggers a cache refresh so subsequent operations see
/// the newly-unlocked items.
///
/// Credentials never cross D-Bus — the daemon handles everything internally.
async fn trigger_unlock(conn: &Connection) -> Result<()> {
    use futures_util::StreamExt as _;

    // Build a Secret Service proxy for Unlock().
    let service_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await?;

    // Call Unlock([default_collection]).  Returns (unlocked_list, prompt_path).
    // prompt_path == "/" means everything was already unlocked (auto-unlock providers).
    let collection_path =
        OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/default".to_string())?;
    let (_, prompt_path): (Vec<OwnedObjectPath>, OwnedObjectPath) = service_proxy
        .call("Unlock", &(vec![collection_path],))
        .await?;
    let prompt_path = prompt_path.to_string();

    if prompt_path == "/" {
        // Already unlocked (auto-unlock providers recovered silently).
        return Ok(());
    }

    // Build a proxy on the prompt object so we can subscribe to Completed.
    let prompt_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        prompt_path.as_str(),
        "org.freedesktop.Secret.Prompt",
    )
    .await?;

    // Subscribe to the Completed signal *before* calling Prompt() to avoid
    // a race where Completed fires before we start listening.
    let mut completed_stream = prompt_proxy.receive_signal("Completed").await?;

    // Tell the daemon to display the credential dialog.
    let _: () = prompt_proxy.call("Prompt", &("",)).await?;

    // Await Completed or Ctrl+C.
    let dismissed = tokio::select! {
        msg = completed_stream.next() => {
            match msg {
                None => {
                    // Stream ended without a signal — treat as cancelled.
                    true
                }
                Some(message) => {
                    // Completed signal body: (dismissed: bool, result: Variant)
                    // We only need the first field.
                    let body = message.body();
                    match body.deserialize::<(bool, zvariant::OwnedValue)>() {
                        Ok((d, _)) => d,
                        Err(_) => true, // parse error → treat as dismissed
                    }
                }
            }
        }
        _ = tokio::signal::ctrl_c() => {
            // User pressed Ctrl+C — cancel the prompt subprocess and exit.
            let daemon_proxy = zbus::Proxy::new(
                conn,
                "org.freedesktop.secrets",
                "/org/rosec/Daemon",
                "org.rosec.Daemon",
            )
            .await?;
            let cancel_path = OwnedObjectPath::try_from(prompt_path.clone())
                .unwrap_or_else(|_| OwnedObjectPath::try_from("/".to_string()).unwrap());
            let _: Result<bool, _> = daemon_proxy.call("CancelPrompt", &(&cancel_path,)).await;
            bail!("cancelled by user");
        }
    };

    if dismissed {
        bail!("unlock cancelled or failed");
    }

    // Unlock succeeded.  Trigger a cache sync so the retry finds items.
    // Use the daemon proxy for SyncProvider; need to look up which provider unlocked.
    // Use "all" shorthand: call Refresh which rebuilds the cache from in-memory state.
    let daemon_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;
    let _: Result<u32, _> = daemon_proxy.call("Refresh", &()).await;

    Ok(())
}

// ---------------------------------------------------------------------------
// Secure field collection (used locally for config-value prompts in `add`)
// ---------------------------------------------------------------------------

/// Open `/dev/tty` and return it as a `zvariant::OwnedFd` for D-Bus fd-passing.
///
/// The returned `OwnedFd` can be passed directly to `UnlockWithTty` /
/// `AuthProviderWithTty`.  `dbus-monitor` sees only the fd number, never the
/// terminal contents.
fn open_tty_owned_fd() -> Result<zvariant::OwnedFd> {
    use std::os::unix::io::{FromRawFd as _, IntoRawFd as _};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| anyhow::anyhow!("cannot open /dev/tty: {e}"))?;
    let raw = file.into_raw_fd();
    // SAFETY: raw is a freshly-opened, valid, owned fd.
    let std_owned: std::os::fd::OwnedFd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
    Ok(zvariant::OwnedFd::from(std_owned))
}

/// Write a password to the write end of a pipe and return the read end as an
/// `OwnedFd` suitable for D-Bus fd-passing.
///
/// The write end is closed after the password is written so the daemon sees
/// EOF when it reads.  The password bytes are never visible in any D-Bus
/// message payload — only the fd number travels over the bus.
fn password_to_pipe_fd(password: &[u8]) -> Result<zvariant::OwnedFd> {
    use std::io::Write as _;
    use std::os::unix::io::FromRawFd as _;

    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: pipe() writes two valid fds into the array.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        bail!("pipe() failed: {}", std::io::Error::last_os_error());
    }
    let read_fd = fds[0];
    let write_fd = fds[1];

    {
        // SAFETY: write_fd is a valid fd from pipe() above.
        let mut write_file: std::fs::File = unsafe { std::fs::File::from_raw_fd(write_fd) };
        write_file.write_all(password)?;
        // write_file dropped here → write end closed → daemon sees EOF on read
    }

    // SAFETY: read_fd is a valid fd from pipe() above.
    let std_owned: std::os::fd::OwnedFd = unsafe { std::os::fd::OwnedFd::from_raw_fd(read_fd) };
    Ok(zvariant::OwnedFd::from(std_owned))
}

/// Read one line from `fd` with terminal echo disabled.
///
/// Flushes any stale input (via `TCSAFLUSH`), saves the current `termios`,
/// clears `ECHO`/`ECHONL`, reads a line, then restores the original settings.
/// The returned string has the trailing newline stripped.
///
/// A `TermiosGuard` ensures the original terminal settings are restored even
/// if the read is interrupted, the thread panics, or the function exits early
/// via `?`.  Additionally, the original termios is registered in a
/// process-global so that a SIGINT handler can restore it if the process is
/// killed while echo is disabled.
///
/// The read buffer is `Zeroizing<Vec<u8>>` so the raw bytes are scrubbed on
/// drop — no plain copy of the secret ever lingers on the heap.
#[cfg(unix)]
fn read_hidden(fd: std::os::unix::io::RawFd) -> io::Result<Zeroizing<String>> {
    use std::os::unix::io::FromRawFd as _;

    /// RAII guard that restores the original `termios` on drop.
    struct TermiosGuard {
        fd: std::os::unix::io::RawFd,
        orig: libc::termios,
    }

    impl Drop for TermiosGuard {
        fn drop(&mut self) {
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSANOW, &self.orig);
            }
            // Clear the global signal-handler backup since we've restored.
            tty_signal::clear();
        }
    }

    // Save current termios and install the RAII guard immediately.
    // SAFETY: fd is valid (we just opened it) and term is properly initialised.
    let guard = unsafe {
        let mut term = std::mem::MaybeUninit::<libc::termios>::uninit();
        if libc::tcgetattr(fd, term.as_mut_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        TermiosGuard {
            fd,
            orig: term.assume_init(),
        }
    };

    // Register the original termios in a process-global so the SIGINT handler
    // can restore it if the process is killed while echo is off.
    tty_signal::install(fd, &guard.orig);

    let mut noecho = guard.orig;
    // Disable echo and the newline-echo-when-echo-off flag.
    noecho.c_lflag &= !(libc::ECHO as libc::tcflag_t);
    noecho.c_lflag &= !(libc::ECHONL as libc::tcflag_t);

    // TCSAFLUSH: apply new settings AND discard any unread input in the
    // kernel tty buffer (e.g. stale keypresses from between prompts).
    unsafe {
        if libc::tcsetattr(fd, libc::TCSAFLUSH, &noecho) != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    // Read one line into a Zeroizing buffer so the raw bytes are scrubbed on
    // drop regardless of what happens next.
    let mut buf = Zeroizing::new(Vec::<u8>::new());
    let result = {
        // SAFETY: we borrow the fd for reading; ManuallyDrop prevents double-close
        // since the original `tty: File` in the caller still owns the fd.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let file = std::mem::ManuallyDrop::new(file);
        let mut reader = io::BufReader::new(&*file);
        reader.read_until(b'\n', &mut buf)
    };

    // The guard restores termios on drop (runs when this function returns),
    // but we also restore explicitly here so the newline write below sees
    // the original settings.
    drop(guard);

    // Print a newline since ECHO is off (the user's Enter was not echoed).
    let _ = unsafe { libc::write(fd, b"\n".as_ptr().cast(), 1) };

    result?;

    // Strip trailing CR/LF and convert to a Zeroizing<String>.  The Vec is
    // zeroized on drop; the String is wrapped in Zeroizing immediately.
    while buf.last() == Some(&b'\n') || buf.last() == Some(&b'\r') {
        buf.pop();
    }
    let s = std::str::from_utf8(&buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        .to_string();
    Ok(Zeroizing::new(s))
}

/// Process-global SIGINT handler that restores terminal settings.
///
/// When `read_hidden` disables echo, it registers the original termios here.
/// If SIGINT arrives before the guard drops, the handler restores the terminal
/// then re-raises SIGINT with the default disposition so the process exits
/// with the correct signal status.
#[cfg(unix)]
mod tty_signal {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicI32, Ordering};

    /// The fd on which echo was disabled, or -1 if none.
    static TTY_FD: AtomicI32 = AtomicI32::new(-1);

    /// Original termios to restore.  Protected by a Mutex, but the signal
    /// handler only reads it via a `try_lock` (non-blocking) to avoid
    /// deadlock.  Worst-case the handler can't acquire the lock and skips
    /// the restore — the process is dying anyway.
    static ORIG_TERMIOS: Mutex<Option<libc::termios>> = Mutex::new(None);

    /// One-shot flag for installing the signal handler.
    static INSTALLED: std::sync::Once = std::sync::Once::new();

    /// Register the original termios and install the SIGINT handler (once).
    pub(super) fn install(fd: std::os::unix::io::RawFd, orig: &libc::termios) {
        TTY_FD.store(fd, Ordering::Release);
        if let Ok(mut guard) = ORIG_TERMIOS.lock() {
            *guard = Some(*orig);
        }
        INSTALLED.call_once(|| unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = sigint_handler as *const () as libc::sighandler_t;
            sa.sa_flags = libc::SA_RESETHAND; // one-shot: auto-restores default
            libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        });
    }

    /// Clear the saved state (called by `TermiosGuard::drop` after normal restore).
    pub(super) fn clear() {
        TTY_FD.store(-1, Ordering::Release);
        if let Ok(mut guard) = ORIG_TERMIOS.lock() {
            *guard = None;
        }
    }

    /// Async-signal-safe(ish) SIGINT handler.
    ///
    /// Restores the original termios using `tcsetattr` (async-signal-safe per
    /// POSIX) then re-raises SIGINT with the default handler.  The `SA_RESETHAND`
    /// flag ensures this handler runs at most once.
    extern "C" fn sigint_handler(_sig: libc::c_int) {
        let fd = TTY_FD.load(Ordering::Acquire);
        if fd >= 0 {
            // try_lock avoids deadlock if the signal arrived while the main
            // thread holds the mutex.  If it fails, we skip — the process is
            // about to die.
            if let Ok(guard) = ORIG_TERMIOS.try_lock()
                && let Some(ref orig) = *guard
            {
                unsafe {
                    libc::tcsetattr(fd, libc::TCSANOW, orig);
                    // Write a newline so the shell prompt starts on a clean line.
                    libc::write(fd, b"\n".as_ptr().cast(), 1);
                }
            }
        }
        // Re-raise SIGINT with default handler (SA_RESETHAND already cleared us).
        unsafe {
            libc::raise(libc::SIGINT);
        }
    }
}

/// Collect a single field value from the terminal.
///
/// Opens `/dev/tty` once per call so that both the prompt write and the input
/// read use the same file descriptor.  For hidden fields (`password`/`secret`)
/// echo is suppressed via `read_hidden`, which calls `tcsetattr` on that same
/// fd.  For visible fields (`text`) the prompt and read also go through the
/// same fd, avoiding any stdin/tty split-brain.
///
/// All blocking I/O runs on a dedicated `spawn_blocking` thread so the tokio
/// executor is not stalled.  Returns `Zeroizing<String>` so the value is
/// scrubbed on drop.
async fn prompt_field(label: &str, placeholder: &str, kind: &str) -> Result<Zeroizing<String>> {
    let prompt_str = if placeholder.is_empty() {
        format!("{label}: ")
    } else {
        format!("{label} [{placeholder}]: ")
    };

    let kind = kind.to_string();
    let value = tokio::task::spawn_blocking(move || -> Result<Zeroizing<String>> {
        use std::io::Write as _;
        use std::os::unix::io::AsRawFd as _;

        // Open /dev/tty once for this prompt — all I/O goes through this fd.
        let tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")?;
        let fd = tty.as_raw_fd();

        match kind.as_str() {
            "password" | "secret" => {
                // Write the prompt to our tty fd, then suppress echo and read
                // from the same fd.  We implement the echo toggle directly so
                // that prompt write and input read share the same file object
                // (and therefore the same kernel file-description / termios).
                let mut tty_write = &tty;
                write!(tty_write, "{prompt_str}")?;
                tty_write.flush()?;

                // Disable echo via tcsetattr on this fd.
                Ok(read_hidden(fd)?)
            }
            _ => {
                let mut writer = &tty;
                write!(writer, "{prompt_str}")?;
                writer.flush()?;
                let mut line = String::new();
                io::BufReader::new(&tty).read_line(&mut line)?;
                Ok(Zeroizing::new(
                    line.trim_end_matches('\n')
                        .trim_end_matches('\r')
                        .to_string(),
                ))
            }
        }
    })
    .await
    .map_err(|e| anyhow::anyhow!("prompt task panicked: {e}"))??;

    Ok(value)
}

// ---------------------------------------------------------------------------
// provider / providers subcommand tree
// ---------------------------------------------------------------------------

async fn cmd_provider(args: &[String]) -> Result<()> {
    let sub = args.first().map(String::as_str).unwrap_or("list");
    match sub {
        "list" | "ls" => cmd_provider_list().await,
        "auth" => cmd_provider_auth(&args[1..]).await,
        "add" => cmd_provider_add(&args[1..]).await,
        "remove" | "rm" => cmd_provider_remove(&args[1..]).await,
        "enable" => cmd_provider_set_enabled(&args[1..], true).await,
        "disable" => cmd_provider_set_enabled(&args[1..], false).await,
        "attach" => cmd_provider_attach(&args[1..]).await,
        "detach" => cmd_provider_detach(&args[1..]).await,
        "add-password" => cmd_provider_add_password(&args[1..]).await,
        "remove-password" => cmd_provider_remove_password(&args[1..]).await,
        "list-passwords" => cmd_provider_list_passwords(&args[1..]).await,
        "change-password" => cmd_provider_change_password(&args[1..]).await,
        "kinds" => {
            cmd_provider_kinds();
            Ok(())
        }
        "help" | "--help" | "-h" => {
            print_provider_help();
            Ok(())
        }
        other => {
            print_provider_help();
            bail!("unknown provider subcommand: {other}");
        }
    }
}

/// `rosec provider list` — show all configured providers with lock state.
async fn cmd_provider_list() -> Result<()> {
    // Load config to detect disabled providers.
    let cfg = load_config();
    if cfg.provider.is_empty() {
        println!("No providers configured. Run `rosec provider add <kind>` to add one.");
        return Ok(());
    }

    // Collect disabled entries from config (they won't appear in D-Bus).
    let disabled: Vec<&rosec_core::config::ProviderEntry> =
        cfg.provider.iter().filter(|p| !p.enabled).collect();

    // Try D-Bus first for live state.
    if let Ok(conn) = conn().await
        && let Ok(proxy) = zbus::Proxy::new(
            &conn,
            "org.freedesktop.secrets",
            "/org/rosec/Daemon",
            "org.rosec.Daemon",
        )
        .await
        && let Ok(entries) = proxy
            .call::<_, _, Vec<(String, String, String, bool)>>("ProviderList", &())
            .await
    {
        if entries.is_empty() && disabled.is_empty() {
            println!("No providers configured. Run `rosec provider add <kind>` to add one.");
            return Ok(());
        }

        let all_ids: Vec<&str> = entries
            .iter()
            .map(|(id, ..)| id.as_str())
            .chain(disabled.iter().map(|p| p.id.as_str()))
            .collect();
        let all_names: Vec<&str> = entries
            .iter()
            .map(|(_, n, ..)| n.as_str())
            .chain(disabled.iter().map(|p| p.id.as_str()))
            .collect();
        let all_kinds: Vec<&str> = entries
            .iter()
            .map(|(_, _, k, _)| k.as_str())
            .chain(disabled.iter().map(|p| p.kind.as_str()))
            .collect();

        let id_w = all_ids.iter().map(|s| s.len()).max().unwrap_or(2).max(2);
        let name_w = all_names.iter().map(|s| s.len()).max().unwrap_or(4).max(4);
        let kind_w = all_kinds.iter().map(|s| s.len()).max().unwrap_or(4).max(4);

        println!(
            "{:<id_w$}  {:<name_w$}  {:<kind_w$}  STATE",
            "ID", "NAME", "KIND",
        );
        println!("{}", "-".repeat(id_w + name_w + kind_w + 14));
        for (id, name, kind, locked) in &entries {
            println!(
                "{:<id_w$}  {:<name_w$}  {:<kind_w$}  {}",
                id,
                name,
                kind,
                if *locked { "locked" } else { "unlocked" },
            );
        }
        for entry in &disabled {
            println!(
                "{:<id_w$}  {:<name_w$}  {:<kind_w$}  disabled",
                entry.id, entry.id, entry.kind,
            );
        }
        return Ok(());
    }

    // Fallback: read config directly (daemon not running).
    let id_w = cfg
        .provider
        .iter()
        .map(|p| p.id.len())
        .max()
        .unwrap_or(2)
        .max(2);
    let kind_w = cfg
        .provider
        .iter()
        .map(|p| p.kind.len())
        .max()
        .unwrap_or(4)
        .max(4);

    println!("{:<id_w$}  {:<kind_w$}  STATE", "ID", "KIND");
    println!("{}", "-".repeat(id_w + kind_w + 12));
    for entry in &cfg.provider {
        let state = if entry.enabled {
            "(daemon not running)"
        } else {
            "disabled"
        };
        println!("{:<id_w$}  {:<kind_w$}  {state}", entry.id, entry.kind,);
    }
    Ok(())
}

/// `rosec provider auth <id>` — interactively authenticate a provider.
///
/// Opens `/dev/tty` and passes the fd to `rosecd` via D-Bus fd-passing.
/// All credential prompting happens inside the daemon — credentials never
/// appear in any D-Bus message payload.
async fn cmd_provider_auth(args: &[String]) -> Result<()> {
    let mut provider_id: Option<&str> = None;
    let mut force = false;
    for arg in args {
        match arg.as_str() {
            "--force" | "-f" => force = true,
            s if s.starts_with('-') => bail!("unknown option: {s}"),
            _ if provider_id.is_none() => provider_id = Some(arg.as_str()),
            _ => bail!("unexpected argument: {arg}"),
        }
    }
    let provider_id =
        provider_id.ok_or_else(|| anyhow::anyhow!("usage: rosec provider auth <id> [--force]"))?;

    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    let tty_fd = open_tty_owned_fd()?;
    let _: () = proxy
        .call("AuthProviderWithTty", &(provider_id, tty_fd, force))
        .await?;

    println!("Provider '{provider_id}' authenticated.");
    Ok(())
}

/// `rosec provider add <kind> [--id <id>] [key=value ...]`
async fn cmd_provider_add(args: &[String]) -> Result<()> {
    // Scan for discovered plugin kinds so we can validate and prompt correctly.
    let registry = rosec_wasm::discovery::scan_plugins();

    let all_kinds: Vec<String> = {
        let mut v: Vec<String> = config_edit::KNOWN_KINDS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        for kind in registry.kinds() {
            if !v.iter().any(|k| k == kind) {
                v.push(kind.to_string());
            }
        }
        v
    };
    let all_kinds_display = all_kinds.join(", ");

    let kind = args.first().ok_or_else(|| {
        anyhow::anyhow!(
            "usage: rosec provider add <kind> [--id <id>] [key=value ...]\nKinds: {all_kinds_display}"
        )
    })?;

    let is_builtin = config_edit::KNOWN_KINDS.contains(&kind.as_str());
    let is_discovered = registry.contains_kind(kind);

    if !is_builtin && !is_discovered {
        bail!("unknown provider kind '{kind}'. Known kinds: {all_kinds_display}");
    }

    // Parse --id, --path, --collection flags and key=value pairs from remaining args.
    let mut custom_id: Option<String> = None;
    let mut custom_path: Option<String> = None;
    let mut collection: Option<String> = None;
    let mut options: Vec<(String, String)> = Vec::new();
    let mut i = 1usize;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--id" {
            i += 1;
            custom_id = Some(
                args.get(i)
                    .ok_or_else(|| anyhow::anyhow!("--id requires a value"))?
                    .clone(),
            );
        } else if let Some(id_val) = arg.strip_prefix("--id=") {
            custom_id = Some(id_val.to_string());
        } else if arg == "--path" {
            i += 1;
            custom_path = Some(
                args.get(i)
                    .ok_or_else(|| anyhow::anyhow!("--path requires a value"))?
                    .clone(),
            );
        } else if let Some(p) = arg.strip_prefix("--path=") {
            custom_path = Some(p.to_string());
        } else if arg == "--collection" {
            i += 1;
            collection = Some(
                args.get(i)
                    .ok_or_else(|| anyhow::anyhow!("--collection requires a value"))?
                    .clone(),
            );
        } else if let Some(c) = arg.strip_prefix("--collection=") {
            collection = Some(c.to_string());
        } else if let Some((k, v)) = arg.split_once('=')
            && !k.starts_with("--config")
        {
            // Also capture path= and collection= as key=value syntax.
            match k {
                "path" => custom_path = Some(v.to_string()),
                "collection" => collection = Some(v.to_string()),
                _ => options.push((k.to_string(), v.to_string())),
            }
        }
        i += 1;
    }

    // Snapshot the keys already supplied on the command line.
    let supplied: std::collections::HashSet<String> =
        options.iter().map(|(k, _)| k.clone()).collect();

    // Collect required options first — we need them to auto-generate the ID.
    // For built-in kinds, use config_edit; for discovered kinds, use the registry.
    if is_discovered {
        if let Some(req_opts) = rosec_wasm::discovery::required_options(&registry, kind) {
            for opt in &req_opts {
                if !supplied.contains(&opt.key) {
                    let v = prompt_field(&opt.description, "", &opt.kind).await?;
                    let s = v.as_str().to_string();
                    if !s.is_empty() {
                        options.push((opt.key.clone(), s));
                    }
                }
            }
        }
    } else {
        for (key, description) in config_edit::required_options_for_kind(kind) {
            if !supplied.contains(*key) {
                let field_kind = if key.contains("secret") || key.contains("password") {
                    "secret"
                } else {
                    "text"
                };
                let v = prompt_field(description, "", field_kind).await?;
                let s = v.as_str().to_string();
                if !s.is_empty() {
                    options.push((key.to_string(), s));
                }
            }
        }
    }

    // Determine the provider ID: explicit --id wins; otherwise derive from credentials.
    let id = match custom_id {
        Some(ref id) => id.clone(),
        None => derive_provider_id(kind, &options, &registry),
    };

    // Prompt for optional options not already supplied.
    let supplied_after_required: std::collections::HashSet<String> =
        options.iter().map(|(k, _)| k.clone()).collect();
    if is_discovered {
        if let Some(opt_opts) = rosec_wasm::discovery::optional_options(&registry, kind) {
            for opt in &opt_opts {
                if !supplied_after_required.contains(&opt.key) {
                    let v = prompt_field(
                        &format!("{} (optional, Enter to skip)", opt.description),
                        "",
                        &opt.kind,
                    )
                    .await?;
                    let s = v.as_str().to_string();
                    if !s.is_empty() {
                        options.push((opt.key.clone(), s));
                    }
                }
            }
        }
    } else {
        for (key, description) in config_edit::optional_options_for_kind(kind) {
            if !supplied_after_required.contains(*key) {
                let v = prompt_field(
                    &format!("{description} (optional, Enter to skip)"),
                    "",
                    "text",
                )
                .await?;
                let s = v.as_str().to_string();
                if !s.is_empty() {
                    options.push((key.to_string(), s));
                }
            }
        }
    }

    // Inject --path and --collection into options if they were supplied as flags.
    if let Some(ref p) = custom_path {
        options.push(("path".to_string(), p.clone()));
    }
    if let Some(ref c) = collection {
        options.push(("collection".to_string(), c.clone()));
    }

    // For local vaults, ensure a path is present — derive one from the ID if
    // the user did not supply an explicit --path or path= argument.
    if kind == "local" && custom_path.is_none() {
        let path = default_vault_path(&id);
        options.push(("path".to_string(), path));
    }

    // Resolve the vault path for local providers so we can check for conflicts.
    if kind == "local" {
        let path_value = options
            .iter()
            .find(|(k, _)| k == "path")
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        let resolved = expand_tilde(path_value);
        if std::path::Path::new(&resolved).exists() {
            bail!(
                "a vault file already exists at {resolved}\n\
                 Use `rosec provider attach --path {resolved}` to attach an existing vault."
            );
        }
    }

    // Check for duplicate ID early (add_provider also checks, but this gives
    // a friendlier message before we touch the config file).
    let cfg_data = load_config();
    if cfg_data.provider.iter().any(|p| p.id == id) {
        bail!("provider '{id}' already exists. Use --id to choose a different name.");
    }

    let cfg = config_path();
    config_edit::add_provider(&cfg, &id, kind, &options)?;
    println!("Added provider '{id}' (kind: {kind}) to {}", cfg.display());

    // If rosecd is running, wait for it to hot-reload the new provider then
    // immediately kick off the auth flow so the user doesn't have to run
    // `rosec provider auth <id>` manually as a separate step.
    if let Some(proxy) = wait_for_daemon_reload(&id).await {
        println!("rosecd picked up the new provider — starting authentication.");
        let tty_fd = open_tty_owned_fd()?;
        let _: () = proxy
            .call("AuthProviderWithTty", &(id.as_str(), tty_fd, false))
            .await?;
        println!("Provider '{id}' authenticated.");
    } else {
        println!("rosecd will hot-reload the config automatically if it is running.");
        println!("Run `rosec provider auth {id}` to authenticate.");
    }

    Ok(())
}

/// Derive a short, stable provider ID from the credential that identifies the account.
///
/// Format: `{kind}-{first8hexchars of sha256(credential)}`
///
/// - `bitwarden-sm`: hashes the organization_id
/// - anything else: falls back to the kind string itself
fn derive_provider_id(
    kind: &str,
    options: &[(String, String)],
    registry: &rosec_wasm::PluginRegistry,
) -> String {
    // For built-in kinds, use hardcoded credential keys.
    // For discovered kinds, use the manifest's id_derivation_key.
    let discovered_key = rosec_wasm::discovery::id_derivation_key(registry, kind);

    let credential_key = match kind {
        "bitwarden-sm" => "organization_id",
        _ => match discovered_key.as_deref() {
            Some(k) => k,
            None => return kind.to_string(),
        },
    };

    let value = options
        .iter()
        .find(|(k, _)| k == credential_key)
        .map(|(_, v)| v.as_str())
        .unwrap_or("");

    if value.is_empty() {
        return kind.to_string();
    }

    let hash = Sha256::digest(value.as_bytes());
    // Use the first 4 bytes (8 hex chars) — low collision probability for personal use
    let short = format!(
        "{:08x}",
        u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
    );
    format!("{kind}-{short}")
}

/// `rosec provider remove <id>`
///
/// For external providers, removes the config entry.
/// For local vaults, also offers to delete the vault file from disk.
async fn cmd_provider_remove(args: &[String]) -> Result<()> {
    let id = args
        .first()
        .ok_or_else(|| anyhow::anyhow!("usage: rosec provider remove <id>"))?;

    let cfg = config_path();

    // Check if this is a local vault with a path — if so, offer to delete the file.
    let cfg_data = load_config();
    let vault_path = cfg_data
        .provider
        .iter()
        .find(|p| p.id == *id && p.kind == "local")
        .and_then(|p| p.path.as_deref())
        .map(expand_tilde);

    config_edit::remove_provider(&cfg, id)?;
    println!("Removed provider '{id}' from {}", cfg.display());

    if let Some(ref path) = vault_path
        && std::path::Path::new(path).exists()
    {
        let confirm = prompt_field(
            &format!("Also delete the vault file at {path}? (yes/no)"),
            "no",
            "text",
        )
        .await?;
        if confirm.as_str() == "yes" {
            match std::fs::remove_file(path) {
                Ok(()) => println!("Deleted vault file: {path}"),
                Err(e) => eprintln!("warning: could not delete vault file {path}: {e}"),
            }
        } else {
            println!("Vault file kept at {path}.");
            println!("Use `rosec provider attach --path {path}` to re-attach later.");
        }
    }

    println!("rosecd will hot-reload the config automatically if it is running.");
    Ok(())
}

/// `rosec provider enable <id>` / `rosec provider disable <id>`
async fn cmd_provider_set_enabled(args: &[String], enabled: bool) -> Result<()> {
    let verb = if enabled { "enable" } else { "disable" };
    let id = args
        .first()
        .ok_or_else(|| anyhow::anyhow!("usage: rosec provider {verb} <id>"))?;

    let cfg = config_path();
    config_edit::set_provider_enabled(&cfg, id, enabled)?;

    if enabled {
        println!("Provider '{id}' enabled.");
    } else {
        println!("Provider '{id}' disabled.");
    }
    println!("rosecd will hot-reload the config automatically if it is running.");
    Ok(())
}

/// `rosec provider attach --path <file> [--id <id>] [--collection <c>]`
///
/// Adds an existing vault file to the config without creating it.
async fn cmd_provider_attach(args: &[String]) -> Result<()> {
    let mut custom_id: Option<String> = None;
    let mut vault_path: Option<String> = None;
    let mut collection: Option<String> = None;
    let mut i = 0usize;

    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "--id" => {
                i += 1;
                custom_id = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--id requires a value"))?
                        .clone(),
                );
            }
            a if a.starts_with("--id=") => {
                custom_id = Some(a.strip_prefix("--id=").unwrap_or(a).to_string());
            }
            "--path" => {
                i += 1;
                vault_path = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--path requires a value"))?
                        .clone(),
                );
            }
            a if a.starts_with("--path=") => {
                vault_path = Some(a.strip_prefix("--path=").unwrap_or(a).to_string());
            }
            "--collection" => {
                i += 1;
                collection = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--collection requires a value"))?
                        .clone(),
                );
            }
            a if a.starts_with("--collection=") => {
                collection = Some(a.strip_prefix("--collection=").unwrap_or(a).to_string());
            }
            "--help" | "-h" => {
                print_provider_help();
                return Ok(());
            }
            other => bail!("unexpected argument: {other}"),
        }
        i += 1;
    }

    let vault_path = vault_path.ok_or_else(|| {
        anyhow::anyhow!(
            "--path is required\nusage: rosec provider attach --path <file> [--id <id>]"
        )
    })?;

    // Derive ID from filename if not specified.
    let id = match custom_id {
        Some(id) => id,
        None => derive_vault_id_from_path(&vault_path),
    };

    let cfg = config_path();
    config_edit::add_local_provider(&cfg, &id, &vault_path, collection.as_deref())?;

    println!("Attached vault '{id}' ({vault_path}) to {}", cfg.display());
    println!("rosecd will hot-reload the config automatically if it is running.");
    println!("Run `rosec provider auth {id}` to authenticate.");
    Ok(())
}

/// `rosec provider detach <id>`
///
/// Removes the vault from the config file but leaves the vault file on disk.
async fn cmd_provider_detach(args: &[String]) -> Result<()> {
    let id = args
        .first()
        .ok_or_else(|| anyhow::anyhow!("usage: rosec provider detach <id>"))?;
    let cfg = config_path();
    config_edit::remove_provider(&cfg, id)?;
    println!("Detached vault '{id}' from {}", cfg.display());
    println!(
        "The vault file was NOT deleted. Use `rosec provider remove` to also delete the file."
    );
    println!("rosecd will hot-reload the config automatically if it is running.");
    Ok(())
}

/// `rosec provider add-password <id> [--label <label>]`
///
/// Add a new unlock password to a vault. The vault must be unlocked (running in
/// rosecd).
async fn cmd_provider_add_password(args: &[String]) -> Result<()> {
    let mut vault_id: Option<&str> = None;
    let mut label: Option<String> = None;
    let mut i = 0usize;

    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "--label" => {
                i += 1;
                label = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--label requires a value"))?
                        .clone(),
                );
            }
            a if a.starts_with("--label=") => {
                label = Some(a.strip_prefix("--label=").unwrap_or(a).to_string());
            }
            "--help" | "-h" => {
                print_provider_help();
                return Ok(());
            }
            a if a.starts_with('-') => bail!("unknown flag: {a}"),
            a => {
                if vault_id.is_some() {
                    bail!("unexpected argument: {a}");
                }
                vault_id = Some(a);
            }
        }
        i += 1;
    }

    let vault_id = vault_id.ok_or_else(|| {
        anyhow::anyhow!("usage: rosec provider add-password <id> [--label <label>]")
    })?;

    // Default label: user@hostname
    let label = label.unwrap_or_else(default_password_label);

    // Prompt for the new password.
    let pw = prompt_field("New password", "", "password").await?;
    if pw.is_empty() {
        bail!("password cannot be empty");
    }
    let pw_confirm = prompt_field("Confirm password", "", "password").await?;
    if pw.as_str() != pw_confirm.as_str() {
        bail!("passwords do not match");
    }

    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    let entry_id: String = proxy
        .call("AddPassword", &(vault_id, pw.as_bytes().to_vec(), &label))
        .await?;

    println!("Added password entry {entry_id} (label: {label}) to vault '{vault_id}'.");
    Ok(())
}

/// `rosec provider list-passwords <vault-id>`
///
/// List the wrapping entries (unlock passwords) for a vault. The vault must be
/// unlocked. Shows the entry ID and label for each password.
async fn cmd_provider_list_passwords(args: &[String]) -> Result<()> {
    let vault_id = args
        .first()
        .ok_or_else(|| anyhow::anyhow!("usage: rosec provider list-passwords <vault-id>"))?;

    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    let entries: Vec<(String, String)> = proxy.call("ListPasswords", &(vault_id.as_str(),)).await?;

    if entries.is_empty() {
        println!("No password entries found for vault '{vault_id}'.");
        return Ok(());
    }

    println!("Password entries for vault '{vault_id}':\n");
    println!("  {:<40} LABEL", "ENTRY ID");
    println!("  {:<40} -----", "--------");
    for (id, label) in &entries {
        let display_label = if label.is_empty() { "(none)" } else { label };
        println!("  {:<40} {}", id, display_label);
    }

    Ok(())
}

/// `rosec provider change-password <vault-id>`
///
/// Change the unlock password for a vault.  Prompts for the current password,
/// new password, and confirmation.  The wrapping entry matched by the old
/// password is atomically replaced with a new one for the new password.
async fn cmd_provider_change_password(args: &[String]) -> Result<()> {
    let vault_id = args
        .first()
        .ok_or_else(|| anyhow::anyhow!("usage: rosec provider change-password <vault-id>"))?;

    let old_pw = prompt_field("Current password", "", "password").await?;
    if old_pw.is_empty() {
        bail!("current password cannot be empty");
    }

    let new_pw = prompt_field("New password", "", "password").await?;
    if new_pw.is_empty() {
        bail!("new password cannot be empty");
    }

    let confirm_pw = prompt_field("Confirm new password", "", "password").await?;
    if new_pw.as_str() != confirm_pw.as_str() {
        bail!("passwords do not match");
    }

    let old_fd = password_to_pipe_fd(old_pw.as_bytes())?;
    let new_fd = password_to_pipe_fd(new_pw.as_bytes())?;

    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    let _: () = proxy
        .call(
            "ChangeProviderPassword",
            &(vault_id.as_str(), old_fd, new_fd),
        )
        .await?;

    println!("Password changed for vault '{vault_id}'.");
    Ok(())
}

/// `rosec provider remove-password <vault-id> <entry-id>`
///
/// Remove an unlock password from a vault. The vault must be unlocked and must
/// have at least 2 passwords.
async fn cmd_provider_remove_password(args: &[String]) -> Result<()> {
    if args.len() < 2 {
        bail!("usage: rosec provider remove-password <vault-id> <entry-id>");
    }
    let vault_id = &args[0];
    let entry_id = &args[1];

    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    // First list passwords to show the user what they're removing.
    let entries: Vec<(String, String)> = proxy.call("ListPasswords", &(vault_id.as_str(),)).await?;

    let target = entries
        .iter()
        .find(|(id, _)| id == entry_id)
        .ok_or_else(|| {
            anyhow::anyhow!("password entry '{entry_id}' not found in vault '{vault_id}'")
        })?;

    let label_display = if target.1.is_empty() {
        "(no label)".to_string()
    } else {
        target.1.clone()
    };

    println!("Removing password entry: {entry_id} {label_display}");

    let _: () = proxy
        .call("RemovePassword", &(vault_id.as_str(), entry_id.as_str()))
        .await?;

    println!("Removed password entry '{entry_id}' from vault '{vault_id}'.");
    Ok(())
}

/// Default vault file path: `$XDG_DATA_HOME/rosec/vaults/<id>.vault`.
fn default_vault_path(id: &str) -> String {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("rosec")
        .join("vaults")
        .join(format!("{id}.vault"))
        .to_string_lossy()
        .into_owned()
}

/// Derive a vault ID from a file path.
///
/// Takes the filename stem (e.g. `/mnt/shared/team.vault` → `team`).
fn derive_vault_id_from_path(path: &str) -> String {
    std::path::Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("vault")
        .to_string()
}

/// Expand `~` to `$HOME` in a path string.
fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return format!("{}/{rest}", home.to_string_lossy());
    }
    path.to_string()
}

// ---------------------------------------------------------------------------
// Top-level commands
// ---------------------------------------------------------------------------

async fn cmd_status() -> Result<()> {
    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    let (cache_size, last_sync_epoch, sessions): (u32, u64, u32) =
        proxy.call("Status", &()).await?;

    // Fetch all providers with type and lock state.
    let providers: Vec<(String, String, String, bool)> = proxy.call("ProviderList", &()).await?;

    println!("Providers:");
    for (id, name, kind, locked) in &providers {
        let lock_indicator = if *locked { "locked" } else { "unlocked" };
        println!("  {name} ({id})  [{kind}, {lock_indicator}]");
    }
    println!();
    println!("Cache size:  {cache_size} items");
    if last_sync_epoch > 0 {
        println!("Last sync:   {last_sync_epoch} (epoch secs)");
    } else {
        println!("Last sync:   never");
    }
    println!("Sessions:    {sessions}");
    Ok(())
}

async fn cmd_sync() -> Result<()> {
    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    // Fetch the list of providers so we know which ones to sync.
    let providers: Vec<(String, String, String, bool)> = proxy.call("ProviderList", &()).await?;

    for (id, _name, _kind, _locked) in &providers {
        eprint!("Syncing '{id}'...");
        match proxy.call::<_, _, u32>("SyncProvider", &(id,)).await {
            Ok(count) => {
                println!(" {count} items");
            }
            Err(zbus::Error::MethodError(_, Some(detail), _))
                if detail.as_str().starts_with("locked::") =>
            {
                // Daemon says this provider needs credentials first.
                // Pass a TTY fd so the daemon can prompt in-process —
                // credentials never appear in any D-Bus message.
                let provider_id = detail.as_str().strip_prefix("locked::").unwrap_or("");
                eprintln!(" locked");
                let tty_fd = open_tty_owned_fd()?;
                let _: () = proxy
                    .call("AuthProviderWithTty", &(provider_id, tty_fd))
                    .await?;
                // Retry sync now that the provider is unlocked.
                eprint!("Syncing '{id}' (retrying)...");
                match proxy.call::<_, _, u32>("SyncProvider", &(id,)).await {
                    Ok(count) => println!(" {count} items"),
                    Err(e) => eprintln!(" failed: {e}"),
                }
            }
            Err(e) => eprintln!(" failed: {e}"),
        }
    }

    Ok(())
}

/// Ensure the daemon's cache is fresh by syncing providers in parallel.
///
/// Checks `DaemonStatus.last_sync_epoch` — if the last sync was more than
/// 60 seconds ago (matching the daemon's internal staleness threshold), calls
/// `SyncProvider` for each unlocked provider concurrently.  If the cache is
/// already fresh, this is a single cheap D-Bus call with no network I/O.
///
/// Locked providers are skipped — the caller handles unlock via the Prompt flow
/// and can call this again afterwards to sync the newly-unlocked providers.
async fn preemptive_sync(conn: &Connection) -> Result<()> {
    let proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    // Check global staleness: if last_sync_epoch is within 60 s, skip.
    let status: (u32, u64, u32) = proxy.call("Status", &()).await?;
    let last_sync_epoch = status.1;

    if last_sync_epoch > 0 {
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now_epoch.saturating_sub(last_sync_epoch) < 60 {
            return Ok(());
        }
    }

    // Stale or never synced — sync each unlocked provider in parallel.
    let providers: Vec<(String, String, String, bool)> = proxy.call("ProviderList", &()).await?;

    let futures: Vec<_> = providers
        .into_iter()
        .filter(|(_, _, _, locked)| !locked)
        .map(|(id, _, _, _)| {
            let conn = conn.clone();
            async move {
                let p = zbus::Proxy::new(
                    &conn,
                    "org.freedesktop.secrets",
                    "/org/rosec/Daemon",
                    "org.rosec.Daemon",
                )
                .await;
                match p {
                    Ok(p) => {
                        if let Err(e) = p.call::<_, _, u32>("SyncProvider", &(&id,)).await {
                            eprintln!("sync {id}: {e}");
                        }
                    }
                    Err(e) => eprintln!("sync {id}: {e}"),
                }
            }
        })
        .collect();

    futures_util::future::join_all(futures).await;

    Ok(())
}

/// Returns `true` if the daemon reports at least one locked provider.
///
/// Used by `cmd_search` with `--sync` to distinguish "genuinely no results"
/// from "empty because the metadata cache was never populated" (cold start with
/// all providers locked).
async fn any_providers_locked(conn: &Connection) -> Result<bool> {
    let proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;
    let providers: Vec<(String, String, String, bool)> = proxy.call("ProviderList", &()).await?;
    Ok(providers.iter().any(|(_, _, _, locked)| *locked))
}

/// Output format for `rosec search`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Human,
    Table,
    Kv,
    Json,
}

impl OutputFormat {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "human" => Some(Self::Human),
            "table" => Some(Self::Table),
            "kv" => Some(Self::Kv),
            "json" => Some(Self::Json),
            _ => None,
        }
    }
}

/// All data fetched for a single search result item.
struct ItemSummary {
    label: String,
    attrs: HashMap<String, String>,
    path: String,
    locked: bool,
}

impl ItemSummary {
    /// The 16-char hex hash that uniquely identifies this item.
    ///
    /// Path segment format: `{provider}_{uuid_sanitised}_{hash:016x}`
    /// The hash is the last `_`-delimited token — always exactly 16 hex chars.
    /// It is derived from `sha256("{provider_id}:{item_id}")[0..8]` so it is
    /// stable across restarts and toolchain upgrades, and collision probability
    /// is ~1 in 2^64 across all items in a vault.
    ///
    /// Pass this directly to `rosec get`.
    fn display_id(&self) -> &str {
        let seg = self.path.rsplit('/').next().unwrap_or(self.path.as_str());
        seg.rsplit('_').next().unwrap_or(seg)
    }
}

/// Returns true if the value string contains any wildmatch glob metacharacters.
fn is_glob(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[')
}

/// Spec-compliant exact-match search via `org.freedesktop.Secret.Service.SearchItems`.
/// Handles lazy-unlock automatically.
async fn search_exact(
    conn: &Connection,
    attrs: &HashMap<String, String>,
) -> Result<(Vec<String>, Vec<String>)> {
    let proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await?;

    let convert =
        |(u, l): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)| -> (Vec<String>, Vec<String>) {
            (
                u.into_iter().map(|p| p.to_string()).collect(),
                l.into_iter().map(|p| p.to_string()).collect(),
            )
        };

    match proxy.call("SearchItems", &(attrs,)).await {
        Ok(result) => Ok(convert(result)),
        Err(ref e) if try_lazy_unlock(conn, e).await? => {
            Ok(convert(proxy.call("SearchItems", &(attrs,)).await?))
        }
        Err(e) => Err(e.into()),
    }
}

/// Detect whether the active Secret Service provider is rosecd.
///
/// Attempts a cheap `org.freedesktop.DBus.Introspectable.Introspect` call on
/// `/org/rosec/Daemon`.  Returns `true` if the call succeeds (object exists),
/// `false` for any error (object absent, service unknown, etc.).
///
/// Call this once per command and pass the result as `is_rosecd: bool` to
/// avoid redundant round-trips.
async fn is_rosecd(conn: &Connection) -> bool {
    let proxy = match zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.freedesktop.DBus.Introspectable",
    )
    .await
    {
        Ok(p) => p,
        Err(_) => return false,
    };
    proxy.call::<_, _, String>("Introspect", &()).await.is_ok()
}

/// If rosecd is running with no configured providers, print a warning to stderr
/// and suggest next steps.  Non-fatal — the caller continues normally (an empty
/// provider list returns empty results, which is correct behaviour).
async fn warn_if_no_providers(conn: &Connection) {
    let Ok(proxy) = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await
    else {
        return;
    };
    let Ok(entries) = proxy
        .call::<_, _, Vec<(String, String, String, bool)>>("ProviderList", &())
        .await
    else {
        return;
    };
    if entries.is_empty() {
        eprintln!("warning: rosecd is running with no configured providers.");
        eprintln!("         Run `rosec provider add <kind>` to add a real provider.");
    }
}

/// Glob search: try `org.rosec.Search.SearchItemsGlob` first when rosecd is running.
///
/// If `is_rosecd` is false (non-rosecd provider), falls back to
/// `SearchItems({})` to retrieve all items, then applies glob matching
/// client-side.  This keeps `rosec search name=John*` working against GNOME
/// Keyring, KWallet, or any other spec-compliant Secret Service daemon.
async fn search_with_glob_fallback(
    conn: &Connection,
    attrs: &HashMap<String, String>,
    is_rosecd: bool,
) -> Result<(Vec<String>, Vec<String>)> {
    if is_rosecd {
        // Use the rosec Search extension — zero client-side work.
        let search_proxy = zbus::Proxy::new(
            conn,
            "org.freedesktop.secrets",
            "/org/rosec/Search",
            "org.rosec.Search",
        )
        .await?;

        let convert =
            |(u, l): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)| -> (Vec<String>, Vec<String>) {
                (
                    u.into_iter().map(|p| p.to_string()).collect(),
                    l.into_iter().map(|p| p.to_string()).collect(),
                )
            };

        // Mirror the lazy-unlock retry that search_exact uses: if the server
        // returns locked::<id>, prompt the user then retry once.
        match search_proxy.call("SearchItemsGlob", &(attrs,)).await {
            Ok(result) => return Ok(convert(result)),
            Err(ref e) if try_lazy_unlock(conn, e).await? => {
                return Ok(convert(
                    search_proxy.call("SearchItemsGlob", &(attrs,)).await?,
                ));
            }
            Err(e) => return Err(e.into()),
        }
    }

    // Fallback for non-rosecd providers: fetch all items then filter client-side.
    let (unlocked, locked) = search_exact(conn, &HashMap::new()).await?;

    let mut filtered_unlocked = Vec::new();
    let mut filtered_locked = Vec::new();

    for path in &unlocked {
        if let Ok(summary) = fetch_item_data(conn, path, false).await
            && glob_matches(&summary, attrs)
        {
            filtered_unlocked.push(path.clone());
        }
    }
    for path in &locked {
        if let Ok(summary) = fetch_item_data(conn, path, true).await
            && glob_matches(&summary, attrs)
        {
            filtered_locked.push(path.clone());
        }
    }

    Ok((filtered_unlocked, filtered_locked))
}

/// Returns true if all glob/exact filters in `attrs` match the item summary.
/// The special key `"name"` matches the item label.
fn glob_matches(item: &ItemSummary, attrs: &HashMap<String, String>) -> bool {
    attrs.iter().all(|(key, pattern)| {
        let value = if key == "name" {
            item.label.as_str()
        } else {
            item.attrs
                .get(key.as_str())
                .map(String::as_str)
                .unwrap_or("")
        };
        wildmatch::WildMatch::new(pattern).matches(value)
    })
}

async fn cmd_search(args: &[String]) -> Result<()> {
    // Parse --format flag, --show-path flag, --sync flag, and k=v filters.
    let mut format = OutputFormat::Table;
    let mut show_path = false;
    let mut sync = false;
    let mut all_attrs: HashMap<String, String> = HashMap::new();

    for arg in args {
        if let Some(fmt_str) = arg.strip_prefix("--format=") {
            match OutputFormat::parse(fmt_str) {
                Some(f) => format = f,
                None => {
                    bail!("unknown format '{fmt_str}': use table, kv, or json");
                }
            }
        } else if arg == "--format" {
            bail!("--format requires a value: --format=table|kv|json");
        } else if arg == "--show-path" {
            show_path = true;
        } else if arg == "--sync" || arg == "-s" {
            sync = true;
        } else if arg == "--help" || arg == "-h" {
            print_search_help();
            return Ok(());
        } else if let Some((key, value)) = arg.split_once('=') {
            all_attrs.insert(key.to_string(), value.to_string());
        } else {
            bail!("invalid argument: {arg}");
        }
    }

    let conn = conn().await?;
    let rosecd = is_rosecd(&conn).await;
    if rosecd {
        warn_if_no_providers(&conn).await;
    }

    // If --sync was requested, ensure the daemon has fresh data first.
    if sync {
        preemptive_sync(&conn).await?;
    }

    let has_globs = all_attrs.values().any(|v| is_glob(v)) || all_attrs.contains_key("name");

    // Strategy:
    //   - Any glob pattern or "name" filter → use org.rosec.Search.SearchItemsGlob
    //     when rosecd is running; otherwise fall back to spec-compliant
    //     SearchItems({}) + client-side glob (works against GNOME Keyring, KWallet, etc.)
    //   - All-exact attrs → always use spec-compliant SearchItems directly.
    let do_search = |conn: &Connection| {
        let conn = conn.clone();
        let all_attrs = all_attrs.clone();
        async move {
            if has_globs {
                search_with_glob_fallback(&conn, &all_attrs, rosecd).await
            } else {
                search_exact(&conn, &all_attrs).await
            }
        }
    };

    let (unlocked, locked) = match do_search(&conn).await {
        Ok(result) => result,
        Err(e) if sync => {
            // Search failed (e.g. all providers locked) — unlock then retry.
            trigger_unlock(&conn).await?;
            preemptive_sync(&conn).await?;
            do_search(&conn).await.map_err(|_| e)?
        }
        Err(e) => return Err(e),
    };

    // With --sync, trigger unlock and retry when:
    //   (a) results are all locked (items exist but collection is locked), OR
    //   (b) both lists are empty AND the daemon has locked providers — the
    //       metadata cache is cold (never synced) because all providers started
    //       locked and preemptive_sync skipped them.
    let needs_unlock = sync
        && ((!locked.is_empty() && unlocked.is_empty())
            || (unlocked.is_empty() && locked.is_empty() && any_providers_locked(&conn).await?));
    let (unlocked, locked) = if needs_unlock {
        trigger_unlock(&conn).await?;
        preemptive_sync(&conn).await?;
        do_search(&conn).await?
    } else {
        (unlocked, locked)
    };

    if unlocked.is_empty() && locked.is_empty() {
        if format != OutputFormat::Json {
            println!("No items found.");
        } else {
            println!("[]");
        }
        return Ok(());
    }

    // Fetch metadata for all result paths.
    let mut items: Vec<ItemSummary> = Vec::new();
    for path in &unlocked {
        let summary = fetch_item_data(&conn, path, false)
            .await
            .unwrap_or_else(|_| ItemSummary {
                label: path.clone(),
                attrs: HashMap::new(),
                path: path.clone(),
                locked: false,
            });
        items.push(summary);
    }
    for path in &locked {
        let summary = fetch_item_data(&conn, path, true)
            .await
            .unwrap_or_else(|_| ItemSummary {
                label: path.clone(),
                attrs: HashMap::new(),
                path: path.clone(),
                locked: true,
            });
        items.push(summary);
    }

    match format {
        OutputFormat::Human | OutputFormat::Table => print_search_table(&items, show_path),
        OutputFormat::Kv => print_search_kv(&items, show_path),
        OutputFormat::Json => print_search_json(&items)?, // JSON always includes path
    }

    Ok(())
}

/// Fetch Label and Attributes for an item into a structured summary.
async fn fetch_item_data(conn: &zbus::Connection, path: &str, locked: bool) -> Result<ItemSummary> {
    let item_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        path,
        "org.freedesktop.Secret.Item",
    )
    .await?;

    let label: String = item_proxy.get_property("Label").await?;
    let attrs: HashMap<String, String> = item_proxy.get_property("Attributes").await?;

    Ok(ItemSummary {
        label,
        attrs,
        path: path.to_string(),
        locked,
    })
}

/// Truncate a string to `max` display chars, appending `…` if cut.
fn trunc(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        // Cut at a char boundary safely.
        let mut end = max.saturating_sub(1); // 1 char for …
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    }
}

/// Print results as an aligned table.
///
/// Columns: TYPE | PROVIDER | NAME | USERNAME | URI | ID [| PATH]
fn print_search_table(items: &[ItemSummary], show_path: bool) {
    const H_TYPE: &str = "TYPE";
    const H_PROV: &str = "PROVIDER";
    const H_NAME: &str = "NAME";
    const H_USER: &str = "USERNAME";
    const H_URI: &str = "URI";
    const H_ID: &str = "ID";

    // Hard caps keep the table usable on a standard 120-column terminal.
    const MAX_TYPE: usize = 10;
    const MAX_PROV: usize = 20;
    const MAX_NAME: usize = 30;
    const MAX_USER: usize = 30;
    const MAX_URI: usize = 40;
    const W_ID: usize = 16; // always exactly 16 hex chars

    let w_type = items
        .iter()
        .map(|i| {
            i.attrs
                .get(rosec_core::ATTR_TYPE)
                .map(String::len)
                .unwrap_or(0)
                .min(MAX_TYPE)
        })
        .max()
        .unwrap_or(0)
        .max(H_TYPE.len());
    let w_prov = items
        .iter()
        .map(|i| {
            i.attrs
                .get(rosec_core::ATTR_PROVIDER)
                .map(String::len)
                .unwrap_or(0)
                .min(MAX_PROV)
        })
        .max()
        .unwrap_or(0)
        .max(H_PROV.len());
    let w_name = items
        .iter()
        .map(|i| i.label.len().min(MAX_NAME))
        .max()
        .unwrap_or(0)
        .max(H_NAME.len());
    let w_user = items
        .iter()
        .map(|i| {
            i.attrs
                .get("username")
                .map(String::len)
                .unwrap_or(0)
                .min(MAX_USER)
        })
        .max()
        .unwrap_or(0)
        .max(H_USER.len());
    let w_uri = items
        .iter()
        .map(|i| {
            i.attrs
                .get("uri")
                .map(String::len)
                .unwrap_or(0)
                .min(MAX_URI)
        })
        .max()
        .unwrap_or(0)
        .max(H_URI.len());

    // Separator width: columns + 2-char gaps between each pair + ID column.
    // The ID header text is 2 chars ("ID") but data is always 16 hex chars.
    let w_id_col = W_ID.max(H_ID.len());
    let sep_w = w_type
        + 2
        + w_prov
        + 2
        + w_name
        + 2
        + w_user
        + 2
        + w_uri
        + 2
        + w_id_col
        + if show_path { 2 + "PATH".len() } else { 0 };

    if show_path {
        println!(
            "{:<w_type$}  {:<w_prov$}  {:<w_name$}  {:<w_user$}  {:<w_uri$}  {:<w_id_col$}  PATH",
            H_TYPE, H_PROV, H_NAME, H_USER, H_URI, H_ID,
        );
    } else {
        println!(
            "{:<w_type$}  {:<w_prov$}  {:<w_name$}  {:<w_user$}  {:<w_uri$}  {}",
            H_TYPE, H_PROV, H_NAME, H_USER, H_URI, H_ID,
        );
    }
    println!("{}", "-".repeat(sep_w));

    for item in items {
        let item_type = item
            .attrs
            .get(rosec_core::ATTR_TYPE)
            .map(String::as_str)
            .unwrap_or("");
        let provider = item
            .attrs
            .get(rosec_core::ATTR_PROVIDER)
            .map(String::as_str)
            .unwrap_or("");
        let username = item.attrs.get("username").map(String::as_str).unwrap_or("");
        let uri = item.attrs.get("uri").map(String::as_str).unwrap_or("");

        let t = trunc(item_type, MAX_TYPE);
        let p = trunc(provider, MAX_PROV);
        let n = trunc(&item.label, MAX_NAME);
        let u = trunc(username, MAX_USER);
        let r = trunc(uri, MAX_URI);
        let lock_indicator = if item.locked { " [locked]" } else { "" };

        if show_path {
            println!(
                "{:<w_type$}  {:<w_prov$}  {:<w_name$}  {:<w_user$}  {:<w_uri$}  {:<w_id_col$}  {}{}",
                t,
                p,
                n,
                u,
                r,
                item.display_id(),
                item.path,
                lock_indicator,
            );
        } else {
            println!(
                "{:<w_type$}  {:<w_prov$}  {:<w_name$}  {:<w_user$}  {:<w_uri$}  {}{}",
                t,
                p,
                n,
                u,
                r,
                item.display_id(),
                lock_indicator,
            );
        }
    }
}

/// Print results as key=value pairs (one item block per result).
fn print_search_kv(items: &[ItemSummary], show_path: bool) {
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            println!();
        }
        println!("label={}", item.label);
        println!("id={}", item.display_id());
        if show_path {
            println!("path={}", item.path);
        }
        if item.locked {
            println!("locked=true");
        }
        // Print all public attributes sorted for determinism.
        let mut sorted_attrs: Vec<_> = item.attrs.iter().collect();
        sorted_attrs.sort_by_key(|(k, _)| k.as_str());
        for (k, v) in &sorted_attrs {
            // Skip internal/redundant attrs in kv mode.
            if k.as_str() == "xdg:schema" {
                continue;
            }
            println!("{k}={v}");
        }
    }
}

/// Print results as a JSON array.
fn print_search_json(items: &[ItemSummary]) -> Result<()> {
    let json_items: Vec<serde_json::Value> = items
        .iter()
        .map(|item| {
            let mut obj = serde_json::Map::new();
            obj.insert(
                "label".to_string(),
                serde_json::Value::String(item.label.clone()),
            );
            obj.insert(
                "id".to_string(),
                serde_json::Value::String(item.display_id().to_string()),
            );
            obj.insert(
                "path".to_string(),
                serde_json::Value::String(item.path.clone()),
            );
            obj.insert("locked".to_string(), serde_json::Value::Bool(item.locked));

            let mut attrs_obj = serde_json::Map::new();
            let mut sorted_attrs: Vec<_> = item.attrs.iter().collect();
            sorted_attrs.sort_by_key(|(k, _)| k.as_str());
            for (k, v) in sorted_attrs {
                attrs_obj.insert(k.clone(), serde_json::Value::String(v.clone()));
            }
            obj.insert(
                "attributes".to_string(),
                serde_json::Value::Object(attrs_obj),
            );

            serde_json::Value::Object(obj)
        })
        .collect();

    println!("{}", serde_json::to_string_pretty(&json_items)?);
    Ok(())
}

/// Resolve a user-supplied item identifier to a full D-Bus object path.
///
/// Accepts:
/// - A full D-Bus path (starts with `/`)
/// - A 16-char hex hash (the `display_id` shown by `rosec search`) — resolved
///   by searching all items for one whose path ends with `_{hash}`
/// - Any other string is treated as the full last path segment and prepended
///   with the collection prefix (legacy behaviour)
///
/// Returns `(path, is_locked)` where `is_locked` is `true` if the item was
/// found in the `locked` list of `SearchItems`.  For full paths and legacy
/// segments (where we don't call `SearchItems`), `is_locked` is `false`.
async fn resolve_item_path(conn: &Connection, raw: &str) -> Result<(String, bool)> {
    if raw.starts_with('/') {
        return Ok((raw.to_string(), false));
    }

    // Attribute search: key=value (supports globs via SearchItemsGlob).
    //
    // Multiple attributes can be separated by spaces (shell quoting), but the
    // common case is a single `name=My Item` or `name=*API*`.
    //
    // We detect this by looking for '=' that isn't at position 0.
    if let Some(eq_pos) = raw.find('=')
        && eq_pos > 0
    {
        return resolve_item_by_attrs(conn, raw).await;
    }

    // 16-char lowercase hex → look up by hash suffix.
    let is_hash = raw.len() == 16 && raw.chars().all(|c| c.is_ascii_hexdigit());
    if is_hash {
        let proxy = zbus::Proxy::new(
            conn,
            "org.freedesktop.secrets",
            "/org/freedesktop/secrets",
            "org.freedesktop.Secret.Service",
        )
        .await?;
        let suffix = format!("_{raw}");
        let (unlocked_paths, locked_paths): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = proxy
            .call("SearchItems", &(&HashMap::<String, String>::new(),))
            .await?;
        let unlocked: Vec<String> = unlocked_paths.into_iter().map(|p| p.to_string()).collect();
        let locked: Vec<String> = locked_paths.into_iter().map(|p| p.to_string()).collect();
        // Check unlocked first (preferred).
        for path in &unlocked {
            if path.ends_with(&suffix) {
                return Ok((path.clone(), false));
            }
        }
        // Then check locked list.
        for path in &locked {
            if path.ends_with(&suffix) {
                return Ok((path.clone(), true));
            }
        }
        anyhow::bail!("no item found with ID {raw}");
    }

    // Legacy: treat as full path segment.
    Ok((
        format!("/org/freedesktop/secrets/collection/default/{raw}"),
        false,
    ))
}

/// Resolve an item path from one or more `key=value` attribute filters.
///
/// Uses `SearchItemsGlob` when rosecd is running (supports glob patterns and
/// the virtual `name` attribute); falls back to spec-compliant `SearchItems`
/// for other providers.
///
/// Returns an error if zero or more than one item matches.
async fn resolve_item_by_attrs(conn: &Connection, raw: &str) -> Result<(String, bool)> {
    let mut attrs = HashMap::new();
    // The raw string may be the single positional arg, so it's one key=value.
    // But we also allow the caller to pass multiple space-separated pairs in
    // the future if needed.  For now, treat the entire raw string as one pair
    // since the shell will have already split spaces into separate args.
    if let Some((key, value)) = raw.split_once('=') {
        attrs.insert(key.to_string(), value.to_string());
    } else {
        anyhow::bail!("invalid attribute filter: {raw}  (expected key=value)");
    }

    let rosecd = is_rosecd(conn).await;
    let has_globs = attrs.values().any(|v| is_glob(v)) || attrs.contains_key("name");

    let (unlocked, locked) = if has_globs {
        search_with_glob_fallback(conn, &attrs, rosecd).await?
    } else {
        search_exact(conn, &attrs).await?
    };

    let total = unlocked.len() + locked.len();
    match total {
        0 => anyhow::bail!("no item found matching {raw}"),
        1 => {
            if let Some(path) = unlocked.into_iter().next() {
                Ok((path, false))
            } else {
                Ok((locked.into_iter().next().expect("locked has 1 item"), true))
            }
        }
        n => {
            let mut msg = format!("{n} items match {raw} — narrow your search:\n");
            for path in unlocked.iter().chain(locked.iter()).take(10) {
                // Extract the short hex ID from the path suffix.
                let id = path.rsplit('_').next().unwrap_or(path);
                msg.push_str(&format!("  {id}  {path}\n"));
            }
            if n > 10 {
                msg.push_str(&format!("  … and {} more\n", n - 10));
            }
            anyhow::bail!("{msg}");
        }
    }
}

async fn cmd_get(args: &[String]) -> Result<()> {
    // Parse flags: --help / -h, --attr <name> / --attr=<name>, --sync
    let mut attr: Option<String> = None;
    let mut sync = false;
    let mut id: Option<&str> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_get_help();
                return Ok(());
            }
            "--sync" | "-s" => {
                sync = true;
            }
            "--attr" => {
                i += 1;
                attr = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--attr requires a value"))?
                        .clone(),
                );
            }
            a if a.starts_with("--attr=") => {
                attr = Some(a.strip_prefix("--attr=").unwrap_or(a).to_string());
            }
            a if a.starts_with('-') => {
                bail!("unknown flag: {a}  (try `rosec get --help`)");
            }
            a => {
                if id.is_some() {
                    bail!("unexpected argument: {a}  (try `rosec get --help`)");
                }
                id = Some(a);
            }
        }
        i += 1;
    }

    let raw =
        id.ok_or_else(|| anyhow::anyhow!("missing item path or ID  (try `rosec get --help`)"))?;

    let conn = conn().await?;

    // If --sync was requested, ensure the daemon has fresh data before resolving.
    if sync {
        preemptive_sync(&conn).await?;
    }

    let resolve_result = resolve_item_path(&conn, raw).await;

    // Determine the item path and whether unlock is needed.
    // With --sync, if the item wasn't found at all we attempt unlock + re-sync
    // before giving up — the item may live in a provider that hasn't been
    // unlocked yet (so the metadata cache has no knowledge of it).
    let (path, is_locked) = match resolve_result {
        Ok(result) => result,
        Err(e) if sync => {
            // Item not found — try unlocking, syncing, and re-resolving.
            trigger_unlock(&conn).await?;
            preemptive_sync(&conn).await?;
            resolve_item_path(&conn, raw).await.map_err(|_| e)? // If still not found, return the original error.
        }
        Err(e) => return Err(e),
    };

    // If the item was in the locked partition, trigger the spec Unlock+Prompt
    // flow before attempting to fetch the secret.
    if is_locked {
        trigger_unlock(&conn).await?;
        // Re-sync the just-unlocked providers so the freshly-available items
        // are pulled from the remote and the metadata cache is populated.
        if sync {
            preemptive_sync(&conn).await?;
        }
    }

    // Try once; if provider is locked, prompt for credentials and retry.
    match cmd_get_inner(&conn, &path, attr.as_deref()).await {
        Ok(()) => Ok(()),
        Err(e) => {
            let zbus_err = e.downcast_ref::<zbus::Error>();
            if let Some(ze) = zbus_err
                && try_lazy_unlock(&conn, ze).await?
            {
                cmd_get_inner(&conn, &path, attr.as_deref()).await
            } else {
                Err(e)
            }
        }
    }
}

fn print_get_help() {
    println!(
        "\
rosec get - print a secret value

USAGE:
    rosec get [--sync] [--attr <name>] <item>

ARGUMENTS:
    <item>          One of:
                      16-char hex item ID       a1b2c3d4e5f60718
                      D-Bus object path         /org/freedesktop/secrets/…
                      Attribute filter           name=MY_API_KEY
                    Attribute filters use key=value syntax.  Glob patterns
                    are supported (name=*prod*, uri=*.example.com).
                    Exactly one item must match.

FLAGS:
    -s, --sync      Sync providers before fetching if the cache is stale (>60 s).
                    Skips the network call when data is already fresh.
    --attr <name>   Print the named public attribute instead of the primary secret
                    (e.g. username, uri, folder, sm.project).
                    Use `rosec inspect <id>` to see all available attributes.
    -h, --help      Show this help

EXAMPLES:
    rosec get a1b2c3d4e5f60718                    # by hex ID
    rosec get name=MY_API_KEY                     # by exact name
    rosec get 'name=*prod*'                       # by name glob
    rosec get uri=github.com                      # by URI attribute
    rosec get --sync name=MY_API_KEY              # sync first, then fetch
    rosec get a1b2c3d4e5f60718 | xclip -sel clip  # pipe to clipboard
    rosec get --attr username name=MY_API_KEY     # print username attribute"
    );
}

/// Normalise an `--attr` value that may use dot-index syntax.
///
/// Any attribute with multiple values uses `name.N` notation in the CLI:
/// - `name`   → `"name"`   (bare = index 0, backwards compat)
/// - `name.0` → `"name"`   (explicit index 0 → bare key)
/// - `name.1` → `"name.1"` (index 1 stored as "name.1")
/// - `name.2` → `"name.2"`, …
///
/// This is generic — it works for `uri`, `custom.field`, or any future
/// multi-value attribute without needing an allowlist.
fn normalise_attr_key(attr: &str) -> String {
    if let Some(dot) = attr.rfind('.') {
        let name = &attr[..dot];
        let suffix = &attr[dot + 1..];
        // Only treat as an index if suffix is a pure decimal integer.
        if !name.is_empty()
            && suffix.chars().all(|c| c.is_ascii_digit())
            && let Ok(idx) = suffix.parse::<usize>()
        {
            return if idx == 0 {
                name.to_string()
            } else {
                format!("{name}.{idx}")
            };
        }
    }
    attr.to_string()
}

/// Print only the secret value (or a named attribute) to stdout — pipeable.
async fn cmd_get_inner(conn: &Connection, path: &str, attr: Option<&str>) -> Result<()> {
    use std::io::Write;

    // --attr mode: read from the public Attributes property, no session needed.
    if let Some(attr_name) = attr {
        let resolved = normalise_attr_key(attr_name);
        let item_proxy = zbus::Proxy::new(
            conn,
            "org.freedesktop.secrets",
            path,
            "org.freedesktop.Secret.Item",
        )
        .await?;
        let attrs: HashMap<String, String> = item_proxy.get_property("Attributes").await?;
        match attrs.get(resolved.as_str()) {
            Some(v) => {
                let mut out = std::io::stdout();
                out.write_all(v.as_bytes())?;
                // Attribute values are plain strings — always add newline on TTY,
                // and only if the value doesn't already end with one.
                if std::io::IsTerminal::is_terminal(&out) && !v.ends_with('\n') {
                    out.write_all(b"\n")?;
                }
                return Ok(());
            }
            None => bail!("attribute '{resolved}' not found on this item"),
        }
    }

    // Default: fetch the primary secret via GetSecrets.
    let service_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await?;

    let (_, session_path): (OwnedValue, OwnedObjectPath) = service_proxy
        .call("OpenSession", &("plain", zvariant::Value::from("")))
        .await?;

    let item_path = OwnedObjectPath::try_from(path.to_string())
        .map_err(|e| anyhow::anyhow!("invalid item path: {e}"))?;
    let items = vec![&item_path];
    let secrets_result: Result<HashMap<OwnedObjectPath, OwnedValue>, zbus::Error> = service_proxy
        .call("GetSecrets", &(items, &session_path))
        .await;

    let _: () = service_proxy
        .call("CloseSession", &(&session_path,))
        .await?;

    match secrets_result {
        Ok(secrets) if secrets.is_empty() => {
            bail!("no secret found for item");
        }
        Ok(secrets) => {
            if let Some((_item_path, value)) = secrets.into_iter().next() {
                match <(OwnedObjectPath, Vec<u8>, Vec<u8>, String)>::try_from(value) {
                    Ok((_session, _params, secret_bytes, _content_type)) => {
                        let mut out = std::io::stdout();
                        out.write_all(&secret_bytes)?;
                        // Add a trailing newline on TTY only if the secret itself
                        // doesn't already end with one (avoids the double-newline
                        // that appears when the stored value has a trailing \n).
                        if std::io::IsTerminal::is_terminal(&out) && !secret_bytes.ends_with(b"\n")
                        {
                            out.write_all(b"\n")?;
                        }
                        return Ok(());
                    }
                    Err(_) => bail!("could not decode secret value"),
                }
            }
            bail!("no secret found for item");
        }
        Err(zbus::Error::MethodError(_, Some(detail), _))
            if detail.as_str().starts_with("no secret for cipher") =>
        {
            bail!("item has no primary secret");
        }
        Err(e) => Err(e.into()),
    }
}

async fn cmd_inspect(args: &[String]) -> Result<()> {
    let mut all_attrs = false;
    let mut sync = false;
    let mut format = OutputFormat::Human;
    let mut raw: Option<&str> = None;

    for arg in args {
        match arg.as_str() {
            "--all-attrs" | "-a" => all_attrs = true,
            "--sync" | "-s" => sync = true,
            s if s.starts_with("--format=") => {
                let fmt_str = &s["--format=".len()..];
                match OutputFormat::parse(fmt_str) {
                    Some(f) => format = f,
                    None => {
                        bail!("unknown format '{fmt_str}': use human, kv, or json");
                    }
                }
            }
            "--format" => {
                bail!("--format requires a value: --format=human|kv|json");
            }
            "--help" | "-h" => {
                print_inspect_help();
                return Ok(());
            }
            s if raw.is_none() => raw = Some(s),
            s => {
                bail!("unexpected argument: {s}");
            }
        }
    }

    let raw = raw.ok_or_else(|| anyhow::anyhow!("missing item path or ID"))?;

    let conn = conn().await?;

    if sync {
        preemptive_sync(&conn).await?;
    }

    // Resolve the item; if not found and --sync is set, try unlock + re-sync first.
    let (path, is_locked) = match resolve_item_path(&conn, raw).await {
        Ok(result) => result,
        Err(e) => {
            // Item not in cache — trigger unlock (which may populate it) then retry.
            trigger_unlock(&conn).await?;
            preemptive_sync(&conn).await?;
            resolve_item_path(&conn, raw).await.map_err(|_| e)?
        }
    };

    if is_locked {
        trigger_unlock(&conn).await?;
        if sync {
            preemptive_sync(&conn).await?;
        }
    }

    match cmd_inspect_inner(&conn, &path, all_attrs, &format).await {
        Ok(()) => Ok(()),
        Err(e) => {
            let zbus_err = e.downcast_ref::<zbus::Error>();
            if let Some(ze) = zbus_err
                && try_lazy_unlock(&conn, ze).await?
            {
                cmd_inspect_inner(&conn, &path, all_attrs, &format).await
            } else {
                Err(e)
            }
        }
    }
}

/// Print full item metadata (label, attributes) plus the secret value.
///
/// When `all_attrs` is true, also fetches sensitive attribute names via
/// `org.rosec.Secrets.GetSecretAttributeNames` and their values via
/// `GetSecretAttribute`, displaying them alongside the public attributes.
async fn cmd_inspect_inner(
    conn: &Connection,
    path: &str,
    all_attrs: bool,
    format: &OutputFormat,
) -> Result<()> {
    let service_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await?;

    let (_, session_path): (OwnedValue, OwnedObjectPath) = service_proxy
        .call("OpenSession", &("plain", zvariant::Value::from("")))
        .await?;

    let item_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        path,
        "org.freedesktop.Secret.Item",
    )
    .await?;

    let label: String = item_proxy.get_property("Label").await?;
    let pub_attrs: HashMap<String, String> = item_proxy.get_property("Attributes").await?;

    // Fetch sensitive attribute names (and optionally values) if requested.
    let secret_attrs: Vec<(String, Zeroizing<Vec<u8>>)> = if all_attrs {
        let secrets_proxy = zbus::Proxy::new(
            conn,
            "org.freedesktop.secrets",
            "/org/rosec/Secrets",
            "org.rosec.Secrets",
        )
        .await?;

        let item_obj_path = OwnedObjectPath::try_from(path.to_string())
            .map_err(|e| anyhow::anyhow!("invalid item path: {e}"))?;

        let names: Vec<String> = secrets_proxy
            .call("GetSecretAttributeNames", &(&item_obj_path,))
            .await?;

        let mut pairs: Vec<(String, Zeroizing<Vec<u8>>)> = Vec::with_capacity(names.len());
        for name in names {
            let bytes: Vec<u8> = secrets_proxy
                .call("GetSecretAttribute", &(&item_obj_path, name.as_str()))
                .await
                .unwrap_or_default();
            pairs.push((name, Zeroizing::new(bytes)));
        }
        pairs
    } else {
        Vec::new()
    };

    // Fetch the primary secret for human/kv (not needed for json as we include
    // sensitive attrs separately).
    let inspect_item_path = OwnedObjectPath::try_from(path.to_string())
        .map_err(|e| anyhow::anyhow!("invalid item path: {e}"))?;
    let items = vec![&inspect_item_path];
    let secrets_result: Result<HashMap<OwnedObjectPath, OwnedValue>, zbus::Error> = service_proxy
        .call("GetSecrets", &(items, &session_path))
        .await;

    let _: () = service_proxy
        .call("CloseSession", &(&session_path,))
        .await?;

    match format {
        OutputFormat::Human | OutputFormat::Table => {
            println!("Label:      {label}");
            println!("Path:       {path}");

            // Public attributes.
            if !pub_attrs.is_empty() {
                println!("Attributes (public):");
                let mut sorted: Vec<_> = pub_attrs.iter().collect();
                sorted.sort_by_key(|(k, _)| *k);
                for (k, v) in sorted {
                    println!("  {k}: {v}");
                }
            }

            // Sensitive attributes (--all-attrs).
            if !secret_attrs.is_empty() {
                println!("Attributes (sensitive):");
                for (k, v) in &secret_attrs {
                    let text = String::from_utf8_lossy(v);
                    println!("  {k}: {text}");
                }
            }

            // Primary secret.
            match secrets_result {
                Ok(secrets) if secrets.is_empty() => {
                    println!("Secret:     <none>");
                }
                Ok(secrets) => {
                    for (_item_path, value) in secrets {
                        match <(OwnedObjectPath, Vec<u8>, Vec<u8>, String)>::try_from(value) {
                            Ok((_session, _params, secret_bytes, content_type)) => {
                                let text = String::from_utf8_lossy(&secret_bytes);
                                if text.is_empty() {
                                    println!("Secret:     <empty>");
                                } else {
                                    println!("Secret ({content_type}):");
                                    println!("  {text}");
                                }
                            }
                            Err(_) => println!("Secret:     <could not decode>"),
                        }
                    }
                }
                Err(zbus::Error::MethodError(_, Some(detail), _))
                    if detail.as_str().starts_with("no secret for cipher") =>
                {
                    println!("Secret:     <not available — this item type has no primary secret>");
                }
                Err(e) => println!("Secret:     <error: {e}>"),
            }
        }

        OutputFormat::Kv => {
            println!("label={label}");
            println!("path={path}");
            let mut sorted_pub: Vec<_> = pub_attrs.iter().collect();
            sorted_pub.sort_by_key(|(k, _)| *k);
            for (k, v) in sorted_pub {
                println!("{k}={v}");
            }
            for (k, v) in &secret_attrs {
                let text = String::from_utf8_lossy(v);
                println!("{k}={text}");
            }
            // Also emit primary secret as `secret=` for completeness.
            if let Ok(secrets) = secrets_result {
                for (_item_path, value) in secrets {
                    if let Ok((_session, _params, secret_bytes, _ct)) =
                        <(OwnedObjectPath, Vec<u8>, Vec<u8>, String)>::try_from(value)
                    {
                        let text = String::from_utf8_lossy(&secret_bytes);
                        println!("secret={text}");
                    }
                }
            }
        }

        OutputFormat::Json => {
            // Build a JSON object with label, path, public_attrs, and (if
            // --all-attrs) sensitive_attrs as a merged or separate sub-object.
            let mut sorted_pub: Vec<_> = pub_attrs.iter().collect();
            sorted_pub.sort_by_key(|(k, _)| *k);

            let pub_obj: serde_json::Map<String, serde_json::Value> = sorted_pub
                .into_iter()
                .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                .collect();

            let secret_obj: serde_json::Map<String, serde_json::Value> = secret_attrs
                .iter()
                .map(|(k, v)| {
                    let text = String::from_utf8_lossy(v).into_owned();
                    (k.clone(), serde_json::Value::String(text))
                })
                .collect();

            // Primary secret value.
            let primary_secret = match secrets_result {
                Ok(secrets) => {
                    let mut val = serde_json::Value::Null;
                    for (_item_path, value) in secrets {
                        if let Ok((_session, _params, secret_bytes, _ct)) =
                            <(OwnedObjectPath, Vec<u8>, Vec<u8>, String)>::try_from(value)
                        {
                            val = serde_json::Value::String(
                                String::from_utf8_lossy(&secret_bytes).into_owned(),
                            );
                        }
                    }
                    val
                }
                Err(_) => serde_json::Value::Null,
            };

            let mut obj = serde_json::Map::new();
            obj.insert("label".into(), serde_json::Value::String(label));
            obj.insert("path".into(), serde_json::Value::String(path.to_string()));
            obj.insert("attributes".into(), serde_json::Value::Object(pub_obj));
            if all_attrs {
                obj.insert(
                    "sensitive_attributes".into(),
                    serde_json::Value::Object(secret_obj),
                );
            }
            obj.insert("secret".into(), primary_secret);

            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::Value::Object(obj))?
            );
        }
    }

    Ok(())
}

async fn cmd_lock() -> Result<()> {
    let conn = conn().await?;

    // Count unlocked providers before locking so we can report how many were locked.
    let mgmt_proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;
    let providers: Vec<(String, String, String, bool)> =
        mgmt_proxy.call("ProviderList", &()).await?;
    let unlocked_count = providers.iter().filter(|(_, _, _, locked)| !locked).count();

    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await?;
    let _: (Vec<OwnedObjectPath>, OwnedObjectPath) = proxy
        .call(
            "Lock",
            &(vec![
                OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/default")
                    .expect("static path"),
            ],),
        )
        .await?;

    match unlocked_count {
        0 => println!("Nothing to lock — all providers already locked."),
        n => println!(
            "Locked: 1 collection, {} provider{}.",
            n,
            if n == 1 { "" } else { "s" }
        ),
    }
    Ok(())
}

async fn cmd_unlock() -> Result<()> {
    let conn = conn().await?;

    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    let providers: Vec<(String, String, String, bool)> = proxy.call("ProviderList", &()).await?;

    if providers.is_empty() {
        println!("No providers configured. Run `rosec provider add <kind>` to add one.");
        return Ok(());
    }

    // Report already-unlocked providers.
    let any_locked = providers.iter().any(|(_, _, _, locked)| *locked);
    for (id, _, _, is_locked) in &providers {
        if !is_locked {
            println!("'{id}' is already unlocked.");
        }
    }

    if !any_locked {
        return Ok(());
    }

    // Pass the caller's TTY fd to the daemon via D-Bus fd-passing.
    // All credential prompting happens inside rosecd — credentials never
    // appear in any D-Bus message payload.
    //
    // Do NOT wrap this call in a spinner: the daemon writes interactive
    // prompts to the TTY fd while this call is in flight, and the spinner
    // would interleave its \r-overwrite output with those prompts, leaving
    // the cursor in the wrong position.
    let tty_fd = open_tty_owned_fd()?;
    eprintln!("Unlocking…");
    type ResultEntry = (String, bool, String); // (provider_id, success, message)
    let results: Vec<ResultEntry> = proxy.call("UnlockWithTty", &(tty_fd,)).await?;

    for (id, success, message) in &results {
        if *success {
            println!("'{id}' unlocked.");
        } else {
            eprintln!("'{id}' failed: {message}");
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// rosec config — read/write config.toml
// ---------------------------------------------------------------------------

/// Supported dotted-path config keys and their human description.
///
/// Only settings that are safe to change at runtime (the daemon hot-reloads
/// config.toml) and genuinely useful from the CLI are listed here.
/// Theme colours and prompt binary paths are intentionally excluded —
/// hand-editing TOML is cleaner for those.
static CONFIG_KEYS: &[(&str, &str)] = &[
    (
        "service.refresh_interval_secs",
        "Vault re-sync interval in seconds (0 = disabled)",
    ),
    (
        "service.dedup_strategy",
        "Deduplication strategy: newest | priority",
    ),
    (
        "service.dedup_time_fallback",
        "Tie-break field when strategy=newest: created | none",
    ),
    (
        "autolock.on_logout",
        "Lock vault when the session ends (true | false)",
    ),
    (
        "autolock.on_session_lock",
        "Lock vault when the screen locks (true | false)",
    ),
    (
        "autolock.idle_timeout_minutes",
        "Lock after N minutes of inactivity (0 or omit = disabled)",
    ),
    (
        "autolock.max_unlocked_minutes",
        "Hard cap: lock after N minutes unlocked (0 or omit = disabled)",
    ),
];

fn print_config_help() {
    println!(
        "\
rosec config - read or modify config.toml

USAGE:
    rosec config show
    rosec config get <key>
    rosec config set <key> <value>

SUBCOMMANDS:
    show            Print the current effective configuration as TOML
    get <key>       Print the current value of a single setting
    set <key> <value>
                    Update a setting.  The daemon hot-reloads config.toml
                    automatically — no restart required.

SETTABLE KEYS:"
    );
    for (key, desc) in CONFIG_KEYS {
        println!("    {key:<40}  {desc}");
    }
    println!(
        "
EXAMPLES:
    rosec config show
    rosec config get autolock.idle_timeout_minutes
    rosec config set autolock.idle_timeout_minutes 30
    rosec config set autolock.on_session_lock false
    rosec config set service.refresh_interval_secs 120"
    );
}

fn cmd_config(args: &[String]) -> Result<()> {
    let sub = args.first().map(String::as_str).unwrap_or("help");
    match sub {
        "show" => cmd_config_show(),
        "get" => {
            let key = args
                .get(1)
                .ok_or_else(|| anyhow::anyhow!("missing key  (try `rosec config --help`)"))?;
            cmd_config_get(key)
        }
        "set" => {
            let key = args
                .get(1)
                .ok_or_else(|| anyhow::anyhow!("missing key  (try `rosec config --help`)"))?;
            let value = args
                .get(2)
                .ok_or_else(|| anyhow::anyhow!("missing value  (try `rosec config --help`)"))?;
            cmd_config_set(key, value)
        }
        "help" | "--help" | "-h" => {
            print_config_help();
            Ok(())
        }
        other => {
            print_config_help();
            bail!("unknown config subcommand: {other}");
        }
    }
}

fn cmd_config_show() -> Result<()> {
    let path = config_path();
    if !path.exists() {
        println!("# No config file found at {}", path.display());
        println!("# Showing compiled-in defaults:\n");
        let default_toml = toml::to_string_pretty(&Config::default())
            .unwrap_or_else(|_| "# (serialization error)".to_string());
        println!("{default_toml}");
        return Ok(());
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
    print!("{raw}");
    Ok(())
}

fn cmd_config_get(key: &str) -> Result<()> {
    // Validate the key is in the supported list.
    if !CONFIG_KEYS.iter().any(|(k, _)| *k == key) {
        bail!("unknown config key: {key}\nrun `rosec config --help` to see supported keys");
    }

    let cfg = load_config();
    let value = config_get_value(&cfg, key)?;
    println!("{value}");
    Ok(())
}

/// Read a single dotted-path value from a loaded `Config` as a display string.
fn config_get_value(cfg: &Config, key: &str) -> Result<String> {
    Ok(match key {
        "service.refresh_interval_secs" => cfg
            .service
            .refresh_interval_secs
            .map(|v| v.to_string())
            .unwrap_or_else(|| "60".to_string()),
        "service.dedup_strategy" => format!("{:?}", cfg.service.dedup_strategy).to_lowercase(),
        "service.dedup_time_fallback" => {
            format!("{:?}", cfg.service.dedup_time_fallback).to_lowercase()
        }
        "autolock.on_logout" => cfg.autolock.on_logout.to_string(),
        "autolock.on_session_lock" => cfg.autolock.on_session_lock.to_string(),
        "autolock.idle_timeout_minutes" => cfg
            .autolock
            .idle_timeout_minutes
            .map(|v| v.to_string())
            .unwrap_or_else(|| "0".to_string()),
        "autolock.max_unlocked_minutes" => cfg
            .autolock
            .max_unlocked_minutes
            .map(|v| v.to_string())
            .unwrap_or_else(|| "0".to_string()),
        other => anyhow::bail!("unhandled key: {other}"),
    })
}

/// Validate a config value before writing it, giving the user a clear error
/// rather than silently writing a value the daemon will reject on reload.
fn validate_config_value(key: &str, value: &str) -> Result<()> {
    match key {
        "service.dedup_strategy" => {
            if !matches!(value, "newest" | "priority") {
                anyhow::bail!("invalid value '{value}': must be 'newest' or 'priority'");
            }
        }
        "service.dedup_time_fallback" => {
            if !matches!(value, "created" | "none") {
                anyhow::bail!("invalid value '{value}': must be 'created' or 'none'");
            }
        }
        "autolock.on_logout" | "autolock.on_session_lock" => {
            if !matches!(value, "true" | "false") {
                anyhow::bail!("invalid value '{value}': must be 'true' or 'false'");
            }
        }
        "service.refresh_interval_secs"
        | "autolock.idle_timeout_minutes"
        | "autolock.max_unlocked_minutes" => {
            value.parse::<u64>().map_err(|_| {
                anyhow::anyhow!("invalid value '{value}': must be a non-negative integer")
            })?;
        }
        _ => {}
    }
    Ok(())
}

fn cmd_config_set(key: &str, value: &str) -> Result<()> {
    // Validate the key is in the supported list.
    if !CONFIG_KEYS.iter().any(|(k, _)| *k == key) {
        bail!("unknown config key: {key}\nrun `rosec config --help` to see supported keys");
    }

    // Validate the value before touching the file.
    validate_config_value(key, value)?;

    let path = config_path();
    config_edit::set_value(&path, key, value)?;

    println!("{key} = {value}");
    Ok(())
}

// ---------------------------------------------------------------------------
// rosec enable / disable — manage D-Bus activation + systemd unit files
// ---------------------------------------------------------------------------

/// File names we manage.
const DBUS_SECRETS_SERVICE: &str = "org.freedesktop.secrets.service";
const DBUS_KEYRING_SERVICE: &str = "org.gnome.keyring.service";
const SYSTEMD_SERVICE_UNIT: &str = "rosecd.service";
const SYSTEMD_SOCKET_UNIT: &str = "rosecd.socket";

/// Known Secret Service providers that may already own the bus name.
const KNOWN_PROVIDERS: &[(&str, &str)] = &[
    (
        "gnome-keyring",
        "/usr/share/dbus-1/services/org.freedesktop.secrets.service",
    ),
    (
        "gnome-keyring",
        "/usr/share/dbus-1/services/org.gnome.keyring.service",
    ),
    (
        "kwallet/ksecretd",
        "/usr/share/dbus-1/services/org.kde.secretservicecompat.service",
    ),
    (
        "keepassxc",
        "/usr/share/dbus-1/services/org.keepassxc.KeePassXC.BrowserServer.service",
    ),
];

/// Return `~/.local/share/dbus-1/services/`.
fn user_dbus_services_dir() -> Result<std::path::PathBuf> {
    let data_home = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| String::from("/tmp"));
            PathBuf::from(home).join(".local/share")
        });
    Ok(data_home.join("dbus-1/services"))
}

/// Return `~/.config/systemd/user/`.
fn user_systemd_dir() -> Result<std::path::PathBuf> {
    let config_home = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| String::from("/tmp"));
            PathBuf::from(home).join(".config")
        });
    Ok(config_home.join("systemd/user"))
}

/// Resolve the absolute path to `rosecd`.
///
/// Strategy:
///   1. Sibling of the current executable (same directory as `rosec`).
///   2. Fall back to `$PATH` lookup via `which rosecd`.
///   3. Error if neither works.
fn resolve_rosecd() -> Result<PathBuf> {
    // Try sibling of current executable.
    if let Ok(self_exe) = std::env::current_exe() {
        let candidate = self_exe
            .canonicalize()
            .unwrap_or(self_exe)
            .parent()
            .map(|dir| dir.join("rosecd"));
        if let Some(p) = candidate
            && p.is_file()
        {
            return Ok(p);
        }
    }

    // Fall back to $PATH.
    let output = std::process::Command::new("which").arg("rosecd").output();
    if let Ok(out) = output
        && out.status.success()
    {
        let path_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !path_str.is_empty() {
            let p = PathBuf::from(&path_str);
            if p.is_file() {
                return Ok(p);
            }
        }
    }

    bail!(
        "could not locate rosecd binary.\n\
         Ensure rosecd is installed and either:\n\
         - in the same directory as rosec, or\n\
         - on your $PATH"
    )
}

/// Detect which Secret Service providers already have system-wide D-Bus
/// activation files installed.
fn detect_existing_providers() -> Vec<(&'static str, &'static str)> {
    KNOWN_PROVIDERS
        .iter()
        .filter(|(_, path)| std::path::Path::new(path).exists())
        .copied()
        .collect()
}

/// Generate D-Bus service file contents with the resolved binary path.
fn gen_dbus_secrets_service(rosecd: &std::path::Path) -> String {
    format!(
        "\
[D-BUS Service]
Name=org.freedesktop.secrets
Exec={rosecd}
SystemdService=rosecd.service
",
        rosecd = rosecd.display()
    )
}

/// Generate the gnome-keyring mask file contents.
fn gen_dbus_keyring_mask() -> &'static str {
    "\
[D-BUS Service]
Name=org.gnome.keyring
Exec=/bin/false
"
}

/// Generate systemd user service unit with the resolved binary path.
fn gen_systemd_service(rosecd: &std::path::Path) -> String {
    format!(
        "\
[Unit]
Description=rosec - read-only Secret Service daemon
Documentation=https://github.com/jmylchreest/rosec
After=dbus.service
Requires=dbus.service
After=graphical-session.target
PartOf=graphical-session.target

[Service]
Type=dbus
BusName=org.freedesktop.secrets
ExecStart={rosecd}
Restart=on-failure
RestartSec=5

NoNewPrivileges=yes
ProtectHome=read-only
ProtectSystem=strict
ReadWritePaths=%h/.config/rosec %h/.local/share/rosec %h/.local/state/rosec
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
MemoryDenyWriteExecute=yes
PrivateNetwork=no
Environment=RUST_LOG=info

[Install]
WantedBy=graphical-session.target
Also=rosecd.socket
",
        rosecd = rosecd.display()
    )
}

/// Generate systemd user socket unit (path-independent).
fn gen_systemd_socket() -> &'static str {
    "\
[Unit]
Description=rosec Secret Service socket
Documentation=https://github.com/jmylchreest/rosec

[Socket]
ListenStream=%t/rosec/secrets.socket
DirectoryMode=0700
Accept=no

[Install]
WantedBy=sockets.target
"
}

/// Write a file, creating parent directories as needed. Returns Ok(true) if
/// written, Ok(false) if the file already has identical contents (skip).
fn install_file(path: &std::path::Path, contents: &str) -> Result<bool> {
    if let Ok(existing) = std::fs::read_to_string(path)
        && existing == contents
    {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("failed to create {}: {e}", parent.display()))?;
    }
    std::fs::write(path, contents)
        .map_err(|e| anyhow::anyhow!("failed to write {}: {e}", path.display()))?;
    Ok(true)
}

/// Remove a file if it exists. Returns whether a file was actually removed.
fn remove_file_if_exists(path: &std::path::Path) -> Result<bool> {
    if path.exists() {
        std::fs::remove_file(path)
            .map_err(|e| anyhow::anyhow!("failed to remove {}: {e}", path.display()))?;
        Ok(true)
    } else {
        Ok(false)
    }
}

fn cmd_enable(args: &[String]) -> Result<()> {
    let mut enable_systemd = true;
    let mut no_mask = false;
    let mut force = false;

    for arg in args {
        match arg.as_str() {
            "--no-systemd" => enable_systemd = false,
            "--no-mask" => no_mask = true,
            "--force" | "-f" => force = true,
            "--help" | "-h" => {
                print_enable_help();
                return Ok(());
            }
            other => bail!("unknown flag: {other}\nrun `rosec enable --help` for usage"),
        }
    }

    // --- resolve rosecd binary path ------------------------------------------

    let rosecd = resolve_rosecd()?;
    println!("using rosecd: {}", rosecd.display());

    let dbus_dir = user_dbus_services_dir()?;
    let systemd_dir = user_systemd_dir()?;
    let secrets_path = dbus_dir.join(DBUS_SECRETS_SERVICE);
    let keyring_path = dbus_dir.join(DBUS_KEYRING_SERVICE);
    let service_path = systemd_dir.join(SYSTEMD_SERVICE_UNIT);
    let socket_path = systemd_dir.join(SYSTEMD_SOCKET_UNIT);

    // --- pre-flight checks ---------------------------------------------------

    if secrets_path.exists() && !force {
        let existing = std::fs::read_to_string(&secrets_path).unwrap_or_default();
        if existing.contains("rosecd") {
            println!("rosec is already enabled ({})", secrets_path.display());
            println!("run `rosec enable --force` to overwrite");
            return Ok(());
        }
        bail!(
            "{} already exists but points to another service.\n\
             Use `rosec enable --force` to overwrite it.",
            secrets_path.display()
        );
    }

    // Report detected providers.
    let existing = detect_existing_providers();
    if !existing.is_empty() {
        println!("Detected existing Secret Service providers:");
        for (name, path) in &existing {
            println!("  {name:<20} {path}");
        }
        println!();
        let has_gnome_keyring = existing.iter().any(|(n, _)| *n == "gnome-keyring");
        if has_gnome_keyring && !no_mask {
            println!(
                "gnome-keyring will be masked via user-local D-Bus override.\n\
                 (pass --no-mask to skip masking)"
            );
        }
        println!();
    }

    // --- install D-Bus service files -----------------------------------------

    let contents = gen_dbus_secrets_service(&rosecd);
    if install_file(&secrets_path, &contents)? {
        println!("installed {}", secrets_path.display());
    } else {
        println!("unchanged {}", secrets_path.display());
    }

    // Write gnome-keyring mask (unless --no-mask).
    if !no_mask {
        let has_gnome_keyring = existing.iter().any(|(n, _)| *n == "gnome-keyring");
        if has_gnome_keyring || force {
            let mask = gen_dbus_keyring_mask();
            if install_file(&keyring_path, mask)? {
                println!("installed {} (masks gnome-keyring)", keyring_path.display());
            } else {
                println!("unchanged {}", keyring_path.display());
            }
        }
    }

    // --- install systemd user units ------------------------------------------

    if enable_systemd {
        let svc_contents = gen_systemd_service(&rosecd);
        if install_file(&service_path, &svc_contents)? {
            println!("installed {}", service_path.display());
        } else {
            println!("unchanged {}", service_path.display());
        }

        let sock_contents = gen_systemd_socket();
        if install_file(&socket_path, sock_contents)? {
            println!("installed {}", socket_path.display());
        } else {
            println!("unchanged {}", socket_path.display());
        }

        // Reload, then enable + start.
        run_systemctl(&["daemon-reload"]);
        run_systemctl(&["enable", "--now", "rosecd.service"]);
    }

    println!();
    println!("rosec is now enabled as the Secret Service provider.");
    println!("Run `rosec status` to verify.");
    Ok(())
}

fn cmd_disable(args: &[String]) -> Result<()> {
    let mut disable_systemd = true;

    for arg in args {
        match arg.as_str() {
            "--no-systemd" => disable_systemd = false,
            "--help" | "-h" => {
                print_disable_help();
                return Ok(());
            }
            other => bail!("unknown flag: {other}\nrun `rosec disable --help` for usage"),
        }
    }

    let dbus_dir = user_dbus_services_dir()?;
    let systemd_dir = user_systemd_dir()?;
    let secrets_path = dbus_dir.join(DBUS_SECRETS_SERVICE);
    let keyring_path = dbus_dir.join(DBUS_KEYRING_SERVICE);
    let service_path = systemd_dir.join(SYSTEMD_SERVICE_UNIT);
    let socket_path = systemd_dir.join(SYSTEMD_SOCKET_UNIT);

    let mut removed_any = false;

    // --- systemd: stop + disable first (before removing unit files) -----------

    if disable_systemd {
        run_systemctl(&["disable", "--now", "rosecd.service"]);
        run_systemctl(&["disable", "--now", "rosecd.socket"]);
    }

    // --- remove D-Bus service files ------------------------------------------

    if remove_file_if_exists(&secrets_path)? {
        println!("removed {}", secrets_path.display());
        removed_any = true;
    }

    if keyring_path.exists() {
        let contents = std::fs::read_to_string(&keyring_path).unwrap_or_default();
        if contents.contains("/bin/false") {
            std::fs::remove_file(&keyring_path)
                .map_err(|e| anyhow::anyhow!("failed to remove {}: {e}", keyring_path.display()))?;
            println!("removed {} (gnome-keyring mask)", keyring_path.display());
            removed_any = true;
        } else {
            eprintln!(
                "warning: {} does not look like a rosec mask file, leaving it alone",
                keyring_path.display()
            );
        }
    }

    // --- remove systemd unit files -------------------------------------------

    if disable_systemd {
        if remove_file_if_exists(&service_path)? {
            println!("removed {}", service_path.display());
            removed_any = true;
        }
        if remove_file_if_exists(&socket_path)? {
            println!("removed {}", socket_path.display());
            removed_any = true;
        }
        run_systemctl(&["daemon-reload"]);
    }

    if !removed_any {
        println!("rosec was not enabled (nothing to disable)");
    } else {
        println!();
        println!("rosec has been disabled as the Secret Service provider.");
        let existing = detect_existing_providers();
        let has_gnome_keyring = existing.iter().any(|(n, _)| *n == "gnome-keyring");
        if has_gnome_keyring {
            println!("gnome-keyring will resume handling Secret Service requests.");
        }
    }
    Ok(())
}

/// Run `systemctl --user <args>`, printing warnings on failure but never
/// aborting — systemd may not be available (e.g. WSL, containers).
fn run_systemctl(extra_args: &[&str]) {
    let mut args = vec!["--user"];
    args.extend_from_slice(extra_args);
    let display_cmd = format!("systemctl {}", args.join(" "));

    let status = std::process::Command::new("systemctl").args(&args).status();
    match status {
        Ok(s) if s.success() => println!("{display_cmd} ... ok"),
        Ok(s) => {
            eprintln!(
                "warning: {display_cmd} exited with {}",
                s.code().map_or("signal".to_string(), |c| c.to_string())
            );
        }
        Err(e) => {
            eprintln!("warning: could not run systemctl: {e}");
        }
    }
}

fn print_enable_help() {
    println!(
        "\
rosec enable - activate rosec as the Secret Service provider

USAGE:
    rosec enable [flags]

Generates and installs user-local D-Bus activation files and systemd user
units so that org.freedesktop.secrets is handled by rosecd.

The rosecd binary path is resolved automatically (sibling of the rosec
binary, or from $PATH) and embedded into all generated files.

FILES INSTALLED:
    ~/.local/share/dbus-1/services/org.freedesktop.secrets.service
        Routes D-Bus activation of org.freedesktop.secrets to rosecd.

    ~/.local/share/dbus-1/services/org.gnome.keyring.service
        Masks gnome-keyring D-Bus auto-activation (only if gnome-keyring
        is detected). User-local files take priority over system-wide
        files in /usr/share/dbus-1/services/.

    ~/.config/systemd/user/rosecd.service
        systemd user service unit with the resolved rosecd path.

    ~/.config/systemd/user/rosecd.socket
        systemd user socket unit for private-socket activation.

FLAGS:
    --no-systemd    Do not install/enable systemd user units
    --no-mask       Do not install the gnome-keyring mask file
    --force, -f     Overwrite existing files even if already enabled

NOTES:
    This command does NOT modify any system files or conflict with
    installed packages. All files are written to user-local directories.
    Run `rosec disable` to reverse all changes."
    );
}

fn print_disable_help() {
    println!(
        "\
rosec disable - deactivate rosec as the Secret Service provider

USAGE:
    rosec disable [flags]

Removes all files installed by `rosec enable`:
  - D-Bus activation files from ~/.local/share/dbus-1/services/
  - systemd user units from ~/.config/systemd/user/

FLAGS:
    --no-systemd    Do not remove/disable systemd user units

NOTES:
    Only removes files that rosec created. If gnome-keyring was masked,
    removing the mask file allows it to resume handling Secret Service
    requests via its system-wide D-Bus activation file."
    );
}
