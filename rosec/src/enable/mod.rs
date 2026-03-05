//! `rosec enable` / `rosec disable` — manage D-Bus activation + systemd unit files.
//!
//! Template files live alongside this module in `templates/` and are embedded
//! at compile time via [`include_str!`].  Templates containing `@@ROSECD@@`
//! have that placeholder replaced with the resolved absolute path to `rosecd`.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

// ---------------------------------------------------------------------------
// Embedded templates (compile-time)
// ---------------------------------------------------------------------------

const TEMPLATE_SERVICE: &str = include_str!("templates/rosecd.service");
const TEMPLATE_SOCKET: &str = include_str!("templates/rosecd.socket");
const TEMPLATE_DBUS_SECRETS: &str = include_str!("templates/org.freedesktop.secrets.service");
const TEMPLATE_DBUS_KEYRING_MASK: &str = include_str!("templates/org.gnome.keyring.service");

/// Placeholder in templates replaced with the resolved `rosecd` binary path.
const ROSECD_PLACEHOLDER: &str = "@@ROSECD@@";

// ---------------------------------------------------------------------------
// File names we manage
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Template rendering
// ---------------------------------------------------------------------------

/// Render a template by replacing `@@ROSECD@@` with the binary path.
fn render(template: &str, rosecd: &Path) -> String {
    template.replace(ROSECD_PLACEHOLDER, &rosecd.display().to_string())
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/// Return `~/.local/share/dbus-1/services/`.
fn user_dbus_services_dir() -> Result<PathBuf> {
    let data_home = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| String::from("/tmp"));
            PathBuf::from(home).join(".local/share")
        });
    Ok(data_home.join("dbus-1/services"))
}

/// Return `~/.config/systemd/user/`.
fn user_systemd_dir() -> Result<PathBuf> {
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
        .filter(|(_, path)| Path::new(path).exists())
        .copied()
        .collect()
}

// ---------------------------------------------------------------------------
// File utilities
// ---------------------------------------------------------------------------

/// Write a file, creating parent directories as needed. Returns `Ok(true)` if
/// written, `Ok(false)` if the file already has identical contents (skip).
fn install_file(path: &Path, contents: &str) -> Result<bool> {
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
fn remove_file_if_exists(path: &Path) -> Result<bool> {
    if path.exists() {
        std::fs::remove_file(path)
            .map_err(|e| anyhow::anyhow!("failed to remove {}: {e}", path.display()))?;
        Ok(true)
    } else {
        Ok(false)
    }
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

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// `rosec enable [flags]`
pub fn cmd_enable(args: &[String]) -> Result<()> {
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

    let contents = render(TEMPLATE_DBUS_SECRETS, &rosecd);
    if install_file(&secrets_path, &contents)? {
        println!("installed {}", secrets_path.display());
    } else {
        println!("unchanged {}", secrets_path.display());
    }

    // Write gnome-keyring mask (unless --no-mask).
    if !no_mask {
        let has_gnome_keyring = existing.iter().any(|(n, _)| *n == "gnome-keyring");
        if has_gnome_keyring || force {
            if install_file(&keyring_path, TEMPLATE_DBUS_KEYRING_MASK)? {
                println!("installed {} (masks gnome-keyring)", keyring_path.display());
            } else {
                println!("unchanged {}", keyring_path.display());
            }
        }
    }

    // --- install systemd user units ------------------------------------------

    if enable_systemd {
        let svc_contents = render(TEMPLATE_SERVICE, &rosecd);
        if install_file(&service_path, &svc_contents)? {
            println!("installed {}", service_path.display());
        } else {
            println!("unchanged {}", service_path.display());
        }

        if install_file(&socket_path, TEMPLATE_SOCKET)? {
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
    println!();
    println!("Note: the D-Bus mask prevents future auto-activation of competing providers,");
    println!("but cannot stop one that is already running (e.g. started by your compositor");
    println!("autostart config). If another Secret Service daemon is running, remove it");
    println!("from your autostart and log out/in for rosec to take effect.");
    Ok(())
}

/// `rosec disable [flags]`
pub fn cmd_disable(args: &[String]) -> Result<()> {
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

// ---------------------------------------------------------------------------
// Help text
// ---------------------------------------------------------------------------

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
