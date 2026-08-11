//! Utility modules

pub mod elevation;
pub mod redact;

// elevation is scaffolding — used when specific operations need UAC elevation.
// Re-exports here for convenience.
#[cfg(target_os = "windows")]
#[allow(unused_imports)]
pub use elevation::run_netsh_elevated;
#[allow(unused_imports)]
pub use elevation::{is_elevated, run_elevated};
pub use redact::redact_email;
pub use redact::redact_endpoint;
pub use redact::redact_ip;

/// Create a `std::process::Command` that runs hidden on Windows (no console popup).
///
/// On Windows, subprocesses launched from a GUI app inherit the parent's console
/// allocation. Since Birdo VPN runs as a GUI app with `#![windows_subsystem = "windows"]`,
/// every `Command::new("netsh" | "powershell" | "route" | ...)` would flash a visible
/// CMD window to the user. `CREATE_NO_WINDOW` (0x0800_0000) suppresses this.
///
/// On non-Windows platforms, this returns a plain `Command`.
pub fn hidden_cmd(program: &str) -> std::process::Command {
    let mut cmd = std::process::Command::new(program);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// Generate a stable, anonymous device identifier.
/// Uses SHA-256 of the hostname + OS family + username for a non-reversible but consistent ID.
///
/// This is the ONE device identity the desktop client presents — SSO handoff,
/// anonymous register/login and email+password login all send this exact value,
/// so every sign-in on a machine lands on the same `(userId, deviceId)` row in
/// the account's device list. Deliberately derived from install-invariant facts
/// only (no app version, no random seed, nothing written to disk): it must
/// survive an app update, a reinstall and a restart, otherwise the backend
/// creates a fresh device row each time and per-device revocation can no longer
/// target the machine the user means.
pub fn get_device_id() -> String {
    use sha2::{Digest, Sha256};

    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let mut hasher = Sha256::new();
    hasher.update(hostname.as_bytes());
    hasher.update(b"|");
    hasher.update(std::env::consts::OS.as_bytes());
    hasher.update(b"|");
    hasher.update(std::env::var("USERNAME").unwrap_or_default().as_bytes());

    hex::encode(hasher.finalize())
}

/// Human-readable name for this machine, shown in the account's device list
/// ("Revoke Windows Desktop (a1b2c3)"). Lives here next to `get_device_id`
/// because every auth payload that carries the id also carries this label —
/// they have to be derived from the same place or a login can relabel the row
/// a registration just named. `commands::vpn::get_device_name` delegates here.
///
/// SEC-PII: this used to be the raw machine hostname, which on consumer
/// Windows/macOS routinely embeds the owner's real name ("Johns-MacBook-Pro"),
/// converting a pseudonymous (or anonymous-plan) account into a named one on
/// every connect and auth call. Now a generic platform label — the shape
/// Android already uses (Build.MANUFACTURER + MODEL, never the hostname) —
/// plus a short prefix of the SHA-256 device id so a user with several
/// machines can still tell the rows apart. The backend already receives that
/// id in full beside this label, so the suffix transmits zero new information.
pub fn get_device_name() -> String {
    let platform = if cfg!(target_os = "macos") {
        "Mac Desktop"
    } else if cfg!(target_os = "linux") {
        "Linux Desktop"
    } else if cfg!(target_os = "windows") {
        "Windows Desktop"
    } else {
        "Desktop"
    };
    let id = get_device_id();
    let suffix: String = id.chars().take(6).collect();
    format!("{} ({})", platform, suffix)
}

/// This build's value for the backend `platform` enum
/// (WINDOWS | MACOS | LINUX | IOS | ANDROID | UNKNOWN).
///
/// The backend only infers the platform from the User-Agent for mobile; a
/// desktop body that omits the field is stored as UNKNOWN. Every desktop auth
/// payload therefore sends it explicitly, from this single mapping, so login
/// and anonymous registration can never disagree about what this machine is.
pub fn device_platform() -> &'static str {
    match std::env::consts::OS {
        "windows" => "WINDOWS",
        "macos" => "MACOS",
        "linux" => "LINUX",
        _ => "UNKNOWN",
    }
}
