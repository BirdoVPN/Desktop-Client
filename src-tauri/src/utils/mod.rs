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
