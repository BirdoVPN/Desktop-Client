//! Utility modules

pub mod crash_report;
pub mod device_id;
pub mod elevation;
pub mod log_policy;
pub mod log_retention;
pub mod redact;

/// Source-level guard that no address-shaped value reaches a logging macro
/// unredacted. Test-only: it reads the tree rather than running in the app.
#[cfg(test)]
mod log_hygiene;

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

/// `hidden_cmd`'s async twin, for subprocesses run from async code (W1-017).
///
/// A `std::process::Command` awaited nowhere blocks a runtime worker for as
/// long as the child runs, and no `tokio::time::timeout` around it can fire.
/// Pair this with [`run_bounded`], which kills the child on timeout.
pub fn hidden_async_cmd(program: &str) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(program);
    #[cfg(target_os = "windows")]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// Run `cmd` to completion within `limit`. The child is killed if the limit
/// passes or the caller is cancelled (`kill_on_drop`), so nothing it does can
/// outlive the step that started it.
pub async fn run_bounded(
    cmd: &mut tokio::process::Command,
    limit: std::time::Duration,
) -> Result<std::process::Output, String> {
    cmd.kill_on_drop(true).stdin(std::process::Stdio::null());
    match tokio::time::timeout(limit, cmd.output()).await {
        Ok(result) => result.map_err(|e| e.to_string()),
        Err(_) => Err(format!("timed out after {limit:?}")),
    }
}

/// This install's device identifier: a random `desktop_<uuid-v4>`, persisted
/// per install and rotated on account deletion (not on sign-out). See
/// `utils::device_id` for why it is no longer derived from the machine.
///
/// This is the ONE device identity the desktop client presents — SSO handoff,
/// anonymous register/login, email+password login and every connect body send
/// this exact value, so every sign-in on this install lands on the same
/// `(userId, deviceId)` row in the account's device list. It survives an app
/// update and a restart (the file is read back), so the backend can reclaim
/// this install's own slot at connect time.
pub fn get_device_id() -> String {
    device_id::get()
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
/// plus a short prefix of the device id so a user with several machines can
/// still tell the rows apart. The backend already receives that id in full
/// beside this label, so the suffix transmits zero new information.
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
    // Skip the constant `desktop_` prefix, or every install would read
    // "(deskto)" and the suffix would stop telling machines apart.
    let random_part = id.strip_prefix("desktop_").unwrap_or(&id);
    let suffix: String = random_part.chars().take(6).collect();
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

#[cfg(test)]
mod bounded_process_tests {
    /// W1-017's test plan: a hung subprocess is cut off at the limit instead
    /// of pinning the caller for as long as it runs.
    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn a_hung_subprocess_is_cut_off_at_the_limit() {
        let started = std::time::Instant::now();
        let result = super::run_bounded(
            super::hidden_async_cmd("cmd.exe").args(["/c", "ping -n 30 127.0.0.1 >nul"]),
            std::time::Duration::from_secs(1),
        )
        .await;
        assert!(result.unwrap_err().contains("timed out"));
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }

    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn a_quick_subprocess_returns_its_output() {
        let out = super::run_bounded(
            super::hidden_async_cmd("cmd.exe").args(["/c", "echo birdo"]),
            std::time::Duration::from_secs(10),
        )
        .await
        .expect("cmd.exe runs");
        assert!(String::from_utf8_lossy(&out.stdout).contains("birdo"));
    }
}

#[cfg(test)]
mod device_name_tests {
    #[test]
    fn the_suffix_comes_from_the_random_part_of_the_id() {
        let name = super::get_device_name();
        assert!(!name.contains("deskto"), "{name}");
        let id = super::get_device_id();
        let expected: String = id.trim_start_matches("desktop_").chars().take(6).collect();
        assert!(name.ends_with(&format!("({expected})")), "{name} vs {id}");
    }
}
