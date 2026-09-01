//! Privilege checks for the desktop client.
//!
//! REALITY OF THE PRIVILEGE MODEL (do not trust older comments): the entire
//! Tauri app — webview, IPC, HTTP client, credential store — runs ELEVATED
//! (Administrator on Windows via the manifest, root on macOS/Linux). There is
//! no per-command elevation broker: a renderer/webview compromise is therefore
//! an Administrator/root compromise. The per-command `run_elevated()` helper
//! this module once carried was never called by any shipped code path (and its
//! Windows arm interpolated the program name into a PowerShell string); it was
//! removed in the 2026-08 dead-code sweep rather than left as a misleading
//! description of a trust boundary that does not exist.
//!
//! What remains is what the app actually uses: `is_elevated()` pre-flight
//! checks, and platform-appropriate copy for the "run elevated" error.

/// Platform-appropriate copy for the "you must run elevated" pre-flight error.
/// The old Windows-only wording ("right-click → Run as administrator") shipped
/// verbatim to Linux users, where it is meaningless.
pub fn elevation_required_message() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "Administrator privileges required. Please right-click the app \
         and select \"Run as administrator\", or restart from an elevated terminal."
    }
    #[cfg(target_os = "linux")]
    {
        "Root privileges required to manage the tunnel. Launch BirdoVPN \
         with pkexec or sudo (e.g. `sudo ./BirdoVPN.AppImage`)."
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        "Elevated privileges are required to manage the VPN tunnel. \
         Please restart the app with administrator rights."
    }
}

/// Check if the current process is running with elevated (admin) privileges.
pub fn is_elevated() -> bool {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Security::{
            GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        // SAFETY: Win32 API calls are used correctly here:
        // - GetCurrentProcess returns a pseudo-handle that does not need closing.
        // - OpenProcessToken with TOKEN_QUERY is read-only; the returned handle
        //   is closed in all paths (including GetTokenInformation error) via
        //   CloseHandle below.
        // - GetTokenInformation receives a properly-sized TOKEN_ELEVATION struct
        //   and return_length is checked implicitly by the Win32 API.
        // - No aliasing violations: token_handle and elevation are stack-local.
        unsafe {
            let mut token_handle = HANDLE::default();
            let process = GetCurrentProcess();

            if OpenProcessToken(process, TOKEN_QUERY, &mut token_handle).is_err() {
                return false;
            }

            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut return_length = 0u32;

            let result = GetTokenInformation(
                token_handle,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut return_length,
            );

            let _ = windows::Win32::Foundation::CloseHandle(token_handle);

            result.is_ok() && elevation.TokenIsElevated != 0
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        // On macOS/Linux, check if effective UID is 0 (root)
        // Use `id -u` command to avoid needing libc as a direct dependency
        std::process::Command::new("id")
            .args(["-u"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
            .unwrap_or(false)
    }
}
