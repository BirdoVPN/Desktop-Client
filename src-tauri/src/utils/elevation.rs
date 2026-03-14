#![allow(dead_code)]
//! Elevation helper for privileged operations (C-1 FIX)
//!
//! Instead of running the entire Tauri app as administrator, this module
//! provides a `run_elevated()` function that spawns individual commands
//! with elevated privileges via PowerShell `Start-Process -Verb RunAs`.
//!
//! This limits the attack surface: the webview, IPC, HTTP client, and
//! credential store all run unprivileged. Only specific netsh / route
//! commands that truly require admin are elevated.
//!
//! # Usage
//! ```rust,no_run,ignore
//! use crate::utils::elevation::{run_elevated, is_elevated};
//!
//! if !is_elevated() {
//!     run_elevated("netsh", &["advfirewall", "firewall", "add", "rule", ...])?;
//! }
//! ```

// Command::new replaced by super::hidden_cmd() for CREATE_NO_WINDOW

/// Check if the current process is running with elevated (admin) privileges.
pub fn is_elevated() -> bool {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Security::{
            GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        use windows::Win32::Foundation::HANDLE;

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
        false
    }
}

/// Run a command with elevated privileges.
///
/// If the process is already elevated, runs the command directly.
/// Otherwise, uses PowerShell `Start-Process -Verb RunAs` to request UAC.
///
/// Returns the combined stdout + stderr output.
pub fn run_elevated(program: &str, args: &[&str]) -> Result<String, String> {
    if is_elevated() {
        // Already elevated — run directly
        let output = super::hidden_cmd(program)
            .args(args)
            .output()
            .map_err(|e| format!("Failed to run {}: {}", program, e))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() && !stderr.is_empty() {
            tracing::debug!("Elevated command stderr: {}", stderr);
        }

        return Ok(format!("{}{}", stdout, stderr));
    }

    // Not elevated — use PowerShell to spawn with RunAs
    let args_str = args.iter()
        .map(|a| format!("'{}'", a.replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(", ");

    let ps_command = format!(
        "Start-Process -FilePath '{}' -ArgumentList {} -Verb RunAs -Wait -WindowStyle Hidden -PassThru | Select-Object -ExpandProperty ExitCode",
        program,
        args_str
    );

    tracing::debug!("Elevating command: {} {}", program, args.join(" "));

    let output = super::hidden_cmd("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps_command])
        .output()
        .map_err(|e| format!("Failed to elevate {}: {}", program, e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(format!("Elevated command failed: {}", stderr));
    }

    Ok(stdout)
}

/// Run a netsh command, elevating if necessary.
///
/// This is a convenience wrapper for the most common privilege-requiring operation.
pub fn run_netsh_elevated(args: &[&str]) -> Result<(), String> {
    if is_elevated() {
        // Already elevated — run directly
        let output = super::hidden_cmd("netsh")
            .args(args)
            .output()
            .map_err(|e| format!("Failed to run netsh: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("No rules match") && !stderr.contains("was not found") {
                tracing::debug!("netsh command note: {}", stderr);
            }
        }
        return Ok(());
    }

    // Not elevated — try direct first, elevate on access denied
    let output = super::hidden_cmd("netsh")
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run netsh: {}", e))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("requires elevation") || stderr.contains("access is denied") || stderr.contains("Access is denied") {
        tracing::info!("netsh requires elevation, requesting UAC...");
        run_elevated("netsh", args)?;
        Ok(())
    } else if stderr.contains("No rules match") || stderr.contains("was not found") {
        // Ignore "rule not found" errors when deleting
        Ok(())
    } else {
        Err(format!("netsh failed: {}", stderr))
    }
}
