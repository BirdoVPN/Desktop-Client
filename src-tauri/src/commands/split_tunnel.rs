//! Split Tunnel commands
//!
//! Exposes the installed-app picker used by the split-tunnel settings UI.
//!
//! The actual split-tunnel bypass is applied at connect time from saved
//! settings via `wfp::set_split_tunnel_apps` (Windows only) — see
//! `commands::vpn::apply_vpn_settings`. The per-app add/remove/clear IPC
//! commands were never wired into the UI and have been removed; this module now
//! only enumerates installed apps for the picker.

/// An installed application discovered for the split-tunnel picker.
#[derive(serde::Serialize)]
pub struct InstalledApp {
    pub name: String,
    /// Full path to the application's executable.
    pub path: String,
}

/// Enumerate installed applications for the split-tunnel "choose an app" picker.
///
/// On Windows this reads `DisplayName` + an executable path from the standard
/// uninstall registry hives (HKLM 64/32-bit + HKCU). It is best-effort and
/// read-only: any unreadable key is skipped and the whole call returns an empty
/// list rather than erroring. Only apps with a real, existing `.exe` outside the
/// Windows/system trees are returned (those can't be split-tunnelled anyway),
/// de-duplicated and sorted by name. The UI stores the FULL PATH, which
/// `resolve_app_path()` accepts directly (more reliable than a bare name).
#[tauri::command]
pub fn list_installed_apps() -> Result<Vec<InstalledApp>, String> {
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
        use winreg::RegKey;

        const UNINSTALL: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
        const UNINSTALL_WOW: &str =
            "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

        let roots: [(RegKey, &str); 3] = [
            (RegKey::predef(HKEY_LOCAL_MACHINE), UNINSTALL),
            (RegKey::predef(HKEY_LOCAL_MACHINE), UNINSTALL_WOW),
            (RegKey::predef(HKEY_CURRENT_USER), UNINSTALL),
        ];

        let mut seen = std::collections::HashSet::new();
        let mut out: Vec<InstalledApp> = Vec::new();

        for (root, sub) in roots {
            let Ok(uninstall) = root.open_subkey_with_flags(sub, KEY_READ) else {
                continue;
            };
            for entry in uninstall.enum_keys().flatten() {
                let Ok(app) = uninstall.open_subkey_with_flags(&entry, KEY_READ) else {
                    continue;
                };
                let name: String = match app.get_value("DisplayName") {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                let name = name.trim().to_string();
                if name.is_empty() {
                    continue;
                }
                // Skip OS components and update/patch entries.
                if app.get_value::<u32, _>("SystemComponent").unwrap_or(0) == 1 {
                    continue;
                }
                if app.get_value::<String, _>("ParentKeyName").is_ok() {
                    continue;
                }
                let Some(path) = exe_from_app_key(&app) else {
                    continue;
                };
                let lower = path.to_lowercase();
                if !lower.ends_with(".exe")
                    || lower.contains("\\system32\\")
                    || lower.contains("\\syswow64\\")
                    || lower.contains("\\windows\\")
                    || lower.contains("\\winsxs\\")
                {
                    continue;
                }
                if !std::path::Path::new(&path).exists() {
                    continue;
                }
                if !seen.insert(lower) {
                    continue;
                }
                out.push(InstalledApp { name, path });
            }
        }
        out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        Ok(out)
    }

    #[cfg(not(target_os = "windows"))]
    {
        Ok(Vec::new())
    }
}

/// Extract a usable `.exe` path from an uninstall key's `DisplayIcon`
/// (e.g. `"C:\\App\\app.exe,0"` → `C:\\App\\app.exe`).
#[cfg(target_os = "windows")]
fn exe_from_app_key(app: &winreg::RegKey) -> Option<String> {
    let icon: String = app.get_value("DisplayIcon").ok()?;
    let raw = icon.trim().trim_matches('"');
    // Strip a trailing ",<index>" icon selector if present.
    let candidate = match raw.rfind(',') {
        Some(idx) if !raw[idx + 1..].trim().is_empty()
            && raw[idx + 1..]
                .trim()
                .chars()
                .all(|c| c.is_ascii_digit() || c == '-') =>
        {
            &raw[..idx]
        }
        _ => raw,
    };
    let candidate = candidate.trim().trim_matches('"').to_string();
    if candidate.to_lowercase().ends_with(".exe") {
        Some(candidate)
    } else {
        None
    }
}
