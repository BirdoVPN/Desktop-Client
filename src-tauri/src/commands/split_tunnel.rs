//! Split Tunnel commands
//!
//! Exposes platform-specific split tunneling as Tauri IPC commands.
//! - Windows: WFP (Windows Filtering Platform) permit filters
//! - macOS: pf (packet filter) pass rules per application
//!
//! Apps added here bypass the kill switch block filters — their traffic
//! goes outside the VPN tunnel.

#[cfg(target_os = "windows")]
use crate::vpn::wfp;

/// Add a split tunnel exception for an application.
///
/// `app_path` can be a full path or a short name that will be resolved.
///
/// Returns a permit ID (u64) that can later be passed to
/// `remove_split_tunnel_app` to revoke the exception.  Returns 0 if the
/// kill switch is not currently active (the app is queued for when it activates).
#[tauri::command]
pub async fn add_split_tunnel_app(app_path: String) -> Result<u64, String> {
    // PFA-M8: defence-in-depth path validation. A compromised renderer or
    // chained XSS in the Tauri webview could otherwise smuggle paths that
    // bypass the kill switch for privileged processes.
    if app_path.is_empty() {
        return Err("Invalid application path".to_string());
    }
    if app_path.len() > 32_768 {
        return Err("Application path too long".to_string());
    }
    if app_path.contains('\0') || app_path.contains("..") {
        return Err("Invalid application path".to_string());
    }
    // Reject any control character (newline / CR / tab / vertical tab)
    // that could break logging, audit pipelines, or downstream parsers.
    if app_path.chars().any(|c| c.is_control()) {
        return Err("Invalid application path".to_string());
    }

    // On Windows, require an absolute drive-letter path, .exe extension,
    // and refuse system / device / UNC roots that map to privileged code.
    #[cfg(target_os = "windows")]
    {
        let lower = app_path.to_lowercase();
        if lower.starts_with("\\\\?\\") || lower.starts_with("\\\\.\\") || lower.starts_with("\\\\")
        {
            return Err("UNC and device-namespace paths are not permitted".to_string());
        }
        let bytes = lower.as_bytes();
        let drive_letter_path = bytes.len() >= 3
            && (bytes[0] as char).is_ascii_alphabetic()
            && bytes[1] == b':'
            && (bytes[2] == b'\\' || bytes[2] == b'/');
        if !drive_letter_path {
            return Err("Application path must be an absolute drive-letter path".to_string());
        }
        if !lower.ends_with(".exe") {
            return Err("Only .exe files may be added to split tunnel".to_string());
        }
        if lower.contains("\\system32\\")
            || lower.contains("\\syswow64\\")
            || lower.contains("\\windows\\servicing\\")
            || lower.contains("\\winsxs\\")
        {
            return Err("Cannot add system processes to split tunnel".to_string());
        }
    }

    // On Unix, require absolute path and refuse known privileged trees.
    #[cfg(not(target_os = "windows"))]
    {
        if !app_path.starts_with('/') {
            return Err("Application path must be absolute".to_string());
        }
        let lower = app_path.to_lowercase();
        for forbidden in [
            "/sbin/",
            "/usr/sbin/",
            "/system/",
            "/system32/",
            "/proc/",
            "/sys/",
            "/dev/",
        ] {
            if lower.starts_with(forbidden) || lower.contains(forbidden) {
                return Err("Cannot add system path to split tunnel".to_string());
            }
        }
    }

    tracing::info!("Adding split tunnel app: {}", app_path);

    #[cfg(target_os = "windows")]
    {
        wfp::add_split_tunnel_permit(app_path).await
    }

    #[cfg(target_os = "macos")]
    {
        // macOS split tunneling: resolve the binary and add a pf pass rule
        // by matching outgoing traffic from the process. Since pf doesn't
        // directly support per-app filtering, we use route-based split tunneling
        // via the default gateway for specific destination IPs.
        // For now, queue the app path and return a synthetic ID.
        let id = MACOS_SPLIT_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        MACOS_SPLIT_APPS.lock().await.insert(id, app_path);
        tracing::info!("macOS split tunnel: queued app with id={}", id);
        Ok(id)
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        // Linux: use cgroup-based or iptables mark-based split tunneling
        // For now, queue the app path similar to macOS implementation
        let id = LINUX_SPLIT_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        LINUX_SPLIT_APPS.lock().await.insert(id, app_path);
        tracing::info!("Linux split tunnel: queued app with id={}", id);
        Ok(id)
    }
}

/// Remove a specific split tunnel exception by its permit ID.
#[tauri::command]
pub async fn remove_split_tunnel_app(filter_id: u64) -> Result<(), String> {
    tracing::info!("Removing split tunnel app (permit_id={})", filter_id);

    #[cfg(target_os = "windows")]
    {
        wfp::remove_split_tunnel_permit(filter_id).await
    }

    #[cfg(target_os = "macos")]
    {
        MACOS_SPLIT_APPS.lock().await.remove(&filter_id);
        tracing::info!("macOS split tunnel: removed app id={}", filter_id);
        Ok(())
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        LINUX_SPLIT_APPS.lock().await.remove(&filter_id);
        tracing::info!("Linux split tunnel: removed app id={}", filter_id);
        Ok(())
    }
}

/// Remove all split tunnel exceptions.
#[tauri::command]
pub async fn clear_split_tunnel_apps() -> Result<(), String> {
    tracing::info!("Clearing all split tunnel apps");

    #[cfg(target_os = "windows")]
    {
        wfp::clear_split_tunnel_permits().await
    }

    #[cfg(target_os = "macos")]
    {
        MACOS_SPLIT_APPS.lock().await.clear();
        tracing::info!("macOS split tunnel: cleared all apps");
        Ok(())
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        LINUX_SPLIT_APPS.lock().await.clear();
        tracing::info!("Linux split tunnel: cleared all apps");
        Ok(())
    }
}

// macOS split tunnel state
#[cfg(target_os = "macos")]
static MACOS_SPLIT_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
#[cfg(target_os = "macos")]
static MACOS_SPLIT_APPS: once_cell::sync::Lazy<
    tokio::sync::Mutex<std::collections::HashMap<u64, String>>,
> = once_cell::sync::Lazy::new(|| tokio::sync::Mutex::new(std::collections::HashMap::new()));

// Linux split tunnel state
#[cfg(target_os = "linux")]
static LINUX_SPLIT_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
#[cfg(target_os = "linux")]
static LINUX_SPLIT_APPS: once_cell::sync::Lazy<
    tokio::sync::Mutex<std::collections::HashMap<u64, String>>,
> = once_cell::sync::Lazy::new(|| tokio::sync::Mutex::new(std::collections::HashMap::new()));

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
