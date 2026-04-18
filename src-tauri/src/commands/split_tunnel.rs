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
    // SEC FIX: Validate app_path before storing or passing to WFP/pf.
    // A compromised renderer could pass traversal sequences, null bytes,
    // or system paths (System32/lsass.exe) to bypass VPN kill-switch for
    // privileged processes — trivially defeating leak protection.
    if app_path.is_empty() || app_path.contains("..") || app_path.contains('\0') {
        return Err("Invalid application path".to_string());
    }

    // On Windows, block adding system process paths to split tunnel.
    // This prevents a compromised webview from routing DNS or system
    // traffic outside the VPN tunnel.
    #[cfg(target_os = "windows")]
    {
        let lower = app_path.to_lowercase();
        if lower.contains("system32") || lower.contains("syswow64") {
            return Err("Cannot add system processes to split tunnel".to_string());
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
