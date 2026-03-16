//! Split Tunnel commands
//!
//! Exposes dynamic WFP split tunneling as Tauri IPC commands.
//! Apps added here bypass the kill switch block filters — their traffic
//! goes outside the VPN tunnel.

#[cfg(target_os = "windows")]
use crate::vpn::wfp;

/// Add a split tunnel exception for an application.
///
/// `app_path` can be a full path (`C:\...\chrome.exe`) or a short name
/// (`chrome.exe`) that will be resolved via `where.exe` / common install dirs.
///
/// Returns a permit ID (u64) that can later be passed to
/// `remove_split_tunnel_app` to revoke the exception.  Returns 0 if the
/// kill switch is not currently active (the app is queued for when it activates).
#[tauri::command]
pub async fn add_split_tunnel_app(app_path: String) -> Result<u64, String> {
    tracing::info!("Adding split tunnel app: {}", app_path);

    #[cfg(target_os = "windows")]
    {
        wfp::add_split_tunnel_permit(app_path).await
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = app_path;
        Err("Split tunneling is only supported on Windows".to_string())
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

    #[cfg(not(target_os = "windows"))]
    {
        let _ = filter_id;
        Err("Split tunneling is only supported on Windows".to_string())
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

    #[cfg(not(target_os = "windows"))]
    Err("Split tunneling is only supported on Windows".to_string())
}
