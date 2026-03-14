//! Auto-update commands
//!
//! Handles checking for updates and installing them.

use serde::{Deserialize, Serialize};
use tauri::AppHandle;
use tauri_plugin_updater::UpdaterExt;

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub available: bool,
    pub version: Option<String>,
    pub notes: Option<String>,
    pub date: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateProgress {
    pub downloaded: u64,
    pub total: Option<u64>,
    pub percent: Option<f32>,
}

/// Check for available updates
#[tauri::command]
pub async fn check_for_updates(app: AppHandle) -> Result<UpdateInfo, String> {
    tracing::info!("Checking for updates...");

    let updater = app.updater().map_err(|e| format!("Failed to get updater: {}", e))?;
    
    match updater.check().await {
        Ok(Some(update)) => {
            tracing::info!("Update available: v{}", update.version);
            Ok(UpdateInfo {
                available: true,
                version: Some(update.version.clone()),
                notes: update.body.clone(),
                date: update.date.map(|d| d.to_string()),
            })
        }
        Ok(None) => {
            tracing::info!("No updates available");
            Ok(UpdateInfo {
                available: false,
                version: None,
                notes: None,
                date: None,
            })
        }
        Err(e) => {
            tracing::warn!("Failed to check for updates: {}", e);
            Err(format!("Failed to check for updates: {}", e))
        }
    }
}

/// Download and install an update
#[tauri::command]
pub async fn install_update(app: AppHandle) -> Result<(), String> {
    tracing::info!("Installing update...");

    let updater = app.updater().map_err(|e| format!("Failed to get updater: {}", e))?;
    
    let update = updater
        .check()
        .await
        .map_err(|e| format!("Failed to check for updates: {}", e))?
        .ok_or("No update available")?;

    tracing::info!("Downloading update v{}...", update.version);

    // Download the update
    let mut downloaded = 0;
    let bytes = update
        .download(
            |chunk_length, content_length| {
                downloaded += chunk_length;
                if let Some(total) = content_length {
                    let percent = (downloaded as f64 / total as f64) * 100.0;
                    tracing::debug!("Download progress: {:.1}%", percent);
                }
            },
            || {
                tracing::debug!("Download completed");
            },
        )
        .await
        .map_err(|e| format!("Failed to download update: {}", e))?;

    tracing::info!("Download complete, installing...");

    // Install the update (this will restart the app)
    update
        .install(bytes)
        .map_err(|e| format!("Failed to install update: {}", e))?;

    // Request app restart
    tracing::info!("Update installed, restarting...");
    app.restart();
    
    // Note: restart() doesn't return, but we need to satisfy the return type
    #[allow(unreachable_code)]
    Ok(())
}

/// Get current app version
#[tauri::command]
pub fn get_app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
