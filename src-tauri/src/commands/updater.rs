//! Auto-update commands
//!
//! The actual update check / download / install is driven from the frontend
//! via the Tauri updater plugin (`@tauri-apps/plugin-updater`), so the former
//! `check_for_updates` / `install_update` IPC wrappers were unused and have
//! been removed. Only the app-version helper remains.

/// Get current app version
#[tauri::command]
pub fn get_app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
