//! Settings › About › Licences (MR-1685): the third-party notices every
//! package ships, generated at build time by
//! `scripts/generate-third-party-notices.mjs` from Cargo.lock,
//! package-lock.json and the bundled xray/wintun, and checked inside each
//! finished package by release.yml's post-bundle gates.

use tauri::path::BaseDirectory;
use tauri::{AppHandle, Manager};

use crate::commands::ipc_error::IpcError;

/// The file's place under the platform resource directory. tauri.conf.json
/// bundles the glob "resources/*" and keeps that relative path: the install
/// dir on Windows, Contents/Resources on macOS, /usr/lib/BirdoVPN on Linux.
const NOTICES_RESOURCE: &str = "resources/THIRD-PARTY-NOTICES.txt";

/// The notices text, for the Licences screen. Fails only in a build that
/// bundled none (a development build); the screen says so. A fixed name
/// under the app's own resource directory: nothing from the UI picks a path.
#[tauri::command]
pub async fn get_third_party_notices(app: AppHandle) -> Result<String, IpcError> {
    let path = app
        .path()
        .resolve(NOTICES_RESOURCE, BaseDirectory::Resource)
        .map_err(|e| IpcError::unknown(format!("No resource directory: {e}")))?;
    tokio::fs::read_to_string(&path).await.map_err(|e| {
        IpcError::unknown(format!(
            "The third-party notices are not in this build: {e}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::NOTICES_RESOURCE;

    /// The generator writes where the bundler picks files up, and where this
    /// command reads: a rename on one side would ship a package whose
    /// Licences screen is empty (the post-bundle gates check the same name).
    #[test]
    fn the_command_reads_what_the_generator_writes_and_the_bundle_ships() {
        let generator = include_str!("../../../scripts/generate-third-party-notices.mjs");
        assert!(generator.contains("path.join(tauriDir, 'resources', 'THIRD-PARTY-NOTICES.txt')"));
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../../tauri.conf.json")).unwrap();
        assert!(conf["bundle"]["resources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "resources/*"));
        assert_eq!(NOTICES_RESOURCE, "resources/THIRD-PARTY-NOTICES.txt");
    }
}
