//! Auto-update commands
//!
//! P1-dk-updater-unpinned: the update check and the installer download used to
//! run through `@tauri-apps/plugin-updater`'s JavaScript API, which builds its
//! OWN reqwest client inside the plugin. That client is not certificate-pinned,
//! so the ONE network path that decides "are you allowed to keep running this
//! build" was the only path in the app a mis-issued certificate could sit on.
//! That was survivable while being out of date was cosmetic; it is not
//! survivable now that the backend hard-blocks clients below a version floor
//! (see `api::upgrade_gate`) — a forced-update policy whose update channel can
//! be silently suppressed is an attack surface, not a safety feature.
//!
//! So the check/download now run in Rust through
//! `UpdaterBuilder::configure_client`, which lets us hand the plugin the SAME
//! `api::cert_pin` verifier and the SAME pin set every other Birdo client path
//! uses (CA-chain SPKI pinning layered on top of full WebPKI validation).
//! There is no second pinning implementation and no unpinned fallback: if the
//! chain cannot be verified the TLS handshake fails and the check returns an
//! error — FAIL CLOSED, no update rather than an unverified update.
//!
//! The one wrinkle is that the updater's two requests do NOT go to the same
//! host. The manifest check hits `api.birdo.app`, which our pins cover. The
//! installer download goes wherever the manifest points, which today is a
//! GitHub release asset — a host our pins were never going to match, so
//! enforcing them there would fail EVERY install rather than securing any of
//! them. We therefore use `cert_pin::rustls_config_pinning_birdo_hosts_only()`:
//! the check (the leg a MITM would suppress) stays fully pinned, the download
//! gets full WebPKI validation, and the minisign signature on the bundle stays
//! the authority on what is allowed to run. That function's doc comment carries
//! the measured chains and the full reasoning.
//!
//! The webview's direct access to the plugin's own (unpinned) IPC commands is
//! revoked in `capabilities/default.json` — `updater:default` is gone — so the
//! unpinned path cannot be reached from the frontend at all.

use std::time::Duration;

use serde::Serialize;
use tauri::{AppHandle, Emitter};
use tauri_plugin_updater::UpdaterExt;

/// Event carrying installer download progress to the frontend.
pub const DOWNLOAD_PROGRESS_EVENT: &str = "updater-download-progress";

/// Get current app version
#[tauri::command]
pub fn get_app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// An available update, as reported to the frontend.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    pub version: String,
    pub current_version: String,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DownloadProgress {
    downloaded: u64,
    /// `None` when the server sent no Content-Length.
    content_length: Option<u64>,
}

/// Build an `Updater` whose HTTP client is the pinned one.
///
/// `configure_client` is applied to BOTH requests the plugin makes — the
/// manifest check and the installer download (the closure is carried into the
/// `Update` the check returns, `tauri-plugin-updater` 2.9.0) — so neither can
/// fall back to a client we did not configure. The verifier itself decides
/// which of the two is pin-checked; see the module docs. Errors are returned,
/// never swallowed.
fn pinned_updater(app: &AppHandle) -> Result<tauri_plugin_updater::Updater, String> {
    app.updater_builder()
        // Bound the request so a black-holing middlebox cannot park the UI in
        // "checking" forever; the frontend also races its own timeout.
        .timeout(Duration::from_secs(30))
        .configure_client(|builder| {
            builder
                // Plaintext HTTP would bypass the pin entirely; refuse it even
                // if a future config ever names an http:// endpoint.
                .https_only(true)
                .use_preconfigured_tls(
                    crate::api::cert_pin::rustls_config_pinning_birdo_hosts_only(),
                )
        })
        .build()
        .map_err(|e| format!("Updater unavailable: {e}"))
}

/// Check the pinned update endpoint. `Ok(None)` means "already up to date".
#[tauri::command]
pub async fn check_for_updates(app: AppHandle) -> Result<Option<UpdateInfo>, String> {
    let updater = pinned_updater(&app)?;
    match updater.check().await {
        Ok(Some(update)) => Ok(Some(UpdateInfo {
            version: update.version.clone(),
            current_version: update.current_version.clone(),
            notes: update.body.clone(),
        })),
        Ok(None) => Ok(None),
        Err(e) => {
            tracing::warn!("Update check failed: {e}");
            Err(format!("Update check failed: {e}"))
        }
    }
}

/// Download and install the available update.
///
/// The re-check that runs first goes to `api.birdo.app` and IS pin-checked. The
/// download that follows is validated by WebPKI plus the plugin's minisign
/// signature check on the downloaded bundle, which is unchanged and remains the
/// authority on what gets executed.
///
/// Emits [`DOWNLOAD_PROGRESS_EVENT`] as bytes arrive. Returns `Ok(false)` if the
/// re-check found nothing to install.
#[tauri::command]
pub async fn install_update(app: AppHandle) -> Result<bool, String> {
    let updater = pinned_updater(&app)?;
    let update = match updater.check().await {
        Ok(Some(update)) => update,
        Ok(None) => return Ok(false),
        Err(e) => {
            tracing::warn!("Update re-check before install failed: {e}");
            return Err(format!("Update check failed: {e}"));
        }
    };

    let progress_app = app.clone();
    let mut downloaded: u64 = 0;
    update
        .download_and_install(
            move |chunk_len, content_length| {
                downloaded = downloaded.saturating_add(chunk_len as u64);
                let _ = progress_app.emit(
                    DOWNLOAD_PROGRESS_EVENT,
                    DownloadProgress {
                        downloaded,
                        content_length,
                    },
                );
            },
            || tracing::info!("Update download finished — installing"),
        )
        .await
        .map_err(|e| {
            tracing::warn!("Update install failed: {e}");
            format!("Update failed: {e}")
        })?;

    Ok(true)
}
