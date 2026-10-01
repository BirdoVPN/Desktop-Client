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

use crate::commands::session::{end_session, EndReason};

/// Event carrying installer download progress to the frontend.
pub const DOWNLOAD_PROGRESS_EVENT: &str = "updater-download-progress";

/// Get current app version
#[tauri::command]
pub fn get_app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// The forced-version-floor requirement, if the backend has already refused
/// this build (HTTP 426 — see `api::upgrade_gate`).
///
/// The gate normally reaches the UI via the `update-required` event, but a
/// client can be refused before the webview has mounted a listener (the very
/// first `get_auth_state` on launch, for instance), so the frontend also reads
/// this once at startup. Otherwise the wall would only appear after a second,
/// pointless refused request.
#[tauri::command]
pub fn get_required_update() -> Option<crate::api::upgrade_gate::RequiredUpdate> {
    crate::api::upgrade_gate::required_update()
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
    let exit_app = app.clone();
    app.updater_builder()
        // W1-004 backstop. On Windows `install()` runs this hook and then
        // `std::process::exit(0)`, so no exit teardown can follow it.
        // `install_update` ends the session BEFORE installing; this only
        // retries DNS an older build left parked, if a teardown timed out. Setting
        // the hook replaces the plugin's own, so its cleanup is kept here.
        .on_before_exit(move || {
            #[cfg(target_os = "windows")]
            {
                use tauri::Manager;
                let _ = exit_app
                    .state::<crate::vpn::VpnManager>()
                    .restore_dns_blocking();
            }
            exit_app.cleanup_before_exit();
        })
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
/// W1-004: download, END THE SESSION, then install. On Windows the plugin's
/// install launches the installer and calls `std::process::exit(0)`: no
/// `RunEvent::ExitRequested`, so no exit teardown ever ran. Every in-app update
/// while connected left the machine state of the session behind for the
/// whole install, the server peer held, and xray running with its file locked
/// against the installer. The download is verified before anything is torn
/// down, so a failed download leaves the session alone.
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
    let bundle = update
        .download(
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
            || tracing::info!("Update downloaded and verified — ending the session to install"),
        )
        .await
        .map_err(|e| {
            tracing::warn!("Update download failed: {e}");
            format!("Update failed: {e}")
        })?;

    end_session(&app, EndReason::Update).await;

    update.install(bundle).map_err(|e| {
        tracing::warn!("Update install failed: {e}");
        format!("Update failed: {e}")
    })?;

    Ok(true)
}

#[cfg(test)]
mod tests {
    /// W1-004: the session ends between the verified download and the install
    /// (which exits the process on Windows); never a combined
    /// download-and-install that skips it.
    #[test]
    fn the_session_ends_between_download_and_install() {
        let source = include_str!("updater.rs");
        let body = &source[source.find("pub async fn install_update(").unwrap()..];
        let body = &body[..body.find("\n}").unwrap()];
        let download = body.find(".download(").expect("download");
        let teardown = body
            .find("end_session(&app, EndReason::Update)")
            .expect("teardown");
        let install = body.find("update.install(bundle)").expect("install");
        assert!(download < teardown && teardown < install);
        assert!(!body.contains(&["download", "_and_install"].concat()));
    }

    /// W1-038: the updater plugin (v2) reads only endpoints, pubkey, windows
    /// and the dangerous_* switches. The v1 `active` / `dialog` keys did
    /// nothing, while suggesting an update dialog that does not exist.
    #[test]
    fn the_updater_config_carries_only_keys_the_plugin_reads() {
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../../tauri.conf.json")).expect("tauri.conf.json");
        let updater = conf["plugins"]["updater"]
            .as_object()
            .expect("plugins.updater");
        let mut keys: Vec<&str> = updater.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["endpoints", "pubkey"]);
    }
}
