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
//!
//! MR-1824: that GitHub download is also why a kill-switch block holds it on
//! macOS and Linux — see [`download_route`].

use std::time::Duration;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_updater::UpdaterExt;

use crate::commands::session::{connect_session, end_session, ConnectTarget, EndReason};
use crate::commands::tray::{restore_and_focus, set_tray_visible};
use crate::utils::redact::for_ipc;
use crate::vpn::AutoReconnectService;

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
        // retries DNS an older build left parked, if a teardown timed out.
        //
        // REVIEW-WIN-002: the hook runs BEFORE `ShellExecuteW` launches the
        // installer (tauri-plugin-updater 2.13.1, unchanged since 2.11.0,
        // updater.rs `install_inner`: extract → hook → ShellExecuteW → Err if
        // it failed, else exit(0)), so it must do nothing a failed launch
        // cannot undo. Setting the hook replaces the plugin's own, which is
        // `cleanup_before_exit()` (lib.rs): it DROPS every tray icon and hides
        // every window (tauri 2.12.0 app.rs, as in 2.11.5),
        // and when an antivirus quarantined the installer the process lived
        // on invisible, with the VPN already off. The tray is hidden instead
        // (no ghost icon after a real exit) and `install_update` shows it
        // again on failure; the window stays as it is until the exit.
        .on_before_exit(move || {
            #[cfg(target_os = "windows")]
            {
                let _ = exit_app
                    .state::<crate::vpn::VpnManager>()
                    .restore_dns_blocking();
            }
            set_tray_visible(&exit_app, false);
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
    check(&app).await.map_err(for_ipc)
}

async fn check(app: &AppHandle) -> Result<Option<UpdateInfo>, String> {
    let updater = pinned_updater(app)?;
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

/// What a failed install does about the VPN session it ended
/// (REVIEW-WIN-002).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reconnect {
    /// There was no session to put back.
    None,
    /// The UI offers Reconnect.
    Offered,
    /// Always-on: Rust is already reconnecting.
    Automatic,
}

/// `install_update`'s error: which stage failed, so the UI can say the right
/// thing — "could not be downloaded or verified" is false for an installer
/// that was verified and then failed to start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateFailure {
    /// `check_failed`, `download_failed`, `install_failed`, or
    /// [`HELD_BY_KILL_SWITCH`]: nothing was attempted, the download waits.
    pub code: &'static str,
    pub message: String,
    pub reconnect: Reconnect,
}

impl UpdateFailure {
    fn before_install(code: &'static str, message: String) -> Self {
        Self {
            code,
            message: for_ipc(message),
            reconnect: Reconnect::None,
        }
    }
}

/// `install_update`'s code for a download a kill-switch block holds back
/// (MR-1824). The UI says why it waits and starts it again by itself once the
/// status says the download can get out (`session/updater.ts`).
pub const HELD_BY_KILL_SWITCH: &str = "held_by_kill_switch";

/// How the installer download would leave the machine right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DownloadRoute {
    /// No block is up, or the block lets this app's HTTPS through (Windows).
    Open,
    /// A block is up and the tunnel carries the download through it: every
    /// block permits the tunnel's own interface, and the tunnel holds the
    /// default route.
    Tunnel,
    /// A block is up and nothing carries the download: it would be dropped.
    HeldByKillSwitch,
}

/// MR-1824: may the installer download start now?
///
/// The manifest's `url` is a GitHub release asset (github.com, redirected to
/// release-assets.githubusercontent.com — measured 2026-10-08 for
/// darwin-aarch64 and linux-x86_64 1.4.46). The Windows block permits this
/// executable's tcp/443 to any host (`app_permitted`), so it never holds
/// the download. The macOS and Linux blocks let root's tcp/443 reach ONLY
/// the control plane — the API and DoH addresses (`pf_policy`,
/// `iptables_policy`) — and they stay that narrow on purpose: permitting
/// GitHub's front and its CDN would let every root process on the machine
/// reach them from the real address, through exactly the window the kill
/// switch seals. So there the download waits for a tunnel to carry it, or
/// for the block to lift, instead of timing out as "could not be
/// downloaded".
fn download_route(app_permitted: bool, blocking: bool, tunnel_connected: bool) -> DownloadRoute {
    if !blocking || app_permitted {
        DownloadRoute::Open
    } else if tunnel_connected {
        DownloadRoute::Tunnel
    } else {
        DownloadRoute::HeldByKillSwitch
    }
}

/// After a failed install: put the session back automatically only where the
/// user asked never to be unprotected (always-on), offer it otherwise.
fn reconnect_after_failed_install(had_session: bool, always_on: bool) -> Reconnect {
    match (had_session, always_on) {
        (false, _) => Reconnect::None,
        (true, true) => Reconnect::Automatic,
        (true, false) => Reconnect::Offered,
    }
}

/// The install failed after the session was ended for it. Bring the app back
/// into view and decide about the session (REVIEW-WIN-002).
async fn recover_from_failed_install(
    app: &AppHandle,
    resume: Option<ConnectTarget>,
    error: String,
) -> UpdateFailure {
    set_tray_visible(app, true);
    restore_and_focus(app);
    let always_on = crate::commands::settings::load_settings_off_runtime(app)
        .await
        .map(|s| s.killswitch_enabled && s.lockdown_mode)
        .unwrap_or(false);
    let reconnect = reconnect_after_failed_install(resume.is_some(), always_on);
    if let (Reconnect::Automatic, Some(target)) = (reconnect, resume) {
        tracing::info!("Update install failed under always-on — reconnecting");
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            if let Err(e) = connect_session(&app, target).await {
                tracing::warn!("Reconnect after a failed update install failed: {}", e);
            }
        });
    }
    UpdateFailure {
        code: "install_failed",
        message: for_ipc(format!("Update failed: {error}")),
        reconnect,
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
/// REVIEW-WIN-002: an install that fails after that (an antivirus holding the
/// installer, say) brings the tray and the window back, says it was the
/// install that failed, and offers to reconnect — or, under always-on,
/// reconnects. The process only exits once the installer is running.
///
/// MR-1824: off Windows, while a kill-switch block is up and no tunnel
/// carries the download, nothing is attempted: the error is
/// [`HELD_BY_KILL_SWITCH`] ([`download_route`]).
///
/// Emits [`DOWNLOAD_PROGRESS_EVENT`] as bytes arrive. Returns `Ok(false)` if the
/// re-check found nothing to install.
#[tauri::command]
pub async fn install_update(app: AppHandle) -> Result<bool, UpdateFailure> {
    let tunnel_connected = app
        .state::<crate::vpn::VpnManager>()
        .get_state()
        .await
        .is_tunnel_active();
    let route = download_route(
        cfg!(target_os = "windows"),
        crate::commands::killswitch::platform_is_blocking(),
        tunnel_connected,
    );
    if route == DownloadRoute::HeldByKillSwitch {
        tracing::info!("Update download held: a kill-switch block is up and no tunnel carries it");
        return Err(UpdateFailure::before_install(
            HELD_BY_KILL_SWITCH,
            "The kill switch is blocking the update download".to_string(),
        ));
    }

    let updater =
        pinned_updater(&app).map_err(|e| UpdateFailure::before_install("check_failed", e))?;
    let update = match updater.check().await {
        Ok(Some(update)) => update,
        Ok(None) => return Ok(false),
        Err(e) => {
            tracing::warn!("Update re-check before install failed: {e}");
            return Err(UpdateFailure::before_install(
                "check_failed",
                format!("Update check failed: {e}"),
            ));
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
            UpdateFailure::before_install("download_failed", format!("Update failed: {e}"))
        })?;

    // The session the install is about to end, so a failed install can put
    // it back. Present exactly while a session is being kept or recovered.
    let resume = app
        .state::<AutoReconnectService>()
        .current_info()
        .await
        .map(|info| ConnectTarget::of(&info));
    end_session(&app, EndReason::Update).await;

    if let Err(e) = update.install(bundle) {
        tracing::warn!("Update install failed: {e}");
        return Err(recover_from_failed_install(&app, resume, e.to_string()).await);
    }

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

    /// REVIEW-WIN-002: the exit hook runs before the installer is launched, so
    /// it must not do what a failed launch cannot undo: Tauri's
    /// `cleanup_before_exit` drops the tray and hides the window.
    #[test]
    fn the_exit_hook_only_does_what_a_failed_install_can_undo() {
        let source = include_str!("updater.rs");
        let hook = &source[source.find(".on_before_exit(move || {").unwrap()..];
        let hook = &hook[..hook.find("        })").unwrap()];
        assert!(
            !hook.contains(&["cleanup", "_before_exit()"].concat()),
            "the hook drops the tray again"
        );
        assert!(!hook.contains(".hide()"), "the hook hides the window");
        assert!(hook.contains("set_tray_visible(&exit_app, false)"));
        assert!(hook.contains("restore_dns_blocking()"));
    }

    /// REVIEW-WIN-002: a failed install brings the app back into view before
    /// it reports, and is reported as an INSTALL failure.
    #[test]
    fn a_failed_install_restores_the_app_and_says_so() {
        let source = include_str!("updater.rs");
        let body = &source[source
            .find("async fn recover_from_failed_install(")
            .unwrap()..];
        let body = &body[..body.find("\n}").unwrap()];
        let shown = body.find("set_tray_visible(app, true)").expect("tray back");
        let focused = body.find("restore_and_focus(app)").expect("window back");
        let code = body.find("\"install_failed\"").expect("install_failed");
        assert!(shown < code && focused < code);

        let install = &source[source.find("pub async fn install_update(").unwrap()..];
        assert!(install.contains("recover_from_failed_install(&app, resume"));
    }

    /// MR-1824: off Windows a block holds the download unless the tunnel
    /// carries it; Windows (which permits the app) and no block never hold it.
    #[test]
    fn a_kill_switch_block_holds_the_download_until_a_tunnel_carries_it() {
        use super::{download_route, DownloadRoute::*};
        // (app permitted through the block, blocking, tunnel connected)
        let unix = false;
        assert_eq!(download_route(unix, true, false), HeldByKillSwitch);
        assert_eq!(download_route(unix, true, true), Tunnel);
        assert_eq!(download_route(unix, false, false), Open);
        assert_eq!(download_route(unix, false, true), Open);
        let windows = true;
        for (blocking, tunnel) in [(true, false), (true, true), (false, false), (false, true)] {
            assert_eq!(download_route(windows, blocking, tunnel), Open);
        }
    }

    /// MR-1824: the hold is decided before anything goes on the wire, from
    /// the platform's block and the tunnel, and reported as its own stage.
    #[test]
    fn the_hold_comes_before_the_re_check_and_the_download() {
        let source = include_str!("updater.rs");
        let body = &source[source.find("pub async fn install_update(").unwrap()..];
        let body = &body[..body.find("\n}").unwrap()];
        let route = body.find("download_route(").expect("route");
        let held = body.find("HELD_BY_KILL_SWITCH").expect("held");
        let check = body.find("updater.check()").expect("re-check");
        let download = body.find(".download(").expect("download");
        assert!(route < held && held < check && check < download);
        assert!(body.contains("cfg!(target_os = \"windows\")"));
        assert!(body.contains("platform_is_blocking()"));
        assert!(body.contains(".is_tunnel_active()"));
        assert_eq!(super::HELD_BY_KILL_SWITCH, "held_by_kill_switch");
    }

    /// REVIEW-WIN-002: what a failed install does about the session it ended.
    #[test]
    fn a_failed_install_puts_the_session_back_as_the_user_asked() {
        use super::{reconnect_after_failed_install, Reconnect};
        assert_eq!(
            reconnect_after_failed_install(false, false),
            Reconnect::None
        );
        assert_eq!(reconnect_after_failed_install(false, true), Reconnect::None);
        assert_eq!(
            reconnect_after_failed_install(true, false),
            Reconnect::Offered
        );
        assert_eq!(
            reconnect_after_failed_install(true, true),
            Reconnect::Automatic
        );
    }

    /// The wire shape the UI parses (`session/updater.ts`).
    #[test]
    fn an_update_failure_serializes_its_stage_and_reconnect() {
        let failure = super::UpdateFailure {
            code: "install_failed",
            message: "Update failed: x".into(),
            reconnect: super::Reconnect::Offered,
        };
        assert_eq!(
            serde_json::to_value(&failure).unwrap(),
            serde_json::json!({
                "code": "install_failed",
                "message": "Update failed: x",
                "reconnect": "offered"
            })
        );
    }

    /// W1-038: the updater plugin (v2) reads only endpoints, pubkey, windows,
    /// the dangerous_* switches and, in 2.13.1, allowDowngrades and
    /// requireSignedVersion. The v1 `active` / `dialog` keys did nothing,
    /// while suggesting an update dialog that does not exist.
    #[test]
    fn the_updater_config_carries_only_keys_the_plugin_reads() {
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../../tauri.conf.json")).expect("tauri.conf.json");
        let updater = conf["plugins"]["updater"]
            .as_object()
            .expect("plugins.updater");
        let mut keys: Vec<&str> = updater.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["endpoints", "pubkey", "requireSignedVersion"]);
    }

    /// The update endpoint's response is not signed, only the artifact is. With
    /// `requireSignedVersion` the plugin also requires the signature's trusted
    /// comment, which the signature covers, to name the version the endpoint
    /// announced, so a forged response cannot pair a higher version number
    /// with an older, genuinely signed release. Without the flag a signature
    /// that names no version (every release up to 1.4.45) skips that check.
    ///
    /// The flag is enforced by the RUNNING app on the update it downloads
    /// (tauri-plugin-updater 2.13.1: `Update::download` -> `verify_signature`
    /// with the announced version), and this app takes only a strictly newer
    /// release: no custom version comparator, allowDowngrades off. So every
    /// update a build with the flag can take is a release signed by
    /// @tauri-apps/cli 2.12 or later, which writes `version:<x.y.z>` (the
    /// v1.4.46 signatures carry `version:1.4.46`; the v1.4.45 ones, CLI
    /// 2.11.4, carry none).
    ///
    /// Read through the plugin's own Config, so a misspelt key, which the
    /// plugin ignores without a word, fails here; and the CLI that signs the
    /// releases must be one that writes the version, or every update would be
    /// signed in a form this flag rejects.
    #[test]
    fn updates_must_carry_a_signature_bound_to_their_version() {
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../../tauri.conf.json")).expect("tauri.conf.json");
        let updater: tauri_plugin_updater::Config =
            serde_json::from_value(conf["plugins"]["updater"].clone())
                .expect("plugins.updater is a valid updater config");
        assert!(
            updater.require_signed_version,
            "plugins.updater.requireSignedVersion must be true"
        );
        assert!(
            !updater.allow_downgrades,
            "allowDowngrades lets an older release be installed, which is what the signed version guards against"
        );
        let comparator = ["version", "_comparator"].concat();
        assert!(!include_str!("../main.rs").contains(&comparator));
        assert!(!include_str!("updater.rs").contains(&comparator));

        let lock: serde_json::Value =
            serde_json::from_str(include_str!("../../../package-lock.json"))
                .expect("package-lock.json");
        let cli = lock["packages"]["node_modules/@tauri-apps/cli"]["version"]
            .as_str()
            .expect("@tauri-apps/cli in package-lock.json");
        let cli_version: Vec<u64> = cli
            .split(['.', '-', '+'])
            .take(3)
            .map(|part| part.parse().expect("numeric @tauri-apps/cli version"))
            .collect();
        assert!(
            cli_version >= vec![2, 12, 0],
            "@tauri-apps/cli {cli} signs updates without `version:`; requireSignedVersion would reject every one"
        );
    }
}
