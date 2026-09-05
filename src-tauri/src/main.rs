//! Birdo VPN Desktop Client
//!
//! Main entry point for the Tauri application.
//! Handles window management, system tray, and IPC commands.
//! Supports Windows, macOS, and Linux.

// FIX-R11: Hide console window in release builds (Windows only)
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod api;
mod commands;
mod storage;
mod utils;
mod vpn;

use api::BirdoApi;
use storage::CredentialStore;
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, Listener, LogicalPosition, Manager, RunEvent, WindowEvent,
};
use tracing::{debug, error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};
use vpn::{AutoReconnectService, VpnManager};

/// Exit-teardown state machine. pf rulesets and iptables chains SURVIVE
/// process exit — unlike Windows WFP dynamic sessions, which self-clean — so
/// quitting without a teardown left macOS/Linux without IPv6 after a normal
/// session, or with NO network at all if the quit landed while the kill switch
/// was blocking (e.g. mid-reconnect), with nothing pointing at the VPN client.
///
/// STARTED guards the teardown from running twice; DONE is what lets the exit
/// we re-request after teardown pass through instead of looping back in.
static EXIT_TEARDOWN_STARTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static EXIT_TEARDOWN_DONE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Best-effort teardown run while an exit request is held open: stop
/// auto-reconnect, bring the tunnel down (routes/DNS/IPv6 restore) and disarm
/// the kill switch. Every step is capped so quitting can never hang.
async fn teardown_for_exit(app: &tauri::AppHandle) {
    use std::time::Duration;

    // Quit is user intent: neutralize auto-reconnect first so it cannot race
    // the teardown and bring the tunnel (and kill-switch arming) back up.
    let auto_reconnect = app.state::<AutoReconnectService>();
    auto_reconnect.set_user_disconnected();
    auto_reconnect.stop().await;

    let vpn_manager = app.state::<VpnManager>();
    vpn_manager.set_user_disconnected(true);

    // Stop the Xray stealth transport if it is running.
    app.state::<crate::vpn::xray::XrayManager>().stop().await;

    // Free the server-side peer while the tunnel is still up (mirrors
    // disconnect_vpn). Courtesy call — tightly capped, never stalls the exit.
    if let Some(key_id) = vpn_manager.get_key_id().await {
        let api = app.state::<BirdoApi>();
        match tokio::time::timeout(Duration::from_secs(3), api.disconnect_vpn(&key_id)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => info!("Exit teardown: backend disconnect notify failed: {}", e),
            Err(_) => info!("Exit teardown: backend disconnect notify timed out"),
        }
    }

    // Tunnel teardown: routes, DNS restore, session IPv6 leak block. Inner cap
    // so a hung stop can never starve the disarm below out of running — the
    // disarm is the piece whose absence outlives the process.
    match tokio::time::timeout(Duration::from_secs(6), vpn_manager.disconnect()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => error!("Exit teardown: tunnel disconnect failed: {}", e),
        Err(_) => error!("Exit teardown: tunnel disconnect timed out"),
    }

    // Disarm the kill switch UNCONDITIONALLY, exactly as disconnect_vpn does
    // (the 3e6f1e2 escape hatch): quitting IS the user ending the session, and
    // is_lockdown_mode() is hard false off-Windows, so any gate here would
    // leave macOS/Linux behind a kernel firewall with no running app to disarm
    // it. disarm() is a no-op if the switch was never armed.
    let _ = crate::commands::killswitch::disarm().await;
}

/// A birdo:// URL captured from the launch argv at cold start, held until the
/// frontend has mounted its "deep-link" listener and pulls it via
/// `take_pending_deep_link`. Emitting the event at `setup()` time would be lost
/// because the webview's listener is not attached until React mounts.
#[derive(Default)]
struct PendingDeepLink(std::sync::Mutex<Option<String>>);

/// Frontend calls this once on mount to retrieve (and clear) any deep link the
/// app was launched with. Returns None on a normal launch.
#[tauri::command]
fn take_pending_deep_link(pending: tauri::State<'_, PendingDeepLink>) -> Option<String> {
    pending.0.lock().ok().and_then(|mut g| g.take())
}

/// Bring the main window back to the foreground (tray click, "Show", quick
/// actions, deep link, single-instance relaunch, post-SSO). Emits "app-shown"
/// so the biometric app-lock can re-challenge after a close-to-tray.
fn restore_and_focus(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
        let _ = window.emit("app-shown", ());
    }
}

/// Surface the window and hand a birdo:// URL to the frontend router. Shared by
/// the runtime deep-link listener and the cold-start path.
fn deliver_deep_link(app: &tauri::AppHandle, url: &str) {
    // P6-CLI-D-03: a birdo:// URL carries the target server id, i.e. connection
    // history. Record the arrival at INFO, the payload only at debug.
    info!("Deep link received");
    debug!("Deep link received: {}", url);
    restore_and_focus(app);
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.emit("deep-link", url);
    }
}

fn main() {
    // Set custom panic hook for crash recovery
    setup_panic_hook();

    // Initialize logging.
    //
    // A release GUI build has no console attached, so the stdout fmt layer is
    // invisible in the field — connection failures were undiagnosable. We add a
    // second fmt layer that appends to <data_dir>/BirdoVPN/logs/birdo.log so the
    // real error (e.g. the raw /vpn/connect failure) is always recoverable from
    // disk. No new dependency: `dirs` + std::fs + a closure MakeWriter.
    let file_layer = dirs::data_dir().and_then(|mut p| {
        p.push("BirdoVPN");
        p.push("logs");
        std::fs::create_dir_all(&p).ok()?;
        p.push("birdo.log");
        // PWR-5: birdo.log is opened in append mode for the life of the
        // process, so a long-running session (this is a VPN client — it can
        // stay connected for weeks) grows it unbounded. A simple one-generation
        // rotation caps the damage: once the log has already grown past
        // MAX_LOG_BYTES, move it aside to birdo.log.1 (clobbering any older
        // one) before we start appending to a fresh file.
        rotate_log_if_large(&p);
        let mut open_opts = std::fs::OpenOptions::new();
        open_opts.create(true).append(true);
        // P6-CLI-D-08: the log records which VPN nodes were used and when —
        // keep it owner-readable only on multi-user Unix hosts. (Windows
        // relies on the per-user %APPDATA% ACL, same as the settings file.)
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open_opts.mode(0o600);
        }
        let file = open_opts.open(&p).ok()?;
        Some(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                // Resilient writer: a per-write try_clone() can fail (FD
                // exhaustion, transient OS error). Panicking here would take
                // down the whole process from inside the logging path — and
                // possibly before earlier logs are flushed. Degrade gracefully
                // by dropping that single log line (io::sink) instead.
                //
                // PWR-5 addendum: rotate_log_if_large only runs at startup, so a
                // weeks-long session used to grow birdo.log without bound. Hard
                // in-session cap: once the file passes 2x MAX_LOG_BYTES, drop
                // further lines (the next launch rotates it aside). A stat per
                // log event at info level is negligible.
                .with_writer(move || -> Box<dyn std::io::Write> {
                    if file
                        .metadata()
                        .map(|m| m.len() > 2 * MAX_LOG_BYTES)
                        .unwrap_or(false)
                    {
                        return Box::new(std::io::sink());
                    }
                    match file.try_clone() {
                        Ok(f) => Box::new(f),
                        Err(_) => Box::new(std::io::sink()),
                    }
                })
                // CLAMP THE PERSISTENT LOG. The redaction strategy leans on
                // "debug never ships": `redact_ip`/`redact_hostname` are
                // pass-throughs under `debug_assertions`, and several
                // connection-history lines are DEMOTED to debug rather than
                // redacted (the node name in manager.rs, the deep-link URL
                // above). `RUST_LOG` is read from the environment below and
                // overrides the default filter for the WHOLE subscriber, so
                // anything able to set an environment variable for this process
                // — a shortcut, a scheduled task, a support instruction copied
                // off a forum — turned birdo.log into a durable record of which
                // exit node was used and when. A per-layer filter fixes that at
                // the sink rather than at the call site: the console layer still
                // honours RUST_LOG in full, the append-only FILE never takes
                // anything below the level this build is allowed to persist.
                .with_filter(crate::utils::log_policy::file_log_max_level()),
        )
    });

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| {
                // PWR-5: the filter used to default to `debug` unconditionally,
                // including in release builds — every user's machine logging at
                // debug verbosity to disk forever. `RUST_LOG` still overrides
                // this for anyone who needs verbose field diagnostics.
                let level = if cfg!(debug_assertions) {
                    "debug"
                } else {
                    "info"
                };
                if cfg!(target_os = "windows") {
                    format!("birdo_vpn_desktop={level},wintun=info,wintun_dll=info")
                } else {
                    format!("birdo_vpn_desktop={level}")
                }
            }),
        ))
        .with(tracing_subscriber::fmt::layer())
        .with(file_layer)
        .init();

    info!("Birdo VPN Client starting...");

    // Install ring as the process-level rustls CryptoProvider. Our own client
    // configs select ring explicitly (see api/cert_pin.rs), but library code we
    // don't control (e.g. the updater plugin's reqwest) may build rustls configs
    // from the process default — and with BOTH `ring` and `aws-lc-rs` features
    // present in the dependency graph (sentry 0.48 enables aws-lc), rustls
    // panics rather than guessing. Installing a default removes that ambiguity.
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        tracing::warn!("rustls CryptoProvider was already installed — continuing");
    }

    // Initialize Sentry crash reporting (release builds only).
    // The DSN is public — it only identifies the project. The guard must
    // live for the entire process so panics / crashes are flushed before exit.
    let _sentry_guard = sentry::init((
        option_env!("SENTRY_DSN").unwrap_or(""),
        sentry::ClientOptions {
            release: Some(std::borrow::Cow::Borrowed(env!("CARGO_PKG_VERSION"))),
            environment: if cfg!(debug_assertions) {
                Some("development".into())
            } else {
                Some("production".into())
            },
            // Scrub PII: no usernames, IPs, or email in breadcrumbs
            send_default_pii: false,
            // SEC-PII: the `contexts` integration fills a None server_name with
            // the machine hostname (`ContextIntegration::setup` only assigns
            // when `options.server_name.is_none()`), and consumer hostnames
            // routinely embed the owner's real name ("Johns-MacBook-Pro").
            // `send_default_pii: false` does NOT gate that path. A pre-set
            // value short-circuits it.
            server_name: Some("redacted".into()),
            // SEC-PII: sentry's `panic` integration chains AHEAD of our
            // sanitizing panic hook (it is installed later, at init time, so
            // it runs first and sees the raw payload). Scrub every
            // message-carrying field with the same redaction the local log
            // gets, at the last point before the event leaves the device.
            before_send: Some(std::sync::Arc::new(|event| {
                Some(scrub_sentry_event_pii(event))
            })),
            sample_rate: 1.0,
            ..Default::default()
        },
    ));

    // ── Self-elevation ──────────────────────────────────────────────────
    // Wintun adapter creation is an in-process FFI call that requires
    // administrator privileges. If we're not elevated, relaunch with
    // "runas" and exit this non-elevated instance.
    //
    // Only in production builds (custom-protocol feature). During development
    // with `tauri dev`, the elevated relaunch can't reconnect to the Vite
    // dev server. For dev: run your terminal as Administrator first.
    #[cfg(all(windows, feature = "custom-protocol"))]
    {
        use crate::utils::elevation::is_elevated;
        if !is_elevated() {
            info!("Not running as administrator — attempting self-elevation via ShellExecuteW");
            match self_elevate() {
                Ok(()) => {
                    info!("Elevated instance launched, exiting non-elevated instance");
                    std::process::exit(0);
                }
                Err(e) => {
                    error!(
                        "Self-elevation failed: {}. Continuing without admin — VPN will not work.",
                        e
                    );
                    // Continue anyway so the UI shows the error to the user
                }
            }
        } else {
            info!("Running with administrator privileges [OK]");
        }
    }

    // In dev mode, just log the elevation status
    #[cfg(all(windows, not(feature = "custom-protocol")))]
    {
        use crate::utils::elevation::is_elevated;
        if is_elevated() {
            info!("Running with administrator privileges [OK]");
        } else {
            error!(
                "[WARN] NOT running as administrator — VPN will fail. \
                 Run your terminal as Administrator and retry `npm run tauri dev`."
            );
        }
    }

    // Linux: TUN device creation requires root (or CAP_NET_ADMIN).
    // In production, the .deb/.AppImage should be launched via pkexec or
    // the binary should have CAP_NET_ADMIN capability set.
    #[cfg(target_os = "linux")]
    {
        use crate::utils::elevation::is_elevated;
        if is_elevated() {
            info!("Running with root privileges [OK]");
        } else {
            info!(
                "Not running as root — TUN creation will require pkexec elevation. \
                 For best experience, run with: sudo birdo-vpn, or set CAP_NET_ADMIN."
            );
        }
    }

    tauri::Builder::default()
        // MUST be the first plugin. A VPN client must never run twice — a second
        // process would fight the first over the WFP filters and the tunnel
        // adapter. On a relaunch we surface the existing window instead; the
        // "deep-link" feature auto-forwards any birdo:// argv to this instance's
        // deep-link handler (fixing warm-start deep links on Windows).
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            info!("Second instance launch intercepted — focusing the running window");
            restore_and_focus(app);
        }))
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_dialog::init())
        // Register application state
        .manage(BirdoApi::new())
        .manage(CredentialStore)
        .manage(VpnManager::new())
        .manage(crate::vpn::xray::XrayManager::new())
        .manage(PendingDeepLink::default())
        .setup(|app| {
            info!("Setting up Birdo VPN application...");

            // Give the forced-version-floor gate a handle so a 426 from ANY
            // request can raise the blocking "update required" screen. Must be
            // set before the first API call is made below.
            crate::api::upgrade_gate::set_app_handle(app.handle().clone());

            // F-001/F-032: reconcile leak-protection state a previous run may have
            // left in the kernel. pf rulesets and ip6tables chains survive process
            // exit, so a crash, a SIGKILL or a power loss mid-session would
            // otherwise leave this host firewalled off or without IPv6 forever.
            // No tunnel can be up this early, so anything we find is stale.
            #[cfg(target_os = "macos")]
            crate::commands::killswitch::reconcile_stale_pf_state();
            #[cfg(target_os = "linux")]
            {
                crate::vpn::tunnel_linux::remove_ipv6_leak_block();
                // The v6 chain was reconciled here but BIRDO_KILLSWITCH was not —
                // and that is the one that blocks EVERYTHING. A SIGKILL or power
                // loss with the kill switch armed left the host with a
                // default-deny chain wired into OUTPUT/INPUT/FORWARD that nothing
                // ever removed: no internet at all, surviving restarts of the app,
                // with no indication the VPN client was responsible.
                //
                // Safe unconditionally at this point for the same reason the v6
                // reconcile is: no tunnel can be up this early, so any chain we
                // find is stale by definition. The chain name is ours alone.
                crate::vpn::firewall_linux::emergency_cleanup();
            }

            // The same reconcile, for DNS. The kernel-state arms above cannot
            // cover it: DNS is moved aside with netsh/networksetup/resolv.conf,
            // and the snapshot that says what to put back died with the process
            // that made the change. A SIGKILL, an OOM kill or a power cut never
            // reaches the panic hook at all, so this call is the only thing that
            // can heal them. Safe unconditionally for the same reason as the
            // arms above: no tunnel can be up this early, so a journal on disk
            // means exactly one thing — the previous session did not restore
            // DNS. Each platform still re-checks that the live state is the one
            // it left before touching anything.
            if crate::vpn::dns_journal::reconcile() {
                tracing::warn!("Restored DNS left moved aside by a previous session");
            }

            // Wire up AutoReconnectService with references to managed state.
            // BirdoApi and VpnManager use Arc<RwLock<..>> internally, so Clone
            // shares the same underlying state — exactly what we need.
            {
                let vpn_manager: VpnManager = app.state::<VpnManager>().inner().clone();
                let api: BirdoApi = app.state::<BirdoApi>().inner().clone();
                let auto_reconnect = AutoReconnectService::new(
                    std::sync::Arc::new(vpn_manager),
                    std::sync::Arc::new(api),
                );
                auto_reconnect.set_app_handle(app.handle().clone());
                app.manage(auto_reconnect);
                info!("Auto-reconnect service registered");
            }

            // Create system tray menu
            let quit = MenuItem::with_id(app, "quit", "Quit BirdoVPN", true, None::<&str>)?;
            let show = MenuItem::with_id(app, "show", "Show Window", true, None::<&str>)?;
            let connect = MenuItem::with_id(app, "connect", "Quick Connect", true, None::<&str>)?;
            let disconnect =
                MenuItem::with_id(app, "disconnect", "Disconnect", false, None::<&str>)?;

            let menu = Menu::with_items(app, &[&connect, &disconnect, &show, &quit])?;

            // Hold handles to the state-dependent menu items so `set_tray_state`
            // can enable/disable them as the connection state changes. Without
            // this, "Disconnect" (created disabled above) would stay permanently
            // greyed out and the tray Disconnect would never work.
            app.manage(commands::tray::TrayMenuItems {
                connect: connect.clone(),
                disconnect: disconnect.clone(),
            });

            // Build system tray. The icon starts in the "disconnected" state and
            // is updated live (icon + tooltip) by the `set_tray_state` command as
            // the connection state changes. The id "main" lets that command find
            // this tray via `app.tray_by_id("main")`.
            let tray_icon =
                commands::tray::load_tray_image(include_bytes!("../icons/tray-disconnected.png"))
                    .expect("embedded tray-disconnected.png is a valid image");
            let _tray = TrayIconBuilder::with_id("main")
                .icon(tray_icon)
                .menu(&menu)
                .show_menu_on_left_click(false)
                .tooltip("BirdoVPN - Disconnected")
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "quit" => {
                        // app.exit() raises RunEvent::ExitRequested, so this
                        // funnels through the same teardown (disconnect +
                        // kill-switch disarm) as every other exit path.
                        info!("User requested quit from tray");
                        app.exit(0);
                    }
                    "show" => {
                        restore_and_focus(app);
                    }
                    "connect" => {
                        info!("Quick connect triggered from tray");
                        // Surface the window first so the action is never silent —
                        // the connect executor (Dashboard) only exists once the user
                        // is past the login / consent / biometric-lock screens, and
                        // the tray click previously did nothing visible there.
                        restore_and_focus(app);
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.emit("tray-quick-connect", ());
                        }
                    }
                    "disconnect" => {
                        info!("Disconnect triggered from tray");
                        restore_and_focus(app);
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.emit("tray-disconnect", ());
                        }
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        restore_and_focus(tray.app_handle());
                    }
                })
                .build(app)?;

            // Pin the window to the top-left corner and show it. The window is
            // frameless (decorations:false) and has no drag regions, so it is
            // not movable by the user — we anchor it here once at startup.
            // Honor the "Start Minimized" setting: when enabled the app stays
            // in the tray (the tray click / "Show Window" item restores it).
            let start_minimized = commands::settings::load_settings_sync(&app.handle().clone())
                .map(|s| s.start_minimized)
                .unwrap_or(false);
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_position(LogicalPosition::new(0.0, 0.0));
                if start_minimized {
                    info!("start_minimized enabled — staying in tray");
                } else {
                    let _ = window.show();
                }
            }

            // Runtime deep links (birdo:// protocol) while the app is running.
            // On Windows these arrive via the single-instance "deep-link" feature
            // forwarding the second-launch argv into this instance.
            let handle = app.handle().clone();
            app.listen("deep-link://new-url", move |event| {
                if let Some(urls) = event
                    .payload()
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                {
                    deliver_deep_link(&handle, urls);
                }
            });

            // Cold start: if the app was launched *by* a birdo:// URL, the runtime
            // listener above never fires (the URL arrives as launch argv, not an
            // event). Capture it and stash it for the frontend to pull on mount —
            // emitting now would be lost since the webview listener isn't attached
            // yet. Fixes deep links that were silently dropped on a cold Windows
            // launch.
            {
                use tauri_plugin_deep_link::DeepLinkExt;
                if let Ok(Some(urls)) = app.deep_link().get_current() {
                    if let Some(first) = urls.into_iter().next() {
                        // P6-CLI-D-03: same treatment as deliver_deep_link.
                        info!("Launch deep link captured");
                        debug!("Launch deep link captured: {}", first);
                        if let Ok(mut g) = app.state::<PendingDeepLink>().0.lock() {
                            *g = Some(first.to_string());
                        }
                    }
                }
            }

            info!("Birdo VPN Client initialized successfully");
            Ok(())
        })
        .on_window_event(|window, event| {
            // Minimize to tray instead of closing
            if let WindowEvent::CloseRequested { api, .. } = event {
                // FIX: Use non-panicking hide — window may already be destroyed
                let _ = window.hide();
                // Re-arm the biometric app-lock: closing to tray must not leave the
                // authenticated UI one tray-click away for anyone at the machine.
                let _ = window.emit("app-hidden", ());
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![
            // Authentication
            commands::auth::login,
            commands::auth::login_anonymous,
            commands::auth::register_anonymous,
            commands::oauth::native_oauth_login, // native Google/GitHub SSO
            commands::auth::logout,
            commands::auth::get_auth_state,
            commands::auth::verify_2fa, // FIX C-2: 2FA TOTP verification
            commands::auth::delete_account, // GDPR account deletion
            commands::auth::export_user_data, // GDPR data export
            // VPN operations
            commands::vpn::connect_vpn,
            commands::vpn::disconnect_vpn,
            commands::vpn::get_vpn_status,
            commands::vpn::get_vpn_stats,
            commands::vpn::quick_connect,
            commands::vpn::reapply_vpn_settings,
            commands::vpn::get_admin_status,
            // Server management
            commands::servers::get_servers,
            commands::servers::ping_server,
            // Settings
            commands::settings::get_settings,
            commands::settings::save_settings,
            commands::settings::set_autostart,
            // System tray
            commands::tray::set_tray_state,
            // Window placement (corner anchor / draggable)
            commands::window::set_window_position,
            // Kill switch
            commands::killswitch::get_killswitch_status,
            commands::killswitch::set_killswitch_live,
            // Split Tunneling
            commands::split_tunnel::list_installed_apps,
            // Auto-updater (pinned client — see commands/updater.rs)
            commands::updater::get_app_version,
            commands::updater::check_for_updates,
            commands::updater::install_update,
            commands::updater::get_required_update,
            // Extended VPN info
            commands::vpn::get_subscription_status,
            commands::vpn::get_usage_stats,
            // Multi-Hop (Double VPN)
            commands::vpn_multi_hop::get_multi_hop_routes,
            commands::vpn_multi_hop::connect_multi_hop,
            // Port Forwarding
            commands::vpn_port_forward::get_port_forwards,
            commands::vpn_port_forward::create_port_forward,
            commands::vpn_port_forward::delete_port_forward,
            // Vouchers
            commands::vouchers::redeem_voucher,
            // Speed Test
            commands::speed_test::run_speed_test_command,
            // Biometric (Windows Hello)
            commands::biometric::check_biometric_available,
            commands::biometric::set_biometric_enabled,
            commands::biometric::authenticate_biometric,
            // Deep link captured at cold start
            take_pending_deep_link,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| {
            if let RunEvent::ExitRequested { code, api, .. } = &event {
                // A restart (updater relaunch) cannot be held open —
                // prevent_exit() is a documented no-op for RESTART_EXIT_CODE —
                // and must not be turned into a plain exit. Let it through; the
                // startup reconcile (setup(), F-001/F-032) clears any stale
                // kernel firewall state in the relaunched instance.
                if *code == Some(tauri::RESTART_EXIT_CODE) {
                    // The full teardown cannot run here, but ONE piece of it
                    // outlives the process on Windows and must: configure_dns()
                    // parks every physical adapter on `static none`, and the
                    // startup reconcile this comment used to rely on has macOS
                    // and Linux arms only. Without this, updating in-app while
                    // connected leaves the machine with no resolvers — and the
                    // relaunched instance then cannot resolve the API it needs
                    // to reconnect. Synchronous and try_read-based throughout,
                    // so it cannot wedge an exit that must not be held open.
                    #[cfg(target_os = "windows")]
                    {
                        let restored = app_handle.state::<VpnManager>().restore_dns_blocking();
                        info!(
                            "Restart requested — skipping exit teardown (DNS restored: {})",
                            restored
                        );
                    }
                    #[cfg(not(target_os = "windows"))]
                    info!("Restart requested — skipping exit teardown");
                    return;
                }
                if !EXIT_TEARDOWN_STARTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    // First exit request (tray Quit lands here too — app.exit()
                    // raises ExitRequested): hold the exit open, run the
                    // teardown, then re-request the exit.
                    info!("Application exit requested — tearing down VPN + kill switch first");
                    api.prevent_exit();
                    let app = app_handle.clone();
                    tauri::async_runtime::spawn(async move {
                        // Hard cap over the whole teardown: quitting must never
                        // hang. The inner steps carry their own tighter budgets.
                        if tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            teardown_for_exit(&app),
                        )
                        .await
                        .is_err()
                        {
                            error!("Exit teardown timed out — exiting anyway");
                        }
                        EXIT_TEARDOWN_DONE.store(true, std::sync::atomic::Ordering::SeqCst);
                        app.exit(0);
                    });
                } else if !EXIT_TEARDOWN_DONE.load(std::sync::atomic::Ordering::SeqCst) {
                    // Teardown in flight (e.g. an impatient second tray Quit):
                    // keep holding the door. Our own re-exit lands after DONE.
                    api.prevent_exit();
                } else {
                    info!("Exit teardown complete — allowing exit");
                }
            }
        });
}

/// PWR-5: cap for `birdo.log` before it gets rotated aside.
const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024; // 10 MiB

/// If `path` already exists and has grown past [`MAX_LOG_BYTES`], move it to
/// `<path>.1` (clobbering any previous `.1`) so the caller can open a fresh,
/// empty file at `path`. Best-effort: any failure here just means we keep
/// appending to the existing file, which is the pre-existing (unbounded)
/// behaviour — never worth failing startup over a log file.
fn rotate_log_if_large(path: &std::path::Path) {
    let Ok(meta) = std::fs::metadata(path) else {
        return; // doesn't exist yet (first run) — nothing to rotate
    };
    if meta.len() <= MAX_LOG_BYTES {
        return;
    }
    let rotated = path.with_file_name(format!(
        "{}.1",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("birdo.log")
    ));
    // std::fs::rename replaces an existing destination on both Windows
    // (MoveFileExW with MOVEFILE_REPLACE_EXISTING) and Unix, so this is a
    // single atomic step — no separate "delete old .1 first" required.
    if let Err(e) = std::fs::rename(path, &rotated) {
        // Can't log through tracing yet (this runs before the subscriber is
        // installed) — stderr is the best available diagnostic.
        eprintln!("birdo.log rotation failed (continuing to append): {}", e);
    }
}

/// SEC-PII: apply the same `sanitize_error` redaction the local log gets to
/// every message-carrying field of an outgoing Sentry event.
///
/// The panic integration stores the raw panic payload in `exception[].value`
/// (see sentry-panic's `event_from_panic_info`), and `event.message` /
/// `logentry` / breadcrumb messages can carry error chains with embedded IPs,
/// hostnames, or emails. Runs as `before_send`, so it covers every capture
/// path regardless of hook ordering. In debug builds `sanitize_error` is a
/// pass-through, exactly like the local log.
fn scrub_sentry_event_pii(
    mut event: sentry::protocol::Event<'static>,
) -> sentry::protocol::Event<'static> {
    use crate::utils::redact::sanitize_error;

    if let Some(msg) = event.message.take() {
        event.message = Some(sanitize_error(&msg));
    }
    if let Some(entry) = event.logentry.as_mut() {
        entry.message = sanitize_error(&entry.message);
        // Positional params are interpolated raw values — drop rather than
        // guess at their shape.
        entry.params.clear();
    }
    for exception in event.exception.values.iter_mut() {
        if let Some(value) = exception.value.take() {
            exception.value = Some(sanitize_error(&value));
        }
    }
    for breadcrumb in event.breadcrumbs.values.iter_mut() {
        if let Some(msg) = breadcrumb.message.take() {
            breadcrumb.message = Some(sanitize_error(&msg));
        }
    }
    event
}

/// Set up a custom panic hook for crash recovery
///
/// This ensures that:
/// 1. Crashes are logged with full backtraces
/// 2. The VPN tunnel is properly cleaned up on crash
/// 3. Kill switch firewall rules are removed
fn setup_panic_hook() {
    let default_hook = std::panic::take_hook();

    std::panic::set_hook(Box::new(move |panic_info| {
        // Log the panic
        let location = panic_info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".to_string());

        let message = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "Unknown panic".to_string()
        };

        // SEC-PII: Sanitize panic message before logging and writing to crash file.
        // Panic messages propagated from error chains can contain raw IP addresses,
        // emails, or hostnames. Apply the same PII redaction used for API errors.
        let message = crate::utils::redact::sanitize_error(&message);

        error!("PANIC at {}: {}", location, message);
        error!("Backtrace:\n{:?}", std::backtrace::Backtrace::capture());

        // Clean up VPN and kill switch on crash
        // Use std::process::Command to ensure cleanup even if async runtime is broken
        cleanup_on_crash();

        // Write crash report to file for later analysis
        write_crash_report(&location, &message);

        // Call the default hook (will abort the process)
        default_hook(panic_info);
    }));
}

/// Clean up VPN resources when the app crashes.
///
/// FIX-2-1: WFP kill-switch filters are created with `FWPM_SESSION_FLAG_DYNAMIC`,
/// so Windows automatically removes them when the engine handle (and the
/// process) is closed — even on abnormal termination.  The explicit netsh
/// cleanup is therefore no longer necessary, but we keep a legacy fallback
/// (harmless no-op if no netsh rules exist) for defense-in-depth.
fn cleanup_on_crash() {
    error!("Performing emergency cleanup...");

    #[cfg(target_os = "windows")]
    {
        // Legacy netsh fallback — harmless no-op since FIX-2-1 (rules are now
        // managed via WFP dynamic sessions, not netsh).  Kept in case a mixed
        // upgrade scenario leaves stale netsh rules from a pre-2-1 version.
        let rules = [
            vpn::wfp::RULE_NAMES.block_all,
            vpn::wfp::RULE_NAMES.permit_vpn,
            vpn::wfp::RULE_NAMES.permit_localhost,
            vpn::wfp::RULE_NAMES.permit_dhcp,
            vpn::wfp::RULE_NAMES.block_ipv6,
            vpn::wfp::RULE_NAMES.block_stun,
            vpn::wfp::RULE_NAMES.block_turn,
        ];
        for rule in rules {
            let _ = crate::utils::hidden_cmd("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    &format!("name={}", rule),
                ])
                .output();
        }
        // WFP engine handle will be closed automatically when the process exits,
        // triggering removal of all dynamic-session filters.

        // DNS is the half WFP does NOT clean up, and this arm restored none of
        // it. configure_dns parks EVERY connected physical adapter on `static
        // none` to suppress the SMHNR leak, and the Wintun adapter — the only
        // thing still holding resolvers — dies with the process, so a panic left
        // the machine with no resolvers at all. Permanently: the next connect
        // snapshots the parked state as the user's own configuration, and every
        // later disconnect then correctly refuses to touch it. The restart path
        // already got this treatment (manager.rs restore_dns_blocking); this is
        // its crash twin, driven off the on-disk journal because the in-memory
        // snapshot is unreachable from here.
        let dns_restored = vpn::dns_journal::reconcile();
        error!(
            "Emergency cleanup completed (WFP dynamic session auto-cleans filters, DNS restored: {})",
            dns_restored
        );
    }

    #[cfg(target_os = "macos")]
    {
        // F-032: restore pf's MAIN RULESET, not a named anchor.
        //
        // This used to run `pfctl -a com.birdo.vpn.killswitch -F all`, which flushes
        // an anchor that has been inert since #59 moved the kill switch to the main
        // ruleset (macOS's stock /etc/pf.conf never references the anchor, so pf
        // never evaluates it). Meanwhile pf rules loaded with `pfctl -f` live in the
        // kernel and SURVIVE process exit — unlike Windows WFP dynamic sessions,
        // which self-clean. So a panic while the kill switch was blocking left the
        // machine fully firewalled off, and a panic during a normal session left it
        // without IPv6, with no recovery short of a manual pfctl or a reboot.
        //
        // Only revert a ruleset carrying our marker anchor, so a third-party pf
        // configuration (LuLu, Murus, a hand-rolled /etc/pf.conf) is never clobbered.
        let ours = std::process::Command::new("pfctl")
            .args(["-s", "rules"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("com.birdo.vpn"))
            .unwrap_or(false);
        if ours {
            let _ = std::process::Command::new("pfctl")
                .args(["-f", "/etc/pf.conf"])
                .output();
        }
        // Legacy anchor flush — harmless no-op, kept for mixed-upgrade hosts.
        let _ = std::process::Command::new("pfctl")
            .args(["-a", "com.birdo.vpn.killswitch", "-F", "all"])
            .output();

        // Restore DNS on every service configure_dns actually touched.
        //
        // This was one hard-coded `networksetup -setdnsservers Wi-Fi empty`,
        // while configure_dns points EVERY enabled service at the tunnel
        // resolvers (that multi-service leak is the reason it does so) and the
        // clean restore already iterates snapshot.all_dns. A Mac on Ethernet, on
        // a dock, with a second Wi-Fi service, or with Wi-Fi renamed was left
        // pointing at a resolver that no longer exists — and `empty` silently
        // discarded any static DNS the user had deliberately set on Wi-Fi. The
        // journal puts each service back to exactly what it had, and only while
        // it still holds the resolvers we installed.
        let dns_restored = vpn::dns_journal::reconcile();
        let _ = std::process::Command::new("dscacheutil")
            .args(["-flushcache"])
            .output();

        error!(
            "Emergency cleanup completed (pf rules flushed, DNS restored: {})",
            dns_restored
        );
    }

    #[cfg(target_os = "linux")]
    {
        // Remove iptables kill switch rules
        vpn::firewall_linux::emergency_cleanup();

        // F-001: and the connect-window IPv6 leak block, which lives in its own
        // chain and is NOT touched by the kill switch's cleanup. ip6tables rules
        // survive process exit, so without this a crash leaves the host with no
        // IPv6 until the next successful connect/disconnect cycle.
        vpn::tunnel_linux::remove_ipv6_leak_block();

        // Restore DNS. `resolvectl revert` is only half of it, despite the old
        // comment's "or": configure_dns OVERWRITES /etc/resolv.conf on every
        // host where the file is not the systemd stub (see
        // resolv_conf_uses_resolved), which is most of them — Ubuntu images with
        // a replaced resolv.conf, Debian resolvconf, NetworkManager dns=default,
        // WSL, containers. Reverting only the link left the file pointing at
        // tunnel resolvers that die with the process. The journal restores the
        // exact pre-connect bytes, and only while the file still carries our
        // marker.
        let _ = std::process::Command::new("resolvectl")
            .args(["revert", "birdo0"])
            .output();
        let dns_restored = vpn::dns_journal::reconcile();

        error!(
            "Emergency cleanup completed (iptables rules flushed, DNS restored: {})",
            dns_restored
        );
    }
}

/// Write crash report to a file for later analysis
fn write_crash_report(location: &str, message: &str) {
    use std::io::Write;

    let crash_dir = dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("Birdo VPN")
        .join("crashes");

    let _ = std::fs::create_dir_all(&crash_dir);

    // P6-CLI-D-05: cap the directory — crash files used to accumulate forever
    // (a permanent, timestamped on-disk history on a product that claims to
    // retain nothing). Keep the newest few; the filename's timestamp format
    // sorts lexicographically, so a plain sort is a time sort.
    const KEEP_CRASH_REPORTS: usize = 5;
    if let Ok(entries) = std::fs::read_dir(&crash_dir) {
        let mut crashes: Vec<std::path::PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("crash_") && n.ends_with(".txt"))
                    .unwrap_or(false)
            })
            .collect();
        crashes.sort();
        // The report being written below makes KEEP_CRASH_REPORTS total.
        if crashes.len() + 1 > KEEP_CRASH_REPORTS {
            for old in &crashes[..crashes.len() + 1 - KEEP_CRASH_REPORTS] {
                let _ = std::fs::remove_file(old);
            }
        }
    }

    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let crash_file = crash_dir.join(format!("crash_{}.txt", timestamp));

    let mut open_opts = std::fs::OpenOptions::new();
    open_opts.write(true).create(true).truncate(true);
    // P6-CLI-D-08: owner-readable only on multi-user Unix hosts.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open_opts.mode(0o600);
    }
    if let Ok(mut file) = open_opts.open(&crash_file) {
        let _ = writeln!(file, "BirdoVPN Crash Report");
        let _ = writeln!(file, "=====================");
        let _ = writeln!(file, "Time: {}", chrono::Utc::now().to_rfc3339());
        let _ = writeln!(file, "Location: {}", location);
        let _ = writeln!(file, "Message: {}", message);
        let _ = writeln!(file);
        let _ = writeln!(file, "Backtrace:");
        // Backtraces can carry PII in path segments (home directory = local
        // username) and panic payload fragments — run them through the same
        // redaction as everything else that reaches disk.
        let backtrace = format!("{:?}", std::backtrace::Backtrace::capture());
        let _ = writeln!(file, "{}", crate::utils::redact::sanitize_error(&backtrace));

        error!("Crash report written to {:?}", crash_file);
    }
}

/// Relaunch the current process with administrator privileges via ShellExecuteW "runas".
/// Returns Ok(()) if the elevated process was launched successfully (caller should exit).
#[cfg(windows)]
fn self_elevate() -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;

    let exe_path =
        std::env::current_exe().map_err(|e| format!("Failed to get current exe path: {}", e))?;

    // Collect command-line args (skip argv[0] which is the exe itself)
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args_str = args.join(" ");

    // P6-CLI-D-03: argv carries the birdo:// deep-link URL on a cold start, and that
    // URL names the target server. This runs BEFORE deliver_deep_link, so redacting
    // only there left the payload in the log one code path earlier.
    info!("Self-elevating");
    debug!("Self-elevating: {:?} {}", exe_path, args_str);

    // Convert to wide strings for ShellExecuteW
    let operation: Vec<u16> = std::ffi::OsStr::new("runas")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let file: Vec<u16> = exe_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let parameters: Vec<u16> = std::ffi::OsStr::new(&args_str)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: ShellExecuteW is a well-documented Win32 API.
    // We pass valid null-terminated UTF-16 strings and check the return value.
    let result = unsafe {
        windows::Win32::UI::Shell::ShellExecuteW(
            windows::Win32::Foundation::HWND::default(),
            windows::core::PCWSTR(operation.as_ptr()),
            windows::core::PCWSTR(file.as_ptr()),
            windows::core::PCWSTR(parameters.as_ptr()),
            windows::core::PCWSTR::null(),
            windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL,
        )
    };

    // ShellExecuteW returns an HINSTANCE; values > 32 indicate success
    let result_val = result.0 as isize;
    if result_val > 32 {
        Ok(())
    } else {
        Err(format!(
            "ShellExecuteW returned {} (user may have denied UAC prompt)",
            result_val
        ))
    }
}
