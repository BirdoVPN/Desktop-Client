//! Birdo VPN Windows Client
//!
//! Main entry point for the Tauri application.
//! Handles window management, system tray, and IPC commands.

// FIX-R11: Hide console window in release builds
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api;
mod commands;
mod storage;
mod utils;
mod vpn;

use api::BirdoApi;
use storage::CredentialStore;
use vpn::{VpnManager, AutoReconnectService};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager, RunEvent, WindowEvent,
};
use tracing::{info, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn main() {
    // Set custom panic hook for crash recovery
    setup_panic_hook();
    
    // Initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "birdo_client_win=info,wintun=info,wintun_dll=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Birdo VPN Client starting...");

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
                    error!("Self-elevation failed: {}. Continuing without admin — VPN will not work.", e);
                    // Continue anyway so the UI shows the error to the user
                }
            }
        } else {
            info!("Running with administrator privileges ✓");
        }
    }

    // In dev mode, just log the elevation status
    #[cfg(all(windows, not(feature = "custom-protocol")))]
    {
        use crate::utils::elevation::is_elevated;
        if is_elevated() {
            info!("Running with administrator privileges ✓");
        } else {
            error!(
                "⚠ NOT running as administrator — VPN will fail. \
                 Run your terminal as Administrator and retry `npm run tauri dev`."
            );
        }
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        // Register application state
        .manage(BirdoApi::new())
        .manage(CredentialStore)
        .manage(VpnManager::new())
        .setup(|app| {
            info!("Setting up Birdo VPN application...");

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
                app.manage(auto_reconnect);
                info!("Auto-reconnect service registered");
            }
            
            // Create system tray menu
            let quit = MenuItem::with_id(app, "quit", "Quit Birdo VPN", true, None::<&str>)?;
            let show = MenuItem::with_id(app, "show", "Show Window", true, None::<&str>)?;
            let connect = MenuItem::with_id(app, "connect", "Quick Connect", true, None::<&str>)?;
            let disconnect =
                MenuItem::with_id(app, "disconnect", "Disconnect", false, None::<&str>)?;

            let menu = Menu::with_items(app, &[&connect, &disconnect, &show, &quit])?;

            // Build system tray
            let _tray = TrayIconBuilder::new()
                .icon(app.default_window_icon().expect("default window icon must be set in tauri.conf.json").clone())
                .menu(&menu)
                .show_menu_on_left_click(false)
                .tooltip("Birdo VPN - Disconnected")
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "quit" => {
                        info!("User requested quit from tray");
                        app.exit(0);
                    }
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "connect" => {
                        info!("Quick connect triggered from tray");
                        // Emit event to frontend
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.emit("tray-quick-connect", ());
                        }
                    }
                    "disconnect" => {
                        info!("Disconnect triggered from tray");
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
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;

            // Show main window after setup
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
            }

            info!("Birdo VPN Client initialized successfully");
            Ok(())
        })
        .on_window_event(|window, event| {
            // Minimize to tray instead of closing
            if let WindowEvent::CloseRequested { api, .. } = event {
                // FIX: Use non-panicking hide — window may already be destroyed
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![
            // Authentication
            commands::auth::login,
            commands::auth::login_anonymous,
            commands::auth::logout,
            commands::auth::get_auth_state,
            commands::auth::refresh_token,
            commands::auth::verify_2fa,  // FIX C-2: 2FA TOTP verification
            // VPN operations
            commands::vpn::connect_vpn,
            commands::vpn::disconnect_vpn,
            commands::vpn::get_vpn_status,
            commands::vpn::get_vpn_stats,
            commands::vpn::quick_connect,
            commands::vpn::get_admin_status,
            // Server management
            commands::servers::get_servers,
            commands::servers::ping_server,
            // Settings
            commands::settings::get_settings,
            commands::settings::save_settings,
            commands::settings::set_autostart,
            // Kill switch
            commands::killswitch::enable_killswitch,
            commands::killswitch::disable_killswitch,
            commands::killswitch::activate_killswitch,
            commands::killswitch::deactivate_killswitch,
            commands::killswitch::get_killswitch_status,
            // Auto-updater
            commands::updater::check_for_updates,
            commands::updater::install_update,
            commands::updater::get_app_version,
            // Extended VPN info
            commands::vpn::measure_vpn_latency,
            commands::vpn::get_subscription_status,
            commands::vpn::get_wfp_status,
            // Multi-Hop (Double VPN)
            commands::vpn::get_multi_hop_routes,
            commands::vpn::connect_multi_hop,
            // Port Forwarding
            commands::vpn::get_port_forwards,
            commands::vpn::create_port_forward,
            commands::vpn::delete_port_forward,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|_app_handle, event| {
            if let RunEvent::ExitRequested { .. } = event {
                // PB-3.12: Allow the exit to proceed (do not call api.prevent_exit())
                info!("Application exit requested, allowing exit");
            }
        });
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
        let location = panic_info.location()
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
            .args(["advfirewall", "firewall", "delete", "rule", &format!("name={}", rule)])
            .output();
    }

    // WFP engine handle will be closed automatically when the process exits,
    // triggering removal of all dynamic-session filters.
    error!("Emergency cleanup completed (WFP dynamic session auto-cleans filters)");
}

/// Write crash report to a file for later analysis
fn write_crash_report(location: &str, message: &str) {
    use std::io::Write;
    
    let crash_dir = dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("Birdo VPN")
        .join("crashes");
    
    let _ = std::fs::create_dir_all(&crash_dir);
    
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let crash_file = crash_dir.join(format!("crash_{}.txt", timestamp));
    
    if let Ok(mut file) = std::fs::File::create(&crash_file) {
        let _ = writeln!(file, "Birdo VPN Crash Report");
        let _ = writeln!(file, "=====================");
        let _ = writeln!(file, "Time: {}", chrono::Utc::now().to_rfc3339());
        let _ = writeln!(file, "Location: {}", location);
        let _ = writeln!(file, "Message: {}", message);
        let _ = writeln!(file, "");
        let _ = writeln!(file, "Backtrace:");
        let _ = writeln!(file, "{:?}", std::backtrace::Backtrace::capture());
        
        error!("Crash report written to {:?}", crash_file);
    }
}

/// Relaunch the current process with administrator privileges via ShellExecuteW "runas".
/// Returns Ok(()) if the elevated process was launched successfully (caller should exit).
#[cfg(windows)]
fn self_elevate() -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;

    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Failed to get current exe path: {}", e))?;

    // Collect command-line args (skip argv[0] which is the exe itself)
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args_str = args.join(" ");

    info!("Self-elevating: {:?} {}", exe_path, args_str);

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
