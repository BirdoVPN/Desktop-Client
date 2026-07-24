//! Kill Switch commands
//!
//! Uses Windows Filtering Platform (WFP) to block all traffic except VPN.
//!
//! SEC-C3 FIX: State is now unified — `killswitch.rs` delegates all state
//! queries to `wfp.rs` instead of maintaining independent AtomicBool flags.
//! Previously, `KILLSWITCH_ENABLED`/`KILLSWITCH_ACTIVE` here and
//! `IS_INITIALIZED`/`IS_BLOCKING` in wfp.rs could desynchronize.

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::{AppHandle, State};
use tokio::sync::RwLock;

use crate::utils::elevation::is_elevated;
#[cfg(target_os = "linux")]
use crate::vpn::firewall_linux;
#[cfg(target_os = "windows")]
use crate::vpn::wfp;

use crate::vpn::manager::VpnManager;

/// SEC-C3 FIX: KILLSWITCH_ENABLED is the single user-intent flag.
/// Active/blocking state is delegated entirely to wfp.rs.
static KILLSWITCH_ENABLED: AtomicBool = AtomicBool::new(false);

/// Global state for kill switch - stores allowed VPN server IP
static VPN_SERVER_IP: once_cell::sync::Lazy<Arc<RwLock<Option<Ipv4Addr>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(None)));

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillSwitchStatus {
    pub enabled: bool,
    pub active: bool,
    pub blocking_connections: u32,
}

/// Enable the kill switch (arm it for when VPN disconnects)
#[tauri::command]
pub async fn enable_killswitch() -> Result<bool, String> {
    tracing::info!("Enabling kill switch");

    #[cfg(target_os = "windows")]
    {
        // Check for admin privileges
        if !is_elevated() {
            tracing::warn!("Kill switch requires administrator privileges");
            return Err("Administrator privileges required for kill switch".to_string());
        }

        // Initialize WFP engine
        if let Err(e) = wfp::initialize().await {
            tracing::error!("Failed to initialize WFP engine: {}", e);
            return Err(format!("Failed to initialize firewall: {}", e));
        }
    }

    #[cfg(target_os = "macos")]
    {
        if !is_elevated() {
            tracing::warn!("Kill switch requires root privileges on macOS");
            return Err("Root privileges required for kill switch".to_string());
        }
    }

    #[cfg(target_os = "linux")]
    {
        if !is_elevated() {
            tracing::warn!("Kill switch requires root privileges on Linux");
            return Err("Root privileges required for kill switch".to_string());
        }
    }

    KILLSWITCH_ENABLED.store(true, Ordering::SeqCst);
    tracing::info!("Kill switch enabled and ready");
    Ok(true)
}

/// Disable the kill switch completely
/// SECURITY: Rejects the command when VPN is in an active state (Connected,
/// Connecting, Reconnecting) to prevent a compromised webview from silently
/// removing leak protection while the tunnel is up.
#[tauri::command]
pub async fn disable_killswitch(vpn_manager: State<'_, VpnManager>) -> Result<bool, String> {
    // F-16 FIX: Enforce VPN state check — reject if tunnel is active
    let state = vpn_manager.get_state().await;
    if state.is_tunnel_active() || state.can_disconnect() {
        tracing::warn!(
            "Refusing to disable kill switch while VPN is in {:?} state",
            state
        );
        return Err(
            "Cannot disable kill switch while VPN is connected or connecting. Disconnect first."
                .to_string(),
        );
    }

    tracing::info!("Disabling kill switch");

    #[cfg(target_os = "windows")]
    {
        // Remove all WFP filters and cleanup
        if let Err(e) = wfp::cleanup().await {
            tracing::warn!("Failed to cleanup WFP filters: {}", e);
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Err(e) = pf_deactivate_blocking().await {
            tracing::warn!("Failed to remove pf rules: {}", e);
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Err(e) = firewall_linux::deactivate_blocking().await {
            tracing::warn!("Failed to remove iptables rules: {}", e);
        }
    }

    KILLSWITCH_ENABLED.store(false, Ordering::SeqCst);
    // SEC-C3 FIX: No longer storing KILLSWITCH_ACTIVE — wfp::is_blocking() is the source of truth
    tracing::info!("Kill switch disabled");
    Ok(true)
}

/// Activate the kill switch (block all non-VPN traffic).
///
/// DT-7: Not a Tauri IPC command — called internally by the auto-reconnect
/// service when the VPN drops unexpectedly. Kept as a plain async fn to shrink
/// the IPC attack surface (the frontend never invoked it).
pub async fn activate_killswitch() -> Result<bool, String> {
    if !KILLSWITCH_ENABLED.load(Ordering::SeqCst) {
        return Ok(false);
    }

    tracing::warn!("Activating kill switch - blocking all non-VPN traffic");

    #[cfg(target_os = "windows")]
    {
        let server_ip = *VPN_SERVER_IP.read().await;
        // Set the VPN server IP before activating
        if let Some(ip) = server_ip {
            wfp::set_vpn_server(ip).await;
        }
        if let Err(e) = wfp::activate_blocking().await {
            tracing::error!("Failed to activate blocking filters: {}", e);
            return Err(format!("Failed to activate blocking: {}", e));
        }
    }

    #[cfg(target_os = "macos")]
    {
        let server_ip = VPN_SERVER_IP.read().await.clone();
        if let Err(e) = pf_activate_blocking(server_ip).await {
            tracing::error!("Failed to activate pf blocking: {}", e);
            return Err(format!("Failed to activate blocking: {}", e));
        }
    }

    #[cfg(target_os = "linux")]
    {
        let server_ip = VPN_SERVER_IP.read().await.clone();
        if let Err(e) = firewall_linux::activate_blocking(server_ip).await {
            tracing::error!("Failed to activate iptables blocking: {}", e);
            return Err(format!("Failed to activate blocking: {}", e));
        }
    }

    // SEC-C3 FIX: Removed KILLSWITCH_ACTIVE.store — wfp::is_blocking() is the source of truth
    Ok(true)
}

/// Deactivate the kill switch (restore normal traffic).
///
/// DT-7: Not a Tauri IPC command — called internally by the auto-reconnect
/// service when the VPN reconnects. Kept as a plain async fn (the frontend
/// never invoked it).
pub async fn deactivate_killswitch() -> Result<bool, String> {
    tracing::info!("Deactivating kill switch - restoring normal traffic");

    #[cfg(target_os = "windows")]
    {
        if let Err(e) = wfp::deactivate_blocking().await {
            tracing::error!("Failed to deactivate blocking filters: {}", e);
            return Err(format!("Failed to deactivate blocking: {}", e));
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Err(e) = pf_deactivate_blocking().await {
            tracing::error!("Failed to deactivate pf blocking: {}", e);
            return Err(format!("Failed to deactivate blocking: {}", e));
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Err(e) = firewall_linux::deactivate_blocking().await {
            tracing::error!("Failed to deactivate iptables blocking: {}", e);
            return Err(format!("Failed to deactivate blocking: {}", e));
        }
    }

    // SEC-C3 FIX: Removed KILLSWITCH_ACTIVE.store — wfp::is_blocking() is the source of truth
    Ok(true)
}

/// Live-apply a kill-switch preference change to the CURRENT session.
///
/// The Settings toggle persists the preference via `save_settings`, but that only
/// takes effect at the next connect (arm() reads it there). Without this, a user
/// who connects with the kill switch OFF and toggles it ON mid-session would see
/// the toggle ON while WFP was never initialized and `KILLSWITCH_ENABLED` stayed
/// false — so an unexpected drop would NOT fail closed. This mirrors mobile,
/// which pushes the flag into the running service live.
///
/// The frontend persists the preference first, then calls this. Behaviour:
/// - enabled=true, session active  → arm now (init WFP + set intent; activate
///   immediately in lockdown mode).
/// - enabled=false, session active → clear the intent so a later drop won't
///   block, and lift any block currently active; WFP stays initialized and the
///   disconnect path fully cleans up.
/// - no active session → no-op; the persisted preference applies at next connect.
#[tauri::command]
pub async fn set_killswitch_live(
    enabled: bool,
    app: AppHandle,
    vpn_manager: State<'_, VpnManager>,
) -> Result<bool, String> {
    let state = vpn_manager.get_state().await;
    let active = state.is_tunnel_active() || state.can_disconnect();
    if !active {
        tracing::debug!("set_killswitch_live: no active session — applies at next connect");
        return Ok(false);
    }

    if enabled {
        // arm() re-reads the (already-persisted) preference and initializes WFP,
        // engaging the reactive protection for the live session.
        arm(&app).await
    } else {
        KILLSWITCH_ENABLED.store(false, Ordering::SeqCst);

        // F-018: lift any block that is currently up, on EVERY platform. This
        // branch used to be `#[cfg(windows)]`-only, so on macOS/Linux turning the
        // kill switch off while the tunnel was Reconnecting/Error (i.e. with the
        // reactive block installed) cleared the intent flag but left the firewall
        // block in place — the machine stayed fully firewalled off until the
        // tunnel recovered, the retry budget ran out, or the user hit Disconnect.
        //
        // On macOS this does NOT lift the F-001 IPv6 leak block: that block is
        // owned by the tunnel session, not the kill switch, so `deactivate` falls
        // back to it rather than to `/etc/pf.conf`.
        #[cfg(target_os = "windows")]
        let blocking = wfp::is_blocking();
        #[cfg(target_os = "macos")]
        let blocking = PF_BLOCKING.load(Ordering::SeqCst);
        #[cfg(target_os = "linux")]
        let blocking = firewall_linux::is_blocking();
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        let blocking = false;

        if blocking {
            let _ = deactivate_killswitch().await;
        }

        tracing::info!("Kill switch softened live for the active session (intent cleared)");
        Ok(true)
    }
}

/// Get kill switch status
/// SEC-C3 FIX: Active state now reads from wfp.rs (single source of truth)
#[tauri::command]
pub async fn get_killswitch_status() -> Result<KillSwitchStatus, String> {
    let enabled = is_enabled();

    #[cfg(target_os = "windows")]
    let active = wfp::is_blocking();
    #[cfg(target_os = "macos")]
    let active = PF_BLOCKING.load(Ordering::SeqCst);
    #[cfg(target_os = "linux")]
    let active = firewall_linux::is_blocking();
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    let active = false;

    // blocking_connections is deprecated, always 0
    let blocking_connections = 0u32;

    Ok(KillSwitchStatus {
        enabled,
        active,
        blocking_connections,
    })
}

/// Set the allowed VPN server IP (called when connecting)
pub async fn set_vpn_server_ip(ip: Option<Ipv4Addr>) {
    *VPN_SERVER_IP.write().await = ip;
    tracing::debug!("Kill switch VPN server IP set to: {:?}", ip);
}

/// Check if kill switch is currently enabled
pub fn is_enabled() -> bool {
    KILLSWITCH_ENABLED.load(Ordering::SeqCst)
}

/// Whether the kill switch is in lockdown (always-on) mode. Cross-platform
/// accessor used by the auto-reconnect loop so it keeps the block active
/// continuously instead of deactivating in steady Connected state.
pub fn is_lockdown_mode() -> bool {
    #[cfg(target_os = "windows")]
    {
        wfp::is_lockdown_mode()
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

/// Arm the kill switch for an active VPN session.
///
/// AUDIT-2026-06-19 FIX (CRITICAL): the WFP kill switch was effectively dead.
/// `enable_killswitch` — the ONLY setter of `KILLSWITCH_ENABLED` and the only
/// caller of `wfp::initialize` — is registered as an IPC command (main.rs) but
/// was never invoked by the frontend or at startup. So `KILLSWITCH_ENABLED`
/// stayed `false` for the whole session and `activate_killswitch()` (called by
/// the auto-reconnect health loop on a drop) short-circuited to `Ok(false)`,
/// installing NO block-all filters. On an unexpected tunnel drop the OS routing
/// table fell back to the physical adapter and IPv4 traffic egressed in the
/// clear — while the UI promised an always-on kill switch.
///
/// This arms the INTENT and initializes the WFP engine as part of the connect
/// lifecycle, so the existing reactive protection actually engages. It does NOT
/// install the block-all filters itself: the auto-reconnect health loop owns the
/// activate/deactivate transitions (it deactivates while healthy-Connected and
/// activates during a drop/reconnect gap), so arming here must not fight that
/// state machine.
///
/// Best-effort: a non-elevated host (should not happen — the app manifest
/// requires administrator) logs and returns `Ok(false)` rather than failing the
/// whole connection.
pub async fn arm(app: &AppHandle) -> Result<bool, String> {
    // Respect the user's kill-switch preference (default ON). Reading it here —
    // the single choke-point every connect path funnels through — keeps all call
    // sites consistent. Fail SAFE: if settings can't be read, treat as enabled.
    let enabled = crate::commands::settings::load_settings_sync(app)
        .map(|s| s.killswitch_enabled)
        .unwrap_or(true);
    if !enabled {
        tracing::info!("Kill switch disabled by user preference — not arming");
        return Ok(false);
    }

    if !is_elevated() {
        tracing::warn!("Kill switch NOT armed: insufficient privileges (admin/root required)");
        return Ok(false);
    }

    #[cfg(target_os = "windows")]
    {
        wfp::initialize()
            .await
            .map_err(|e| format!("Failed to initialize kill-switch firewall: {}", e))?;
    }

    KILLSWITCH_ENABLED.store(true, Ordering::SeqCst);

    // LOCKDOWN (always-on) mode: activate the block-all NOW and keep it on for
    // the whole session, so there is ZERO reactive detection window. (Reactive
    // mode — the default — leaves the block off in steady state and only
    // activates during a reconnect gap.) The tunnel is already up by the time
    // arm() runs on the connect path, so its interface LUID is published and
    // activate_blocking can permit tunneled traffic; if it cannot, it fails
    // loudly rather than blocking the user's own traffic.
    #[cfg(target_os = "windows")]
    if wfp::is_lockdown_mode() {
        if let Err(e) = activate_killswitch().await {
            // Lockdown could not install the always-on block-all (e.g. the tunnel
            // interface LUID was not published yet, so activate_blocking refused
            // rather than block the user's own traffic). DON'T disable protection
            // entirely — that would leave a later drop fully unprotected, which is
            // worse than reactive. Degrade to the reactive kill switch (block-all
            // installed on drop; it does not need the tunnel LUID) for this
            // session. KILLSWITCH_ENABLED stays true; set_lockdown_mode is an
            // in-memory session flag, so the user's saved preference is untouched.
            tracing::warn!(
                "Lockdown activation failed ({}); falling back to reactive kill switch for this session",
                e
            );
            wfp::set_lockdown_mode(false);
            return Ok(false);
        }
        tracing::info!("Kill switch armed in LOCKDOWN (always-on) mode");
        return Ok(true);
    }

    tracing::info!("Kill switch armed for active session (reactive)");
    Ok(true)
}

/// Disarm the kill switch when the user ends the session: clear the intent flag
/// and remove all firewall filters so connectivity is fully restored.
///
/// Always safe to call (no-op if never armed). MUST be called from the
/// user-initiated disconnect path so disconnecting can never strand the machine
/// behind an active block-all filter set.
pub async fn disarm() -> Result<(), String> {
    KILLSWITCH_ENABLED.store(false, Ordering::SeqCst);

    #[cfg(target_os = "windows")]
    {
        if let Err(e) = wfp::cleanup().await {
            tracing::warn!("Failed to clean up WFP filters on disarm: {}", e);
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Err(e) = pf_deactivate_blocking().await {
            tracing::warn!("Failed to remove pf rules on disarm: {}", e);
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Err(e) = firewall_linux::deactivate_blocking().await {
            tracing::warn!("Failed to remove iptables rules on disarm: {}", e);
        }
    }

    tracing::info!("Kill switch disarmed");
    Ok(())
}

// ──────────────────────────────────────────────────────────────
// macOS pf (packet filter) kill switch implementation
// ──────────────────────────────────────────────────────────────

/// Tracks whether pf blocking rules are active on macOS
#[cfg(target_os = "macos")]
static PF_BLOCKING: AtomicBool = AtomicBool::new(false);

/// True when WE enabled pf (it was disabled before us). Governs whether
/// deactivation should `pfctl -d` — we must never disable pf if the user or
/// another tool had it running.
#[cfg(target_os = "macos")]
static PF_WE_ENABLED: AtomicBool = AtomicBool::new(false);

/// F-001: true while a tunnel session wants the steady-state IPv6 leak block as
/// pf's BASELINE ruleset. This is what makes the leak block survive a kill-switch
/// cycle: `pf_deactivate_blocking()` consults it and restores the leak block
/// instead of bare `/etc/pf.conf`.
#[cfg(target_os = "macos")]
static PF_IPV6_BLOCK_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Is pf currently enabled? Parses `pfctl -s info` ("Status: Enabled").
#[cfg(target_os = "macos")]
fn pf_is_enabled() -> bool {
    crate::utils::hidden_cmd("pfctl")
        .args(["-s", "info"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("Status: Enabled"))
        .unwrap_or(false)
}

// ──────────────────────────────────────────────────────────────
// F-001 (P0): macOS steady-state IPv6 leak block
//
// The relay fleet is IPv4-only, and `tunnel_macos.rs` neither routes nor blocks
// IPv6 — so on a dual-stack network every IPv6-capable app egressed via the
// physical NIC's untouched IPv6 default route for the whole "Connected" session
// (real address + geolocation exposed, no UI signal). The reactive kill switch
// could never cover it: an IPv6 leak does not drop the IPv4 tunnel, so it never
// trips, and it is torn down in steady state anyway.
//
// WHY THIS LIVES IN killswitch.rs: on macOS pf's MAIN RULESET is the only thing
// evaluated (a named anchor is inert unless `/etc/pf.conf` references it — see
// `pf_activate_blocking`'s note, the bug #59 had to fix). The kill switch owns
// the main ruleset. Two independent writers would clobber each other: the leak
// block would be silently wiped the first time `pf_deactivate_blocking()` ran
// after a reconnect, restoring the leak mid-session. So there is ONE owner and
// a two-level baseline:
//
//   kill switch blocking   → block-all ruleset (denies IPv6 as a side effect)
//   tunnel up, no block    → IPv6 leak-block ruleset   ← the baseline
//   no tunnel              → /etc/pf.conf
// ──────────────────────────────────────────────────────────────

/// Marker anchor embedded in every ruleset WE load, so a stale ruleset left by a
/// crash can be positively identified as ours before we replace it. Declaring an
/// empty anchor is a no-op for packet processing but shows up in `pfctl -s rules`.
#[cfg(target_os = "macos")]
const PF_MARKER_ANCHOR: &str = "com.birdo.vpn";

/// Filter rules that black-hole routable IPv6 while keeping the host functional.
///
/// IPv4 is deliberately NOT mentioned: pf's implicit default is *pass*, so a
/// ruleset containing only `inet6` rules cannot break IPv4 connectivity. Link-local
/// and link-scoped multicast stay permitted so NDP/RA/DAD/DHCPv6/MLD keep working.
#[cfg(target_os = "macos")]
/// Kept to the smallest set that is provably sufficient, because this ruleset
/// cannot be unit-tested — every extra rule is another chance for a pfctl parse
/// error that would fail the connect. Link-local↔link-local covers NDP
/// (NS/NA/RS/RA unicast); `any → ff02::/16` covers every link-scoped multicast
/// case including DAD (source `::`), router solicitation, MLD and DHCPv6.
const PF_IPV6_FILTER_RULES: &str = "\
pass quick inet6 from fe80::/10 to fe80::/10 no state\n\
pass quick inet6 from any to ff02::/16 no state\n\
block drop quick inet6 all\n";

/// Preferred leak-block ruleset: re-declares the stock `/etc/pf.conf` anchors so
/// Apple's own pf rules (application firewall / Internet Sharing) keep working
/// for the duration of the session, then appends our IPv6 block.
///
/// pf requires rule types in order: options → normalization → queueing →
/// translation → filtering. This mirrors stock `/etc/pf.conf` ordering exactly.
#[cfg(target_os = "macos")]
fn pf_ipv6_ruleset_full() -> String {
    format!(
        "# Birdo VPN — IPv6 leak block (main ruleset; pf evaluates this directly)\n\
         set block-policy drop\n\
         set skip on lo0\n\
         scrub-anchor \"com.apple/*\"\n\
         nat-anchor \"com.apple/*\"\n\
         rdr-anchor \"com.apple/*\"\n\
         dummynet-anchor \"com.apple/*\"\n\
         anchor \"com.apple/*\"\n\
         load anchor \"com.apple\" from \"/etc/pf.anchors/com.apple\"\n\
         anchor \"{PF_MARKER_ANCHOR}\"\n\
         {PF_IPV6_FILTER_RULES}"
    )
}

/// Fallback leak-block ruleset for hosts where the stock Apple anchor file is
/// missing or unparseable (the `load anchor` line would fail the whole load).
/// Same protection, minus the Apple anchors for the session.
#[cfg(target_os = "macos")]
fn pf_ipv6_ruleset_minimal() -> String {
    format!(
        "# Birdo VPN — IPv6 leak block (minimal fallback)\n\
         set block-policy drop\n\
         set skip on lo0\n\
         anchor \"{PF_MARKER_ANCHOR}\"\n\
         {PF_IPV6_FILTER_RULES}"
    )
}

/// Load `rules` as pf's main ruleset via `pfctl -f -`.
///
/// Piping through stdin (rather than a temp file) avoids both a TOCTOU race and
/// a world-readable file. Shared by the kill switch and the IPv6 leak block so
/// there is exactly one code path that writes pf's main ruleset.
#[cfg(target_os = "macos")]
fn pf_load_ruleset(rules: &str) -> Result<(), String> {
    use std::io::Write;

    let mut child = crate::utils::hidden_cmd("pfctl")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("pfctl spawn failed: {}", e))?;

    match child.stdin.take() {
        Some(mut stdin) => {
            stdin
                .write_all(rules.as_bytes())
                .map_err(|e| format!("Failed to write pf rules to stdin: {}", e))?;
            // Explicitly close stdin to signal EOF to pfctl before waiting
            drop(stdin);
        }
        None => {
            // stdin was unavailable: rules can never be loaded, so do not claim
            // the ruleset is active. Kill the child and fail loudly.
            let _ = child.kill();
            return Err("pfctl stdin unavailable; pf rules not loaded".to_string());
        }
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("pfctl wait failed: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "pfctl load ruleset failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

/// Read back pf's live ruleset. Used to verify a block is genuinely in force
/// rather than trusting `pfctl`'s exit status alone.
#[cfg(target_os = "macos")]
fn pf_live_rules() -> String {
    crate::utils::hidden_cmd("pfctl")
        .args(["-s", "rules"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

/// Install the IPv6 leak-block ruleset as pf's main ruleset and enable pf.
///
/// Tries the anchor-preserving ruleset first, falls back to the minimal one, then
/// VERIFIES the result — a leak fix that silently failed to load is worse than no
/// fix, because the UI would report protection that isn't there.
#[cfg(target_os = "macos")]
fn pf_apply_ipv6_baseline() -> Result<(), String> {
    let was_enabled = pf_is_enabled();

    if let Err(primary) = pf_load_ruleset(&pf_ipv6_ruleset_full()) {
        tracing::warn!(
            "F-001: anchor-preserving IPv6 ruleset failed to load ({}); trying the minimal ruleset",
            primary
        );
        pf_load_ruleset(&pf_ipv6_ruleset_minimal()).map_err(|e| {
            format!("IPv6 leak block failed to load ({primary}); fallback also failed: {e}")
        })?;
    }

    // pf must actually be running or the loaded ruleset is inert.
    if !was_enabled {
        crate::utils::hidden_cmd("pfctl")
            .args(["-e"])
            .output()
            .map_err(|e| format!("pfctl enable failed: {}", e))?;
        PF_WE_ENABLED.store(true, Ordering::SeqCst);
    }

    // Read back: our ruleset always contains inet6 rules. If pf reports none, the
    // load did not take effect and we must NOT claim the leak is blocked.
    if !pf_live_rules().contains("inet6") {
        return Err("IPv6 leak block did not take effect (pf reports no inet6 rules)".to_string());
    }

    tracing::info!("F-001: IPv6 egress blocked for the connect window (pf main ruleset)");
    Ok(())
}

/// Restore pf to the system default ruleset and, if we were the ones who turned
/// pf on, turn it back off.
#[cfg(target_os = "macos")]
fn pf_restore_default_ruleset() {
    let output = crate::utils::hidden_cmd("pfctl")
        .args(["-f", "/etc/pf.conf"])
        .output();
    match output {
        Ok(o) if !o.status.success() => {
            tracing::warn!(
                "pfctl restore /etc/pf.conf: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            );
        }
        Err(e) => tracing::warn!("pfctl restore failed: {}", e),
        _ => {}
    }

    // Only disable pf if we enabled it (never disable pf out from under the user
    // or another tool that had it running).
    if PF_WE_ENABLED.swap(false, Ordering::SeqCst) {
        let _ = crate::utils::hidden_cmd("pfctl").args(["-d"]).output();
    }
}

/// F-001: engage the steady-state IPv6 leak block for a tunnel session.
///
/// Called from `tunnel_macos.rs::start()`, INDEPENDENT of the kill-switch
/// enabled/lockdown setting — exactly as Windows blocks IPv6 at tunnel start.
#[cfg(target_os = "macos")]
pub async fn ipv6_block_activate() -> Result<(), String> {
    // Record the intent FIRST so that, if the kill switch is mid-block, its
    // deactivation lands on our baseline instead of bare /etc/pf.conf.
    PF_IPV6_BLOCK_ACTIVE.store(true, Ordering::SeqCst);

    if PF_BLOCKING.load(Ordering::SeqCst) {
        tracing::info!(
            "F-001: kill-switch block-all is active and already denies IPv6; \
             leak block recorded as the pf baseline"
        );
        return Ok(());
    }

    pf_apply_ipv6_baseline().inspect_err(|_| {
        // Do not leave a claim we could not honour.
        PF_IPV6_BLOCK_ACTIVE.store(false, Ordering::SeqCst);
    })
}

/// F-001: lift the steady-state IPv6 leak block at teardown.
///
/// Best-effort and always safe to call (no-op if never engaged), so it can never
/// fail a disconnect — a stuck block would leave the host without IPv6.
#[cfg(target_os = "macos")]
pub async fn ipv6_block_deactivate() {
    if !PF_IPV6_BLOCK_ACTIVE.swap(false, Ordering::SeqCst) {
        return;
    }

    if PF_BLOCKING.load(Ordering::SeqCst) {
        // The kill switch owns the ruleset right now. The baseline flag is now
        // clear, so its own deactivation will restore /etc/pf.conf.
        tracing::info!("F-001: leak block released; kill switch still owns the pf ruleset");
        return;
    }

    pf_restore_default_ruleset();
    tracing::info!("F-001: IPv6 egress block removed");
}

/// F-001: remove a leak-block / kill-switch ruleset left behind by a crash.
///
/// pf rules loaded with `pfctl -f` live in the kernel and survive process exit —
/// unlike Windows WFP dynamic sessions, which self-clean. Without this, a panic
/// or SIGKILL while blocking leaves the machine either without IPv6 or (worse,
/// if the kill switch was mid-block) fully firewalled off, with no recovery short
/// of a reboot. Only reverts rulesets carrying OUR marker anchor, so a third
/// party's pf configuration is never clobbered.
#[cfg(target_os = "macos")]
pub fn reconcile_stale_pf_state() {
    if !pf_is_enabled() {
        return;
    }
    if !pf_live_rules().contains(PF_MARKER_ANCHOR) {
        return; // not ours — leave it alone
    }
    tracing::warn!("Found a stale Birdo pf ruleset from a previous run — restoring /etc/pf.conf");
    let _ = crate::utils::hidden_cmd("pfctl")
        .args(["-f", "/etc/pf.conf"])
        .output();
    PF_BLOCKING.store(false, Ordering::SeqCst);
    PF_IPV6_BLOCK_ACTIVE.store(false, Ordering::SeqCst);
}

/// Activate pf blocking: block all traffic except to the VPN server and localhost.
///
/// CRITICAL FIX: the rules are loaded as pf's **main ruleset** (`pfctl -f -`),
/// not into a named anchor. A named anchor is only evaluated when the main
/// ruleset contains a matching `anchor "..."` line, and macOS's default
/// `/etc/pf.conf` has no such line — so the previous anchor-only approach loaded
/// rules pf never evaluated, and the kill switch silently failed OPEN (all
/// traffic leaked while the UI reported it active). The main ruleset is always
/// evaluated. `pf_deactivate_blocking` restores `/etc/pf.conf`.
#[cfg(target_os = "macos")]
async fn pf_activate_blocking(server_ip: Option<Ipv4Addr>) -> Result<(), String> {
    // Let the tunnel re-establish while blocked by permitting the VPN server.
    // WireGuard is UDP; allow the server on both transports so a stealth/TCP
    // fallback can also reconnect through the block.
    let server_rule = if let Some(ip) = server_ip {
        format!(
            "pass out quick inet proto {{ udp tcp }} to {} no state\n",
            ip
        )
    } else {
        String::new()
    };

    // Default-deny with `quick` passes short-circuiting for the allow-list.
    // Also permit any utun* WireGuard interface so that, if the tunnel comes
    // back up before deactivation lands, traffic already inside the VPN is not
    // dropped by this main ruleset.
    let rules = format!(
        "# Birdo VPN Kill Switch (main ruleset — pf evaluates this directly)\n\
         set block-policy drop\n\
         anchor \"{PF_MARKER_ANCHOR}\"\n\
         block drop all\n\
         pass quick on lo0 all\n\
         pass quick on utun0 all\n\
         pass quick on utun1 all\n\
         pass quick on utun2 all\n\
         pass quick on utun3 all\n\
         pass out quick proto udp to any port 67 no state\n\
         pass in quick proto udp from any port 68 no state\n\
         {server_rule}"
    );

    // Record pf's pre-existing state BEFORE we change it, so deactivation only
    // disables pf if we were the ones who enabled it.
    let was_enabled = pf_is_enabled();

    // Pipe rules directly to pfctl via stdin — avoids TOCTOU race and world-readable temp file
    pf_load_ruleset(&rules)?;

    // Enable pf if it wasn't already, and remember that we did so.
    if !was_enabled {
        let en = crate::utils::hidden_cmd("pfctl").args(["-e"]).output();
        // `pfctl -e` returns non-zero if pf was already enabled; we already
        // guarded on was_enabled, so treat a spawn failure as fatal — an
        // un-enabled pf means the loaded block ruleset is not enforced.
        match en {
            Ok(_) => PF_WE_ENABLED.store(true, Ordering::SeqCst),
            Err(e) => return Err(format!("pfctl enable failed: {}", e)),
        }
    }

    PF_BLOCKING.store(true, Ordering::SeqCst);
    tracing::info!("macOS pf kill switch activated (main ruleset enforced)");
    Ok(())
}

/// Deactivate pf blocking: drop the block-all main ruleset and fall back to the
/// correct baseline — the IPv6 leak block if a tunnel session is still live,
/// otherwise the system default ruleset (disabling pf only if we enabled it).
///
/// F-001: the fallback is not optional. This runs on every reconnect (the
/// auto-reconnect loop deactivates once the tunnel is healthy again). Restoring
/// bare `/etc/pf.conf` here would wipe the connect-window IPv6 block and silently
/// reopen the leak for the rest of the session.
#[cfg(target_os = "macos")]
async fn pf_deactivate_blocking() -> Result<(), String> {
    PF_BLOCKING.store(false, Ordering::SeqCst);

    if PF_IPV6_BLOCK_ACTIVE.load(Ordering::SeqCst) {
        // Propagating the error deliberately leaves the block-all ruleset loaded.
        // That is both fail-safe and still usable: block-all permits lo0 and utun*,
        // so a healthy tunnel keeps carrying the user's traffic. Falling back to
        // /etc/pf.conf here would restore the IPv6 leak instead.
        pf_apply_ipv6_baseline()?;
        tracing::info!("macOS pf kill switch deactivated (IPv6 leak block retained)");
        return Ok(());
    }

    // Reload the default ruleset, dropping our block-all rules. This is the
    // correct inverse of loading a main ruleset (a per-anchor flush would leave
    // our main-ruleset block rules in place and keep blocking).
    pf_restore_default_ruleset();
    tracing::info!("macOS pf kill switch deactivated");
    Ok(())
}
