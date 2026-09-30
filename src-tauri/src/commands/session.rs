//! The VPN session lifecycle: ONE way in and ONE way out.
//!
//! `connect_session` is the only user-initiated connect. Single-hop, Multi-Hop,
//! quick-connect and the live settings reapply are thin wrappers over it, so
//! they cannot drift apart again (W1-022: Multi-Hop never stopped
//! auto-reconnect before connecting, so a failed Multi-Hop switch was silently
//! "recovered" onto the PREVIOUS target). The unattended re-dial in
//! `vpn::auto_reconnect` shares its tunnel preparation (`prepare_tunnel`).
//!
//! `end_session` is the only teardown. Disconnect, sign-out, account deletion,
//! quitting, installing an update and a rejected sign-in session all run it,
//! so none of them can leave a block, a tunnel or an in-flight connect behind
//! (W1-009, W1-004, contract §3).

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tauri::{AppHandle, Emitter, Manager};
use tokio::time::timeout;
use zeroize::{Zeroize, Zeroizing};

use crate::api::types::{ConnectResponse, MultiHopConnectResponse, VpnConfig};
use crate::api::BirdoApi;
use crate::commands::ipc_error::{IpcError, IpcErrorCode};
use crate::commands::killswitch;
use crate::commands::vpn::{
    apply_vpn_settings, build_vpn_config, derive_quantum_psk, enforce_requested_protection,
    generate_wireguard_keypair, get_device_name, parse_endpoint_ip, start_stealth_tunnel,
    transport_fallback_reason,
};
use crate::storage::CredentialStore;
use crate::vpn::auto_reconnect::ReconnectInfo;
use crate::vpn::manager::{
    ConnectPhase, ConnectionState, MultiHopStatus, SessionLabel, VpnManager,
};
use crate::vpn::xray::XrayManager;
use crate::vpn::AutoReconnectService;

/// Restore the stored session into the API client if it has none in memory,
/// or report that the user is not signed in.
pub(crate) async fn ensure_signed_in(
    api: &BirdoApi,
    credentials: &CredentialStore,
) -> Result<(), IpcError> {
    if !api.is_authenticated().await {
        if let Ok(tokens) = credentials.get_tokens() {
            api.restore_tokens_if_absent(tokens.access_token.clone(), tokens.refresh_token.clone())
                .await;
        }
    }
    if api.is_authenticated().await {
        Ok(())
    } else {
        Err(IpcError::new(
            IpcErrorCode::SessionExpired,
            "Sign in to continue.",
        ))
    }
}

/// Where a user connect goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConnectTarget {
    SingleHop { server_id: String },
    MultiHop { entry_id: String, exit_id: String },
}

impl ConnectTarget {
    /// The target a live session was built for (settings reapply).
    pub(crate) fn of(info: &ReconnectInfo) -> Self {
        match &info.multi_hop {
            Some(route) => ConnectTarget::MultiHop {
                entry_id: info.server_id.clone(),
                exit_id: route.exit_id.clone(),
            },
            None => ConnectTarget::SingleHop {
                server_id: info.server_id.clone(),
            },
        }
    }
}

/// What one attempt learned that the failure path needs.
struct AttemptContext {
    epoch: u64,
    /// A protected session was up when the connect started (a switch).
    was_live: bool,
    /// The block-all was engaged for the rebuild and must be released on
    /// success where the platform does not hold it for the session.
    block_engaged: bool,
    /// The OLD session's stealth transport was restarted for the new one, so
    /// the old tunnel no longer carries traffic even if it is still held.
    old_transport_touched: bool,
}

/// Connect (or switch) to `target`. See the module docs.
pub(crate) async fn connect_session(
    app: &AppHandle,
    target: ConnectTarget,
) -> Result<(), IpcError> {
    // Pre-flight: Wintun adapter creation is an in-process FFI call that
    // requires administrator — failing early with a clear error beats a
    // cryptic Win32 one deep in the tunnel code.
    if !crate::utils::elevation::is_elevated() {
        return Err(IpcError::not_elevated());
    }
    let api = app.state::<BirdoApi>();
    ensure_signed_in(&api, &app.state::<CredentialStore>()).await?;
    let vm = app.state::<VpnManager>();
    let ar = app.state::<AutoReconnectService>();

    // W1-021/W1-022: supersede whatever is in flight (an older connect, an
    // auto-reconnect dial) and stop the reconnect loop BEFORE anything else,
    // on every target. `store_last_config` only runs after a SUCCESSFUL
    // connect, so a loop left running here recovers a failed switch onto the
    // server the user just switched away from. Under the commit lock, so an
    // older attempt either finished committing before this (and its loop is
    // stopped here) or sees its epoch superseded and commits nothing.
    let epoch = {
        let _commit = vm.lock_commit().await;
        let epoch = vm.begin_attempt();
        ar.stop().await;
        epoch
    };

    let was_live = vm.get_state().await.is_tunnel_active() && vm.holds_tunnel().await;
    let _ = vm
        .set_state(if was_live {
            ConnectionState::Switching
        } else {
            ConnectionState::Connecting
        })
        .await;

    let mut ctx = AttemptContext {
        epoch,
        was_live,
        // A block already engaged — a reconnect this connect interrupted, or
        // a give-up — is released on success exactly like the rebuild guard:
        // left alone, a reactive block (no tunnel permit) would hold the new
        // session's traffic under a "Protected" UI.
        block_engaged: killswitch::platform_is_blocking(),
        old_transport_touched: false,
    };
    let mut result = attempt(app, &target, None, &mut ctx).await;

    // ADAPTIVE TRANSPORT: when the direct attempt failed in the
    // transport-shaped way (the establish-time handshake was unanswered or
    // refused), retry ONCE with the backend's any-plan stealth grant. A single
    // retry cannot loop: the stealth attempt's handshake runs against the
    // local Xray proxy, whose failures do not classify as transport-shaped.
    if let Err(direct) = &result {
        if let Some(reason) = fallback_reason_for(app, &target, direct).await {
            tracing::warn!(
                "Adaptive Transport: direct WireGuard failed ({reason}) — rebuilding over the \
                 stealth transport"
            );
            // Cover the transport switch with the same block that covers a
            // reconnect gap, so the backlog of a user who believed they were
            // protected cannot burst out in the clear on exactly the network
            // that is interfering with us. No-op on a fresh first connect.
            if ctx.was_live {
                engage_rebuild_block(&mut ctx).await;
            }
            // Surface the switch — the user must never silently land on a
            // different transport.
            let _ = app.emit(
                "adaptive-transport-fallback",
                serde_json::json!({ "reason": reason }),
            );
            result = attempt(app, &target, Some(reason), &mut ctx).await;
        }
    }

    match result {
        Ok(()) => Ok(()),
        Err(error) => Err(fail_connect(app, error, &ctx).await),
    }
}

/// Engage the block-all for a rebuild of a live session (no-op when the kill
/// switch is not armed).
async fn engage_rebuild_block(ctx: &mut AttemptContext) {
    if let Err(e) = killswitch::activate_killswitch().await {
        tracing::warn!("Kill switch activation before the rebuild failed: {}", e);
    }
    ctx.block_engaged = true;
}

/// Release the rebuild block once the NEW tunnel is up — except where the
/// platform holds the block for the whole Connected session (Windows lockdown;
/// macOS/Linux whenever armed): there `arm()` has just re-activated it with
/// the new tunnel permitted, and releasing it would reopen the reactive
/// detection window.
async fn release_rebuild_block(engaged: bool) {
    if !engaged || killswitch::holds_block_while_connected() {
        return;
    }
    if let Err(e) = killswitch::deactivate_killswitch().await {
        tracing::warn!("Kill switch release after the rebuild failed: {}", e);
    }
}

/// `Some(reason)` when a failed direct attempt warrants the stealth retry.
async fn fallback_reason_for(
    app: &AppHandle,
    target: &ConnectTarget,
    error: &IpcError,
) -> Option<&'static str> {
    // The Multi-Hop connect contract has no `fallbackReason`: Multi-Hop asks
    // for stealth up front through the same grant (mirrors Android).
    if !matches!(target, ConnectTarget::SingleHop { .. }) {
        return None;
    }
    let reason = transport_fallback_reason(error)?;
    // Respect an explicit transport choice: with Stealth Mode forced ON the
    // failed attempt WAS the stealth transport, and it is the last we have.
    let forced_stealth = crate::commands::settings::get_settings(app.clone())
        .await
        .map(|s| s.stealth_mode)
        .unwrap_or(false);
    (!forced_stealth).then_some(reason)
}

/// One full connect attempt: API → stealth/PQ → tunnel → commit.
async fn attempt(
    app: &AppHandle,
    target: &ConnectTarget,
    fallback_reason: Option<&'static str>,
    ctx: &mut AttemptContext,
) -> Result<(), IpcError> {
    let api = app.state::<BirdoApi>();
    let vm = app.state::<VpnManager>();
    tracing::debug!(?target, ?fallback_reason, "connect attempt");

    let device_name = get_device_name();
    // FIX-1-1: the X25519 keypair is generated here — the private key never
    // leaves this device. Zeroizing until it moves into the config.
    let (private_key, client_public_key) = generate_wireguard_keypair();
    let mut private_key = Zeroizing::new(private_key);
    let settings = apply_vpn_settings(app).await;

    // AUDIT-C1: with PQ requested, attach our ML-KEM-1024 public key so the
    // server can encapsulate against it.
    let pq_pk = if settings.quantum_protection {
        Some(
            crate::vpn::birdo_pq::get_client_public_key_b64().ok_or_else(|| {
                IpcError::new(
                    IpcErrorCode::PqFailed,
                    "Post-quantum engine unavailable. Connection aborted because quantum \
                     protection is enabled.",
                )
            })?,
        )
    } else {
        None
    };

    vm.set_phase(ConnectPhase::Authenticating);
    let (response, multi_hop, dialled_id) = match target {
        ConnectTarget::SingleHop { server_id } => {
            let response = vm
                .run_cancellable(
                    ctx.epoch,
                    api.connect_vpn(
                        server_id,
                        &device_name,
                        Some(client_public_key),
                        settings.stealth_mode.then_some(true),
                        fallback_reason,
                        settings.quantum_protection.then_some(true),
                        pq_pk,
                        settings.dns_filtering,
                    ),
                )
                .await?
                .map_err(|e| {
                    tracing::error!("API call failed: {}", e);
                    IpcError::from(e)
                })?;
            tracing::info!("API response received: success={}", response.success);
            (response, None, server_id.as_str())
        }
        ConnectTarget::MultiHop { entry_id, exit_id } => {
            let response = vm
                .run_cancellable(
                    ctx.epoch,
                    api.connect_multi_hop(
                        entry_id,
                        exit_id,
                        &device_name,
                        &client_public_key,
                        settings.stealth_mode,
                        settings.quantum_protection,
                        pq_pk,
                        settings.dns_filtering,
                    ),
                )
                .await?
                .map_err(IpcError::from)?;
            let (response, route) = verified_multi_hop_response(response, entry_id, exit_id)?;
            (response, Some(route), entry_id.as_str())
        }
    };
    if !response.success {
        let message = response
            .message
            .clone()
            .unwrap_or_else(|| "Connection failed".to_string());
        tracing::error!("Server rejected connection: {}", message);
        return Err(IpcError::connect_refused(&message));
    }

    // Starting stealth restarts xray, which is what carried an old stealth
    // session: from here that session is gone even though its tunnel is held.
    let starts_stealth =
        response.stealth_enabled.unwrap_or(false) && response.xray_endpoint.is_some();
    if starts_stealth && app.state::<XrayManager>().is_running().await {
        ctx.old_transport_touched = true;
    }
    let prepared = prepare_tunnel(
        app,
        &vm,
        ctx.epoch,
        response,
        TunnelRequest {
            server_id: dialled_id,
            stealth_mode: settings.stealth_mode,
            quantum_protection: settings.quantum_protection,
            fallback_reason,
            custom_dns: settings.custom_dns.clone(),
            custom_mtu: settings.custom_mtu,
            custom_port: &settings.custom_port,
        },
        &mut private_key,
    )
    .await?;

    // W1-043: the switch guard engages only NOW, immediately before the old
    // tunnel is torn down. Engaged at the start of the attempt, the reactive
    // block-all — which carries no tunnel-interface permit — stopped the
    // HEALTHY old tunnel's traffic for the whole API + stealth window. From
    // here to the new handshake nothing carries traffic, which is the window
    // the guard exists for.
    if ctx.was_live {
        engage_rebuild_block(ctx).await;
    }
    // The relay permit moves to the new server together with the guard, so a
    // switch that fails before this point leaves the old session's permit.
    apply_relay_permit(&prepared.relay_endpoint).await;

    let label = SessionLabel {
        server_name: match &multi_hop {
            Some(route) => format!("{} → {}", route.entry_name, route.exit_name),
            None => prepared.server_name.clone(),
        },
        server_id: multi_hop
            .as_ref()
            .map_or_else(|| dialled_id.to_string(), |route| route.exit_id.clone()),
        multi_hop: multi_hop.clone(),
    };
    vm.set_phase(ConnectPhase::Handshaking);
    vm.connect(
        prepared.config,
        label.clone(),
        settings.local_network_sharing,
        ctx.epoch,
    )
    .await?;

    // COMMIT, serialised against end_session (see VpnManager::commit_lock).
    let _commit = vm.lock_commit().await;
    if !vm.is_current(ctx.epoch) {
        // Superseded as the tunnel came up. Whoever superseded owns the
        // teardown: end_session disconnects after taking this lock, and a
        // newer connect disposes of this tunnel as `displaced`.
        return Err(IpcError::cancelled());
    }

    // AUDIT-2026-06-19 FIX (CRITICAL): arm the kill switch now that the tunnel
    // is up, so an unexpected drop fails CLOSED. Best-effort: a failure to arm
    // must not tear down a working tunnel.
    if let Err(e) = killswitch::arm(app).await {
        tracing::warn!("Failed to arm kill switch after connect: {}", e);
    }
    release_rebuild_block(ctx.block_engaged).await;
    if !prepared.started_stealth {
        // A leftover xray from a previous stealth session must not later read
        // as THIS session's transport dying.
        app.state::<XrayManager>().stop().await;
    }

    // Wire up auto-reconnect for the NEW target. ADAPTIVE TRANSPORT: persist
    // the fallback reason for this session so a drop rebuilds over the
    // transport that is KNOWN to work here.
    let ar = app.state::<AutoReconnectService>();
    ar.store_last_config(ReconnectInfo {
        server_id: dialled_id.to_string(),
        server_name: label.server_name,
        local_network_sharing: settings.local_network_sharing,
        custom_mtu: settings.custom_mtu,
        custom_port: settings.custom_port,
        custom_dns: settings.custom_dns,
        stealth_mode: settings.stealth_mode,
        quantum_protection: settings.quantum_protection,
        dns_filtering: settings.dns_filtering,
        fallback_reason: fallback_reason.map(str::to_string),
        multi_hop,
    })
    .await;
    if let Err(e) = ar.start().await {
        tracing::warn!("Failed to start auto-reconnect: {}", e);
    }

    // LOG-001: the chosen node id is connection history — keep it out of the
    // release log (info reaches birdo.log); the id is still visible at debug.
    tracing::info!("VPN connected successfully");
    tracing::debug!("VPN connected to server id {}", dialled_id);
    Ok(())
}

/// Land a failed user connect in a state the contract can explain (W1-010):
/// never an unexplained block, never a silent revert to another server.
async fn fail_connect(app: &AppHandle, error: IpcError, ctx: &AttemptContext) -> IpcError {
    let vm = app.state::<VpnManager>();
    // Under the commit lock, like a successful commit: a disconnect landing
    // now must not have its `disconnected` overwritten by this `error`, nor a
    // reverted session restarted behind it.
    let _commit = vm.lock_commit().await;
    if error.code == IpcErrorCode::Cancelled || !vm.is_current(ctx.epoch) {
        // Whoever cancelled (a disconnect, a newer connect) owns the state.
        return IpcError::cancelled();
    }
    tracing::error!("Connect failed: {}", error);

    // iOS #354: a switch that failed BEFORE the old tunnel was touched keeps
    // the old session and shows the error beside it. Its reconnect info is
    // still the old one (the new target is only stored on success), so the
    // loop goes back to guarding it.
    if ctx.was_live && !ctx.old_transport_touched && vm.holds_tunnel().await {
        let _ = vm.set_state(ConnectionState::Connected).await;
        release_rebuild_block(ctx.block_engaged).await;
        let ar = app.state::<AutoReconnectService>();
        if ar.current_info().await.is_some() {
            if let Err(e) = ar.start().await {
                tracing::warn!(
                    "Failed to restart auto-reconnect after a failed switch: {}",
                    e
                );
            }
        }
        return error;
    }

    // The protected session is gone (or never existed). If one was live its
    // traffic has nowhere safe to go: keep it blocked (a no-op when the kill
    // switch is not armed). The UI shows `kill_switch_blocking` with a
    // working Disconnect, which is the documented way out.
    if ctx.was_live {
        if let Err(e) = killswitch::activate_killswitch().await {
            tracing::warn!("Kill switch activation after a failed switch failed: {}", e);
        }
    }
    if vm.holds_tunnel().await {
        let _ = vm
            .disconnect_to(ConnectionState::Error(error.clone()))
            .await;
    } else {
        let _ = vm.set_state(ConnectionState::Error(error.clone())).await;
    }
    // Nothing is left for a stealth transport to carry.
    app.state::<XrayManager>().stop().await;
    error
}

/// VERIFY THE ROUTE WE ASKED FOR IS THE ROUTE WE GOT.
///
/// `success: true` only says the request was handled. The client then built a
/// tunnel and displayed the entry -> exit pair from its OWN settings, never
/// reading the `multi_hop` block the backend returns describing what was
/// actually installed. So every failure mode that yields a working single-hop
/// tunnel — the forwarding install being skipped, a fallback path, a response
/// for a different pair — was rendered to the user as their chosen multi-hop
/// route. The user cannot observe their own egress country, so the client is
/// the only thing that can tell them. Refuse rather than display a route we
/// cannot confirm. Shared by the user connect and the unattended re-dial.
pub(crate) fn verified_multi_hop_response(
    response: MultiHopConnectResponse,
    entry_id: &str,
    exit_id: &str,
) -> Result<(ConnectResponse, MultiHopStatus), IpcError> {
    if !response.success {
        return Err(IpcError::connect_refused(
            response
                .message
                .as_deref()
                .unwrap_or("Multi-hop connection failed"),
        ));
    }
    let Some(route) = response.multi_hop.as_ref() else {
        // P6-CLI-D-03: node ids are connection history and ERROR IS written in
        // release, so the ids go to debug and the event stays loud without them.
        tracing::error!(
            "Multi-hop connect returned success but NO route block — refusing to present an \
             unconfirmed route as multi-hop"
        );
        tracing::debug!(entry = %entry_id, exit = %exit_id, "Unconfirmed multi-hop route");
        return Err(IpcError::new(
            IpcErrorCode::ServerError,
            "The server did not confirm the Multi-Hop route. Not connecting, because this \
             could leave you on a single-hop tunnel while the app showed two.",
        ));
    };
    if route.entry_node.id != entry_id || route.exit_node.id != exit_id {
        // P6-CLI-D-03: same treatment — four raw node ids must not reach birdo.log.
        tracing::error!("Multi-hop route MISMATCH — refusing");
        tracing::debug!(
            requested_entry = %entry_id,
            requested_exit = %exit_id,
            got_entry = %route.entry_node.id,
            got_exit = %route.exit_node.id,
            "Multi-hop route mismatch detail"
        );
        return Err(IpcError::new(
            IpcErrorCode::ServerError,
            format!(
                "The server established a different Multi-Hop route ({}) than the one \
                 selected. Not connecting.",
                route.route
            ),
        ));
    }
    let status = MultiHopStatus {
        entry_id: route.entry_node.id.clone(),
        entry_name: route.entry_node.name.clone(),
        exit_id: route.exit_node.id.clone(),
        exit_name: route.exit_node.name.clone(),
    };
    Ok((ConnectResponse::from(response), status))
}

/// What a connect asked the backend for, and the local overrides to apply.
pub(crate) struct TunnelRequest<'a> {
    /// The server dialled (the Multi-Hop ENTRY).
    pub server_id: &'a str,
    pub stealth_mode: bool,
    pub quantum_protection: bool,
    pub fallback_reason: Option<&'a str>,
    pub custom_dns: Option<Vec<String>>,
    pub custom_mtu: u16,
    pub custom_port: &'a str,
}

/// A validated tunnel config, ready for `VpnManager::connect`.
pub(crate) struct PreparedTunnel {
    pub config: VpnConfig,
    pub server_name: String,
    pub started_stealth: bool,
    /// The address the kill switch must permit: the upstream relay, not the
    /// local Xray proxy when stealth is in use.
    pub relay_endpoint: String,
}

/// Everything between a successful connect response and the tunnel build,
/// shared by the user connect and the unattended re-dial so a security check
/// can never exist on one path only: protection enforcement (no silent
/// downgrade), the stealth transport, the BirdoPQ PSK and the
/// `build_vpn_config` choke point (client key, `validate_tunnel_scope`).
pub(crate) async fn prepare_tunnel(
    app: &AppHandle,
    vm: &VpnManager,
    epoch: u64,
    response: ConnectResponse,
    request: TunnelRequest<'_>,
    private_key: &mut Zeroizing<String>,
) -> Result<PreparedTunnel, IpcError> {
    enforce_requested_protection(&response, request.stealth_mode, request.quantum_protection)?;

    // ADAPTIVE TRANSPORT: a fallback retry MUST come back with the stealth
    // transport. Direct WireGuard is proven broken on this network, so
    // silently rebuilding it would just burn another multi-second handshake
    // failure and report a misleading error.
    if request.fallback_reason.is_some() && !response.stealth_enabled.unwrap_or(false) {
        return Err(IpcError::new(
            IpcErrorCode::StealthFailed,
            "This network blocks standard VPN traffic, and the server could not provide \
             Stealth Mode. Please try a different server.",
        ));
    }

    if response.stealth_enabled.unwrap_or(false) {
        vm.set_phase(ConnectPhase::StartingStealth);
    }
    let stealth_endpoint = vm
        .run_cancellable(
            epoch,
            start_stealth_tunnel(app, &response, request.custom_port),
        )
        .await??;
    let upstream_endpoint = if stealth_endpoint.is_some() {
        response
            .xray_endpoint
            .clone()
            .or_else(|| response.endpoint.clone())
    } else {
        None
    };

    vm.set_phase(ConnectPhase::NegotiatingPq);
    let quantum_psk =
        derive_quantum_psk(&response).map_err(|m| IpcError::new(IpcErrorCode::PqFailed, m))?;

    let (mut config, server_name) = build_vpn_config(
        response,
        request.server_id,
        request.custom_dns,
        std::mem::take(&mut **private_key),
        request.custom_mtu,
        request.custom_port,
    )
    .map_err(|m| IpcError::new(IpcErrorCode::ServerError, m))?;

    if let Some(ref stealth_ep) = stealth_endpoint {
        tracing::info!(
            "Overriding WireGuard endpoint to Xray proxy: {}",
            stealth_ep
        );
        config.endpoint = stealth_ep.clone();
    }
    // `quantum_psk` is `Zeroizing`; the config wipes its own copy on drop.
    // `replace` + zeroize rather than `=`: on the classical-fallback path the
    // field already holds the server's PSK (moved in by `build_vpn_config`),
    // and a plain assignment frees the displaced String un-wiped (#175).
    if let Some(psk) = quantum_psk.as_deref() {
        if let Some(mut displaced) = config.preshared_key.replace(psk.to_owned()) {
            displaced.zeroize();
        }
    }

    tracing::debug!(
        "Got VPN config: endpoint={}, client_ip={}",
        crate::utils::redact_endpoint(&config.endpoint),
        crate::utils::redact_ip(&config.client_ip)
    );
    let relay_endpoint = upstream_endpoint.unwrap_or_else(|| config.endpoint.clone());
    Ok(PreparedTunnel {
        config,
        server_name,
        started_stealth: stealth_endpoint.is_some(),
        relay_endpoint,
    })
}

/// Point the kill switch's relay permit at `endpoint`, re-baking an engaged
/// block so the new handshake is not dropped by it.
pub(crate) async fn apply_relay_permit(endpoint: &str) {
    let Some(ip) = parse_endpoint_ip(endpoint) else {
        // P6-CLI-D-03: the endpoint names the relay, so both lines are
        // redacted (`redact_*` is a pass-through in debug builds).
        tracing::warn!(
            "Could not resolve kill switch endpoint IP from '{}'; kill switch may not filter \
             traffic to the VPN server correctly",
            crate::utils::redact::redact_hostname(endpoint)
        );
        tracing::debug!(
            "Unresolvable kill switch endpoint: {}",
            crate::utils::redact_endpoint(endpoint)
        );
        return;
    };
    killswitch::set_vpn_server_ip(Some(ip)).await;
    // update_vpn_server sets the IP AND re-activates an engaged block atomically.
    #[cfg(target_os = "windows")]
    if let Err(e) = crate::vpn::wfp::update_vpn_server(ip).await {
        tracing::warn!("Failed to update WFP VPN server: {}", e);
    }
    // Linux twin: the relay is permitted by ADDRESS and the self-permit is
    // scoped to tcp/443, so a connect onto a different server needs the live
    // block re-armed or its handshake is dropped.
    #[cfg(target_os = "linux")]
    if let Err(e) = crate::vpn::firewall_linux::update_vpn_server(ip).await {
        tracing::warn!("Failed to update iptables VPN server: {}", e);
    }
    // macOS twin: pf bakes the relay permit into the loaded ruleset, so an
    // engaged block must be re-loaded with the NEW relay IP (block drop all wins).
    #[cfg(target_os = "macos")]
    if killswitch::pf_blocking_active() {
        if let Err(e) = killswitch::activate_killswitch().await {
            tracing::warn!("Failed to update pf VPN server permit: {}", e);
        }
    }
}

/// Why a session is ending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    UserDisconnect,
    SignOut,
    /// The account was just erased server-side: nothing is left to notify.
    AccountDeleted,
    AppExit,
    Update,
    /// The server rejected the sign-in session: tokens are dead, so the peer
    /// is not released through an API call that would only 401 again.
    SessionExpired,
}

/// End the session from ANY state (contract §3.1): cancel an in-flight
/// connect or re-dial, stop auto-reconnect, stop the stealth transport,
/// release the server-side peer, tear the tunnel down and release the WFP
/// block — an explicit end ALWAYS releases, always-on included — ending at
/// `disconnected` with `kill_switch_blocking=false`.
pub async fn end_session(app: &AppHandle, reason: EndReason) {
    let vm = app.state::<VpnManager>();
    tracing::info!("Ending the VPN session ({reason:?})");

    // Cancel FIRST: an in-flight connect or re-dial stops at its next await,
    // including mid-build, so nothing below races a tunnel coming up.
    vm.cancel_in_flight();
    let _commit = vm.lock_commit().await;

    let ar = app.state::<AutoReconnectService>();
    ar.stop().await;
    ar.clear_last_config().await;

    app.state::<XrayManager>().stop().await;

    // PERF-DISCONNECT: free the server-side peer (and device slot) while the
    // tunnel is still up. A courtesy call: tightly capped, never fatal.
    if !matches!(
        reason,
        EndReason::SessionExpired | EndReason::AccountDeleted
    ) {
        if let Some(key_id) = vm.get_key_id().await {
            let api = app.state::<BirdoApi>();
            match timeout(Duration::from_secs(3), api.disconnect_vpn(&key_id)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::info!("Backend disconnect notify failed: {}", e),
                Err(_) => tracing::info!("Backend disconnect notify timed out"),
            }
        }
    }

    // Routes, DNS restore, the session IPv6 block. Exits are capped so a hung
    // stop can never starve the disarm below: that is the piece whose absence
    // outlives the process on macOS/Linux.
    let disconnect = vm.disconnect();
    let result = match reason {
        EndReason::AppExit | EndReason::Update => timeout(Duration::from_secs(6), disconnect)
            .await
            .unwrap_or_else(|_| Err("Tunnel disconnect timed out".to_string())),
        _ => disconnect.await,
    };
    if let Err(e) = result {
        tracing::error!("Tunnel disconnect failed: {}", e);
    }

    // The 3e6f1e2 escape hatch, unconditionally: ending the session is the
    // user releasing the block, and is_lockdown_mode() is hard false
    // off-Windows, so any gate here would leave macOS/Linux behind a kernel
    // firewall with no session to own it. A no-op if never armed.
    let _ = killswitch::disarm().await;
    // `disconnect()` returns early when no tunnel is held (an Error after a
    // give-up), so the end state is written here, whatever came before.
    let _ = vm.set_state(ConnectionState::Disconnected).await;
}

static EXPIRY_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// Contract §3.3: the server rejected the refresh token. Tear the VPN down,
/// clear the tokens and tell the UI, which routes to sign-in with a banner.
/// Idempotent: every request in flight can report the same rejection.
pub async fn handle_session_expired(app: &AppHandle) {
    if EXPIRY_IN_FLIGHT.swap(true, Ordering::SeqCst) {
        return;
    }
    tracing::warn!("The server rejected the sign-in session — signing out");
    end_session(app, EndReason::SessionExpired).await;
    app.state::<BirdoApi>().clear_tokens().await;
    if let Err(e) = app.state::<CredentialStore>().clear_tokens() {
        tracing::warn!(
            "Could not clear the stored session: {}",
            crate::utils::redact::sanitize_error(&e.to_string())
        );
    }
    // Only "expired" is emitted: the backend's refresh 401 carries nothing
    // that tells a revoked session apart from an expired one.
    let _ = app.emit(
        "session-expired",
        serde_json::json!({ "reason": "expired" }),
    );
    EXPIRY_IN_FLIGHT.store(false, Ordering::SeqCst);
}

/// Source pins for the lifecycle ordering. The functions take an `AppHandle`,
/// which a unit test cannot build, so these read this file the way
/// `ipv6_binding_tests` reads `src/vpn`.
#[cfg(test)]
mod lifecycle_tests {
    const SOURCE: &str = include_str!("session.rs");

    fn body(signature: &str) -> &'static str {
        let start = SOURCE
            .find(signature)
            .unwrap_or_else(|| panic!("{signature} not found"));
        let rest = &SOURCE[start..];
        &rest[..rest.find("\n}").expect("closing brace at column 0")]
    }

    fn order(haystack: &str, needles: &[&str]) {
        let mut last = 0;
        for needle in needles {
            let at = haystack[last..]
                .find(needle)
                .unwrap_or_else(|| panic!("`{needle}` missing or out of order"));
            last += at + needle.len();
        }
    }

    /// W1-009 / W1-021 / contract §3.1: cancel before anything else, stop the
    /// loop before touching the tunnel, disarm last, end Disconnected.
    #[test]
    fn end_session_cancels_first_and_disarms_last() {
        order(
            body("pub async fn end_session("),
            &[
                "vm.cancel_in_flight()",
                "vm.lock_commit()",
                "ar.stop()",
                "ar.clear_last_config()",
                "XrayManager>().stop()",
                "vm.disconnect()",
                "killswitch::disarm()",
                "ConnectionState::Disconnected",
            ],
        );
    }

    /// W1-022: every target stops auto-reconnect before anything is dialled,
    /// under the commit lock, with a fresh epoch.
    #[test]
    fn connect_session_supersedes_and_stops_the_loop_first() {
        order(
            body("pub(crate) async fn connect_session("),
            &[
                "vm.lock_commit()",
                "vm.begin_attempt()",
                "ar.stop()",
                "attempt(app, &target, None",
            ],
        );
    }

    /// W1-021 / W1-009: nothing is armed and no loop is started for an
    /// attempt a disconnect has superseded.
    #[test]
    fn the_commit_rechecks_the_epoch_under_the_lock() {
        order(
            body("async fn attempt("),
            &[
                "vm.connect(",
                "vm.lock_commit()",
                "vm.is_current(ctx.epoch)",
                "killswitch::arm(app)",
                "ar.store_last_config(",
                "ar.start()",
            ],
        );
    }

    /// W1-043: the guard engages after the API/stealth phase, right before
    /// the tunnel is rebuilt.
    #[test]
    fn the_switch_guard_engages_just_before_the_rebuild() {
        order(
            body("async fn attempt("),
            &[
                "prepare_tunnel(",
                "engage_rebuild_block(ctx)",
                "apply_relay_permit(",
                "vm.connect(",
            ],
        );
    }
}
