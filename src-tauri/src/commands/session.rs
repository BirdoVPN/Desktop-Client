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

use crate::api::session_gate::StoredSession;
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

/// Why a connect runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectPurpose {
    /// The user picked where to go: connect, quick connect, Multi-Hop, a
    /// server switch. A direct attempt the network filters is retried once
    /// over the stealth transport (Adaptive Transport).
    User,
    /// A settings change is being applied to the live session (WIN-FIX-3).
    /// It is rebuilt on the transport it already runs on — the stealth grant
    /// it was given, if any — and gets no Adaptive Transport retry of its
    /// own: a rebuild that fails over a settings change is reverted to the
    /// previous settings instead (`vpn::reapply_vpn_settings`).
    SettingsReapply {
        fallback_reason: Option<&'static str>,
    },
}

/// What one attempt learned that the failure path needs.
struct AttemptContext {
    epoch: u64,
    /// A protected session was up when the connect started (a switch), or
    /// this connect displaced a tunnel it found held (see `session_was_live`
    /// and the guard before `vm.connect`).
    was_live: bool,
    /// The block-all was engaged for the rebuild and must be released on
    /// success where the platform does not hold it for the session.
    block_engaged: bool,
    /// `XrayManager::ended_count` when the connect started, if the OLD
    /// session rode the stealth transport. Once the count moves, the old
    /// tunnel no longer carries traffic even if it is still held.
    old_stealth_mark: Option<u64>,
    /// The relay the block permitted when the connect started: what a switch
    /// that keeps the old session must point the permit back at.
    #[cfg(target_os = "windows")]
    old_relay: Option<crate::vpn::wfp_policy::Relay>,
    /// The kill switch intent's sequence when the dial began, for its arm
    /// (round 6 of the review of #222): an OFF the user made during the dial
    /// makes that arm stand aside (`killswitch::arm_since`).
    intent_seen: u64,
}

impl AttemptContext {
    /// REVIEW-WIN-010: the old session's stealth transport was actually
    /// stopped. Read from the transport itself rather than predicted from the
    /// response: the early refusals in `prepare_tunnel` (protection
    /// enforcement, the fallback check, the Xray parameter validation) all
    /// return before `XrayManager::start` stops anything, and a switch they
    /// refuse must keep the old session (iOS #354).
    fn old_transport_touched(&self, xray: &XrayManager) -> bool {
        self.old_stealth_mark
            .is_some_and(|mark| xray.ended_count() != mark)
    }
}

/// REVIEW-WIN-001: whether a protected session is live, from POSSESSION of a
/// tunnel rather than from the published label alone.
///
/// The label it replaced, `is_tunnel_active()`, is `Connected` only. A connect
/// that supersedes a switch still in its API phase reads the `Switching` that
/// switch wrote, while the OLD tunnel is still held and carrying traffic: it
/// then skipped the rebuild guard, displaced that tunnel unguarded (the
/// reactive kill switch leaks for the whole rebuild) and, on failure, released
/// nothing it had promised to hold. `Switching` with a tunnel held is exactly
/// that case. `Reconnecting` and `Error` with a tunnel held are a DEAD tunnel
/// the reconnect loop had not torn down yet: not a session to keep.
fn session_was_live(state: &ConnectionState, holds_tunnel: bool) -> bool {
    holds_tunnel
        && matches!(
            state,
            ConnectionState::Connected | ConnectionState::Switching
        )
}

/// Connect (or switch) to `target` for the user. See the module docs.
pub(crate) async fn connect_session(
    app: &AppHandle,
    target: ConnectTarget,
) -> Result<(), IpcError> {
    connect_session_for(app, target, ConnectPurpose::User, None)
        .await
        .result
}

/// How a connect ended, and the epoch it ran under (`None`: it never
/// began). A connect that follows it up checks that epoch has not moved
/// (WIN3-002, see `connect_session_for`).
pub(crate) struct ConnectOutcome {
    pub(crate) epoch: Option<u64>,
    pub(crate) result: Result<(), IpcError>,
}

impl ConnectOutcome {
    fn never_began(error: IpcError) -> Self {
        Self {
            epoch: None,
            result: Err(error),
        }
    }
}

/// [`connect_session`] for `purpose`.
///
/// `follows`: the epoch of the attempt this connect follows up — the
/// settings revert follows the rebuild that failed. It begins only while that
/// epoch is still current, so a Disconnect or a newer connect since then wins
/// and this resolves `cancelled` (`VpnManager::begin_follow_up`). `None`
/// supersedes whatever is in flight, as a user's connect must.
pub(crate) async fn connect_session_for(
    app: &AppHandle,
    target: ConnectTarget,
    purpose: ConnectPurpose,
    follows: Option<u64>,
) -> ConnectOutcome {
    // Pre-flight: Wintun adapter creation is an in-process FFI call that
    // requires administrator — failing early with a clear error beats a
    // cryptic Win32 one deep in the tunnel code.
    if !crate::utils::elevation::is_elevated() {
        return ConnectOutcome::never_began(IpcError::not_elevated());
    }
    let api = app.state::<BirdoApi>();
    if let Err(error) = ensure_signed_in(&api, &app.state::<CredentialStore>()).await {
        return ConnectOutcome::never_began(error);
    }
    let vm = app.state::<VpnManager>();
    let ar = app.state::<AutoReconnectService>();

    // W1-021/W1-022: supersede whatever is in flight (an older connect, an
    // auto-reconnect dial) and stop the reconnect loop BEFORE anything else,
    // on every target. `store_last_config` only runs after a SUCCESSFUL
    // connect, so a loop left running here recovers a failed switch onto the
    // server the user just switched away from. Under the commit lock, so an
    // older attempt either finished committing before this (and its loop is
    // stopped here) or sees its epoch superseded and commits nothing.
    let began = {
        let _commit = vm.lock_commit().await;
        let began = match follows {
            None => Some(vm.begin_attempt()),
            Some(of) => vm.begin_follow_up(of),
        };
        if began.is_some() {
            ar.stop().await;
        }
        began
    };
    let Some(epoch) = began else {
        tracing::info!("A disconnect or a newer connect came first — not reconnecting");
        return ConnectOutcome::never_began(IpcError::cancelled());
    };

    let was_live = session_was_live(&vm.get_state().await, vm.holds_tunnel().await);
    // Before the state says Connecting/Switching, which is what the UI acts on.
    let intent_seen = killswitch::intent_seq();
    let _ = vm
        .set_state(if was_live {
            ConnectionState::Switching
        } else {
            ConnectionState::Connecting
        })
        .await;

    let xray = app.state::<XrayManager>();
    let mut ctx = AttemptContext {
        epoch,
        was_live,
        // A block already engaged — a reconnect this connect interrupted, or
        // a give-up — is released on success exactly like the rebuild guard:
        // left alone, a reactive block (no tunnel permit) would hold the new
        // session's traffic under a "Protected" UI.
        block_engaged: killswitch::platform_is_blocking(),
        // A live xray is the old session's transport: the commit stops any
        // xray a non-stealth session would otherwise inherit.
        old_stealth_mark: if was_live && xray.is_running().await {
            Some(xray.ended_count())
        } else {
            None
        },
        #[cfg(target_os = "windows")]
        old_relay: crate::vpn::wfp::current_relay(),
        intent_seen,
    };
    let (first_transport, adaptive) = match purpose {
        ConnectPurpose::User => (None, true),
        ConnectPurpose::SettingsReapply { fallback_reason } => (fallback_reason, false),
    };
    let mut result = attempt(app, &target, first_transport, &mut ctx).await;

    // ADAPTIVE TRANSPORT: when the direct attempt failed in the
    // transport-shaped way (the establish-time handshake was unanswered or
    // refused), retry ONCE with the backend's any-plan stealth grant. A single
    // retry cannot loop: the stealth attempt's handshake runs against the
    // local Xray proxy, whose failures do not classify as transport-shaped.
    // Not for a settings reapply (see `ConnectPurpose`).
    if let Some(direct) = result.as_ref().err().filter(|_| adaptive) {
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

    let result = match result {
        Ok(()) => Ok(()),
        Err(error) => Err(fail_connect(app, error, &ctx).await),
    };
    ConnectOutcome {
        epoch: Some(epoch),
        result,
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
    let forced_stealth = crate::commands::settings::load_settings_off_runtime(app)
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
        return Err(IpcError::connect_refused(&message, response.quota_exceeded));
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
    //
    // REVIEW-WIN-001: decided by what `vm.connect` is about to displace — a
    // tunnel held right now — not only by what the start of the attempt
    // believed. Whatever it displaces was the user's protection, so a failure
    // from here on holds the block too.
    let guard_rebuild = ctx.was_live || vm.holds_tunnel().await;
    if guard_rebuild {
        ctx.was_live = true;
        ctx.block_engaged = true;
    }
    // REVIEW-WIN2-001: the guard and the relay permit move in ONE commit, so
    // the block that goes up already lets the new handshake out. The guard
    // used to engage first, naming the OLD relay, and lockdown never re-baked
    // the permit, so every switch's handshake was dropped by our own block. A
    // block already held (a give-up, lockdown) is rebuilt with the new relay
    // by the same call. A switch that fails before this point leaves the old
    // session's permit.
    apply_relay_permit(
        &prepared.relay_endpoint,
        prepared.started_stealth,
        guard_rebuild,
    )
    .await;

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
    if let Err(e) = killswitch::arm_since(app, ctx.intent_seen).await {
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
    // What a later settings reapply goes back to if it cannot be applied.
    ar.store_connected_settings(settings.snapshot).await;
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

/// How a failed user connect ends (W1-010). Pure, so every branch is tested.
#[derive(Debug, PartialEq, Eq)]
enum FailureOutcome {
    /// Superseded by a disconnect or a newer connect: it owns the state.
    Cancelled,
    /// iOS #354: a switch that failed BEFORE the old tunnel was touched keeps
    /// the old session, and the error is shown beside it.
    KeepOldSession,
    /// End in `error`. `hold_block`: a protected session was live, and its
    /// traffic has nowhere safe to go, so the block (if armed) stays up.
    Error { hold_block: bool },
}

fn failure_outcome(
    superseded: bool,
    was_live: bool,
    old_transport_touched: bool,
    old_tunnel_held: bool,
) -> FailureOutcome {
    if superseded {
        FailureOutcome::Cancelled
    } else if was_live && !old_transport_touched && old_tunnel_held {
        FailureOutcome::KeepOldSession
    } else {
        FailureOutcome::Error {
            hold_block: was_live,
        }
    }
}

/// Land a failed user connect in a state the contract can explain (W1-010):
/// never an unexplained block, never a silent revert to another server.
async fn fail_connect(app: &AppHandle, error: IpcError, ctx: &AttemptContext) -> IpcError {
    let vm = app.state::<VpnManager>();
    // Under the commit lock, like a successful commit: a disconnect landing
    // now must not have its `disconnected` overwritten by this `error`, nor a
    // reverted session restarted behind it.
    let _commit = vm.lock_commit().await;
    let outcome = failure_outcome(
        error.code == IpcErrorCode::Cancelled || !vm.is_current(ctx.epoch),
        ctx.was_live,
        ctx.old_transport_touched(&app.state::<XrayManager>()),
        vm.holds_tunnel().await,
    );
    let hold_block = match outcome {
        FailureOutcome::Cancelled => return IpcError::cancelled(),
        FailureOutcome::KeepOldSession => {
            tracing::error!("Switch failed; keeping the current session: {}", error);
            // The relay permit may already have moved to the new server, just
            // before the rebuild (REVIEW-WIN2-001); a block held for the
            // session (lockdown) would then drop the kept session's own
            // WireGuard traffic. Point it back.
            #[cfg(target_os = "windows")]
            if let Some(relay) = ctx.old_relay {
                if crate::vpn::wfp::current_relay() != Some(relay) {
                    if let Err(e) = killswitch::move_relay(relay, false).await {
                        tracing::warn!("Could not put the kept session's relay permit back: {}", e);
                    }
                }
            }
            // Its reconnect info is still the old one (the new target is only
            // stored on success), so the loop goes back to guarding it.
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
        FailureOutcome::Error { hold_block } => hold_block,
    };
    tracing::error!("Connect failed: {}", error);

    // The UI shows `kill_switch_blocking` with a working Disconnect, which is
    // the documented way out. (A no-op when the kill switch is not armed.)
    if hold_block {
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
            response.quota_exceeded,
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

/// Point the kill switch's relay permit at `endpoint` before the handshake
/// that needs it, rebuilding a block already in force around it. With
/// `engage`, also put the block-all up for the rebuild of a live session: the
/// block and the new relay's permit then come into force together
/// (REVIEW-WIN2-001). `stealth`: the relay is reached by the xray helper over
/// TCP rather than by our own WireGuard socket over UDP, which is what the
/// Windows permit is scoped to (W1-013).
pub(crate) async fn apply_relay_permit(endpoint: &str, stealth: bool, engage: bool) {
    let ip = parse_endpoint_ip(endpoint);
    match ip {
        Some(ip) => killswitch::set_vpn_server_ip(Some(ip)).await,
        None => {
            // P6-CLI-D-03: the endpoint names the relay, so both lines are
            // redacted (`redact_*` is a pass-through in debug builds).
            tracing::warn!(
                "Could not resolve kill switch endpoint IP from '{}'; kill switch may not \
                 filter traffic to the VPN server correctly",
                crate::utils::redact::redact_hostname(endpoint)
            );
            tracing::debug!(
                "Unresolvable kill switch endpoint: {}",
                crate::utils::redact_endpoint(endpoint)
            );
        }
    }
    #[cfg(target_os = "windows")]
    {
        use crate::vpn::wfp_policy::{parse_relay, RelayTransport};
        let transport = if stealth {
            RelayTransport::StealthTcp
        } else {
            RelayTransport::WireGuardUdp
        };
        match parse_relay(endpoint, transport) {
            Some(relay) => {
                if let Err(e) = killswitch::move_relay(relay, engage).await {
                    tracing::warn!("Failed to move the WFP relay permit: {}", e);
                }
            }
            None => {
                if ip.is_some() {
                    tracing::warn!("Kill switch relay endpoint has no usable port");
                }
                // No relay to permit, but the rebuild is still guarded.
                if engage {
                    if let Err(e) = killswitch::activate_killswitch().await {
                        tracing::warn!("Kill switch activation before the rebuild failed: {}", e);
                    }
                }
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = stealth;
        if engage {
            // pf and iptables read the relay from VPN_SERVER_IP, recorded
            // above, so engaging now is one load that already permits it.
            if let Err(e) = killswitch::activate_killswitch().await {
                tracing::warn!("Kill switch activation before the rebuild failed: {}", e);
            }
            return;
        }
        let Some(ip) = ip else {
            return;
        };
        // Linux twin: the relay is permitted by ADDRESS and the self-permit is
        // scoped to tcp/443, so a connect onto a different server needs the
        // live block re-armed or its handshake is dropped.
        //
        // Through the kill switch, like macOS below (review of #222): it reads
        // the intent before and after the load, and lifts what an OFF no
        // longer wants — a partial load included. iptables reads the relay
        // from VPN_SERVER_IP, recorded above.
        #[cfg(target_os = "linux")]
        {
            let _ = ip;
            if killswitch::platform_is_blocking() {
                if let Err(e) = killswitch::activate_killswitch().await {
                    tracing::warn!("Failed to update iptables VPN server permit: {}", e);
                }
            }
        }
        // macOS twin: pf bakes the relay permit into the loaded ruleset, so an
        // engaged block must be re-loaded with the NEW relay IP (block drop
        // all wins).
        #[cfg(target_os = "macos")]
        {
            let _ = ip;
            if killswitch::pf_blocking_active() {
                if let Err(e) = killswitch::activate_killswitch().await {
                    tracing::warn!("Failed to update pf VPN server permit: {}", e);
                }
            }
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

/// The longest a session end waits for its teardown before it releases the
/// block anyway (WIN-FIX-3). Every step of the teardown has its own bound,
/// the reconnect loop's stop grace (35 s) the longest, so this fires only on
/// an engine that is wedged — and then the user's Disconnect still frees the
/// machine instead of waiting on it.
const RELEASE_DEADLINE: Duration = Duration::from_secs(40);

/// End the session from ANY state (contract §3.1): cancel an in-flight
/// connect or re-dial, stop auto-reconnect, stop the stealth transport,
/// release the server-side peer, tear the tunnel down and release the WFP
/// block — an explicit end ALWAYS releases, always-on included — ending at
/// `disconnected` with `kill_switch_blocking=false`.
///
/// The block is released last, once the teardown is done — or at
/// [`RELEASE_DEADLINE`], whichever comes first: a wedged engine must never
/// hold the block with Disconnect pressed (WIN-FIX-3). A teardown past the
/// deadline carries on behind the release; it cannot re-engage the block
/// (`disarm` clears the kill switch's intent), and a new connect waits for it
/// on the commit lock it holds.
pub async fn end_session(app: &AppHandle, reason: EndReason) {
    tracing::info!("Ending the VPN session ({reason:?})");
    let teardown = tauri::async_runtime::spawn(tear_down(app.clone(), reason));
    if timeout(RELEASE_DEADLINE, teardown).await.is_err() {
        tracing::error!(
            "The session teardown has not finished after {} s — releasing the kill switch's \
             block anyway; the teardown carries on",
            RELEASE_DEADLINE.as_secs()
        );
    }

    // The 3e6f1e2 escape hatch, unconditionally: ending the session is the
    // user releasing the block, and is_lockdown_mode() is hard false
    // off-Windows, so any gate here would leave macOS/Linux behind a kernel
    // firewall with no session to own it. A no-op if never armed.
    let _ = killswitch::disarm().await;
    // `disconnect()` returns early when no tunnel is held (an Error after a
    // give-up), so the end state is written here, whatever came before.
    let _ = app
        .state::<VpnManager>()
        .set_state(ConnectionState::Disconnected)
        .await;
}

/// Everything [`end_session`] does before it releases the block, in order.
async fn tear_down(app: AppHandle, reason: EndReason) {
    let app = &app;
    let vm = app.state::<VpnManager>();

    // Cancel FIRST: an in-flight connect or re-dial stops at its next await,
    // including mid-build, so nothing below races a tunnel coming up. And
    // again once the lock is held, for a connect that was queued on it
    // (REVIEW-WIN-003, see `lock_commit_for_teardown`). "Next await" is not
    // always prompt: a build inside a synchronous route/DNS step finishes it
    // first, and the `disconnect()` below waits behind it for at most the
    // operation-lock timeout (`vpn::manager` docs, REVIEW-WIN-013).
    let _commit = vm.lock_commit_for_teardown().await;

    let ar = app.state::<AutoReconnectService>();
    ar.stop().await;
    ar.clear_last_config().await;

    // PERF-DISCONNECT: free the server-side peer (and device slot) while the
    // tunnel is still up. A courtesy call: tightly capped, never fatal. The
    // stealth transport stays up until after it: this call rides the tunnel,
    // and stopping xray first (as the old disconnect did) sent it into a dead
    // tunnel — a 3 s stall on every stealth disconnect, and the peer was
    // never released.
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
    app.state::<XrayManager>().stop().await;
}

static EXPIRY_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// Contract §3.3: the sign-in session is over. Tear the VPN down, clear the
/// tokens and tell the UI, which routes to sign-in with a banner.
/// `stored`: whether the keystore's copy goes too — only when the server
/// rejected the refresh token itself (`session_gate::StoredSession`).
/// Idempotent: every request in flight can report the same rejection.
pub async fn handle_session_expired(app: &AppHandle, stored: StoredSession) {
    if EXPIRY_IN_FLIGHT.swap(true, Ordering::SeqCst) {
        return;
    }
    tracing::warn!("The sign-in session ended — signing out");
    let api = app.state::<BirdoApi>();
    // REVIEW-WIN2-021: the tokens to clear are the ones that expired. The UI
    // is on Login at once, and the teardown below takes seconds: a user who
    // signs straight back in has new tokens by the time it is over.
    let expired = api.access_token_value().await;
    end_session(app, EndReason::SessionExpired).await;
    if api.clear_tokens_if(expired.as_deref()).await {
        if stored == StoredSession::Discard {
            if let Err(e) = app.state::<CredentialStore>().clear_tokens() {
                tracing::warn!(
                    "Could not clear the stored session: {}",
                    crate::utils::redact::sanitize_error(&e.to_string())
                );
            }
        }
        // REVIEW-WIN-007 / REVIEW-WIN2-023: the next account to sign in on
        // this machine must not inherit this one's server or route.
        crate::commands::settings::clear_account_choices(app).await;
    } else {
        tracing::info!("A new sign-in arrived while the expired session ended — keeping it");
    }
    // Only "expired" is emitted: the backend's refresh 401 carries nothing
    // that tells a revoked session apart from an expired one.
    let _ = app.emit(
        "session-expired",
        serde_json::json!({ "reason": "expired" }),
    );
    EXPIRY_IN_FLIGHT.store(false, Ordering::SeqCst);
}

/// A command was refused with `session_expired` (REVIEW-WIN-012).
///
/// Rust ends the session on its own only when the REFRESH is rejected (the
/// `session_gate`). An `Unauthorized` on a request retried after a successful
/// refresh, or a call with no session at all, also maps to `session_expired`,
/// and the UI then signs out and shows Login — while the tunnel stayed up and
/// auto-reconnect kept running, watched by nothing, and a later give-up under
/// lockdown could hold the block behind the Login screen. The UI calls this
/// whenever it ends a session over such an answer, so Rust ends it too: the
/// same teardown and `session-expired` event as §3.3.
///
/// The keystore's tokens are KEPT here (REVIEW-WIN2-003). A refresh the server
/// refused has already gone through the gate, which discards them when the
/// token itself was rejected; whatever else reaches the UI as
/// `session_expired` — no session in memory, a 401 on a request retried after
/// a refresh that worked — is no proof the stored session is dead, and a later
/// launch re-checks it. Idempotent, like `handle_session_expired`.
#[tauri::command]
pub async fn end_expired_session(app: AppHandle) {
    handle_session_expired(&app, StoredSession::Keep).await;
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
    /// WIN-FIX-3: "last" is after the teardown or at the release deadline,
    /// whichever comes first.
    #[test]
    fn end_session_cancels_first_and_disarms_last() {
        order(
            body("async fn tear_down("),
            &[
                "vm.lock_commit_for_teardown()",
                "ar.stop()",
                "ar.clear_last_config()",
                "api.disconnect_vpn(&key_id)",
                "vm.disconnect()",
                "XrayManager>().stop()",
            ],
        );
        order(
            body("pub async fn end_session("),
            &[
                "spawn(tear_down(app.clone(), reason))",
                "timeout(RELEASE_DEADLINE, teardown)",
                "killswitch::disarm()",
                "ConnectionState::Disconnected",
            ],
        );
        assert!(!body("async fn tear_down(").contains("killswitch::disarm()"));
        assert_eq!(super::RELEASE_DEADLINE, std::time::Duration::from_secs(40));
    }

    /// WIN-FIX-3: quitting never depends on the async runtime. Its teardown
    /// is a task on that runtime; a runtime that cannot run it (every worker
    /// stuck, the T5 hang) held the exit open for good, with the block up. A
    /// plain thread exits past the cap, and the WFP block — a dynamic session
    /// — goes with the process.
    #[test]
    fn quitting_exits_even_when_the_runtime_cannot_run_the_teardown() {
        let main_rs = include_str!("../main.rs");
        let held = &main_rs[main_rs
            .find("if !EXIT_TEARDOWN_STARTED.swap(true")
            .expect("the first exit request")..];
        let held = &held[..held.find("} else if").expect("the branch end")];
        order(
            held,
            &[
                "api.prevent_exit();",
                "std::thread::Builder::new()",
                "std::thread::sleep(EXIT_TEARDOWN_CAP + EXIT_FALLBACK_MARGIN)",
                "if !EXIT_TEARDOWN_DONE.load(",
                "utils::run_on_helper_for(",
                "EXIT_FALLBACK_CLEANUP,",
                "error!(",
                "release_dns_at_exit()",
                "std::process::exit(0)",
                "tauri::async_runtime::spawn(async move {",
            ],
        );
        // WIN3-006: nothing between the decision and the bounded helper can
        // wait on what the wedged teardown holds (the helper's own wait is
        // tested in `utils`).
        let decided = &held[held.find("if !EXIT_TEARDOWN_DONE.load(").unwrap()..];
        let before_helper = &decided[..decided.find("utils::run_on_helper_for(").unwrap()];
        for blocking in ["error!(", "release_dns_at_exit", "restore_dns_blocking"] {
            assert!(!before_helper.contains(blocking), "{blocking}");
        }
    }

    /// WIN-FIX-3: a settings reapply is rebuilt on the session's own
    /// transport and never runs the Adaptive Transport retry; a user connect
    /// starts direct and does. The session's settings are recorded at the
    /// commit, beside its reconnect record, for the reapply's revert.
    #[test]
    fn a_settings_reapply_keeps_its_transport_and_gets_no_stealth_retry() {
        let connect = body("pub(crate) async fn connect_session_for(");
        order(
            connect,
            &[
                "ConnectPurpose::User => (None, true)",
                "ConnectPurpose::SettingsReapply { fallback_reason } => (fallback_reason, false)",
                "attempt(app, &target, first_transport, &mut ctx)",
                ".filter(|_| adaptive)",
                "fallback_reason_for(app, &target, direct)",
            ],
        );
        order(
            body("async fn attempt("),
            &[
                "killswitch::arm_since(app, ctx.intent_seen)",
                "ar.store_connected_settings(settings.snapshot)",
                "ar.store_last_config(",
            ],
        );
    }

    /// Round 6 of the review of #222 (P3-1): the dial reads the kill switch
    /// intent's sequence before its state says Connecting/Switching, and its
    /// arm stores only if nothing wrote the intent since (killswitch tests
    /// `an_off_during_the_dial_makes_its_arm_stand_aside`).
    #[test]
    fn the_dials_arm_takes_the_intent_sequence_from_the_dials_start() {
        order(
            body("pub(crate) async fn connect_session_for("),
            &[
                "let Some(epoch) = began else {",
                "let intent_seen = killswitch::intent_seq();",
                ".set_state(if was_live {",
                "intent_seen,",
                "attempt(app, &target, first_transport",
            ],
        );
        let attempt = body("async fn attempt(");
        assert!(attempt.contains("killswitch::arm_since(app, ctx.intent_seen)"));
        assert!(!attempt.contains("killswitch::arm(app)"));
    }

    /// W1-022: every target stops auto-reconnect before anything is dialled,
    /// under the commit lock, with a fresh epoch. WIN3-002: a follow-up (the
    /// settings revert) takes its epoch only while the attempt it follows is
    /// still current — checked under the same lock — and otherwise touches
    /// nothing, the loop included (`begin_follow_up` is tested in `manager`).
    #[test]
    fn connect_session_supersedes_and_stops_the_loop_first() {
        let connect = body("pub(crate) async fn connect_session_for(");
        order(
            connect,
            &[
                "vm.lock_commit()",
                "None => Some(vm.begin_attempt())",
                "Some(of) => vm.begin_follow_up(of)",
                "if began.is_some() {",
                "ar.stop()",
                "let Some(epoch) = began else {",
                "ConnectOutcome::never_began(IpcError::cancelled())",
                "attempt(app, &target, first_transport",
            ],
        );
        order(
            body("pub(crate) async fn connect_session("),
            &["connect_session_for(app, target, ConnectPurpose::User, None)"],
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
                "killswitch::arm_since(app, ctx.intent_seen)",
                "ar.store_last_config(",
                "ar.start()",
            ],
        );
    }

    /// REVIEW-WIN-012: a command-level `session_expired` ends the session in
    /// Rust through the same §3.3 path as a rejected refresh — keeping the
    /// keystore's tokens, which only the refresh's own rejection discards
    /// (REVIEW-WIN2-003). The tokens cleared are the ones that expired, read
    /// BEFORE the teardown (REVIEW-WIN2-021; `clear_tokens_if` is tested in
    /// `api::client`).
    #[test]
    fn an_expired_session_reported_by_the_ui_takes_the_same_path() {
        order(
            body("pub async fn end_expired_session("),
            &["handle_session_expired(&app, StoredSession::Keep)"],
        );
        let handled = body("pub async fn handle_session_expired(");
        order(
            handled,
            &[
                "api.access_token_value().await",
                "end_session(app, EndReason::SessionExpired)",
                "api.clear_tokens_if(expired.as_deref())",
                "stored == StoredSession::Discard",
                "CredentialStore>().clear_tokens()",
                "settings::clear_account_choices(app)",
                "\"session-expired\"",
            ],
        );
        assert!(
            !handled.contains("api.clear_tokens()") && !handled.contains(".clear_tokens().await"),
            "an unconditional clear wipes a session signed in during the teardown"
        );
    }

    /// W1-010: every way a user connect can fail ends somewhere explainable.
    #[test]
    fn a_failed_connect_ends_in_an_explainable_state() {
        use super::{failure_outcome, FailureOutcome};
        // A disconnect or newer connect superseded it: hands off.
        assert_eq!(
            failure_outcome(true, true, false, true),
            FailureOutcome::Cancelled
        );
        // A switch that failed before touching the old tunnel keeps it.
        assert_eq!(
            failure_outcome(false, true, false, true),
            FailureOutcome::KeepOldSession
        );
        // The old tunnel is gone, or its stealth transport was restarted: the
        // protected session is over — error, block held.
        for (touched, held) in [(false, false), (true, true), (true, false)] {
            assert_eq!(
                failure_outcome(false, true, touched, held),
                FailureOutcome::Error { hold_block: true },
                "touched={touched} held={held}"
            );
        }
        // A fresh connect that failed: error, nothing to hold.
        assert_eq!(
            failure_outcome(false, false, false, false),
            FailureOutcome::Error { hold_block: false }
        );
    }

    /// W1-043: the guard engages after the API/stealth phase, right before
    /// the tunnel is rebuilt — and (REVIEW-WIN-001) whenever a tunnel is held
    /// at that moment, whatever the start of the attempt believed.
    ///
    /// REVIEW-WIN2-001: it engages INSIDE the relay move, one commit; what
    /// that commit holds is tested behaviourally in `wfp_policy`
    /// (`a_lockdown_switch_commits_the_new_relay_with_the_block` and its
    /// siblings). This pin only keeps the step where it must be: before the
    /// handshake, with no separate engage naming the old relay.
    #[test]
    fn the_switch_guard_moves_with_the_relay_just_before_the_rebuild() {
        let attempt = body("async fn attempt(");
        order(
            attempt,
            &[
                "prepare_tunnel(",
                "vm.holds_tunnel().await",
                "apply_relay_permit(",
                "guard_rebuild,",
                "vm.connect(",
            ],
        );
        assert!(
            !attempt.contains("engage_rebuild_block("),
            "a separate engage puts the block up naming the previous relay"
        );
    }

    /// REVIEW-WIN-001, the reapply-racing-a-switch scenario. Connected to A;
    /// switch B is in its API call and has published `Switching`; a settings
    /// reapply C supersedes it. Tunnel A is still held and carrying traffic,
    /// so C must treat the session as live: guard the rebuild, keep A if C
    /// fails before touching it, and hold the block if C fails after. The old
    /// derivation (`is_tunnel_active()`, i.e. `Connected` only) read B's
    /// `Switching` as "nothing live".
    #[test]
    fn a_connect_superseding_a_switch_still_sees_the_live_session() {
        use super::{failure_outcome, session_was_live, FailureOutcome};
        use crate::vpn::manager::ConnectionState;

        let was_live = session_was_live(&ConnectionState::Switching, true);
        assert!(was_live, "Switching over a held tunnel is a live session");
        assert_eq!(
            failure_outcome(false, was_live, false, true),
            FailureOutcome::KeepOldSession
        );
        assert_eq!(
            failure_outcome(false, was_live, false, false),
            FailureOutcome::Error { hold_block: true }
        );

        assert!(session_was_live(&ConnectionState::Connected, true));
        // Nothing held: nothing to protect, whatever the label says.
        assert!(!session_was_live(&ConnectionState::Connected, false));
        assert!(!session_was_live(&ConnectionState::Switching, false));
        // A dead tunnel the reconnect loop had not torn down is not a session
        // to keep (the guard before `vm.connect` still covers its rebuild).
        for dead in [
            ConnectionState::Reconnecting {
                attempt: 1,
                last_error: None,
            },
            ConnectionState::Error(crate::commands::ipc_error::IpcError::unknown("x")),
        ] {
            assert!(!session_was_live(&dead, true), "{dead:?}");
        }
    }

    /// REVIEW-WIN-010: a switch the new node refuses before the old xray was
    /// stopped (a requested protection missing, bad Xray parameters) keeps the
    /// old stealth session; once the old transport has really been stopped,
    /// the session is over and the block is held. The child only pings
    /// loopback; nothing leaves the machine.
    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn only_a_stopped_old_transport_ends_the_old_session() {
        use super::{failure_outcome, AttemptContext, FailureOutcome};
        use crate::vpn::xray::XrayManager;

        let xray = XrayManager::new();
        xray.adopt_for_test(
            std::process::Command::new("cmd.exe")
                .args(["/c", "ping -n 30 127.0.0.1 >nul"])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn a long-running child"),
        )
        .await;
        let ctx = AttemptContext {
            epoch: 1,
            was_live: true,
            block_engaged: false,
            old_stealth_mark: Some(xray.ended_count()),
            old_relay: None,
            intent_seen: 0,
        };

        // Refused before XrayManager::start: the old transport is untouched.
        assert!(!ctx.old_transport_touched(&xray));
        assert_eq!(
            failure_outcome(false, ctx.was_live, ctx.old_transport_touched(&xray), true),
            FailureOutcome::KeepOldSession
        );

        // XrayManager::start begins with stop(): from here the old session
        // is gone even though its tunnel is still held.
        xray.stop().await;
        assert!(ctx.old_transport_touched(&xray));
        assert_eq!(
            failure_outcome(false, ctx.was_live, ctx.old_transport_touched(&xray), true),
            FailureOutcome::Error { hold_block: true }
        );
    }
}
