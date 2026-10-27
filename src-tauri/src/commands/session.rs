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
use zeroize::Zeroize;

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
    /// `was_live` as the connect started, before the guard widened it to a
    /// dead tunnel it found held. Only a session live then can be kept when
    /// the switch fails before `vm.connect` (MR-2070, `old_session_gone`).
    live_at_start: bool,
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
    /// The Stealth Mode the latest attempt asked for: `settings.stealth_mode`
    /// from the settings in force for it, recorded by `attempt` before it can
    /// fail. Those are the defaults (stealth OFF) when the file could not be
    /// read (`vpn::settings_in_force`). The Adaptive Transport retry is
    /// decided from this, never from a second read of the file
    /// (`fallback_reason_for`).
    stealth_mode: bool,
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

    /// Whether the old session can no longer carry traffic, even with its
    /// tunnel still held: its stealth transport was stopped, or it was never
    /// live — a dead tunnel the guard before `vm.connect` took into
    /// `was_live`, which a switch refused at the relay permit (MR-2070) now
    /// fails on while that tunnel is still held. Such a tunnel is never kept
    /// as the session: a failure holds the block instead.
    fn old_session_gone(&self, xray: &XrayManager) -> bool {
        !self.live_at_start || self.old_transport_touched(xray)
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
        live_at_start: was_live,
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
        // `attempt` records what it asks for before anything can fail.
        stealth_mode: false,
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
        if let Some(reason) = fallback_reason_for(&target, direct, ctx.stealth_mode) {
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
/// `attempted_stealth`: the Stealth Mode the failed attempt asked for
/// ([`AttemptContext::stealth_mode`]).
fn fallback_reason_for(
    target: &ConnectTarget,
    error: &IpcError,
    attempted_stealth: bool,
) -> Option<&'static str> {
    // The Multi-Hop connect contract has no `fallbackReason`: Multi-Hop asks
    // for stealth up front through the same grant (mirrors Android).
    if !matches!(target, ConnectTarget::SingleHop { .. }) {
        return None;
    }
    let reason = transport_fallback_reason(error)?;
    // Respect an explicit transport choice: with Stealth Mode forced ON the
    // failed attempt WAS the stealth transport, and it is the last we have.
    // Decided by what that attempt asked for, not by reading settings.json
    // again: when the attempt's own read failed (an antivirus lock), it went
    // out direct on the defaults, and a second read that then succeeded with
    // stealth ON suppressed the one retry that would have used it.
    (!attempted_stealth).then_some(reason)
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
    let settings = apply_vpn_settings(app).await;
    // What this attempt asks for, for the Adaptive Transport decision should
    // it fail (`fallback_reason_for`).
    ctx.stealth_mode = settings.stealth_mode;

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
    // MR-1639: a refusal the server marks retryable with a wait
    // (`psk_delivery_unavailable`, `quota_check_unavailable`,
    // `tunnel_address_unavailable` since MR-2057) is asked ONCE
    // more, after that wait (clamped at parse), with the SAME `settings` and
    // the SAME post-quantum key. Nothing is re-read between the two, so the
    // second request cannot go out without the Quantum Protection (or
    // Stealth) the first one asked for: a PQ connect is retried as a PQ
    // connect or fails, closed, with the server's error. A Disconnect during
    // the wait cancels it like any other step.
    let mut retried = false;
    let (response, multi_hop, dialled_id, private_key) = loop {
        // FIX-1-1: the X25519 keypair is generated here — the private key
        // never leaves this device. A fresh one per request, so a refused
        // request's key is never sent again. MR-822: it is a `WgPrivateKey`,
        // moved out of this loop to `vm.connect` and on into the tunnel; a
        // refused request's key, and every early return before that, drops
        // it, which wipes it.
        let (private_key, client_public_key) = generate_wireguard_keypair();
        let asked: Result<(ConnectResponse, Option<MultiHopStatus>, &str), IpcError> = async {
            match target {
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
                                pq_pk.clone(),
                                settings.dns_filtering,
                            ),
                        )
                        .await?
                        .map_err(|e| {
                            tracing::error!("API call failed: {}", e);
                            IpcError::from(e)
                        })?;
                    tracing::info!("API response received: success={}", response.success);
                    Ok((response, None, server_id.as_str()))
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
                                pq_pk.clone(),
                                settings.dns_filtering,
                            ),
                        )
                        .await?
                        .map_err(IpcError::from)?;
                    let (response, route) =
                        verified_multi_hop_response(response, entry_id, exit_id)?;
                    Ok((response, Some(route), entry_id.as_str()))
                }
            }
        }
        .await;
        match asked {
            Ok((response, multi_hop, dialled_id)) => {
                break (response, multi_hop, dialled_id, private_key)
            }
            Err(error) => match error.server_asked_to_wait().filter(|_| !retried) {
                Some(wait) => {
                    retried = true;
                    tracing::warn!(
                        "Connect refused as retryable ({}) — asking once more in {}s",
                        error,
                        wait.as_secs()
                    );
                    vm.run_cancellable(ctx.epoch, tokio::time::sleep(wait))
                        .await?;
                }
                None => return Err(error),
            },
        }
    };
    if !response.success {
        let message = response
            .message
            .clone()
            .unwrap_or_else(|| "Connection failed".to_string());
        tracing::error!("Server rejected connection: {}", message);
        return Err(IpcError::connect_refused(
            &message,
            response.quota_exceeded,
            response.refusal_reason.as_deref(),
        ));
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
    //
    // MR-2070: and when that step fails, nothing is rebuilt. `vm.connect`
    // tears down the tunnel it displaces and dials the new relay; with the
    // guard not up (reactive mode, no block before it) all of that went out
    // in the clear, the failure only logged. The switch fails here instead,
    // before the old tunnel is touched: `fail_connect` keeps a live session,
    // its relay permit pointed back, and ends anything else in `error` with
    // the block held — or, where no block can go up, the tunnel left in
    // place.
    apply_relay_permit(
        &prepared.relay_endpoint,
        prepared.started_stealth,
        guard_rebuild,
    )
    .await
    .map_err(|e| {
        tracing::error!("Not rebuilding: the kill switch is not ready for the new relay ({e})");
        IpcError::new(
            IpcErrorCode::KillswitchFailed,
            "The kill switch could not block traffic for the new connection.",
        )
    })?;

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
        private_key,
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
    /// End in `error`. `hold_block`: a protected session was live, or a
    /// tunnel is still held, and its traffic has nowhere safe to go, so the
    /// block (if armed) stays up.
    Error { hold_block: bool },
}

/// `old_session_gone`: [`AttemptContext::old_session_gone`].
///
/// MR-2070: a tunnel still held when a connect fails is the user's protection
/// whatever the start of the connect believed — a dead one included, which
/// the kill switch keeps in place while it cannot block (`fail_connect`,
/// `auto_reconnect`'s hold). It used to be torn down with no block asked for.
fn failure_outcome(
    superseded: bool,
    was_live: bool,
    old_session_gone: bool,
    old_tunnel_held: bool,
) -> FailureOutcome {
    if superseded {
        FailureOutcome::Cancelled
    } else if was_live && !old_session_gone && old_tunnel_held {
        FailureOutcome::KeepOldSession
    } else {
        FailureOutcome::Error {
            hold_block: was_live || old_tunnel_held,
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
        ctx.old_session_gone(&app.state::<XrayManager>()),
        vm.holds_tunnel().await,
    );
    let hold_block = match outcome {
        FailureOutcome::Cancelled => return IpcError::cancelled(),
        FailureOutcome::KeepOldSession => {
            tracing::error!("Switch failed; keeping the current session: {}", error);
            // The relay permit may already have moved to the new server, just
            // before the rebuild (REVIEW-WIN2-001); a block held for the
            // session (lockdown) would then drop the kept session's own
            // WireGuard traffic. Point it back. A move that failed (MR-2070)
            // left the old block in force, but the relay it records already
            // names the new server, for the next block that goes up.
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
    //
    // MR-2070: a block the kill switch wants but cannot put up leaves the
    // tunnel still held in place, so its routes keep the traffic the block
    // could not (`reconnect_policy::teardown_covered`, the rule the reconnect
    // loop's teardown follows). Torn down, everything went out in the clear
    // as soon as a switch refused at the relay permit ended. The kept tunnel
    // reads as the block (`VpnManager::keep_tunnel_in_error`): Disconnect,
    // the main button and the tray's, releases it, as it releases a block;
    // with the kill switch turned off, the next connect displaces it
    // unguarded, as asked.
    let mut keep_tunnel = false;
    if hold_block {
        let engaged = killswitch::activate_killswitch().await;
        if let Err(e) = &engaged {
            tracing::warn!("Kill switch activation after a failed switch failed: {}", e);
        }
        keep_tunnel = crate::vpn::reconnect_policy::teardown_covered(
            &engaged,
            killswitch::platform_is_blocking(),
        )
        .is_err();
    }
    let held = vm.holds_tunnel().await;
    let error = if held && keep_tunnel {
        tracing::error!(
            "The kill switch could not block traffic — keeping the tunnel in place, so \
             nothing leaves outside it, until you disconnect"
        );
        // What holds the traffic now is the kill switch's doing, so that is
        // the error shown: the connect's own (a dead tunnel swallows its API
        // call, so often "unreachable") would send the user to their network.
        kept_tunnel_error()
    } else {
        error
    };
    if held && keep_tunnel {
        vm.keep_tunnel_in_error(error.clone()).await;
    } else if held {
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

/// The error a failed connect ends in when it keeps its tunnel because the
/// kill switch could not block (MR-2070, `fail_connect`).
fn kept_tunnel_error() -> IpcError {
    IpcError::new(
        IpcErrorCode::KillswitchFailed,
        "The kill switch could not block traffic, so the old tunnel is kept in place and \
         nothing leaves outside it. Disconnect to release it.",
    )
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
            response.refusal_reason.as_deref(),
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

/// A validated tunnel config, ready for `VpnManager::connect`. It holds no
/// private key (MR-822): the caller keeps the attempt's `WgPrivateKey` and
/// moves it to `VpnManager::connect` beside this config.
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
/// `build_vpn_config` choke point (`validate_tunnel_scope`). The client's
/// private key does not pass through here (MR-822): it goes from the caller
/// straight to `VpnManager::connect`.
pub(crate) async fn prepare_tunnel(
    app: &AppHandle,
    vm: &VpnManager,
    epoch: u64,
    response: ConnectResponse,
    request: TunnelRequest<'_>,
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
///
/// MR-2070: `Err` when the permit could not be moved or the block could not
/// go up, where it used to be logged and dialled past. A block already in
/// force then stays as it was, naming the previous relay; with `engage`,
/// nothing at all may be blocking. The user's connect fails on it before the
/// old tunnel is touched (`attempt`). The re-dial dials on: the block its
/// `dial` put up first stays in force and drops a handshake it does not
/// permit.
pub(crate) async fn apply_relay_permit(
    endpoint: &str,
    stealth: bool,
    engage: bool,
) -> Result<(), String> {
    let ip = parse_endpoint_ip(endpoint);
    // macOS/Linux: the relay the block permits now, for a guard that fails.
    #[cfg(not(target_os = "windows"))]
    let previous = killswitch::vpn_server_ip();
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
        let relay = parse_relay(endpoint, transport);
        if relay.is_none() && ip.is_some() {
            tracing::warn!("Kill switch relay endpoint has no usable port");
        }
        permit_relay(
            relay,
            engage,
            killswitch::move_relay,
            killswitch::activate_killswitch,
        )
        .await
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = stealth;
        if engage {
            // pf and iptables read the relay from VPN_SERVER_IP, recorded
            // above, so engaging now is one load that already permits it.
            // MR-2070: one that fails gives the relay back to the session
            // the block was for, which the switch then keeps (`attempt`).
            return match killswitch::activate_killswitch().await {
                Ok(_) => Ok(()),
                Err(e) => {
                    killswitch::set_vpn_server_ip(previous).await;
                    Err(format!("the block could not go up for the rebuild: {e}"))
                }
            };
        }
        let Some(ip) = ip else {
            return Ok(());
        };
        // Linux twin: the relay is permitted by ADDRESS and the self-permit is
        // scoped to tcp/443, so a connect onto a different server needs the
        // live block re-armed or its handshake is dropped.
        //
        // Through the kill switch, like macOS below (review of #222): it reads
        // the intent before and after the load, and lifts what an OFF no
        // longer wants — a partial load included. iptables reads the relay
        // from VPN_SERVER_IP, recorded above, under the chains' lock, where
        // whether a block is up is decided too (MR-1998): asked lock-free
        // here, an arm still in flight said no and kept the old relay.
        #[cfg(target_os = "linux")]
        {
            let _ = ip;
            killswitch::rearm_for_relay()
                .await
                .map_err(|e| format!("the iptables relay permit was not updated: {e}"))?;
        }
        // macOS twin: pf bakes the relay permit into the loaded ruleset, so an
        // engaged block must be re-loaded with the NEW relay IP (block drop
        // all wins).
        #[cfg(target_os = "macos")]
        {
            let _ = ip;
            if killswitch::pf_blocking_active() {
                killswitch::activate_killswitch()
                    .await
                    .map_err(|e| format!("the pf relay permit was not updated: {e}"))?;
            }
        }
        Ok(())
    }
}

/// Windows: the relay-permit half of [`apply_relay_permit`]. `move_relay`
/// (`killswitch::move_relay`) points the permit at `relay` and, with
/// `engage`, puts the block-all up in the same commit; with no relay to
/// permit, `engage` puts the block up alone (`activate`,
/// `killswitch::activate_killswitch`). Either failure is returned, never
/// logged and dialled past (MR-2070). The two kill-switch calls are
/// parameters so these paths are tested without a WFP session.
#[cfg(target_os = "windows")]
async fn permit_relay<MF, AF>(
    relay: Option<crate::vpn::wfp_policy::Relay>,
    engage: bool,
    move_relay: impl FnOnce(crate::vpn::wfp_policy::Relay, bool) -> MF,
    activate: impl FnOnce() -> AF,
) -> Result<(), String>
where
    MF: std::future::Future<Output = Result<(), String>>,
    AF: std::future::Future<Output = Result<bool, String>>,
{
    match relay {
        Some(relay) => move_relay(relay, engage)
            .await
            .map_err(|e| format!("the WFP relay permit was not moved: {e}")),
        // No relay to permit, but the rebuild is still guarded.
        None if engage => activate()
            .await
            .map(|_| ())
            .map_err(|e| format!("the block could not go up for the rebuild: {e}")),
        None => Ok(()),
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
/// the reconnect loop's stop grace (35 s) usually the longest, so this fires
/// only on an engine that is wedged — and then the user's Disconnect still
/// frees the machine instead of waiting on it.
///
/// One wedged case can now outlast it by design (MR-2036): a disconnect
/// whose tunnel stop() timed out (15 s) also waits for the cleanup that stop
/// handed to a thread of its own, up to the platform's emergency bound
/// (`vpn::EMERGENCY_TEARDOWN_BOUND`, 65 s on Windows). The release then fires
/// here, and the teardown carries on behind it under the commit lock until
/// that cleanup ends or its bound is spent; a new connect waits for it there.
const RELEASE_DEADLINE: Duration = Duration::from_secs(40);

/// End the session from ANY state (contract §3.1): cancel an in-flight
/// connect or re-dial, stop auto-reconnect, stop the stealth transport,
/// release the server-side peer, tear the tunnel down and release the WFP
/// block — an explicit end ALWAYS releases, always-on included — ending at
/// `disconnected` with `kill_switch_blocking=false`.
///
/// The block is released last: at the end of the teardown, under its commit
/// lock — or at [`RELEASE_DEADLINE`], whichever comes first: a wedged engine
/// must never hold the block with Disconnect pressed (WIN-FIX-3). A teardown
/// past the deadline carries on behind the release; it cannot re-engage the
/// block (`disarm` clears the kill switch's intent), and a new connect waits
/// for it on the commit lock it holds.
pub async fn end_session(app: &AppHandle, reason: EndReason) {
    tracing::info!("Ending the VPN session ({reason:?})");
    // MR-1861: only the session an update ends is put back by the version it
    // installs; any other end is the user's (or the server's) choice.
    if reason != EndReason::Update {
        crate::commands::update_resume::discard();
    }
    let teardown = tauri::async_runtime::spawn(tear_down(app.clone(), reason));
    release_unless_torn_down(teardown, async {
        // The 3e6f1e2 escape hatch, whenever the teardown did not get there:
        // ending the session is the user releasing the block, and
        // is_lockdown_mode() is hard false off-Windows, so any gate here would
        // leave macOS/Linux behind a kernel firewall with no session to own it.
        // A no-op if never armed.
        let _ = killswitch::disarm().await;
        // `disconnect()` returns early when no tunnel is held (an Error after a
        // give-up), so the end state is written here, whatever came before.
        let _ = app
            .state::<VpnManager>()
            .set_state(ConnectionState::Disconnected)
            .await;
    })
    .await;
}

/// [`end_session`]'s wait, apart from the `AppHandle` so a test can drive it
/// on paused time (MR-1408): wait for `teardown` up to [`RELEASE_DEADLINE`]
/// and run `release` unless it finished. A teardown that finished released
/// the block and wrote Disconnected itself, under its commit lock.
///
/// A teardown still running at the deadline is not cancelled, only no longer
/// waited for: `end_session` passes a spawned task's handle, and dropping a
/// handle leaves its task running.
async fn release_unless_torn_down<E: std::fmt::Display>(
    teardown: impl std::future::Future<Output = Result<(), E>>,
    release: impl std::future::Future<Output = ()>,
) {
    match timeout(RELEASE_DEADLINE, teardown).await {
        Ok(Ok(())) => return,
        Ok(Err(e)) => tracing::error!(
            "The session teardown failed ({e}) — releasing the kill switch's block anyway"
        ),
        Err(_) => tracing::error!(
            "The session teardown has not finished after {} s — releasing the kill switch's \
             block anyway; the teardown carries on",
            RELEASE_DEADLINE.as_secs()
        ),
    }
    release.await;
}

/// Everything [`end_session`] does before it releases the block, in order.
async fn tear_down(app: AppHandle, reason: EndReason) {
    let vm = app.state::<VpnManager>();

    // Cancel FIRST: an in-flight connect or re-dial stops at its next await,
    // including mid-build, so nothing below races a tunnel coming up. And
    // again once the lock is held, for a connect that was queued on it
    // (REVIEW-WIN-003, see `lock_commit_for_teardown`). "Next await" is not
    // always prompt: a build inside a synchronous route/DNS step finishes it
    // first, and the `disconnect()` below waits behind it for at most the
    // operation-lock timeout (`vpn::manager` docs, REVIEW-WIN-013).
    let _commit = vm.lock_commit_for_teardown().await;

    end_the_tunnel(&app, reason).await;

    // Release the block and end Disconnected while the commit lock is still
    // held (round 7 of the review of #222, N1). A connect queued on the lock
    // reads the kill switch intent's sequence when it begins: a disarm after
    // the release moved it under that connect, whose arm then stood aside —
    // a new session with the intent OFF while the file and the toggle said
    // ON. A Disconnected written after the release overwrote the new dial's
    // Connecting the same way. Past RELEASE_DEADLINE, end_session does both.
    // After the steps, however they end (round 8): end_session trusts a
    // finished teardown to have done this, so no early return in the steps
    // may skip it.
    let _ = killswitch::disarm().await;
    let _ = vm.set_state(ConnectionState::Disconnected).await;
}

/// The steps of [`tear_down`], under its commit lock, before it releases the
/// block.
async fn end_the_tunnel(app: &AppHandle, reason: EndReason) {
    let vm = app.state::<VpnManager>();
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
    /// WIN-FIX-3: "last" is at the end of the teardown or at the release
    /// deadline, whichever comes first. Round 7 of the review of #222 (N1):
    /// the end of the teardown, under its commit lock, so a connect queued on
    /// that lock reads the intent's sequence after the disarm (its arm stood
    /// aside before) and its Connecting is not overwritten by Disconnected.
    /// end_session disarms and writes Disconnected only when the teardown did
    /// not finish: past the deadline, or failed.
    #[test]
    fn end_session_cancels_first_and_disarms_last() {
        let teardown = body("async fn tear_down(");
        order(
            teardown,
            &[
                "vm.lock_commit_for_teardown()",
                "end_the_tunnel(&app, reason).await",
                "killswitch::disarm()",
                "ConnectionState::Disconnected",
            ],
        );
        order(
            body("async fn end_the_tunnel("),
            &[
                "ar.stop()",
                "ar.clear_last_config()",
                "api.disconnect_vpn(&key_id)",
                "vm.disconnect()",
                "XrayManager>().stop()",
            ],
        );
        // The guard lives to the end of the function, and nothing in it can
        // leave before the disarm (round 8): the steps run in their own
        // function, so an early return there still reaches it.
        assert!(teardown.contains("let _commit = vm.lock_commit_for_teardown().await;"));
        assert!(!teardown.contains("drop(_commit)"));
        let code: String = teardown
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!code.contains("return"), "an early return in tear_down");
        assert!(!code.contains('?'), "a `?` in tear_down");
        // The wiring only: what the wait does with the deadline is driven on
        // paused time in `release_deadline_tests` (MR-1408).
        order(
            body("pub async fn end_session("),
            &[
                "let teardown = tauri::async_runtime::spawn(tear_down(app.clone(), reason));",
                "release_unless_torn_down(teardown, async {",
                "killswitch::disarm()",
                "ConnectionState::Disconnected",
            ],
        );
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
                "utils::exit_unless_torn_down(",
                "&EXIT_TEARDOWN_DONE,",
                "EXIT_FALLBACK_CLEANUP,",
                "error!(",
                "release_dns_at_exit()",
                "|| std::process::exit(0),",
                "tauri::async_runtime::spawn(async move {",
            ],
        );
        // WIN3-006: nothing between the sleep and the bounded decision can
        // wait on what the wedged teardown holds. What the decision does is
        // driven in `utils::tests::the_exit_fallback_exits_whatever_its_cleanup_waits_on`.
        let slept = &held[held
            .find("EXIT_TEARDOWN_CAP + EXIT_FALLBACK_MARGIN")
            .unwrap()..];
        let before_decision = &slept[..slept.find("utils::exit_unless_torn_down(").unwrap()];
        for blocking in ["error!(", "release_dns_at_exit", "restore_dns_blocking"] {
            assert!(!before_decision.contains(blocking), "{blocking}");
        }
    }

    /// MR-1934: macOS's Cmd+Q, the Dock's Quit and logout reach the end of
    /// the run (`RunEvent::Exit`) with no exit request before it, and the
    /// teardown that request runs was skipped: pf's block and the session's
    /// DNS outlived the app. There, off Windows and unless a restart was let
    /// through, the same teardown now runs, capped, before the process ends.
    /// What the helper does is driven in
    /// `utils::tests::an_exit_that_never_asked_first_runs_the_teardown_once`.
    #[test]
    fn an_exit_with_no_exit_request_still_tears_down_off_windows() {
        let main_rs = include_str!("../main.rs").replace('\r', "");
        let exit = &main_rs[main_rs
            .find("if matches!(event, RunEvent::Exit) {")
            .expect("the RunEvent::Exit arm")..];
        let exit = &exit[..exit
            .find("if let RunEvent::ExitRequested")
            .expect("the arm's end")];
        order(
            exit,
            &[
                "record_if_exit_kept_the_session(",
                "#[cfg(not(target_os = \"windows\"))]",
                "if !EXIT_RESTARTING.load(",
                "utils::tear_down_unless_started(",
                "&EXIT_TEARDOWN_STARTED,",
                "EXIT_TEARDOWN_CAP + EXIT_FALLBACK_MARGIN,",
                "tauri::async_runtime::block_on(",
                "teardown_for_exit(&app)",
                "clear_on_exit();",
            ],
        );
        // A restart is let through without the teardown, and says so before
        // it returns, so the end of its run does not run it either.
        let restart = &main_rs[main_rs
            .find("if *code == Some(tauri::RESTART_EXIT_CODE) {")
            .expect("the restart branch")..];
        let restart = &restart[..restart.find("return;").expect("the branch's return")];
        assert!(restart.contains("EXIT_RESTARTING.store(true"));
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
                "fallback_reason_for(&target, direct, ctx.stealth_mode)",
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

    /// The Adaptive Transport retry follows what the failed attempt asked
    /// for, not a second read of settings.json. An antivirus lock failed the
    /// attempt's own read, so it went out direct on the defaults (stealth
    /// OFF, `vpn::settings_in_force`); by the time it failed, the file read
    /// again with Stealth Mode ON. That second read suppressed the retry and
    /// the connect failed; the retry over Xray now goes ahead.
    #[test]
    fn the_stealth_retry_follows_what_the_failed_attempt_asked_for() {
        use super::{fallback_reason_for, AttemptContext, ConnectTarget};
        use crate::commands::ipc_error::IpcError;
        use crate::commands::settings::AppSettings;
        use crate::commands::vpn::FALLBACK_HANDSHAKE_TIMEOUT;

        // The settings in force for an attempt whose read failed: the
        // defaults, which is what `attempt` records.
        let ctx = AttemptContext {
            epoch: 1,
            was_live: false,
            live_at_start: false,
            block_engaged: false,
            old_stealth_mark: None,
            #[cfg(target_os = "windows")]
            old_relay: None,
            intent_seen: 0,
            stealth_mode: AppSettings::default().stealth_mode,
        };
        assert!(!ctx.stealth_mode, "the attempt went out direct");

        let single_hop = ConnectTarget::SingleHop {
            server_id: "node-1".into(),
        };
        let unanswered = IpcError::from_tunnel_failure(&format!(
            "Failed to start tunnel: Handshake failed after 3 attempts: {}",
            crate::vpn::ERR_HANDSHAKE_NO_RESPONSE
        ));
        assert_eq!(
            fallback_reason_for(&single_hop, &unanswered, ctx.stealth_mode),
            Some(FALLBACK_HANDSHAKE_TIMEOUT),
            "the retry over Xray goes ahead, whatever the file says now"
        );
        // An attempt that asked for stealth WAS the stealth transport.
        assert_eq!(fallback_reason_for(&single_hop, &unanswered, true), None);
        let multi_hop = ConnectTarget::MultiHop {
            entry_id: "a".into(),
            exit_id: "b".into(),
        };
        assert_eq!(fallback_reason_for(&multi_hop, &unanswered, false), None);

        // Nothing reads the file again, and the attempt records what it asks
        // for before it can fail.
        assert!(!body("fn fallback_reason_for(").contains("load_settings"));
        let attempt = body("async fn attempt(");
        let recorded = attempt
            .find("ctx.stealth_mode = settings.stealth_mode;")
            .expect("the attempt records its Stealth Mode");
        let before = &attempt[..recorded];
        assert!(before.contains("let settings = apply_vpn_settings(app).await;"));
        assert!(
            !before.contains(")?") && !before.contains("return "),
            "recorded before the attempt can fail"
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

    /// MR-1639: a retryable refusal (`psk_delivery_unavailable`,
    /// `quota_check_unavailable`) is asked once more, after the server's
    /// wait, cancellably. Settings and the post-quantum key are read ONCE,
    /// before the loop, and both requests are built from them — so the retry
    /// cannot go out without the Quantum Protection the first one asked for.
    /// Each request gets a fresh keypair (FIX-1-1).
    #[test]
    fn a_retryable_refusal_is_asked_once_more_with_the_same_protection() {
        let attempt = body("async fn attempt(");
        order(
            attempt,
            &[
                "let settings = apply_vpn_settings(app).await;",
                "let pq_pk = if settings.quantum_protection {",
                "let mut retried = false;",
                "loop {",
                "generate_wireguard_keypair()",
                "settings.quantum_protection.then_some(true),",
                "pq_pk.clone(),",
                "settings.quantum_protection,",
                "pq_pk.clone(),",
                "error.server_asked_to_wait().filter(|_| !retried)",
                "retried = true;",
                "vm.run_cancellable(ctx.epoch, tokio::time::sleep(wait))",
                "None => return Err(error),",
                "prepare_tunnel(",
            ],
        );
        for once in [
            "apply_vpn_settings(",
            "get_client_public_key_b64()",
            "generate_wireguard_keypair()",
        ] {
            assert_eq!(attempt.matches(once).count(), 1, "{once}");
        }
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

    /// MR-2070: a relay permit that could not move (or a guard that could
    /// not go up) ends the attempt before `vm.connect`, which would tear down
    /// the session it displaces and dial the new relay with nothing blocking.
    /// What the step returns is driven in
    /// `a_relay_permit_that_cannot_move_is_the_steps_error`; where the failed
    /// switch lands, in
    /// `a_switch_refused_before_the_rebuild_keeps_only_a_live_session`.
    #[test]
    fn a_switch_whose_relay_permit_cannot_move_is_not_rebuilt() {
        order(
            body("async fn attempt("),
            &[
                "apply_relay_permit(",
                "guard_rebuild,",
                ".map_err(|e| {",
                "IpcErrorCode::KillswitchFailed,",
                "})?;",
                "vm.set_phase(ConnectPhase::Handshaking);",
                "vm.connect(",
            ],
        );
        // Each kill-switch step's failure is returned, none logged and
        // dialled past; and on macOS/Linux a guard that fails gives the
        // relay back to the session the switch keeps.
        let permit = body("pub(crate) async fn apply_relay_permit(");
        assert!(
            !permit.contains("if let Err(e) = killswitch::"),
            "a kill-switch failure is swallowed"
        );
        order(
            permit,
            &[
                "let previous = killswitch::vpn_server_ip();",
                "killswitch::set_vpn_server_ip(Some(ip))",
                "permit_relay(",
                "killswitch::move_relay,",
                "killswitch::activate_killswitch,",
                "if engage {",
                "Err(e) => {",
                "killswitch::set_vpn_server_ip(previous).await;",
                "Err(format!(",
            ],
        );
        for rebuilt in [
            "the iptables relay permit was not updated: {e}\"))?;",
            "the pf relay permit was not updated: {e}\"))?;",
        ] {
            assert!(permit.contains(rebuilt), "{rebuilt}");
        }
    }

    /// MR-2070, where the refused switch lands (`fail_connect`). A session
    /// live when the connect started, its transport untouched, is kept: no
    /// teardown, no dial, its relay permit pointed back. A dead tunnel the
    /// guard took into `was_live` (one the reconnect loop had not torn down,
    /// still held when the step failed) is never kept as the session — it
    /// would read Connected — and the failure holds the block instead.
    #[test]
    fn a_switch_refused_before_the_rebuild_keeps_only_a_live_session() {
        use super::{failure_outcome, AttemptContext, FailureOutcome};
        use crate::vpn::xray::XrayManager;

        let xray = XrayManager::new();
        // After the guard: `was_live` is set for whatever tunnel it found.
        let guarded = |live_at_start| AttemptContext {
            epoch: 1,
            was_live: true,
            live_at_start,
            block_engaged: true,
            old_stealth_mark: None,
            #[cfg(target_os = "windows")]
            old_relay: None,
            intent_seen: 0,
            stealth_mode: false,
        };

        let live = guarded(true);
        assert!(!live.old_session_gone(&xray));
        assert_eq!(
            failure_outcome(false, live.was_live, live.old_session_gone(&xray), true),
            FailureOutcome::KeepOldSession
        );

        let dead = guarded(false);
        assert!(dead.old_session_gone(&xray));
        assert_eq!(
            failure_outcome(false, dead.was_live, dead.old_session_gone(&xray), true),
            FailureOutcome::Error { hold_block: true }
        );
    }

    /// MR-2070: a failed connect that still holds a tunnel holds the block
    /// before that tunnel goes — a dead one too, which the start of the
    /// connect did not count as live (the kill switch keeps one in place while
    /// it cannot block: the reconnect loop's hold, or this path's own). When
    /// no block can go up while the kill switch wants one, the tunnel is not
    /// torn down at all, and its routes keep the traffic. The rule is
    /// `reconnect_policy::teardown_covered`, driven in its own tests.
    #[test]
    fn a_failed_connect_tears_a_held_tunnel_down_only_behind_a_block() {
        use super::{failure_outcome, FailureOutcome};
        // Not live when the connect started, a tunnel still held: the block
        // is held. It used to be torn down with no block asked for.
        for gone in [false, true] {
            assert_eq!(
                failure_outcome(false, false, gone, true),
                FailureOutcome::Error { hold_block: true },
                "gone={gone}"
            );
        }
        // Nothing live and nothing held: nothing to hold.
        assert_eq!(
            failure_outcome(false, false, true, false),
            FailureOutcome::Error { hold_block: false }
        );

        let failed = body("async fn fail_connect(");
        order(
            failed,
            &[
                "FailureOutcome::Error { hold_block } => hold_block,",
                "if hold_block {",
                "let engaged = killswitch::activate_killswitch().await;",
                "keep_tunnel = crate::vpn::reconnect_policy::teardown_covered(",
                "&engaged,",
                "killswitch::platform_is_blocking(),",
                ".is_err();",
                "let held = vm.holds_tunnel().await;",
                "let error = if held && keep_tunnel {",
                "kept_tunnel_error()",
                // The kept tunnel reads as the block, with Disconnect
                // (`VpnManager::keep_tunnel_in_error`, driven in the
                // manager's tests): a plain `error` read as "nothing held".
                "if held && keep_tunnel {",
                "vm.keep_tunnel_in_error(error.clone()).await;",
                "} else if held {",
                ".disconnect_to(ConnectionState::Error(error.clone()))",
                "} else {",
                ".set_state(ConnectionState::Error(error.clone()))",
            ],
        );
        // A kept tunnel says why the traffic is held: the kill switch.
        assert_eq!(
            super::kept_tunnel_error().code,
            crate::commands::ipc_error::IpcErrorCode::KillswitchFailed
        );
        // A kept tunnel is torn down nowhere else on the way out, and is
        // kept nowhere else.
        assert_eq!(failed.matches("disconnect_to(").count(), 1);
        assert_eq!(failed.matches("keep_tunnel_in_error(").count(), 1);
    }

    /// MR-2070: a relay permit that cannot move — or, with no relay to
    /// permit, a guard that cannot go up — is the step's error; it used to be
    /// logged and the switch dialled past it. The kill switch's two calls are
    /// stubbed: no WFP session is opened.
    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn a_relay_permit_that_cannot_move_is_the_steps_error() {
        use super::permit_relay;
        use crate::vpn::wfp_policy::{parse_relay, Relay, RelayTransport};
        use std::future::{ready, Ready};

        let relay = parse_relay("192.0.2.1:51820", RelayTransport::WireGuardUdp);
        assert!(relay.is_some());
        let refused = |_: Relay, _: bool| {
            ready(Err::<(), String>(
                "FwpmTransactionCommit0 failed: 0x80320008".into(),
            ))
        };
        let nothing_to_move = |_: Relay, _: bool| -> Ready<Result<(), String>> {
            panic!("there is no relay to move")
        };
        let not_engaged_alone = || -> Ready<Result<bool, String>> {
            panic!("the move puts the block up in its own commit")
        };

        // Putting the block up with the move, or rebuilding one in force.
        for engage in [true, false] {
            let moved = permit_relay(relay, engage, refused, not_engaged_alone).await;
            assert!(
                moved
                    .as_ref()
                    .is_err_and(|e| e.contains("FwpmTransactionCommit0")),
                "engage={engage}: {moved:?}"
            );
        }
        // No relay to permit: the guard alone, and its failure.
        let guarded = permit_relay(None, true, nothing_to_move, || {
            ready(Err::<bool, String>("Kill switch not initialized".into()))
        })
        .await;
        assert!(guarded.is_err(), "{guarded:?}");

        // The controls: a move that commits, a guard that goes up or is not
        // wanted, and nothing asked of the step at all.
        let committed = permit_relay(
            relay,
            true,
            |moved: Relay, engage| {
                assert!(engage && Some(moved) == relay);
                ready(Ok(()))
            },
            not_engaged_alone,
        )
        .await;
        assert_eq!(committed, Ok(()));
        for engaged in [true, false] {
            let up = permit_relay(None, true, nothing_to_move, || ready(Ok(engaged))).await;
            assert_eq!(up, Ok(()));
        }
        let idle = permit_relay(None, false, nothing_to_move, not_engaged_alone).await;
        assert_eq!(idle, Ok(()));
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
            live_at_start: true,
            block_engaged: false,
            old_stealth_mark: Some(xray.ended_count()),
            old_relay: None,
            intent_seen: 0,
            stealth_mode: true,
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

/// WIN-FIX-3 / MR-1408: Disconnect releases the block at the end of the
/// teardown or 40 s after it began, whichever comes first, driven on paused
/// time (these used to be a source-order pin and a constant check).
#[cfg(test)]
mod release_deadline_tests {
    use super::release_unless_torn_down;
    use std::future::{pending, Future};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::time::{advance, sleep, Duration, Instant};

    const DEADLINE: Duration = Duration::from_secs(40);

    /// When the release ran, if it did.
    #[derive(Clone, Default)]
    struct Release(Arc<Mutex<Option<Instant>>>);

    impl Release {
        fn run(&self) -> impl Future<Output = ()> + Send + 'static {
            let at = self.0.clone();
            async move {
                let mut at = at.lock().unwrap();
                assert!(at.is_none(), "released twice");
                *at = Some(Instant::now());
            }
        }

        fn at(&self) -> Option<Instant> {
            *self.0.lock().unwrap()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_wedged_teardown_is_released_at_the_deadline_and_not_before() {
        let start = Instant::now();
        let release = Release::default();
        let wait = tokio::spawn(release_unless_torn_down(
            pending::<Result<(), String>>(),
            release.run(),
        ));
        // Let the wait start its clock now, not after the first advance.
        tokio::task::yield_now().await;

        advance(DEADLINE - Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(release.at(), None, "released before the deadline");
        assert!(!wait.is_finished());

        advance(Duration::from_millis(1)).await;
        wait.await.unwrap();
        assert_eq!(release.at(), Some(start + DEADLINE));
    }

    #[tokio::test(start_paused = true)]
    async fn a_teardown_that_finishes_in_time_is_not_released_again() {
        let start = Instant::now();
        let release = Release::default();
        let teardown = async {
            sleep(DEADLINE - Duration::from_secs(1)).await;
            Ok::<(), String>(())
        };
        release_unless_torn_down(teardown, release.run()).await;
        assert_eq!(start.elapsed(), DEADLINE - Duration::from_secs(1));
        assert_eq!(release.at(), None, "it released the block itself");
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_teardown_is_released_at_once() {
        let start = Instant::now();
        let release = Release::default();
        let teardown = async {
            sleep(Duration::from_secs(5)).await;
            Err::<(), _>("the teardown task panicked")
        };
        release_unless_torn_down(teardown, release.run()).await;
        assert_eq!(release.at(), Some(start + Duration::from_secs(5)));
    }

    /// The release does not wait for the teardown, and does not stop it: the
    /// spawned task finishes on its own, after the block was released.
    #[tokio::test(start_paused = true)]
    async fn a_teardown_past_the_deadline_carries_on_behind_the_release() {
        let start = Instant::now();
        let release = Release::default();
        let finished = Arc::new(AtomicBool::new(false));
        let teardown = tokio::spawn({
            let finished = finished.clone();
            async move {
                sleep(Duration::from_secs(90)).await;
                finished.store(true, Ordering::SeqCst);
            }
        });
        release_unless_torn_down(teardown, release.run()).await;
        assert_eq!(release.at(), Some(start + DEADLINE));
        assert!(!finished.load(Ordering::SeqCst));

        // Past the teardown's own 90 s (not AT it: two timers due at the same
        // instant wake in no promised order).
        sleep(Duration::from_secs(51)).await;
        assert!(
            finished.load(Ordering::SeqCst),
            "the teardown was cancelled at the deadline"
        );
    }
}
