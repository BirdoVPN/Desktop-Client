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
use crate::api::types::{ConnectResponse, MultiHopConnectResponse, VpnConfig, VpnServer};
use crate::api::BirdoApi;
use crate::commands::ipc_error::{IpcError, IpcErrorCode, TransportFailure};
use crate::commands::killswitch;
use crate::commands::vpn::{
    apply_vpn_settings, build_vpn_config, derive_quantum_psk, enforce_requested_protection,
    generate_wireguard_keypair, get_device_name, parse_endpoint_ip, start_stealth_tunnel,
    transport_fallback_reason,
};
use crate::storage::CredentialStore;
use crate::vpn::auto_reconnect::{ReconnectInfo, SERVER_LIST_TIMEOUT};
use crate::vpn::birdo_pq::PqSession;
use crate::vpn::manager::{
    ConnectPhase, ConnectionState, MultiHopStatus, SessionLabel, VpnManager,
};
use crate::vpn::relay_retry::{self, SelectionOrigin};
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
    /// `origin`: who chose the server (MR-2390). It decides how far the
    /// session may move if that server leaves the pool.
    SingleHop {
        server_id: String,
        origin: SelectionOrigin,
    },
    /// Always the user's own pair of locations: it never moves.
    MultiHop { entry_id: String, exit_id: String },
}

impl ConnectTarget {
    /// The target a live session was built for (settings reapply). Its
    /// origin goes with it.
    pub(crate) fn of(info: &ReconnectInfo) -> Self {
        match &info.multi_hop {
            Some(route) => ConnectTarget::MultiHop {
                entry_id: info.server_id.clone(),
                exit_id: route.exit_id.clone(),
            },
            None => ConnectTarget::SingleHop {
                server_id: info.server_id.clone(),
                origin: info.origin,
            },
        }
    }

    /// Who chose where this connect goes (MR-2390).
    fn origin(&self) -> SelectionOrigin {
        match self {
            ConnectTarget::SingleHop { origin, .. } => *origin,
            ConnectTarget::MultiHop { .. } => SelectionOrigin::User,
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
    let result = dial(&mut AppDial { app, ctx: &mut ctx }, &target, purpose).await;

    let result = match result {
        Ok(()) => Ok(()),
        Err(error) => Err(fail_connect(app, error, &ctx).await),
    };
    ConnectOutcome {
        epoch: Some(epoch),
        result,
    }
}

/// What a user connect's attempts do to the world, apart from the
/// `AppHandle`, so a test can drive [`dial`] and count them (MR-2514; the
/// pattern of `vpn::RevertSteps`).
trait DialSteps {
    /// One full attempt at `target` over `transport` ([`attempt`]).
    async fn attempt_once(
        &mut self,
        target: &ConnectTarget,
        transport: Option<&'static str>,
    ) -> Result<(), IpcError>;
    /// The Stealth Mode the latest attempt asked for
    /// ([`AttemptContext::stealth_mode`]).
    fn attempted_stealth(&self) -> bool;
    /// Before another attempt: a session that was live stays behind the
    /// block across the gap. No-op on a fresh first connect.
    async fn cover_the_gap(&mut self);
    /// Tell the UI the session is going over the stealth transport.
    fn announce_stealth(&self, reason: &'static str);
    /// No Disconnect or newer connect has superseded this connect.
    fn still_current(&self) -> bool;
    /// `/vpn/servers`, fetched now, or `None` when it does not arrive in
    /// time (or the connect is superseded meanwhile).
    async fn fresh_servers(&mut self) -> Option<Vec<VpnServer>>;
    /// Tell the UI the connect is going to another server: who chose the
    /// first one and how far the retry goes (classes, never the server).
    fn announce_relay_retry(&self, origin: SelectionOrigin, reach: relay_retry::Reach);
    /// One counts-only line for the log.
    fn log(&self, line: &str);
}

/// The app's [`DialSteps`].
struct AppDial<'a> {
    app: &'a AppHandle,
    ctx: &'a mut AttemptContext,
}

impl DialSteps for AppDial<'_> {
    async fn attempt_once(
        &mut self,
        target: &ConnectTarget,
        transport: Option<&'static str>,
    ) -> Result<(), IpcError> {
        attempt(self.app, target, transport, self.ctx).await
    }

    fn attempted_stealth(&self) -> bool {
        self.ctx.stealth_mode
    }

    async fn cover_the_gap(&mut self) {
        // The same block that covers a reconnect gap, so the backlog of a
        // user who believed they were protected cannot burst out in the
        // clear on exactly the network that is interfering with us.
        if self.ctx.was_live {
            engage_rebuild_block(self.ctx).await;
        }
    }

    fn announce_stealth(&self, reason: &'static str) {
        let _ = self.app.emit(
            "adaptive-transport-fallback",
            serde_json::json!({ "reason": reason }),
        );
    }

    fn still_current(&self) -> bool {
        self.app.state::<VpnManager>().is_current(self.ctx.epoch)
    }

    async fn fresh_servers(&mut self) -> Option<Vec<VpnServer>> {
        let vm = self.app.state::<VpnManager>();
        let api = self.app.state::<BirdoApi>();
        match vm
            .run_cancellable(
                self.ctx.epoch,
                timeout(SERVER_LIST_TIMEOUT, api.get_servers()),
            )
            .await
        {
            Ok(Ok(Ok(servers))) => Some(servers),
            _ => None,
        }
    }

    fn announce_relay_retry(&self, origin: SelectionOrigin, reach: relay_retry::Reach) {
        let _ = self.app.emit(
            "relay-retry",
            serde_json::json!({ "origin": origin.as_str(), "reach": reach.as_str() }),
        );
    }

    fn log(&self, line: &str) {
        tracing::warn!("{}", line);
    }
}

/// A user connect's attempts, in order. A first attempt that fails can be
/// followed by at most two more, each ONCE: the Adaptive Transport's on the
/// same server, then the relay retry's on another (MR-2514). Never a loop.
async fn dial<S: DialSteps>(
    steps: &mut S,
    target: &ConnectTarget,
    purpose: ConnectPurpose,
) -> Result<(), IpcError> {
    let (first_transport, adaptive) = match purpose {
        ConnectPurpose::User => (None, true),
        ConnectPurpose::SettingsReapply { fallback_reason } => (fallback_reason, false),
    };
    let mut result = steps.attempt_once(target, first_transport).await;
    // MR-2514: the server's first handshake never completed: no answer, or
    // (review I3, as iOS, whose window counts any handshake that does not
    // complete) a DIRECT handshake the relay actively refused. Refused
    // through the local Stealth helper is this machine's (review L2).
    let mut unanswered = false;

    // ADAPTIVE TRANSPORT: when the direct attempt failed in the
    // transport-shaped way (the establish-time handshake was unanswered or
    // refused), retry ONCE with the backend's any-plan stealth grant. A single
    // retry cannot loop: the stealth attempt's handshake runs against the
    // local Xray proxy, whose failures do not classify as transport-shaped.
    // Not for a settings reapply (see `ConnectPurpose`).
    if let Some(direct) = result.as_ref().err().filter(|_| adaptive) {
        unanswered = match direct.transport {
            Some(TransportFailure::NoResponse) => true,
            Some(TransportFailure::Refused) => !steps.attempted_stealth(),
            None => false,
        };
        if let Some(reason) = fallback_reason_for(target, direct, steps.attempted_stealth()) {
            tracing::warn!(
                "Adaptive Transport: direct WireGuard failed ({reason}) — rebuilding over the \
                 stealth transport"
            );
            // Cover the transport switch. No-op on a fresh first connect.
            steps.cover_the_gap().await;
            // Surface the switch — the user must never silently land on a
            // different transport.
            steps.announce_stealth(reason);
            result = steps.attempt_once(target, Some(reason)).await;
        }
    }

    match result {
        Err(error) if unanswered => retry_on_another_server(steps, target, error).await,
        result => result,
    }
}

/// MR-2514 [DESK-AUTO-RETRY-PARITY]: the ONE automatic retry, on another
/// server, of a user connect whose server never answered its first
/// handshake: direct, then over the stealth transport where the Adaptive
/// Transport tried it. `error` is how that server failed.
///
/// The owner's rule (2026-11-19, MR-2212 Q2; 2026-11-20 for a user's pick),
/// the same on every client (iOS `retryOnAnotherRelay`, Mobile #645):
///   * a server the CLIENT chose (`SelectionOrigin::Automatic`) may move to
///     another country;
///   * a location the USER picked moves only within its own country, the
///     same city first ("Same country, like iPhone"); with nothing eligible
///     there, its error stands. A Multi-Hop route, the user's own pair,
///     never moves;
///   * the server is `relay_retry::after_no_handshake`'s choice (#466's
///     `next`: online and open to this plan, as `/vpn/servers` lists them
///     for this account, fetched now; never the server that failed). A node
///     held for its jurisdiction is never listed online, and `/vpn/connect`
///     checks the plan and the ONLINE status again;
///   * ONE retry: its failure is the connect's, and is never retried again.
///     A Disconnect, a newer connect or a refusal no retry can overcome ends
///     the connect without one;
///   * the retry is a fresh connect to that server, direct (or over Stealth
///     Mode when the user turned it on), under the same kill switch as the
///     first attempt (`cover_the_gap`, and `attempt`'s relay permit);
///   * the log gives the origin, the counts and how far the retry went,
///     never a server.
async fn retry_on_another_server<S: DialSteps>(
    steps: &mut S,
    target: &ConnectTarget,
    error: IpcError,
) -> Result<(), IpcError> {
    let ConnectTarget::SingleHop { server_id, origin } = target else {
        return Err(error);
    };
    // A Disconnect, a newer connect, a refusal no retry can overcome, or a
    // failure of this machine's own (review L2) ends it without a retry.
    if !server_did_not_serve(&error) || !steps.still_current() {
        return Err(error);
    }
    let listed = steps.fresh_servers().await;
    if !steps.still_current() {
        return Err(error);
    }
    let Some(servers) = listed else {
        steps.log(
            "No handshake from the server: no server list in time, so no automatic retry \
             (retry 0 of 1)",
        );
        return Err(error);
    };
    // Where the failed server was, should the fresh list no longer have it.
    let last_known = relay_retry::known_location(server_id);
    relay_retry::remember(&servers);
    let choice = relay_retry::after_no_handshake(server_id, &servers, *origin, last_known.as_ref());
    steps.log(&relay_retry::no_handshake_line(choice.as_ref(), *origin));
    let Some(choice) = choice else {
        return Err(error);
    };
    // The move keeps who chose: a user's pick stays the user's.
    let moved = ConnectTarget::SingleHop {
        server_id: choice.server.id,
        origin: *origin,
    };
    steps.cover_the_gap().await;
    steps.announce_relay_retry(*origin, choice.reach);
    let result = steps.attempt_once(&moved, None).await;
    // A Disconnect or a newer connect during the retry's dial: the connect is
    // theirs, not a retry that failed (review L4).
    if result
        .as_ref()
        .is_err_and(|e| e.code == IpcErrorCode::Cancelled)
        || !steps.still_current()
    {
        return result;
    }
    let connected = result.is_ok();
    steps.log(&relay_retry::retry_outcome_line(
        connected,
        relay_retry::count_retry(connected),
    ));
    result
}

/// Whether `error`, how the server's own attempts last failed, says the
/// SERVER did not serve (MR-2514, review L2): its handshake got no answer
/// (direct, or through the stealth transport), the backend refused it as
/// unavailable, or the backend did not grant it the stealth transport (review
/// L5, `IpcError::stealth_not_granted`). Anything else (a Disconnect, a hard
/// refusal, the adapter, the kill switch, a rate limit, the local Stealth
/// helper, a handshake refused through it) would fail the same way on
/// another server, so it spends no retry.
fn server_did_not_serve(error: &IpcError) -> bool {
    error.transport == Some(TransportFailure::NoResponse)
        || error.code == IpcErrorCode::ServerUnavailable
        || error.stealth_not_granted
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
    // BirdoShield (D18): the preference goes on the wire only while the fleet
    // gate is known to be on (owner 2026-11-13; `get_client_config` keeps the
    // process-wide copy). Read once, so the retried request below asks for
    // exactly what the first one did.
    let dns_filtering = crate::api::client::dns_filtering_with_gate(
        settings.dns_filtering,
        crate::api::client::dns_filtering_gate_on(),
    );

    // AUDIT-C1: with PQ requested, attach our ML-KEM-1024 public key so the
    // server can encapsulate against it. MR-703 / MR-1742: the keypair is made
    // HERE, once per attempt, and its secret lives only in this `PqSession`:
    // held across the retryable-refusal retry below (the same key is re-sent,
    // so the server's ciphertext still fits), moved into `prepare_tunnel` to
    // decapsulate, and wiped on every other exit (an error, a cancel, a drop).
    // A later attempt (the Adaptive Transport retry) and every re-dial call
    // `begin()` again: no pair is ever reused across attempts.
    let pq_session = settings.quantum_protection.then(PqSession::begin);
    let pq_pk = pq_session.as_ref().map(PqSession::public_key_b64);

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
                ConnectTarget::SingleHop { server_id, .. } => {
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
                                dns_filtering,
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
                                dns_filtering,
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
        return Err(IpcError::connect_refused_with(
            &message,
            response.quota_exceeded,
            response.refusal_reason.as_deref(),
            response.account_restriction.as_ref(),
        ));
    }
    // `deviceNotice` rides a SUCCESSFUL connect; it is shown once the tunnel
    // is up, and never changes what the connect does.
    let device_notice = response.device_notice.clone();

    let prepared = prepare_tunnel(
        app,
        &vm,
        ctx.epoch,
        response,
        TunnelRequest {
            server_id: dialled_id,
            stealth_mode: settings.stealth_mode,
            quantum_protection: settings.quantum_protection,
            pq_session,
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
        // MR-2569: published with the server, so the UI records who chose it
        // (the relay retry keeps the connect's origin on the server it moves to).
        origin: target.origin(),
    };
    vm.set_phase(ConnectPhase::Handshaking);
    vm.connect(
        prepared.config,
        private_key,
        label.clone(),
        &prepared.relay_endpoint,
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
        origin: target.origin(),
    })
    .await;
    if let Err(e) = ar.start().await {
        tracing::warn!("Failed to start auto-reconnect: {}", e);
    }

    // LOG-001: the chosen node id is connection history — keep it out of the
    // release log (info reaches birdo.log); the id is still visible at debug.
    tracing::info!("VPN connected successfully");
    tracing::debug!("VPN connected to server id {}", dialled_id);
    if let Some(payload) = device_notice.as_ref().and_then(device_notice_payload) {
        let _ = app.emit("device-notice", payload);
    }
    Ok(())
}

/// The `device-notice` event's payload for a connect's `deviceNotice`: the
/// server's sentence (redacted, bounded) and the website path of its Devices
/// page when that is a plain same-site path. `None` without a sentence: there
/// is nothing to show, and ignoring the notice loses nothing (contract).
fn device_notice_payload(notice: &crate::api::types::DeviceNotice) -> Option<serde_json::Value> {
    let message: String = crate::utils::redact::sanitize_always(notice.message.as_deref()?.trim())
        .chars()
        .take(400)
        .collect();
    if message.is_empty() {
        return None;
    }
    let manage_path = notice
        .manage_path
        .as_deref()
        .and_then(crate::commands::ipc_error::site_path);
    Some(serde_json::json!({ "message": message, "managePath": manage_path }))
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
        return Err(IpcError::connect_refused_with(
            response
                .message
                .as_deref()
                .unwrap_or("Multi-hop connection failed"),
            response.quota_exceeded,
            response.refusal_reason.as_deref(),
            response.account_restriction.as_ref(),
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
    /// The keypair this request's `pqClientPublicKey` came from (MR-703).
    /// Consumed by the decapsulation; `None` when quantum protection is off.
    pub pq_session: Option<PqSession>,
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
    mut request: TunnelRequest<'_>,
) -> Result<PreparedTunnel, IpcError> {
    enforce_requested_protection(&response, request.stealth_mode, request.quantum_protection)?;

    // ADAPTIVE TRANSPORT: a fallback retry MUST come back with the stealth
    // transport. Direct WireGuard is proven broken on this network, so
    // silently rebuilding it would just burn another multi-second handshake
    // failure and report a misleading error.
    if request.fallback_reason.is_some() && !response.stealth_enabled.unwrap_or(false) {
        return Err(IpcError::stealth_not_granted());
    }

    // AUD-DESK-08 (review of #446): a relay the kill switch could not permit
    // is refused before anything starts for it, the Stealth helper and its
    // DoH lookup of a host name included. `build_vpn_config` checks again.
    if response.success {
        crate::commands::vpn::check_permittable_relays(&response)
            .map_err(|m| IpcError::new(IpcErrorCode::ServerError, m))?;
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
    let quantum_psk = derive_quantum_psk(&response, request.pq_session.take())
        .map_err(|m| IpcError::new(IpcErrorCode::PqFailed, m))?;

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
///
/// AUD-DESK-08: an endpoint that is not an IPv4 address (a host name) is
/// `Err` before anything moves. It used to be logged and answered `Ok` with
/// the permit left on the PREVIOUS relay. The server sends only addresses,
/// and `build_vpn_config` refuses anything else first.
pub(crate) async fn apply_relay_permit(
    endpoint: &str,
    stealth: bool,
    engage: bool,
) -> Result<(), String> {
    let Some(ip) = parse_endpoint_ip(endpoint) else {
        // P6-CLI-D-03: the endpoint names the relay, so both lines are
        // redacted (`redact_*` is a pass-through in debug builds).
        tracing::warn!(
            "Kill switch endpoint '{}' is not an IPv4 address; refusing it rather than \
             keeping the previous relay's permit",
            crate::utils::redact::redact_hostname(endpoint)
        );
        tracing::debug!(
            "Unresolvable kill switch endpoint: {}",
            crate::utils::redact_endpoint(endpoint)
        );
        return Err("the relay endpoint is not an IPv4 address".to_string());
    };
    // macOS/Linux: the relay the block permits now, for a guard that fails.
    #[cfg(not(target_os = "windows"))]
    let previous = killswitch::vpn_server_ip();
    killswitch::set_vpn_server_ip(Some(ip)).await;
    #[cfg(target_os = "windows")]
    {
        use crate::vpn::wfp_policy::{parse_relay, RelayTransport};
        let transport = if stealth {
            RelayTransport::StealthTcp
        } else {
            RelayTransport::WireGuardUdp
        };
        let relay = parse_relay(endpoint, transport);
        if relay.is_none() {
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

    // MR-2255 (review of #445): on Linux the server switch's hold is lifted
    // only by its guard's Drop, and since MR-2255 it holds every non-tunnel
    // IPv4 flow, not just DNS. A removal that failed there (an iptables
    // error) left it in the kernel past the switch, cutting the host off
    // after this Disconnect until the next launch. Every Disconnect lifts it
    // again. Idempotent, our chains only: a no-op with no hold. A hold lives
    // only inside a switch's connect(), which needs a tunnel to displace,
    // and the disconnect above has just taken it. (macOS's pf watchdog
    // retries a lift that did not take.)
    #[cfg(target_os = "linux")]
    crate::vpn::tunnel_linux::remove_dns_hold();
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

    /// MR-2255 (review of #445, LOW): every Disconnect lifts a server-switch
    /// hold left in the kernel on Linux, after the tunnel and the stealth
    /// transport are down and before the block is released. With the IPv4
    /// half, a hold whose own removal failed cut every non-tunnel IPv4 flow
    /// until the next launch. `tunnel_linux`'s netns test
    /// `a_dns_hold_left_by_a_killed_run_is_lifted_by_the_startup_sweep` pins
    /// that the call lifts a hold left exactly as a failed removal leaves it.
    #[test]
    fn a_disconnect_lifts_a_switch_hold_left_in_the_kernel() {
        let steps = body("async fn end_the_tunnel(");
        order(
            steps,
            &[
                "vm.disconnect()",
                "XrayManager>().stop()",
                "#[cfg(target_os = \"linux\")]",
                "crate::vpn::tunnel_linux::remove_dns_hold();",
            ],
        );
        // Inside the teardown, so it runs before tear_down's disarm.
        order(
            body("async fn tear_down("),
            &["end_the_tunnel(&app, reason).await", "killswitch::disarm()"],
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

    /// MR-1934 / MA-DESK-013: macOS's Cmd+Q, the Dock's Quit and logout reach
    /// the end of the run (`RunEvent::Exit`) with no exit request before it.
    /// What the end of the run does, and in which order (record, teardown,
    /// clear; not on Windows, not after a restart, not twice), is driven with
    /// fakes in `utils::tests::the_end_of_the_run_records_then_tears_down_then_clears`
    /// and what the teardown helper does in
    /// `utils::tests::an_exit_that_never_asked_first_runs_the_teardown_once`.
    /// Kept, because only the source can say it: `main.rs` hands that function
    /// the real flags and the real teardown, and a restart says so before it
    /// returns.
    #[test]
    fn the_exit_arm_hands_the_end_of_the_run_the_real_flags_and_teardown() {
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
                "utils::end_of_run(",
                "&EXIT_TEARDOWN_STARTED,",
                "&EXIT_RESTARTING,",
                "cfg!(not(target_os = \"windows\")),",
                "EXIT_TEARDOWN_CAP + EXIT_FALLBACK_MARGIN,",
                "record_if_exit_kept_the_session(",
                "teardown_for_exit(&app)",
                "commands::clipboard::clear_on_exit,",
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

    /// MR-2569 (review M1 of #470): the status names who chose the server it
    /// names. A connect publishes its target's origin with the server
    /// (`SessionLabel::origin`, which the relay retry's move keeps); a
    /// re-dial or a move off a server that left publishes the record's; the
    /// manager sets it with the server and clears it with it; the status
    /// carries it as `serverOrigin`. The UI records a server Rust moved the
    /// session to under that origin, never as the client's pick by guess.
    #[test]
    fn the_status_says_who_chose_the_server_it_names() {
        let label = body("async fn attempt(");
        let built = &label[label.find("let label = SessionLabel {").expect("the label")..];
        assert!(
            built[..built.find("};").unwrap()].contains("origin: target.origin(),"),
            "{built}"
        );
        let manager = include_str!("../vpn/manager.rs").replace('\r', "");
        order(
            &manager,
            &[
                ".write_state_with(ConnectionState::Connected, |p| {",
                "p.server_id = Some(label.server_id);",
                "p.server_origin = Some(label.origin);",
            ],
        );
        order(
            &manager,
            &["p.server_id = None;", "p.server_origin = None;"],
        );
        let redial = include_str!("../vpn/auto_reconnect.rs").replace('\r', "");
        let redial = &redial[redial
            .find("pub fn label(&self) -> SessionLabel {")
            .unwrap()..];
        let redial = &redial[..redial.find("\n    }").unwrap()];
        assert!(redial.contains("origin: self.origin,"), "{redial}");
        assert!(include_str!("vpn.rs")
            .contains("server_origin: published.server_origin.map(SelectionOrigin::as_str),"));
    }

    /// Review L5 of #470: the backend not granting the stealth transport is
    /// built by its own constructor at the one place it is decided, so the
    /// relay retry can tell it from the local Stealth helper's failures,
    /// which never use it.
    #[test]
    fn the_backends_stealth_refusal_has_its_own_constructor() {
        let prepare = body("pub(crate) async fn prepare_tunnel(");
        order(
            prepare,
            &[
                "if request.fallback_reason.is_some() && !response.stealth_enabled.unwrap_or(false) {",
                "return Err(IpcError::stealth_not_granted());",
            ],
        );
        assert!(!include_str!("vpn.rs").contains("stealth_not_granted"));
    }

    /// WIN-FIX-3: a settings reapply is rebuilt on the session's own
    /// transport and never runs the Adaptive Transport retry; a user connect
    /// starts direct and does. The session's settings are recorded at the
    /// commit, beside its reconnect record, for the reapply's revert.
    #[test]
    fn a_settings_reapply_keeps_its_transport_and_gets_no_stealth_retry() {
        order(
            body("pub(crate) async fn connect_session_for("),
            &["let result = dial(&mut AppDial { app, ctx: &mut ctx }, &target, purpose)"],
        );
        // MR-2514: the attempts moved into `dial` (driven in `dial_tests`).
        order(
            body("async fn dial<S: DialSteps>("),
            &[
                "ConnectPurpose::User => (None, true)",
                "ConnectPurpose::SettingsReapply { fallback_reason } => (fallback_reason, false)",
                "steps.attempt_once(target, first_transport)",
                ".filter(|_| adaptive)",
                "fallback_reason_for(target, direct, steps.attempted_stealth())",
            ],
        );
        assert!(body("fn attempted_stealth(&self) -> bool {").contains("self.ctx.stealth_mode"));
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
        use super::{fallback_reason_for, AttemptContext, ConnectTarget, SelectionOrigin};
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
            origin: SelectionOrigin::User,
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

    /// Owner 2026-11-13: both dial paths send BirdoShield through the fleet
    /// gate, and the session on record keeps the preference (the re-dial
    /// gates it again when it sends, `redial_info_under_gate`).
    #[test]
    fn both_dial_paths_send_dns_filtering_through_the_fleet_gate() {
        let attempt = body("async fn attempt(");
        let gated = attempt
            .find("let dns_filtering = crate::api::client::dns_filtering_with_gate(")
            .expect("the attempt gates the flag");
        assert!(attempt[gated..].contains("crate::api::client::dns_filtering_gate_on(),"));
        let sent = &attempt[gated..];
        assert_eq!(
            sent.matches("                                dns_filtering,")
                .count(),
            2,
            "connect_vpn and connect_multi_hop both pass the gated flag"
        );
        assert!(
            !attempt.contains("                                settings.dns_filtering,"),
            "no dial path passes the ungated preference"
        );
        assert!(attempt.contains("dns_filtering: settings.dns_filtering,"));
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
                "let result = dial(",
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
                "let result = dial(",
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
                "let pq_session = settings.quantum_protection.then(PqSession::begin);",
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
            "PqSession::begin",
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

    /// AUD-DESK-08 (review of #446): a relay the kill switch could not permit
    /// is refused before the Stealth helper starts for it, so before it looks
    /// a host name up. What is refused is driven in
    /// `vpn::tests::a_relay_endpoint_that_is_not_an_ipv4_address_is_refused`.
    #[test]
    fn a_relay_that_cannot_be_permitted_is_refused_before_stealth_starts() {
        order(
            body("pub(crate) async fn prepare_tunnel("),
            &[
                "if response.success {",
                "check_permittable_relays(&response)",
                "start_stealth_tunnel(app, &response, request.custom_port)",
                "build_vpn_config(",
            ],
        );
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

/// MR-2514 [DESK-AUTO-RETRY-PARITY]: a user connect's attempts, driven
/// through `dial` in a scripted world, so the owner's retry rule (2026-11-19,
/// MR-2212 Q2) is tested as it runs: which servers are dialled, over which
/// transport, how many times, and what the log says.
#[cfg(test)]
mod dial_tests {
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;

    use super::{dial, ConnectPurpose, ConnectTarget, DialSteps, SelectionOrigin};
    use crate::api::types::VpnServer;
    use crate::commands::ipc_error::{IpcError, IpcErrorCode};
    use crate::commands::vpn::{FALLBACK_HANDSHAKE_TIMEOUT, FALLBACK_TRANSPORT_BLOCKED};
    use crate::vpn::relay_retry::Reach;

    const STEALTH: Option<&str> = Some(FALLBACK_HANDSHAKE_TIMEOUT);

    /// A server in the `/vpn/servers` wire shape.
    fn server(
        id: &str,
        cc: &str,
        city: &str,
        load: u8,
        online: bool,
        accessible: bool,
    ) -> VpnServer {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "name": format!("name-{id}"),
            "country": format!("country-{cc}"),
            "countryCode": cc,
            "city": city,
            "load": load,
            "isOnline": online,
            "accessible": accessible,
        }))
        .unwrap()
    }

    /// One server per city, as the fleet is. `srv-fra` is the one that never
    /// answers; `srv-held` is depooled for its jurisdiction (never listed
    /// online); `srv-locked` is outside this plan.
    fn fleet() -> Vec<VpnServer> {
        vec![
            server("srv-fra", "DE", "Frankfurt", 5, true, true),
            server("srv-ams", "NL", "Amsterdam", 30, true, true),
            server("srv-held", "SE", "Stockholm", 0, false, true),
            server("srv-locked", "CH", "Zurich", 1, true, false),
            server("srv-nyc", "US", "New York", 20, true, true),
        ]
    }

    /// The establish-time handshake got no answer.
    fn unanswered() -> IpcError {
        IpcError::from_tunnel_failure(&format!(
            "Failed to start tunnel: Handshake failed after 3 attempts: {}",
            crate::vpn::ERR_HANDSHAKE_NO_RESPONSE
        ))
    }

    fn picked_by(origin: SelectionOrigin, server_id: &str) -> ConnectTarget {
        ConnectTarget::SingleHop {
            server_id: server_id.into(),
            origin,
        }
    }

    /// A scripted world: each attempt takes the next answer (none left: no
    /// handshake), and everything the connect does is written down.
    struct World {
        answers: VecDeque<Result<(), IpcError>>,
        servers: Option<Vec<VpnServer>>,
        stealth_setting: bool,
        current: Cell<bool>,
        /// A Disconnect lands while the list is fetched.
        superseded_by_the_fetch: bool,
        /// A Disconnect lands during this attempt (1-based): it answers
        /// `cancelled`, as `attempt` does when its epoch moves.
        superseded_on_dial: Option<usize>,
        /// (server, transport) per attempt, in order.
        dialled: Vec<(String, Option<&'static str>)>,
        gaps: u32,
        list_fetches: u32,
        stealth_notices: Cell<u32>,
        retry_notices: Cell<u32>,
        /// Who chose, and how far each announced retry went.
        retry_reaches: RefCell<Vec<(SelectionOrigin, Reach)>>,
        log: RefCell<Vec<String>>,
    }

    impl World {
        fn answering(answers: impl IntoIterator<Item = Result<(), IpcError>>) -> Self {
            Self {
                answers: answers.into_iter().collect(),
                servers: Some(fleet()),
                stealth_setting: false,
                current: Cell::new(true),
                superseded_by_the_fetch: false,
                superseded_on_dial: None,
                dialled: Vec::new(),
                gaps: 0,
                list_fetches: 0,
                stealth_notices: Cell::new(0),
                retry_notices: Cell::new(0),
                retry_reaches: RefCell::new(Vec::new()),
                log: RefCell::new(Vec::new()),
            }
        }

        fn dialled(&self) -> Vec<(&str, Option<&str>)> {
            self.dialled
                .iter()
                .map(|(server, transport)| (server.as_str(), *transport))
                .collect()
        }

        fn logged(&self, words: &str) -> bool {
            self.log.borrow().iter().any(|line| line.contains(words))
        }
    }

    impl DialSteps for World {
        async fn attempt_once(
            &mut self,
            target: &ConnectTarget,
            transport: Option<&'static str>,
        ) -> Result<(), IpcError> {
            let server = match target {
                ConnectTarget::SingleHop { server_id, .. } => server_id.clone(),
                ConnectTarget::MultiHop { entry_id, exit_id } => format!("{entry_id}>{exit_id}"),
            };
            self.dialled.push((server, transport));
            let answer = self
                .answers
                .pop_front()
                .unwrap_or_else(|| Err(unanswered()));
            if self.superseded_on_dial == Some(self.dialled.len()) {
                self.current.set(false);
                return Err(IpcError::cancelled());
            }
            answer
        }

        fn attempted_stealth(&self) -> bool {
            self.stealth_setting
        }

        async fn cover_the_gap(&mut self) {
            self.gaps += 1;
        }

        fn announce_stealth(&self, _reason: &'static str) {
            self.stealth_notices.set(self.stealth_notices.get() + 1);
        }

        fn still_current(&self) -> bool {
            self.current.get()
        }

        async fn fresh_servers(&mut self) -> Option<Vec<VpnServer>> {
            self.list_fetches += 1;
            if self.superseded_by_the_fetch {
                self.current.set(false);
            }
            self.servers.clone()
        }

        fn announce_relay_retry(&self, origin: SelectionOrigin, reach: Reach) {
            self.retry_notices.set(self.retry_notices.get() + 1);
            self.retry_reaches.borrow_mut().push((origin, reach));
        }

        fn log(&self, line: &str) {
            self.log.borrow_mut().push(line.to_string());
        }
    }

    /// A server the client chose that never answers, direct or over the
    /// stealth transport, is retried ONCE on the best other server: here in
    /// another country, past the emptier held and plan-locked nodes. The
    /// retry runs under the same gap cover as the stealth retry, and the UI
    /// is told.
    #[tokio::test]
    async fn an_automatic_pick_that_never_answers_is_retried_once_on_another_server() {
        let mut world = World::answering([Err(unanswered()), Err(unanswered()), Ok(())]);
        let result = dial(
            &mut world,
            &picked_by(SelectionOrigin::Automatic, "srv-fra"),
            ConnectPurpose::User,
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(
            world.dialled(),
            vec![("srv-fra", None), ("srv-fra", STEALTH), ("srv-nyc", None)]
        );
        assert_eq!(world.list_fetches, 1);
        assert_eq!(world.gaps, 2, "the stealth retry and the relay retry");
        assert_eq!(world.stealth_notices.get(), 1);
        assert_eq!(world.retry_notices.get(), 1);
        assert_eq!(
            *world.retry_reaches.borrow(),
            vec![(SelectionOrigin::Automatic, Reach::OtherCountry)]
        );
        assert!(world.logged("automatic retry 1 of 1"), "{:?}", world.log);
        assert!(world.logged("other-country"), "{:?}", world.log);
        assert!(world.logged("connected (this run: "), "{:?}", world.log);
    }

    /// One retry, whatever it meets: a retry that fails too ends the
    /// connect with its error, and nothing is dialled after it.
    #[tokio::test]
    async fn a_retry_that_fails_too_is_never_retried_again() {
        for retry_failure in [
            unanswered(),
            IpcError::connect_refused_with(
                "Server unavailable",
                false,
                Some("server_unavailable"),
                None,
            ),
        ] {
            let code = retry_failure.code;
            let mut world = World::answering([
                Err(unanswered()),
                Err(unanswered()),
                Err(retry_failure),
                Ok(()),
                Ok(()),
            ]);
            let result = dial(
                &mut world,
                &picked_by(SelectionOrigin::Automatic, "srv-fra"),
                ConnectPurpose::User,
            )
            .await;
            assert_eq!(result.unwrap_err().code, code);
            assert_eq!(
                world.dialled(),
                vec![("srv-fra", None), ("srv-fra", STEALTH), ("srv-nyc", None)]
            );
            assert_eq!(world.list_fetches, 1);
            assert_eq!(world.retry_notices.get(), 1);
            assert!(world.logged("not retried again"), "{:?}", world.log);
        }
    }

    /// Owner, 2026-11-20 ("Same country, like iPhone"): a location the user
    /// picked that never answers is retried ONCE on the best other server in
    /// its own country (the same city first), as on iOS. Here Berlin, not the
    /// emptier servers abroad. A retry that fails too is not retried again.
    #[tokio::test]
    async fn a_users_pick_is_retried_once_in_its_own_country() {
        let mut list = fleet();
        list.push(server("srv-ber", "DE", "Berlin", 40, true, true));
        let mut world = World::answering([Err(unanswered()), Err(unanswered()), Ok(()), Ok(())]);
        world.servers = Some(list.clone());
        let result = dial(
            &mut world,
            &picked_by(SelectionOrigin::User, "srv-fra"),
            ConnectPurpose::User,
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(
            world.dialled(),
            vec![("srv-fra", None), ("srv-fra", STEALTH), ("srv-ber", None)]
        );
        assert_eq!(world.list_fetches, 1);
        assert_eq!(world.retry_notices.get(), 1);
        // The UI is told it stays in the country.
        assert_eq!(
            *world.retry_reaches.borrow(),
            vec![(SelectionOrigin::User, Reach::SameCountry)]
        );
        assert!(
            world.logged("retry 1 of 1 on another server (user pick, same-country)"),
            "{:?}",
            world.log
        );

        let mut world = World::answering([
            Err(unanswered()),
            Err(unanswered()),
            Err(unanswered()),
            Ok(()),
        ]);
        world.servers = Some(list);
        assert!(dial(
            &mut world,
            &picked_by(SelectionOrigin::User, "srv-fra"),
            ConnectPurpose::User,
        )
        .await
        .is_err());
        assert_eq!(world.dialled().len(), 3, "{:?}", world.dialled());
        assert!(world.logged("not retried again"), "{:?}", world.log);
    }

    /// A location the user picked never leaves its country: with no other
    /// eligible server at home (here the only German one is held, and the
    /// eligible ones are abroad) there is no retry, and the connect ends
    /// with the server's own error. Nor does a Multi-Hop route move, the
    /// user's own pair.
    #[tokio::test]
    async fn a_users_pick_never_goes_abroad() {
        let mut list = fleet();
        list.push(server("srv-ber-held", "DE", "Berlin", 0, false, true));
        let mut world = World::answering([Err(unanswered()), Err(unanswered()), Ok(()), Ok(())]);
        world.servers = Some(list);
        let result = dial(
            &mut world,
            &picked_by(SelectionOrigin::User, "srv-fra"),
            ConnectPurpose::User,
        )
        .await;
        assert_eq!(result.unwrap_err().code, IpcErrorCode::ServerUnreachable);
        assert_eq!(
            world.dialled(),
            vec![("srv-fra", None), ("srv-fra", STEALTH)]
        );
        assert_eq!(world.retry_notices.get(), 0);
        assert!(
            world.logged("no automatic retry (user pick, retry 0 of 1)"),
            "{:?}",
            world.log
        );

        let mut world = World::answering([Err(unanswered()), Ok(()), Ok(())]);
        let route = ConnectTarget::MultiHop {
            entry_id: "srv-fra".into(),
            exit_id: "srv-nyc".into(),
        };
        assert!(dial(&mut world, &route, ConnectPurpose::User)
            .await
            .is_err());
        assert_eq!(world.dialled(), vec![("srv-fra>srv-nyc", None)]);
        assert_eq!(world.list_fetches, 0);
    }

    /// Only servers the fresh list names online and open to this plan
    /// qualify: never a node held for its jurisdiction (depooled, so not
    /// online), never one outside the plan, never one only an earlier list
    /// named (the account's allow-list is the list itself), never the server
    /// that failed, even as the least loaded. With none left, no retry.
    #[tokio::test]
    async fn held_plan_excluded_and_unlisted_servers_are_never_chosen() {
        crate::vpn::relay_retry::remember(&[server(
            "srv-cached-only",
            "FR",
            "Paris",
            0,
            true,
            true,
        )]);
        let mut fresh: Vec<_> = fleet().into_iter().filter(|s| s.id != "srv-nyc").collect();
        fresh[0].load = 0;
        let mut world = World::answering([Err(unanswered()), Err(unanswered()), Ok(())]);
        world.servers = Some(fresh.clone());
        let result = dial(
            &mut world,
            &picked_by(SelectionOrigin::Automatic, "srv-fra"),
            ConnectPurpose::User,
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(world.dialled().last(), Some(&("srv-ams", None)));

        // Only the held and the plan-locked nodes are left: no retry.
        let ineligible: Vec<_> = fresh.into_iter().filter(|s| s.id != "srv-ams").collect();
        let mut world = World::answering([Err(unanswered()), Err(unanswered()), Ok(())]);
        world.servers = Some(ineligible);
        assert!(dial(
            &mut world,
            &picked_by(SelectionOrigin::Automatic, "srv-fra"),
            ConnectPurpose::User,
        )
        .await
        .is_err());
        assert_eq!(
            world.dialled(),
            vec![("srv-fra", None), ("srv-fra", STEALTH)]
        );
        assert_eq!(world.retry_notices.get(), 0);
        assert!(
            world.logged("no automatic retry (automatic pick, retry 0 of 1)"),
            "{:?}",
            world.log
        );

        // A user's pick: the only other German servers are held or outside
        // the plan, and the German one an earlier list named is not on the
        // fresh list. No retry.
        crate::vpn::relay_retry::remember(&[server(
            "srv-ber-cached-only",
            "DE",
            "Berlin",
            0,
            true,
            true,
        )]);
        let mut list = fleet();
        list.push(server("srv-ham-held", "DE", "Hamburg", 0, false, true));
        list.push(server("srv-muc-locked", "DE", "Munich", 0, true, false));
        let mut world = World::answering([Err(unanswered()), Err(unanswered()), Ok(())]);
        world.servers = Some(list);
        assert!(dial(
            &mut world,
            &picked_by(SelectionOrigin::User, "srv-fra"),
            ConnectPurpose::User,
        )
        .await
        .is_err());
        assert_eq!(world.dialled().len(), 2, "{:?}", world.dialled());
        assert_eq!(world.retry_notices.get(), 0);
    }

    /// Without a fresh list in time there is no retry: a cached list could
    /// name a server depooled since. The server's own error stands.
    #[tokio::test]
    async fn no_fresh_list_means_no_retry() {
        let mut world = World::answering([Err(unanswered()), Err(unanswered()), Ok(())]);
        world.servers = None;
        let result = dial(
            &mut world,
            &picked_by(SelectionOrigin::Automatic, "srv-fra"),
            ConnectPurpose::User,
        )
        .await;
        assert_eq!(result.unwrap_err().code, IpcErrorCode::ServerUnreachable);
        assert_eq!(world.dialled().len(), 2);
        assert_eq!(world.retry_notices.get(), 0);
        assert!(world.logged("no server list in time"), "{:?}", world.log);
    }

    /// A Disconnect or a newer connect (before or during the list fetch),
    /// or a refusal no retry can overcome, ends the connect without a retry.
    #[tokio::test]
    async fn a_disconnect_or_a_hard_refusal_ends_it_without_a_retry() {
        for (second, current, superseded_by_the_fetch, fetches) in [
            (IpcError::cancelled(), true, false, 0),
            (
                IpcError::connect_refused_with("Device limit", false, Some("device_limit"), None),
                true,
                false,
                0,
            ),
            (unanswered(), false, false, 0),
            (unanswered(), true, true, 1),
        ] {
            let mut world = World::answering([Err(unanswered()), Err(second), Ok(())]);
            world.current.set(current);
            world.superseded_by_the_fetch = superseded_by_the_fetch;
            assert!(dial(
                &mut world,
                &picked_by(SelectionOrigin::Automatic, "srv-fra"),
                ConnectPurpose::User,
            )
            .await
            .is_err());
            assert_eq!(world.dialled().len(), 2, "{:?}", world.dialled());
            assert_eq!(world.list_fetches, fetches);
            assert_eq!(world.retry_notices.get(), 0);
        }
    }

    /// Only a server that never answered the first handshake is retried
    /// elsewhere: a refusal or a local failure is not, and neither is a
    /// server the stealth transport reached.
    #[tokio::test]
    async fn only_a_server_that_never_answered_is_retried_elsewhere() {
        for first in [
            IpcError::connect_refused_with(
                "Server unavailable",
                false,
                Some("server_unavailable"),
                None,
            ),
            IpcError::from_tunnel_failure("Failed to create the adapter"),
        ] {
            let mut world = World::answering([Err(first), Ok(()), Ok(())]);
            assert!(dial(
                &mut world,
                &picked_by(SelectionOrigin::Automatic, "srv-fra"),
                ConnectPurpose::User,
            )
            .await
            .is_err());
            assert_eq!(world.dialled(), vec![("srv-fra", None)]);
            assert_eq!(world.list_fetches, 0);
        }
        let mut world = World::answering([Err(unanswered()), Ok(()), Ok(())]);
        assert!(dial(
            &mut world,
            &picked_by(SelectionOrigin::Automatic, "srv-fra"),
            ConnectPurpose::User,
        )
        .await
        .is_ok());
        assert_eq!(
            world.dialled(),
            vec![("srv-fra", None), ("srv-fra", STEALTH)]
        );
        assert_eq!(world.list_fetches, 0);
    }

    /// A settings reapply rebuilds the live session on its own server and
    /// transport, and is reverted when that fails (WIN-FIX-3): it never
    /// moves.
    #[tokio::test]
    async fn a_settings_reapply_is_never_moved() {
        let mut world = World::answering([Err(unanswered()), Ok(()), Ok(())]);
        let result = dial(
            &mut world,
            &picked_by(SelectionOrigin::Automatic, "srv-fra"),
            ConnectPurpose::SettingsReapply {
                fallback_reason: STEALTH,
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(world.dialled(), vec![("srv-fra", STEALTH)]);
        assert_eq!(world.list_fetches, 0);
    }

    /// With Stealth Mode turned on, the first attempt WAS the stealth
    /// transport, so there is no Adaptive Transport retry; the relay retry
    /// still runs, and asks for what the user's settings ask for.
    #[tokio::test]
    async fn with_stealth_mode_on_the_relay_retry_still_runs() {
        let mut world = World::answering([Err(unanswered()), Ok(())]);
        world.stealth_setting = true;
        let result = dial(
            &mut world,
            &picked_by(SelectionOrigin::Automatic, "srv-fra"),
            ConnectPurpose::User,
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(world.dialled(), vec![("srv-fra", None), ("srv-nyc", None)]);
        assert_eq!(world.stealth_notices.get(), 0);
        assert_eq!(world.retry_notices.get(), 1);
    }

    /// A user's pick goes to another server in the same CITY first, even a
    /// fuller one, before the rest of its country; the log never says
    /// other-country for it (review of #470, delta item 3).
    #[tokio::test]
    async fn a_users_pick_is_retried_in_its_own_city_first() {
        let mut list = fleet();
        list.push(server("srv-fra-2", "DE", "Frankfurt", 90, true, true));
        list.push(server("srv-ber", "DE", "Berlin", 0, true, true));
        let mut world = World::answering([Err(unanswered()), Err(unanswered()), Ok(())]);
        world.servers = Some(list);
        let result = dial(
            &mut world,
            &picked_by(SelectionOrigin::User, "srv-fra"),
            ConnectPurpose::User,
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(world.dialled().last(), Some(&("srv-fra-2", None)));
        assert!(world.logged("(user pick, same-city)"), "{:?}", world.log);
        assert!(!world.logged("other-country"), "{:?}", world.log);
    }

    /// Where the failed server was: its entry in the fresh list, else where
    /// an earlier list put it (read before this list is remembered). A
    /// user's pick gone from the fresh list still moves within that
    /// country. With neither, its country is unknown: a user's pick does
    /// not move, and the server's own error stands.
    #[tokio::test]
    async fn a_users_pick_gone_from_the_fresh_list_keeps_its_country_from_an_earlier_list() {
        crate::vpn::relay_retry::remember(&[server(
            "srv-gone-known",
            "DE",
            "Munich",
            5,
            true,
            true,
        )]);
        // The only other German server is Berlin; abroad is emptier.
        let mut list: Vec<_> = fleet().into_iter().filter(|s| s.id != "srv-fra").collect();
        list.push(server("srv-ber", "DE", "Berlin", 40, true, true));
        let mut world = World::answering([Err(unanswered()), Err(unanswered()), Ok(())]);
        world.servers = Some(list.clone());
        let result = dial(
            &mut world,
            &picked_by(SelectionOrigin::User, "srv-gone-known"),
            ConnectPurpose::User,
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(world.dialled().last(), Some(&("srv-ber", None)));
        assert_eq!(
            *world.retry_reaches.borrow(),
            vec![(SelectionOrigin::User, Reach::SameCountry)]
        );

        let mut world = World::answering([Err(unanswered()), Err(unanswered()), Ok(())]);
        world.servers = Some(list);
        let result = dial(
            &mut world,
            &picked_by(SelectionOrigin::User, "srv-gone-unknown"),
            ConnectPurpose::User,
        )
        .await;
        assert_eq!(result.unwrap_err().code, IpcErrorCode::ServerUnreachable);
        assert_eq!(world.dialled().len(), 2, "{:?}", world.dialled());
        assert_eq!(world.retry_notices.get(), 0);
    }

    /// Review L2: only a server that truly did not answer spends the retry.
    /// A local failure of the Stealth attempt (the adapter, the kill switch,
    /// a rate limit) would fail the same way on any server, and an actively
    /// refused handshake is not a silent one: neither moves the connect. A
    /// backend that calls the server unavailable does.
    #[tokio::test]
    async fn only_a_true_no_answer_spends_the_retry() {
        let refused = IpcError::from_tunnel_failure(&format!(
            "Failed to start tunnel: Handshake failed: {}",
            crate::vpn::ERR_HANDSHAKE_RECV
        ));
        for (first, second) in [
            (
                unanswered(),
                IpcError::from_tunnel_failure("Failed to create the adapter"),
            ),
            (
                unanswered(),
                IpcError::new(IpcErrorCode::KillswitchFailed, "kill switch"),
            ),
            (
                unanswered(),
                IpcError::new(IpcErrorCode::RateLimited, "slow down"),
            ),
            // A local failure of the Stealth helper (`vpn::stealth_failed`).
            (
                unanswered(),
                IpcError::new(IpcErrorCode::StealthFailed, "Stealth Mode couldn't start"),
            ),
            // Refused through the local Stealth helper: not the server's.
            (refused.clone(), refused),
        ] {
            let last_code = second.code;
            let mut world = World::answering([Err(first), Err(second), Ok(()), Ok(())]);
            let result = dial(
                &mut world,
                &picked_by(SelectionOrigin::Automatic, "srv-fra"),
                ConnectPurpose::User,
            )
            .await;
            assert_eq!(result.unwrap_err().code, last_code);
            assert_eq!(world.dialled().len(), 2, "{:?}", world.dialled());
            assert_eq!(world.list_fetches, 0);
            assert_eq!(world.retry_notices.get(), 0);
        }
        let mut world = World::answering([
            Err(unanswered()),
            Err(IpcError::connect_refused_with(
                "Server unavailable",
                false,
                Some("server_unavailable"),
                None,
            )),
            Ok(()),
        ]);
        assert!(dial(
            &mut world,
            &picked_by(SelectionOrigin::Automatic, "srv-fra"),
            ConnectPurpose::User,
        )
        .await
        .is_ok());
        assert_eq!(world.dialled().last(), Some(&("srv-nyc", None)));
    }

    /// Review L5 of #470: a server that cannot provide Stealth Mode is the
    /// server not serving. Its direct handshake got no answer, and the
    /// backend then did not grant the stealth transport for it (a node with
    /// no Xray, or a refused grant): the connect moves to another server, as
    /// iOS does for any no-answer. A failure of the LOCAL Stealth helper does
    /// not (`only_a_true_no_answer_spends_the_retry`).
    #[tokio::test]
    async fn a_server_that_cannot_provide_stealth_is_retried_elsewhere() {
        for origin in [SelectionOrigin::Automatic, SelectionOrigin::User] {
            let mut list = fleet();
            list.push(server("srv-ber", "DE", "Berlin", 40, true, true));
            let mut world = World::answering([
                Err(unanswered()),
                Err(IpcError::stealth_not_granted()),
                Ok(()),
            ]);
            world.servers = Some(list);
            let result = dial(
                &mut world,
                &picked_by(origin, "srv-fra"),
                ConnectPurpose::User,
            )
            .await;
            assert!(result.is_ok(), "{origin:?}: {result:?}");
            assert_eq!(
                world.dialled().len(),
                3,
                "{origin:?}: {:?}",
                world.dialled()
            );
            assert_eq!(world.retry_notices.get(), 1, "{origin:?}");
        }
    }

    /// Review I3 of #470, iOS parity: iOS retries a dial whose first
    /// handshake never completes within its window, whatever the cause, so a
    /// DIRECT handshake the relay actively refused (its WireGuard port
    /// unreachable) is retried elsewhere too. Refused through the local
    /// Stealth helper (Stealth Mode on) is this machine's, and is not.
    #[tokio::test]
    async fn a_refused_direct_handshake_is_retried_like_one_that_never_came() {
        let refused = || {
            IpcError::from_tunnel_failure(&format!(
                "Failed to start tunnel: Handshake failed: {}",
                crate::vpn::ERR_HANDSHAKE_RECV
            ))
        };
        let mut world = World::answering([Err(refused()), Err(unanswered()), Ok(())]);
        let result = dial(
            &mut world,
            &picked_by(SelectionOrigin::Automatic, "srv-fra"),
            ConnectPurpose::User,
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(
            world.dialled(),
            vec![
                ("srv-fra", None),
                ("srv-fra", Some(FALLBACK_TRANSPORT_BLOCKED)),
                ("srv-nyc", None)
            ]
        );

        let mut world = World::answering([Err(refused()), Ok(()), Ok(())]);
        world.stealth_setting = true;
        assert!(dial(
            &mut world,
            &picked_by(SelectionOrigin::Automatic, "srv-fra"),
            ConnectPurpose::User,
        )
        .await
        .is_err());
        assert_eq!(world.dialled(), vec![("srv-fra", None)]);
        assert_eq!(world.list_fetches, 0);
    }

    /// Review L4 and its test gap: a Disconnect during the retry's own dial
    /// ends the connect as cancelled, nothing is dialled after it, and it is
    /// neither counted nor logged as a retry that failed.
    #[tokio::test]
    async fn a_retry_cancelled_during_its_dial_is_not_counted_as_failed() {
        let mut world = World::answering([Err(unanswered()), Err(unanswered()), Ok(()), Ok(())]);
        world.superseded_on_dial = Some(3);
        let result = dial(
            &mut world,
            &picked_by(SelectionOrigin::Automatic, "srv-fra"),
            ConnectPurpose::User,
        )
        .await;
        assert_eq!(result.unwrap_err().code, IpcErrorCode::Cancelled);
        assert_eq!(world.dialled().len(), 3, "{:?}", world.dialled());
        assert!(!world.logged("failed too"), "{:?}", world.log);
        assert!(!world.logged("this run: "), "{:?}", world.log);
    }

    /// Review test gap: without a retry there is no extra gap cover; the
    /// Stealth retry's is the only one, and none without it.
    #[tokio::test]
    async fn no_gap_is_covered_for_a_retry_that_does_not_run() {
        let mut world = World::answering([Err(unanswered()), Err(unanswered())]);
        world.servers = None;
        let _ = dial(
            &mut world,
            &picked_by(SelectionOrigin::Automatic, "srv-fra"),
            ConnectPurpose::User,
        )
        .await;
        assert_eq!(world.gaps, 1, "the Stealth retry's only");

        let mut world = World::answering([Err(unanswered()), Err(unanswered())]);
        let _ = dial(
            &mut world,
            &picked_by(SelectionOrigin::User, "srv-fra"),
            ConnectPurpose::User,
        )
        .await;
        assert_eq!(world.gaps, 1, "the Stealth retry's only");

        let mut world = World::answering([Err(IpcError::from_tunnel_failure(
            "Failed to create the adapter",
        ))]);
        let _ = dial(
            &mut world,
            &picked_by(SelectionOrigin::Automatic, "srv-fra"),
            ConnectPurpose::User,
        )
        .await;
        assert_eq!(world.gaps, 0);
    }

    /// Everything the retry path logs is counts: the origin, the retry's
    /// number, a reach class and this run's totals. No server's id, name,
    /// city or country, the failed one's or the target's.
    #[tokio::test]
    async fn the_retry_logs_counts_only() {
        let mut lines = Vec::new();
        for (origin, answers) in [
            (
                SelectionOrigin::Automatic,
                vec![Err(unanswered()), Err(unanswered()), Ok(())],
            ),
            (
                SelectionOrigin::Automatic,
                vec![Err(unanswered()), Err(unanswered()), Err(unanswered())],
            ),
            (
                SelectionOrigin::User,
                vec![Err(unanswered()), Err(unanswered())],
            ),
        ] {
            let mut world = World::answering(answers);
            let _ = dial(
                &mut world,
                &picked_by(origin, "srv-fra"),
                ConnectPurpose::User,
            )
            .await;
            lines.extend(world.log.take());
        }
        let mut world = World::answering([Err(unanswered()), Err(unanswered())]);
        world.servers = None;
        let _ = dial(
            &mut world,
            &picked_by(SelectionOrigin::Automatic, "srv-fra"),
            ConnectPurpose::User,
        )
        .await;
        lines.extend(world.log.take());
        // A user's pick retried in its own country (owner, 2026-11-20).
        let berlin = server("srv-ber", "DE", "Berlin", 40, true, true);
        let mut world = World::answering([Err(unanswered()), Err(unanswered()), Ok(())]);
        world.servers = Some(fleet().into_iter().chain([berlin.clone()]).collect());
        let _ = dial(
            &mut world,
            &picked_by(SelectionOrigin::User, "srv-fra"),
            ConnectPurpose::User,
        )
        .await;
        lines.extend(world.log.take());

        assert!(lines.len() >= 8, "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("this run: ")), "{lines:?}");
        assert!(
            lines
                .iter()
                .any(|l| l.contains("retry 1 of 1 on another server (user pick, same-country)")),
            "{lines:?}"
        );
        for line in &lines {
            for s in fleet().into_iter().chain([berlin.clone()]) {
                for field in [&s.id, &s.name, &s.country, &s.country_code, &s.city] {
                    assert!(!line.contains(field.as_str()), "{line} names `{field}`");
                }
            }
            assert!(!line.contains("srv-"), "{line}");
        }
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

/// AUD-DESK-08: a relay endpoint that is not an IPv4 address (a host name, an
/// IPv6 literal) is refused before the kill switch's permit moves, on every
/// platform. It used to answer `Ok` with the permit left on the PREVIOUS
/// relay. Nothing here reaches the kill switch: the refusal comes first, and
/// `engage` is off, so an old build answers `Ok` without touching it either.
/// Runs on Windows, Linux and macOS (tests.yml FILTER).
#[cfg(test)]
mod hostname_relay_tests {
    use super::apply_relay_permit;

    #[tokio::test]
    async fn a_relay_endpoint_that_is_not_an_ipv4_address_is_refused() {
        for endpoint in [
            "relay.example.net:51820",
            "relay.example.net:8443",
            "[2001:db8::1]:51820",
        ] {
            for stealth in [false, true] {
                let refused = apply_relay_permit(endpoint, stealth, false).await;
                assert!(
                    refused
                        .as_ref()
                        .is_err_and(|e| e.contains("not an IPv4 address")),
                    "{endpoint} (stealth {stealth}): {refused:?}"
                );
            }
        }
    }
}
