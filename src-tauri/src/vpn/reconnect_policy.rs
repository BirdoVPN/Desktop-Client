//! Auto-reconnect decisions as a pure state machine (W1-029).
//!
//! The health loop used to interleave every decision with its side effects in
//! one 800-line `select!`, and the defects that mattered most were transition
//! bugs no test could reach: a dead tunnel consulted a connectivity probe that
//! was routed INTO that dead tunnel before tearing it down, and cycled
//! Reconnecting ⇄ Disconnected forever (W1-001). This module owns the
//! decisions; `auto_reconnect.rs` gathers the observations and executes the
//! actions. Nothing here does I/O, so every transition is unit-tested below.
//!
//! The rules, in priority order:
//!   1. The 426 floor stops recovery. A live tunnel is left alone (the floor
//!      blocks the control plane, not the data plane).
//!   2. A tunnel that is gone dead is torn down BEFORE anything else is
//!      consulted — its routes are what made the old probe lie.
//!   3. A hard refusal (session expired, revoked, device limit, plan, 426,
//!      elevation) gives up at once; no retry can change the answer.
//!   4. The circuit breaker (iOS `TunnelCircuitBreaker` parity): a session that
//!      keeps dying after reconnecting stops being re-dialled.
//!   5. With no route off the machine, wait without spending budget — for at
//!      most `OFFLINE_PAUSE_CAP`, so a wrong signal cannot hold anyone forever.
//!   6. Otherwise dial with exponential backoff until the budget is spent.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::api::types::HeartbeatResponse;
use crate::commands::ipc_error::{IpcError, IpcErrorCode};

/// Liveness is not judged until the session has been up this long, so the
/// first rekey has time to happen on a slow network (iOS/Android parity).
pub const LIVENESS_GRACE: Duration = Duration::from_secs(60);

/// A handshake older than this means the peer is unreachable, not idle:
/// WireGuard rekeys well inside two minutes on any session that carries
/// traffic. Same threshold as iOS `maxHandshakeAge` and Android TunnelMonitor.
pub const MAX_HANDSHAKE_AGE: Duration = Duration::from_secs(180);

/// Past this age an IDLE session is asked for a handshake, so the 180 s rule
/// never fires on a healthy peer that simply had nothing to send (persistent
/// keepalive can be off). 30 s leaves six handshake retransmits of headroom.
pub const HANDSHAKE_NUDGE_AGE: Duration = Duration::from_secs(150);

/// After a resume, a handshake must complete within this window or the path
/// is treated as broken and re-dialled at once, instead of after the 30-60 s
/// the old watchdog needed (W1-003).
pub const PATH_VERIFY_WINDOW: Duration = Duration::from_secs(10);

/// Longest wait for a route off the machine before dialling anyway.
pub const OFFLINE_PAUSE_CAP: Duration = Duration::from_secs(120);

/// Drops older than this do not count toward the breaker (iOS `failureWindow`),
/// so a node that dies once an hour never accumulates its way to a trip.
pub const BREAKER_WINDOW: Duration = Duration::from_secs(10 * 60);

/// Died-after-handshake drops inside the window before the breaker trips (iOS
/// `redialBudget(.diedAfterHandshake)`).
pub const BREAKER_DROPS: usize = 4;

/// What the OS says about getting off this machine. Read from the routing
/// table, never from a probe: see `network_events`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Connectivity {
    Online,
    Offline,
    /// This platform has no signal (macOS today): behave as online and let the
    /// WireGuard handshake be the reachability test.
    Unknown,
}

/// Why a live session was declared dead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropCause {
    /// No handshake for `MAX_HANDSHAKE_AGE` (W1-002).
    HandshakeStale,
    /// The stealth transport (xray) exited under the session (W1-005).
    TransportDied,
    /// The default route moved to another gateway or interface, or a resume
    /// could not be re-proven (W1-003). The node is not at fault, so this
    /// never counts toward the breaker, and it is re-dialled without backoff.
    PathChanged,
    /// Declared dead while there was no route off the machine at all: a
    /// local outage (Wi-Fi dropped, a train tunnel), not a dead peer
    /// (REVIEW-WIN2-005). Never counts toward the breaker; the offline pause
    /// covers the wait.
    NetworkLost,
}

impl DropCause {
    fn counts_toward_breaker(self) -> bool {
        !matches!(self, DropCause::PathChanged | DropCause::NetworkLost)
    }
}

/// What a Connected session's liveness check makes of the machine's own
/// connectivity, tick by tick (REVIEW-WIN2-005).
///
/// With no route off the machine nothing can answer a handshake, so the fast
/// dead-peer rule cannot judge the peer: the initiations boringtun keeps
/// counting while the link is down used to declare the tunnel dead about 30 s
/// into any Wi-Fi drop, and every drop counted toward the breaker — four in
/// ten minutes ended in a give-up that held a lockdown block over a healthy
/// server. When the link comes back on the same path, the path is re-proven
/// the way a resume is: what went unanswered while it was down says nothing.
#[derive(Debug, Default)]
pub struct LocalLink {
    offline: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    Online,
    /// No route off the machine: skip the fast dead-peer rule.
    Offline,
    /// Back after being offline: re-prove the path now.
    Returned,
}

impl LocalLink {
    pub fn observe(&mut self, connectivity: Connectivity) -> LinkState {
        let offline = connectivity == Connectivity::Offline;
        let was_offline = std::mem::replace(&mut self.offline, offline);
        match (was_offline, offline) {
            (_, true) => LinkState::Offline,
            (true, false) => LinkState::Returned,
            (false, false) => LinkState::Online,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    Healthy,
    /// Healthy, but ask for a handshake now (idle session, or a resume that
    /// has not been re-proven yet).
    Nudge,
    Dead(DropCause),
}

/// The liveness verdict for a Connected session.
///
/// `verify_elapsed`: time since a resume asked the path to be re-proven, while
/// no handshake has completed since. Past `PATH_VERIFY_WINDOW` the path is
/// broken. The grace period does not apply to it: a resume after a long sleep
/// is exactly when the session is oldest.
pub fn liveness(
    connected_for: Duration,
    handshake_age: Duration,
    verify_elapsed: Option<Duration>,
) -> Liveness {
    if let Some(elapsed) = verify_elapsed {
        if handshake_age >= elapsed {
            return if elapsed >= PATH_VERIFY_WINDOW {
                Liveness::Dead(DropCause::PathChanged)
            } else {
                Liveness::Nudge
            };
        }
    }
    if connected_for < LIVENESS_GRACE {
        return Liveness::Healthy;
    }
    if handshake_age > MAX_HANDSHAKE_AGE {
        Liveness::Dead(DropCause::HandshakeStale)
    } else if handshake_age > HANDSHAKE_NUDGE_AGE {
        Liveness::Nudge
    } else {
        Liveness::Healthy
    }
}

/// The session was built over one physical default route; the WireGuard socket
/// and the endpoint host route are pinned to it. A DIFFERENT route (another
/// gateway or interface: Wi-Fi to Ethernet, a dock) means the tunnel's packets
/// no longer leave the machine. No route at all is left to the offline path
/// instead: a short blip that comes back on the same network needs nothing.
pub fn needs_rebind<R: PartialEq>(pinned: Option<&R>, now: Option<&R>) -> bool {
    matches!((pinned, now), (Some(a), Some(b)) if a != b)
}

/// Whether the SERVER ended the session: a revocation (owner default, iOS
/// parity, P1-parity-021) or a used-up Free allowance (birdo-web #590). No
/// reconnect can bring either back.
pub fn server_ended(code: IpcErrorCode) -> bool {
    matches!(code, IpcErrorCode::Revoked | IpcErrorCode::QuotaExceeded)
}

/// Whether a give-up keeps the block-all engaged. Always-on (lockdown) keeps
/// blocking — the user asked for exactly that — EXCEPT when the server ended
/// the session: blocking would only hold the machine offline.
pub fn give_up_keeps_block(code: IpcErrorCode, lockdown: bool) -> bool {
    lockdown && !server_ended(code)
}

/// Whether the final `error` status is marked as a recovery that gave up
/// (`gave_up`, REVIEW-WIN-009). An ending the server decided is reported by
/// its own code whichever path brought it. A used-up allowance reaches a
/// Windows client as the RE-DIAL's refusal, not as the heartbeat's answer
/// (REVIEW-WIN2-002); marked, the UI showed "stopped reconnecting: the
/// connection keeps dropping" instead of the allowance and View plans.
pub fn marks_give_up(code: IpcErrorCode) -> bool {
    !server_ended(code)
}

/// What a heartbeat answer means for the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeartbeatVerdict {
    Fine,
    /// The relay is going offline; informational.
    ServerGoingOffline,
    /// The Free allowance is used up and the session ends when the grace
    /// window closes (birdo-web #590): tell the user, keep the tunnel.
    QuotaGrace {
        seconds_remaining: Option<u64>,
    },
    /// The server ended the session: tear down, release the block, no retry.
    End(IpcError),
}

/// The heartbeat's answer, decided. `valid:false` ends the session: with the
/// quota mark it is `quota_exceeded`, otherwise a revocation. `valid:true`
/// with the quota mark is the grace window. An older server sends neither
/// mark, and everything behaves as before.
pub fn heartbeat_verdict(resp: &HeartbeatResponse) -> HeartbeatVerdict {
    let quota = resp.quota_exceeded || resp.reason.as_deref() == Some("quota_exceeded");
    if !resp.valid {
        return HeartbeatVerdict::End(if quota {
            quota_exceeded_error()
        } else {
            revoked_error(resp.message.as_deref())
        });
    }
    if quota {
        return HeartbeatVerdict::QuotaGrace {
            seconds_remaining: resp.quota_grace_seconds_remaining,
        };
    }
    if !resp.server_online {
        return HeartbeatVerdict::ServerGoingOffline;
    }
    HeartbeatVerdict::Fine
}

/// How long a session counts as recently alive after it connected or a
/// heartbeat answered for it: the server's stale reap needs five minutes of
/// silence (WEB-HB), so a key gone sooner was taken, not reaped.
pub const ALIVE_WINDOW: Duration = Duration::from_secs(5 * 60);

/// Whether a key the server says it no longer has was taken away from this
/// device rather than reaped: the session was confirmed alive (connected, or
/// a heartbeat answered) within [`ALIVE_WINDOW`], with no resume since — a
/// machine that slept can have been reaped whatever the clock says.
pub fn recently_alive(alive_at: Option<Instant>, now: Instant, resumed_since: bool) -> bool {
    !resumed_since && alive_at.is_some_and(|at| now.duration_since(at) < ALIVE_WINDOW)
}

/// Whether a death is the kind a server-side removal causes — the relay
/// stopped answering — and so worth asking the old key about before a
/// re-dial. Not a moved path, a local outage or the stealth helper exiting.
pub fn asks_the_old_key(cause: DropCause) -> bool {
    cause == DropCause::HandshakeStale
}

/// What the dead session's own key says, asked ONCE after the dead tunnel
/// came down and before any re-dial (REVIEW-WIN2-002 generalised;
/// REVIEW-AND2-001). `Some(error)` ends the session with no re-dial; `None`
/// re-dials.
///
/// WHY. The backend removes a key's peer from its node BEFORE it answers —
/// on an eviction (the device cap), a revocation (another device's
/// "disconnect", sign-out everywhere), the #590 quota end and a drain — and
/// on Windows the heartbeat rides the tunnel, so the answer that says so dies
/// with the peer. The tunnel just went quiet, and the re-dial that followed
/// undid the server's decision: two devices on a one-device plan evicted each
/// other for ever, a remote disconnect was reversed, and the allowance's end
/// was never seen. With the tunnel gone, this probe leaves over the physical
/// network through the app's own control-plane permit, like the re-dial it
/// precedes.
///
/// `answer`: the reply, `None` when the probe failed or timed out (an outage
/// must not delay recovery: re-dial). `recently_alive`: see
/// [`recently_alive`].
///
/// | reply | verdict |
/// |---|---|
/// | none, or `valid:true` (`ok`, a server going offline, the quota grace) | re-dial |
/// | `quota_exceeded` | end: `quota_exceeded` |
/// | `evicted`, `revoked` | end: `revoked` |
/// | `reaped`, `server_offline` (a drain) | re-dial |
/// | `not_found`, no `reason` (a server before WEB-HB), anything newer | end as `revoked` if recently alive, else re-dial (WEB-HB's client table) |
pub fn after_teardown(
    answer: Option<&HeartbeatResponse>,
    recently_alive: bool,
) -> Option<IpcError> {
    let resp = answer?;
    if resp.valid {
        return None;
    }
    if resp.quota_exceeded || resp.reason.as_deref() == Some("quota_exceeded") {
        return Some(quota_exceeded_error());
    }
    match resp.reason.as_deref() {
        Some("evicted" | "revoked") => Some(revoked_error(resp.message.as_deref())),
        Some("reaped" | "server_offline") => None,
        _ => recently_alive.then(|| revoked_error(resp.message.as_deref())),
    }
}

/// The error for a session the server ended over the Free allowance. The UI
/// words it by code (and offers View plans); this is the secondary sentence.
pub fn quota_exceeded_error() -> IpcError {
    IpcError::new(
        IpcErrorCode::QuotaExceeded,
        "You've used this month's free data allowance. Upgrade to keep using BirdoVPN.",
    )
}

/// The error for a heartbeat `valid:false`. The server's own sentence wins
/// when it sent one (canonical vocabulary: "prefer the server's message").
pub fn revoked_error(server_message: Option<&str>) -> IpcError {
    let message = server_message
        .map(str::trim)
        .filter(|m| !m.is_empty())
        .unwrap_or("Connection has been revoked. Please reconnect.");
    IpcError::new(IpcErrorCode::Revoked, message)
}

/// What the loop saw this tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observed {
    Connected,
    /// Reconnecting, Error or Disconnected: nothing is carrying traffic.
    NotConnected,
    /// Connecting, Switching or Disconnecting: someone else owns the tunnel
    /// right now, so the loop waits.
    Busy,
}

#[derive(Debug, Clone, Copy)]
pub struct Tick {
    pub now: Instant,
    pub observed: Observed,
    /// A tunnel object is still held (dead or alive).
    pub holds_tunnel: bool,
    /// Only meaningful while `Connected`.
    pub liveness: Liveness,
    pub connectivity: Connectivity,
    /// The 426 floor is latched (`api::upgrade_gate`).
    pub upgrade_blocked: bool,
    /// There is a session on record to re-dial.
    pub has_target: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Idle,
    /// Ask the tunnel for a handshake.
    Nudge,
    /// Back to Connected after recovering: release a reactive block.
    Recovered,
    /// Engage the block, tear the dead tunnel down, decide again at once.
    TearDown {
        cause: DropCause,
    },
    /// No route off the machine: block, show Reconnecting, wait.
    PauseOffline {
        attempt: u32,
    },
    /// Block, show Reconnecting, wait `delay`, then re-dial.
    Dial {
        attempt: u32,
        delay: Duration,
    },
    /// Terminal: end in `Error` with this code; see `give_up_keeps_block`.
    GiveUp(IpcError),
    /// Terminal: the 426 floor with a live tunnel. Stop recovering, touch
    /// nothing.
    Halt,
}

#[derive(Debug, Clone, Copy)]
pub struct Budget {
    /// Dials per episode; 0 = unbounded.
    pub max_attempts: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub multiplier: f64,
}

/// Exponential backoff for the `attempts`-th retry (0-based), capped.
pub fn backoff_delay(attempts: u32, budget: &Budget) -> Duration {
    let delay_ms =
        budget.initial_delay.as_millis() as f64 * budget.multiplier.powi(attempts as i32);
    // P3: a non-finite intermediate (f64 overflow under an unbounded budget)
    // reads as the cap, identical to the clamped behaviour.
    if !delay_ms.is_finite() {
        return budget.max_delay;
    }
    Duration::from_millis(delay_ms as u64).min(budget.max_delay)
}

pub struct ReconnectPolicy {
    budget: Budget,
    /// Dials spent in the current episode.
    attempts: u32,
    /// Set while an episode is open; the next Connected tick is a recovery.
    recovering: bool,
    offline_since: Option<Instant>,
    /// The next dial skips the backoff (the network came back, or the path
    /// moved and the node was never at fault).
    immediate: bool,
    last_error: Option<IpcError>,
    drops: VecDeque<Instant>,
    tripped: bool,
}

impl ReconnectPolicy {
    pub fn new(budget: Budget) -> Self {
        Self {
            budget,
            attempts: 0,
            recovering: false,
            offline_since: None,
            immediate: false,
            last_error: None,
            drops: VecDeque::new(),
            tripped: false,
        }
    }

    /// The retry budget as the UI shows it (`reconnect_max`; None = unbounded).
    pub fn reconnect_max(&self) -> Option<u32> {
        (self.budget.max_attempts != 0).then_some(self.budget.max_attempts)
    }

    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    pub fn last_error(&self) -> Option<&IpcError> {
        self.last_error.as_ref()
    }

    /// A re-dial failed. A hard refusal ends recovery on the next decision.
    pub fn on_dial_failed(&mut self, error: IpcError) {
        self.last_error = Some(error);
    }

    fn open_episode(&mut self, cause: DropCause, now: Instant) {
        self.attempts = 0;
        self.recovering = true;
        self.last_error = None;
        self.immediate = cause == DropCause::PathChanged;
        if cause.counts_toward_breaker() {
            while self
                .drops
                .front()
                .is_some_and(|t| now.duration_since(*t) > BREAKER_WINDOW)
            {
                self.drops.pop_front();
            }
            self.drops.push_back(now);
            if self.drops.len() >= BREAKER_DROPS {
                self.tripped = true;
            }
        }
    }

    fn give_up_error(&self) -> IpcError {
        if self.tripped {
            return IpcError::new(
                IpcErrorCode::ServerUnreachable,
                "BirdoVPN stopped reconnecting: the connection to this server keeps \
                 dropping. Connect again to retry, or choose another location.",
            );
        }
        let plural = if self.attempts == 1 {
            "attempt"
        } else {
            "attempts"
        };
        match &self.last_error {
            Some(last) => IpcError::new(
                last.code,
                format!(
                    "BirdoVPN stopped reconnecting after {} {plural}. {}",
                    self.attempts, last.message
                ),
            ),
            None => IpcError::new(
                IpcErrorCode::ServerUnreachable,
                format!(
                    "BirdoVPN stopped reconnecting after {} {plural}: this server could not \
                     be reached. Try a different location, or a different network.",
                    self.attempts
                ),
            ),
        }
    }

    pub fn decide(&mut self, tick: &Tick) -> Action {
        if tick.upgrade_blocked {
            return match tick.observed {
                Observed::Connected => Action::Halt,
                _ => Action::GiveUp(IpcError::new(
                    IpcErrorCode::UpgradeRequired,
                    "This version of BirdoVPN is no longer supported. Update to keep connecting.",
                )),
            };
        }

        match tick.observed {
            Observed::Busy => Action::Idle,
            Observed::Connected => {
                if self.recovering {
                    self.recovering = false;
                    self.attempts = 0;
                    self.offline_since = None;
                    self.immediate = false;
                    self.last_error = None;
                    return Action::Recovered;
                }
                match tick.liveness {
                    Liveness::Healthy => Action::Idle,
                    Liveness::Nudge => Action::Nudge,
                    Liveness::Dead(cause) => {
                        // Whatever rule fired, with no route off the machine
                        // the node is not what failed (REVIEW-WIN2-005).
                        let cause = if tick.connectivity == Connectivity::Offline {
                            DropCause::NetworkLost
                        } else {
                            cause
                        };
                        self.open_episode(cause, tick.now);
                        Action::TearDown { cause }
                    }
                }
            }
            Observed::NotConnected => {
                if !tick.has_target {
                    return Action::Idle;
                }
                // W1-001: a tunnel still held while nothing is connected is a
                // dead one. Its /1 routes swallow everything, including any
                // attempt to find out whether the network is up. Remove it
                // before looking at anything else.
                if tick.holds_tunnel {
                    return Action::TearDown {
                        cause: DropCause::HandshakeStale,
                    };
                }
                if let Some(refusal) = self
                    .last_error
                    .as_ref()
                    .filter(|e| e.code.is_hard_refusal())
                {
                    return Action::GiveUp(refusal.clone());
                }
                if self.tripped {
                    return Action::GiveUp(self.give_up_error());
                }
                self.recovering = true;

                if tick.connectivity == Connectivity::Offline {
                    let since = *self.offline_since.get_or_insert(tick.now);
                    if tick.now.duration_since(since) < OFFLINE_PAUSE_CAP {
                        return Action::PauseOffline {
                            attempt: self.attempts + 1,
                        };
                    }
                    // Still "offline" after the cap: dial anyway. The attempt
                    // is the real test, and it spends budget, so a wrong
                    // offline signal cannot hold the machine behind the block.
                } else if self.offline_since.take().is_some() {
                    // The network is back: a full budget, and no backoff.
                    self.attempts = 0;
                    self.immediate = true;
                }

                if self.budget.max_attempts != 0 && self.attempts >= self.budget.max_attempts {
                    return Action::GiveUp(self.give_up_error());
                }
                let delay = if std::mem::take(&mut self.immediate) {
                    Duration::ZERO
                } else {
                    backoff_delay(self.attempts, &self.budget)
                };
                self.attempts += 1;
                Action::Dial {
                    attempt: self.attempts,
                    delay,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget() -> Budget {
        Budget {
            max_attempts: 3,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            multiplier: 2.0,
        }
    }

    fn tick(now: Instant, observed: Observed) -> Tick {
        Tick {
            now,
            observed,
            holds_tunnel: false,
            liveness: Liveness::Healthy,
            connectivity: Connectivity::Online,
            upgrade_blocked: false,
            has_target: true,
        }
    }

    fn not_connected(now: Instant) -> Tick {
        tick(now, Observed::NotConnected)
    }

    /// W1-001's regression, exactly as the audit wrote it: the tunnel is dead,
    /// the state says Error, and the (old) probe says offline. The dead tunnel
    /// must be torn down FIRST — pausing for the network with its routes still
    /// installed is what looped forever.
    #[test]
    fn dead_tunnel_is_torn_down_before_offline_pause() {
        let mut p = ReconnectPolicy::new(budget());
        let now = Instant::now();
        let mut t = not_connected(now);
        t.holds_tunnel = true;
        t.connectivity = Connectivity::Offline;
        assert!(matches!(p.decide(&t), Action::TearDown { .. }));

        // With the tunnel gone, the offline pause applies.
        t.holds_tunnel = false;
        assert_eq!(p.decide(&t), Action::PauseOffline { attempt: 1 });
    }

    #[test]
    fn a_dead_connected_session_is_torn_down_then_redialled() {
        let mut p = ReconnectPolicy::new(budget());
        let now = Instant::now();
        let mut t = tick(now, Observed::Connected);
        t.liveness = Liveness::Dead(DropCause::HandshakeStale);
        assert_eq!(
            p.decide(&t),
            Action::TearDown {
                cause: DropCause::HandshakeStale
            }
        );
        assert_eq!(
            p.decide(&not_connected(now)),
            Action::Dial {
                attempt: 1,
                delay: Duration::from_secs(1)
            }
        );
    }

    #[test]
    fn offline_pause_spends_no_budget_and_is_capped() {
        let mut p = ReconnectPolicy::new(budget());
        let start = Instant::now();
        let mut t = not_connected(start);
        t.connectivity = Connectivity::Offline;
        for s in [0, 30, 60, 119] {
            t.now = start + Duration::from_secs(s);
            assert_eq!(p.decide(&t), Action::PauseOffline { attempt: 1 }, "at {s}s");
        }
        assert_eq!(p.attempts(), 0);
        // Past the cap it dials anyway, spending budget.
        t.now = start + OFFLINE_PAUSE_CAP;
        assert!(matches!(p.decide(&t), Action::Dial { attempt: 1, .. }));
    }

    #[test]
    fn network_return_resumes_at_once_with_a_fresh_budget() {
        let mut p = ReconnectPolicy::new(budget());
        let now = Instant::now();
        // Two failed dials...
        for _ in 0..2 {
            assert!(matches!(p.decide(&not_connected(now)), Action::Dial { .. }));
            p.on_dial_failed(IpcError::new(IpcErrorCode::ServerUnreachable, "x"));
        }
        // ...then the network goes away...
        let mut t = not_connected(now);
        t.connectivity = Connectivity::Offline;
        assert!(matches!(p.decide(&t), Action::PauseOffline { .. }));
        // ...and comes back: attempt 1 again, no backoff.
        assert_eq!(
            p.decide(&not_connected(now)),
            Action::Dial {
                attempt: 1,
                delay: Duration::ZERO
            }
        );
    }

    #[test]
    fn budget_exhaustion_gives_up_with_the_last_error_code() {
        let mut p = ReconnectPolicy::new(budget());
        let now = Instant::now();
        let mut delays = Vec::new();
        for _ in 0..3 {
            match p.decide(&not_connected(now)) {
                Action::Dial { delay, .. } => delays.push(delay.as_secs()),
                other => panic!("{other:?}"),
            }
            p.on_dial_failed(IpcError::new(IpcErrorCode::StealthFailed, "xray died"));
        }
        assert_eq!(delays, vec![1, 2, 4]);
        match p.decide(&not_connected(now)) {
            Action::GiveUp(err) => {
                assert_eq!(err.code, IpcErrorCode::StealthFailed);
                assert!(err.message.contains("after 3 attempts"), "{}", err.message);
            }
            other => panic!("expected give-up, got {other:?}"),
        }
    }

    #[test]
    fn an_unbounded_budget_never_gives_up_on_its_own() {
        let mut p = ReconnectPolicy::new(Budget {
            max_attempts: 0,
            ..budget()
        });
        assert_eq!(p.reconnect_max(), None);
        let now = Instant::now();
        for _ in 0..50 {
            assert!(matches!(p.decide(&not_connected(now)), Action::Dial { .. }));
            p.on_dial_failed(IpcError::new(IpcErrorCode::ServerUnreachable, "x"));
        }
    }

    #[test]
    fn hard_refusals_stop_immediately() {
        for code in [
            IpcErrorCode::DeviceLimit,
            IpcErrorCode::SubscriptionRequired,
            IpcErrorCode::SessionExpired,
            IpcErrorCode::Revoked,
            IpcErrorCode::NotElevated,
        ] {
            let mut p = ReconnectPolicy::new(budget());
            let now = Instant::now();
            assert!(matches!(p.decide(&not_connected(now)), Action::Dial { .. }));
            p.on_dial_failed(IpcError::new(code, "no"));
            match p.decide(&not_connected(now)) {
                Action::GiveUp(err) => assert_eq!(err.code, code),
                other => panic!("{code:?}: expected give-up, got {other:?}"),
            }
        }
    }

    /// The 426 latch (W1 section (b)): recovery stops; a live tunnel is left
    /// alone, a dead one ends in `upgrade_required`.
    #[test]
    fn the_upgrade_floor_stops_recovery() {
        let mut p = ReconnectPolicy::new(budget());
        let now = Instant::now();
        let mut t = tick(now, Observed::Connected);
        t.upgrade_blocked = true;
        assert_eq!(p.decide(&t), Action::Halt);
        let mut t = not_connected(now);
        t.upgrade_blocked = true;
        match p.decide(&t) {
            Action::GiveUp(err) => assert_eq!(err.code, IpcErrorCode::UpgradeRequired),
            other => panic!("{other:?}"),
        }
    }

    /// User disconnect during reconnect: `end_session` clears the target (and
    /// stops the loop); nothing is dialled for a session nobody wants.
    #[test]
    fn no_target_means_no_dial() {
        let mut p = ReconnectPolicy::new(budget());
        let mut t = not_connected(Instant::now());
        t.has_target = false;
        t.holds_tunnel = true;
        assert_eq!(p.decide(&t), Action::Idle);
    }

    #[test]
    fn busy_states_are_left_to_their_owner() {
        let mut p = ReconnectPolicy::new(budget());
        let mut t = tick(Instant::now(), Observed::Busy);
        t.holds_tunnel = true;
        t.liveness = Liveness::Dead(DropCause::HandshakeStale);
        assert_eq!(p.decide(&t), Action::Idle);
    }

    #[test]
    fn recovery_resets_the_episode() {
        let mut p = ReconnectPolicy::new(budget());
        let now = Instant::now();
        assert!(matches!(p.decide(&not_connected(now)), Action::Dial { .. }));
        p.on_dial_failed(IpcError::new(IpcErrorCode::ServerUnreachable, "x"));
        assert!(matches!(
            p.decide(&not_connected(now)),
            Action::Dial { attempt: 2, .. }
        ));
        assert_eq!(p.decide(&tick(now, Observed::Connected)), Action::Recovered);
        assert_eq!(p.attempts(), 0);
        assert_eq!(p.last_error(), None);
        assert_eq!(p.decide(&tick(now, Observed::Connected)), Action::Idle);
    }

    /// iOS breaker parity: a session that keeps dying after reconnecting is
    /// not re-dialled a fifth time inside the window.
    #[test]
    fn the_breaker_trips_on_repeated_drops_inside_the_window() {
        let mut p = ReconnectPolicy::new(budget());
        let start = Instant::now();
        for i in 0..BREAKER_DROPS as u64 {
            let now = start + Duration::from_secs(60 * i);
            let mut t = tick(now, Observed::Connected);
            t.liveness = Liveness::Dead(DropCause::HandshakeStale);
            assert!(matches!(p.decide(&t), Action::TearDown { .. }));
            let next = p.decide(&not_connected(now));
            if (i as usize) + 1 < BREAKER_DROPS {
                assert!(matches!(next, Action::Dial { .. }), "drop {i}: {next:?}");
                assert_eq!(p.decide(&tick(now, Observed::Connected)), Action::Recovered);
            } else {
                match next {
                    Action::GiveUp(err) => {
                        assert_eq!(err.code, IpcErrorCode::ServerUnreachable);
                        assert!(err.message.contains("keeps dropping"));
                    }
                    other => panic!("expected the breaker to trip, got {other:?}"),
                }
            }
        }
    }

    #[test]
    fn drops_outside_the_window_and_path_changes_do_not_trip_the_breaker() {
        let mut p = ReconnectPolicy::new(budget());
        let start = Instant::now();
        for i in 0..8u64 {
            let now = start + BREAKER_WINDOW * (i as u32) + Duration::from_secs(1);
            let mut t = tick(now, Observed::Connected);
            t.liveness = Liveness::Dead(DropCause::HandshakeStale);
            assert!(matches!(p.decide(&t), Action::TearDown { .. }));
            assert!(matches!(p.decide(&not_connected(now)), Action::Dial { .. }));
            assert_eq!(p.decide(&tick(now, Observed::Connected)), Action::Recovered);
        }
        let now = start;
        for _ in 0..8 {
            let mut t = tick(now, Observed::Connected);
            t.liveness = Liveness::Dead(DropCause::PathChanged);
            assert!(matches!(p.decide(&t), Action::TearDown { .. }));
            // A moved path is re-dialled without backoff.
            assert_eq!(
                p.decide(&not_connected(now)),
                Action::Dial {
                    attempt: 1,
                    delay: Duration::ZERO
                }
            );
            assert_eq!(p.decide(&tick(now, Observed::Connected)), Action::Recovered);
        }
    }

    /// REVIEW-WIN2-005: a laptop on flaky Wi-Fi, four drops in ten minutes.
    /// A tunnel declared dead while there was no route off the machine is a
    /// local outage: it never trips the breaker, and the next decision waits
    /// for the network instead of dialling into nothing.
    #[test]
    fn local_outages_never_trip_the_breaker() {
        let mut p = ReconnectPolicy::new(budget());
        let start = Instant::now();
        for i in 0..(BREAKER_DROPS as u64 * 2) {
            let now = start + Duration::from_secs(60 * i);
            let mut t = tick(now, Observed::Connected);
            t.connectivity = Connectivity::Offline;
            t.liveness = Liveness::Dead(DropCause::HandshakeStale);
            assert_eq!(
                p.decide(&t),
                Action::TearDown {
                    cause: DropCause::NetworkLost
                },
                "drop {i}"
            );
            let mut gone = not_connected(now);
            gone.connectivity = Connectivity::Offline;
            assert_eq!(p.decide(&gone), Action::PauseOffline { attempt: 1 });
            // The Wi-Fi is back: at once, a full budget.
            assert_eq!(
                p.decide(&not_connected(now)),
                Action::Dial {
                    attempt: 1,
                    delay: Duration::ZERO
                }
            );
            assert_eq!(p.decide(&tick(now, Observed::Connected)), Action::Recovered);
        }
    }

    /// The same drops with a route up ARE the node's: the breaker still
    /// trips on them (iOS parity is unchanged).
    #[test]
    fn a_dead_peer_with_a_route_up_still_counts() {
        let mut p = ReconnectPolicy::new(budget());
        let now = Instant::now();
        let mut t = tick(now, Observed::Connected);
        t.liveness = Liveness::Dead(DropCause::HandshakeStale);
        assert_eq!(
            p.decide(&t),
            Action::TearDown {
                cause: DropCause::HandshakeStale
            }
        );
    }

    /// The liveness check's view of the link: offline skips the fast rule,
    /// and coming back re-proves the path once.
    #[test]
    fn the_link_reports_loss_and_return_once() {
        let mut link = LocalLink::default();
        assert_eq!(link.observe(Connectivity::Online), LinkState::Online);
        assert_eq!(link.observe(Connectivity::Offline), LinkState::Offline);
        assert_eq!(link.observe(Connectivity::Offline), LinkState::Offline);
        assert_eq!(link.observe(Connectivity::Online), LinkState::Returned);
        assert_eq!(link.observe(Connectivity::Online), LinkState::Online);
        // A platform with no route signal is never "offline".
        assert_eq!(link.observe(Connectivity::Unknown), LinkState::Online);
    }

    #[test]
    fn liveness_follows_handshake_age() {
        let s = Duration::from_secs;
        // Grace: nothing is judged in the first minute.
        assert_eq!(liveness(s(30), s(500), None), Liveness::Healthy);
        assert_eq!(liveness(s(600), s(100), None), Liveness::Healthy);
        assert_eq!(liveness(s(600), s(160), None), Liveness::Nudge);
        assert_eq!(
            liveness(s(600), s(181), None),
            Liveness::Dead(DropCause::HandshakeStale)
        );
    }

    #[test]
    fn a_resume_must_be_reproven_within_the_window() {
        let s = Duration::from_secs;
        // No handshake since the resume 4 s ago: keep asking.
        assert_eq!(liveness(s(900), s(40), Some(s(4))), Liveness::Nudge);
        // Still none after the window: the path is broken.
        assert_eq!(
            liveness(s(900), s(40), Some(s(10))),
            Liveness::Dead(DropCause::PathChanged)
        );
        // A handshake 2 s ago, after the resume 4 s ago: proven, and the normal
        // rules apply again (even inside the grace period).
        assert_eq!(liveness(s(10), s(2), Some(s(4))), Liveness::Healthy);
    }

    #[test]
    fn a_different_default_route_needs_a_rebind_and_no_route_does_not() {
        assert!(needs_rebind(Some(&(1, 7)), Some(&(2, 7))));
        assert!(needs_rebind(Some(&(1, 7)), Some(&(1, 9))));
        assert!(!needs_rebind(Some(&(1, 7)), Some(&(1, 7))));
        assert!(!needs_rebind(Some(&(1, 7)), None));
        assert!(!needs_rebind::<(u8, u8)>(None, Some(&(1, 7))));
    }

    fn heartbeat(json: &str) -> HeartbeatResponse {
        serde_json::from_str(json).unwrap()
    }

    /// birdo-web #590, all three shapes, and today's server.
    #[test]
    fn heartbeat_answers_decide_the_session() {
        assert_eq!(
            heartbeat_verdict(&heartbeat(r#"{"valid":true}"#)),
            HeartbeatVerdict::Fine
        );
        assert_eq!(
            heartbeat_verdict(&heartbeat(r#"{"valid":true,"serverOnline":false}"#)),
            HeartbeatVerdict::ServerGoingOffline
        );
        // An old server's revocation: unchanged.
        match heartbeat_verdict(&heartbeat(r#"{"valid":false,"message":"Session ended"}"#)) {
            HeartbeatVerdict::End(e) => assert_eq!(e.code, IpcErrorCode::Revoked),
            other => panic!("{other:?}"),
        }
        // Inside the grace window: a warning, and the tunnel stays.
        assert_eq!(
            heartbeat_verdict(&heartbeat(
                r#"{"valid":true,"quotaExceeded":true,"quotaGraceEndsAt":"2026-10-01T12:15:00Z","quotaGraceSecondsRemaining":540,"message":"Free data allowance used"}"#
            )),
            HeartbeatVerdict::QuotaGrace {
                seconds_remaining: Some(540)
            }
        );
        assert_eq!(
            heartbeat_verdict(&heartbeat(
                r#"{"valid":true,"quotaExceeded":true,"quotaGraceSecondsRemaining":"soon"}"#
            )),
            HeartbeatVerdict::QuotaGrace {
                seconds_remaining: None
            }
        );
        // After it: terminal, and not a revocation.
        for after in [
            r#"{"valid":false,"quotaExceeded":true,"reason":"quota_exceeded","message":"x"}"#,
            r#"{"valid":false,"reason":"quota_exceeded"}"#,
        ] {
            match heartbeat_verdict(&heartbeat(after)) {
                HeartbeatVerdict::End(e) => {
                    assert_eq!(e.code, IpcErrorCode::QuotaExceeded);
                    assert!(!e.retryable);
                    assert!(e.code.is_hard_refusal());
                }
                other => panic!("{other:?}"),
            }
        }
    }

    /// The probe of the old key after a teardown, every row of the table,
    /// against the replies birdo-web sends today (no `reason` except the
    /// quota's) and after WEB-HB (a `reason` on every reply).
    #[test]
    fn the_old_keys_answer_decides_between_ending_and_re_dialling() {
        let ends = |json: &str, alive: bool| after_teardown(Some(&heartbeat(json)), alive);

        // No answer (offline, timed out): never delays a recovery.
        assert_eq!(after_teardown(None, true), None);
        // The key lives: the path failed, not the session.
        for live in [
            r#"{"valid":true,"serverOnline":true,"reason":"ok"}"#,
            r#"{"valid":true,"serverOnline":false,"reason":"server_offline"}"#,
            r#"{"valid":true,"quotaExceeded":true,"quotaGraceSecondsRemaining":60}"#,
            r#"{"valid":true}"#,
        ] {
            assert_eq!(ends(live, true), None, "{live}");
        }
        // The server ended it: stop, whatever the timing.
        for (gone, code) in [
            (
                r#"{"valid":false,"serverOnline":false,"reason":"evicted"}"#,
                IpcErrorCode::Revoked,
            ),
            (
                r#"{"valid":false,"serverOnline":false,"reason":"revoked"}"#,
                IpcErrorCode::Revoked,
            ),
            (
                r#"{"valid":false,"serverOnline":true,"quotaExceeded":true,"reason":"quota_exceeded","message":"x"}"#,
                IpcErrorCode::QuotaExceeded,
            ),
        ] {
            for alive in [true, false] {
                let err = ends(gone, alive).unwrap_or_else(|| panic!("{gone}: re-dialled"));
                assert_eq!(err.code, code, "{gone}");
                assert!(!give_up_keeps_block(err.code, true), "{gone}");
                assert!(!marks_give_up(err.code), "{gone}");
            }
        }
        // Reaped or drained: a re-dial is what the server expects.
        for redial in [
            r#"{"valid":false,"serverOnline":false,"reason":"reaped"}"#,
            r#"{"valid":false,"serverOnline":false,"reason":"server_offline"}"#,
        ] {
            assert_eq!(ends(redial, true), None, "{redial}");
        }
        // Not found — and today's server, which says only "not found": taken
        // from a device that was just checking in, reaped from one that was
        // not (or slept).
        for unknown in [
            r#"{"valid":false,"serverOnline":false,"reason":"not_found"}"#,
            r#"{"valid":false,"serverOnline":false,"message":"Connection not found. Please reconnect."}"#,
            r#"{"valid":false,"serverOnline":false,"reason":"something_newer"}"#,
        ] {
            assert_eq!(
                ends(unknown, true).map(|e| e.code),
                Some(IpcErrorCode::Revoked),
                "{unknown}"
            );
            assert_eq!(ends(unknown, false), None, "{unknown}");
        }
    }

    /// The eviction ping-pong, end to end through the policy: device A is
    /// evicted by B on a one-device plan. A's dead tunnel is torn down, the
    /// old key answers that it was taken, and A stops — no re-dial, so B is
    /// never evicted back.
    #[test]
    fn an_evicted_device_stops_instead_of_evicting_the_other_one_back() {
        let mut p = ReconnectPolicy::new(budget());
        let now = Instant::now();
        let mut t = tick(now, Observed::Connected);
        t.liveness = Liveness::Dead(DropCause::HandshakeStale);
        let Action::TearDown { cause } = p.decide(&t) else {
            panic!("expected a teardown");
        };
        assert!(asks_the_old_key(cause));
        let alive = recently_alive(Some(now - Duration::from_secs(25)), now, false);
        let verdict = after_teardown(
            Some(&heartbeat(
                r#"{"valid":false,"serverOnline":false,"message":"Connection not found. Please reconnect."}"#,
            )),
            alive,
        );
        assert_eq!(verdict.map(|e| e.code), Some(IpcErrorCode::Revoked));
        // Only a dead peer is worth the question.
        for other in [
            DropCause::PathChanged,
            DropCause::NetworkLost,
            DropCause::TransportDied,
        ] {
            assert!(!asks_the_old_key(other), "{other:?}");
        }
    }

    #[test]
    fn alive_means_confirmed_within_the_reap_window_and_no_sleep_since() {
        let now = Instant::now();
        let ago = |s| Some(now - Duration::from_secs(s));
        assert!(recently_alive(ago(30), now, false));
        assert!(recently_alive(ago(299), now, false));
        assert!(!recently_alive(ago(300), now, false));
        assert!(!recently_alive(ago(30), now, true), "a resume since");
        assert!(!recently_alive(None, now, false));
    }

    #[test]
    fn a_used_up_allowance_releases_the_block_even_in_lockdown() {
        assert!(!give_up_keeps_block(IpcErrorCode::QuotaExceeded, true));
        assert!(!give_up_keeps_block(IpcErrorCode::QuotaExceeded, false));
    }

    /// REVIEW-WIN2-002, the path #590 really takes on Windows: the heartbeat's
    /// answer is lost with the removed peer, the dead tunnel is torn down, and
    /// the FIRST re-dial is refused with `quotaExceeded`. Recovery ends there
    /// — no second dial, no backoff — with the allowance's own code, the block
    /// released even under lockdown, and no "stopped reconnecting" mark.
    #[test]
    fn a_quota_refusal_on_the_re_dial_ends_the_session_at_once() {
        let mut p = ReconnectPolicy::new(Budget {
            max_attempts: 10,
            ..budget()
        });
        let now = Instant::now();
        let mut t = tick(now, Observed::Connected);
        t.liveness = Liveness::Dead(DropCause::HandshakeStale);
        assert!(matches!(p.decide(&t), Action::TearDown { .. }));
        assert!(matches!(
            p.decide(&not_connected(now)),
            Action::Dial { attempt: 1, .. }
        ));
        p.on_dial_failed(crate::commands::ipc_error::IpcError::connect_refused(
            "Free-tier data limit reached",
            true,
        ));
        match p.decide(&not_connected(now)) {
            Action::GiveUp(err) => {
                assert_eq!(err.code, IpcErrorCode::QuotaExceeded);
                assert_eq!(p.attempts(), 1, "no second dial");
                assert!(!give_up_keeps_block(err.code, true));
                assert!(!marks_give_up(err.code));
            }
            other => panic!("expected the session to end, got {other:?}"),
        }
    }

    #[test]
    fn only_a_recovery_that_failed_is_marked_as_a_give_up() {
        for ended in [IpcErrorCode::QuotaExceeded, IpcErrorCode::Revoked] {
            assert!(!marks_give_up(ended), "{ended:?}");
        }
        for failed in [
            IpcErrorCode::ServerUnreachable,
            IpcErrorCode::ServerUnavailable,
            IpcErrorCode::StealthFailed,
            IpcErrorCode::DeviceLimit,
        ] {
            assert!(marks_give_up(failed), "{failed:?}");
        }
    }

    #[test]
    fn revocation_releases_the_block_even_in_lockdown() {
        assert!(!give_up_keeps_block(IpcErrorCode::Revoked, true));
        assert!(give_up_keeps_block(IpcErrorCode::ServerUnreachable, true));
        assert!(!give_up_keeps_block(IpcErrorCode::ServerUnreachable, false));
        assert_eq!(revoked_error(None).code, IpcErrorCode::Revoked);
        assert_eq!(
            revoked_error(Some("Signed in on another device")).message,
            "Signed in on another device"
        );
        assert_eq!(
            revoked_error(Some("  ")).message,
            "Connection has been revoked. Please reconnect."
        );
    }

    #[test]
    fn backoff_is_exponential_and_capped() {
        let b = budget();
        let secs: Vec<u64> = (0..8).map(|n| backoff_delay(n, &b).as_secs()).collect();
        assert_eq!(secs, vec![1, 2, 4, 8, 16, 32, 60, 60]);
        assert_eq!(backoff_delay(10_000, &b), b.max_delay);
    }
}
