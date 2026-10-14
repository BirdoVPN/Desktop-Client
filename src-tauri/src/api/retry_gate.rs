//! MR-1808: the client never re-sends a request the server told it to hold
//! sooner than it said.
//!
//! A 429 or a busy 5xx that carries `Retry-After` (parsed and clamped by
//! `error::retry_after_header`) holds THAT request — method and path — for
//! the wait. Until it is over, the request is answered here with
//! `ApiError::Held` — the status the server sent and the wait that is left —
//! and nothing goes out. That covers
//! every caller at once: the token refresh every 401 runs (the backend sends
//! `Retry-After: 60` on its refresh limiter), the 30 s heartbeat, the UI's
//! polls and a user's repeated clicks.
//!
//! Per request, not per client: a rate limit on one route says nothing about
//! the others, and a gate on everything would hold a sign-out or a heartbeat
//! hostage to a throttled speed test. The dial paths honour the same wait on
//! their own (`IpcError::retry_wait`), so a re-dial is scheduled after it
//! instead of spending an attempt on a request this gate would refuse.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use super::error::ApiError;

/// Requests held at once. Holds last at most `RETRY_AFTER_MAX_SECS`, so in
/// practice a handful; past this the hold nearest its end is forgotten first
/// (the request then goes out and the server answers for itself).
const MAX_HELD: usize = 32;

/// Per held request: the status the server answered (429 or a 5xx) and when
/// the wait is over.
#[derive(Default)]
pub(crate) struct RetryGate {
    held: Mutex<HashMap<String, (u16, Instant)>>,
}

impl RetryGate {
    /// `Err(Held)` while `key` is held: the server's status, with the wait
    /// that is left. Nothing may be sent then.
    pub(crate) fn check(&self, key: &str, now: Instant) -> Result<(), ApiError> {
        let mut held = self.held.lock();
        let Some(&(status, until)) = held.get(key) else {
            return Ok(());
        };
        if now >= until {
            held.remove(key);
            return Ok(());
        }
        Err(ApiError::Held {
            status,
            retry_after_secs: whole_secs_left(until - now),
        })
    }

    /// Hold `key` when `error` named a wait; anything else changes nothing.
    pub(crate) fn note(&self, key: &str, error: &ApiError, now: Instant) {
        let (status, secs) = match error {
            ApiError::RateLimited {
                retry_after_secs: Some(secs),
            } => (429, *secs),
            ApiError::ServerBusy {
                status,
                retry_after_secs,
            } => (*status, *retry_after_secs),
            _ => return,
        };
        let until = now + Duration::from_secs(secs);
        let mut held = self.held.lock();
        held.retain(|_, (_, t)| *t > now);
        if held.len() >= MAX_HELD && !held.contains_key(key) {
            let soonest = held
                .iter()
                .min_by_key(|(_, (_, t))| *t)
                .map(|(k, _)| k.clone());
            if let Some(soonest) = soonest {
                held.remove(&soonest);
            }
        }
        held.insert(key.to_owned(), (status, until));
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.held.lock().len()
    }
}

/// Rounded up and never 0: 0.2 s left is a 1 s wait, so a caller that waits
/// what it was told never arrives early.
fn whole_secs_left(left: Duration) -> u64 {
    (left.as_secs() + u64::from(left.subsec_nanos() > 0)).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(secs: u64) -> Duration {
        Duration::from_secs(secs)
    }

    /// A 429 with `Retry-After` holds that request for the wait, answered
    /// locally (`Held`, never a real-looking 429) with the wait that is
    /// left; then it goes out again.
    #[test]
    fn a_429_holds_its_request_for_the_wait() {
        let gate = RetryGate::default();
        let t0 = Instant::now();
        let key = "POST /auth/refresh";
        assert!(gate.check(key, t0).is_ok());
        gate.note(
            key,
            &ApiError::RateLimited {
                retry_after_secs: Some(60),
            },
            t0,
        );
        for (at, left) in [(0, 60), (1, 59), (59, 1)] {
            assert!(
                matches!(
                    gate.check(key, t0 + s(at)),
                    Err(ApiError::Held { status: 429, retry_after_secs: l }) if l == left
                ),
                "at {at}s"
            );
        }
        // A fraction of a second left still reads as a whole second.
        assert!(matches!(
            gate.check(key, t0 + Duration::from_millis(59_800)),
            Err(ApiError::Held {
                status: 429,
                retry_after_secs: 1
            })
        ));
        assert!(gate.check(key, t0 + s(60)).is_ok(), "the wait is over");
        assert_eq!(gate.len(), 0, "an expired hold is forgotten");
    }

    /// A busy 5xx holds with its own status, so the answer stays a busy
    /// server (`server_error` with the wait), never a rate limit.
    #[test]
    fn a_busy_5xx_holds_with_its_status() {
        let gate = RetryGate::default();
        let t0 = Instant::now();
        gate.note(
            "GET /vpn/servers",
            &ApiError::ServerBusy {
                status: 503,
                retry_after_secs: 30,
            },
            t0,
        );
        assert!(matches!(
            gate.check("GET /vpn/servers", t0 + s(10)),
            Err(ApiError::Held {
                status: 503,
                retry_after_secs: 20
            })
        ));
    }

    /// Only the request the server named is held, and only an error that
    /// named a wait holds anything.
    #[test]
    fn only_the_named_request_is_held_and_only_on_a_wait() {
        let gate = RetryGate::default();
        let t0 = Instant::now();
        gate.note(
            "POST /auth/refresh",
            &ApiError::RateLimited {
                retry_after_secs: Some(60),
            },
            t0,
        );
        assert!(gate.check("POST /vpn/heartbeat/k1", t0).is_ok());
        assert!(gate.check("GET /auth/refresh", t0).is_ok());
        for error in [
            ApiError::RateLimited {
                retry_after_secs: None,
            },
            ApiError::ServerError(503),
            ApiError::Unauthorized,
            ApiError::Network("reset".into()),
            ApiError::QuotaCheckUnavailable {
                retry_after_secs: Some(30),
            },
        ] {
            gate.note("GET /x", &error, t0);
            assert!(gate.check("GET /x", t0).is_ok(), "{error:?}");
        }
    }

    /// Bounded: past `MAX_HELD`, the hold nearest its end makes room.
    #[test]
    fn the_holds_are_bounded() {
        let gate = RetryGate::default();
        let t0 = Instant::now();
        let busy = |secs| ApiError::ServerBusy {
            status: 503,
            retry_after_secs: secs,
        };
        for i in 0..MAX_HELD as u64 {
            gate.note(&format!("GET /{i}"), &busy(10 + i), t0);
        }
        assert_eq!(gate.len(), MAX_HELD);
        gate.note("GET /new", &busy(60), t0);
        assert_eq!(gate.len(), MAX_HELD);
        assert!(gate.check("GET /0", t0).is_ok(), "the soonest hold went");
        assert!(gate.check("GET /new", t0).is_err());
        assert!(gate.check("GET /1", t0).is_err());
    }
}
