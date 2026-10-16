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
//!
//! MR-2012: what "a request" is follows the backend's buckets ([`hold_key`]).
//! The credential routes (every `/auth...` path but `/auth/me` and
//! `/auth/refresh`, and any `/login` or `/register`) share ONE bucket per
//! network address on the server (birdo-web `GlobalRateLimitMiddleware`
//! category `auth`, 10 per 60 s, and the auth limiters in main.ts), so a 429
//! on one of them holds them all. The shared hold is conservative, not exact:
//! the login route also has a limiter of its own, keyed on the network AND
//! the identity signing in (birdo-web `bootstrap-rate-limiter.ts`), so a 429
//! from it for one identity also holds register, 2FA verify and the SSO
//! exchange here, for at most `RETRY_AFTER_MAX_SECS`. That errs on the safe
//! side: no request goes out sooner than the server asked; at worst another
//! credential route waits when it did not have to.
//!
//! Every other route stays held on its own, on purpose. The `vpn` category
//! (120 per 60 s per account) shares a bucket too, but its
//! routes also carry limits of their own that say nothing about each other:
//! the speed test's (vpn/speed-test.ts) and the connect limiter's
//! (vpn.service.ts) answer 429 with `Retry-After` as well, so a category hold
//! there would hold the heartbeat hostage to a throttled speed test. Holding
//! per route costs one more refused request per route when the shared bucket
//! itself is spent, nothing more.
//!
//! Holds are the session's: sign-out (`BirdoApi::clear_tokens`) forgets them
//! ([`RetryGate::forget_session`]), all but the credential bucket, which the
//! server keys on the network rather than on the account and so still holds
//! for whoever signs in next from here.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use super::error::ApiError;

/// The hold key of the credential routes' shared bucket (MR-2012).
const CREDENTIAL_BUCKET: &str = "auth credential routes";

/// What a request is held under (MR-2012): the credential routes' shared
/// bucket ([`CREDENTIAL_BUCKET`]) for every path the backend counts in its
/// `auth` category, and `"{method} {path}"` for every other request.
pub(crate) fn hold_key(method: &reqwest::Method, path: &str) -> String {
    if is_credential_route(path) {
        CREDENTIAL_BUCKET.to_owned()
    } else {
        format!("{method} {path}")
    }
}

/// birdo-web `GlobalRateLimitMiddleware.getEndpointCategory` = `auth`: a path
/// under `/auth`, or one with `/login` or `/register` in it, except `/auth/me`
/// and `/auth/refresh`, which it buckets as `default` (they take no
/// credential, and the refresh has a limiter keyed on its own token). Read
/// the way the backend reads it: lower-cased, without a query.
fn is_credential_route(path: &str) -> bool {
    let path = path.split(['?', '#']).next().unwrap_or_default();
    let path = path.trim_end_matches('/').to_ascii_lowercase();
    if path == "/auth/me" || path == "/auth/refresh" {
        return false;
    }
    path.starts_with("/auth") || path.contains("/login") || path.contains("/register")
}

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

    /// The session ended (sign-out, an expired or deleted account): forget
    /// every hold but the credential routes' (MR-2012). The others were the
    /// signed-out account's: the server keys them on the account (or, for
    /// the refresh, on its token), so the next account to sign in here owes
    /// them nothing. The credential bucket is the network's.
    pub(crate) fn forget_session(&self) {
        self.held.lock().retain(|key, _| key == CREDENTIAL_BUCKET);
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

    /// MR-2012: the credential routes share the backend's `auth` bucket, so
    /// a 429 on one holds them all; `/auth/me`, the refresh and every other
    /// route keep holds of their own. On main the key was method and path for
    /// every request, so after a refused sign-in the 2FA code, the account
    /// creation and the SSO exchange all went out to meet the same 429.
    #[test]
    fn the_credential_routes_share_one_hold() {
        use reqwest::Method;
        let credential = [
            (Method::POST, "/auth/login/desktop"),
            (Method::POST, "/auth/login/anonymous"),
            (Method::POST, "/auth/register/anonymous"),
            (Method::POST, "/auth/native/exchange"),
            (Method::POST, "/auth/2fa/verify"),
            (Method::POST, "/auth/logout"),
            (Method::POST, "/AUTH/Login/Desktop?x=1"),
        ];
        let key = |method: &Method, path: &str| hold_key(method, path);
        let login = key(&Method::POST, "/auth/login/desktop");
        for (method, path) in &credential {
            assert_eq!(key(method, path), login, "{method} {path}");
        }
        let own: Vec<String> = [
            (Method::GET, "/auth/me"),
            (Method::POST, "/auth/refresh"),
            (Method::GET, "/vpn/servers"),
            (Method::POST, "/vpn/heartbeat/k1"),
            (Method::GET, "/api/v1/gdpr/export"),
        ]
        .iter()
        .map(|(method, path)| key(method, path))
        .collect();
        for k in &own {
            assert_ne!(*k, login);
        }

        let gate = RetryGate::default();
        let t0 = Instant::now();
        gate.note(
            &login,
            &ApiError::RateLimited {
                retry_after_secs: Some(40),
            },
            t0,
        );
        for (method, path) in &credential {
            assert!(
                matches!(
                    gate.check(&key(method, path), t0 + s(1)),
                    Err(ApiError::Held {
                        status: 429,
                        retry_after_secs: 39
                    })
                ),
                "{method} {path}"
            );
        }
        for k in &own {
            assert!(gate.check(k, t0).is_ok(), "{k}");
        }
    }

    /// MR-2012: a sign-out forgets the session's holds, so the next account
    /// signed in here is not held for the last one's; the credential bucket,
    /// keyed on the network, stays.
    #[test]
    fn a_sign_out_forgets_the_sessions_holds() {
        use reqwest::Method;
        let gate = RetryGate::default();
        let t0 = Instant::now();
        let limited = ApiError::RateLimited {
            retry_after_secs: Some(60),
        };
        let keys = [
            hold_key(&Method::POST, "/auth/login/desktop"),
            hold_key(&Method::GET, "/auth/me"),
            hold_key(&Method::POST, "/auth/refresh"),
            hold_key(&Method::GET, "/vpn/servers"),
        ];
        for key in &keys {
            gate.note(key, &limited, t0);
        }
        gate.forget_session();
        assert!(
            gate.check(&keys[0], t0).is_err(),
            "the network's bucket stays"
        );
        for key in &keys[1..] {
            assert!(gate.check(key, t0).is_ok(), "{key}");
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
