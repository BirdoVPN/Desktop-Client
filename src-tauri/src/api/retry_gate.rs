//! MR-1808: the client never re-sends a request the server told it to hold
//! sooner than it said.
//!
//! A 429 or a busy 5xx that carries `Retry-After` (parsed and clamped by
//! `error::retry_after_header`) holds THAT request — method and path — for
//! the wait. Until it is over, the request is answered here with
//! `ApiError::Held` — the status the server sent and the wait that is left —
//! and nothing goes out. That covers
//! every caller at once: the token refresh every 401 runs (the backend sends
//! `Retry-After: 60` on its refresh limiter, and a refresh 429 without a
//! readable one holds for `REFRESH_DEFAULT_HOLD_SECS`, MR-1771), the 30 s
//! heartbeat, the UI's polls and a user's repeated clicks.
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
//! for whoever signs in next from here. A sign-in (`BirdoApi::begin_session`)
//! starts the refresh over too ([`RetryGate::session_started`]): its hold,
//! backoff step and owed retry were the last token's.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
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

/// MR-1771: how long a 429 from `/auth/refresh` that named no readable wait
/// holds the refresh. Every other request answered that way holds nothing
/// (the status decides the error, the user decides when to try again), but
/// nobody clicks a refresh: every request that meets a 401 sends one, one
/// after another under the refresh lock, so without a hold a burst of 401s
/// is a burst of refreshes into the same limit, each refused, and the limit
/// never rests. birdo-web's own refresh limiters always name their wait
/// (contract README "Token refresh"), so this covers a 429 from in front of
/// them. MR-2500 / MR-1771 (the one refresh rule, 2026-11-19): 60 s, the
/// controller's own wait, when neither `Retry-After` nor the body's
/// `details.retryAfter` names one; within `RETRY_AFTER_MAX_SECS` like every
/// hold. A failed refresh flight holds the same (`refresh_policy`).
pub(crate) const REFRESH_DEFAULT_HOLD_SECS: u64 = 60;

/// The token refresh's hold key: method and path, like every route outside
/// the credential bucket.
fn is_refresh(key: &str) -> bool {
    key == hold_key(&reqwest::Method::POST, super::endpoints::auth::REFRESH)
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
    /// MR-2500: refresh flights in a row that ended with neither new tokens
    /// nor a 401: the step of the backoff the next failed one holds for
    /// ([`Self::refresh_failed`]).
    refresh_failures: AtomicU32,
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

    /// Hold `key` when `error` named a wait, or when it is a refresh 429
    /// that did not ([`REFRESH_DEFAULT_HOLD_SECS`]); anything else changes
    /// nothing.
    pub(crate) fn note(&self, key: &str, error: &ApiError, now: Instant) {
        let (status, secs) = match error {
            ApiError::RateLimited {
                retry_after_secs: Some(secs),
            } => (429, *secs),
            ApiError::RateLimited {
                retry_after_secs: None,
            } if is_refresh(key) => (429, REFRESH_DEFAULT_HOLD_SECS),
            ApiError::ServerBusy {
                status,
                retry_after_secs,
            } => (*status, *retry_after_secs),
            _ => return,
        };
        self.hold(key, status, now + Duration::from_secs(secs), now);
    }

    /// Hold `key` until `until`, answering `status`; bounded by [`MAX_HELD`].
    fn hold(&self, key: &str, status: u16, until: Instant, now: Instant) {
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

    /// MR-2500 / MR-1771: what a refresh flight (one send,
    /// `BirdoApi::fly_refresh`) that did not renew the session leaves behind.
    /// A 401 ends the session, and the backoff starts over. An answer
    /// `refresh_policy::after_failure` holds for (a 429, a 403, a 5xx, a
    /// timeout, no answer, any other status; a 426, a pin failure and an
    /// unreadable 2xx too) holds the refresh `key` for it:
    /// a 429 for its own wait, the rest for the next step of a capped
    /// exponential backoff with jitter, counted across flights. The hold
    /// answers 429 for a rate limit and 503 for the rest
    /// (`refresh_policy::held_status`), and is never shorter than one the
    /// server's own answer left ([`Self::note`]). A retry is then owed
    /// ([`Self::refresh_retry_due`]). The call that met it, and every caller
    /// after it until the hold is over, is answered at once (`Held`) instead
    /// of sending the same token again (single flight), and a long outage is
    /// asked less and less often. `true` when it holds; nothing changes for
    /// an answer that teaches nothing (`Next::Keep`: a refresh already held
    /// sent nothing, a session that ended has nobody to hold for, …).
    pub(crate) fn refresh_failed(
        &self,
        key: &str,
        error: &ApiError,
        now: Instant,
        unit: f64,
    ) -> bool {
        use super::refresh_policy::{after_failure, held_status, Next};
        let step = self
            .refresh_failures
            .load(Ordering::SeqCst)
            .saturating_add(1);
        let pause = match after_failure(error, step, unit) {
            Next::Hold(pause) => pause,
            Next::SignOut => {
                self.refresh_settled();
                return false;
            }
            Next::Keep => return false,
        };
        self.refresh_failures.store(step, Ordering::SeqCst);
        let longer = self.held.lock().get(key).map(|&(_, until)| until);
        let until = longer.map_or(now + pause, |longer| longer.max(now + pause));
        self.hold(key, held_status(error), until, now);
        true
    }

    /// MR-2500: a refresh flight renewed the session, or the server ended it
    /// (401): the refresh backoff starts over, and no retry is owed.
    pub(crate) fn refresh_settled(&self) {
        self.refresh_failures.store(0, Ordering::SeqCst);
    }

    /// MR-2500 / MR-1771 (lead decision 2026-11-19; Mobile #653's
    /// `retryIsDue`): whether the last refresh flight failed in a way that
    /// held it ([`Self::refresh_failed`]), nothing has renewed or ended the
    /// session since, and the hold on the refresh `key` is over. The
    /// window's return to the foreground asks this
    /// (`BirdoApi::retry_held_refresh`); nothing asks it on a timer.
    pub(crate) fn refresh_retry_due(&self, key: &str, now: Instant) -> bool {
        self.refresh_failures.load(Ordering::SeqCst) > 0 && self.check(key, now).is_ok()
    }

    /// Tests: every hold as if `by` had passed (a hold that would end before
    /// then is forgotten), without waiting for it.
    #[cfg(test)]
    pub(crate) fn elapse(&self, by: Duration) {
        self.held
            .lock()
            .retain(|_, (_, until)| match until.checked_sub(by) {
                Some(earlier) => {
                    *until = earlier;
                    true
                }
                None => false,
            });
    }

    /// The session ended (sign-out, an expired or deleted account): forget
    /// every hold but the credential routes' (MR-2012). The others were the
    /// signed-out account's: the server keys them on the account (or, for
    /// the refresh, on its token), so the next account to sign in here owes
    /// them nothing. The credential bucket is the network's.
    pub(crate) fn forget_session(&self) {
        self.held.lock().retain(|key, _| key == CREDENTIAL_BUCKET);
        self.refresh_settled();
    }

    /// MR-2500 / MR-1771 (L1 of the Mobile #653 review): a new session's pair
    /// was installed (a sign-in, or a restore into an empty session). The
    /// refresh owes nothing from before it: the hold on the refresh, the
    /// backoff step and the retry owed were the last refresh token's (the
    /// server keys its refresh limiter on the token), so they go, and the new
    /// session's first refresh is not held and its first failure is step 1.
    /// Every other hold stays: the same account, or the network, may still
    /// owe it (a sign-out has already forgotten the last account's).
    pub(crate) fn session_started(&self) {
        self.held.lock().retain(|key, _| !is_refresh(key));
        self.refresh_settled();
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

    /// MR-1771: a refresh 429 that names no readable wait (none, or one
    /// `retry_after_header` could not read) still holds the refresh, for
    /// `REFRESH_DEFAULT_HOLD_SECS`; one that names its wait holds for that.
    /// No other request is held without a wait. On main the refresh went
    /// straight out again on the next 401.
    #[test]
    fn a_refresh_429_without_a_wait_holds_the_refresh_for_the_default() {
        use reqwest::Method;
        let gate = RetryGate::default();
        let t0 = Instant::now();
        let refresh = hold_key(&Method::POST, super::super::endpoints::auth::REFRESH);
        let no_wait = ApiError::RateLimited {
            retry_after_secs: None,
        };
        gate.note(&refresh, &no_wait, t0);
        assert!(matches!(
            gate.check(&refresh, t0 + s(1)),
            Err(ApiError::Held {
                status: 429,
                retry_after_secs: 59
            })
        ));
        assert!(gate
            .check(&refresh, t0 + s(REFRESH_DEFAULT_HOLD_SECS))
            .is_ok());
        // MR-2500 / MR-1771: 60 s when neither the header nor the body names
        // a wait (it was 30).
        assert_eq!(REFRESH_DEFAULT_HOLD_SECS, 60);
        const _: () =
            assert!(REFRESH_DEFAULT_HOLD_SECS <= super::super::error::RETRY_AFTER_MAX_SECS);

        // The server's own wait wins.
        gate.note(
            &refresh,
            &ApiError::RateLimited {
                retry_after_secs: Some(45),
            },
            t0,
        );
        assert!(matches!(
            gate.check(&refresh, t0 + s(31)),
            Err(ApiError::Held {
                status: 429,
                retry_after_secs: 14
            })
        ));

        // Nothing else is held without a wait: not `/auth/me`, not another
        // method on the refresh path, not the credential bucket.
        for key in [
            hold_key(&Method::GET, "/auth/me"),
            hold_key(&Method::GET, "/auth/refresh"),
            hold_key(&Method::POST, "/auth/login/desktop"),
            hold_key(&Method::GET, "/vpn/servers"),
        ] {
            gate.note(&key, &no_wait, t0);
            assert!(gate.check(&key, t0).is_ok(), "{key}");
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

    /// The refresh's hold, as `Held`'s wait in whole seconds at `at`.
    fn held_for(gate: &RetryGate, key: &str, at: Instant) -> Option<(u16, u64)> {
        match gate.check(key, at) {
            Err(ApiError::Held {
                status,
                retry_after_secs,
            }) => Some((status, retry_after_secs)),
            _ => None,
        }
    }

    /// MR-2500 / MR-1771: a refresh flight that ended with neither new tokens
    /// nor a 401 holds the refresh for the next backoff step, growing flight
    /// after flight up to the cap, so the call that met it and every caller
    /// after it are answered at once instead of sending the same token
    /// again. The hold answers 503 whatever the refresh met (a 403 included,
    /// never as itself: the lead's decision of 2026-11-19). A flight that
    /// renewed (or ended) the session starts the backoff over; so does a
    /// sign-out. On main a 5xx or a network failure held nothing: every
    /// caller waiting on the refresh lock sent the token again.
    #[test]
    fn a_failed_refresh_flight_holds_the_refresh_for_a_growing_backoff() {
        use super::super::refresh_policy::{backoff, BACKOFF_CAP};
        let gate = RetryGate::default();
        let refresh = hold_key(
            &reqwest::Method::POST,
            super::super::endpoints::auth::REFRESH,
        );
        let t0 = Instant::now();
        let mut last = 0;
        for (flight, error) in [
            ApiError::ServerError(503),
            ApiError::Network("timed out".into()),
            ApiError::Rejected {
                status: 502,
                message: "Bad gateway".into(),
            },
            ApiError::Unknown("HTTP 504".into()),
            ApiError::Forbidden,
            ApiError::Rejected {
                status: 403,
                message: "Your IP address has been blocked".into(),
            },
            ApiError::ServerError(500),
            ApiError::ServerError(503),
        ]
        .into_iter()
        .enumerate()
        {
            let now = t0 + s(1000 * flight as u64);
            assert!(
                gate.refresh_failed(&refresh, &error, now, 0.5),
                "flight {flight}"
            );
            let step = backoff(flight as u32 + 1, 0.5);
            let secs = whole_secs_left(step);
            assert_eq!(
                held_for(&gate, &refresh, now),
                Some((503, secs)),
                "flight {flight}"
            );
            assert!(secs >= last, "the backoff shrank at flight {flight}");
            assert!(secs <= BACKOFF_CAP.as_secs(), "past the cap");
            last = secs;
        }
        assert_eq!(backoff(7, 0.5), backoff(30, 0.5), "capped");
        assert_eq!(last, whole_secs_left(backoff(30, 0.5)));

        // Renewed: the next failure is the first step again.
        gate.refresh_settled();
        let now = t0 + s(100_000);
        gate.refresh_failed(&refresh, &ApiError::ServerError(503), now, 0.0);
        assert_eq!(held_for(&gate, &refresh, now), Some((503, 1)));

        // A 401 ends the session: nothing held, and the backoff starts over.
        let later = now + s(1000);
        assert!(!gate.refresh_failed(&refresh, &ApiError::Unauthorized, later, 0.0));
        assert_eq!(held_for(&gate, &refresh, later), None);
        assert!(
            !gate.refresh_retry_due(&refresh, later),
            "a 401 owes nothing"
        );
        gate.refresh_failed(&refresh, &ApiError::ServerError(503), later, 0.0);
        assert_eq!(held_for(&gate, &refresh, later), Some((503, 1)));

        // A sign-out forgets the backoff with the hold.
        gate.refresh_failed(&refresh, &ApiError::ServerError(503), later, 0.0);
        gate.forget_session();
        assert_eq!(held_for(&gate, &refresh, later), None);
        gate.refresh_failed(&refresh, &ApiError::ServerError(503), later, 0.0);
        assert_eq!(held_for(&gate, &refresh, later), Some((503, 1)));
    }

    /// MR-2500 / MR-1771: the hold after a failed flight never cuts short
    /// the server's own wait (a 429's 60 s, a busy 5xx's `Retry-After`), a
    /// 429 stays a rate limit, and nothing is held for a 401 (the session is
    /// over), a flight that sent nothing (already held) or a session that
    /// ended mid-flight. The cases are labelled, never formatted (CodeQL
    /// reads an assert's message as a log).
    #[test]
    fn the_hold_after_a_failed_flight_keeps_the_servers_wait() {
        let refresh = hold_key(
            &reqwest::Method::POST,
            super::super::endpoints::auth::REFRESH,
        );
        let t0 = Instant::now();

        let gate = RetryGate::default();
        let limited = ApiError::RateLimited {
            retry_after_secs: Some(60),
        };
        gate.note(&refresh, &limited, t0);
        assert!(gate.refresh_failed(&refresh, &limited, t0, 0.0));
        assert_eq!(held_for(&gate, &refresh, t0), Some((429, 60)));

        // A 429 that named no wait: 60 s, as `note` holds it.
        let gate = RetryGate::default();
        let bare = ApiError::RateLimited {
            retry_after_secs: None,
        };
        gate.note(&refresh, &bare, t0);
        assert!(gate.refresh_failed(&refresh, &bare, t0, 0.5));
        assert_eq!(
            held_for(&gate, &refresh, t0),
            Some((429, REFRESH_DEFAULT_HOLD_SECS))
        );

        // A busy 5xx's own wait outlasts the first backoff step; it answers
        // as the 503 every backoff hold does.
        let gate = RetryGate::default();
        let busy = ApiError::ServerBusy {
            status: 502,
            retry_after_secs: 10,
        };
        gate.note(&refresh, &busy, t0);
        assert!(gate.refresh_failed(&refresh, &busy, t0, 0.0));
        assert_eq!(held_for(&gate, &refresh, t0), Some((503, 10)));

        let nothing = [
            ("401", ApiError::Unauthorized),
            (
                "401, the server's sentence",
                ApiError::Rejected {
                    status: 401,
                    message: "Invalid refresh token".into(),
                },
            ),
            (
                "already held",
                ApiError::Held {
                    status: 429,
                    retry_after_secs: 30,
                },
            ),
            ("session ended", ApiError::NotAuthenticated),
        ];
        for (case, error) in &nothing {
            let gate = RetryGate::default();
            assert!(!gate.refresh_failed(&refresh, error, t0, 0.5), "{case}");
            assert_eq!(held_for(&gate, &refresh, t0), None, "{case}");
            assert!(!gate.refresh_retry_due(&refresh, t0), "{case}");
        }
    }

    /// The one timing table (lead 2026-11-19 21:39Z, Mobile #653's hold):
    /// the version floor (426), a TLS pin failure and an unreadable 2xx hold
    /// the refresh for the same growing, capped backoff as a 5xx, held as
    /// 503, with a retry owed once the hold is over. Before, none of them
    /// held anything or owed a retry.
    #[test]
    fn a_426_a_pin_failure_and_an_unreadable_2xx_hold_the_refresh() {
        use super::super::refresh_policy::{backoff, BACKOFF_CAP};
        use super::super::upgrade_gate::RequiredUpdate;
        let refresh = hold_key(
            &reqwest::Method::POST,
            super::super::endpoints::auth::REFRESH,
        );
        let t0 = Instant::now();
        // By label: ApiError is not `Clone`.
        let error = |case: &str| match case {
            "426" => ApiError::UpgradeRequired(RequiredUpdate {
                required_version: None,
                download_url: None,
                message: None,
            }),
            "pin" => ApiError::CertificatePinningFailed("x".into()),
            _ => ApiError::Parse("eof".into()),
        };
        for case in ["426", "pin", "unreadable 2xx"] {
            let gate = RetryGate::default();
            let mut last = 0;
            for flight in 0..8u32 {
                let now = t0 + s(1000 * u64::from(flight));
                assert!(
                    gate.refresh_failed(&refresh, &error(case), now, 0.5),
                    "{case}: not held at flight {flight}"
                );
                let secs = whole_secs_left(backoff(flight + 1, 0.5));
                assert_eq!(
                    held_for(&gate, &refresh, now),
                    Some((503, secs)),
                    "{case}: flight {flight}"
                );
                assert!(
                    (last..=BACKOFF_CAP.as_secs()).contains(&secs),
                    "{case}: shrank or past the cap"
                );
                last = secs;
                assert!(!gate.refresh_retry_due(&refresh, now), "{case}: due early");
                assert!(
                    gate.refresh_retry_due(&refresh, now + s(secs)),
                    "{case}: not owed after the hold"
                );
            }
        }
    }

    /// L1 of the Mobile #653 review: a sign-in starts the refresh over. The
    /// last session's refresh hold, backoff step and owed retry go, so the
    /// new session's first refresh is not held and its first failure holds
    /// for step 1; every other hold stays (the same account, or the network,
    /// may still owe it). A sign-out forgets them too (`forget_session`).
    #[test]
    fn a_sign_in_starts_the_refresh_over() {
        use reqwest::Method;
        let refresh = hold_key(&Method::POST, super::super::endpoints::auth::REFRESH);
        let servers = hold_key(&Method::GET, "/vpn/servers");
        let login = hold_key(&Method::POST, "/auth/login/desktop");
        let t0 = Instant::now();
        let gate = RetryGate::default();
        let limited = ApiError::RateLimited {
            retry_after_secs: Some(60),
        };
        // Four failed flights in: a long hold, and a retry owed after it.
        for _ in 0..4 {
            gate.refresh_failed(&refresh, &ApiError::ServerError(503), t0, 0.0);
        }
        gate.note(&servers, &limited, t0);
        gate.note(&login, &limited, t0);
        assert!(held_for(&gate, &refresh, t0).is_some());
        assert_eq!(gate.refresh_failures.load(Ordering::SeqCst), 4, "owed");

        gate.session_started();
        assert_eq!(
            held_for(&gate, &refresh, t0),
            None,
            "the first refresh is held"
        );
        assert!(
            !gate.refresh_retry_due(&refresh, t0 + s(60)),
            "a retry is owed from the last session"
        );
        assert!(gate.check(&servers, t0).is_err(), "the account's hold went");
        assert!(gate.check(&login, t0).is_err(), "the network's hold went");
        gate.refresh_failed(&refresh, &ApiError::ServerError(503), t0, 0.0);
        assert_eq!(
            held_for(&gate, &refresh, t0),
            Some((503, 1)),
            "the backoff did not start over"
        );
    }

    /// MR-2500 / MR-1771 (no background timer): a retry is owed after a
    /// flight that held the refresh, and due only once that hold is over;
    /// a renewal, a 401 or a sign-out owes nothing.
    #[test]
    fn a_retry_is_owed_after_a_held_failure_and_due_once_the_hold_is_over() {
        let refresh = hold_key(
            &reqwest::Method::POST,
            super::super::endpoints::auth::REFRESH,
        );
        let t0 = Instant::now();
        let gate = RetryGate::default();
        assert!(!gate.refresh_retry_due(&refresh, t0), "nothing failed");

        gate.refresh_failed(&refresh, &ApiError::ServerError(503), t0, 0.0);
        assert!(!gate.refresh_retry_due(&refresh, t0), "the hold still runs");
        assert!(
            gate.refresh_retry_due(&refresh, t0 + s(1)),
            "the hold is over"
        );

        // `elapse` moves the hold on as the clock would.
        gate.refresh_failed(&refresh, &ApiError::ServerError(503), t0, 0.0);
        assert!(!gate.refresh_retry_due(&refresh, t0));
        gate.elapse(s(2));
        assert!(gate.refresh_retry_due(&refresh, t0));

        gate.refresh_settled();
        assert!(!gate.refresh_retry_due(&refresh, t0 + s(60)), "renewed");

        gate.refresh_failed(&refresh, &ApiError::ServerError(503), t0, 0.0);
        gate.forget_session();
        assert!(!gate.refresh_retry_due(&refresh, t0 + s(60)), "signed out");
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
