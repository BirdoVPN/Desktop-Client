//! MR-2500 / MR-1771: what the client does with each answer to
//! `POST /auth/refresh`. One rule, the one birdo-web's contract states
//! (backend/contract/README.md, "Token refresh") and all three clients keep:
//!
//! - **401**: this refresh token is dead. The session ENDS: signed out, the
//!   tokens cleared from memory and the keystore (`session_gate`). It is the
//!   ONLY answer that ends a session.
//! - **429**: rate limited, and the server has NOT spent the token. The
//!   session, the token and its keystore entry are kept, and the user is never
//!   shown "signed out". The refresh is held for `Retry-After`, else the
//!   body's `details.retryAfter` (birdo-web #912), else 60 s.
//! - **403, 5xx, a timeout, no answer, any other status**: kept likewise, and
//!   the token is never discarded. A 503 can be the server putting back a
//!   token whose rotation failed after it was consumed (MR-2500; MR-2466
//!   design), so the token is good. A 403 is never a verdict on the token:
//!   the backend's refresh route has no 403 of its own; one comes from in
//!   front of it. The refresh is held for a capped exponential backoff with
//!   jitter, never shorter than the server's own `Retry-After`.
//! - **426, a TLS pin failure, an unreadable 2xx**: kept likewise, and held
//!   for the same backoff as a 5xx (the one timing table, lead 2026-11-19
//!   21:39Z: Desktop's numbers, Mobile #653's hold). Unlike the answers
//!   above, the call that met one is told it as it is ([`told`]): the
//!   version floor (the upgrade gate's own screen), the pin failure ("could
//!   not verify it is talking to its own servers"), the unreadable answer.
//!   The calls after it inside the hold get the hold (`ApiError::Held` 503)
//!   and send nothing. (MR-2537: a real pin failure reaches this rule as
//!   `CertificatePinningFailed` since `client::send_failed`; it used to
//!   arrive as `Network` and was told as no network.)
//!
//! The one timing table (both clients):
//! - backoff: [`BACKOFF_BASE`] 1 s doubling to [`BACKOFF_CAP`] 30 s, equal
//!   jitter ([`backoff`]);
//! - a server-named wait (`Retry-After`, else `details.retryAfter`): clamped
//!   to `1..=error::RETRY_AFTER_MAX_SECS` (60 s), a `0` read as 1 s; a value
//!   that is junk, negative, not a number or an HTTP-date names no wait
//!   (`error::retry_after_delta`, as the refresh reads its header), so a 429
//!   then holds [`RATE_LIMIT_DEFAULT_WAIT`], 60 s.
//!
//! No wait inside a call (lead decision 2026-11-19, as Mobile #653). A flight
//! sends the token ONCE. When that fails, the hold and the backoff step are
//! recorded in the retry gate (`RetryGate::refresh_failed`), and the call
//! that asked fails at once with a transient error that keeps the session
//! ([`told`]): the hold itself (`ApiError::Held`, 429 for a rate limit, else
//! 503, with the wait), or the network failure when nothing answered. It is
//! never a 403, and never an answer that reads as "this server is
//! unavailable": an auth failure must never send anyone to another server
//! (`session_gate::error_after_failed_refresh`). The SAME token goes again
//! with the next request that needs it once the hold is over, or when the
//! window comes to the foreground (`BirdoApi::retry_held_refresh`). There is
//! no background timer: an app nobody uses sends nothing.
//!
//! One refresh is in flight at a time (single flight). Every refresh runs
//! under the client's refresh lock (`BirdoApi::refresh_detached`,
//! `refresh_token`), so concurrent callers wait for the one in flight. Each
//! then finds either the rotated pair (its request goes again with it) or,
//! after a flight that failed, the refresh held: it is answered at once
//! (`ApiError::Held`) and never sends the token again on its own.

use std::time::Duration;

use super::error::ApiError;

/// The first backoff step. Each step doubles it, up to [`BACKOFF_CAP`].
pub(crate) const BACKOFF_BASE: Duration = Duration::from_secs(1);

/// The longest backoff step, jitter included.
pub(crate) const BACKOFF_CAP: Duration = Duration::from_secs(30);

/// A 429 that named no readable wait, in the header or the body: the same
/// 60 s the retry gate holds the refresh for.
pub(crate) const RATE_LIMIT_DEFAULT_WAIT: Duration =
    Duration::from_secs(super::retry_gate::REFRESH_DEFAULT_HOLD_SECS);

/// What a refresh that did not renew the session asks for next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Next {
    /// A 401: the session is over (the session gate ends it).
    SignOut,
    /// Keep everything, and hold the refresh this long. The SAME token goes
    /// again with the first request that needs it after that (or the
    /// window's return to the foreground). Nobody waits for it.
    Hold(Duration),
    /// Keep everything and hold nothing: a refresh still held from an earlier
    /// answer (nothing was sent), or a session that ended under it (nobody
    /// is left to hold for).
    Keep,
}

/// What a failed refresh asks for, `step` failed flights in a row (this one
/// included). `unit` is the jitter, uniform in `[0, 1)` ([`unit_random`]).
pub(crate) fn after_failure(error: &ApiError, step: u32, unit: f64) -> Next {
    if super::session_gate::refresh_rejected(error) {
        return Next::SignOut;
    }
    match error {
        ApiError::Held { .. } | ApiError::NotAuthenticated => Next::Keep,
        ApiError::RateLimited { retry_after_secs } => {
            Next::Hold(rate_limit_wait(*retry_after_secs))
        }
        // A 5xx that named its wait: the backoff, but never sooner than that.
        ApiError::ServerBusy {
            retry_after_secs, ..
        } => Next::Hold(backoff(step, unit).max(Duration::from_secs(*retry_after_secs))),
        // A 403, any other 5xx, a timeout, no answer, any other status (Mobile
        // #653: "an unexpected status" backs off like a 5xx). And, by the one
        // timing table (lead 2026-11-19 21:39Z), the version floor (426), a
        // pin failure and an unreadable 2xx: the same token sent again at
        // once would only meet the same answer.
        _ => Next::Hold(backoff(step, unit)),
    }
}

/// The answers a refresh is held for that the call which met them is told as
/// they are, never as the hold (see [`told`]): the version floor (426), a TLS
/// pin failure and an unreadable 2xx. Each says something the user has to
/// see (update the app; the app could not verify its own servers, so get the
/// latest version or try another network; the answer was unreadable), and
/// none of them reads as a reason to change server.
pub(crate) fn told_as_it_is(error: &ApiError) -> bool {
    matches!(
        error,
        ApiError::UpgradeRequired(_) | ApiError::CertificatePinningFailed(_) | ApiError::Parse(_)
    )
}

/// The status a held refresh answers with (`ApiError::Held`), as Mobile #653's
/// does: 429 while a rate limit's wait runs, 503 during a backoff. Never the
/// 403 the refresh may have met.
pub(crate) fn held_status(error: &ApiError) -> u16 {
    if matches!(error, ApiError::RateLimited { .. }) {
        429
    } else {
        503
    }
}

/// What the call whose refresh just failed is told, given `held`, the retry
/// gate's answer for the refresh right after the failure was recorded: the
/// hold (`Held`, a transient error with the wait), the same answer every
/// caller after it gets until the hold is over. No answer at all stays the
/// network failure ("check your connection"), which names no server either;
/// the version floor, a pin failure and an unreadable 2xx stay themselves
/// ([`told_as_it_is`]). The calls after it get the hold all the same.
pub(crate) fn told(error: ApiError, held: Result<(), ApiError>) -> ApiError {
    match (error, held) {
        (error @ ApiError::Network(_), _) => error,
        (error, _) if told_as_it_is(&error) => error,
        (_, Err(held)) => held,
        (error, Ok(())) => error,
    }
}

/// A 429's wait: the one it named (the header, else `details.retryAfter`;
/// `BirdoApi::classify_error_response_after` reads both), else 60 s.
pub(crate) fn rate_limit_wait(retry_after_secs: Option<u64>) -> Duration {
    retry_after_secs.map_or(RATE_LIMIT_DEFAULT_WAIT, Duration::from_secs)
}

/// The `step`th backoff (1-based): [`BACKOFF_BASE`] doubled each step, capped
/// at [`BACKOFF_CAP`], with "equal jitter": half the step plus up to half
/// again by `unit` (in `[0, 1)`). Clients that failed together do not come
/// back together, and none comes back sooner than half the step.
pub(crate) fn backoff(step: u32, unit: f64) -> Duration {
    let doubled = BACKOFF_BASE.saturating_mul(1u32 << step.saturating_sub(1).min(16));
    let step = doubled.min(BACKOFF_CAP);
    let unit = if unit.is_finite() {
        unit.clamp(0.0, 1.0)
    } else {
        0.0
    };
    step / 2 + step.mul_f64(unit) / 2
}

/// The jitter in production: uniform in `[0, 1)`.
pub(crate) fn unit_random() -> f64 {
    rand::random::<f64>()
}

// The cases below are labelled, never formatted: CodeQL reads an assert's
// message as a log, and a test `ApiError` in one is flagged as cleartext.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::BirdoApi;
    use reqwest::StatusCode;

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    /// The refresh endpoint's answer, through the client's real mapping.
    fn answered(status: u16, body: &str, header: Option<u64>) -> ApiError {
        BirdoApi::classify_error_response_after(StatusCode::from_u16(status).unwrap(), body, header)
    }

    /// birdo-web #912's refresh 429, word for word in shape: the controller's
    /// envelope with `details: {code: "rate_limited", retryAfter}`.
    const LIMITED_17: &str = r#"{"statusCode":429,"message":"Too many token refresh attempts. Try again later.","error":"TOO_MANY_REQUESTS","details":{"code":"rate_limited","retryAfter":17}}"#;
    /// The Express-level /auth limiter's shape of the same.
    const LIMITED_EXPRESS_9: &str = r#"{"error":"Too many auth requests, slow down","details":{"code":"rate_limited","retryAfter":9}}"#;

    #[test]
    fn only_a_401_signs_out() {
        let signs_out = [
            ("bare variant", ApiError::Unauthorized),
            ("401, no body", answered(401, "", None)),
            (
                "401, the server's sentence",
                answered(
                    401,
                    r#"{"statusCode":401,"message":"Invalid refresh token"}"#,
                    None,
                ),
            ),
        ];
        for (case, error) in &signs_out {
            assert_eq!(after_failure(error, 1, 0.5), Next::SignOut, "{case}");
        }
        let kept = [
            ("403, no body", answered(403, "", None)),
            (
                "403, the server's sentence",
                answered(403, r#"{"statusCode":403,"message":"Forbidden"}"#, None),
            ),
            ("429", answered(429, LIMITED_17, None)),
            ("503", answered(503, "", None)),
            ("timeout", ApiError::Network("operation timed out".into())),
        ];
        for (case, error) in &kept {
            assert_ne!(after_failure(error, 1, 0.5), Next::SignOut, "{case}");
        }
    }

    /// MR-1771: a 429 holds the header's `Retry-After`, else the body's
    /// `details.retryAfter`, else 60 s; the header wins over the body.
    #[test]
    fn a_429_holds_the_header_then_the_body_then_60_s() {
        for (body, header, wait) in [
            (LIMITED_17, Some(42), 42),
            (LIMITED_17, None, 17),
            (LIMITED_EXPRESS_9, None, 9),
            (r#"{"statusCode":429,"message":"Slow down"}"#, None, 60),
            ("Too Many Requests", None, 60),
            ("", None, 60),
            (
                r#"{"details":{"code":"rate_limited","retryAfter":0}}"#,
                None,
                1,
            ),
            (
                r#"{"details":{"code":"rate_limited","retryAfter":900}}"#,
                None,
                60,
            ),
        ] {
            let error = answered(429, body, header);
            assert_eq!(
                after_failure(&error, 1, 0.5),
                Next::Hold(secs(wait)),
                "{body} {header:?}"
            );
            // Not jittered, and the same whatever the step.
            assert_eq!(after_failure(&error, 4, 0.0), Next::Hold(secs(wait)));
            assert_eq!(held_status(&error), 429);
        }
        assert_eq!(RATE_LIMIT_DEFAULT_WAIT, secs(60));
    }

    /// MR-2500, and the lead's decision on a 403 (2026-11-19): a 403, a 5xx,
    /// a timeout, no answer or any other status backs off exponentially with
    /// jitter, capped, and is held as a 503; a 5xx that named its wait is
    /// never asked again sooner.
    #[test]
    fn everything_else_backs_off_exponentially_with_jitter_and_a_cap() {
        let failures = [
            ("403", answered(403, "", None)),
            (
                "403, blocked",
                answered(
                    403,
                    r#"{"statusCode":403,"message":"Your IP address has been blocked"}"#,
                    None,
                ),
            ),
            ("500", answered(500, "", None)),
            ("502", answered(502, "", None)),
            ("503", answered(503, "", None)),
            (
                "503, deploying",
                answered(503, r#"{"statusCode":503,"message":"Deploying"}"#, None),
            ),
            ("504", answered(504, "", None)),
            ("404", answered(404, "", None)),
            ("400", answered(400, r#"{"message":"Bad request"}"#, None)),
            ("timeout", ApiError::Network("operation timed out".into())),
            ("reset", ApiError::Network("connection reset".into())),
        ];
        for (case, error) in &failures {
            for step in 1..=8 {
                assert_eq!(
                    after_failure(error, step, 0.25),
                    Next::Hold(backoff(step, 0.25)),
                    "{case} at step {step}"
                );
            }
            assert_eq!(held_status(error), 503, "{case}");
        }
        // Doubling from 1 s, half of each step at least, capped at 30 s.
        let low: Vec<Duration> = (1..=7).map(|step| backoff(step, 0.0)).collect();
        let high: Vec<Duration> = (1..=7).map(|step| backoff(step, 0.999_999)).collect();
        assert_eq!(
            low,
            [500, 1_000, 2_000, 4_000, 8_000, 15_000, 15_000].map(Duration::from_millis)
        );
        for (step, jittered) in high.iter().enumerate() {
            assert!(
                *jittered > low[step] && *jittered <= BACKOFF_CAP,
                "{step}: {jittered:?}"
            );
        }
        assert!(backoff(40, 0.999_999) <= BACKOFF_CAP);
        assert_eq!(backoff(3, f64::NAN), backoff(3, 0.0));
        assert_eq!(backoff(3, 7.0), backoff(3, 1.0));

        // The server's own wait is a floor.
        let busy = answered(
            503,
            r#"{"statusCode":503,"message":"Session store unavailable"}"#,
            Some(10),
        );
        assert!(matches!(
            busy,
            ApiError::ServerBusy {
                retry_after_secs: 10,
                ..
            }
        ));
        assert_eq!(after_failure(&busy, 1, 0.5), Next::Hold(secs(10)));
        assert_eq!(after_failure(&busy, 6, 0.0), Next::Hold(secs(15)));
        assert_eq!(held_status(&busy), 503);
    }

    /// Nothing is held where nothing was learned: a refresh still held sent
    /// nothing, and a session that ended has nobody to hold for.
    #[test]
    fn nothing_is_held_where_nothing_was_learned() {
        let kept = [
            (
                "held 429",
                ApiError::Held {
                    status: 429,
                    retry_after_secs: 30,
                },
            ),
            (
                "held 503",
                ApiError::Held {
                    status: 503,
                    retry_after_secs: 4,
                },
            ),
            ("session ended", ApiError::NotAuthenticated),
        ];
        for (case, error) in &kept {
            assert_eq!(after_failure(error, 1, 0.5), Next::Keep, "{case}");
        }
    }

    /// The one timing table (lead 2026-11-19 21:39Z: Desktop's numbers,
    /// Mobile #653's hold): the version floor (426), a TLS pin failure and an
    /// unreadable 2xx are held for the same capped, jittered backoff as a
    /// 5xx, held as 503, and never sign out. The call that met one is told it
    /// as it is, not the hold. Before, each was `Keep`: nothing held, and the
    /// next 401 sent the same token straight back into the same answer.
    #[test]
    fn a_426_a_pin_failure_and_an_unreadable_2xx_hold_like_a_5xx() {
        let held = || -> Result<(), ApiError> {
            Err(ApiError::Held {
                status: 503,
                retry_after_secs: 1,
            })
        };
        let cases = [
            ("426", answered(426, "", None)),
            (
                "426, the server's body",
                answered(
                    426,
                    r#"{"statusCode":426,"error":"update_required","message":"Please update the app.","details":{"minVersion":"9.9.9"}}"#,
                    None,
                ),
            ),
            ("pin", ApiError::CertificatePinningFailed("x".into())),
            ("unreadable 2xx", ApiError::Parse("eof".into())),
        ];
        for (case, error) in cases {
            for step in 1..=8 {
                assert_eq!(
                    after_failure(&error, step, 0.25),
                    Next::Hold(backoff(step, 0.25)),
                    "{case} at step {step}"
                );
            }
            assert!(
                matches!(
                    after_failure(&error, 40, 0.999_999),
                    Next::Hold(wait) if wait <= BACKOFF_CAP
                ),
                "{case}: past the cap"
            );
            assert_eq!(held_status(&error), 503, "{case}");
            assert!(told_as_it_is(&error), "{case}");
            let is_426 = matches!(error, ApiError::UpgradeRequired(_));
            let is_pin = matches!(error, ApiError::CertificatePinningFailed(_));
            let is_parse = matches!(error, ApiError::Parse(_));
            let answer = told(error, held());
            assert!(
                (is_426 && matches!(answer, ApiError::UpgradeRequired(_)))
                    || (is_pin && matches!(answer, ApiError::CertificatePinningFailed(_)))
                    || (is_parse && matches!(answer, ApiError::Parse(_))),
                "{case}: told the hold"
            );
        }
        // Everything else the backoff holds is told the hold.
        for (case, error) in [
            ("403", answered(403, "", None)),
            ("503", answered(503, "", None)),
            ("404", answered(404, "", None)),
        ] {
            assert!(!told_as_it_is(&error), "{case}");
        }
    }

    /// The lead's decisions (2026-11-19): the call whose refresh failed is
    /// told the hold, a transient answer with its wait, never the 403 or the
    /// 5xx it met; no answer at all stays the network failure.
    #[test]
    fn the_caller_is_told_the_hold_or_the_network_failure() {
        let held = || -> Result<(), ApiError> {
            Err(ApiError::Held {
                status: 503,
                retry_after_secs: 1,
            })
        };
        for (case, error) in [
            ("403", answered(403, "", None)),
            ("503", answered(503, "", None)),
            ("500", answered(500, "", None)),
        ] {
            assert!(
                matches!(
                    told(error, held()),
                    ApiError::Held {
                        status: 503,
                        retry_after_secs: 1
                    }
                ),
                "{case}"
            );
        }
        assert!(matches!(
            told(
                answered(429, LIMITED_17, None),
                Err(ApiError::Held {
                    status: 429,
                    retry_after_secs: 17
                })
            ),
            ApiError::Held {
                status: 429,
                retry_after_secs: 17
            }
        ));
        assert!(matches!(
            told(ApiError::Network("operation timed out".into()), held()),
            ApiError::Network(_)
        ));
    }
}
