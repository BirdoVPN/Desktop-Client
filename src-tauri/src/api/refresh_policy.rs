//! MR-2500 / MR-1771: what the client does with each answer to
//! `POST /auth/refresh`. One rule, the one birdo-web's contract states
//! (backend/contract/README.md, "Token refresh") and all three clients keep:
//!
//! - **401**: this refresh token is dead. The session ENDS: signed out, the
//!   tokens cleared from memory and the keystore (`session_gate`). It is the
//!   ONLY answer that ends a session.
//! - **429**: rate limited, and the server has NOT spent the token. The
//!   session, the token and its keystore entry are kept, and the user is never
//!   shown "signed out". The flight waits `Retry-After`, else the body's
//!   `details.retryAfter` (birdo-web #912), else 60 s, and sends the SAME
//!   token again.
//! - **5xx, a timeout, no answer**: kept likewise, and the token is never
//!   discarded. A 503 can be the server putting back a token whose rotation
//!   failed after it was consumed (MR-2500; MR-2466 design), so the token is
//!   good. The flight waits a capped exponential backoff with jitter (never
//!   less than the server's own `Retry-After`) and sends the SAME token again.
//! - **403**: never a verdict on the token. The backend's refresh route has
//!   no 403 of its own; one comes from in front of it. Kept, and surfaced as
//!   the server failing to answer (`session_gate::error_after_failed_refresh`).
//!
//! One refresh is in flight at a time (single flight). Every refresh runs
//! under the client's refresh lock (`BirdoApi::refresh_detached`,
//! `refresh_token`), so concurrent callers wait for the one in flight. Each
//! then finds either the rotated pair (its request goes again with it) or,
//! after a flight that failed, the refresh held for the next backoff step
//! (`RetryGate::refresh_failed`). In the second case it is answered at once
//! (`ApiError::Held`) and never sends the token again on its own.

use std::future::Future;
use std::time::Duration;

use super::error::ApiError;

/// Sends of one token in one flight, the first included. Bounded so a caller
/// waiting on the refresh lock is not held for long: a flight lasts at most
/// two waits (one rate-limit wait of up to `RETRY_AFTER_MAX_SECS`, or two
/// backoff steps), and the gate's hold takes over after it.
pub(crate) const REFRESH_ATTEMPTS: u32 = 3;

/// The first backoff step. Each step doubles it, up to [`BACKOFF_CAP`].
pub(crate) const BACKOFF_BASE: Duration = Duration::from_secs(1);

/// The longest backoff step, jitter included.
pub(crate) const BACKOFF_CAP: Duration = Duration::from_secs(30);

/// A 429 that named no readable wait, in the header or the body: the same
/// 60 s the retry gate holds the refresh for.
pub(crate) const RATE_LIMIT_DEFAULT_WAIT: Duration =
    Duration::from_secs(super::retry_gate::REFRESH_DEFAULT_HOLD_SECS);

/// What a failed send of the refresh asks for next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Next {
    /// A 401: the session is over (the session gate ends it).
    SignOut,
    /// Keep everything and send the SAME token again after this wait.
    Retry(Duration),
    /// Keep everything and stop here: a 403, a refresh still held from an
    /// earlier answer (nothing was sent), an unreadable 2xx (the server may
    /// have spent the token, and sending it again cannot help), a pin
    /// failure, anything else.
    Keep,
}

/// What the `sent`th failed send of one flight asks for. `unit` is the
/// jitter, uniform in `[0, 1)` ([`unit_random`]).
pub(crate) fn after_failure(error: &ApiError, sent: u32, unit: f64) -> Next {
    if super::session_gate::refresh_rejected(error) {
        return Next::SignOut;
    }
    match error {
        ApiError::RateLimited { retry_after_secs } => {
            Next::Retry(rate_limit_wait(*retry_after_secs))
        }
        // A 5xx that named its wait: the backoff, but never sooner than that.
        ApiError::ServerBusy {
            retry_after_secs, ..
        } => Next::Retry(backoff(sent, unit).max(Duration::from_secs(*retry_after_secs))),
        error if server_failed_or_no_answer(error) => Next::Retry(backoff(sent, unit)),
        _ => Next::Keep,
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

/// A 5xx, a timeout, or no answer at all: the server or the path failed, not
/// the token.
pub(crate) fn server_failed_or_no_answer(error: &ApiError) -> bool {
    match error {
        ApiError::Network(_) | ApiError::ServerError(_) | ApiError::ServerBusy { .. } => true,
        ApiError::Rejected { status, .. } => (500..600).contains(status),
        // `classify_error_response_after`'s answer for a status it does not
        // name, a 504 among them.
        ApiError::Unknown(message) => message.starts_with("HTTP 5"),
        _ => false,
    }
}

/// Whether a flight that ended on `error` holds the refresh for the next
/// backoff step (`RetryGate::refresh_failed`): a 429, a 403, a 5xx, a
/// timeout or no answer. Not a 401 (the session is over), a refresh that was
/// held already (it sent nothing), a flight whose session ended under it, an
/// unreadable 2xx or a pin failure.
pub(crate) fn holds_after(error: &ApiError) -> bool {
    matches!(error, ApiError::RateLimited { .. })
        || super::session_gate::refresh_forbidden(error)
        || server_failed_or_no_answer(error)
}

/// One refresh flight. `send` presents the SAME refresh token each time it is
/// called. After a failure [`after_failure`] retries, `wait` waits and answers
/// whether the session still presents that token. A sign-out, or another
/// account's sign-in, during the wait ends the flight with nothing more sent
/// (`NotAuthenticated`, as an adoption that finds the session gone does). The
/// flight ends on the first success, a 401, a failure that is not retried, or
/// after [`REFRESH_ATTEMPTS`] sends, with that send's answer.
pub(crate) async fn fly<T, S, SF, W, WF>(
    mut send: S,
    mut wait: W,
    unit: impl Fn() -> f64,
) -> Result<T, ApiError>
where
    S: FnMut() -> SF,
    SF: Future<Output = Result<T, ApiError>>,
    W: FnMut(Duration) -> WF,
    WF: Future<Output = bool>,
{
    let mut sent = 0;
    loop {
        sent += 1;
        let error = match send().await {
            Ok(done) => return Ok(done),
            Err(error) => error,
        };
        match after_failure(&error, sent, unit()) {
            Next::Retry(pause) if sent < REFRESH_ATTEMPTS => {
                if !wait(pause).await {
                    return Err(ApiError::NotAuthenticated);
                }
            }
            _ => return Err(error),
        }
    }
}

/// The jitter in production: uniform in `[0, 1)`.
pub(crate) fn unit_random() -> f64 {
    rand::random::<f64>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::BirdoApi;
    use reqwest::StatusCode;
    use std::cell::RefCell;

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
        for error in [
            ApiError::Unauthorized,
            answered(401, "", None),
            answered(
                401,
                r#"{"statusCode":401,"message":"Invalid refresh token"}"#,
                None,
            ),
        ] {
            assert_eq!(after_failure(&error, 1, 0.5), Next::SignOut, "{error:?}");
        }
        for error in [
            answered(403, "", None),
            answered(403, r#"{"statusCode":403,"message":"Forbidden"}"#, None),
        ] {
            assert_eq!(after_failure(&error, 1, 0.5), Next::Keep, "{error:?}");
        }
    }

    /// MR-1771: a 429 waits the header's `Retry-After`, else the body's
    /// `details.retryAfter`, else 60 s; the header wins over the body.
    #[test]
    fn a_429_waits_the_header_then_the_body_then_60_s() {
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
                Next::Retry(secs(wait)),
                "{body} {header:?}"
            );
            // Not jittered, and the same on every send of the flight.
            assert_eq!(after_failure(&error, 2, 0.0), Next::Retry(secs(wait)));
        }
        assert_eq!(RATE_LIMIT_DEFAULT_WAIT, secs(60));
    }

    /// MR-2500: a 5xx, a timeout or no answer backs off exponentially with
    /// jitter, capped; a 5xx that named its wait never comes back sooner.
    #[test]
    fn server_failures_back_off_exponentially_with_jitter_and_a_cap() {
        let failures = [
            answered(500, "", None),
            answered(502, "", None),
            answered(503, "", None),
            answered(503, r#"{"statusCode":503,"message":"Deploying"}"#, None),
            answered(504, "", None),
            ApiError::Network("operation timed out".into()),
            ApiError::Network("connection reset".into()),
        ];
        for error in &failures {
            assert!(server_failed_or_no_answer(error), "{error:?}");
            for step in 1..=8 {
                assert_eq!(
                    after_failure(error, step, 0.25),
                    Next::Retry(backoff(step, 0.25)),
                    "{error:?}"
                );
            }
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
        assert_eq!(after_failure(&busy, 1, 0.5), Next::Retry(secs(10)));
        assert_eq!(after_failure(&busy, 6, 0.0), Next::Retry(secs(15)));
    }

    /// Nothing else is sent again inside the flight: a refresh still held
    /// sent nothing, an unreadable 2xx may have spent the token, a pin
    /// failure will not pass on the next try, and a 4xx is the answer.
    #[test]
    fn everything_else_is_kept_and_not_sent_again() {
        for error in [
            ApiError::Held {
                status: 429,
                retry_after_secs: 30,
            },
            ApiError::Held {
                status: 503,
                retry_after_secs: 4,
            },
            ApiError::Parse("eof".into()),
            ApiError::CertificatePinningFailed("x".into()),
            ApiError::NotAuthenticated,
            answered(400, "", None),
            answered(404, "", None),
            answered(403, "", None),
            ApiError::Unknown("the token refresh did not finish: cancelled".into()),
        ] {
            assert_eq!(after_failure(&error, 1, 0.5), Next::Keep, "{error:?}");
            assert!(!server_failed_or_no_answer(&error), "{error:?}");
        }
    }

    /// One scripted flight: the answers to give, in order, and what the
    /// flight did. Every send records the token it presented.
    struct Script {
        answers: RefCell<Vec<Result<&'static str, ApiError>>>,
        presented: RefCell<Vec<&'static str>>,
        waits: RefCell<Vec<Duration>>,
    }

    impl Script {
        fn new(mut answers: Vec<Result<&'static str, ApiError>>) -> Self {
            answers.reverse();
            Self {
                answers: RefCell::new(answers),
                presented: RefCell::default(),
                waits: RefCell::default(),
            }
        }

        /// Fly with `token`, the session still presenting it after
        /// `still_ours` waits (then signed out).
        async fn fly(
            &self,
            token: &'static str,
            still_ours: usize,
        ) -> Result<&'static str, ApiError> {
            fly(
                || {
                    self.presented.borrow_mut().push(token);
                    let answer = self.answers.borrow_mut().pop().expect("a send too many");
                    async move { answer }
                },
                |pause| {
                    self.waits.borrow_mut().push(pause);
                    let ours = self.waits.borrow().len() <= still_ours;
                    async move { ours }
                },
                || 0.5,
            )
            .await
        }

        fn sent(&self) -> usize {
            self.presented.borrow().len()
        }
    }

    /// MR-1771: a 429 keeps everything and waits, then the SAME token goes
    /// again, and the session is renewed. On main the flight ended at the
    /// 429; the next 401 sent the refresh again only after the gate's 30 s.
    #[tokio::test]
    async fn a_429_keeps_the_token_waits_and_sends_the_same_token_again() {
        let script = Script::new(vec![
            Err(answered(429, LIMITED_17, None)),
            Ok("rotated pair"),
        ]);
        assert_eq!(script.fly("r1", usize::MAX).await.unwrap(), "rotated pair");
        assert_eq!(*script.presented.borrow(), ["r1", "r1"]);
        assert_eq!(*script.waits.borrow(), [secs(17)]);
    }

    /// MR-2500: a 503 (a rotation that failed after the token was consumed,
    /// and was put back) keeps the token and backs off; the same token
    /// renews the session. No token is lost on the way.
    #[tokio::test]
    async fn a_503_keeps_the_token_and_backs_off_until_it_renews() {
        let script = Script::new(vec![
            Err(answered(503, "", None)),
            Err(ApiError::Network("operation timed out".into())),
            Ok("rotated pair"),
        ]);
        assert_eq!(script.fly("r1", usize::MAX).await.unwrap(), "rotated pair");
        assert_eq!(*script.presented.borrow(), ["r1", "r1", "r1"]);
        assert_eq!(*script.waits.borrow(), [backoff(1, 0.5), backoff(2, 0.5)]);
        assert!(script.waits.borrow()[0] < script.waits.borrow()[1]);
    }

    /// A 401 ends the flight at once: nothing more is sent, and the answer
    /// is the one that signs out.
    #[tokio::test]
    async fn a_401_ends_the_flight_at_once() {
        let script = Script::new(vec![Err(answered(401, "", None))]);
        let ended = script.fly("r1", usize::MAX).await.unwrap_err();
        assert!(super::super::session_gate::refresh_rejected(&ended));
        assert_eq!(script.sent(), 1);
        assert!(script.waits.borrow().is_empty());
    }

    /// A 403 keeps the session and is not sent again inside the flight.
    #[tokio::test]
    async fn a_403_keeps_the_session_and_is_not_sent_again() {
        let script = Script::new(vec![Err(answered(403, "", None))]);
        let kept = script.fly("r1", usize::MAX).await.unwrap_err();
        assert!(!super::super::session_gate::refresh_rejected(&kept));
        assert_eq!(script.sent(), 1);
    }

    /// The flight is bounded: after `REFRESH_ATTEMPTS` sends it ends on the
    /// last answer, still a transient one that keeps the session.
    #[tokio::test]
    async fn a_flight_gives_up_after_its_attempts_and_keeps_the_session() {
        let script = Script::new(vec![
            Err(answered(503, "", None)),
            Err(answered(502, "", None)),
            Err(answered(500, "", None)),
        ]);
        let last = script.fly("r1", usize::MAX).await.unwrap_err();
        assert!(matches!(last, ApiError::ServerError(500)), "{last:?}");
        assert!(!super::super::session_gate::refresh_rejected(&last));
        assert!(holds_after(&last));
        assert_eq!(script.sent(), REFRESH_ATTEMPTS as usize);
        assert_eq!(script.waits.borrow().len(), REFRESH_ATTEMPTS as usize - 1);
    }

    /// A sign-out (or another account's sign-in) during the wait ends the
    /// flight: the old token is not sent again.
    #[tokio::test]
    async fn a_session_that_ended_during_the_wait_is_not_refreshed() {
        let script = Script::new(vec![Err(answered(429, LIMITED_17, None))]);
        let ended = script.fly("r1", 0).await.unwrap_err();
        assert!(matches!(ended, ApiError::NotAuthenticated), "{ended:?}");
        assert_eq!(script.sent(), 1);
        assert!(!holds_after(&ended));
    }

    /// A refresh the gate still holds sent nothing: the flight ends at once,
    /// with no wait (the callers waiting on the lock share that answer).
    #[tokio::test]
    async fn a_held_refresh_ends_the_flight_without_a_wait() {
        let script = Script::new(vec![Err(ApiError::Held {
            status: 503,
            retry_after_secs: 4,
        })]);
        assert!(matches!(
            script.fly("r1", usize::MAX).await,
            Err(ApiError::Held { .. })
        ));
        assert!(script.waits.borrow().is_empty());
    }
}
