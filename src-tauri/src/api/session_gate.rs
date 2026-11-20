//! Contract §3.3: a refresh token the server REJECTS ends the sign-in session
//! everywhere at once.
//!
//! The rejection is detected deep in the API client — the 401 interceptor,
//! the explicit refresh, the GDPR delete's own retry — which has no app handle
//! and must not depend on the command layer. So the client only REPORTS it
//! here, and the handler registered at start-up (`commands::session::
//! handle_session_expired`) tears the VPN down, clears the tokens and emits
//! `session-expired`. Same shape as `upgrade_gate` for the 426 floor.
//!
//! What a refresh means is decided once, in [`refresh_outcome`], the twin of
//! Android's and iOS's `RefreshOutcome`: only a 401 from the refresh endpoint
//! ends the session (MR-2500 / MR-1771, the one refresh rule; birdo-web
//! contract README "Token refresh"). A 429, a 5xx, a timeout, no answer, a
//! 403, an unreadable body or a pin failure may succeed on the next attempt,
//! and discarding a live refresh token over one of those costs the user their
//! account session (see `commands::auth::get_auth_state`), and an anonymous
//! user who never saved the 24-digit number the account itself. What the
//! client then does (holds the refresh, sends the same token again later) is
//! `api::refresh_policy`.
//!
//! A 403 used to end the session too (keeping the keystore copy). It is never
//! a verdict on the token: the backend's refresh route has no 403 of its own;
//! one comes from in front of it (the IP blocklist, the CORS check, the edge
//! proxy), and an infrastructure block answers it to everyone (the Caddy
//! client-ip outage put every user in one rate-limit bucket). So it keeps the
//! session now, and the caller is told a transient, 503-like answer
//! ([`error_after_failed_refresh`]).

use std::sync::OnceLock;

use super::error::ApiError;

/// What one refresh attempt says about the sign-in session (Android/iOS
/// `RefreshOutcome {SUCCESS, UNAUTHORIZED, TRANSIENT}` parity).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefreshOutcome {
    Success,
    /// The server refused the refresh: the session is over.
    Unauthorized,
    /// It may work next time: the session and its tokens are kept.
    Transient,
}

/// What ending an expired session does with the tokens in the OS keystore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredSession {
    /// The server rejected the refresh token itself (401): it will never work
    /// again, so it is discarded.
    Discard,
    /// Kept, so a later launch can still recover: every expiry the UI reports
    /// rather than the refresh (`commands::session::end_expired_session`).
    /// (A refresh 403 used to end the session this way; since MR-1771 it ends
    /// nothing.)
    Keep,
}

type Handler = Box<dyn Fn(StoredSession) + Send + Sync>;

static HANDLER: OnceLock<Handler> = OnceLock::new();

/// Register the session-expiry handler. The first registration wins.
pub fn set_handler(handler: impl Fn(StoredSession) + Send + Sync + 'static) {
    let _ = HANDLER.set(Box::new(handler));
}

/// Classify a refresh attempt.
pub(crate) fn refresh_outcome<T>(result: &Result<T, ApiError>) -> RefreshOutcome {
    match result {
        Ok(_) => RefreshOutcome::Success,
        Err(e) if refresh_rejected(e) => RefreshOutcome::Unauthorized,
        Err(_) => RefreshOutcome::Transient,
    }
}

/// Whether a failed refresh is the server's definitive refusal: a 401, the
/// ONLY answer that ends a session (MR-2500 / MR-1771).
pub(crate) fn refresh_rejected(error: &ApiError) -> bool {
    matches!(
        error,
        ApiError::Unauthorized | ApiError::Rejected { status: 401, .. }
    )
}

/// What becomes of the stored tokens when `error` ends the session.
pub(crate) fn stored_session_after(error: &ApiError) -> StoredSession {
    if matches!(
        error,
        ApiError::Unauthorized | ApiError::Rejected { status: 401, .. }
    ) {
        StoredSession::Discard
    } else {
        StoredSession::Keep
    }
}

/// What a request whose 401 led to a FAILED refresh answers its caller
/// (REVIEW-WIN2-003). Every refresh failure used to collapse into
/// `Unauthorized`, which the UI reads as `session_expired` and ends the
/// session over — so a Wi-Fi blip or a deploy's 502 on the hourly refresh
/// signed the user out and wiped the tokens. A transient failure now answers
/// as itself (`network_offline`, `server_error`, `rate_limited`, …) and the
/// session survives it.
///
/// MR-2500 / MR-1771 (lead decision 2026-11-19, as Mobile #653): a refresh
/// that failed for any other reason is TRANSIENT, and never reads as a
/// server or a plan the user should change. Auto-Connect and server
/// selection must never move anyone because of auth. The refresh flight
/// already answers a 429, a 403, a 5xx or an unexpected status with its hold
/// (`ApiError::Held`, 429 or 503, with the wait; `refresh_policy::told`), no
/// answer at all with the network failure, and a 426, a pin failure or an
/// unreadable 2xx as itself (held all the same); those, and the other
/// transient answers, pass through as they are. Anything else that reaches
/// here (a 403, a 404, a 5xx as the server sent it) becomes a busy 503 with
/// the first backoff step's wait: `server_error`, "please try again". Not the
/// answer as the server sent it:
/// - a bare 403 reads as `subscription_required` ("Your plan does not include
///   this"), a hard refusal that stops auto-reconnect;
/// - a 404, a bare 503 (`ServerError(503)`) or one with a sentence reads as
///   `server_unavailable` ("This server isn't available right now. Try
///   another location.", whose action opens the server list).
pub(crate) fn error_after_failed_refresh(refresh_error: ApiError) -> ApiError {
    if refresh_rejected(&refresh_error) {
        return ApiError::Unauthorized;
    }
    match refresh_error {
        ApiError::Held { .. }
        | ApiError::RateLimited { .. }
        | ApiError::ServerBusy { .. }
        | ApiError::Network(_)
        | ApiError::NotAuthenticated
        | ApiError::Parse(_)
        | ApiError::CertificatePinningFailed(_)
        | ApiError::TlsIntercepted
        | ApiError::UpgradeRequired(_) => refresh_error,
        _ => ApiError::ServerBusy {
            status: 503,
            retry_after_secs: super::refresh_policy::BACKOFF_BASE.as_secs(),
        },
    }
}

/// Report a failed refresh. Does nothing unless the server refused it.
pub(crate) fn report_refresh_failure(error: &ApiError) {
    if refresh_rejected(error) {
        if let Some(handler) = HANDLER.get() {
            handler(stored_session_after(error));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::BirdoApi;
    use crate::commands::ipc_error::{IpcError, IpcErrorCode};
    use reqwest::StatusCode;

    /// The refresh endpoint's answer, through the client's real mapping.
    fn refresh_answered(status: u16, body: &str) -> Result<(), ApiError> {
        Err(BirdoApi::classify_error_response(
            StatusCode::from_u16(status).unwrap(),
            body,
        ))
    }

    #[test]
    fn a_refresh_that_worked_is_a_success() {
        assert_eq!(
            refresh_outcome(&Ok::<(), ApiError>(())),
            RefreshOutcome::Success
        );
    }

    /// 401: the refresh token is dead. The session ends and the stored
    /// tokens go with it; the request reports `session_expired`.
    #[test]
    fn a_401_from_the_refresh_ends_the_session_and_discards_the_tokens() {
        for body in [
            "",
            r#"{"statusCode":401,"message":"Invalid refresh token"}"#,
        ] {
            let result = refresh_answered(401, body);
            assert_eq!(refresh_outcome(&result), RefreshOutcome::Unauthorized);
            let e = result.unwrap_err();
            assert_eq!(stored_session_after(&e), StoredSession::Discard);
            assert_eq!(
                IpcError::from_api(&error_after_failed_refresh(e)).code,
                IpcErrorCode::SessionExpired
            );
        }
    }

    /// MR-1771, and the lead's decision of 2026-11-19: a 403 from the refresh
    /// keeps the session (it never reaches the session-expiry handler) and
    /// the caller is told a transient, 503-like answer: a busy server
    /// (`server_error`, retryable, with a wait). Never `session_expired`,
    /// never the plan copy a bare 403 gets, never "this server is
    /// unavailable". On main it ended the session (keystore kept) and the UI
    /// dropped to Login.
    #[test]
    fn a_403_from_the_refresh_keeps_the_session_and_reads_as_a_busy_server() {
        for body in [
            "",
            r#"{"statusCode":403,"message":"Forbidden"}"#,
            r#"{"statusCode":403,"message":"Your IP address has been blocked"}"#,
        ] {
            let result = refresh_answered(403, body);
            assert_eq!(
                refresh_outcome(&result),
                RefreshOutcome::Transient,
                "{body}"
            );
            let e = result.unwrap_err();
            assert!(!refresh_rejected(&e), "{body}");
            let after = error_after_failed_refresh(e);
            assert!(
                matches!(
                    after,
                    ApiError::ServerBusy {
                        status: 503,
                        retry_after_secs: 1
                    }
                ),
                "{body}"
            );
            let told = IpcError::from_api(&after);
            assert_eq!(told.code, IpcErrorCode::ServerError, "{body}");
            assert!(told.retryable, "{body}");
            assert_eq!(told.retry_after_secs, Some(1), "{body}");
        }
    }

    /// MR-2500 / MR-1771: of every answer the refresh can get, only a 401
    /// ends the session.
    #[test]
    fn only_a_401_ends_the_session() {
        for status in [400u16, 403, 404, 408, 409, 425, 429, 500, 502, 503, 504] {
            for body in ["", r#"{"statusCode":0,"message":"No"}"#] {
                let result = refresh_answered(status, body);
                assert_eq!(
                    refresh_outcome(&result),
                    RefreshOutcome::Transient,
                    "{status} {body}"
                );
            }
        }
        assert_eq!(
            refresh_outcome(&refresh_answered(401, "")),
            RefreshOutcome::Unauthorized
        );
    }

    /// REVIEW-WIN2-003: everything else is transient. The session is kept,
    /// and the request answers as what happened — never `session_expired`.
    /// MR-2500 / MR-1771: a refresh 503 reads as a busy server, no longer as
    /// `server_unavailable` ("Try another location"). The cases are labelled,
    /// never formatted (CodeQL reads an assert's message as a log).
    #[test]
    fn a_transient_refresh_failure_keeps_the_session() {
        let cases: Vec<(&str, Result<(), ApiError>, IpcErrorCode)> = vec![
            (
                "reset",
                Err(ApiError::Network("connection reset".into())),
                IpcErrorCode::NetworkOffline,
            ),
            ("502", refresh_answered(502, ""), IpcErrorCode::ServerError),
            ("500", refresh_answered(500, ""), IpcErrorCode::ServerError),
            (
                "503, deploying",
                refresh_answered(503, r#"{"message":"Deploying"}"#),
                IpcErrorCode::ServerError,
            ),
            ("429", refresh_answered(429, ""), IpcErrorCode::RateLimited),
            (
                "429, slow down",
                refresh_answered(429, r#"{"message":"Slow down"}"#),
                IpcErrorCode::RateLimited,
            ),
            (
                "unreadable 2xx",
                Err(ApiError::Parse("eof".into())),
                IpcErrorCode::ServerError,
            ),
            (
                "pin",
                Err(ApiError::CertificatePinningFailed("x".into())),
                IpcErrorCode::CertPinFailed,
            ),
            (
                "intercepted",
                Err(ApiError::TlsIntercepted),
                IpcErrorCode::TlsIntercepted,
            ),
        ];
        for (case, result, code) in cases {
            assert_eq!(
                refresh_outcome(&result),
                RefreshOutcome::Transient,
                "{case}"
            );
            let e = result.unwrap_err();
            assert!(!refresh_rejected(&e), "{case}");
            let answered = IpcError::from_api(&error_after_failed_refresh(e));
            assert_eq!(answered.code, code, "{case}");
            assert_ne!(answered.code, IpcErrorCode::SessionExpired);
        }
    }

    /// The lead's decision of 2026-11-19 (Mobile #653): a refresh failure
    /// never reads as a reason to change server, even as the server sent it
    /// (the flight's own answer, the hold, is driven in `client.rs`
    /// `a_refresh_failure_never_points_at_another_server`). Its code is
    /// never one whose UI action opens the server list
    /// (`server_unavailable`, `server_unreachable`: `src/lib/errors.ts`),
    /// never a hard refusal (auto-reconnect would give up instead of
    /// re-dialling the session's own server), never an ending the server
    /// decided, never `session_expired` and never the plan copy; and it is
    /// retryable. The one timing table (lead 2026-11-19 21:39Z) adds a 426,
    /// a pin failure and an unreadable 2xx, told as they are: the version
    /// floor is the one hard stop (`upgrade_required` asks for the update
    /// and stops auto-reconnect), and it moves nobody either.
    #[test]
    fn a_refresh_failure_never_reads_as_another_server_or_a_plan() {
        let failed = |status: u16, body: &str, header: Option<u64>| {
            BirdoApi::classify_error_response_after(
                StatusCode::from_u16(status).unwrap(),
                body,
                header,
            )
        };
        let cases = [
            ("403", failed(403, "", None)),
            (
                "403, blocked",
                failed(
                    403,
                    r#"{"statusCode":403,"message":"Your IP address has been blocked"}"#,
                    None,
                ),
            ),
            ("404", failed(404, "", None)),
            ("410, sentence", failed(410, r#"{"message":"Gone"}"#, None)),
            ("429", failed(429, "", None)),
            ("429, header", failed(429, "", Some(42))),
            (
                "429, body",
                failed(
                    429,
                    r#"{"details":{"code":"rate_limited","retryAfter":17}}"#,
                    None,
                ),
            ),
            ("500", failed(500, "", None)),
            ("502", failed(502, "", None)),
            ("503", failed(503, "", None)),
            (
                "503, sentence",
                failed(503, r#"{"message":"Service unavailable"}"#, None),
            ),
            ("503, busy", failed(503, "", Some(10))),
            ("504", failed(504, "", None)),
            ("timeout", ApiError::Network("operation timed out".into())),
            ("no answer", ApiError::Network("connection refused".into())),
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
            ("426", failed(426, "", None)),
            (
                "426, the server's body",
                failed(
                    426,
                    r#"{"statusCode":426,"error":"update_required","message":"Please update the app.","details":{"minVersion":"9.9.9"}}"#,
                    None,
                ),
            ),
            ("pin", ApiError::CertificatePinningFailed("x".into())),
            ("intercepted", ApiError::TlsIntercepted),
            ("unreadable 2xx", ApiError::Parse("eof".into())),
        ];
        for (case, error) in cases {
            let told = IpcError::from_api(&error_after_failed_refresh(error));
            assert!(
                !matches!(
                    told.code,
                    IpcErrorCode::ServerUnavailable
                        | IpcErrorCode::ServerUnreachable
                        | IpcErrorCode::SubscriptionRequired
                        | IpcErrorCode::SessionExpired
                ),
                "{case}"
            );
            let floor = case.starts_with("426");
            assert_eq!(told.code == IpcErrorCode::UpgradeRequired, floor, "{case}");
            assert_eq!(told.code.is_hard_refusal(), floor, "{case}");
            assert!(
                !crate::vpn::reconnect_policy::server_ended(told.code),
                "{case}"
            );
            assert_eq!(told.retryable, !floor, "{case}");
        }
    }

    /// No refresh token at all is not the server's answer: nothing to end.
    #[test]
    fn no_refresh_token_is_not_a_rejection() {
        assert!(!refresh_rejected(&ApiError::NotAuthenticated));
    }
}
