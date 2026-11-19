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
//! client then does (waits, sends the same token again) is
//! `api::refresh_policy`.
//!
//! A 403 used to end the session too (keeping the keystore copy). It is never
//! a verdict on the token: the backend's refresh route has no 403 of its own;
//! one comes from in front of it (the IP blocklist, the CORS check, the edge
//! proxy), and an infrastructure block answers it to everyone (the Caddy
//! client-ip outage put every user in one rate-limit bucket). So it keeps the
//! session now, and the caller is told the server could not answer.

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
/// MR-1771: a 403 from the refresh keeps the session and is surfaced as the
/// server failing to answer (`server_error`, "please try again"), not as
/// itself: a bare 403 reads as `subscription_required` ("Your plan does not
/// include this"), wrong for a block in front of the backend.
pub(crate) fn error_after_failed_refresh(refresh_error: ApiError) -> ApiError {
    if refresh_rejected(&refresh_error) {
        ApiError::Unauthorized
    } else if refresh_forbidden(&refresh_error) {
        ApiError::ServerError(403)
    } else {
        refresh_error
    }
}

/// A 403 from the refresh, with or without the server's sentence.
pub(crate) fn refresh_forbidden(error: &ApiError) -> bool {
    matches!(
        error,
        ApiError::Forbidden | ApiError::Rejected { status: 403, .. }
    )
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

    /// MR-1771: a 403 from the refresh keeps the session (it never reaches
    /// the session-expiry handler) and the caller is told the server could
    /// not answer: never `session_expired`, never the plan copy a bare 403
    /// gets. On main it ended the session (keystore kept) and the UI dropped
    /// to Login.
    #[test]
    fn a_403_from_the_refresh_keeps_the_session_and_says_the_server_failed() {
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
            assert!(refresh_forbidden(&e), "{body}");
            let told = IpcError::from_api(&error_after_failed_refresh(e));
            assert_eq!(told.code, IpcErrorCode::ServerError, "{body}");
            assert_ne!(told.code, IpcErrorCode::SessionExpired);
            assert_ne!(told.code, IpcErrorCode::SubscriptionRequired);
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
    #[test]
    fn a_transient_refresh_failure_keeps_the_session() {
        let cases: Vec<(Result<(), ApiError>, IpcErrorCode)> = vec![
            (
                Err(ApiError::Network("connection reset".into())),
                IpcErrorCode::NetworkOffline,
            ),
            (refresh_answered(502, ""), IpcErrorCode::ServerError),
            (refresh_answered(500, ""), IpcErrorCode::ServerError),
            (
                refresh_answered(503, r#"{"message":"Deploying"}"#),
                IpcErrorCode::ServerUnavailable,
            ),
            (refresh_answered(429, ""), IpcErrorCode::RateLimited),
            (
                refresh_answered(429, r#"{"message":"Slow down"}"#),
                IpcErrorCode::RateLimited,
            ),
            (
                Err(ApiError::Parse("eof".into())),
                IpcErrorCode::ServerError,
            ),
            (
                Err(ApiError::CertificatePinningFailed("x".into())),
                IpcErrorCode::CertPinFailed,
            ),
        ];
        for (result, code) in cases {
            assert_eq!(
                refresh_outcome(&result),
                RefreshOutcome::Transient,
                "{result:?}"
            );
            let e = result.unwrap_err();
            assert!(!refresh_rejected(&e), "{e:?}");
            let answered = IpcError::from_api(&error_after_failed_refresh(e));
            assert_eq!(answered.code, code);
            assert_ne!(answered.code, IpcErrorCode::SessionExpired);
        }
    }

    /// No refresh token at all is not the server's answer: nothing to end.
    #[test]
    fn no_refresh_token_is_not_a_rejection() {
        assert!(!refresh_rejected(&ApiError::NotAuthenticated));
    }
}
