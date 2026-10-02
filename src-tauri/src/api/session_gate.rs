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
//! Android's and iOS's `RefreshOutcome`: only a DEFINITIVE answer from the
//! refresh endpoint — 401, or 403 — ends the session. A network error, a 5xx,
//! a 429, an unreadable body or a pin failure may succeed on the next attempt,
//! and discarding a live refresh token over one of those costs the user their
//! account session (see `commands::auth::get_auth_state`), and an anonymous
//! user who never saved the 24-digit number the account itself.

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
    /// Kept, so a later launch can still recover: a 403 from the refresh is
    /// not always the token's fault — an infrastructure block answers 403 to
    /// everyone (the Caddy client-ip outage put every user in one rate-limit
    /// bucket), and wiping on it would sign the whole user base out for good
    /// (Android's rule). Also every expiry the UI reports rather than the
    /// refresh (`commands::session::end_expired_session`).
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

/// Whether a failed refresh is the server's definitive refusal (401 or 403).
pub(crate) fn refresh_rejected(error: &ApiError) -> bool {
    matches!(
        error,
        ApiError::Unauthorized
            | ApiError::Forbidden
            | ApiError::Rejected {
                status: 401 | 403,
                ..
            }
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
pub(crate) fn error_after_failed_refresh(refresh_error: ApiError) -> ApiError {
    if refresh_rejected(&refresh_error) {
        ApiError::Unauthorized
    } else {
        refresh_error
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

    /// 403: the session ends, but the stored tokens are kept (Android).
    #[test]
    fn a_403_from_the_refresh_ends_the_session_and_keeps_the_tokens() {
        for body in ["", r#"{"statusCode":403,"message":"Forbidden"}"#] {
            let result = refresh_answered(403, body);
            assert_eq!(refresh_outcome(&result), RefreshOutcome::Unauthorized);
            let e = result.unwrap_err();
            assert_eq!(stored_session_after(&e), StoredSession::Keep);
            assert_eq!(
                IpcError::from_api(&error_after_failed_refresh(e)).code,
                IpcErrorCode::SessionExpired
            );
        }
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
