//! API error types

use super::upgrade_gate::RequiredUpdate;
use std::fmt;

#[derive(Debug)]
pub enum ApiError {
    /// Network error (no connection, timeout, etc.)
    Network(String),
    /// Not authenticated (no token)
    NotAuthenticated,
    /// Authentication failed (401)
    Unauthorized,
    /// Access denied (403)
    Forbidden,
    /// Resource not found (404)
    NotFound,
    /// Rate limited (429) — EVERY 429, whatever its body says (MR-1808): the
    /// UI words it by its code, and the wait must travel with it.
    /// `retry_after_secs` is the response's `Retry-After`, clamped by
    /// [`retry_after_header`]; `None` when it sent none.
    RateLimited { retry_after_secs: Option<u64> },
    /// 426: this build is below the backend's forced version floor. Carries the
    /// version to move to so the UI can name it. Distinct from every other
    /// variant because it is TERMINAL for this process — retrying cannot help.
    UpgradeRequired(RequiredUpdate),
    /// Server error (5xx)
    ServerError(u16),
    /// A 5xx that said when to come back (`Retry-After`, MR-1808): the server
    /// is busy or in maintenance, so the SAME request is worth sending again
    /// after the wait — not "try another location". The wait is clamped by
    /// [`retry_after_header`].
    ServerBusy { status: u16, retry_after_secs: u64 },
    /// NOT SENT: the API client's retry gate answered a request the server had
    /// asked to hold — a 429 (`status` 429) or a busy 5xx — with the wait
    /// that is left (MR-1808). It reads to the user exactly as the server's
    /// own answer did; it is its own variant because nothing crossed the
    /// network, so it says nothing about the network or the tunnel.
    Held { status: u16, retry_after_secs: u64 },
    /// Failed to parse response
    Parse(String),
    /// SEC-C1: TLS certificate pinning verification failed (possible MITM)
    CertificatePinningFailed(String),
    /// Any other non-2xx answer that carried the backend's own sentence. The
    /// status travels with it so `commands::ipc_error` can pick an error code
    /// by status instead of by wording, and the sentence stays the specific,
    /// actionable one ("Stealth mode requires an Operative or Sovereign
    /// subscription") rather than a generic "Access denied".
    Rejected { status: u16, message: String },
    /// The action needs the account's two-factor code (`error:
    /// "two_factor_required"`, Account API contract item 85). Carries the
    /// backend's sentence.
    TwoFactorRequired(String),
    /// The two-factor code sent was wrong (`error: "two_factor_invalid"`).
    TwoFactorInvalid(String),
    /// 503 `error: "quota_check_unavailable"` (birdo-web #590): the server
    /// could not check a Free plan's allowance just now. Worth retrying, after
    /// `retry_after_secs` when the server says.
    QuotaCheckUnavailable { retry_after_secs: Option<u64> },
    /// 503 `error: "psk_delivery_unavailable"` (birdo-web
    /// `VpnController.rethrowPskDeliveryRefusal`, MR-1639): the backend could
    /// only have added the peer over its SSH fallback, which never carries a
    /// pre-shared key, so it rolled the peer back instead of installing it
    /// without one. A temporary, server-side condition (the backend running
    /// without its node agent, for every relay at once), not this device's or
    /// this relay's. Nothing was downgraded, and the SAME request is worth
    /// retrying, after `retry_after_secs` when the server says.
    PskDeliveryUnavailable { retry_after_secs: Option<u64> },
    /// 403 `error: "client_attestation_required"` (contract `$defs/ErrorCode`,
    /// MR-1944): the server's attestation policy refused this build. Its own
    /// variant so it is not read as a plan refusal (a bare 403 is
    /// `subscription_required`). Carries the backend's sentence.
    ClientAttestationRequired(String),
    /// Unknown error
    Unknown(String),
}

/// The longest wait a `details.retryAfterSeconds` may impose (MR-1639). The
/// server sends 30. A larger value (a server bug) is cut to this, so one
/// answer can never park a connect or a re-dial for longer than the reconnect
/// backoff's own cap (`AutoReconnectConfig::max_delay_ms`).
pub const RETRY_AFTER_MAX_SECS: u64 = 60;

/// `details.retryAfterSeconds` of a retryable refusal, in whole seconds,
/// clamped to `1..=RETRY_AFTER_MAX_SECS`. `None` when it is absent or not a
/// non-negative number: the refusal stays retryable, just without a wait.
/// A 0 reads as 1 so a retry can never spin.
pub fn retry_after_secs(details: Option<&serde_json::Value>) -> Option<u64> {
    let value = details?.get("retryAfterSeconds")?;
    let secs = match value.as_u64() {
        Some(secs) => secs,
        // The contract says integer; a `30.0` is read, rounded up.
        None => {
            let secs = value.as_f64().filter(|s| s.is_finite() && *s >= 0.0)?;
            secs.ceil().min(RETRY_AFTER_MAX_SECS as f64) as u64
        }
    };
    Some(secs.clamp(1, RETRY_AFTER_MAX_SECS))
}

/// A `Retry-After` response header (MR-1808, RFC 9110 §10.2.3), as whole
/// seconds from `now`: delta-seconds, or an HTTP-date (IMF-fixdate, and the
/// obsolete RFC 850 and asctime forms a recipient must still accept).
///
/// Clamped to `1..=RETRY_AFTER_MAX_SECS`, exactly like `retryAfterSeconds`
/// above and for the same reasons: a `0` or a date already past reads as 1 so
/// a retry can never spin, and no single answer holds a request (a connect, a
/// re-dial behind the kill switch) back for longer than the reconnect
/// backoff's own cap. A server that still wants quiet after that answers the
/// next request with a fresh `Retry-After`, so the client still sends at most
/// one request per minute to it. `None` for anything else: the error stays
/// what its status says, just without a wait.
pub fn retry_after_header(value: &str, now: std::time::SystemTime) -> Option<u64> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let secs = if value.bytes().all(|b| b.is_ascii_digit()) {
        // All digits but past u64: still "a long time", not garbage.
        value.parse::<u64>().unwrap_or(u64::MAX)
    } else {
        let at = http_date(value)?;
        let millis = at
            .signed_duration_since(chrono::DateTime::<chrono::Utc>::from(now))
            .num_milliseconds();
        // Rounded up: a date 1.2 s away is a 2 s wait, never a 1 s one.
        u64::try_from(millis).map_or(0, |ms| ms.div_ceil(1000))
    };
    Some(secs.clamp(1, RETRY_AFTER_MAX_SECS))
}

/// An HTTP-date in any of its three forms, in UTC.
fn http_date(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::{NaiveDateTime, TimeZone, Utc};
    // IMF-fixdate ("Sun, 06 Nov 1994 08:49:37 GMT") is RFC 2822's date shape.
    if let Ok(at) = chrono::DateTime::parse_from_rfc2822(value) {
        return Some(at.with_timezone(&Utc));
    }
    // RFC 850 ("Sunday, 06-Nov-94 08:49:37 GMT") and asctime
    // ("Sun Nov  6 08:49:37 1994").
    ["%A, %d-%b-%y %H:%M:%S GMT", "%a %b %e %H:%M:%S %Y"]
        .iter()
        .find_map(|format| NaiveDateTime::parse_from_str(value, format).ok())
        .map(|naive| Utc.from_utc_datetime(&naive))
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::Network(msg) => write!(f, "Network error: {}", msg),
            ApiError::NotAuthenticated => write!(f, "Not authenticated"),
            ApiError::Unauthorized => write!(f, "Authentication failed"),
            ApiError::Forbidden => write!(f, "Access denied"),
            ApiError::NotFound => write!(f, "Not found"),
            ApiError::RateLimited { .. } => write!(f, "Too many requests, please slow down"),
            ApiError::UpgradeRequired(info) => match (&info.message, &info.required_version) {
                (Some(msg), _) if !msg.trim().is_empty() => write!(f, "{}", msg),
                (_, Some(version)) => write!(
                    f,
                    "Update required: BirdoVPN {} or later is needed to continue",
                    version
                ),
                _ => write!(
                    f,
                    "Update required: this version of BirdoVPN is no longer supported"
                ),
            },
            ApiError::ServerError(code) => write!(f, "Server error ({})", code),
            ApiError::ServerBusy {
                status,
                retry_after_secs,
            } => write!(
                f,
                "The service is busy (HTTP {}); try again in {} s",
                status, retry_after_secs
            ),
            ApiError::Held {
                status,
                retry_after_secs,
            } => write!(
                f,
                "Not sent: the server asked to wait (HTTP {}); try again in {} s",
                status, retry_after_secs
            ),
            ApiError::Parse(msg) => write!(f, "Failed to parse response: {}", msg),
            ApiError::CertificatePinningFailed(msg) => write!(f, "Security verification failed. This may mean the app needs updating or your connection is being intercepted. Please update BirdoVPN to the latest version. ({})", msg),
            ApiError::Rejected { message, .. }
            | ApiError::TwoFactorRequired(message)
            | ApiError::TwoFactorInvalid(message)
            | ApiError::ClientAttestationRequired(message) => write!(f, "{}", message),
            ApiError::QuotaCheckUnavailable { .. } => {
                write!(f, "The data allowance check is unavailable right now")
            }
            ApiError::PskDeliveryUnavailable { .. } => {
                write!(
                    f,
                    "A secure connection to this server could not be set up right now"
                )
            }
            ApiError::Unknown(msg) => write!(f, "Unknown error: {}", msg),
        }
    }
}

impl std::error::Error for ApiError {}

// Allow conversion to String for Tauri commands
impl From<ApiError> for String {
    fn from(err: ApiError) -> Self {
        err.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    /// A fixed "now": Sun, 06 Nov 1994 08:49:37 GMT, RFC 9110's own example.
    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(784_111_777)
    }

    /// MR-1808: delta-seconds, clamped to 1..=RETRY_AFTER_MAX_SECS — a 0
    /// never makes a retry spin, and no answer holds a request for longer
    /// than the reconnect backoff's cap. All digits but huge is still long.
    #[test]
    fn delta_seconds_are_read_and_clamped() {
        assert_eq!(retry_after_header("30", now()), Some(30));
        assert_eq!(retry_after_header(" 30 ", now()), Some(30));
        assert_eq!(retry_after_header("0", now()), Some(1));
        assert_eq!(retry_after_header("60", now()), Some(60));
        assert_eq!(
            retry_after_header("1800", now()),
            Some(RETRY_AFTER_MAX_SECS)
        );
        assert_eq!(
            retry_after_header("99999999999999999999999", now()),
            Some(RETRY_AFTER_MAX_SECS)
        );
        assert_eq!(RETRY_AFTER_MAX_SECS, 60);
    }

    /// All three HTTP-date forms, counted from `now` and rounded up; a date
    /// already past reads as 1.
    #[test]
    fn http_dates_are_read_in_all_three_forms() {
        for form in [
            "Sun, 06 Nov 1994 08:50:22 GMT",  // IMF-fixdate
            "Sunday, 06-Nov-94 08:50:22 GMT", // RFC 850
            "Sun Nov  6 08:50:22 1994",       // asctime
        ] {
            assert_eq!(retry_after_header(form, now()), Some(45), "{form}");
        }
        let later = now() + Duration::from_millis(200);
        assert_eq!(
            retry_after_header("Sun, 06 Nov 1994 08:50:22 GMT", later),
            Some(45),
            "44.8 s is a 45 s wait"
        );
        assert_eq!(
            retry_after_header("Sun, 06 Nov 1994 09:49:37 GMT", now()),
            Some(RETRY_AFTER_MAX_SECS)
        );
        assert_eq!(
            retry_after_header("Sun, 06 Nov 1994 08:00:00 GMT", now()),
            Some(1),
            "past"
        );
    }

    /// Anything else is no wait at all, never a guess.
    #[test]
    fn anything_else_is_no_wait() {
        for junk in [
            "",
            "  ",
            "-5",
            "1.5",
            "soon",
            "30s",
            "Sun, 32 Nov 1994 08:50:22 GMT",
        ] {
            assert_eq!(retry_after_header(junk, now()), None, "{junk:?}");
        }
    }
}
