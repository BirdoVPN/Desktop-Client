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
    /// Rate limited (429)
    RateLimited,
    /// 426: this build is below the backend's forced version floor. Carries the
    /// version to move to so the UI can name it. Distinct from every other
    /// variant because it is TERMINAL for this process — retrying cannot help.
    UpgradeRequired(RequiredUpdate),
    /// Server error (5xx)
    ServerError(u16),
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
    /// `VpnController.rethrowPskDeliveryRefusal`, MR-1639): the relay could
    /// only have been reached over the SSH fallback, which never carries a
    /// pre-shared key, so the server rolled the peer back instead of
    /// installing it without one. Nothing was downgraded, and the SAME
    /// request is worth retrying, after `retry_after_secs` when the server
    /// says.
    PskDeliveryUnavailable { retry_after_secs: Option<u64> },
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

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::Network(msg) => write!(f, "Network error: {}", msg),
            ApiError::NotAuthenticated => write!(f, "Not authenticated"),
            ApiError::Unauthorized => write!(f, "Authentication failed"),
            ApiError::Forbidden => write!(f, "Access denied"),
            ApiError::NotFound => write!(f, "Not found"),
            ApiError::RateLimited => write!(f, "Too many requests, please slow down"),
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
            ApiError::Parse(msg) => write!(f, "Failed to parse response: {}", msg),
            ApiError::CertificatePinningFailed(msg) => write!(f, "Security verification failed. This may mean the app needs updating or your connection is being intercepted. Please update BirdoVPN to the latest version. ({})", msg),
            ApiError::Rejected { message, .. }
            | ApiError::TwoFactorRequired(message)
            | ApiError::TwoFactorInvalid(message) => write!(f, "{}", message),
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
