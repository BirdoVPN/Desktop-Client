//! The typed error every connection-facing IPC command returns (IPC contract v2, §2).
//!
//! WHY THIS EXISTS (W1-024). Errors used to cross IPC as free-form strings and
//! the UI classified them by substring, in order. That gave wrong advice — a
//! route failure ("Failed to start tunnel: … routing loop") contains "tunnel",
//! so users were told to reinstall the Wintun driver — and it coupled UI
//! behaviour to the exact wording of Rust messages. The UI now maps `code` to
//! its canonical copy and treats `message` as secondary detail.
//!
//! ONE PLACE maps backend, HTTP and transport failures to codes:
//! [`IpcError::from_api`] for everything the control plane returns and
//! [`IpcError::from_tunnel_failure`] for the tunnel stage. Every other site
//! builds an error with an explicit code.

use serde::Serialize;

use crate::api::ApiError;

/// Stable, snake_case error codes. Extend only by ADDING codes: the UI keys
/// its copy on them, and an unknown code falls back to `unknown` there.
///
/// The sign-in commands answer a refusal with `Ok(LoginResponse)` and put the
/// code in its `code` field (`invalid_credentials`, `two_factor_required`,
/// `two_factor_invalid`, …); every other command returns it as the `Err`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IpcErrorCode {
    NetworkOffline,
    ServerUnreachable,
    ServerUnavailable,
    SessionExpired,
    Revoked,
    DeviceLimit,
    SubscriptionRequired,
    UpgradeRequired,
    RateLimited,
    InvalidCredentials,
    TwoFactorRequired,
    TwoFactorInvalid,
    CertPinFailed,
    StealthFailed,
    PqFailed,
    KillswitchFailed,
    AdapterFailed,
    NotElevated,
    Cancelled,
    ServerError,
    Unknown,
}

impl IpcErrorCode {
    /// Whether repeating the same action, unchanged, can succeed. This is the
    /// default for `IpcError::retryable`; the UI uses it to decide whether to
    /// offer "Try again" at all.
    pub fn retryable(self) -> bool {
        !matches!(
            self,
            IpcErrorCode::SessionExpired
                | IpcErrorCode::Revoked
                | IpcErrorCode::DeviceLimit
                | IpcErrorCode::SubscriptionRequired
                | IpcErrorCode::UpgradeRequired
                | IpcErrorCode::InvalidCredentials
                | IpcErrorCode::NotElevated
                | IpcErrorCode::Cancelled
        )
    }

    /// A refusal no automatic retry can overcome. Auto-reconnect stops on the
    /// FIRST one instead of spending its budget re-asking a backend that has
    /// already said no (contract §3.4: nothing loops silently).
    pub fn is_hard_refusal(self) -> bool {
        matches!(
            self,
            IpcErrorCode::SessionExpired
                | IpcErrorCode::Revoked
                | IpcErrorCode::DeviceLimit
                | IpcErrorCode::SubscriptionRequired
                | IpcErrorCode::UpgradeRequired
                | IpcErrorCode::NotElevated
        )
    }
}

/// How the establish-time WireGuard handshake failed. Internal only: it picks
/// the Adaptive Transport `fallbackReason` wire value and never crosses IPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportFailure {
    /// No answer inside the receive window: the network silently ate it.
    NoResponse,
    /// The receive itself failed (ICMP unreachable, reset): actively refused.
    Refused,
}

/// `{ code, message, retryable, retry_after_secs }` on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IpcError {
    pub code: IpcErrorCode,
    /// A user-safe English sentence. Always passed through `sanitize_always`,
    /// so no address, key or token can reach the renderer through it.
    pub message: String,
    pub retryable: bool,
    pub retry_after_secs: Option<u64>,
    #[serde(skip)]
    pub transport: Option<TransportFailure>,
}

impl std::fmt::Display for IpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl IpcError {
    pub fn new(code: IpcErrorCode, message: impl AsRef<str>) -> Self {
        Self {
            code,
            // Always redacted, debug builds included: this text reaches the
            // renderer and whatever it shows or copies, not a local log.
            message: crate::utils::redact::sanitize_always(message.as_ref()),
            retryable: code.retryable(),
            retry_after_secs: None,
            transport: None,
        }
    }

    pub fn cancelled() -> Self {
        Self::new(
            IpcErrorCode::Cancelled,
            "The connection attempt was cancelled.",
        )
    }

    pub fn not_elevated() -> Self {
        Self::new(
            IpcErrorCode::NotElevated,
            crate::utils::elevation::elevation_required_message(),
        )
    }

    pub fn session_expired() -> Self {
        Self::new(
            IpcErrorCode::SessionExpired,
            "Your session has expired. Sign in again.",
        )
    }

    pub fn unknown(message: impl AsRef<str>) -> Self {
        Self::new(IpcErrorCode::Unknown, message)
    }

    pub fn with_retry_after(mut self, secs: u64) -> Self {
        self.retry_after_secs = Some(secs);
        self
    }

    /// The single mapping from a control-plane failure to a code.
    pub fn from_api(error: &ApiError) -> Self {
        match error {
            ApiError::Network(_) => Self::new(
                IpcErrorCode::NetworkOffline,
                "Couldn't reach BirdoVPN. Check your internet connection.",
            ),
            ApiError::NotAuthenticated | ApiError::Unauthorized => Self::session_expired(),
            ApiError::Forbidden => Self::new(
                IpcErrorCode::SubscriptionRequired,
                "Your plan does not include this.",
            ),
            ApiError::NotFound => Self::new(
                IpcErrorCode::ServerUnavailable,
                "This server is no longer available.",
            ),
            ApiError::RateLimited => Self::new(
                IpcErrorCode::RateLimited,
                "Too many attempts. Please wait a moment.",
            ),
            ApiError::UpgradeRequired(_) => {
                Self::new(IpcErrorCode::UpgradeRequired, error.to_string())
            }
            ApiError::ServerError(503) => Self::new(
                IpcErrorCode::ServerUnavailable,
                "This server is unavailable right now. Try another location.",
            ),
            ApiError::ServerError(_) | ApiError::Parse(_) => Self::new(
                IpcErrorCode::ServerError,
                "BirdoVPN had a problem answering. Please try again.",
            ),
            ApiError::CertificatePinningFailed(_) => {
                Self::new(IpcErrorCode::CertPinFailed, error.to_string())
            }
            ApiError::Rejected { status, message } => Self::from_rejection(*status, message),
            ApiError::Unknown(message) => Self::unknown(message),
        }
    }

    /// A non-2xx answer that carried the backend's own sentence. The status
    /// picks the code; the sentence stays as the (secondary) message, because
    /// it is usually the specific one ("Stealth mode requires an Operative or
    /// Sovereign subscription").
    fn from_rejection(status: u16, message: &str) -> Self {
        let code = match status {
            401 => IpcErrorCode::InvalidCredentials,
            402 => IpcErrorCode::SubscriptionRequired,
            403 | 409 if is_device_limit_message(message) => IpcErrorCode::DeviceLimit,
            403 => IpcErrorCode::SubscriptionRequired,
            404 | 409 | 410 | 503 => IpcErrorCode::ServerUnavailable,
            429 => IpcErrorCode::RateLimited,
            500..=599 => IpcErrorCode::ServerError,
            _ => IpcErrorCode::Unknown,
        };
        Self::new(code, message)
    }

    /// `/vpn/connect` answered 2xx with `success:false`: the backend refused
    /// THIS server (full, offline, removed) — or, when it says so, the device
    /// limit.
    pub fn connect_refused(message: &str) -> Self {
        let code = if is_device_limit_message(message) {
            IpcErrorCode::DeviceLimit
        } else {
            IpcErrorCode::ServerUnavailable
        };
        Self::new(code, message)
    }

    /// The tunnel stage failed (`VpnManager::connect`). The only distinction
    /// the error text is trusted for is the establish-time handshake, whose
    /// two markers are load-bearing constants in `wireguard_new.rs`; every
    /// other failure at this stage is adapter, route or DNS setup.
    pub fn from_tunnel_failure(error: &str) -> Self {
        let transport = if error.contains(crate::vpn::ERR_HANDSHAKE_NO_RESPONSE) {
            Some(TransportFailure::NoResponse)
        } else if error.contains(crate::vpn::ERR_HANDSHAKE_RECV) {
            Some(TransportFailure::Refused)
        } else {
            None
        };
        let mut err = match transport {
            Some(_) => Self::new(
                IpcErrorCode::ServerUnreachable,
                "Couldn't establish a secure tunnel to this server. Try another location.",
            ),
            None => Self::new(
                IpcErrorCode::AdapterFailed,
                "The VPN network adapter could not be set up.",
            ),
        };
        err.transport = transport;
        err
    }
}

/// Whether a backend refusal names the device limit. The backend sends no
/// machine-readable code for it, so this is the one place its wording is
/// read; everything else is classified by HTTP status.
fn is_device_limit_message(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    m.contains("device") && (m.contains("limit") || m.contains("maximum"))
}

impl From<ApiError> for IpcError {
    fn from(error: ApiError) -> Self {
        Self::from_api(&error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_to_the_contract_shape() {
        let err = IpcError::new(IpcErrorCode::RateLimited, "Slow down").with_retry_after(30);
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "code": "rate_limited",
                "message": "Slow down",
                "retryable": true,
                "retry_after_secs": 30
            })
        );
    }

    #[test]
    fn every_code_serializes_snake_case() {
        let pairs = [
            (IpcErrorCode::NetworkOffline, "network_offline"),
            (IpcErrorCode::ServerUnreachable, "server_unreachable"),
            (IpcErrorCode::ServerUnavailable, "server_unavailable"),
            (IpcErrorCode::SessionExpired, "session_expired"),
            (IpcErrorCode::Revoked, "revoked"),
            (IpcErrorCode::DeviceLimit, "device_limit"),
            (IpcErrorCode::SubscriptionRequired, "subscription_required"),
            (IpcErrorCode::UpgradeRequired, "upgrade_required"),
            (IpcErrorCode::RateLimited, "rate_limited"),
            (IpcErrorCode::InvalidCredentials, "invalid_credentials"),
            (IpcErrorCode::TwoFactorRequired, "two_factor_required"),
            (IpcErrorCode::TwoFactorInvalid, "two_factor_invalid"),
            (IpcErrorCode::CertPinFailed, "cert_pin_failed"),
            (IpcErrorCode::StealthFailed, "stealth_failed"),
            (IpcErrorCode::PqFailed, "pq_failed"),
            (IpcErrorCode::KillswitchFailed, "killswitch_failed"),
            (IpcErrorCode::AdapterFailed, "adapter_failed"),
            (IpcErrorCode::NotElevated, "not_elevated"),
            (IpcErrorCode::Cancelled, "cancelled"),
            (IpcErrorCode::ServerError, "server_error"),
            (IpcErrorCode::Unknown, "unknown"),
        ];
        for (code, wire) in pairs {
            assert_eq!(serde_json::to_value(code).unwrap(), wire);
        }
    }

    #[test]
    fn the_message_is_sanitized() {
        let err = IpcError::unknown("relay 203.0.113.7 refused");
        assert!(!err.message.contains("203.0.113.7"), "{}", err.message);
    }

    #[test]
    fn api_errors_map_to_codes() {
        let cases = [
            (ApiError::Network("x".into()), IpcErrorCode::NetworkOffline),
            (ApiError::Unauthorized, IpcErrorCode::SessionExpired),
            (ApiError::NotAuthenticated, IpcErrorCode::SessionExpired),
            (ApiError::Forbidden, IpcErrorCode::SubscriptionRequired),
            (ApiError::NotFound, IpcErrorCode::ServerUnavailable),
            (ApiError::RateLimited, IpcErrorCode::RateLimited),
            (ApiError::ServerError(502), IpcErrorCode::ServerError),
            (ApiError::ServerError(503), IpcErrorCode::ServerUnavailable),
            (ApiError::Parse("x".into()), IpcErrorCode::ServerError),
            (
                ApiError::CertificatePinningFailed("x".into()),
                IpcErrorCode::CertPinFailed,
            ),
            (
                ApiError::UpgradeRequired(crate::api::upgrade_gate::RequiredUpdate {
                    required_version: None,
                    download_url: None,
                    message: None,
                }),
                IpcErrorCode::UpgradeRequired,
            ),
            (ApiError::Unknown("x".into()), IpcErrorCode::Unknown),
        ];
        for (api, code) in cases {
            assert_eq!(IpcError::from_api(&api).code, code, "{api:?}");
        }
    }

    #[test]
    fn rejections_map_by_status_and_keep_the_backend_sentence() {
        let rejected = |status, message: &str| ApiError::Rejected {
            status,
            message: message.to_string(),
        };
        let plan = IpcError::from_api(&rejected(
            403,
            "Stealth mode requires an Operative or Sovereign subscription",
        ));
        assert_eq!(plan.code, IpcErrorCode::SubscriptionRequired);
        assert!(plan.message.contains("Stealth mode requires"));

        assert_eq!(
            IpcError::from_api(&rejected(403, "Device limit reached for your plan")).code,
            IpcErrorCode::DeviceLimit
        );
        assert_eq!(
            IpcError::from_api(&rejected(409, "Maximum number of devices connected")).code,
            IpcErrorCode::DeviceLimit
        );
        assert_eq!(
            IpcError::from_api(&rejected(409, "Mesh identity conflict")).code,
            IpcErrorCode::ServerUnavailable
        );
        assert_eq!(
            IpcError::from_api(&rejected(401, "Incorrect password")).code,
            IpcErrorCode::InvalidCredentials
        );
        assert_eq!(
            IpcError::from_api(&rejected(429, "Slow down")).code,
            IpcErrorCode::RateLimited
        );
        assert_eq!(
            IpcError::from_api(&rejected(500, "boom")).code,
            IpcErrorCode::ServerError
        );
        assert_eq!(
            IpcError::from_api(&rejected(400, "bad")).code,
            IpcErrorCode::Unknown
        );
    }

    /// W1-024's own example: a route failure used to be shown as a Wintun
    /// driver problem. The tunnel stage is now classified by stage, not by
    /// words in the message.
    #[test]
    fn tunnel_failures_classify_by_stage_not_wording() {
        let route = IpcError::from_tunnel_failure(
            "Failed to start tunnel: Failed to add endpoint host route - VPN would create a \
             routing loop",
        );
        assert_eq!(route.code, IpcErrorCode::AdapterFailed);
        assert_eq!(route.transport, None);

        let silent = IpcError::from_tunnel_failure(&format!(
            "Failed to start tunnel: Handshake failed after 3 attempts: {}",
            crate::vpn::ERR_HANDSHAKE_NO_RESPONSE
        ));
        assert_eq!(silent.code, IpcErrorCode::ServerUnreachable);
        assert_eq!(silent.transport, Some(TransportFailure::NoResponse));

        let refused = IpcError::from_tunnel_failure(&format!(
            "{}: An existing connection was forcibly closed (os error 10054)",
            crate::vpn::ERR_HANDSHAKE_RECV
        ));
        assert_eq!(refused.code, IpcErrorCode::ServerUnreachable);
        assert_eq!(refused.transport, Some(TransportFailure::Refused));
    }

    #[test]
    fn hard_refusals_are_exactly_the_ones_a_retry_cannot_fix() {
        for code in [
            IpcErrorCode::SessionExpired,
            IpcErrorCode::Revoked,
            IpcErrorCode::DeviceLimit,
            IpcErrorCode::SubscriptionRequired,
            IpcErrorCode::UpgradeRequired,
            IpcErrorCode::NotElevated,
        ] {
            assert!(code.is_hard_refusal(), "{code:?}");
            assert!(!code.retryable(), "{code:?}");
        }
        for code in [
            IpcErrorCode::ServerUnreachable,
            IpcErrorCode::NetworkOffline,
            IpcErrorCode::AdapterFailed,
            IpcErrorCode::StealthFailed,
            IpcErrorCode::KillswitchFailed,
            IpcErrorCode::ServerError,
        ] {
            assert!(!code.is_hard_refusal(), "{code:?}");
        }
    }

    #[test]
    fn connect_refusals_distinguish_the_device_limit() {
        assert_eq!(
            IpcError::connect_refused("All VPN servers are currently offline").code,
            IpcErrorCode::ServerUnavailable
        );
        assert_eq!(
            IpcError::connect_refused("You have reached your device limit").code,
            IpcErrorCode::DeviceLimit
        );
    }
}
