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
    /// The Free plan's monthly allowance is used up and the server ended the
    /// session (heartbeat `reason: "quota_exceeded"`, birdo-web #590).
    QuotaExceeded,
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
                | IpcErrorCode::QuotaExceeded
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
                | IpcErrorCode::QuotaExceeded
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
    /// Settings reapply only (REVIEW-WIN4-004): the previous settings were
    /// saved back before this failure, so the UI re-reads them. Absent from
    /// the wire unless set: a refused restore saved nothing, and re-reading
    /// would hydrate defaults the next save writes over the user's file.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub settings_restored: bool,
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
            settings_restored: false,
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
            ApiError::TwoFactorRequired(message) => {
                Self::new(IpcErrorCode::TwoFactorRequired, message)
            }
            ApiError::TwoFactorInvalid(message) => {
                Self::new(IpcErrorCode::TwoFactorInvalid, message)
            }
            // Retryable by nature: the check is down, the account was not refused.
            ApiError::QuotaCheckUnavailable { retry_after_secs } => {
                let err = Self::new(
                    IpcErrorCode::ServerError,
                    "BirdoVPN couldn't check your plan's data allowance just now. Please try \
                     again in a moment.",
                );
                match retry_after_secs {
                    Some(secs) => err.with_retry_after(*secs),
                    None => err,
                }
            }
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
    /// limit, or (`quotaExceeded`, birdo-web #590) the Free allowance.
    ///
    /// The allowance is a hard refusal with the canonical copy, exactly as
    /// when the heartbeat brings it. It used to read as "server unavailable",
    /// which is retryable: the re-dial after an over-cap session was ended
    /// spent its whole budget, then held a lockdown block with the generic
    /// give-up text (REVIEW-WIN2-002).
    pub fn connect_refused(message: &str, quota_exceeded: bool) -> Self {
        if quota_exceeded {
            return crate::vpn::reconnect_policy::quota_exceeded_error();
        }
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

    /// REVIEW-WIN4-004: `settings_restored` is on the wire only when set, so
    /// every other error keeps the contract shape.
    #[test]
    fn settings_restored_is_sent_only_when_set() {
        let mut error = IpcError::new(IpcErrorCode::ServerUnreachable, "x");
        let plain = serde_json::to_value(&error).unwrap();
        assert!(plain.get("settings_restored").is_none(), "{plain}");
        error.settings_restored = true;
        let marked = serde_json::to_value(&error).unwrap();
        assert_eq!(marked["settings_restored"], serde_json::json!(true));
    }

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
            (IpcErrorCode::QuotaExceeded, "quota_exceeded"),
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
            (
                ApiError::TwoFactorRequired("x".into()),
                IpcErrorCode::TwoFactorRequired,
            ),
            (
                ApiError::TwoFactorInvalid("x".into()),
                IpcErrorCode::TwoFactorInvalid,
            ),
            (
                ApiError::QuotaCheckUnavailable {
                    retry_after_secs: Some(30),
                },
                IpcErrorCode::ServerError,
            ),
        ];
        // Cases are named by index, not by `{api:?}`: an ApiError can carry what a
        // user typed, and CodeQL reads formatting it as cleartext logging.
        for (i, (api, code)) in cases.iter().enumerate() {
            assert_eq!(IpcError::from_api(api).code, *code, "case {i}");
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
            IpcErrorCode::QuotaExceeded,
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

    /// birdo-web #590: a Free connect while the allowance check is down is a
    /// retryable server error with the server's wait, never "this server is
    /// unavailable, try another location".
    #[test]
    fn an_unavailable_quota_check_is_retryable_with_its_wait() {
        let body = r#"{"statusCode":503,"error":"quota_check_unavailable","message":"Try again shortly","details":{"retryable":true,"retryAfterSeconds":30}}"#;
        let api = crate::api::BirdoApi::classify_error_response(
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            body,
        );
        assert!(matches!(
            api,
            ApiError::QuotaCheckUnavailable {
                retry_after_secs: Some(30)
            }
        ));
        let err = IpcError::from_api(&api);
        assert_eq!(err.code, IpcErrorCode::ServerError);
        assert!(err.retryable);
        assert_eq!(err.retry_after_secs, Some(30));

        // Without `details`, still retryable, just without a wait.
        let bare = IpcError::from_api(&crate::api::BirdoApi::classify_error_response(
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"quota_check_unavailable"}"#,
        ));
        assert_eq!(bare.code, IpcErrorCode::ServerError);
        assert!(bare.retryable);
        assert_eq!(bare.retry_after_secs, None);

        // Any other 503 maps as before.
        let other = crate::api::BirdoApi::classify_error_response(
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            "",
        );
        assert_eq!(
            IpcError::from_api(&other).code,
            IpcErrorCode::ServerUnavailable
        );
    }

    #[test]
    fn connect_refusals_distinguish_the_device_limit() {
        assert_eq!(
            IpcError::connect_refused("All VPN servers are currently offline", false).code,
            IpcErrorCode::ServerUnavailable
        );
        assert_eq!(
            IpcError::connect_refused("You have reached your device limit", false).code,
            IpcErrorCode::DeviceLimit
        );
    }

    /// REVIEW-WIN2-002: birdo-web #590's connect gate, as the backend sends it
    /// (`{success:false, quotaExceeded:true, message}`, HTTP 200), single-hop
    /// and Multi-Hop, read through the real response types. A hard refusal
    /// with the allowance code — never "server unavailable", which is
    /// retryable and offers "try another location".
    #[test]
    fn a_used_up_allowance_at_connect_is_a_hard_quota_refusal() {
        use crate::api::types::{ConnectResponse, MultiHopConnectResponse};
        let body = serde_json::json!({
            "success": false,
            "quotaExceeded": true,
            "message": "Free-tier data limit reached (10.0 / 10 GB this period). Your allowance \
                        resets after 12 Oct. Upgrade to Operative for unlimited data."
        });
        let single: ConnectResponse = serde_json::from_value(body.clone()).unwrap();
        let multi: ConnectResponse =
            ConnectResponse::from(serde_json::from_value::<MultiHopConnectResponse>(body).unwrap());
        for response in [single, multi] {
            assert!(!response.success);
            let err = IpcError::connect_refused(
                response.message.as_deref().unwrap_or_default(),
                response.quota_exceeded,
            );
            assert_eq!(err.code, IpcErrorCode::QuotaExceeded);
            assert!(err.code.is_hard_refusal());
            assert!(!err.retryable);
            assert!(!crate::vpn::reconnect_policy::give_up_keeps_block(
                err.code, true
            ));
        }

        // An older server's refusal says nothing about the allowance.
        let old: ConnectResponse =
            serde_json::from_value(serde_json::json!({ "success": false, "message": "Full" }))
                .unwrap();
        assert!(!old.quota_exceeded);
        assert_eq!(
            IpcError::connect_refused("Full", old.quota_exceeded).code,
            IpcErrorCode::ServerUnavailable
        );
    }

    /// P1-dk-redaction-incomplete: the commands outside the contract still
    /// answer `Result<_, String>`, and their text reaches the renderer as
    /// written. Every one of them passes its error through
    /// `redact::for_ipc`, like `IpcError::new` does for the rest — scanned
    /// from the source, so a new String command cannot skip it.
    #[test]
    fn every_string_error_command_redacts_its_error() {
        // Answers `Result<_, String>` but has no error path: every registry
        // read that fails is skipped, not reported.
        const NO_ERROR_PATH: &[&str] = &["list_installed_apps"];
        let sources = [
            ("auth.rs", include_str!("auth.rs")),
            ("biometric.rs", include_str!("biometric.rs")),
            ("killswitch.rs", include_str!("killswitch.rs")),
            ("oauth.rs", include_str!("oauth.rs")),
            ("servers.rs", include_str!("servers.rs")),
            ("session.rs", include_str!("session.rs")),
            ("settings.rs", include_str!("settings.rs")),
            ("speed_test.rs", include_str!("speed_test.rs")),
            ("split_tunnel.rs", include_str!("split_tunnel.rs")),
            ("tray.rs", include_str!("tray.rs")),
            ("updater.rs", include_str!("updater.rs")),
            ("vouchers.rs", include_str!("vouchers.rs")),
            ("vpn.rs", include_str!("vpn.rs")),
            ("vpn_multi_hop.rs", include_str!("vpn_multi_hop.rs")),
            ("vpn_port_forward.rs", include_str!("vpn_port_forward.rs")),
        ];
        let mut string_commands = 0;
        let mut unredacted = Vec::new();
        for (file, source) in sources {
            // A Windows checkout has CRLF endings (core.autocrlf).
            let source = source.replace('\r', "");
            for item in source.split("#[tauri::command]\n").skip(1) {
                let item = &item[..item.find("\n}\n").unwrap_or(item.len())];
                let signature = &item[..item.find('{').unwrap_or(item.len())];
                let squashed: String = signature.chars().filter(|c| !c.is_whitespace()).collect();
                if !squashed.ends_with(",String>") {
                    continue;
                }
                let name = signature
                    .split("fn ")
                    .nth(1)
                    .and_then(|rest| rest.split('(').next())
                    .unwrap_or(signature);
                string_commands += 1;
                if !item.contains("for_ipc") && !NO_ERROR_PATH.contains(&name) {
                    unredacted.push(format!("{file}: {name}"));
                }
            }
        }
        assert!(
            string_commands >= 9,
            "the scan found {string_commands} commands"
        );
        assert!(
            unredacted.is_empty(),
            "unredacted String errors: {unredacted:?}"
        );

        // install_update answers an UpdateFailure, whose message is built in
        // two places; both redact.
        let updater = include_str!("updater.rs").replace('\r', "");
        assert!(updater.contains("message: for_ipc(message),"));
        assert!(updater.contains("message: for_ipc(format!(\"Update failed: {error}\")),"));
    }

    /// What `for_ipc` does to a raw transport error a String command used to
    /// pass through untouched.
    #[test]
    fn a_raw_transport_error_reaches_the_renderer_redacted() {
        let raw = "error sending request for url (https://api.birdo.app/vpn/speed-test/ping): \
                   connection refused by 185.199.110.153:443";
        let shown = crate::utils::redact::for_ipc(raw);
        assert!(!shown.contains("birdo.app"), "{shown}");
        assert!(!shown.contains("185.199"), "{shown}");
        assert!(shown.contains("connection refused"), "{shown}");
    }
}
