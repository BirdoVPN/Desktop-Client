//! API request and response types
//!
//! These types are defined for serialization/deserialization with the API.
//! Fields on Deserialize structs are populated by serde, not by Rust code,
//! and are surfaced to the frontend via Tauri commands or read by future
//! features. Suppress dead-code warnings module-wide.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

// ============================================================================
// Protocol Error Codes (from birdo-shared/protocol.json)
// ============================================================================

/// Standardized error codes for cross-platform consistency.
/// Generated from the ErrorCode enum in protocol.json.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtocolErrorCode {
    AuthRequired,
    AuthExpired,
    SubscriptionRequired,
    SubscriptionExpired,
    DeviceLimitReached,
    RateLimited,
    ServerOffline,
    ServerFull,
    NoServersAvailable,
    TunnelCreationFailed,
    TunnelStartFailed,
    DnsConfigurationFailed,
    RouteConfigurationFailed,
    KillSwitchFailed,
    Ipv6BlockFailed,
    StealthTunnelFailed,
    QuantumHandshakeFailed,
    AdminRequired,
    NetworkUnreachable,
    HandshakeTimeout,
    DllIntegrityFailed,
    JniIntegrityFailed,
    SettingsTampered,
    BiometricFailed,
    Unknown,
}

impl ProtocolErrorCode {
    /// Human-readable message for UI display
    pub fn user_message(&self) -> &'static str {
        match self {
            Self::AuthRequired => "Please sign in to continue",
            Self::AuthExpired => "Your session has expired — please sign in again",
            Self::SubscriptionRequired => "A subscription is required for this feature",
            Self::SubscriptionExpired => "Your subscription has expired",
            Self::DeviceLimitReached => "Device limit reached — remove a device to connect",
            Self::RateLimited => "Too many requests — please wait a moment",
            Self::ServerOffline => "This server is currently offline",
            Self::ServerFull => "This server is at capacity — try another",
            Self::NoServersAvailable => "No servers available — check back shortly",
            Self::TunnelCreationFailed => "Failed to create VPN tunnel",
            Self::TunnelStartFailed => "Failed to start VPN tunnel",
            Self::DnsConfigurationFailed => "Failed to configure DNS",
            Self::RouteConfigurationFailed => "Failed to configure routing",
            Self::KillSwitchFailed => "Kill switch activation failed",
            Self::Ipv6BlockFailed => "IPv6 leak protection failed",
            Self::StealthTunnelFailed => "Stealth tunnel failed — try without stealth mode",
            Self::QuantumHandshakeFailed => {
                "Post-quantum handshake failed — try without quantum protection"
            }
            Self::AdminRequired => "Administrator privileges are required",
            Self::NetworkUnreachable => "Network is unreachable — check your connection",
            Self::HandshakeTimeout => "Connection timed out — try a closer server",
            Self::DllIntegrityFailed => {
                "Security check failed — application files may be corrupted"
            }
            Self::JniIntegrityFailed => {
                "Security check failed — application files may be corrupted"
            }
            Self::SettingsTampered => "Settings integrity check failed",
            Self::BiometricFailed => "Biometric authentication failed",
            Self::Unknown => "An unexpected error occurred",
        }
    }
}

impl std::fmt::Display for ProtocolErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.user_message())
    }
}

/// Parsed error body from API responses
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiErrorBody {
    #[serde(default)]
    pub error_code: Option<ProtocolErrorCode>,
    #[serde(default)]
    pub message: Option<String>,
}

/// Heartbeat response from the backend
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeartbeatResponse {
    pub valid: bool,
    #[serde(default = "default_true")]
    pub server_online: bool,
    #[serde(default)]
    pub message: Option<String>,
}

fn default_true() -> bool {
    true
}

// ============================================================================
// Connection Quality Reporting (P2-15)
// ============================================================================

/// Client-reported quality telemetry, sent every ~60s while connected.
/// Backend stores ephemerally in Redis and aggregates per-server.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QualityReport {
    pub key_id: String,
    pub latency_ms: f64,
    pub jitter_ms: f64,
    pub packet_loss_percent: f64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub handshake_age_seconds: u64,
    pub connection_state: String,
    pub platform: String,
}

/// Zeroize key_id from heap memory when a QualityReport is dropped. These
/// reports are sent every ~60s while connected, so without this the sensitive
/// key_id accumulates copies in freed memory at a high rate.
impl Drop for QualityReport {
    fn drop(&mut self) {
        self.key_id.zeroize();
    }
}

// ============================================================================
// Authentication Types
// ============================================================================

/// Email + password body for POST /auth/login/desktop.
///
/// This used to be `{ email, password }` and NOTHING else, even though the
/// backend's LoginSchema merges DeviceInfoSchema and every other native
/// sign-in path (SSO handoff, anonymous register/login) already sent device
/// context. Two things broke because of it:
///
///  * The trusted-device 2FA skip is keyed on `deviceId`. With no id in the
///    body the backend's `isTrustedDevice` short-circuits to false, so a user
///    who ticked "trust this device" was still challenged for a TOTP code on
///    every single desktop login — the feature could not work at all.
///  * With `deviceId` absent the backend falls back to hashing
///    `userId|x-desktop-client|user-agent`, and our User-Agent embeds
///    CARGO_PKG_VERSION. Every app update therefore minted a BRAND-NEW device
///    row: the account's device list filled up with duplicates of one machine
///    and "revoke this device" could no longer target the right one.
///
/// So the body now carries the same stable identity as the rest of the client
/// (`utils::get_device_id`) plus the descriptive fields. The descriptors are
/// not optional politeness: `registerDevice` refreshes `deviceName`/`platform`
/// on every upsert, so a login that sent only the id would rename the row to
/// the backend's generic "Desktop client" / UNKNOWN placeholders and undo the
/// labels anonymous registration set.
///
/// Fields are private on purpose — construct via `LoginRequest::new` so no
/// future caller can rebuild this body and drop the device context again.
#[derive(Debug, Serialize)]
pub struct LoginRequest {
    email: String,
    password: String,
    #[serde(rename = "deviceId")]
    device_id: String,
    #[serde(rename = "deviceName")]
    device_name: String,
    #[serde(rename = "deviceType")]
    device_type: String,
    platform: String,
    #[serde(rename = "appVersion")]
    app_version: String,
}

/// Clamp a device label to what DeviceInfoSchema accepts: 1..=`max` characters.
/// Byte slicing would panic mid-codepoint on a non-ASCII hostname, and an empty
/// label fails the schema's `.min(1)` — either would reject the whole login
/// before the credentials are even looked at, so both are handled here.
pub(super) fn clamp_device_name(s: &str, max: usize) -> String {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return "Desktop".to_string();
    }
    trimmed.chars().take(max).collect()
}

impl LoginRequest {
    /// Build the desktop login body, deriving the device context here rather
    /// than taking it from the caller. `get_device_id()` is the same value the
    /// SSO exchange and the anonymous flows send, which is what keeps all of a
    /// machine's sign-ins on one `(userId, deviceId)` row.
    pub fn new(email: &str, password: &str) -> Self {
        Self {
            email: email.to_string(),
            password: password.to_string(),
            device_id: crate::utils::get_device_id(),
            // DeviceInfoSchema caps deviceName at 100 chars and the whole body
            // is validated before the password is ever checked — an unusually
            // long hostname must not turn a valid login into a 400. Truncate on
            // a char boundary (hostnames can be non-ASCII).
            device_name: clamp_device_name(&crate::utils::get_device_name(), 100),
            device_type: "DESKTOP".to_string(),
            platform: crate::utils::device_platform().to_string(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// FIX-1-3: Zeroize password from heap memory when LoginRequest is dropped.
impl Drop for LoginRequest {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

/// Token pair returned from desktop login
#[derive(Debug, Deserialize, Clone)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
}

/// CR-1 FIX: Zeroize auth tokens from heap memory when TokenPair is dropped.
/// Prevents tokens from lingering in freed memory where they could be read
/// via memory dumps or cold-boot attacks.
impl Drop for TokenPair {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}

/// FIX C-2: Response from /auth/login/desktop endpoint.
/// When 2FA is enabled, the server returns a challenge token instead of auth tokens.
/// serde(untagged) tries each variant in order until one matches.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum LoginResult {
    /// 2FA required — must be tried FIRST because untagged tries in order,
    /// and TwoFactorChallenge has a distinctive `requires_two_factor` field.
    TwoFactorChallenge {
        #[serde(rename = "requiresTwoFactor")]
        requires_two_factor: bool,
        #[serde(rename = "challengeToken")]
        challenge_token: String,
    },
    /// Successful login with tokens
    Success { ok: bool, tokens: TokenPair },
}

/// FIX C-2: Request body for 2FA TOTP verification
#[derive(Debug, Serialize)]
pub struct TwoFactorVerifyRequest {
    #[serde(rename = "challengeToken")]
    pub challenge_token: String,
    pub token: String,
}

/// Zeroize sensitive 2FA material (challenge token + TOTP code) from heap
/// memory when the request is dropped, consistent with LoginRequest/TokenPair.
impl Drop for TwoFactorVerifyRequest {
    fn drop(&mut self) {
        self.challenge_token.zeroize();
        self.token.zeroize();
    }
}

/// FIX C-2: Response from 2FA verification — returns tokens on success
#[derive(Debug, Deserialize)]
pub struct TwoFactorVerifyResponse {
    pub ok: bool,
    pub tokens: Option<TokenPair>,
    #[serde(default, rename = "backupCodeUsed")]
    pub backup_code_used: bool,
}

/// Native SSO exchange request. Presents the single-use handoff code the web
/// broker delivered to our loopback redirect, plus the PKCE code_verifier this
/// process generated at the start of the flow (proves we are the same client the
/// challenge was bound to). deviceId is the usual trusted-device context.
#[derive(Debug, Serialize)]
pub struct NativeExchangeRequest {
    pub code: String,
    #[serde(rename = "code_verifier")]
    pub code_verifier: String,
    #[serde(rename = "deviceId")]
    pub device_id: String,
}

impl Drop for NativeExchangeRequest {
    fn drop(&mut self) {
        self.code.zeroize();
        self.code_verifier.zeroize();
    }
}

/// Anonymous login request. The backend's AnonymousLoginSchema requires the
/// account's 24-digit anonymousId (this endpoint NEVER creates accounts) plus
/// an optional password (if one was set on the website). deviceId is optional
/// context the backend uses for trusted-device 2FA skip + device tracking.
#[derive(Debug, Serialize)]
pub struct AnonymousLoginRequest {
    #[serde(rename = "anonymousId")]
    pub anonymous_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(rename = "deviceId")]
    pub device_id: String,
}

/// Per-user monthly bandwidth usage + cap (backend GET /vpn/stats), for the
/// data-usage meter. All bandwidth fields are nullable: a plan with no cap, or a
/// node that has never synced usage, leaves them null so the UI can show
/// "unlimited" / "awaiting first sync" instead of a misleading 0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageStats {
    #[serde(default)]
    pub plan: Option<String>,
    #[serde(rename = "bandwidthLimitGb", default)]
    pub bandwidth_limit_gb: Option<f64>,
    #[serde(rename = "bandwidthUsedGb", default)]
    pub bandwidth_used_gb: Option<f64>,
    #[serde(rename = "bandwidthPeriodEnd", default)]
    pub bandwidth_period_end: Option<String>,
    #[serde(rename = "bandwidthLastSyncAt", default)]
    pub bandwidth_last_sync_at: Option<String>,
    #[serde(rename = "bandwidthIsFresh", default)]
    pub bandwidth_is_fresh: Option<bool>,
}

/// In-app anonymous account creation (native clients). Body is device info only;
/// the server generates the 24-digit ID (matches backend DeviceInfoSchema — all
/// fields optional). Reuses `AnonymousLoginResult` for the response shape
/// ({ ok, anonymousId, tokens }).
#[derive(Debug, Serialize)]
pub struct AnonymousRegisterRequest {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    #[serde(rename = "deviceName", skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    #[serde(rename = "deviceType")]
    pub device_type: String,
    pub platform: String,
    #[serde(rename = "appVersion", skip_serializing_if = "Option::is_none")]
    pub app_version: Option<String>,
}

/// Anonymous login response. Success = { ok, anonymousId, tokens }; accounts
/// with 2FA enabled instead return { requiresTwoFactor, challengeToken }.
#[derive(Debug, Deserialize)]
pub struct AnonymousLoginResult {
    #[serde(default)]
    pub ok: bool,
    #[serde(rename = "anonymousId")]
    pub anonymous_id: Option<String>,
    pub tokens: Option<TokenPair>,
    #[serde(default, rename = "requiresTwoFactor")]
    pub requires_two_factor: bool,
    #[serde(rename = "challengeToken")]
    pub challenge_token: Option<String>,
}

/// Password reset request
#[derive(Debug, Serialize)]
pub struct PasswordResetRequest {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

/// Zeroize the refresh token from heap memory when the request is dropped,
/// consistent with the TokenPair/LoginRequest patterns above.
impl Drop for RefreshRequest {
    fn drop(&mut self) {
        self.refresh_token.zeroize();
    }
}

/// FIX C-1: Updated refresh response to include new refresh token when server returns it
#[derive(Debug, Deserialize)]
pub struct RefreshResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
}

// ============================================================================
// User Types
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserProfile {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub created_at: Option<String>,
    /// Whether the account has a password at all. SSO accounts sign in through
    /// Google/GitHub and have none, so a delete dialog that demands one can
    /// never be satisfied by them.
    ///
    /// Defaults to `true`: if the field is missing because we're talking to a
    /// backend that predates it, keep the old always-ask behaviour rather than
    /// dropping the prompt for accounts that genuinely need it.
    #[serde(default = "default_true")]
    pub has_password: bool,
    /// `alias` is REQUIRED here. The struct's `rename_all = "camelCase"` derives
    /// `isSso`, but the backend sends `isSSO` (auth.controller.ts `@Get("me")`),
    /// so without the alias this silently stayed `false` for every SSO account —
    /// a wrong value rather than a loud failure, because `#[serde(default)]`
    /// quietly fills the gap. The field is currently unused; the alias is here so
    /// the first consumer gets the truth instead of a plausible lie.
    #[serde(default, alias = "isSSO")]
    pub is_sso: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionStatus {
    #[serde(default = "default_plan")]
    pub plan: String,
    #[serde(default = "default_status")]
    pub status: String,
    pub expires_at: Option<String>,
    #[serde(default)]
    pub devices_used: u32,
    #[serde(default = "default_one")]
    pub devices_limit: u32,
    pub bandwidth_limit: Option<u64>,
}

fn default_plan() -> String {
    "recon".to_string()
}
fn default_status() -> String {
    "active".to_string()
}
fn default_one() -> u32 {
    1
}

// ============================================================================
// VPN Types
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnServer {
    pub id: String,
    pub name: String,
    pub country: String,
    #[serde(default)]
    pub country_code: String,
    #[serde(default)]
    pub city: String,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default, alias = "ip")]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub load: u8,
    #[serde(default)]
    pub is_premium: bool,
    /// Minimum plan required to connect: RECON | OPERATIVE | SOVEREIGN.
    /// Absent on pre-minPlan backends; `accessible` (computed server-side) is
    /// what gates the UI, so this is display/telemetry only.
    #[serde(default)]
    pub min_plan: Option<String>,
    /// Low-load / high-throughput node. Replaces the old `isStreaming` flag —
    /// Birdo does not and cannot promise streaming-service unblocking.
    #[serde(default)]
    pub is_high_speed: bool,
    /// Node supports inbound port forwarding. Replaces the old `isP2p` flag —
    /// this is the real capability; it is NOT an invitation to torrent.
    #[serde(default)]
    pub is_port_forwarding: bool,
    #[serde(default = "default_true")]
    pub is_online: bool,
    #[serde(default = "default_true")]
    pub accessible: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnConfig {
    pub server_id: String,
    pub key_id: String,
    pub private_key: String,
    pub public_key: String,
    pub server_public_key: String,
    #[serde(default)]
    pub preshared_key: Option<String>,
    pub endpoint: String,
    pub allowed_ips: Vec<String>,
    pub dns: Vec<String>,
    pub client_ip: String,
    /// Optional IPv6 tunnel address (e.g. "fd00::2/128"). When present, enables
    /// dual-stack routing through the tunnel.
    #[serde(default)]
    pub client_ipv6: Option<String>,
    /// IPv6 CIDRs to route through the tunnel (e.g. ["::/0"]). Empty = IPv4-only.
    #[serde(default)]
    pub allowed_ips_v6: Vec<String>,
    pub mtu: u16,
    pub persistent_keepalive: u16,
}

/// P1-dk-vpnconfig-debug-serialize-privkey: manual Debug so a careless
/// `tracing::debug!(?config)` or panic-context capture can never print the
/// WireGuard private key / PSK. Endpoint and addresses are connection history
/// (LOG-001) — redact those too.
impl std::fmt::Debug for VpnConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VpnConfig")
            .field("server_id", &self.server_id)
            .field("key_id", &self.key_id)
            .field("private_key", &"[redacted]")
            .field("public_key", &self.public_key)
            .field("server_public_key", &self.server_public_key)
            .field(
                "preshared_key",
                &self.preshared_key.as_ref().map(|_| "[redacted]"),
            )
            .field("endpoint", &"[redacted]")
            .field("allowed_ips", &self.allowed_ips)
            .field("dns", &self.dns)
            .field("client_ip", &"[redacted]")
            .field(
                "client_ipv6",
                &self.client_ipv6.as_ref().map(|_| "[redacted]"),
            )
            .field("allowed_ips_v6", &self.allowed_ips_v6)
            .field("mtu", &self.mtu)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .finish()
    }
}

/// FIX-R3: Zero sensitive key material before deallocation.
/// Prevents private key recovery from freed heap memory (e.g., via core dump).
/// Note: Rust String zeroization clears the buffer but V8/JS string copies
/// may still exist if this struct was serialized. Defense-in-depth only.
impl Drop for VpnConfig {
    fn drop(&mut self) {
        self.private_key.zeroize();
        if let Some(ref mut psk) = self.preshared_key {
            psk.zeroize();
        }
        self.server_public_key.zeroize();
    }
}

impl VpnConfig {
    /// Zero only the private key material while keeping the config usable
    /// for reconnection metadata (server_id, endpoint, etc.).
    /// Called after the WireGuard session has consumed the key.
    pub fn scrub_key_material(&mut self) {
        self.private_key.zeroize();
        if let Some(ref mut psk) = self.preshared_key {
            psk.zeroize();
        }
    }
}

// ============================================================================
// VPN Connection
// ============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_node_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_region: Option<String>,
    /// FIX-1-1: Client-generated public key. When provided, the server does not
    /// generate a keypair and never sees the private key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_public_key: Option<String>,
    /// Request stealth mode (Xray Reality tunnel)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stealth_mode: Option<bool>,
    /// ADAPTIVE TRANSPORT: set on an automatic retry after direct WireGuard
    /// failed at establish time (no handshake response — the DPI-filtering
    /// signature). Unlike `stealth_mode` (a deliberate, plan-gated user
    /// preference) this is an observed-failure signal the backend honours on
    /// ANY plan, including anonymous — on a filtered network stealth is the
    /// only transport that carries packets.
    ///
    /// Wire values are pinned by the backend's ConnectDto/zod enum
    /// (`handshake-timeout` | `transport-blocked` | `dns-blocked`); anything
    /// else is a 400, which on the fallback retry would leave a censored user
    /// with no working transport — build it from the
    /// `commands::vpn::FALLBACK_*` constants, never a literal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<String>,
    /// Request post-quantum protection (Rosenpass PSK)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantum_protection: Option<bool>,
    /// AUDIT-C1: BirdoPQ v1 ML-KEM-1024 client public key (Base64).
    /// When present together with `quantum_protection=true`, the server
    /// encapsulates against this key and returns the ciphertext in
    /// `rosenpassPublicKey` so the client can derive the same PSK locally.
    /// Closes B1 (PQ claimed but not implemented on desktop).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pq_client_public_key: Option<String>,
    /// Ed25519 client attestation (`BIRDO-DESKTOP-ATTEST-v1`, see api::attestation).
    /// All five are absent on builds compiled without the signing key, so the
    /// request body is byte-identical to a pre-attestation client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desktop_attest_nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desktop_attest_kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desktop_attest_sig: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desktop_attest_platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desktop_attest_version: Option<String>,
}

/// Single-use nonce the client signs (`GET /vpn/attestation/nonce`).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationNonceResponse {
    pub nonce: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectResponse {
    pub success: bool,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub error_code: Option<ProtocolErrorCode>,
    #[serde(default)]
    pub config: Option<String>,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub preshared_key: Option<String>,
    #[serde(default)]
    pub assigned_ip: Option<String>,
    /// IPv6 tunnel address — present only for ipv6Enabled nodes (camelCase
    /// `clientIpv6` from the backend). Its presence makes the client route IPv6.
    #[serde(default)]
    pub client_ipv6: Option<String>,
    #[serde(default)]
    pub server_public_key: Option<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub dns: Option<Vec<String>>,
    #[serde(default)]
    pub allowed_ips: Option<Vec<String>>,
    #[serde(default)]
    pub mtu: Option<u16>,
    #[serde(default)]
    pub persistent_keepalive: Option<u16>,
    #[serde(default)]
    pub server_node: Option<ServerNodeInfo>,
    // Stealth Mode (Xray Reality)
    #[serde(default, rename = "stealthEnabled")]
    pub stealth_enabled: Option<bool>,
    #[serde(default, rename = "xrayEndpoint")]
    pub xray_endpoint: Option<String>,
    #[serde(default, rename = "xrayUuid")]
    pub xray_uuid: Option<String>,
    #[serde(default, rename = "xrayPublicKey")]
    pub xray_public_key: Option<String>,
    #[serde(default, rename = "xrayShortId")]
    pub xray_short_id: Option<String>,
    #[serde(default, rename = "xraySni")]
    pub xray_sni: Option<String>,
    #[serde(default, rename = "xrayFlow")]
    pub xray_flow: Option<String>,
    // Post-Quantum (Rosenpass)
    #[serde(default, rename = "quantumEnabled")]
    pub quantum_enabled: Option<bool>,
    #[serde(default, rename = "rosenpassPublicKey")]
    pub rosenpass_public_key: Option<String>,
    #[serde(default, rename = "rosenpassEndpoint")]
    pub rosenpass_endpoint: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerNodeInfo {
    pub id: String,
    pub name: String,
    pub region: String,
    pub country: String,
    pub hostname: String,
}

// ============================================================================
// Multi-Hop (Double VPN) Types
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MultiHopRoute {
    pub entry_node_id: String,
    pub exit_node_id: String,
    pub entry_country: String,
    pub exit_country: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MultiHopConnectRequest {
    pub entry_node_id: String,
    pub exit_node_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stealth_mode: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantum_protection: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pq_client_public_key: Option<String>,
    /// Ed25519 client attestation — see `ConnectRequest`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desktop_attest_nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desktop_attest_kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desktop_attest_sig: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desktop_attest_platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desktop_attest_version: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MultiHopConnectResponse {
    pub success: bool,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub config: Option<String>,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub preshared_key: Option<String>,
    #[serde(default)]
    pub assigned_ip: Option<String>,
    /// IPv6 tunnel address — present only for ipv6Enabled nodes (camelCase
    /// `clientIpv6` from the backend). Its presence makes the client route IPv6.
    #[serde(default)]
    pub client_ipv6: Option<String>,
    #[serde(default)]
    pub server_public_key: Option<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub dns: Option<Vec<String>>,
    #[serde(default)]
    pub allowed_ips: Option<Vec<String>>,
    #[serde(default)]
    pub mtu: Option<u16>,
    #[serde(default)]
    pub persistent_keepalive: Option<u16>,
    #[serde(default)]
    pub multi_hop: Option<MultiHopInfo>,
    #[serde(default, rename = "stealthEnabled")]
    pub stealth_enabled: Option<bool>,
    #[serde(default, rename = "xrayEndpoint")]
    pub xray_endpoint: Option<String>,
    #[serde(default, rename = "xrayUuid")]
    pub xray_uuid: Option<String>,
    #[serde(default, rename = "xrayPublicKey")]
    pub xray_public_key: Option<String>,
    #[serde(default, rename = "xrayShortId")]
    pub xray_short_id: Option<String>,
    #[serde(default, rename = "xraySni")]
    pub xray_sni: Option<String>,
    #[serde(default, rename = "xrayFlow")]
    pub xray_flow: Option<String>,
    #[serde(default, rename = "quantumEnabled")]
    pub quantum_enabled: Option<bool>,
    #[serde(default, rename = "rosenpassPublicKey")]
    pub rosenpass_public_key: Option<String>,
    #[serde(default, rename = "rosenpassEndpoint")]
    pub rosenpass_endpoint: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MultiHopInfo {
    pub entry_node: MultiHopNodeInfo,
    pub exit_node: MultiHopNodeInfo,
    pub route: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MultiHopNodeInfo {
    pub id: String,
    pub name: String,
    pub country: String,
    pub region: String,
}

// ============================================================================
// Port Forwarding Types
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortForward {
    pub id: String,
    pub external_port: u16,
    pub internal_port: u16,
    pub protocol: String,
    pub enabled: bool,
    pub server_node_id: String,
    pub created_at: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePortForwardRequest {
    pub internal_port: u16,
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_port: Option<u16>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePortForwardResponse {
    pub success: bool,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub port_forward: Option<PortForward>,
}

/// Request body for `POST /vouchers/redeem`.
#[derive(Debug, Serialize)]
pub struct RedeemVoucherRequest {
    pub code: String,
}

/// Success body from `POST /vouchers/redeem`. On failure the backend returns a
/// non-2xx status with `{ error: <slug> }`; that is surfaced as an `ApiError`
/// and mapped to a friendly message in the command layer (see commands/vouchers.rs).
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedeemVoucherResponse {
    #[serde(default)]
    pub ok: bool,
    #[serde(default = "default_plan")]
    pub plan: String,
    #[serde(default)]
    pub duration_days: i32,
    #[serde(default)]
    pub new_period_end: Option<String>,
    #[serde(default)]
    pub extended: bool,
}
