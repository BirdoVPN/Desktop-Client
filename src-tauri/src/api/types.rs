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

#[derive(Debug, Serialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
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

/// Anonymous login request — only requires a device ID
#[derive(Debug, Serialize)]
pub struct AnonymousLoginRequest {
    #[serde(rename = "deviceId")]
    pub device_id: String,
}

/// Anonymous login response
#[derive(Debug, Deserialize)]
pub struct AnonymousLoginResult {
    pub ok: bool,
    #[serde(rename = "anonymousId")]
    pub anonymous_id: Option<String>,
    pub tokens: Option<TokenPair>,
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
    #[serde(default)]
    pub is_streaming: bool,
    #[serde(default)]
    pub is_p2p: bool,
    #[serde(default = "default_true")]
    pub is_online: bool,
    #[serde(default = "default_true")]
    pub accessible: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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
