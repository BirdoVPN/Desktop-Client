//! API request and response types
//!
//! These types are defined for serialization/deserialization with the API.
//! Some fields are only used for deserialization and may appear unused.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

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
    Success {
        ok: bool,
        tokens: TokenPair,
    },
}

/// FIX C-2: Request body for 2FA TOTP verification
#[derive(Debug, Serialize)]
pub struct TwoFactorVerifyRequest {
    #[serde(rename = "challengeToken")]
    pub challenge_token: String,
    pub token: String,
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
    #[serde(default)]
    pub bandwidth_used: u64,
    pub bandwidth_limit: Option<u64>,
}

fn default_plan() -> String { "recon".to_string() }
fn default_status() -> String { "active".to_string() }
fn default_one() -> u32 { 1 }

// ============================================================================
// VPN Types
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnServer {
    pub id: String,
    pub name: String,
    pub country: String,
    pub country_code: String,
    pub city: String,
    pub hostname: String,
    pub ip_address: String,
    pub port: u16,
    pub load: u8,
    pub is_premium: bool,
    pub is_streaming: bool,
    pub is_p2p: bool,
    pub is_online: bool,
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
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectResponse {
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

#[derive(Debug, Serialize)]
pub struct ConnectionReport {
    pub server_id: String,
    pub connected: bool,
    pub client_version: String,
}

// ============================================================================
// Server Statistics
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerStats {
    pub server_id: String,
    pub current_users: u32,
    pub max_users: u32,
    pub bandwidth_in: u64,
    pub bandwidth_out: u64,
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
