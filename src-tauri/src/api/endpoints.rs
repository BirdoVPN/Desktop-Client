//! API endpoint constants
//!
//! Central definition for all API paths used by the desktop client.
//! Imported by client.rs to avoid hardcoded strings drifting out of sync.

/// Authentication endpoints
pub mod auth {
    pub const LOGIN_DESKTOP: &str = "/auth/login/desktop";
    pub const LOGIN_ANONYMOUS: &str = "/auth/login/anonymous";
    pub const LOGOUT: &str = "/auth/logout";
    pub const REFRESH: &str = "/auth/refresh";
    pub const ME: &str = "/auth/me";
    /// FIX C-2: 2FA verification endpoint
    pub const TWO_FACTOR_VERIFY: &str = "/auth/2fa/verify";
    /// Password reset request (opens flow — server sends email)
    pub const _PASSWORD_RESET_REQUEST: &str = "/auth/password/request-reset";
    /// GDPR account deletion (requires password confirmation)
    pub const GDPR_DELETE: &str = "/v1/gdpr/delete";
    /// GDPR data export (Right to Data Portability)
    pub const GDPR_EXPORT: &str = "/v1/gdpr/export";
}

/// User endpoints — FIX C-3: route through /auth/me instead of phantom /users/subscription
pub mod users {
    pub const SUBSCRIPTION: &str = "/auth/me";
}

/// Voucher endpoints
pub mod vouchers {
    /// Authenticated user redeems a 30/90-day time-extension code.
    /// Backend: NestJS `POST /vouchers/redeem` (birdo-web backend/src/vouchers).
    pub const REDEEM: &str = "/vouchers/redeem";
}

/// VPN endpoints
pub mod vpn {
    pub const SERVERS: &str = "/vpn/servers";
    pub const CONNECT: &str = "/vpn/connect";
    pub const MULTI_HOP_ROUTES: &str = "/vpn/multi-hop/routes";
    pub const MULTI_HOP_CONNECT: &str = "/vpn/multi-hop/connect";
    pub const PORT_FORWARDS: &str = "/vpn/port-forwards";

    /// Percent-encodes a single path segment for defense-in-depth.
    ///
    /// `key_id` originates from server responses, but encoding any character
    /// outside the unreserved set (RFC 3986 `ALPHA / DIGIT / "-" / "." / "_" / "~"`)
    /// prevents a stray `/`, `?`, `#`, or `%` from producing a malformed path or
    /// enabling path traversal. Kept dependency-free intentionally.
    fn encode_segment(input: &str) -> String {
        let mut out = String::with_capacity(input.len());
        for &byte in input.as_bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    out.push(byte as char);
                }
                _ => {
                    out.push('%');
                    out.push(char::from_digit((byte >> 4) as u32, 16).unwrap().to_ascii_uppercase());
                    out.push(char::from_digit((byte & 0xF) as u32, 16).unwrap().to_ascii_uppercase());
                }
            }
        }
        out
    }

    /// Returns the path for disconnecting a specific VPN connection
    pub fn connection(key_id: &str) -> String {
        format!("/vpn/connections/{}", encode_segment(key_id))
    }

    /// Returns the path for heartbeating a specific VPN connection
    pub fn heartbeat(key_id: &str) -> String {
        format!("/vpn/heartbeat/{}", encode_segment(key_id))
    }

    /// Returns the path for rotating the WireGuard key of an active connection
    #[allow(dead_code)] // Used by ApiClient::rotate_key (reserved auto-rotate surface)
    pub fn rotate_key(key_id: &str) -> String {
        format!("/vpn/connections/{}/rotate", encode_segment(key_id))
    }

    /// P2-15: Client quality telemetry reporting endpoint
    pub const QUALITY_REPORT: &str = "/vpn/quality-report";
}
