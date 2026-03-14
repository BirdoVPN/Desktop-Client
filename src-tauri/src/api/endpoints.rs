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
}

/// User endpoints — FIX C-3: route through /auth/me instead of phantom /users/subscription
pub mod users {
    pub const SUBSCRIPTION: &str = "/auth/me";
}

/// VPN endpoints
pub mod vpn {
    pub const SERVERS: &str = "/vpn/servers";
    pub const CONNECT: &str = "/vpn/connect";
    pub const MULTI_HOP_ROUTES: &str = "/vpn/multi-hop/routes";
    pub const MULTI_HOP_CONNECT: &str = "/vpn/multi-hop/connect";
    pub const PORT_FORWARDS: &str = "/vpn/port-forwards";

    /// Returns the path for disconnecting a specific VPN connection
    pub fn connection(key_id: &str) -> String {
        format!("/vpn/connections/{}", key_id)
    }

    /// Returns the path for heartbeating a specific VPN connection
    pub fn heartbeat(key_id: &str) -> String {
        format!("/vpn/heartbeat/{}", key_id)
    }
}
