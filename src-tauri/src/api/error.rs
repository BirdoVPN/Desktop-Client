//! API error types

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
    /// Server error (5xx)
    ServerError(u16),
    /// Failed to parse response
    Parse(String),
    /// SEC-C1: TLS certificate pinning verification failed (possible MITM)
    CertificatePinningFailed(String),
    /// Unknown error
    Unknown(String),
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
            ApiError::ServerError(code) => write!(f, "Server error ({})", code),
            ApiError::Parse(msg) => write!(f, "Failed to parse response: {}", msg),
            ApiError::CertificatePinningFailed(msg) => write!(f, "Certificate pinning failed (possible MITM): {}", msg),
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
