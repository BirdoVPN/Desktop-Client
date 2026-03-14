//! VPN tunnel module
//!
//! WireGuard tunnel management using Wintun and boringtun.

pub mod auto_reconnect;
pub mod buffer_pool;  // FIX-2-4: Reduced to packet size constants only
pub mod doh;  // DNS-over-HTTPS resolver for SEC-002
pub mod latency;
pub mod manager;
pub mod tunnel;
// Removed: pub mod wireguard; - deprecated file with placeholder crypto
mod wireguard_new;

// Windows Filtering Platform for kill switch
#[cfg(target_os = "windows")]
pub mod wfp;

// Re-export the new boringtun-based implementation
#[allow(unused_imports)]
pub use wireguard_new::WireGuardSession;
pub use manager::VpnManager;

// Re-export DoH resolver (available for future use)
#[allow(unused_imports)]
pub use doh::resolve_via_doh;

// Public API for auto-reconnect (may be used by external consumers)
#[allow(unused_imports)]
pub use auto_reconnect::{AutoReconnectService, AutoReconnectConfig, AutoReconnectStatus};

// Public API for latency checking (may be used by external consumers)
#[allow(unused_imports)]
pub use latency::{LatencyResult, check_server_latency, check_multiple_servers, find_best_server};

// Unit tests for auto-reconnect, kill switch, tunnel health
#[cfg(test)]
mod tests;
