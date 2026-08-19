//! Server commands
//!
//! Handles server listing and latency testing.

use crate::api::BirdoApi;
use crate::storage::CredentialStore;
use serde::Serialize;
use std::time::{Duration, Instant};
use tauri::State;
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerInfo {
    pub id: String,
    pub name: String,
    pub hostname: Option<String>,
    pub country: String,
    pub country_code: String,
    pub city: String,
    pub ip_address: Option<String>,
    pub port: Option<u16>,
    pub load: u8,
    pub is_premium: bool,
    /// RECON | OPERATIVE | SOVEREIGN — the plan a user needs for this node.
    pub min_plan: Option<String>,
    pub is_high_speed: bool,
    pub is_port_forwarding: bool,
    pub is_online: bool,
    pub accessible: bool,
    pub latency_ms: Option<u32>,
}

/// Get list of available VPN servers
#[tauri::command]
pub async fn get_servers(
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<Vec<ServerInfo>, String> {
    tracing::trace!("get_servers command called");

    // Set tokens in API client if available
    if let Ok(tokens) = credentials.get_tokens() {
        tracing::trace!("Setting tokens in API client");
        api.set_tokens(tokens.access_token.clone(), tokens.refresh_token.clone())
            .await;
    } else {
        tracing::trace!("No tokens available in credential store");
    }

    tracing::trace!("Calling api.get_servers()");
    let servers = api.get_servers().await.map_err(|e| {
        tracing::warn!("Failed to fetch servers: {}", e);
        format!("Failed to fetch servers: {}", e)
    })?;

    tracing::trace!("Got {} servers from API", servers.len());

    Ok(servers
        .into_iter()
        .map(|s| ServerInfo {
            id: s.id,
            name: s.name,
            hostname: s.hostname,
            country: s.country,
            country_code: s.country_code,
            city: s.city,
            ip_address: s.ip_address,
            port: s.port,
            load: s.load,
            is_premium: s.is_premium,
            min_plan: s.min_plan,
            is_high_speed: s.is_high_speed,
            is_port_forwarding: s.is_port_forwarding,
            is_online: s.is_online,
            accessible: s.accessible,
            latency_ms: None, // Will be filled by ping_server
        })
        .collect())
}

/// Ping a specific server to measure latency
///
/// SEC-SCAN FIX: Restricts allowed ports to known VPN service ports
/// to prevent abuse as a port scanner from the user's machine.
/// Only WireGuard (51820) and common VPN ports are permitted.
#[tauri::command]
pub async fn ping_server(hostname: String, port: Option<u16>) -> Result<Option<u32>, String> {
    let port = port.unwrap_or(51820);

    // SEC-SCAN FIX: Allowlist of legitimate VPN server ports.
    // Prevents a compromised webview from using this command for port scanning.
    const ALLOWED_PORTS: &[u16] = &[51820, 51821, 443, 1194, 500, 4500];
    if !ALLOWED_PORTS.contains(&port) {
        tracing::warn!("ping_server blocked: port {} not in allowlist", port);
        return Err(format!("Port {} is not allowed for latency testing", port));
    }

    // Basic shape check before resolving.
    if hostname.is_empty() || hostname.contains('/') || hostname.contains('\\') {
        return Err("Invalid hostname for latency testing".to_string());
    }

    // P1-dk-ping-server-private-filter-bypass: the old check was a string-prefix
    // filter on the INPUT ("127.", "10.", ...), trivially bypassed with
    // "0177.0.0.1", "2130706433", a DNS name resolving to 127.0.0.1, or any
    // IPv6 literal form. Resolve first, then reject any resolved address that
    // is loopback/private/link-local/unspecified, and connect to the vetted
    // SocketAddr (not the hostname) so a resolve/connect TOCTOU cannot rebind.
    fn is_disallowed(ip: &std::net::IpAddr) -> bool {
        match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_unspecified()
                    || v4.is_broadcast()
                    || v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1])
                // CGNAT
            }
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || (v6.segments()[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                    || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local
                    || v6.to_ipv4_mapped().is_some_and(|v4| {
                        std::net::IpAddr::V4(v4) != *ip && is_disallowed(&std::net::IpAddr::V4(v4))
                    })
            }
        }
    }

    let lookup_target = format!("{}:{}", hostname, port);
    let resolved: Vec<std::net::SocketAddr> = tokio::net::lookup_host(&lookup_target)
        .await
        .map_err(|_| "Invalid hostname for latency testing".to_string())?
        .collect();

    if resolved.is_empty() || resolved.iter().any(|a| is_disallowed(&a.ip())) {
        tracing::warn!(
            "ping_server blocked: hostname '{}' resolves to a private/loopback address",
            crate::utils::redact::redact_hostname(&hostname)
        );
        return Err("Invalid hostname for latency testing".to_string());
    }
    let addr = resolved[0];

    tracing::debug!(
        "Pinging server: {}",
        crate::utils::redact_ip(&addr.ip().to_string())
    );

    let start = Instant::now();

    // Try TCP connection as a proxy for latency — to the vetted resolved address.
    match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
        Ok(Ok(_)) => {
            let latency = start.elapsed().as_millis() as u32;
            tracing::debug!(
                "Server {} latency: {}ms",
                crate::utils::redact::redact_hostname(&hostname),
                latency
            );
            Ok(Some(latency))
        }
        Ok(Err(e)) => {
            // LOG-001: `addr` is the chosen VPN node — redact so birdo.log
            // carries no plaintext connection history.
            tracing::warn!(
                "Failed to connect to {}: {}",
                crate::utils::redact_endpoint(&addr.to_string()),
                e
            );
            Ok(None)
        }
        Err(_) => {
            tracing::warn!(
                "Timeout connecting to {}",
                crate::utils::redact_endpoint(&addr.to_string())
            );
            Ok(None)
        }
    }
}
