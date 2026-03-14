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
    pub hostname: String,
    pub country: String,
    pub country_code: String,
    pub city: String,
    pub load: u8,
    pub is_premium: bool,
    pub is_streaming: bool,
    pub is_p2p: bool,
    pub is_online: bool,
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
        api.set_tokens(tokens.access_token.clone(), tokens.refresh_token.clone()).await;
    } else {
        tracing::trace!("No tokens available in credential store");
    }

    tracing::trace!("Calling api.get_servers()");
    let servers = api
        .get_servers()
        .await
        .map_err(|e| {
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
            load: s.load,
            is_premium: s.is_premium,
            is_streaming: s.is_streaming,
            is_p2p: s.is_p2p,
            is_online: s.is_online,
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

    // Validate hostname: must be a valid domain or IPv4, no localhost/private IPs
    if hostname.is_empty()
        || hostname.contains('/')
        || hostname.contains('\\')
        || hostname.starts_with("127.")
        || hostname.starts_with("10.")
        || hostname.starts_with("192.168.")
        || hostname.starts_with("169.254.")
        || hostname == "localhost"
        || hostname == "0.0.0.0"
        || hostname.starts_with("[")
    {
        tracing::warn!("ping_server blocked: invalid or private hostname '{}'", hostname);
        return Err("Invalid hostname for latency testing".to_string());
    }

    // Block 172.16.0.0/12 (172.16.x.x – 172.31.x.x)
    if hostname.starts_with("172.") {
        let is_private = hostname.split('.').nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .map(|octet| (16..=31).contains(&octet))
            .unwrap_or(false);
        if is_private {
            tracing::warn!("ping_server blocked: private hostname '{}'", hostname);
            return Err("Invalid hostname for latency testing".to_string());
        }
    }

    let addr = format!("{}:{}", hostname, port);

    tracing::debug!("Pinging server: {}", addr);

    let start = Instant::now();

    // Try TCP connection as a proxy for latency
    match timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => {
            let latency = start.elapsed().as_millis() as u32;
            tracing::debug!("Server {} latency: {}ms", hostname, latency);
            Ok(Some(latency))
        }
        Ok(Err(e)) => {
            tracing::warn!("Failed to connect to {}: {}", addr, e);
            Ok(None)
        }
        Err(_) => {
            tracing::warn!("Timeout connecting to {}", addr);
            Ok(None)
        }
    }
}
