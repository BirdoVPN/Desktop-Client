//! Server commands
//!
//! Handles server listing and latency testing.

use crate::api::BirdoApi;
use crate::commands::ipc_error::IpcError;
use crate::storage::CredentialStore;
use serde::Serialize;
use tauri::State;

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
) -> Result<Vec<ServerInfo>, IpcError> {
    tracing::trace!("get_servers command called");

    // W1-028: only when memory holds no session. This used to overwrite the
    // in-memory tokens from the keystore on EVERY server-list refresh, which
    // can put a consumed refresh token back mid-rotation.
    if let Ok(tokens) = credentials.get_tokens() {
        api.restore_tokens_if_absent(tokens.access_token.clone(), tokens.refresh_token.clone())
            .await;
    } else {
        tracing::trace!("No tokens available in credential store");
    }

    tracing::trace!("Calling api.get_servers()");
    let servers = api.get_servers().await.map_err(|e| {
        tracing::warn!("Failed to fetch servers: {}", e);
        IpcError::from(e)
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
            latency_ms: None, // unmeasured: see ping_server
        })
        .collect())
}

/// Server-list latency: always `null` (W1-026).
///
/// This used to TCP-connect to each server's WireGuard port. WireGuard is UDP,
/// so on every WireGuard-only node the connect could only time out or be
/// refused — latency was blank by construction — and on every launch it
/// resolved the whole fleet's hostnames through the plain system resolver,
/// showing the ISP resolver the list of Birdo nodes on exactly the networks
/// Stealth Mode exists for. There is no honest, cheap measurement of a node
/// this client is not connected to, so none is made: the UI hides latency
/// when it is null. The LIVE session's latency is a real one (the last
/// handshake's round trip, `get_vpn_stats.current_latency_ms`).
///
/// Kept as a command, its arguments ignored, so the current UI's call
/// resolves to "unmeasured" instead of rejecting.
#[tauri::command]
pub fn ping_server() -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    #[test]
    fn server_latency_is_unmeasured_and_nothing_is_probed() {
        assert_eq!(super::ping_server(), None);
        // Built at run time so this file does not match its own needles.
        let source = include_str!("servers.rs");
        for needle in [["lookup", "_host"].concat(), ["Tcp", "Stream"].concat()] {
            assert!(
                !source.contains(&needle),
                "servers.rs probes again: {needle}"
            );
        }
    }
}
