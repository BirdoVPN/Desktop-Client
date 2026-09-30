//! Port Forwarding commands
//!
//! Extracted from vpn.rs — handles port forward CRUD operations.

use tauri::State;

use crate::api::BirdoApi;
use crate::commands::ipc_error::IpcError;
use crate::commands::session::ensure_signed_in;
use crate::storage::CredentialStore;

/// Get active port forwards for the current user
#[tauri::command]
pub async fn get_port_forwards(
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<Vec<crate::api::types::PortForward>, IpcError> {
    ensure_signed_in(&api, &credentials).await?;

    api.get_port_forwards().await.map_err(IpcError::from)
}

/// Create a new port forward
#[tauri::command]
pub async fn create_port_forward(
    port: u16,
    protocol: String,
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<crate::api::types::CreatePortForwardResponse, IpcError> {
    // SEC FIX: Rust-side allowlist validation — TypeScript types are not a security boundary.
    // A compromised renderer can bypass TypeScript and send arbitrary strings via IPC.
    if protocol != "tcp" && protocol != "udp" {
        return Err(IpcError::unknown(
            "Invalid protocol: must be 'tcp' or 'udp'",
        ));
    }

    // Reject port 0 (OS-assigned) and privileged ports (1-1023) — these are not
    // suitable for user-initiated port forwarding.
    if port < 1024 {
        return Err(IpcError::unknown(
            "Invalid port: must be in range 1024-65535",
        ));
    }

    ensure_signed_in(&api, &credentials).await?;

    let response = api
        .create_port_forward(port, &protocol, None)
        .await
        .map_err(IpcError::from)?;

    // Surface any backend-provided context (e.g. "Port already in use") for debugging.
    if let Some(message) = response.message.as_deref() {
        if !message.trim().is_empty() {
            tracing::info!("Create port forward response: {}", message);
        }
    }

    Ok(response)
}

/// Delete an existing port forward
#[tauri::command]
pub async fn delete_port_forward(
    id: String,
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<bool, IpcError> {
    // SEC FIX: Validate id is a CUID/UUID to prevent URL path traversal.
    // The id flows into format!("{}/{}", PORT_FORWARDS_ENDPOINT, id), so
    // a malicious renderer could inject traversal sequences like "../../other".
    if id.is_empty()
        || id.len() > 50
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(IpcError::unknown("Invalid port forward ID"));
    }

    ensure_signed_in(&api, &credentials).await?;

    api.delete_port_forward(&id).await.map_err(IpcError::from)?;

    Ok(true)
}
