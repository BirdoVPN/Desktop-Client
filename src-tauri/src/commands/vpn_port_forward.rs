//! Port Forwarding commands
//!
//! Extracted from vpn.rs — handles port forward CRUD operations.

use tauri::State;

use crate::api::BirdoApi;
use crate::storage::CredentialStore;
use crate::utils::redact::sanitize_error;

/// Get active port forwards for the current user
#[tauri::command]
pub async fn get_port_forwards(
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<Vec<crate::api::types::PortForward>, String> {
    if !api.is_authenticated().await {
        if let Ok(tokens) = credentials.get_tokens() {
            api.set_tokens(tokens.access_token.clone(), tokens.refresh_token.clone()).await;
        }
    }
    if !api.is_authenticated().await {
        return Err("Not authenticated. Please log in first.".to_string());
    }

    api.get_port_forwards()
        .await
        .map_err(|e| sanitize_error(&format!("Failed to get port forwards: {}", e)))
}

/// Create a new port forward
#[tauri::command]
pub async fn create_port_forward(
    port: u16,
    protocol: String,
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<crate::api::types::CreatePortForwardResponse, String> {
    if !api.is_authenticated().await {
        if let Ok(tokens) = credentials.get_tokens() {
            api.set_tokens(tokens.access_token.clone(), tokens.refresh_token.clone()).await;
        }
    }
    if !api.is_authenticated().await {
        return Err("Not authenticated. Please log in first.".to_string());
    }

    api.create_port_forward(port, &protocol, None)
        .await
        .map_err(|e| sanitize_error(&format!("Failed to create port forward: {}", e)))
}

/// Delete an existing port forward
#[tauri::command]
pub async fn delete_port_forward(
    id: String,
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<bool, String> {
    if !api.is_authenticated().await {
        if let Ok(tokens) = credentials.get_tokens() {
            api.set_tokens(tokens.access_token.clone(), tokens.refresh_token.clone()).await;
        }
    }
    if !api.is_authenticated().await {
        return Err("Not authenticated. Please log in first.".to_string());
    }

    api.delete_port_forward(&id)
        .await
        .map_err(|e| sanitize_error(&format!("Failed to delete port forward: {}", e)))?;

    Ok(true)
}
