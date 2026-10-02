//! Multi-Hop (Double VPN) commands
//!
//! Extracted from vpn.rs — handles multi-hop route listing and connection.

use tauri::{AppHandle, State};

use crate::api::BirdoApi;
use crate::commands::ipc_error::IpcError;
use crate::commands::session::{connect_session, ensure_signed_in, ConnectTarget};
use crate::storage::CredentialStore;

/// Get available multi-hop routes (SOVEREIGN plan only)
#[tauri::command]
pub async fn get_multi_hop_routes(
    api: State<'_, BirdoApi>,
    credentials: State<'_, CredentialStore>,
) -> Result<Vec<crate::api::types::MultiHopRoute>, IpcError> {
    ensure_signed_in(&api, &credentials).await?;
    api.get_multi_hop_routes().await.map_err(IpcError::from)
}

/// Connect via multi-hop (double VPN): routes through entry node then exit node.
///
/// W1-022: this used to be a second, hand-maintained copy of the connect
/// orchestration that had drifted — it never stopped auto-reconnect before
/// connecting, so a failed Multi-Hop switch was silently "recovered" onto the
/// PREVIOUS target. It now shares `session::connect_session` with single-hop:
/// the same cancellation, switch guard, failure states and commit. The route
/// the backend confirms is verified there (`verified_multi_hop_response`).
#[tauri::command]
pub async fn connect_multi_hop(
    #[allow(non_snake_case)] entryNodeId: String,
    #[allow(non_snake_case)] exitNodeId: String,
    app: AppHandle,
) -> Result<bool, IpcError> {
    tracing::debug!(entry = %entryNodeId, exit = %exitNodeId, "connect_multi_hop called");
    connect_session(
        &app,
        ConnectTarget::MultiHop {
            entry_id: entryNodeId,
            exit_id: exitNodeId,
        },
    )
    .await
    .map(|()| {
        // LOG-001: the chosen entry/exit nodes are connection history — keep
        // them out of the release log (info reaches birdo.log).
        tracing::info!("Multi-hop VPN connected");
        true
    })
}
