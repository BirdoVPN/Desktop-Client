//! Speed test command
//!
//! Exposes the on-device speed test to the frontend UI.

use crate::api::BirdoApi;
use crate::vpn::speed_test::{run_speed_test, SpeedTestResult};
use tauri::State;

/// Speed test API endpoint — Bearer-authed backend routes (api.birdo.app),
/// reachable through the tunnel: {base}/download, /upload, /ping.
const SPEED_TEST_URL: &str = "https://api.birdo.app/vpn/speed-test";

/// P2-14: Run an on-device speed test through the VPN tunnel.
/// Downloads 10MB, uploads 5MB, measures latency/jitter.
///
/// SEC FIX: Reuse the hardened BirdoApi client (HTTPS-only, TLS 1.2+, cert-pinned)
/// instead of building a bare reqwest::Client that bypasses all TLS safeguards.
/// The speed-test endpoints require auth, so attach the access token.
#[tauri::command]
pub async fn run_speed_test_command(api: State<'_, BirdoApi>) -> Result<SpeedTestResult, String> {
    let client = api.http_client();
    let token = api.access_token_value().await;
    run_speed_test(&client, SPEED_TEST_URL, SPEED_TEST_URL, token.as_deref()).await
}
