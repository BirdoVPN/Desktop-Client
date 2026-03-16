//! Speed test command
//!
//! Exposes the on-device speed test to the frontend UI.

use crate::vpn::speed_test::{run_speed_test, SpeedTestResult};

/// Speed test API endpoint
const SPEED_TEST_URL: &str = "https://birdo.app/api/speed-test";

/// P2-14: Run an on-device speed test through the VPN tunnel.
/// Downloads 10MB, uploads 5MB, measures latency/jitter.
#[tauri::command]
pub async fn run_speed_test_command() -> Result<SpeedTestResult, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    run_speed_test(&client, SPEED_TEST_URL, SPEED_TEST_URL).await
}
