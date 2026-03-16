//! On-device speed test module
//!
//! Measures actual throughput through the VPN tunnel by downloading
//! and uploading test data to a speed-test endpoint on the VPN server.
//!
//! The speed test:
//! - Downloads a fixed payload (e.g. 10MB) and measures throughput
//! - Uploads a random payload (e.g. 5MB) and measures throughput
//! - Reports download/upload Mbps and latency
//!
//! Privacy: No user data is transmitted. Only random/zero-filled payloads.

use std::time::Instant;
use serde::Serialize;

/// Speed test result reported to the frontend
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpeedTestResult {
    /// Download speed in Mbps
    pub download_mbps: f64,
    /// Upload speed in Mbps
    pub upload_mbps: f64,
    /// Latency in milliseconds (ICMP or HTTP)
    pub latency_ms: u32,
    /// Jitter in milliseconds (stddev of latency samples)
    pub jitter_ms: u32,
    /// Total bytes downloaded during test
    pub bytes_downloaded: u64,
    /// Total bytes uploaded during test
    pub bytes_uploaded: u64,
    /// Test duration in seconds
    pub duration_seconds: f64,
    /// Server endpoint used
    pub server_endpoint: String,
}

/// Download speed test — fetches a binary payload from the speed test endpoint
pub async fn measure_download(
    client: &reqwest::Client,
    speed_test_url: &str,
    size_bytes: u64,
) -> Result<(f64, u64), String> {
    let url = format!("{}/download?size={}", speed_test_url, size_bytes);

    let start = Instant::now();
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Download request failed: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("Download returned status {}", response.status()));
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| format!("Failed to read download body: {}", e))?;

    let elapsed = start.elapsed().as_secs_f64();
    let bytes_received = bytes.len() as u64;
    let mbps = if elapsed > 0.0 {
        (bytes_received as f64 * 8.0) / (elapsed * 1_000_000.0)
    } else {
        0.0
    };

    Ok((mbps, bytes_received))
}

/// Upload speed test — sends a random payload to the speed test endpoint
pub async fn measure_upload(
    client: &reqwest::Client,
    speed_test_url: &str,
    size_bytes: usize,
) -> Result<(f64, u64), String> {
    let url = format!("{}/upload", speed_test_url);
    // Generate random payload
    let payload = vec![0u8; size_bytes];

    let start = Instant::now();
    let response = client
        .post(&url)
        .body(payload)
        .send()
        .await
        .map_err(|e| format!("Upload request failed: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("Upload returned status {}", response.status()));
    }

    let elapsed = start.elapsed().as_secs_f64();
    let bytes_sent = size_bytes as u64;
    let mbps = if elapsed > 0.0 {
        (bytes_sent as f64 * 8.0) / (elapsed * 1_000_000.0)
    } else {
        0.0
    };

    Ok((mbps, bytes_sent))
}

/// Measure latency by timing multiple small HTTP requests
pub async fn measure_latency(
    client: &reqwest::Client,
    speed_test_url: &str,
    samples: u32,
) -> (u32, u32) {
    let mut latencies = Vec::with_capacity(samples as usize);

    for _ in 0..samples {
        let url = format!("{}/ping", speed_test_url);
        let start = Instant::now();
        if client.get(&url).send().await.is_ok() {
            latencies.push(start.elapsed().as_millis() as f64);
        }
    }

    if latencies.is_empty() {
        return (0, 0);
    }

    let avg = latencies.iter().sum::<f64>() / latencies.len() as f64;
    let variance = latencies.iter().map(|l| (l - avg).powi(2)).sum::<f64>() / latencies.len() as f64;
    let jitter = variance.sqrt();

    (avg as u32, jitter as u32)
}

/// Run a complete speed test
pub async fn run_speed_test(
    client: &reqwest::Client,
    speed_test_url: &str,
    server_endpoint: &str,
) -> Result<SpeedTestResult, String> {
    let start = Instant::now();

    // 1. Latency (5 samples)
    let (latency_ms, jitter_ms) = measure_latency(client, speed_test_url, 5).await;

    // 2. Download test (10MB)
    let (download_mbps, bytes_downloaded) = measure_download(client, speed_test_url, 10 * 1024 * 1024).await?;

    // 3. Upload test (5MB)
    let (upload_mbps, bytes_uploaded) = measure_upload(client, speed_test_url, 5 * 1024 * 1024).await?;

    let duration_seconds = start.elapsed().as_secs_f64();

    Ok(SpeedTestResult {
        download_mbps,
        upload_mbps,
        latency_ms,
        jitter_ms,
        bytes_downloaded,
        bytes_uploaded,
        duration_seconds,
        server_endpoint: server_endpoint.to_string(),
    })
}
