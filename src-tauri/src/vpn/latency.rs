//! Server latency checking utility
//!
//! Measures ping latency to VPN servers for optimal server selection.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::time::timeout;

// FIX-2-3: Use DoH instead of system DNS to prevent leaking VPN server hostnames to ISP
use super::doh::resolve_via_doh;

/// Result of a latency check
#[derive(Debug, Clone)]
pub struct LatencyResult {
    pub server_id: String,
    pub hostname: String,
    pub latency_ms: Option<u32>,
    pub is_reachable: bool,
    pub error: Option<String>,
}

/// Check latency to a single server using TCP connection time
/// This is more reliable than ICMP ping which may be blocked
pub async fn check_server_latency(
    server_id: String,
    hostname: String,
    port: u16,
    timeout_ms: u64,
) -> LatencyResult {
    let _addr_str = format!("{}:{}", hostname, port);
    
    // FIX-2-3: Resolve hostname via DNS-over-HTTPS to prevent leaking VPN server
    // hostnames to the ISP's DNS resolver. Falls back gracefully on parse if it's an IP.
    let socket_addr: SocketAddr = match hostname.parse::<std::net::IpAddr>() {
        Ok(ip) => SocketAddr::new(ip, port),
        Err(_) => {
            // Hostname — resolve via DoH
            match resolve_via_doh(&hostname).await {
                Ok(ip) => SocketAddr::new(std::net::IpAddr::V4(ip), port),
                Err(e) => {
                    return LatencyResult {
                        server_id,
                        hostname,
                        latency_ms: None,
                        is_reachable: false,
                        error: Some(format!("DoH resolution failed: {}", e)),
                    };
                }
            }
        }
    };

    // Measure TCP connection time
    let start = Instant::now();
    let connect_result = timeout(
        Duration::from_millis(timeout_ms),
        TcpStream::connect(socket_addr),
    )
    .await;

    match connect_result {
        Ok(Ok(_stream)) => {
            let latency = start.elapsed().as_millis() as u32;
            LatencyResult {
                server_id,
                hostname,
                latency_ms: Some(latency),
                is_reachable: true,
                error: None,
            }
        }
        Ok(Err(e)) => LatencyResult {
            server_id,
            hostname,
            latency_ms: None,
            is_reachable: false,
            error: Some(format!("Connection failed: {}", e)),
        },
        Err(_) => LatencyResult {
            server_id,
            hostname,
            latency_ms: None,
            is_reachable: false,
            error: Some("Connection timeout".to_string()),
        },
    }
}

/// Check latency to multiple servers concurrently
pub async fn check_multiple_servers(
    servers: Vec<(String, String, u16)>, // (server_id, hostname, port)
    timeout_ms: u64,
) -> Vec<LatencyResult> {
    let mut handles = Vec::new();

    for (server_id, hostname, port) in servers {
        let handle = tokio::spawn(check_server_latency(
            server_id,
            hostname,
            port,
            timeout_ms,
        ));
        handles.push(handle);
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(result) = handle.await {
            results.push(result);
        }
    }

    // Sort by latency (reachable servers first, then by latency)
    results.sort_by(|a, b| {
        match (a.latency_ms, b.latency_ms) {
            (Some(la), Some(lb)) => la.cmp(&lb),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        }
    });

    results
}

/// Find the best server based on latency
pub async fn find_best_server(
    servers: Vec<(String, String, u16)>,
    timeout_ms: u64,
) -> Option<LatencyResult> {
    let results = check_multiple_servers(servers, timeout_ms).await;
    results.into_iter().find(|r| r.is_reachable)
}

/// Simple ICMP-style latency check using raw sockets (requires admin)
/// Falls back to TCP if ICMP fails
/// FIX-2-3: Resolves hostname via DoH, then passes IP to ping to avoid DNS leaks.
#[cfg(target_os = "windows")]
pub async fn check_latency_icmp(
    hostname: &str,
    timeout_ms: u64,
) -> Result<u32, String> {
    use tokio::process::Command;
    
    // FIX-2-3: Resolve via DoH first, then ping the IP to prevent DNS leaks
    let target = match hostname.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.to_string(),
        Err(_) => resolve_via_doh(hostname)
            .await
            .map(|ip| ip.to_string())
            .map_err(|e| format!("DoH resolution failed for ping target: {}", e))?,
    };
    
    // Use Windows ping command (PB-3.10: non-blocking tokio Command)
    // tokio::process::Command has creation_flags() built-in on Windows
    let mut ping_cmd = Command::new("ping");
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    ping_cmd.creation_flags(CREATE_NO_WINDOW);
    let output = ping_cmd
        .args(["-n", "1", "-w", &timeout_ms.to_string(), &target])
        .output()
        .await
        .map_err(|e| format!("Failed to execute ping: {}", e))?;

    if !output.status.success() {
        return Err("Ping failed".to_string());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // Parse the ping output to extract time
    // Example: "Reply from 1.2.3.4: bytes=32 time=15ms TTL=64"
    for line in stdout.lines() {
        if line.contains("time=") || line.contains("time<") {
            // Extract time value
            if let Some(time_start) = line.find("time") {
                let time_part = &line[time_start..];
                if let Some(eq_pos) = time_part.find(['=', '<']) {
                    let after_eq = &time_part[eq_pos + 1..];
                    let ms_end = after_eq.find(|c: char| !c.is_ascii_digit());
                    let ms_str = match ms_end {
                        Some(pos) => &after_eq[..pos],
                        None => after_eq,
                    };
                    if let Ok(ms) = ms_str.parse::<u32>() {
                        return Ok(ms);
                    }
                }
            }
        }
    }

    Err("Could not parse ping output".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_check_latency_cloudflare() {
        let result = check_server_latency(
            "test".to_string(),
            "1.1.1.1".to_string(),
            443,
            3000,
        ).await;
        
        println!("Latency result: {:?}", result);
        // Cloudflare should generally be reachable
    }
}
