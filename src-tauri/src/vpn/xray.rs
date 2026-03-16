//! Xray Reality Stealth Tunnel Manager
//!
//! Wraps WireGuard UDP traffic inside VLESS + XTLS-Reality over TLS 1.3,
//! making VPN traffic appear as normal HTTPS to deep packet inspection.
//!
//! Flow:
//!   WireGuard ←→ 127.0.0.1:{local_port} (dokodemo-door, UDP)
//!       ←→ Xray VLESS client (TCP/TLS 1.3 Reality)
//!           ←→ Server:8443 [appears as HTTPS to www.microsoft.com]
//!
//! The Xray binary (xray.exe) is bundled in src-tauri/resources/ and
//! extracted to the app data directory at runtime.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::watch;
use tokio::io::{AsyncBufReadExt, BufReader};
use serde_json::json;

/// Default local UDP port for the dokodemo-door inbound
const DEFAULT_LOCAL_PORT: u16 = 51821;

/// Xray Reality tunnel configuration from server ConnectResponse
#[derive(Debug, Clone)]
pub struct XrayConfig {
    /// Server endpoint for Reality (e.g., "144.172.110.131:8443")
    pub endpoint: String,
    /// VLESS UUID for authentication
    pub uuid: String,
    /// Reality X25519 public key
    pub public_key: String,
    /// Reality short ID (hex)
    pub short_id: String,
    /// TLS SNI domain (e.g., "www.microsoft.com")
    pub sni: String,
    /// Flow control (e.g., "xtls-rprx-vision")
    pub flow: String,
    /// Original WireGuard endpoint port (typically 51820)
    pub wg_port: u16,
}

/// Manages the lifecycle of an Xray Reality stealth tunnel process
pub struct XrayManager {
    process: Arc<Mutex<Option<Child>>>,
    local_port: Arc<Mutex<u16>>,
    config_path: Arc<Mutex<Option<PathBuf>>>,
    health_cancel: Arc<Mutex<Option<watch::Sender<bool>>>>,
}

impl XrayManager {
    pub fn new() -> Self {
        Self {
            process: Arc::new(Mutex::new(None)),
            local_port: Arc::new(Mutex::new(DEFAULT_LOCAL_PORT)),
            config_path: Arc::new(Mutex::new(None)),
            health_cancel: Arc::new(Mutex::new(None)),
        }
    }

    /// Start the Xray Reality tunnel. Returns the local port to use as WireGuard endpoint.
    pub async fn start(&self, app_data_dir: &PathBuf, config: &XrayConfig) -> Result<u16, String> {
        // Stop any existing instance
        self.stop().await;

        // Find an available local port
        let local_port = find_available_port(DEFAULT_LOCAL_PORT)
            .ok_or("No available local ports for Xray tunnel")?;
        *self.local_port.lock().await = local_port;

        // Parse server endpoint
        let (server_host, server_port) = parse_endpoint(&config.endpoint)?;

        // Generate Xray config JSON
        let xray_config = build_xray_config(
            local_port,
            &server_host,
            server_port,
            config.wg_port,
            &config.uuid,
            &config.public_key,
            &config.short_id,
            &config.sni,
            &config.flow,
        );

        // Write config to temp file
        let config_dir = app_data_dir.join("xray");
        std::fs::create_dir_all(&config_dir)
            .map_err(|e| format!("Failed to create Xray config directory: {}", e))?;
        let config_file = config_dir.join("config.json");
        std::fs::write(&config_file, serde_json::to_string_pretty(&xray_config)
            .map_err(|e| format!("Failed to serialize Xray config: {}", e))?)
            .map_err(|e| format!("Failed to write Xray config: {}", e))?;
        *self.config_path.lock().await = Some(config_file.clone());

        // Find xray binary — check resources dir first, then PATH
        let xray_binary = find_xray_binary(app_data_dir)?;

        tracing::info!(
            "Starting Xray Reality tunnel: {} → 127.0.0.1:{} → {}:{}",
            config.sni, local_port, server_host, server_port
        );

        // Start Xray process
        let mut child = Command::new(&xray_binary)
            .args(["run", "-config"])
            .arg(&config_file)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(0x08000000) // CREATE_NO_WINDOW on Windows
            .spawn()
            .map_err(|e| format!("Failed to start Xray process: {}. Binary: {:?}", e, xray_binary))?;

        tracing::info!("Xray process started (PID: {})", child.id());

        // P1-12: Drain stdout and stderr asynchronously to prevent pipe buffer deadlock
        // and capture crash indicators.
        if let Some(stdout) = child.stdout.take() {
            let stdout_async = tokio::process::ChildStdout::from_std(stdout)
                .map_err(|e| format!("Failed to create async stdout: {}", e))?;
            tokio::spawn(async move {
                let reader = BufReader::new(stdout_async);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    tracing::debug!(target: "xray::stdout", "{}", line);
                }
            });
        }
        if let Some(stderr) = child.stderr.take() {
            let stderr_async = tokio::process::ChildStderr::from_std(stderr)
                .map_err(|e| format!("Failed to create async stderr: {}", e))?;
            tokio::spawn(async move {
                let reader = BufReader::new(stderr_async);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    if line.contains("panic") || line.contains("fatal") || line.contains("FATAL") {
                        tracing::error!(target: "xray::stderr", "CRASH: {}", line);
                    } else {
                        tracing::warn!(target: "xray::stderr", "{}", line);
                    }
                }
            });
        }

        *self.process.lock().await = Some(child);

        // Give Xray time to bind the port
        tokio::time::sleep(std::time::Duration::from_millis(800)).await;

        // Delete config file immediately — Xray loads config into memory at startup,
        // so the file (containing UUID, Reality keys) doesn't need to persist on disk.
        if let Some(ref path) = *self.config_path.lock().await {
            let _ = std::fs::remove_file(path);
        }

        // Verify the process is still alive
        let mut proc = self.process.lock().await;
        if let Some(ref mut child) = *proc {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let _ = proc.take(); // Clean up
                    return Err(format!("Xray process exited immediately with status: {}", status));
                }
                Ok(None) => { /* Still running — good */ }
                Err(e) => {
                    tracing::warn!("Could not check Xray process status: {}", e);
                }
            }
        }

        tracing::info!("Xray Reality tunnel active on 127.0.0.1:{}", local_port);

        // Start background health monitor
        self.start_health_monitor(local_port).await;

        Ok(local_port)
    }

    /// Stop the Xray Reality tunnel
    pub async fn stop(&self) {
        // Cancel health monitor
        if let Some(tx) = self.health_cancel.lock().await.take() {
            let _ = tx.send(true);
        }

        let mut proc = self.process.lock().await;
        if let Some(mut child) = proc.take() {
            tracing::info!("Stopping Xray Reality tunnel (PID: {})", child.id());
            // Try graceful kill first, then force
            let _ = child.kill();
            let _ = child.wait(); // Reap the zombie
        }

        // Clean up config file
        let mut config_path = self.config_path.lock().await;
        if let Some(ref path) = *config_path {
            let _ = std::fs::remove_file(path);
        }
        *config_path = None;
    }

    /// Get the local port Xray is listening on
    pub async fn get_local_port(&self) -> u16 {
        *self.local_port.lock().await
    }

    /// Start a background task that periodically checks Xray process health
    async fn start_health_monitor(&self, port: u16) {
        // Cancel any existing monitor
        if let Some(tx) = self.health_cancel.lock().await.take() {
            let _ = tx.send(true);
        }

        let (cancel_tx, mut cancel_rx) = watch::channel(false);
        *self.health_cancel.lock().await = Some(cancel_tx);

        let process = Arc::clone(&self.process);

        tokio::spawn(async move {
            let mut consecutive_failures: u32 = 0;
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(15)) => {}
                    _ = cancel_rx.changed() => break,
                }

                if *cancel_rx.borrow() {
                    break;
                }

                // Check 1: Is the process still alive?
                let proc_alive = {
                    let mut proc = process.lock().await;
                    if let Some(ref mut child) = *proc {
                        match child.try_wait() {
                            Ok(Some(status)) => {
                                tracing::error!("Xray process exited unexpectedly: {}", status);
                                proc.take();
                                false
                            }
                            Ok(None) => true,
                            Err(e) => {
                                tracing::warn!("Failed to check Xray process: {}", e);
                                false
                            }
                        }
                    } else {
                        false
                    }
                };

                if !proc_alive {
                    tracing::error!("Xray health monitor: process not running, stopping monitor");
                    break;
                }

                // Check 2: Can we connect to the local port?
                let port_open = tokio::net::TcpStream::connect(
                    format!("127.0.0.1:{}", port)
                ).await.is_ok();

                if port_open {
                    if consecutive_failures > 0 {
                        tracing::info!("Xray health recovered after {} failures", consecutive_failures);
                    }
                    consecutive_failures = 0;
                } else {
                    consecutive_failures += 1;
                    tracing::warn!(
                        "Xray health check failed: port {} not responding (failure #{})",
                        port, consecutive_failures
                    );
                }
            }
        });
    }

    /// Check if Xray process is currently running
    pub async fn is_running(&self) -> bool {
        let mut proc = self.process.lock().await;
        if let Some(ref mut child) = *proc {
            match child.try_wait() {
                Ok(Some(_)) => {
                    // Process has exited
                    proc.take();
                    false
                }
                Ok(None) => true,
                Err(_) => false,
            }
        } else {
            false
        }
    }
}

impl Drop for XrayManager {
    fn drop(&mut self) {
        // Synchronous cleanup — kill process if still running
        if let Ok(mut proc) = self.process.try_lock() {
            if let Some(mut child) = proc.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

/// Find an available TCP/UDP port starting from the given port
fn find_available_port(start: u16) -> Option<u16> {
    for port in start..start + 100 {
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return Some(port);
        }
    }
    None
}

/// Parse "host:port" endpoint string
fn parse_endpoint(endpoint: &str) -> Result<(String, u16), String> {
    let parts: Vec<&str> = endpoint.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid endpoint format: {}", endpoint));
    }
    let port = parts[0].parse::<u16>()
        .map_err(|_| format!("Invalid port in endpoint: {}", endpoint))?;
    Ok((parts[1].to_string(), port))
}

/// Build the Xray JSON configuration
fn build_xray_config(
    local_port: u16,
    server_host: &str,
    server_port: u16,
    wg_port: u16,
    uuid: &str,
    public_key: &str,
    short_id: &str,
    sni: &str,
    flow: &str,
) -> serde_json::Value {
    json!({
        "log": {
            "loglevel": "warning"
        },
        "inbounds": [{
            "tag": "wireguard-in",
            "listen": "127.0.0.1",
            "port": local_port,
            "protocol": "dokodemo-door",
            "settings": {
                "address": server_host,
                "port": wg_port,
                "network": "udp"
            },
            "sniffing": {
                "enabled": false
            }
        }],
        "outbounds": [{
            "tag": "vless-reality",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": server_host,
                    "port": server_port,
                    "users": [{
                        "id": uuid,
                        "encryption": "none",
                        "flow": flow
                    }]
                }]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "fingerprint": "chrome",
                    "serverName": sni,
                    "publicKey": public_key,
                    "shortId": short_id
                }
            }
        }]
    })
}

/// Find the xray binary — check bundled resources first, then PATH
fn find_xray_binary(app_data_dir: &PathBuf) -> Result<PathBuf, String> {
    // Check app resources directory
    let bundled = app_data_dir.join("xray").join("xray.exe");
    if bundled.exists() {
        return Ok(bundled);
    }

    // Check alongside the main executable
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let sibling = exe_dir.join("xray.exe");
            if sibling.exists() {
                return Ok(sibling);
            }
            // Also check resources subdirectory
            let resources = exe_dir.join("resources").join("xray.exe");
            if resources.exists() {
                return Ok(resources);
            }
        }
    }

    // Fall back to PATH
    if let Ok(path) = which::which("xray") {
        return Ok(path);
    }

    Err(
        "Xray binary not found. Place xray.exe in the app resources directory or install it in PATH."
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_endpoint() {
        let (host, port) = parse_endpoint("144.172.110.131:8443").unwrap();
        assert_eq!(host, "144.172.110.131");
        assert_eq!(port, 8443);
    }

    #[test]
    fn test_build_xray_config_structure() {
        let config = build_xray_config(
            51821, "1.2.3.4", 8443, 51820,
            "test-uuid", "test-pubkey", "abcdef01", "www.example.com", "xtls-rprx-vision",
        );
        assert_eq!(config["inbounds"][0]["port"], 51821);
        assert_eq!(config["outbounds"][0]["protocol"], "vless");
        assert_eq!(
            config["outbounds"][0]["streamSettings"]["realitySettings"]["serverName"],
            "www.example.com"
        );
    }
}
