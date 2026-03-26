//! Linux TUN tunnel implementation
//!
//! Creates and manages a TUN virtual network interface for WireGuard VPN on Linux.
//! Uses /dev/net/tun with IFF_TUN | IFF_NO_PI for raw IP packet I/O.

#![allow(dead_code)]

use std::net::Ipv4Addr;
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use tokio::sync::{mpsc, RwLock};

use super::wireguard_new::WireGuardSession;
use crate::api::types::VpnConfig;
use crate::utils::redact_ip;

/// Run a command (no special flags needed on Linux — no console window issue)
fn cmd(program: &str) -> Command {
    crate::utils::hidden_cmd(program)
}

/// TUN device name prefix
const TUN_DEVICE_NAME: &str = "birdo0";

/// Stores original DNS and default route info for restoration on disconnect
#[derive(Debug, Clone)]
struct NetworkSnapshot {
    /// Original DNS servers from /etc/resolv.conf or systemd-resolved
    dns_servers: Vec<String>,
    /// Original default gateway
    default_gateway: Option<String>,
    /// Original default interface (e.g. "eth0", "wlan0")
    default_interface: Option<String>,
    /// Whether systemd-resolved is available
    uses_systemd_resolved: bool,
    /// Original resolv.conf contents for fallback restoration
    resolv_conf_backup: Option<String>,
}

/// Linux TUN tunnel for WireGuard VPN
pub struct LinuxTunnel {
    config: VpnConfig,
    running: Arc<AtomicBool>,
    bytes_sent: Arc<AtomicU64>,
    bytes_received: Arc<AtomicU64>,
    packets_sent: Arc<AtomicU64>,
    packets_received: Arc<AtomicU64>,
    wg_session: Arc<RwLock<Option<WireGuardSession>>>,
    shutdown_tx: Arc<RwLock<Option<mpsc::Sender<()>>>>,
    /// The TUN device name (e.g. "birdo0")
    tun_name: Arc<RwLock<Option<String>>>,
    /// The raw file descriptor for the TUN device
    tun_fd: Arc<RwLock<Option<i32>>>,
    /// Network snapshot for restoration on disconnect
    network_snapshot: Arc<RwLock<Option<NetworkSnapshot>>>,
    /// Whether to allow local network access while VPN is active
    local_network_sharing: bool,
    /// Endpoint IP for route exclusion
    endpoint_ip: Arc<RwLock<Option<String>>>,
}

impl LinuxTunnel {
    /// Create a new TUN tunnel with the given VPN configuration.
    pub async fn create(config: &VpnConfig, local_network_sharing: bool) -> Result<Self, String> {
        validate_config(config)?;

        Ok(Self {
            config: config.clone(),
            running: Arc::new(AtomicBool::new(false)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
            packets_sent: Arc::new(AtomicU64::new(0)),
            packets_received: Arc::new(AtomicU64::new(0)),
            wg_session: Arc::new(RwLock::new(None)),
            shutdown_tx: Arc::new(RwLock::new(None)),
            tun_name: Arc::new(RwLock::new(None)),
            tun_fd: Arc::new(RwLock::new(None)),
            network_snapshot: Arc::new(RwLock::new(None)),
            local_network_sharing,
            endpoint_ip: Arc::new(RwLock::new(None)),
        })
    }

    /// Start the tunnel: create TUN device, configure routes/DNS, start packet loop.
    pub async fn start(&self) -> Result<(), String> {
        tracing::info!("Starting Linux TUN tunnel");

        if !crate::utils::elevation::is_elevated() {
            tracing::warn!("Tunnel requires root privileges for TUN/route configuration");
        }

        // Snapshot current network config for restoration
        let snapshot = capture_network_snapshot().await?;
        tracing::info!("Captured network snapshot: gw={:?}, iface={:?}",
            snapshot.default_gateway.as_deref().map(|s| redact_ip(s)),
            snapshot.default_interface);
        *self.network_snapshot.write().await = Some(snapshot);

        // Create the TUN device
        let (tun_name, tun_fd) = create_tun_device()
            .map_err(|e| format!("Failed to create TUN device: {}", e))?;
        tracing::info!("Created TUN device: {}", tun_name);

        *self.tun_name.write().await = Some(tun_name.clone());
        *self.tun_fd.write().await = Some(tun_fd);

        // Create WireGuard session BEFORE configuring routes
        let wg_session = WireGuardSession::new(
            &self.config.private_key,
            &self.config.server_public_key,
            &self.config.endpoint,
            self.config.preshared_key.as_deref(),
        )
        .await
        .map_err(|e| format!("Failed to create WireGuard session: {}", e))?;
        tracing::info!("WireGuard session created");

        let endpoint_ip = wg_session.endpoint_ip();
        tracing::info!("WireGuard endpoint IP: {}", redact_ip(&endpoint_ip.to_string()));
        *self.endpoint_ip.write().await = Some(endpoint_ip.to_string());

        // Configure the TUN interface IP and bring it up
        configure_tun_address(&tun_name, &self.config.client_ip, &self.config.mtu)?;

        // Configure routing
        configure_routes(
            &tun_name,
            &endpoint_ip.to_string(),
            &self.config.allowed_ips,
            self.local_network_sharing,
        )
        .await?;

        // Configure DNS
        let snapshot = self.network_snapshot.read().await;
        let uses_resolved = snapshot.as_ref().map_or(false, |s| s.uses_systemd_resolved);
        drop(snapshot);
        configure_dns(&self.config.dns, &tun_name, uses_resolved).await?;

        // Store WireGuard session
        *self.wg_session.write().await = Some(wg_session);
        self.running.store(true, Ordering::SeqCst);

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);
        *self.shutdown_tx.write().await = Some(shutdown_tx);

        // Start packet processing loop
        let running = self.running.clone();
        let bytes_sent = self.bytes_sent.clone();
        let bytes_received = self.bytes_received.clone();
        let packets_sent = self.packets_sent.clone();
        let packets_received = self.packets_received.clone();
        let wg_session = self.wg_session.clone();
        let fd = tun_fd;

        tokio::spawn(async move {
            Self::packet_loop(
                fd,
                wg_session,
                running,
                bytes_sent,
                bytes_received,
                packets_sent,
                packets_received,
                shutdown_rx,
            )
            .await;
        });

        tracing::info!("Linux tunnel started successfully");
        Ok(())
    }

    /// Stop the tunnel and restore network configuration.
    pub async fn stop(&self) -> Result<(), String> {
        tracing::info!("Stopping Linux TUN tunnel");

        self.running.store(false, Ordering::SeqCst);

        // Signal the packet loop to stop
        if let Some(tx) = self.shutdown_tx.write().await.take() {
            let _ = tx.send(()).await;
        }

        // Restore DNS
        if let Some(snapshot) = self.network_snapshot.read().await.as_ref() {
            restore_dns(snapshot).await;
        }

        // Remove routes
        if let Some(ep_ip) = self.endpoint_ip.read().await.as_ref() {
            remove_routes(ep_ip, &self.config.allowed_ips).await;
        }

        // Close the TUN file descriptor (kernel auto-removes the device)
        if let Some(fd) = self.tun_fd.write().await.take() {
            let _ = unsafe { libc::close(fd) };
            tracing::info!("Closed TUN file descriptor");
        }

        *self.tun_name.write().await = None;
        *self.wg_session.write().await = None;

        tracing::info!("Linux tunnel stopped successfully");
        Ok(())
    }

    /// Check if the tunnel is currently running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get tunnel statistics: (bytes_sent, bytes_received, packets_sent, packets_received)
    pub fn get_stats(&self) -> (u64, u64, u64, u64) {
        (
            self.bytes_sent.load(Ordering::Relaxed),
            self.bytes_received.load(Ordering::Relaxed),
            self.packets_sent.load(Ordering::Relaxed),
            self.packets_received.load(Ordering::Relaxed),
        )
    }

    /// Get current latency in milliseconds.
    pub async fn get_latency_ms(&self) -> Option<u32> {
        if let Some(session) = self.wg_session.read().await.as_ref() {
            session.get_latency_ms().await
        } else {
            None
        }
    }

    /// Measure latency to the VPN endpoint.
    pub async fn measure_latency(&self) -> Option<u32> {
        if let Some(session) = self.wg_session.read().await.as_ref() {
            session.measure_latency().await
        } else {
            None
        }
    }

    /// Get the client IP address.
    pub fn get_client_ip(&self) -> &str {
        &self.config.client_ip
    }

    /// Get the server endpoint address.
    pub fn get_endpoint(&self) -> &str {
        &self.config.endpoint
    }

    /// Packet processing loop: read from TUN, encrypt via WireGuard, send to server.
    ///
    /// Linux TUN with IFF_NO_PI provides raw IP packets — no protocol header unlike macOS utun.
    async fn packet_loop(
        tun_fd: i32,
        wg_session: Arc<RwLock<Option<WireGuardSession>>>,
        running: Arc<AtomicBool>,
        bytes_sent: Arc<AtomicU64>,
        bytes_received: Arc<AtomicU64>,
        packets_sent: Arc<AtomicU64>,
        packets_received: Arc<AtomicU64>,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) {
        tracing::info!("Packet loop started on TUN fd={}", tun_fd);

        const MAX_PACKET_SIZE: usize = 65536;

        let mut read_buf = vec![0u8; MAX_PACKET_SIZE];

        loop {
            if !running.load(Ordering::SeqCst) {
                tracing::info!("Packet loop: running flag cleared, exiting");
                break;
            }

            tokio::select! {
                _ = shutdown_rx.recv() => {
                    tracing::info!("Packet loop: shutdown signal received");
                    break;
                }
                // Read from TUN (async via spawn_blocking for the fd read)
                result = tokio::task::spawn_blocking({
                    let fd = tun_fd;
                    let mut buf = read_buf.clone();
                    move || {
                        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                        if n > 0 {
                            buf.truncate(n as usize);
                            Some(buf)
                        } else if n < 0 {
                            let err = std::io::Error::last_os_error();
                            if err.raw_os_error() != Some(libc::EAGAIN) {
                                tracing::debug!("TUN read error: {}", err);
                            }
                            None
                        } else {
                            None
                        }
                    }
                }) => {
                    if let Ok(Some(ip_packet)) = result {
                        // Linux TUN with IFF_NO_PI: data is already a raw IP packet
                        let packet_len = ip_packet.len() as u64;

                        if let Some(session) = wg_session.read().await.as_ref() {
                            match session.send_packet(&ip_packet).await {
                                Ok(_) => {
                                    bytes_sent.fetch_add(packet_len, Ordering::Relaxed);
                                    packets_sent.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(e) => {
                                    tracing::debug!("Failed to send WG packet: {}", e);
                                }
                            }
                        }
                    }
                }
            }

            // Read from WireGuard and write decrypted packets to TUN
            if let Some(session) = wg_session.read().await.as_ref() {
                if let Ok(Some(decrypted)) = session.recv_packet().await {
                    let packet_len = decrypted.len() as u64;

                    // Linux TUN with IFF_NO_PI: write raw IP packet directly (no header)
                    let fd = tun_fd;
                    let buf = decrypted;
                    let _ = tokio::task::spawn_blocking(move || {
                        let written = unsafe {
                            libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len())
                        };
                        if written < 0 {
                            tracing::debug!("TUN write error: {}", std::io::Error::last_os_error());
                        }
                    }).await;

                    bytes_received.fetch_add(packet_len, Ordering::Relaxed);
                    packets_received.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        tracing::info!("Packet loop exited");
    }
}

// ──────────────────────────────────────────────────────────────
// Platform-specific helper functions
// ──────────────────────────────────────────────────────────────

/// Validate all VPN config values before they reach system commands.
fn validate_config(config: &VpnConfig) -> Result<(), String> {
    Ipv4Addr::from_str(&config.client_ip)
        .map_err(|_| format!("Invalid client_ip: '{}'", config.client_ip))?;

    let endpoint_host = config.endpoint.split(':').next()
        .ok_or_else(|| "Invalid endpoint format: missing host".to_string())?;
    if endpoint_host.parse::<Ipv4Addr>().is_err() {
        if endpoint_host.is_empty()
            || endpoint_host.len() > 253
            || !endpoint_host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            || endpoint_host.starts_with('-')
            || endpoint_host.starts_with('.')
        {
            return Err(format!("Invalid endpoint hostname: '{}'", endpoint_host));
        }
    }

    for dns in &config.dns {
        Ipv4Addr::from_str(dns)
            .map_err(|_| format!("Invalid DNS address: '{}'", dns))?;
    }

    for cidr in &config.allowed_ips {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid CIDR format: '{}'", cidr));
        }
        Ipv4Addr::from_str(parts[0])
            .map_err(|_| format!("Invalid network in CIDR: '{}'", cidr))?;
        let prefix: u8 = parts[1].parse()
            .map_err(|_| format!("Invalid prefix in CIDR: '{}'", cidr))?;
        if prefix > 32 {
            return Err(format!("Prefix out of range in CIDR: '{}'", cidr));
        }
    }

    if config.mtu < 576 || config.mtu > 9000 {
        return Err(format!("Invalid MTU: {} (expected 576-9000)", config.mtu));
    }

    Ok(())
}

/// Create a Linux TUN device via /dev/net/tun ioctl.
///
/// Uses IFF_TUN | IFF_NO_PI for raw IP packet I/O (no protocol info header).
/// Returns (tun_name, raw_fd) on success.
fn create_tun_device() -> Result<(String, i32), String> {
    // struct ifreq — only the fields we need
    #[repr(C)]
    struct IfReq {
        ifr_name: [u8; libc::IFNAMSIZ],
        ifr_flags: libc::c_short,
        _pad: [u8; 22], // padding to match struct size
    }

    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;
    // TUNSETIFF ioctl number: _IOW('T', 202, int)
    const TUNSETIFF: libc::c_ulong = 0x400454CA;

    // Open /dev/net/tun
    let tun_path = std::ffi::CString::new("/dev/net/tun")
        .map_err(|_| "Invalid TUN device path".to_string())?;

    let fd = unsafe { libc::open(tun_path.as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return Err(format!(
            "Failed to open /dev/net/tun: {} (are you root? is the tun module loaded?)",
            std::io::Error::last_os_error()
        ));
    }

    // Prepare ifreq
    let mut ifr = IfReq {
        ifr_name: [0u8; libc::IFNAMSIZ],
        ifr_flags: IFF_TUN | IFF_NO_PI,
        _pad: [0u8; 22],
    };

    // Set device name
    let name_bytes = TUN_DEVICE_NAME.as_bytes();
    if name_bytes.len() >= libc::IFNAMSIZ {
        unsafe { libc::close(fd) };
        return Err("TUN device name too long".to_string());
    }
    ifr.ifr_name[..name_bytes.len()].copy_from_slice(name_bytes);

    // Create the device
    let ret = unsafe { libc::ioctl(fd, TUNSETIFF, &mut ifr as *mut IfReq) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(format!("ioctl TUNSETIFF failed: {}", err));
    }

    // Extract actual device name from ifreq
    let name_end = ifr.ifr_name.iter().position(|&b| b == 0).unwrap_or(libc::IFNAMSIZ);
    let tun_name = String::from_utf8_lossy(&ifr.ifr_name[..name_end]).to_string();

    // Set non-blocking mode
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags >= 0 {
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    }

    tracing::info!("Successfully created TUN device: {} (fd={})", tun_name, fd);
    Ok((tun_name, fd))
}

/// Configure the TUN interface IP address and MTU using `ip` command.
fn configure_tun_address(tun_name: &str, client_ip: &str, mtu: &u16) -> Result<(), String> {
    // Validate tun_name to prevent command injection
    if !tun_name.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(format!("Invalid TUN device name: {}", tun_name));
    }

    // ip addr add <client_ip>/32 dev <tun_name>
    let output = cmd("ip")
        .args(["addr", "add", &format!("{}/32", client_ip), "dev", tun_name])
        .output()
        .map_err(|e| format!("Failed to configure TUN address: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // RTNETLINK File exists = address already assigned, not fatal
        if !stderr.contains("File exists") {
            return Err(format!("ip addr add failed: {}", stderr));
        }
    }
    tracing::info!("Configured {} with IP {}", tun_name, redact_ip(client_ip));

    // ip link set <tun_name> mtu <mtu> up
    let output = cmd("ip")
        .args(["link", "set", tun_name, "mtu", &mtu.to_string(), "up"])
        .output()
        .map_err(|e| format!("Failed to bring up TUN interface: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("ip link set failed: {}", stderr));
    }

    Ok(())
}

/// Configure routing to send traffic through the VPN tunnel.
async fn configure_routes(
    tun_name: &str,
    endpoint_ip: &str,
    allowed_ips: &[String],
    local_network_sharing: bool,
) -> Result<(), String> {
    // Get current default gateway for endpoint route
    let default_gw = get_default_gateway()?;
    let default_iface = get_default_interface()?;
    tracing::info!("Default gateway: {} via {}", redact_ip(&default_gw), default_iface);

    // Add a specific route for the VPN endpoint via the real gateway
    // so WireGuard UDP packets don't get caught in the VPN tunnel
    let output = cmd("ip")
        .args(["route", "add", &format!("{}/32", endpoint_ip), "via", &default_gw, "dev", &default_iface])
        .output()
        .map_err(|e| format!("Failed to add endpoint route: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("File exists") {
            tracing::warn!("Endpoint route warning: {}", stderr);
        }
    }

    // Add routes for allowed_ips via the TUN interface
    for cidr in allowed_ips {
        let output = cmd("ip")
            .args(["route", "add", cidr, "dev", tun_name])
            .output()
            .map_err(|e| format!("Failed to add route for {}: {}", cidr, e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("File exists") {
                tracing::warn!("Route add for {} warning: {}", cidr, stderr);
            }
        }
    }

    // If local network sharing is enabled, add RFC1918 routes via the real gateway
    if local_network_sharing {
        let rfc1918 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];
        for cidr in &rfc1918 {
            let _ = cmd("ip")
                .args(["route", "add", cidr, "via", &default_gw, "dev", &default_iface])
                .output();
        }
        tracing::info!("Added local network sharing routes (RFC1918)");
    }

    Ok(())
}

/// Configure DNS servers on Linux.
///
/// Prefers systemd-resolved (resolvectl) when available, falls back to /etc/resolv.conf.
async fn configure_dns(dns_servers: &[String], tun_name: &str, uses_resolved: bool) -> Result<(), String> {
    if uses_resolved {
        // systemd-resolved: set DNS for our TUN interface
        let mut args = vec!["dns".to_string(), tun_name.to_string()];
        args.extend(dns_servers.iter().cloned());

        let output = cmd("resolvectl")
            .args(&args)
            .output()
            .map_err(|e| format!("resolvectl dns failed: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("resolvectl dns failed: {}", stderr));
        }

        // Set our TUN as the default route for DNS (highest priority)
        let output = cmd("resolvectl")
            .args(["domain", tun_name, "~."])
            .output()
            .map_err(|e| format!("resolvectl domain failed: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("resolvectl domain warning: {}", stderr);
        }

        tracing::info!("Configured DNS via systemd-resolved on {}: {:?}", tun_name, dns_servers);
    } else {
        // Fallback: write /etc/resolv.conf directly
        let mut contents = String::from("# Generated by Birdo VPN — will be restored on disconnect\n");
        for dns in dns_servers {
            contents.push_str(&format!("nameserver {}\n", dns));
        }

        std::fs::write("/etc/resolv.conf", contents)
            .map_err(|e| format!("Failed to write /etc/resolv.conf: {}", e))?;

        tracing::info!("Configured DNS via /etc/resolv.conf: {:?}", dns_servers);
    }

    Ok(())
}

/// Restore original DNS configuration.
async fn restore_dns(snapshot: &NetworkSnapshot) {
    if snapshot.uses_systemd_resolved {
        // systemd-resolved: revert the TUN interface DNS (device is being torn down,
        // systemd-resolved will automatically drop configuration for removed interfaces)
        let _ = cmd("resolvectl")
            .args(["revert", TUN_DEVICE_NAME])
            .output();
        tracing::info!("Reverted systemd-resolved DNS for {}", TUN_DEVICE_NAME);
    } else if let Some(ref backup) = snapshot.resolv_conf_backup {
        // Restore original /etc/resolv.conf
        let _ = std::fs::write("/etc/resolv.conf", backup);
        tracing::info!("Restored /etc/resolv.conf from backup");
    } else {
        // Best effort: write back original DNS servers
        let mut contents = String::new();
        if snapshot.dns_servers.is_empty() {
            // No original DNS — write a reasonable default
            contents.push_str("nameserver 1.1.1.1\nnameserver 8.8.8.8\n");
        } else {
            for dns in &snapshot.dns_servers {
                contents.push_str(&format!("nameserver {}\n", dns));
            }
        }
        let _ = std::fs::write("/etc/resolv.conf", contents);
        tracing::info!("Restored /etc/resolv.conf from snapshot");
    }
}

/// Remove VPN-specific routes.
async fn remove_routes(endpoint_ip: &str, allowed_ips: &[String]) {
    // Remove endpoint route
    let _ = cmd("ip")
        .args(["route", "del", &format!("{}/32", endpoint_ip)])
        .output();

    // Remove allowed_ip routes
    for cidr in allowed_ips {
        let _ = cmd("ip")
            .args(["route", "del", cidr])
            .output();
    }

    tracing::info!("Removed VPN routes");
}

/// Capture current network configuration for later restoration.
async fn capture_network_snapshot() -> Result<NetworkSnapshot, String> {
    let default_gateway = get_default_gateway().ok();
    let default_interface = get_default_interface().ok();

    // Check if systemd-resolved is active
    let uses_resolved = cmd("systemctl")
        .args(["is-active", "--quiet", "systemd-resolved"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    // Capture current DNS servers
    let (dns_servers, resolv_conf_backup) = if uses_resolved {
        // Read from resolvectl
        let output = cmd("resolvectl")
            .args(["status", "--no-pager"])
            .output()
            .map_err(|e| format!("Failed to get DNS status: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let servers: Vec<String> = stdout.lines()
            .filter(|l| l.contains("DNS Servers:") || l.contains("Current DNS Server:"))
            .flat_map(|l| {
                l.split(':').nth(1)
                    .map(|s| s.trim().to_string())
                    .into_iter()
                    .filter(|s| !s.is_empty())
            })
            .collect();

        (servers, None)
    } else {
        // Read from /etc/resolv.conf
        let resolv = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
        let servers: Vec<String> = resolv.lines()
            .filter(|l| l.starts_with("nameserver"))
            .filter_map(|l| l.split_whitespace().nth(1).map(|s| s.to_string()))
            .collect();

        (servers, Some(resolv))
    };

    Ok(NetworkSnapshot {
        dns_servers,
        default_gateway,
        default_interface,
        uses_systemd_resolved: uses_resolved,
        resolv_conf_backup,
    })
}

/// Get the default gateway IP from the routing table.
fn get_default_gateway() -> Result<String, String> {
    let output = cmd("ip")
        .args(["route", "show", "default"])
        .output()
        .map_err(|e| format!("Failed to get default route: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    // default via 192.168.1.1 dev eth0
    stdout.split_whitespace()
        .skip_while(|&w| w != "via")
        .nth(1)
        .map(|s| s.to_string())
        .ok_or_else(|| "Could not determine default gateway".to_string())
}

/// Get the default network interface name.
fn get_default_interface() -> Result<String, String> {
    let output = cmd("ip")
        .args(["route", "show", "default"])
        .output()
        .map_err(|e| format!("Failed to get default route: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    // default via 192.168.1.1 dev eth0
    stdout.split_whitespace()
        .skip_while(|&w| w != "dev")
        .nth(1)
        .map(|s| s.to_string())
        .ok_or_else(|| "Could not determine default interface".to_string())
}
