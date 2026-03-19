//! macOS utun tunnel implementation
//!
//! Creates and manages a utun virtual network interface for WireGuard VPN on macOS.
//! Uses the kernel utun interface via AF_SYSTEM sockets.

#![allow(dead_code)]

use std::net::Ipv4Addr;
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use tokio::sync::{mpsc, RwLock};
use nix::sys::socket::{socket, AddressFamily, SockType, SockFlag};
use nix::unistd::close;

use super::wireguard_new::WireGuardSession;
use crate::api::types::VpnConfig;
use crate::utils::redact_ip;

/// Run a command without visible terminal window
fn cmd(program: &str) -> Command {
    crate::utils::hidden_cmd(program)
}

/// utun adapter name (assigned by macOS kernel, typically utun0, utun1, etc.)
const ADAPTER_PREFIX: &str = "utun";

/// DNS resolver config path
const RESOLVER_DIR: &str = "/etc/resolver";

/// Stores original DNS and default route info for restoration on disconnect
#[derive(Debug, Clone)]
struct NetworkSnapshot {
    /// The primary network service name (e.g. "Wi-Fi", "Ethernet")
    service_name: String,
    /// Original DNS servers
    dns_servers: Vec<String>,
    /// Original default gateway
    default_gateway: Option<String>,
    /// Original default interface
    default_interface: Option<String>,
}

/// macOS utun tunnel for WireGuard VPN
pub struct UtunTunnel {
    config: VpnConfig,
    running: Arc<AtomicBool>,
    bytes_sent: Arc<AtomicU64>,
    bytes_received: Arc<AtomicU64>,
    packets_sent: Arc<AtomicU64>,
    packets_received: Arc<AtomicU64>,
    wg_session: Arc<RwLock<Option<WireGuardSession>>>,
    shutdown_tx: Arc<RwLock<Option<mpsc::Sender<()>>>>,
    /// The utun device name assigned by the kernel (e.g. "utun3")
    utun_name: Arc<RwLock<Option<String>>>,
    /// The raw file descriptor for the utun device
    utun_fd: Arc<RwLock<Option<i32>>>,
    /// Network snapshot for restoration on disconnect
    network_snapshot: Arc<RwLock<Option<NetworkSnapshot>>>,
    /// Whether to allow local network access while VPN is active
    local_network_sharing: bool,
    /// Endpoint IP for route exclusion
    endpoint_ip: Arc<RwLock<Option<String>>>,
}

impl UtunTunnel {
    /// Create a new utun tunnel with the given VPN configuration.
    pub async fn create(config: &VpnConfig, local_network_sharing: bool) -> Result<Self, String> {
        // Validate config before any system changes
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
            utun_name: Arc::new(RwLock::new(None)),
            utun_fd: Arc::new(RwLock::new(None)),
            network_snapshot: Arc::new(RwLock::new(None)),
            local_network_sharing,
            endpoint_ip: Arc::new(RwLock::new(None)),
        })
    }

    /// Start the tunnel: create utun device, configure routes/DNS, start packet loop.
    pub async fn start(&self) -> Result<(), String> {
        tracing::info!("Starting macOS utun tunnel");

        // Check for root privileges
        if !crate::utils::elevation::is_elevated() {
            tracing::warn!("Tunnel requires root privileges for utun/route configuration");
        }

        // Snapshot current network config for restoration
        let snapshot = capture_network_snapshot().await?;
        tracing::info!("Captured network snapshot: service={}", snapshot.service_name);
        *self.network_snapshot.write().await = Some(snapshot);

        // Create the utun device
        let (utun_name, utun_fd) = create_utun_device()
            .map_err(|e| format!("Failed to create utun device: {}", e))?;
        tracing::info!("Created utun device: {}", utun_name);

        *self.utun_name.write().await = Some(utun_name.clone());
        *self.utun_fd.write().await = Some(utun_fd);

        // Create WireGuard session BEFORE configuring routes
        // (needs direct network access for DNS resolution of endpoint)
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

        // Configure the utun interface IP
        configure_utun_address(&utun_name, &self.config.client_ip, &self.config.mtu)?;

        // Configure routing
        configure_routes(
            &utun_name,
            &endpoint_ip.to_string(),
            &self.config.allowed_ips,
            self.local_network_sharing,
        )
        .await?;

        // Configure DNS
        configure_dns(&self.config.dns).await?;

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
        let fd = utun_fd;

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

        tracing::info!("macOS tunnel started successfully");
        Ok(())
    }

    /// Stop the tunnel and restore network configuration.
    pub async fn stop(&self) -> Result<(), String> {
        tracing::info!("Stopping macOS utun tunnel");

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

        // Close the utun file descriptor
        if let Some(fd) = self.utun_fd.write().await.take() {
            let _ = close(fd);
            tracing::info!("Closed utun file descriptor");
        }

        // Destroy the utun interface (happens automatically when fd is closed)
        *self.utun_name.write().await = None;

        // Clear WireGuard session
        *self.wg_session.write().await = None;

        tracing::info!("macOS tunnel stopped successfully");
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
            session.latency_ms()
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

    /// Packet processing loop: read from utun, encrypt via WireGuard, send to server.
    async fn packet_loop(
        utun_fd: i32,
        wg_session: Arc<RwLock<Option<WireGuardSession>>>,
        running: Arc<AtomicBool>,
        bytes_sent: Arc<AtomicU64>,
        bytes_received: Arc<AtomicU64>,
        packets_sent: Arc<AtomicU64>,
        packets_received: Arc<AtomicU64>,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) {
        tracing::info!("Packet loop started on utun fd={}", utun_fd);

        // macOS utun prepends a 4-byte protocol header (AF_INET = 2 for IPv4)
        const UTUN_HEADER_SIZE: usize = 4;
        const MAX_PACKET_SIZE: usize = 65536;

        let mut read_buf = vec![0u8; MAX_PACKET_SIZE + UTUN_HEADER_SIZE];
        let mut write_buf = vec![0u8; MAX_PACKET_SIZE + UTUN_HEADER_SIZE];

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
                // Read from utun (async via tokio::task::spawn_blocking for the fd read)
                result = tokio::task::spawn_blocking({
                    let fd = utun_fd;
                    let mut buf = read_buf.clone();
                    move || {
                        use nix::unistd::read;
                        match read(fd, &mut buf) {
                            Ok(n) if n > UTUN_HEADER_SIZE => {
                                buf.truncate(n);
                                Some(buf)
                            }
                            Ok(_) => None,
                            Err(e) => {
                                if e != nix::errno::Errno::EAGAIN {
                                    tracing::debug!("utun read error: {}", e);
                                }
                                None
                            }
                        }
                    }
                }) => {
                    if let Ok(Some(data)) = result {
                        // Strip 4-byte utun header to get raw IP packet
                        let ip_packet = &data[UTUN_HEADER_SIZE..];
                        let packet_len = ip_packet.len() as u64;

                        // Encrypt and send via WireGuard
                        if let Some(session) = wg_session.read().await.as_ref() {
                            if let Ok(encrypted) = session.encapsulate(ip_packet).await {
                                if let Err(e) = session.send(&encrypted).await {
                                    tracing::debug!("Failed to send WG packet: {}", e);
                                } else {
                                    bytes_sent.fetch_add(packet_len, Ordering::Relaxed);
                                    packets_sent.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                }
            }

            // Read from WireGuard and write decrypted packets to utun
            if let Some(session) = wg_session.read().await.as_ref() {
                if let Ok(Some(decrypted)) = session.receive().await {
                    let packet_len = decrypted.len() as u64;

                    // Prepend utun header (AF_INET = 0x00000002 for IPv4)
                    write_buf[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x02]);
                    write_buf[4..4 + decrypted.len()].copy_from_slice(&decrypted);

                    let write_len = 4 + decrypted.len();
                    let fd = utun_fd;
                    let buf = write_buf[..write_len].to_vec();
                    let _ = tokio::task::spawn_blocking(move || {
                        use nix::unistd::write;
                        let _ = write(fd, &buf);
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

/// Create a macOS utun device via AF_SYSTEM socket.
///
/// Returns (utun_name, raw_fd) on success.
fn create_utun_device() -> Result<(String, i32), String> {
    use std::os::unix::io::RawFd;

    // macOS-specific constants for utun
    const AF_SYSTEM: i32 = 32; // AF_SYSTEM
    const SYSPROTO_CONTROL: i32 = 2;
    const AF_SYS_CONTROL: i32 = 2;
    const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";

    // struct ctl_info { u_int32_t ctl_id; char ctl_name[96]; }
    #[repr(C)]
    struct CtlInfo {
        ctl_id: u32,
        ctl_name: [u8; 96],
    }

    // struct sockaddr_ctl { ... }
    #[repr(C)]
    struct SockaddrCtl {
        sc_len: u8,
        sc_family: u8,
        ss_sysaddr: u16,
        sc_id: u32,
        sc_unit: u32, // utun unit number + 1
        sc_reserved: [u32; 5],
    }

    // CTLIOCGINFO ioctl number
    const CTLIOCGINFO: libc::c_ulong = 0xc0644e03;

    // Create AF_SYSTEM socket
    let fd: RawFd = unsafe {
        libc::socket(AF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL)
    };
    if fd < 0 {
        return Err(format!(
            "Failed to create AF_SYSTEM socket: errno {}",
            std::io::Error::last_os_error()
        ));
    }

    // Get the control ID for utun
    let mut ctl_info = CtlInfo {
        ctl_id: 0,
        ctl_name: [0u8; 96],
    };
    ctl_info.ctl_name[..UTUN_CONTROL_NAME.len()]
        .copy_from_slice(UTUN_CONTROL_NAME);

    let ret = unsafe {
        libc::ioctl(fd, CTLIOCGINFO, &mut ctl_info as *mut CtlInfo)
    };
    if ret < 0 {
        unsafe { libc::close(fd) };
        return Err(format!(
            "ioctl CTLIOCGINFO failed: errno {}",
            std::io::Error::last_os_error()
        ));
    }

    tracing::debug!("utun control id: {}", ctl_info.ctl_id);

    // Try successive unit numbers until one works (auto-assign)
    for unit in 0..256u32 {
        let addr = SockaddrCtl {
            sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
            sc_family: AF_SYSTEM as u8,
            ss_sysaddr: AF_SYS_CONTROL as u16,
            sc_id: ctl_info.ctl_id,
            sc_unit: unit + 1, // utun unit = sc_unit - 1
            sc_reserved: [0; 5],
        };

        let ret = unsafe {
            libc::connect(
                fd,
                &addr as *const SockaddrCtl as *const libc::sockaddr,
                std::mem::size_of::<SockaddrCtl>() as u32,
            )
        };

        if ret == 0 {
            let utun_name = format!("utun{}", unit);
            tracing::info!("Successfully created utun device: {} (fd={})", utun_name, fd);

            // Set non-blocking mode
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags >= 0 {
                unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
            }

            return Ok((utun_name, fd));
        }
    }

    unsafe { libc::close(fd) };
    Err("Failed to create utun device: all unit numbers 0-255 in use".to_string())
}

/// Configure the utun interface IP address and MTU.
fn configure_utun_address(utun_name: &str, client_ip: &str, mtu: &u32) -> Result<(), String> {
    // Validate utun_name to prevent command injection
    if !utun_name.starts_with("utun") || !utun_name[4..].chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("Invalid utun name: {}", utun_name));
    }

    // ifconfig utunN inet <client_ip> <client_ip> up
    let output = cmd("ifconfig")
        .args([utun_name, "inet", client_ip, client_ip, "up"])
        .output()
        .map_err(|e| format!("Failed to configure utun address: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("ifconfig address failed: {}", stderr));
    }
    tracing::info!("Configured {} with IP {}", utun_name, redact_ip(client_ip));

    // Set MTU
    let output = cmd("ifconfig")
        .args([utun_name, "mtu", &mtu.to_string()])
        .output()
        .map_err(|e| format!("Failed to set MTU: {}", e))?;

    if !output.status.success() {
        tracing::warn!("Failed to set MTU to {}: {}", mtu, String::from_utf8_lossy(&output.stderr));
    }

    Ok(())
}

/// Configure routing to send traffic through the VPN tunnel.
async fn configure_routes(
    utun_name: &str,
    endpoint_ip: &str,
    allowed_ips: &[String],
    local_network_sharing: bool,
) -> Result<(), String> {
    // Get current default gateway for endpoint route
    let default_gw = get_default_gateway()?;
    tracing::info!("Default gateway: {}", redact_ip(&default_gw));

    // Add a specific route for the VPN endpoint via the real gateway
    // so WireGuard UDP packets don't get caught in the VPN tunnel
    let output = cmd("route")
        .args(["-n", "add", "-host", endpoint_ip, default_gw.as_str()])
        .output()
        .map_err(|e| format!("Failed to add endpoint route: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::warn!("Endpoint route may already exist: {}", stderr);
    }

    // Add routes for allowed_ips via the utun interface
    for cidr in allowed_ips {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            continue;
        }

        let network = parts[0];
        let prefix: u8 = parts[1].parse().unwrap_or(32);
        let mask = prefix_to_mask(prefix);

        // route -n add -net <network> -netmask <mask> -interface <utun>
        let output = cmd("route")
            .args(["-n", "add", "-net", network, "-netmask", &mask, "-interface", utun_name])
            .output()
            .map_err(|e| format!("Failed to add route for {}: {}", cidr, e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("Route add for {} may already exist: {}", cidr, stderr);
        }
    }

    // If local network sharing is enabled, add RFC1918 routes via the real gateway
    if local_network_sharing {
        let rfc1918 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];
        for cidr in &rfc1918 {
            let parts: Vec<&str> = cidr.split('/').collect();
            let mask = prefix_to_mask(parts[1].parse().unwrap_or(8));
            let _ = cmd("route")
                .args(["-n", "add", "-net", parts[0], "-netmask", &mask, &default_gw])
                .output();
        }
        tracing::info!("Added local network sharing routes (RFC1918)");
    }

    Ok(())
}

/// Configure DNS servers on macOS via networksetup.
async fn configure_dns(dns_servers: &[String]) -> Result<(), String> {
    // Get the primary network service
    let service = get_primary_network_service()?;

    // Set DNS servers via networksetup
    let mut args = vec!["-setdnsservers".to_string(), service.clone()];
    args.extend(dns_servers.iter().cloned());

    let output = cmd("networksetup")
        .args(&args)
        .output()
        .map_err(|e| format!("Failed to set DNS: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("networksetup DNS failed: {}", stderr));
    }

    tracing::info!("Configured DNS on service '{}': {:?}", service, dns_servers);

    // Flush DNS cache
    let _ = cmd("dscacheutil").args(["-flushcache"]).output();
    let _ = cmd("killall").args(["-HUP", "mDNSResponder"]).output();

    Ok(())
}

/// Restore original DNS configuration.
async fn restore_dns(snapshot: &NetworkSnapshot) {
    if snapshot.dns_servers.is_empty() {
        // Was using DHCP DNS — set to "empty" which restores DHCP
        let _ = cmd("networksetup")
            .args(["-setdnsservers", &snapshot.service_name, "empty"])
            .output();
    } else {
        let mut args = vec!["-setdnsservers".to_string(), snapshot.service_name.clone()];
        args.extend(snapshot.dns_servers.iter().cloned());
        let _ = cmd("networksetup").args(&args).output();
    }

    // Flush DNS cache
    let _ = cmd("dscacheutil").args(["-flushcache"]).output();
    let _ = cmd("killall").args(["-HUP", "mDNSResponder"]).output();

    tracing::info!("Restored DNS configuration for '{}'", snapshot.service_name);
}

/// Remove VPN-specific routes.
async fn remove_routes(endpoint_ip: &str, allowed_ips: &[String]) {
    // Remove endpoint route
    let _ = cmd("route")
        .args(["-n", "delete", "-host", endpoint_ip])
        .output();

    // Remove allowed_ip routes
    for cidr in allowed_ips {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            continue;
        }
        let mask = prefix_to_mask(parts[1].parse().unwrap_or(32));
        let _ = cmd("route")
            .args(["-n", "delete", "-net", parts[0], "-netmask", &mask])
            .output();
    }

    tracing::info!("Removed VPN routes");
}

/// Capture current network configuration for later restoration.
async fn capture_network_snapshot() -> Result<NetworkSnapshot, String> {
    let service = get_primary_network_service()?;

    // Get current DNS servers
    let output = cmd("networksetup")
        .args(["-getdnsservers", &service])
        .output()
        .map_err(|e| format!("Failed to get DNS: {}", e))?;

    let dns_text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let dns_servers = if dns_text.contains("aren't any") || dns_text.is_empty() {
        vec![] // DHCP DNS
    } else {
        dns_text.lines().map(|l| l.trim().to_string()).collect()
    };

    let default_gateway = get_default_gateway().ok();
    let default_interface = get_default_interface().ok();

    Ok(NetworkSnapshot {
        service_name: service,
        dns_servers,
        default_gateway,
        default_interface,
    })
}

/// Get the primary network service name (e.g. "Wi-Fi", "Ethernet").
fn get_primary_network_service() -> Result<String, String> {
    let output = cmd("route")
        .args(["-n", "get", "default"])
        .output()
        .map_err(|e| format!("Failed to get default route: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Extract interface from "interface: en0"
    let iface = stdout.lines()
        .find(|l| l.trim().starts_with("interface:"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().to_string())
        .ok_or_else(|| "Could not determine default interface".to_string())?;

    // Map interface to network service name
    let output = cmd("networksetup")
        .args(["-listallhardwareports"])
        .output()
        .map_err(|e| format!("Failed to list hardware ports: {}", e))?;

    let text = String::from_utf8_lossy(&output.stdout);
    let mut current_service = String::new();

    for line in text.lines() {
        if let Some(name) = line.strip_prefix("Hardware Port: ") {
            current_service = name.trim().to_string();
        } else if let Some(dev) = line.strip_prefix("Device: ") {
            if dev.trim() == iface {
                return Ok(current_service);
            }
        }
    }

    // Fallback: try "Wi-Fi" or first available
    Ok("Wi-Fi".to_string())
}

/// Get the default gateway IP.
fn get_default_gateway() -> Result<String, String> {
    let output = cmd("route")
        .args(["-n", "get", "default"])
        .output()
        .map_err(|e| format!("Failed to get default gateway: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.lines()
        .find(|l| l.trim().starts_with("gateway:"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().to_string())
        .ok_or_else(|| "Could not determine default gateway".to_string())
}

/// Get the default network interface name.
fn get_default_interface() -> Result<String, String> {
    let output = cmd("route")
        .args(["-n", "get", "default"])
        .output()
        .map_err(|e| format!("Failed to get default interface: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.lines()
        .find(|l| l.trim().starts_with("interface:"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().to_string())
        .ok_or_else(|| "Could not determine default interface".to_string())
}

/// Convert a CIDR prefix length to a dotted-decimal netmask.
fn prefix_to_mask(prefix: u8) -> String {
    if prefix == 0 {
        return "0.0.0.0".to_string();
    }
    let mask_bits: u32 = !0u32 << (32 - prefix as u32);
    format!(
        "{}.{}.{}.{}",
        (mask_bits >> 24) & 0xFF,
        (mask_bits >> 16) & 0xFF,
        (mask_bits >> 8) & 0xFF,
        mask_bits & 0xFF,
    )
}
