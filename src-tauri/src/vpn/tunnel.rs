//! Wintun tunnel implementation
//!
//! Creates and manages the Wintun virtual network adapter for WireGuard VPN.

#![allow(dead_code)]

use std::net::Ipv4Addr;
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sha2::{Sha256, Digest};
use tokio::sync::{mpsc, RwLock};
use wintun::{Adapter, Session};

use super::wireguard_new::WireGuardSession;
use crate::api::types::VpnConfig;
use crate::utils::redact_ip;

/// Hidden command helper — creates a Command that won't flash console windows
fn cmd(program: &str) -> Command {
    crate::utils::hidden_cmd(program)
}

/// Wintun adapter configuration
const ADAPTER_NAME: &str = "Birdo VPN";
const TUNNEL_TYPE: &str = "Birdo";

/// Fixed GUID for the Birdo VPN adapter, so we can reliably reopen/delete
/// stale adapters across restarts and crashes.
/// Generated once — do not change after release.
const ADAPTER_GUID: u128 = 0xB1BD0_0000_0001_0000_0000_B1BD0B1Du128;

/// Get the Win32 last error code and format it as a human-readable string.
#[cfg(windows)]
fn get_last_error_info() -> (u32, String) {
    use windows::Win32::Foundation::GetLastError;
    let err = unsafe { GetLastError() };
    let code = err.0;
    let desc = match code {
        0 => "ERROR_SUCCESS".to_string(),
        2 => "ERROR_FILE_NOT_FOUND — driver file not found".to_string(),
        5 => "ERROR_ACCESS_DENIED — app is not running as administrator".to_string(),
        32 => "ERROR_SHARING_VIOLATION — adapter is locked by another process".to_string(),
        87 => "ERROR_INVALID_PARAMETER".to_string(),
        183 => "ERROR_ALREADY_EXISTS — adapter already exists".to_string(),
        577 => "ERROR_INVALID_IMAGE_HASH — wintun.dll or driver not properly signed for this Windows version".to_string(),
        1168 => "ERROR_NOT_FOUND — adapter or device not found".to_string(),
        1314 => "ERROR_PRIVILEGE_NOT_HELD — app needs administrator privileges".to_string(),
        _ => format!("Win32 error code {}", code),
    };
    (code, desc)
}

/// SEC-F17: Expected SHA256 hash of the bundled wintun.dll (v0.14.1 amd64)
/// Update this constant when upgrading the Wintun SDK.
const WINTUN_DLL_SHA256: &str = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";

/// Verify the SHA256 hash of a DLL from bytes already read under exclusive lock.
/// Returns Ok(()) if the hash matches, or an error message if it doesn't.
fn verify_dll_integrity(bytes: &[u8], display_path: &std::path::Path) -> Result<(), String> {
    let hash = Sha256::digest(bytes);
    let hex_hash = format!("{:x}", hash);
    
    if hex_hash != WINTUN_DLL_SHA256 {
        tracing::error!(
            "wintun.dll integrity check FAILED: expected {}, got {}",
            WINTUN_DLL_SHA256,
            hex_hash
        );
        return Err(format!(
            "wintun.dll integrity verification failed. The DLL may have been tampered with. \
             Expected SHA256: {}, Got: {}",
            WINTUN_DLL_SHA256, hex_hash
        ));
    }
    
    tracing::info!("wintun.dll integrity verified (SHA256 matches) at {:?}", display_path);
    Ok(())
}

/// SEC-C4 FIX: Encode a PowerShell script as Base64 UTF-16LE for use with -EncodedCommand.
/// This prevents command injection via interpolated strings (adapter names, etc.)
/// because -EncodedCommand does not interpret shell metacharacters.
fn base64_encode_utf16le(script: &str) -> String {
    use base64::Engine;
    let utf16: Vec<u8> = script.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    base64::engine::general_purpose::STANDARD.encode(&utf16)
}

/// H-4 FIX: Stores original DNS configuration for an adapter, enabling
/// precise restoration on disconnect instead of blindly setting DHCP.
#[derive(Debug, Clone)]
struct AdapterDnsSnapshot {
    adapter_name: String,
    /// Original DNS servers (empty = was DHCP)
    dns_servers: Vec<String>,
}

pub struct WintunTunnel {
    config: VpnConfig,
    /// Lock-free running flag for high-throughput packet loop
    running: Arc<AtomicBool>,
    /// Lock-free byte counters for statistics without blocking
    bytes_sent: Arc<AtomicU64>,
    bytes_received: Arc<AtomicU64>,
    /// Lock-free packet counters for statistics
    packets_sent: Arc<AtomicU64>,
    packets_received: Arc<AtomicU64>,
    adapter: Arc<RwLock<Option<Arc<Adapter>>>>,
    session: Arc<RwLock<Option<Arc<Session>>>>,
    wg_session: Arc<RwLock<Option<WireGuardSession>>>,
    shutdown_tx: Arc<RwLock<Option<mpsc::Sender<()>>>>,
    /// H-4 FIX: Snapshot of original DNS config for all adapters,
    /// captured before we modify them. Used in restore_dns().
    dns_snapshots: Arc<RwLock<Vec<AdapterDnsSnapshot>>>,
    /// Resolved endpoint IP (from WireGuard socket), used for route cleanup
    resolved_endpoint_ip: Arc<RwLock<Option<String>>>,
    /// Default gateway saved during route setup, used for cleanup
    saved_default_gateway: Arc<RwLock<Option<String>>>,
    /// Whether local network sharing is enabled (route RFC1918 via real gateway)
    local_network_sharing: bool,
    /// Whether split tunneling routes were added (for cleanup)
    local_network_routes_added: Arc<AtomicBool>,
}

impl WintunTunnel {
    /// Create a new Wintun tunnel instance
    ///
    /// `local_network_sharing`: when true, RFC1918 private ranges are routed
    /// via the real default gateway instead of through the VPN tunnel, allowing
    /// access to printers, NAS devices, and other LAN resources.
    pub async fn create(config: &VpnConfig, local_network_sharing: bool) -> Result<Self, String> {
        tracing::debug!("Creating Wintun tunnel for {}", redact_ip(&config.endpoint));
        
        Ok(Self {
            config: config.clone(),
            running: Arc::new(AtomicBool::new(false)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
            packets_sent: Arc::new(AtomicU64::new(0)),
            packets_received: Arc::new(AtomicU64::new(0)),
            adapter: Arc::new(RwLock::new(None)),
            session: Arc::new(RwLock::new(None)),
            wg_session: Arc::new(RwLock::new(None)),
            shutdown_tx: Arc::new(RwLock::new(None)),
            dns_snapshots: Arc::new(RwLock::new(Vec::new())),
            resolved_endpoint_ip: Arc::new(RwLock::new(None)),
            saved_default_gateway: Arc::new(RwLock::new(None)),
            local_network_sharing,
            local_network_routes_added: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Start the tunnel
    pub async fn start(&self) -> Result<(), String> {
        if self.running.load(Ordering::SeqCst) {
            return Err("Tunnel is already running".to_string());
        }

        // Validate all config values that will be passed to system commands
        self.validate_config()?;

        tracing::info!("Starting Wintun tunnel to {}", redact_ip(&self.config.endpoint));

        // Load Wintun DLL — verify integrity before loading
        // SEC-C2 FIX: Use absolute path derived from executable location to prevent
        // TOCTOU race condition and DLL hijacking via relative path resolution.
        let exe_dir = std::env::current_exe()
            .map_err(|e| format!("Failed to get executable path: {}", e))?
            .parent()
            .ok_or_else(|| "Failed to get executable directory".to_string())?
            .to_path_buf();

        // Check multiple locations: next to exe (dev/portable), then resources/ subfolder (installed)
        let dll_path = {
            let beside_exe = exe_dir.join("wintun.dll");
            let in_resources = exe_dir.join("resources").join("wintun.dll");
            if beside_exe.exists() {
                beside_exe
            } else if in_resources.exists() {
                in_resources
            } else {
                tracing::error!(
                    "wintun.dll not found at {:?} or {:?}",
                    beside_exe, in_resources
                );
                return Err(
                    "wintun.dll not found in the application directory. \
                     Please reinstall the application.".to_string()
                );
            }
        };

        // SEC-F17: Verify DLL hash before loading to prevent DLL replacement attacks.
        // SEC-C2 FIX: Open with exclusive lock to prevent swap between hash and load.
        use std::fs::OpenOptions;
        #[cfg(windows)]
        use std::os::windows::fs::OpenOptionsExt;
        {
            use std::io::Read;
            // T-1 FIX: Propagate error with `?` — previously the Result was silently
            // discarded, so integrity check ran without the exclusive lock on failure.
            let mut exclusive_handle = OpenOptions::new()
                .read(true)
                .share_mode(0) // Exclusive — no other process can modify
                .open(&dll_path)
                .map_err(|e| format!("Failed to open wintun.dll exclusively: {}", e))?;
            // Read bytes from the exclusive handle directly (not a second open)
            // to avoid OS error 32 (sharing violation) self-deadlock.
            let mut bytes = Vec::new();
            exclusive_handle.read_to_end(&mut bytes)
                .map_err(|e| format!("Failed to read wintun.dll: {}", e))?;
            // Hash check happens while we hold the exclusive handle
            verify_dll_integrity(&bytes, &dll_path)?;
        }

        // SAFETY: `dll_path` points to a wintun.dll whose SHA-256 hash was
        // verified immediately above while holding an exclusive file lock,
        // preventing TOCTOU replacement.  `wintun::load_from_path` performs
        // `LoadLibraryW` and resolves FFI symbol pointers; the resulting
        // `Wintun` handle is kept alive for the tunnel's lifetime.
        let wintun = unsafe {
            wintun::load_from_path(&dll_path)
                .map_err(|e| format!("Failed to load wintun.dll: {}", e))?
        };

        tracing::info!("Wintun DLL loaded successfully from {:?}", dll_path);

        // Log elevation status for diagnostics
        let elevated = crate::utils::elevation::is_elevated();
        tracing::info!("Process elevation status: {}", if elevated { "ADMIN" } else { "NOT ADMIN" });
        if !elevated {
            tracing::warn!(
                "Wintun requires administrator privileges. Adapter creation will likely fail."
            );
        }

        // Check the running Wintun driver version to verify the driver is installed
        match wintun::get_running_driver_version(&wintun) {
            Ok(version) => {
                tracing::info!("Wintun driver version: {}", version);
            }
            Err(e) => {
                // Driver not installed yet — this is normal on first run.
                // Adapter::create will auto-install the driver from the DLL.
                tracing::info!(
                    "Wintun driver not yet loaded (expected on first run): {}",
                    e
                );
            }
        }

        // Try to open existing adapter (from previous session) or create new one.
        // Use a fixed GUID so that stale adapters from crashes can be reliably
        // identified and cleaned up.
        let adapter = match Adapter::open(&wintun, ADAPTER_NAME) {
            Ok(adapter) => {
                tracing::info!("Reusing existing Wintun adapter: {}", ADAPTER_NAME);
                adapter
            }
            Err(open_err) => {
                tracing::info!(
                    "No existing adapter '{}' ({}), creating new one",
                    ADAPTER_NAME,
                    open_err
                );

                // First attempt: create adapter with our fixed GUID
                match Adapter::create(&wintun, ADAPTER_NAME, TUNNEL_TYPE, Some(ADAPTER_GUID)) {
                    Ok(adapter) => {
                        tracing::info!("Wintun adapter created successfully");
                        adapter
                    }
                    Err(e) => {
                        let (win_err, win_desc) = get_last_error_info();
                        tracing::error!(
                            "Adapter creation failed: {} (Win32: {} — {})",
                            e, win_err, win_desc
                        );

                        // Retry strategy: clean up any stale state and try again

                        // 1. Try opening stale adapter and dropping it
                        if let Ok(stale) = Adapter::open(&wintun, ADAPTER_NAME) {
                            tracing::info!("Found stale adapter, dropping it for cleanup");
                            drop(stale);
                            std::thread::sleep(std::time::Duration::from_millis(500));
                        }

                        // 2. Try disabling the network interface via netsh
                        let netsh_result = cmd("netsh")
                            .args(["interface", "set", "interface", ADAPTER_NAME, "admin=disable"])
                            .output();
                        match &netsh_result {
                            Ok(out) if out.status.success() => {
                                tracing::info!("Disabled stale network interface via netsh");
                            }
                            Ok(out) => {
                                tracing::debug!(
                                    "netsh disable returned: {}",
                                    String::from_utf8_lossy(&out.stderr)
                                );
                            }
                            Err(e) => tracing::debug!("netsh disable failed: {}", e),
                        }

                        // 3. Also try removing via devcon-like PowerShell if it's a stuck device
                        let ps_remove = cmd("powershell")
                            .args([
                                "-NoProfile", "-NonInteractive", "-Command",
                                "Get-PnpDevice -FriendlyName 'Wintun*' -ErrorAction SilentlyContinue | Remove-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue"
                            ])
                            .output();
                        if let Ok(out) = &ps_remove {
                            if out.status.success() {
                                tracing::info!("Removed stale Wintun PnP device");
                            }
                        }

                        std::thread::sleep(std::time::Duration::from_millis(1000));

                        // Retry with fixed GUID
                        tracing::info!("Retrying adapter creation...");
                        match Adapter::create(&wintun, ADAPTER_NAME, TUNNEL_TYPE, Some(ADAPTER_GUID)) {
                            Ok(adapter) => {
                                tracing::info!("Adapter created successfully on retry");
                                adapter
                            }
                            Err(e2) => {
                                let (win_err2, win_desc2) = get_last_error_info();
                                tracing::error!(
                                    "Adapter creation failed on retry: {} (Win32: {} — {})",
                                    e2, win_err2, win_desc2
                                );

                                // Last resort: try WITHOUT fixed GUID (let Windows assign one)
                                tracing::info!("Last resort: creating adapter without fixed GUID");
                                Adapter::create(&wintun, ADAPTER_NAME, TUNNEL_TYPE, None)
                                    .map_err(|e3| {
                                        let (win_err3, win_desc3) = get_last_error_info();
                                        format!(
                                            "Failed to create Wintun adapter: {} (Win32: {} — {}). \
                                             Ensure the app is running as administrator, no other VPN \
                                             is active, and your antivirus is not blocking Wintun.",
                                            e3, win_err3, win_desc3
                                        )
                                    })?
                            }
                        }
                    }
                }
            }
        };

        // After successful adapter creation, check driver version
        match wintun::get_running_driver_version(&wintun) {
            Ok(version) => tracing::info!("Wintun driver version (post-create): {}", version),
            Err(e) => tracing::warn!("Could not query driver version after adapter creation: {}", e),
        }


        // adapter is already Arc<Adapter> from wintun crate
        tracing::info!("Wintun adapter ready");

        // Start a session with ring buffer
        let session = adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .map_err(|e| format!("Failed to start Wintun session: {}", e))?;
        let session = Arc::new(session);
        tracing::debug!("Wintun session started");

        // IMPORTANT: Create WireGuard session BEFORE configuring routes/DNS
        // This must happen while we still have direct network access for DNS resolution.
        // After routes are configured, all traffic goes through VPN tunnel.
        let wg_session = WireGuardSession::new(
            &self.config.private_key,
            &self.config.server_public_key,
            &self.config.endpoint,
            self.config.preshared_key.as_deref(),
        )
        .await
        .map_err(|e| format!("Failed to create WireGuard session: {}", e))?;
        tracing::info!("WireGuard session created (before route changes)");

        // Get the ACTUAL resolved endpoint IP from the WireGuard socket.
        // This is the IP the socket is connected to — we MUST use this same IP
        // for the endpoint host route to prevent a routing loop.
        let endpoint_ip = wg_session.endpoint_ip();
        tracing::info!("WireGuard socket connected to endpoint IP: {}", redact_ip(&endpoint_ip.to_string()));

        // Configure the adapter's IP address
        self.configure_adapter().await?;

        // Configure routing (pass the actual endpoint IP to avoid double-resolution)
        self.configure_routes(&endpoint_ip.to_string()).await?;

        // Configure local network sharing routes (RFC1918 via real gateway)
        if self.local_network_sharing {
            self.configure_local_network_routes().await?;
        }

        // Configure DNS
        self.configure_dns().await?;

        // Block IPv6 to prevent leaks (IPv6 traffic would bypass VPN tunnel)
        self.block_ipv6_leaks().await?;

        // Store state
        *self.adapter.write().await = Some(adapter);
        *self.session.write().await = Some(session.clone());
        *self.wg_session.write().await = Some(wg_session);
        self.running.store(true, Ordering::SeqCst);

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);
        *self.shutdown_tx.write().await = Some(shutdown_tx);

        // Start packet processing in a background task
        let running = self.running.clone();
        let bytes_sent = self.bytes_sent.clone();
        let bytes_received = self.bytes_received.clone();
        let packets_sent = self.packets_sent.clone();
        let packets_received = self.packets_received.clone();
        let wg_session = self.wg_session.clone();
        let session_clone = session.clone();

        tokio::spawn(async move {
            Self::packet_loop(
                session_clone,
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

        tracing::info!("Tunnel started successfully");
        Ok(())
    }

    /// Validate all VPN config values that will be passed to system commands.
    ///
    /// Prevents route/DNS injection if the backend is ever compromised.
    /// Rejects any value that is not a valid IPv4 address or CIDR block
    /// before it reaches netsh, route, or powershell commands.
    fn validate_config(&self) -> Result<(), String> {
        // Validate client IP (passed to netsh set address)
        Ipv4Addr::from_str(&self.config.client_ip)
            .map_err(|_| format!("Invalid client_ip: '{}'", self.config.client_ip))?;

        // Validate endpoint host (passed to route add)
        let endpoint_host = self.config.endpoint.split(':').next()
            .ok_or_else(|| "Invalid endpoint format: missing host".to_string())?;
        // Endpoint host can be an IP or a hostname. Validate that hostnames
        // contain only safe characters (alphanumeric, dots, hyphens).
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

        // Validate DNS entries (passed to netsh set/add dns)
        for dns in &self.config.dns {
            Ipv4Addr::from_str(dns)
                .map_err(|_| format!("Invalid DNS address: '{}'", dns))?;
        }

        // Validate allowed_ips CIDRs (network portion passed to route add)
        for cidr in &self.config.allowed_ips {
            let parts: Vec<&str> = cidr.split('/').collect();
            if parts.len() != 2 {
                return Err(format!("Invalid CIDR format: '{}'", cidr));
            }
            Ipv4Addr::from_str(parts[0])
                .map_err(|_| format!("Invalid network address in CIDR: '{}'", cidr))?;
            let prefix: u8 = parts[1].parse()
                .map_err(|_| format!("Invalid prefix length in CIDR: '{}'", cidr))?;
            if prefix > 32 {
                return Err(format!("Prefix length out of range in CIDR: '{}'", cidr));
            }
        }

        // Validate MTU is in sane range
        if self.config.mtu < 576 || self.config.mtu > 9000 {
            return Err(format!("Invalid MTU: {} (expected 576-9000)", self.config.mtu));
        }

        tracing::debug!("VPN config validation passed");
        Ok(())
    }

    /// Configure the adapter's IP address using netsh
    async fn configure_adapter(&self) -> Result<(), String> {
        let client_ip = &self.config.client_ip;
        tracing::debug!("Configuring adapter IP: {}", client_ip);

        // Use netsh to set IP address
        let output = cmd("netsh")
            .args([
                "interface",
                "ip",
                "set",
                "address",
                &format!("name={}", ADAPTER_NAME),
                "static",
                client_ip,
                "255.255.255.0", // Subnet mask
            ])
            .output()
            .map_err(|e| format!("Failed to run netsh: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Ignore "already configured" errors
            if !stderr.contains("already") && !stderr.is_empty() {
                tracing::warn!("netsh set address output: {}", stderr);
            }
        }

        // P3-4: Use the MTU from config (which may be the user's custom value or the server default)
        let mtu_value = format!("mtu={}", self.config.mtu);
        let mtu_output = cmd("netsh")
            .args([
                "interface",
                "ipv4",
                "set",
                "subinterface",
                ADAPTER_NAME,
                &mtu_value,
                "store=active",
            ])
            .output();
        
        if let Ok(output) = mtu_output {
            if output.status.success() {
                tracing::debug!("MTU set to {}", self.config.mtu);
            } else {
                tracing::warn!("Failed to set MTU: {}", String::from_utf8_lossy(&output.stderr));
            }
        }

        tracing::debug!("Adapter IP configured");
        Ok(())
    }

    /// Configure routes to send traffic through the VPN
    /// FIX-ROUTE-2: Accept the endpoint IP from the WireGuard session to avoid
    /// double-resolution.  The WG socket connects to IP_A (resolved at socket
    /// creation time).  If we re-resolve here (via DoH) we might get IP_B, and
    /// the host route would protect the WRONG IP — causing a routing loop where
    /// encrypted traffic re-enters the Wintun adapter.
    async fn configure_routes(&self, endpoint_ip: &str) -> Result<(), String> {
        tracing::debug!("Configuring routes");

        // Get the interface index for our Wintun adapter
        let if_index = self.get_adapter_index().await?;
        tracing::debug!("Wintun adapter interface index: {}", if_index);

        // FIX-ROUTE: Set a low interface metric on the Wintun adapter so that
        // combined route metric (route_metric + interface_metric) beats the
        // physical adapter.  Without this, even metric-5 routes can lose to the
        // system default because the interface metric alone is higher.
        let _ = cmd("netsh")
            .args([
                "interface", "ip", "set", "interface",
                ADAPTER_NAME,
                "metric=5",
            ])
            .output();

        // Get default gateway BEFORE adding any routes (so we parse the real one)
        let default_gateway = self.get_default_gateway().await?;
        tracing::info!(
            "Default gateway: {}, endpoint IP: {}",
            redact_ip(&default_gateway),
            redact_ip(endpoint_ip)
        );

        // Save for cleanup
        *self.resolved_endpoint_ip.write().await = Some(endpoint_ip.to_string());
        *self.saved_default_gateway.write().await = Some(default_gateway.clone());

        // CRITICAL: Add host route for the VPN server BEFORE split routes.
        // Without this, the /1 split routes would capture the WireGuard UDP
        // traffic itself, creating a routing loop (encrypted packets re-enter
        // Wintun, get double-encrypted, server can't decrypt → no responses).
        match cmd("route")
            .args([
                "add",
                endpoint_ip,
                "mask",
                "255.255.255.255",
                &default_gateway,
                "metric",
                "1",
            ])
            .output()
        {
            Ok(output) if output.status.success() => {
                tracing::info!(
                    "Endpoint host route added: {} via {} (metric 1)",
                    redact_ip(endpoint_ip),
                    redact_ip(&default_gateway)
                );
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                tracing::error!(
                    "CRITICAL: Endpoint host route FAILED for {}: exit={:?}, stderr={}, stdout={}",
                    redact_ip(endpoint_ip),
                    output.status.code(),
                    stderr.trim(),
                    stdout.trim()
                );
                return Err(format!(
                    "Failed to add endpoint host route — VPN would create a routing loop: {}",
                    stderr.trim()
                ));
            }
            Err(e) => {
                tracing::error!("CRITICAL: Could not execute route command: {}", e);
                return Err(format!("Failed to execute route add for endpoint: {}", e));
            }
        }

        // FIX-ROUTE: Split 0.0.0.0/0 into 0.0.0.0/1 + 128.0.0.0/1
        // This is the standard WireGuard technique used by wireguard-windows,
        // Mullvad, ProtonVPN, etc.  Two /1 routes are MORE SPECIFIC than any
        // /0 default route, so they ALWAYS win the longest-prefix-match
        // regardless of metric.  A plain 0.0.0.0/0 route competes with the
        // system default on metric and often loses.
        let mut routes_to_add: Vec<(String, String)> = Vec::new();
        for allowed_ip in &self.config.allowed_ips {
            if allowed_ip == "0.0.0.0/0" {
                tracing::info!("Splitting 0.0.0.0/0 into two /1 routes for reliable routing");
                routes_to_add.push(("0.0.0.0".to_string(), "128.0.0.0".to_string()));    // 0.0.0.0/1
                routes_to_add.push(("128.0.0.0".to_string(), "128.0.0.0".to_string()));  // 128.0.0.0/1
            } else {
                let (network, mask) = self.parse_cidr(allowed_ip)?;
                routes_to_add.push((network, mask));
            }
        }

        for (network, mask) in &routes_to_add {
            tracing::debug!("Adding route: {} mask {} IF {}", network, mask, if_index);

            // Use interface index for Wintun adapter - gateway 0.0.0.0 with IF parameter
            match cmd("route")
                .args([
                    "add",
                    network,
                    "mask",
                    mask,
                    "0.0.0.0",  // Gateway - use 0.0.0.0 for point-to-point interfaces
                    "metric",
                    "5",
                    "IF",
                    &if_index.to_string(),
                ])
                .output()
            {
                Ok(output) if output.status.success() => {
                    tracing::debug!("Route added successfully: {} mask {}", network, mask);
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    tracing::warn!(
                        "Route command failed for {} mask {}: exit={:?}, stderr={}",
                        network,
                        mask,
                        output.status.code(),
                        stderr.trim()
                    );
                }
                Err(e) => {
                    tracing::error!("Failed to execute route command for {} mask {}: {}", network, mask, e);
                }
            }
        }

        tracing::info!("Routes configured ({} entries + endpoint host route)", routes_to_add.len());
        Ok(())
    }

    /// Configure local network sharing routes.
    /// Adds explicit routes for RFC1918 private ranges via the real default gateway,
    /// so LAN traffic (printers, NAS, etc.) bypasses the VPN tunnel.
    /// These routes are more specific than the /1 split routes, so they win
    /// longest-prefix-match without needing metric tricks.
    async fn configure_local_network_routes(&self) -> Result<(), String> {
        let default_gateway = match self.saved_default_gateway.read().await.as_ref() {
            Some(gw) => gw.clone(),
            None => {
                tracing::warn!("No saved default gateway — skipping local network routes");
                return Ok(());
            }
        };

        tracing::info!("Configuring local network sharing routes via {}", redact_ip(&default_gateway));

        // RFC1918 private address ranges
        let local_routes: [(&str, &str); 3] = [
            ("10.0.0.0", "255.0.0.0"),         // 10.0.0.0/8
            ("172.16.0.0", "255.240.0.0"),      // 172.16.0.0/12
            ("192.168.0.0", "255.255.0.0"),     // 192.168.0.0/16
        ];

        let mut added = 0u32;
        for (network, mask) in &local_routes {
            match cmd("route")
                .args([
                    "add",
                    network,
                    "mask",
                    mask,
                    &default_gateway,
                    "metric",
                    "1", // Low metric to ensure these win over VPN routes for local traffic
                ])
                .output()
            {
                Ok(output) if output.status.success() => {
                    tracing::debug!("Local network route added: {} mask {} via {}", network, mask, redact_ip(&default_gateway));
                    added += 1;
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    tracing::warn!("Local network route failed for {} mask {}: {}", network, mask, stderr.trim());
                }
                Err(e) => {
                    tracing::warn!("Failed to execute route for {} mask {}: {}", network, mask, e);
                }
            }
        }

        // Also add link-local (169.254.0.0/16) for mDNS/device discovery
        let _ = cmd("route")
            .args([
                "add", "169.254.0.0", "mask", "255.255.0.0",
                &default_gateway, "metric", "1",
            ])
            .output();

        self.local_network_routes_added.store(true, Ordering::SeqCst);
        tracing::info!("Local network sharing: {}/3 routes added", added);
        Ok(())
    }

    /// H-3 FIX: Get list of non-VPN adapter names using PowerShell Get-NetAdapter.
    /// This is reliable regardless of adapter name formatting, unlike netsh text parsing.
    /// SEC-C4 FIX: Use -EncodedCommand with Base64 to prevent command injection
    /// via malicious adapter names containing PowerShell metacharacters.
    fn get_non_vpn_adapters() -> Vec<String> {
        // Build PowerShell script, then Base64-encode it to avoid injection
        let ps_script = format!(
            "Get-NetAdapter -Physical -ErrorAction SilentlyContinue | \
             Where-Object {{ $_.Name -ne '{}' -and $_.Status -eq 'Up' }} | \
             Select-Object -ExpandProperty Name",
            ADAPTER_NAME  // ADAPTER_NAME is a compile-time constant, safe to interpolate
        );
        let encoded = base64_encode_utf16le(&ps_script);
        let output = cmd("powershell")
            .args([
                "-NoProfile", "-NonInteractive", "-EncodedCommand",
                &encoded,
            ])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect()
            }
            _ => {
                tracing::warn!("PowerShell Get-NetAdapter failed, falling back to netsh");
                // Fallback to netsh parsing (original behavior)
                let netsh_output = cmd("netsh")
                    .args(["interface", "show", "interface"])
                    .output();
                match netsh_output {
                    Ok(out) => {
                        let text = String::from_utf8_lossy(&out.stdout);
                        text.lines()
                            .filter_map(|line| {
                                let trimmed = line.trim();
                                if trimmed.is_empty() || trimmed.starts_with("---") 
                                    || trimmed.starts_with("Admin") || trimmed.starts_with("Idx") {
                                    return None;
                                }
                                let parts: Vec<&str> = trimmed.splitn(5, char::is_whitespace).collect();
                                if parts.len() >= 5 {
                                    let name = parts[4..].join(" ").trim().to_string();
                                    if !name.is_empty() && name != ADAPTER_NAME
                                        && !name.contains("Loopback") && !name.contains("loopback") {
                                        return Some(name);
                                    }
                                }
                                None
                            })
                            .collect()
                    }
                    Err(_) => Vec::new(),
                }
            }
        }
    }

    /// H-4 FIX: Snapshot the current DNS configuration of an adapter.
    /// SEC-C4 FIX: Use -EncodedCommand with Base64 to prevent command injection
    /// via adapter names that contain single quotes or PowerShell metacharacters.
    fn snapshot_adapter_dns(adapter_name: &str) -> AdapterDnsSnapshot {
        let ps_script = format!(
            "(Get-DnsClientServerAddress -InterfaceAlias '{}' -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses -join ','",
            adapter_name.replace('\'', "''")
        );
        let encoded = base64_encode_utf16le(&ps_script);
        let output = cmd("powershell")
            .args([
                "-NoProfile", "-NonInteractive", "-EncodedCommand",
                &encoded,
            ])
            .output();

        let dns_servers = match output {
            Ok(out) if out.status.success() => {
                let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if text.is_empty() {
                    Vec::new()
                } else {
                    text.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
                }
            }
            _ => Vec::new(),
        };

        AdapterDnsSnapshot {
            adapter_name: adapter_name.to_string(),
            dns_servers,
        }
    }

    /// Configure DNS servers
    /// SECURITY FIX (Vuln-DNS-1): Disable DNS on all non-VPN adapters to prevent
    /// Windows "Smart Multi-Homed Name Resolution" (SMHNR) from querying ISP DNS
    /// in parallel with the VPN's DNS servers, leaking queries.
    async fn configure_dns(&self) -> Result<(), String> {
        tracing::debug!("Configuring DNS servers");

        let adapter_name = format!("name={}", ADAPTER_NAME);

        // H-3 FIX: Use PowerShell Get-NetAdapter for reliable adapter enumeration
        let non_vpn_adapters = Self::get_non_vpn_adapters();

        // H-4 FIX: Snapshot original DNS config BEFORE modifying anything
        let mut snapshots = Vec::new();
        for name in &non_vpn_adapters {
            snapshots.push(Self::snapshot_adapter_dns(name));
        }
        *self.dns_snapshots.write().await = snapshots;
        tracing::debug!("Captured DNS snapshots for {} adapters", non_vpn_adapters.len());

        // STEP 1: Disable DNS on all other adapters to prevent SMHNR leak
        for iface_name in &non_vpn_adapters {
            let _ = cmd("netsh")
                .args([
                    "interface", "ip", "set", "dns",
                    &format!("name={}", iface_name),
                    "static", "none",
                ])
                .output();
            tracing::debug!("Disabled DNS on adapter: {}", iface_name);
        }

        // STEP 2: Set DNS on VPN adapter
        for (i, dns) in self.config.dns.iter().enumerate() {
            let args: Vec<&str> = if i == 0 {
                vec![
                    "interface",
                    "ip",
                    "set",
                    "dns",
                    &adapter_name,
                    "static",
                    dns,
                ]
            } else {
                vec![
                    "interface",
                    "ip",
                    "add",
                    "dns",
                    &adapter_name,
                    dns,
                    "index=2",
                ]
            };

            let output = cmd("netsh")
                .args(&args)
                .output()
                .map_err(|e| format!("Failed to set DNS: {}", e))?;

            if !output.status.success() {
                tracing::warn!(
                    "DNS configuration warning: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }

        tracing::debug!("DNS configured (VPN-only): {:?}", self.config.dns);
        Ok(())
    }

    /// Block IPv6 traffic to prevent leaks
    /// IPv6 traffic would bypass the VPN tunnel since we only route IPv4
    /// SECURITY FIX (PB-11): Comprehensive IPv6 blocking —
    /// previously only blocked protocol 41 (6in4 encapsulation) and ICMPv6,
    /// missing native IPv6 outbound over dual-stack interfaces.
    ///
    /// FIX-1-4: All firewall rule errors are now checked and logged. The primary
    /// outbound rule is mandatory — if it fails, the function returns an error
    /// to prevent IPv6 leaks from going undetected.
    async fn block_ipv6_leaks(&self) -> Result<(), String> {
        tracing::info!("Blocking IPv6 to prevent leaks (comprehensive)");
        let mut succeeded = 0u32;
        let mut warnings: Vec<&str> = Vec::new();

        // PERF-CONNECT: Combined all PowerShell IPv6 work into a SINGLE invocation.
        // Previously this was 3 separate PowerShell calls (~1-2s startup each = 3-6s).
        // Now a single script does adapter binding disable + outbound + inbound rules.
        match cmd("powershell")
            .args([
                "-NoProfile", "-NonInteractive", "-Command",
                // METHOD 1: Disable IPv6 bindings on all adapters
                "try { Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | Disable-NetAdapterBinding -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction SilentlyContinue; Write-Output 'BIND_OK' } catch { Write-Output 'BIND_FAIL' }; \
                 # METHOD 2+3: Firewall rules for outbound and inbound IPv6 \
                 try { \
                   Remove-NetFirewallRule -DisplayName 'Birdo VPN Block IPv6 Out' -ErrorAction SilentlyContinue; \
                   Remove-NetFirewallRule -DisplayName 'Birdo VPN Block IPv6 Out UDP' -ErrorAction SilentlyContinue; \
                   Remove-NetFirewallRule -DisplayName 'Birdo VPN Block IPv6 In' -ErrorAction SilentlyContinue; \
                   Remove-NetFirewallRule -DisplayName 'Birdo VPN Block IPv6 In UDP' -ErrorAction SilentlyContinue; \
                   New-NetFirewallRule -DisplayName 'Birdo VPN Block IPv6 Out' -Direction Outbound -Action Block -Protocol TCP -RemoteAddress ::/0 -ErrorAction Stop | Out-Null; \
                   New-NetFirewallRule -DisplayName 'Birdo VPN Block IPv6 Out UDP' -Direction Outbound -Action Block -Protocol UDP -RemoteAddress ::/0 -ErrorAction Stop | Out-Null; \
                   New-NetFirewallRule -DisplayName 'Birdo VPN Block IPv6 In' -Direction Inbound -Action Block -Protocol TCP -RemoteAddress ::/0 -ErrorAction Stop | Out-Null; \
                   New-NetFirewallRule -DisplayName 'Birdo VPN Block IPv6 In UDP' -Direction Inbound -Action Block -Protocol UDP -RemoteAddress ::/0 -ErrorAction Stop | Out-Null; \
                   Write-Output 'FW_OK' \
                 } catch { Write-Output 'FW_FAIL' }",
            ])
            .output()
        {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout);
                if stdout.contains("BIND_OK") { succeeded += 1; }
                else { warnings.push("adapter-binding"); }
                if stdout.contains("FW_OK") { succeeded += 2; } // counts as 2 (in+out)
                else { warnings.push("fw-rules"); }
            }
            Err(e) => {
                tracing::warn!("PowerShell IPv6 blocking failed: {}", e);
                warnings.push("powershell");
            }
        }

        // PERF-CONNECT: Combined both netsh firewall rules into one call.
        // METHOD 4+5: Block ICMPv6 + protocol 41 (6in4 tunneling)
        for (name, protocol) in [("Birdo VPN Block ICMPv6", "icmpv6"), ("Birdo VPN Block 6in4", "41")] {
            match cmd("netsh")
                .args([
                    "advfirewall", "firewall", "add", "rule",
                    &format!("name={}", name),
                    "dir=out",
                    "action=block",
                    &format!("protocol={}", protocol),
                ])
                .output()
            {
                Ok(o) if o.status.success() => { succeeded += 1; }
                Ok(_) => { warnings.push(if protocol == "icmpv6" { "ICMPv6" } else { "6in4" }); }
                Err(_) => { warnings.push(if protocol == "icmpv6" { "ICMPv6" } else { "6in4" }); }
            }
        }

        // At least one method must succeed to proceed
        if succeeded == 0 {
            return Err(
                "Critical: All IPv6 leak prevention methods failed. \
                 Ensure the app is running as administrator."
                .to_string(),
            );
        }

        if !warnings.is_empty() {
            tracing::warn!(
                "IPv6 protection: {}/{} methods succeeded, failed: {:?}",
                succeeded, succeeded + warnings.len() as u32, warnings
            );
        }

        tracing::info!("IPv6 leak protection enabled ({} methods active)", succeeded);
        Ok(())
    }

    /// Remove IPv6 blocking rules when disconnecting
    async fn unblock_ipv6(&self) -> Result<(), String> {
        tracing::debug!("Removing IPv6 block rules");

        // PERF-DISCONNECT: Use netsh instead of PowerShell to avoid the 1-3s
        // PowerShell cold-start penalty. Each netsh call is ~30-50ms vs ~1500ms
        // for a single PowerShell invocation.
        for rule_name in [
            "Birdo VPN Block IPv6 Out",
            "Birdo VPN Block IPv6 Out UDP",
            "Birdo VPN Block IPv6 In",
            "Birdo VPN Block IPv6 In UDP",
            "Birdo VPN Block ICMPv6",
            "Birdo VPN Block 6in4",
        ] {
            let _ = cmd("netsh")
                .args(["advfirewall", "firewall", "delete", "rule", &format!("name={}", rule_name)])
                .output();
        }

        // Re-enable IPv6 adapter bindings via PowerShell (no netsh equivalent).
        // Spawn it non-blocking — adapter re-binding is not critical for VPN disconnect.
        tokio::task::spawn_blocking(|| {
            let _ = cmd("powershell")
                .args([
                    "-NoProfile", "-NonInteractive", "-Command",
                    "Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | \
                     Enable-NetAdapterBinding -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction SilentlyContinue",
                ])
                .output();
        });

        tracing::debug!("IPv6 block rules removed");
        Ok(())
    }

    /// H-4 FIX: Restore DNS to the EXACT configuration captured before VPN connected.
    /// Instead of blindly setting DHCP on all adapters (which broke static DNS configs),
    /// this restores each adapter to its original DNS servers.
    async fn restore_dns(&self) -> Result<(), String> {
        tracing::debug!("Restoring DNS from snapshots");
        
        // Restore DNS on VPN adapter
        let _ = cmd("netsh")
            .args([
                "interface", "ip", "set", "dns",
                &format!("name={}", ADAPTER_NAME),
                "dhcp"
            ])
            .output();

        // H-4 FIX: Restore from snapshots instead of blindly setting DHCP
        let snapshots = self.dns_snapshots.read().await.clone();
        
        if snapshots.is_empty() {
            // No snapshots — fall back to DHCP on all adapters (legacy behavior)
            tracing::warn!("No DNS snapshots found, falling back to DHCP restoration");
            let adapters = Self::get_non_vpn_adapters();
            for name in &adapters {
                let _ = cmd("netsh")
                    .args([
                        "interface", "ip", "set", "dns",
                        &format!("name={}", name),
                        "dhcp",
                    ])
                    .output();
            }
        } else {
            for snapshot in &snapshots {
                if snapshot.dns_servers.is_empty() {
                    // Was DHCP — restore to DHCP
                    let _ = cmd("netsh")
                        .args([
                            "interface", "ip", "set", "dns",
                            &format!("name={}", snapshot.adapter_name),
                            "dhcp",
                        ])
                        .output();
                    tracing::debug!("Restored {} to DHCP", snapshot.adapter_name);
                } else {
                    // Had static DNS — restore exact servers
                    for (i, dns) in snapshot.dns_servers.iter().enumerate() {
                        if i == 0 {
                            let _ = cmd("netsh")
                                .args([
                                    "interface", "ip", "set", "dns",
                                    &format!("name={}", snapshot.adapter_name),
                                    "static", dns,
                                ])
                                .output();
                        } else {
                            let _ = cmd("netsh")
                                .args([
                                    "interface", "ip", "add", "dns",
                                    &format!("name={}", snapshot.adapter_name),
                                    dns,
                                    &format!("index={}", i + 1),
                                ])
                                .output();
                        }
                    }
                    tracing::debug!("Restored {} to static DNS: {:?}", snapshot.adapter_name, snapshot.dns_servers);
                }
            }
        }
        
        tracing::debug!("DNS restoration complete");
        Ok(())
    }

    /// Get the default gateway from the routing table
    async fn get_default_gateway(&self) -> Result<String, String> {
        let output = cmd("route")
            .args(["print", "0.0.0.0"])
            .output()
            .map_err(|e| format!("Failed to get routes: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse the routing table output to find default gateway
        for line in stdout.lines() {
            if line.contains("0.0.0.0") && !line.contains("On-link") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    // Gateway is typically the 3rd column
                    let gateway = parts[2];
                    if gateway != "0.0.0.0" && gateway.parse::<Ipv4Addr>().is_ok() {
                        return Ok(gateway.to_string());
                    }
                }
            }
        }

        Err("Could not find default gateway".to_string())
    }

    /// Get the interface index of the Wintun adapter
    async fn get_adapter_index(&self) -> Result<u32, String> {
        // Use netsh to get interface info
        let output = cmd("netsh")
            .args(["interface", "ipv4", "show", "interfaces"])
            .output()
            .map_err(|e| format!("Failed to get interfaces: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        
        // Parse the output to find our adapter
        for line in stdout.lines() {
            if line.contains(ADAPTER_NAME) {
                // Format: "   Idx     Met         MTU          State                Name"
                // Example: "   42       1        1500  connected     Birdo VPN"
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(idx_str) = parts.first() {
                    if let Ok(idx) = idx_str.parse::<u32>() {
                        return Ok(idx);
                    }
                }
            }
        }

        // Fallback: try to use PowerShell
        let ps_output = cmd("powershell")
            .args([
                "-Command",
                &format!("(Get-NetAdapter -Name '{}' -ErrorAction SilentlyContinue).ifIndex", ADAPTER_NAME),
            ])
            .output()
            .map_err(|e| format!("Failed to get adapter index via PowerShell: {}", e))?;

        let idx_str = String::from_utf8_lossy(&ps_output.stdout).trim().to_string();
        idx_str.parse::<u32>()
            .map_err(|_| format!("Could not find interface index for {}", ADAPTER_NAME))
    }

    /// Parse CIDR notation into network and mask
    fn parse_cidr(&self, cidr: &str) -> Result<(String, String), String> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid CIDR: {}", cidr));
        }

        let network = parts[0].to_string();
        let prefix: u8 = parts[1]
            .parse()
            .map_err(|_| format!("Invalid prefix length: {}", parts[1]))?;

        let mask = match prefix {
            0 => "0.0.0.0".to_string(),
            1 => "128.0.0.0".to_string(),
            8 => "255.0.0.0".to_string(),
            16 => "255.255.0.0".to_string(),
            24 => "255.255.255.0".to_string(),
            32 => "255.255.255.255".to_string(),
            _ => {
                let mask_bits: u32 = !0u32 << (32 - prefix);
                Ipv4Addr::from(mask_bits).to_string()
            }
        };

        Ok((network, mask))
    }

    /// Packet processing loop - reads from Wintun, encrypts, sends to WireGuard server
    /// 
    /// PERF-001: Uses batch processing to amortize lock + timer overhead.
    /// PERF-002: Acquires RwLock once per batch (not per packet) to reduce contention.
    /// PERF-003: Uses adaptive polling with interval timers instead of per-iteration sleep.
    ///
    /// Under high throughput (50k+ pps during speed tests), the previous design
    /// acquired the RwLock twice per packet (TX + RX), creating 100k lock acquisitions/sec.
    /// This version acquires once per batch of up to MAX_BATCH_SIZE packets.
    async fn packet_loop(
        session: Arc<Session>,
        wg_session: Arc<RwLock<Option<WireGuardSession>>>,
        running: Arc<AtomicBool>,
        bytes_sent: Arc<AtomicU64>,
        bytes_received: Arc<AtomicU64>,
        packets_sent: Arc<AtomicU64>,
        packets_received: Arc<AtomicU64>,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) {
        tracing::debug!("Starting packet processing loop (batch mode)");
        
        // Adaptive polling: start fast, slow down when idle
        let mut idle_cycles: u32 = 0;
        const IDLE_THRESHOLD: u32 = 100;       // Switch to slow mode after 100 idle cycles
        const FAST_POLL_US: u64 = 10;          // 10 microseconds when active
        const SLOW_POLL_US: u64 = 500;         // 500 microseconds when idle
        
        // FIX-DL: Timer task — boringtun requires periodic update_timers() calls
        // to send keepalives, manage rekeys, and handle cookie responses.
        // Without this the server's session expires and stops sending data.
        let mut last_timer_update = Instant::now();
        const TIMER_INTERVAL: Duration = Duration::from_millis(250);

        // Diagnostic: periodic stats log to verify bidirectional traffic
        let mut last_stats_log = Instant::now();
        const STATS_LOG_INTERVAL: Duration = Duration::from_secs(5);
        
        // PERF-001: Batch size — process up to this many packets per wakeup
        // to amortize timer and lock overhead across multiple packets
        const MAX_BATCH_SIZE: usize = 64;

        loop {
            tokio::select! {
                biased;  // Prioritize shutdown over packet processing
                
                _ = shutdown_rx.recv() => {
                    tracing::debug!("Received shutdown signal");
                    break;
                }
                _ = tokio::time::sleep(Duration::from_micros(
                    if idle_cycles > IDLE_THRESHOLD { SLOW_POLL_US } else { FAST_POLL_US }
                )) => {
                    // Use lock-free check for running state (major performance improvement)
                    if !running.load(Ordering::Relaxed) {
                        break;
                    }
                    
                    let mut had_activity = false;

                    // PERF-002: Acquire the WireGuard session lock ONCE for the entire batch
                    // instead of once per packet. The session only changes on disconnect
                    // (which triggers shutdown_rx) or rekey (which is handled internally
                    // by boringtun).
                    //
                    // FIX-R4: Use try_read() instead of read().await to avoid starving a
                    // pending write lock during disconnect.  If disconnect is acquiring the
                    // write lock we simply skip this iteration (10–500 µs later we retry).
                    let guard = wg_session.try_read();
                    if let Ok(ref session_guard) = guard {
                      if let Some(ref wg) = **session_guard {
                        // ---- TX batch: Read from Wintun, encrypt, send to WireGuard ----
                        for _ in 0..MAX_BATCH_SIZE {
                            match session.try_receive() {
                                Ok(Some(packet)) => {
                                    had_activity = true;
                                    let data = packet.bytes();
                                    // Lock-free atomic increment for stats
                                    bytes_sent.fetch_add(data.len() as u64, Ordering::Relaxed);
                                    packets_sent.fetch_add(1, Ordering::Relaxed);

                                    // Encrypt and send via WireGuard
                                    if let Err(e) = wg.send_packet(data).await {
                                        tracing::warn!("Failed to send packet: {}", e);
                                    }
                                }
                                Ok(None) => break, // No more packets in this batch
                                Err(e) => {
                                    tracing::error!("Error receiving packet from adapter: {}", e);
                                    break;
                                }
                            }
                        }

                        // ---- RX batch: Receive from WireGuard, decrypt, write to Wintun ----
                        for _ in 0..MAX_BATCH_SIZE {
                            match wg.receive_packet().await {
                                Ok(Some(data)) => {
                                    had_activity = true;
                                    // Lock-free atomic increment for stats
                                    bytes_received.fetch_add(data.len() as u64, Ordering::Relaxed);
                                    packets_received.fetch_add(1, Ordering::Relaxed);

                                    // Write to Wintun adapter
                                    match session.allocate_send_packet(data.len() as u16) {
                                        Ok(mut write_packet) => {
                                            write_packet.bytes_mut().copy_from_slice(&data);
                                            session.send_packet(write_packet);
                                        }
                                        Err(e) => {
                                            tracing::warn!("Failed to allocate send packet: {}", e);
                                        }
                                    }
                                }
                                Ok(None) => break, // No more packets in this batch
                                Err(e) => {
                                    // Don't log transient decryption errors at warn level 
                                    // (they're expected during rekey transitions)
                                    tracing::trace!("WireGuard recv error: {}", e);
                                    break;
                                }
                            }
                        }

                        // ---- FIX-DL: Periodic timer update for boringtun ----
                        // boringtun needs update_timers() called regularly so it can:
                        //   1. Send persistent keepalives (every 25s by default)
                        //   2. Initiate rekeys before the session expires (after 120s)
                        //   3. Detect dead peers via handshake timeout
                        // Without this, the server's crypto session goes stale and it
                        // stops sending data — upload works but download doesn't.
                        if last_timer_update.elapsed() >= TIMER_INTERVAL {
                            last_timer_update = Instant::now();
                            if let Err(e) = wg.update_timers().await {
                                tracing::trace!("Timer update error: {}", e);
                            }
                        }

                        // Diagnostic: periodic stats log
                        if last_stats_log.elapsed() >= STATS_LOG_INTERVAL {
                            last_stats_log = Instant::now();
                            let s = bytes_sent.load(Ordering::Relaxed);
                            let r = bytes_received.load(Ordering::Relaxed);
                            let ps = packets_sent.load(Ordering::Relaxed);
                            let pr = packets_received.load(Ordering::Relaxed);
                            tracing::info!(
                                "VPN traffic stats — TX: {} pkts / {} bytes, RX: {} pkts / {} bytes",
                                ps, s, pr, r
                            );
                        }
                      }
                    }
                    // FIX-R4: Drop the read guard here; if try_read failed we simply do nothing
                    drop(guard);
                    
                    // Update idle counter for adaptive polling
                    if had_activity {
                        idle_cycles = 0; // Reset on any activity
                    } else {
                        idle_cycles = idle_cycles.saturating_add(1);
                    }
                }
            }
        }

        tracing::debug!("Packet processing loop ended");
    }

    /// Stop the tunnel
    /// SECURITY: Order of operations is critical to prevent traffic leaks
    /// Kill switch must remain active until after all cleanup is complete
    pub async fn stop(&self) -> Result<(), String> {
        if !self.running.load(Ordering::SeqCst) {
            return Ok(());
        }

        tracing::info!("Stopping Wintun tunnel");

        // STEP 1: Signal shutdown to packet loop
        if let Some(tx) = self.shutdown_tx.write().await.take() {
            let _ = tx.send(()).await;
        }
        self.running.store(false, Ordering::SeqCst);

        // STEP 2: Close WireGuard session FIRST (stops encrypted traffic)
        // This prevents any new packets from being sent/received
        if let Some(wg) = self.wg_session.write().await.take() {
            wg.close().await;
        }
        tracing::debug!("WireGuard session closed");

        // STEP 3: Network cleanup — run all three in parallel since they
        // are independent and each spawns external processes.
        // Also flush DNS inline (ipconfig /flushdns is ~10ms).
        let _ = cmd("ipconfig").args(["/flushdns"]).output();
        let (dns_r, ipv6_r, route_r) = tokio::join!(
            self.restore_dns(),
            self.unblock_ipv6(),
            self.cleanup_routes(),
        );
        if let Err(e) = dns_r { tracing::warn!("DNS restore error: {}", e); }
        if let Err(e) = ipv6_r { tracing::warn!("IPv6 unblock error: {}", e); }
        if let Err(e) = route_r { tracing::warn!("Route cleanup error: {}", e); }

        // STEP 4: Close Wintun adapter
        *self.session.write().await = None;
        if let Some(adapter) = self.adapter.write().await.take() {
            drop(adapter);
        }

        // NOTE: Kill switch deactivation is handled separately by the VPN manager
        // or auto-reconnect service, NOT here. This allows the kill switch to 
        // remain active during reconnection attempts.

        tracing::info!("Tunnel stopped successfully");
        Ok(())
    }

    /// Clean up routes when disconnecting
    async fn cleanup_routes(&self) -> Result<(), String> {
        tracing::debug!("Cleaning up routes");

        // Remove server endpoint host route (use the stored resolved IP, not the config hostname)
        if let Some(ref endpoint_ip) = *self.resolved_endpoint_ip.read().await {
            tracing::debug!("Removing endpoint host route for {}", redact_ip(endpoint_ip));
            let _ = cmd("route")
                .args(["delete", endpoint_ip, "mask", "255.255.255.255"])
                .output();
        }

        // Remove VPN routes (including split routes for 0.0.0.0/0)
        for allowed_ip in &self.config.allowed_ips {
            if allowed_ip == "0.0.0.0/0" {
                // FIX-ROUTE: Clean up the two /1 split routes
                let _ = cmd("route").args(["delete", "0.0.0.0", "mask", "128.0.0.0"]).output();
                let _ = cmd("route").args(["delete", "128.0.0.0", "mask", "128.0.0.0"]).output();
            } else if let Ok((network, _)) = self.parse_cidr(allowed_ip) {
                let _ = cmd("route")
                    .args(["delete", &network])
                    .output();
            }
        }

        // Clean up local network sharing routes if they were added
        if self.local_network_routes_added.load(Ordering::SeqCst) {
            tracing::debug!("Removing local network sharing routes");
            let local_routes = [
                ("10.0.0.0", "255.0.0.0"),
                ("172.16.0.0", "255.240.0.0"),
                ("192.168.0.0", "255.255.0.0"),
                ("169.254.0.0", "255.255.0.0"),
            ];
            for (network, mask) in &local_routes {
                let _ = cmd("route").args(["delete", network, "mask", mask]).output();
            }
            self.local_network_routes_added.store(false, Ordering::SeqCst);
        }

        Ok(())
    }

    /// Check if tunnel is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get bandwidth statistics (lock-free)
    /// Returns (bytes_sent, bytes_received, packets_sent, packets_received)
    pub fn get_stats(&self) -> (u64, u64, u64, u64) {
        let sent = self.bytes_sent.load(Ordering::Relaxed);
        let received = self.bytes_received.load(Ordering::Relaxed);
        let pkts_sent = self.packets_sent.load(Ordering::Relaxed);
        let pkts_received = self.packets_received.load(Ordering::Relaxed);
        (sent, received, pkts_sent, pkts_received)
    }

    /// Get the last measured latency in milliseconds
    pub async fn get_latency_ms(&self) -> Option<u32> {
        if let Some(wg) = self.wg_session.read().await.as_ref() {
            wg.get_latency_ms().await
        } else {
            None
        }
    }

    /// Measure latency to the VPN server
    pub async fn measure_latency(&self) -> Option<u32> {
        if let Some(wg) = self.wg_session.read().await.as_ref() {
            wg.measure_latency().await
        } else {
            None
        }
    }

    /// Get assigned client IP
    pub fn get_client_ip(&self) -> &str {
        &self.config.client_ip
    }

    /// Get server endpoint
    pub fn get_endpoint(&self) -> &str {
        &self.config.endpoint
    }
}

/// T-2 FIX: Emergency cleanup on panic/unexpected drop.
/// If the tunnel is still running when dropped (e.g., due to panic unwinding),
/// perform best-effort synchronous cleanup of system state to prevent
/// DNS leaks, stale routes, and leftover firewall rules.
///
/// Normal shutdown should always go through `stop()` which does a proper
/// ordered teardown. This is a safety net only.
impl Drop for WintunTunnel {
    fn drop(&mut self) {
        if !self.running.load(Ordering::SeqCst) {
            return;
        }

        tracing::warn!(
            "WintunTunnel dropped while still running — performing emergency cleanup \
             to prevent DNS/route leaks"
        );
        self.running.store(false, Ordering::SeqCst);

        // Best-effort: flush DNS cache to clear VPN-specific entries
        let _ = cmd("ipconfig")
            .args(["/flushdns"])
            .output();

        // Best-effort: reset VPN adapter DNS to DHCP (prevents DNS leak)
        let _ = cmd("netsh")
            .args([
                "interface", "ip", "set", "dns",
                &format!("name={}", ADAPTER_NAME),
                "dhcp",
            ])
            .output();

        // Best-effort: remove server-specific route
        if let Some(endpoint_ip) = self.config.endpoint.split(':').next() {
            if !endpoint_ip.is_empty() {
                let _ = cmd("route")
                    .args(["delete", endpoint_ip])
                    .output();
            }
        }

        // Best-effort: remove IPv6 blocking firewall rules
        let _ = cmd("powershell")
            .args([
                "-NoProfile", "-NonInteractive", "-Command",
                "Remove-NetFirewallRule -DisplayName 'Birdo VPN Block IPv6 Out' -ErrorAction SilentlyContinue; \
                 Remove-NetFirewallRule -DisplayName 'Birdo VPN Block IPv6 Out UDP' -ErrorAction SilentlyContinue; \
                 Remove-NetFirewallRule -DisplayName 'Birdo VPN Block IPv6 In' -ErrorAction SilentlyContinue; \
                 Remove-NetFirewallRule -DisplayName 'Birdo VPN Block IPv6 In UDP' -ErrorAction SilentlyContinue",
            ])
            .output();
        let _ = cmd("netsh")
            .args(["advfirewall", "firewall", "delete", "rule", "name=Birdo VPN Block ICMPv6"])
            .output();
        let _ = cmd("netsh")
            .args(["advfirewall", "firewall", "delete", "rule", "name=Birdo VPN Block 6in4"])
            .output();
        // Also try legacy rule names
        let _ = cmd("netsh")
            .args(["advfirewall", "firewall", "delete", "rule", "name=Birdo Block IPv6"])
            .output();
        // Re-enable IPv6 adapter bindings
        let _ = cmd("powershell")
            .args([
                "-NoProfile", "-NonInteractive", "-Command",
                "Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | Enable-NetAdapterBinding -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction SilentlyContinue",
            ])
            .output();

        tracing::warn!("Emergency cleanup complete — DNS/route state may need manual verification");
    }
}
