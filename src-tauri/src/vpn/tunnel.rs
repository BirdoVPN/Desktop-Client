//! Wintun tunnel implementation
//!
//! Creates and manages the Wintun virtual network adapter for WireGuard VPN.

#![allow(dead_code)]

use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, RwLock};
use wintun::{Adapter, Session};

use super::wireguard_new::WireGuardSession;
use crate::api::types::VpnConfig;
use crate::utils::redact_ip;

/// Hidden command helper — creates a Command that won't flash console windows
fn cmd(program: &str) -> Command {
    crate::utils::hidden_cmd(program)
}

/// Read the lowest-metric IPv4 default-route next hop via the IP Helper API
/// (`GetIpForwardTable2`). Returns `None` on any failure so the caller can fall
/// back to parsing `route print`. Native + instant; no subprocess.
#[cfg(windows)]
fn default_gateway_native() -> Option<String> {
    default_route_native().map(|(gw, _idx)| gw.to_string())
}

/// Lowest-metric IPv4 default route: returns `(gateway, physical_interface_index)`
/// via `GetIpForwardTable2`. The interface index is needed to pin the endpoint
/// host route to the physical NIC natively. `None` on any failure.
#[cfg(windows)]
fn default_route_native() -> Option<(Ipv4Addr, u32)> {
    use windows::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIpForwardTable2, MIB_IPFORWARD_TABLE2,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: `table` is a valid out-pointer; on success the OS allocates the
    // table and we release it with `FreeMibTable` below.
    let err = unsafe { GetIpForwardTable2(AF_INET, &mut table) };
    if err.0 != 0 || table.is_null() {
        return None;
    }

    let result = {
        // SAFETY: `table` is non-null and points to a valid table allocated by
        // the OS; `NumEntries` describes the length of the trailing `Table` array.
        let t = unsafe { &*table };
        let rows = unsafe { std::slice::from_raw_parts(t.Table.as_ptr(), t.NumEntries as usize) };
        let mut best: Option<(u32, Ipv4Addr, u32)> = None; // (metric, gateway, if_index)
        for row in rows {
            if row.DestinationPrefix.PrefixLength != 0 {
                continue; // not a default route (0.0.0.0/0)
            }
            // SAFETY: union access — we only read the IPv4 view and verify family.
            let nh = unsafe { row.NextHop.Ipv4 };
            if nh.sin_family != AF_INET {
                continue;
            }
            let o = unsafe { nh.sin_addr.S_un.S_un_b };
            let ip = Ipv4Addr::new(o.s_b1, o.s_b2, o.s_b3, o.s_b4);
            if ip.is_unspecified() {
                continue;
            }
            if best.map_or(true, |(m, _, _)| row.Metric < m) {
                best = Some((row.Metric, ip, row.InterfaceIndex));
            }
        }
        best.map(|(_, ip, idx)| (ip, idx))
    };

    // SAFETY: `table` was allocated by `GetIpForwardTable2` and is non-null.
    unsafe { FreeMibTable(table as *const core::ffi::c_void) };
    result
}

/// Add an IPv4 route natively via `CreateIpForwardEntry2`. `next_hop` 0.0.0.0
/// means on-link (point-to-point, e.g. the Wintun adapter). Returns Err on
/// failure so the caller can fall back to `route.exe`. ERROR_OBJECT_ALREADY_EXISTS
/// is treated as success.
#[cfg(windows)]
fn add_route_native(
    dest: Ipv4Addr,
    prefix_len: u8,
    next_hop: Ipv4Addr,
    if_index: u32,
    metric: u32,
) -> Result<(), String> {
    use windows::Win32::NetworkManagement::IpHelper::{
        CreateIpForwardEntry2, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    let mut row = MIB_IPFORWARD_ROW2::default();
    // SAFETY: fills the row with valid defaults.
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceIndex = if_index;
    row.DestinationPrefix.PrefixLength = prefix_len;
    // Writes to SOCKADDR_INET union fields are safe; octets in network order.
    row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
    row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(dest.octets());
    row.NextHop.Ipv4.sin_family = AF_INET;
    row.NextHop.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(next_hop.octets());
    row.Metric = metric;

    // SAFETY: `row` is fully initialised by InitializeIpForwardEntry + our fields.
    let e = unsafe { CreateIpForwardEntry2(&row) };
    if e.0 != 0 && e.0 != 5010 {
        return Err(format!("CreateIpForwardEntry2 failed: 0x{:08X}", e.0));
    }
    Ok(())
}

/// Assign an IPv6 address to an interface natively (CreateUnicastIpAddressEntry,
/// AF_INET6). Used for dual-stack nodes; Err on failure so the caller can fall
/// back to blocking IPv6.
#[cfg(windows)]
fn set_adapter_ipv6_native(if_index: u32, ip: Ipv6Addr, prefix: u8) -> Result<(), String> {
    use windows::Win32::NetworkManagement::IpHelper::{
        CreateUnicastIpAddressEntry, InitializeUnicastIpAddressEntry, MIB_UNICASTIPADDRESS_ROW,
    };
    use windows::Win32::Networking::WinSock::AF_INET6;

    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    // SAFETY: fills the row with valid defaults.
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceIndex = if_index;
    row.OnLinkPrefixLength = prefix;
    // Writes to the SOCKADDR_INET / IN6_ADDR union fields are safe in Rust.
    row.Address.Ipv6.sin6_family = AF_INET6;
    row.Address.Ipv6.sin6_addr.u.Byte = ip.octets();
    // SAFETY: `row` is fully initialised; InterfaceIndex identifies the adapter.
    let e = unsafe { CreateUnicastIpAddressEntry(&row) };
    if e.0 != 0 && e.0 != 5010 {
        return Err(format!(
            "CreateUnicastIpAddressEntry (v6) failed: 0x{:08X}",
            e.0
        ));
    }
    Ok(())
}

/// Add an IPv6 route natively (CreateIpForwardEntry2, AF_INET6). `:: ` next hop
/// (all-zero) means on-link via the given interface. Err on failure.
#[cfg(windows)]
fn add_route6_native(
    dest: Ipv6Addr,
    prefix_len: u8,
    if_index: u32,
    metric: u32,
) -> Result<(), String> {
    use windows::Win32::NetworkManagement::IpHelper::{
        CreateIpForwardEntry2, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2,
    };
    use windows::Win32::Networking::WinSock::AF_INET6;

    let mut row = MIB_IPFORWARD_ROW2::default();
    // SAFETY: fills the row with valid defaults.
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceIndex = if_index;
    row.DestinationPrefix.PrefixLength = prefix_len;
    row.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
    row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte = dest.octets();
    row.NextHop.Ipv6.sin6_family = AF_INET6; // :: → on-link
    row.Metric = metric;
    // SAFETY: `row` is fully initialised by InitializeIpForwardEntry + our fields.
    let e = unsafe { CreateIpForwardEntry2(&row) };
    if e.0 != 0 && e.0 != 5010 {
        return Err(format!("CreateIpForwardEntry2 (v6) failed: 0x{:08X}", e.0));
    }
    Ok(())
}

/// Set the resolver list on an interface (by adapter GUID) via the native
/// `SetInterfaceDnsSettings` API — instant, no `netsh` subprocess. Returns Err
/// on any failure so the caller can fall back to netsh (DNS is never left unset).
// Clippy: DNS_INTERFACE_SETTINGS is an FFI struct — default-then-assign matches
// the Windows API documentation examples.
#[allow(clippy::field_reassign_with_default)]
#[cfg(windows)]
fn set_dns_native(adapter_guid: u128, servers: &[String]) -> Result<(), String> {
    use windows::core::{GUID, PWSTR};
    use windows::Win32::NetworkManagement::IpHelper::{
        SetInterfaceDnsSettings, DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1,
        DNS_SETTING_NAMESERVER,
    };

    if servers.is_empty() {
        return Err("no DNS servers to set".to_string());
    }

    // SetInterfaceDnsSettings takes a comma-separated nameserver list.
    let ns = servers.join(",");
    let mut ns_w: Vec<u16> = ns.encode_utf16().chain(std::iter::once(0)).collect();

    let mut settings = DNS_INTERFACE_SETTINGS::default();
    settings.Version = DNS_INTERFACE_SETTINGS_VERSION1;
    settings.Flags = DNS_SETTING_NAMESERVER as u64;
    settings.NameServer = PWSTR(ns_w.as_mut_ptr());

    let guid = GUID::from_u128(adapter_guid);
    // SAFETY: `settings` is a fully-initialised struct; `NameServer` points to a
    // NUL-terminated wide buffer that outlives this call.
    let err = unsafe { SetInterfaceDnsSettings(guid, &settings) };
    if err.0 != 0 {
        return Err(format!("SetInterfaceDnsSettings failed: 0x{:08X}", err.0));
    }
    Ok(())
}

/// Set an interface's IPv4 address + MTU natively via the IP Helper API
/// (addressed by interface index, so no cross-crate LUID type concerns).
/// Returns Err on failure so the caller can fall back to netsh.
// Clippy: MIB_* FFI rows must be default-initialised and then populated
// (InitializeUnicastIpAddressEntry fills the row between the two steps).
#[allow(clippy::field_reassign_with_default)]
#[cfg(windows)]
fn set_adapter_ip_mtu_native(if_index: u32, ip: &str, prefix: u8, mtu: u32) -> Result<(), String> {
    use windows::Win32::NetworkManagement::IpHelper::{
        CreateUnicastIpAddressEntry, GetIpInterfaceEntry, InitializeUnicastIpAddressEntry,
        SetIpInterfaceEntry, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    let addr: Ipv4Addr = ip
        .parse()
        .map_err(|_| format!("invalid client IP: {}", ip))?;

    // ── IPv4 unicast address ──
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    // SAFETY: fills the row with valid defaults (DAD state, lifetimes, etc.).
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceIndex = if_index;
    row.OnLinkPrefixLength = prefix;
    // Writing the IPv4 view of the SOCKADDR_INET union (writes to union fields
    // are safe in Rust). Octets stored in network byte order via from_ne_bytes.
    row.Address.Ipv4.sin_family = AF_INET;
    row.Address.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(addr.octets());
    // SAFETY: `row` is fully initialised; InterfaceIndex identifies the adapter.
    let e = unsafe { CreateUnicastIpAddressEntry(&row) };
    // 0 = OK; 5010 = ERROR_OBJECT_ALREADY_EXISTS (same IP from a prior connect).
    if e.0 != 0 && e.0 != 5010 {
        return Err(format!("CreateUnicastIpAddressEntry failed: 0x{:08X}", e.0));
    }

    // ── MTU (read-modify-write the interface row) ──
    let mut irow = MIB_IPINTERFACE_ROW::default();
    irow.Family = AF_INET;
    irow.InterfaceIndex = if_index;
    // SAFETY: Family + InterfaceIndex are set; the call fills the remaining fields.
    let g = unsafe { GetIpInterfaceEntry(&mut irow) };
    if g.0 != 0 {
        return Err(format!("GetIpInterfaceEntry failed: 0x{:08X}", g.0));
    }
    irow.NlMtu = mtu;
    // Required for IPv4: SitePrefixLength must be 0 or SetIpInterfaceEntry rejects it.
    irow.SitePrefixLength = 0;
    // SAFETY: `irow` was populated by GetIpInterfaceEntry; we only adjusted NlMtu.
    let s = unsafe { SetIpInterfaceEntry(&mut irow) };
    if s.0 != 0 {
        return Err(format!("SetIpInterfaceEntry failed: 0x{:08X}", s.0));
    }
    Ok(())
}

/// Wintun adapter configuration
pub(super) const ADAPTER_NAME: &str = "Birdo VPN";
const TUNNEL_TYPE: &str = "Birdo";

/// Fixed GUID for the Birdo VPN adapter, so we can reliably reopen/delete
/// stale adapters across restarts and crashes.
/// Generated once — do not change after release.
#[allow(clippy::unusual_byte_groupings)] // grouping mirrors GUID segment layout
pub(super) const ADAPTER_GUID: u128 = 0xB1BD0_0000_0001_0000_0000_B1BD0B1Du128;

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

    tracing::info!(
        "wintun.dll integrity verified (SHA256 matches) at {:?}",
        display_path
    );
    Ok(())
}

/// SEC-C4 FIX: Encode a PowerShell script as Base64 UTF-16LE for use with -EncodedCommand.
/// This prevents command injection via interpolated strings (adapter names, etc.)
/// because -EncodedCommand does not interpret shell metacharacters.
fn base64_encode_utf16le(script: &str) -> String {
    use base64::Engine;
    let utf16: Vec<u8> = script
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    base64::engine::general_purpose::STANDARD.encode(&utf16)
}

/// H-4 FIX: Stores original DNS configuration for an adapter, enabling
/// precise restoration on disconnect instead of blindly setting DHCP.
///
/// Serialisable because the same record is ALSO written to disk (see
/// `vpn::dns_journal`): the in-memory copy dies with the process, and after a
/// crash nothing can tell a parked adapter from one the user configured
/// `static`-with-no-servers themselves.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct AdapterDnsSnapshot {
    /// Friendly name at record time. A LOG LABEL and a netsh argument, never an
    /// identity: names are user-editable in Network Connections and localised on
    /// a fresh install, so the restore re-resolves the CURRENT name from the GUID
    /// below (I7). Kept because a legacy record has nothing else.
    pub(super) adapter_name: String,
    /// Interface GUID, `{XXXXXXXX-...}` upper-cased — the record key, and the one
    /// identifier that cannot change while the adapter is parked.
    ///
    /// `serde(default)` so a journal written by an older build (which keyed by
    /// name) still reconciles after an upgrade: the machine it describes is a
    /// machine with no resolvers, and refusing to read it would strand exactly
    /// the users this record exists for.
    #[serde(default)]
    pub(super) adapter_guid: String,
    /// Was IPv4 DNS sourced from DHCP before we touched it?
    ///
    /// NOT the same as `dns_servers.is_empty()`, and conflating the two rewrites
    /// other software's network configuration. Measured on a stock Windows 11
    /// machine with no VPN running: VirtualBox Host-Only, the Hyper-V/WSL
    /// vSwitch and the OpenVPN TAP adapter were all `Statically Configured DNS
    /// Servers: None` — static, with no servers — and two of them were Up, so
    /// the machine-state owner enumerates them. Restoring those to DHCP is an
    /// unrequested, elevated change to VirtualBox and Hyper-V networking, on
    /// every clean disconnect.
    pub(super) v4_was_dhcp: bool,
    /// IPv6 twin of `v4_was_dhcp`.
    pub(super) v6_was_dhcp: bool,
    /// Original IPv4 DNS servers (empty = was DHCP)
    pub(super) dns_servers: Vec<String>,
    /// Original IPv6 DNS servers (empty = was DHCP/RA). Snapshotted separately
    /// because the netsh `ip` context is IPv4-only: without this the IPv6
    /// resolvers (usually a link-local from RA/RDNSS) are neither disabled during
    /// the session nor restored afterwards.
    pub(super) dns_servers_v6: Vec<String>,
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
    /// Handle to the packet-processing task. stop() joins this so the task's
    /// Arc<Session> (which keeps the Wintun adapter alive) is dropped BEFORE we
    /// release the adapter — otherwise a server switch fails to recreate the
    /// adapter ("Could not start the VPN network adapter").
    packet_task: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    /// Default gateway saved during route setup, used for the LAN-sharing routes
    saved_default_gateway: Arc<RwLock<Option<String>>>,
    /// Whether local network sharing is enabled (route RFC1918 via real gateway)
    local_network_sharing: bool,
    /// This tunnel's ownership token for the machine state (I1).
    ///
    /// The parked physical-adapter DNS and the installed routes used to live in
    /// this struct, which made every question about them a question about tunnel
    /// lifetime — and tunnel lifetime is what was broken. `Adapter::open`
    /// deliberately reuses one OS adapter, so two tunnels can legitimately exist
    /// over it, and `VpnManager::tunnel` was written by paths that did not
    /// dispose of what they displaced. The orphan's `Drop` then un-parked every
    /// physical NIC and deleted the live tunnel's routes (issue #98).
    ///
    /// So the state lives in `win_machine_state` and this is the only claim on
    /// it. A tunnel whose token is not the current owner mutates NOTHING —
    /// which also replaces the old `dns_modified` / `routes_installed` /
    /// `local_network_routes_added` flags: "did we change anything" is now
    /// answered by the owner, which cannot disagree with itself.
    state_gen: crate::vpn::win_machine_state::Gen,

    /// Is THIS tunnel's session still live, for the DNS park refresh thread
    /// (#99)?
    ///
    /// Deliberately not `running`, and deliberately not ownership. Not
    /// `running`, because it is set only at the very end of `start_inner()` and
    /// the netsh calls before it can take 10-25s on an AV-heavy machine, so the
    /// first tick could observe `false` on a perfectly healthy connect and end
    /// the refresh for the whole session. Not ownership, because ownership
    /// outlives the session whenever an un-park could not be verified — see
    /// `win_machine_state::refresh_live_session`.
    dns_refresh_active: Arc<AtomicBool>,
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
            packet_task: Arc::new(RwLock::new(None)),
            saved_default_gateway: Arc::new(RwLock::new(None)),
            local_network_sharing,
            state_gen: crate::vpn::win_machine_state::next_generation(),
            dns_refresh_active: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Start the tunnel.
    ///
    /// LEAK-2: IPv6 is blocked BEFORE any network setup and stays blocked for the
    /// whole connect window. It used to be blocked as the LAST network step, so
    /// IPv6 egressed the physical NIC throughout DLL load, adapter creation, the
    /// WireGuard handshake and the route/DNS netsh calls — which this module
    /// itself documents as taking 10-25s on AV-heavy machines.
    pub async fn start(&self) -> Result<(), String> {
        if self.running.load(Ordering::SeqCst) {
            return Err("Tunnel is already running".to_string());
        }

        // Validate all config values that will be passed to system commands
        self.validate_config()?;

        // Pre-emptive IPv6 block, installed BEFORE any of start_inner()'s
        // multi-second setup (DLL load, adapter, handshake, route/DNS netsh), so
        // IPv6 cannot egress the physical NIC during the connect window.
        //
        // A FAILED connect must not strand IPv6 blocked with no tunnel. That
        // lift is owned by the manager (VpnManager::connect), which wraps this
        // start() in a timeout and calls lift_ipv6_block_after_failed_connect()
        // on BOTH the error-return and the timeout-cancellation paths — the only
        // two ways start() fails under the manager. A previous RAII guard here
        // also lifted, but from a detached Drop task that raced a subsequent
        // connect's fresh block (removing a live block = the exact leak this
        // guards against); the manager's synchronous lift is the single, race-free
        // mechanism.

        // I1: claim the machine state BEFORE the first mutation, so everything
        // installed from here on is attributable to this generation and nothing
        // else may un-park or delete it. This ADOPTS whatever a previous
        // generation left in force — on a reconnect the manager holds the park
        // and the routes across the gap rather than releasing them into it.
        crate::vpn::win_machine_state::take_ownership(self.state_gen);

        self.block_ipv6_leaks().await?;
        self.start_inner().await
    }

    async fn start_inner(&self) -> Result<(), String> {
        tracing::info!(
            "Starting Wintun tunnel to {}",
            redact_ip(&self.config.endpoint)
        );

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
                    beside_exe,
                    in_resources
                );
                return Err("wintun.dll not found in the application directory. \
                     Please reinstall the application."
                    .to_string());
            }
        };

        // SEC-F17: Verify DLL hash before loading to prevent DLL replacement attacks.
        // SEC-C2 FIX: Open with exclusive lock to prevent swap between hash and load.
        use std::fs::OpenOptions;
        #[cfg(windows)]
        use std::os::windows::fs::OpenOptionsExt;
        // T-1 FIX: Keep exclusive handle open through load_from_path to eliminate
        // TOCTOU window between hash verification and DLL load.
        let _exclusive_handle = {
            use std::io::Read;
            // FILE_SHARE_READ (0x1) — NOT 0 (deny-all). The previous deny-all
            // mode blocked LoadLibraryExW itself: the Windows image loader must
            // open the DLL to map it as a section, and an exclusive handle made
            // that open fail with a sharing violation ("LoadLibraryExW failed"),
            // breaking every VPN connection. Allowing only READ still denies
            // WRITE and DELETE, so the file cannot be swapped/replaced during
            // the hash→load window — the anti-TOCTOU intent is preserved.
            const FILE_SHARE_READ: u32 = 0x0000_0001;
            let mut exclusive_handle = OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ) // deny write/delete, allow the loader to read
                .open(&dll_path)
                .map_err(|e| format!("Failed to open wintun.dll: {}", e))?;
            // Read bytes from the exclusive handle directly (not a second open)
            // to avoid OS error 32 (sharing violation) self-deadlock.
            let mut bytes = Vec::new();
            exclusive_handle
                .read_to_end(&mut bytes)
                .map_err(|e| format!("Failed to read wintun.dll: {}", e))?;
            // Hash check happens while we hold the exclusive handle
            verify_dll_integrity(&bytes, &dll_path)?;
            exclusive_handle // keep alive through load_from_path
        };

        // SAFETY: `dll_path` points to a wintun.dll whose SHA-256 hash was
        // verified immediately above. The exclusive file lock (`_exclusive_handle`)
        // is held through this call, preventing TOCTOU replacement.
        // `wintun::load_from_path` performs `LoadLibraryW` and resolves FFI
        // symbol pointers; the resulting `Wintun` handle is kept alive for the
        // tunnel's lifetime.
        let wintun = unsafe {
            wintun::load_from_path(&dll_path)
                .map_err(|e| format!("Failed to load wintun.dll: {}", e))?
        };
        // DLL is now loaded into process memory — safe to release exclusive lock
        drop(_exclusive_handle);

        tracing::info!("Wintun DLL loaded successfully from {:?}", dll_path);

        // Log elevation status for diagnostics
        let elevated = crate::utils::elevation::is_elevated();
        tracing::info!(
            "Process elevation status: {}",
            if elevated { "ADMIN" } else { "NOT ADMIN" }
        );
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
                            e,
                            win_err,
                            win_desc
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
                            .args([
                                "interface",
                                "set",
                                "interface",
                                ADAPTER_NAME,
                                "admin=disable",
                            ])
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
                        match Adapter::create(
                            &wintun,
                            ADAPTER_NAME,
                            TUNNEL_TYPE,
                            Some(ADAPTER_GUID),
                        ) {
                            Ok(adapter) => {
                                tracing::info!("Adapter created successfully on retry");
                                adapter
                            }
                            Err(e2) => {
                                let (win_err2, win_desc2) = get_last_error_info();
                                tracing::error!(
                                    "Adapter creation failed on retry: {} (Win32: {} — {})",
                                    e2,
                                    win_err2,
                                    win_desc2
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
            Err(e) => tracing::warn!(
                "Could not query driver version after adapter creation: {}",
                e
            ),
        }

        // adapter is already Arc<Adapter> from wintun crate
        tracing::info!("Wintun adapter ready");

        // Store the adapter handle NOW — BEFORE IP/route/DNS configuration — so
        // methods that read it natively (get_adapter_index via the adapter LUID,
        // configure_dns via the adapter GUID) see it. It used to be stored only
        // at the very end, so those reads saw None and errored / fell back.
        *self.adapter.write().await = Some(adapter.clone());

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
            self.config.persistent_keepalive,
        )
        .await
        .map_err(|e| format!("Failed to create WireGuard session: {}", e))?;
        tracing::info!("WireGuard session created (before route changes)");

        // Get the ACTUAL resolved endpoint IP from the WireGuard socket.
        // This is the IP the socket is connected to — we MUST use this same IP
        // for the endpoint host route to prevent a routing loop.
        let endpoint_ip = wg_session.endpoint_ip();
        tracing::info!(
            "WireGuard socket connected to endpoint IP: {}",
            redact_ip(&endpoint_ip.to_string())
        );

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

        // #99: `configure_dns` runs exactly once per tunnel, so an adapter that
        // is DOWN at connect — a dock still negotiating after resume, Wi-Fi
        // re-associating, a phone tether appearing — is never parked, and
        // Windows SMHNR races its ISP resolvers against the tunnel's for the
        // rest of the session with the UI showing Connected. Re-derive the park
        // on a ticker for as long as this generation owns it.
        //
        // A plain OS thread rather than a task: every machine-state operation is
        // synchronous by design (it has to be callable from Drop and from the
        // panic hook), and the pass is idempotent — adapters already in the
        // record are skipped, never re-snapshotted, which is #99's own stated
        // objection to the naive "re-run configure_dns" fix.
        //
        // Scoped to the SESSION, not to ownership. Ownership does not end when
        // the session does: an un-park that could not be verified — an adapter
        // unplugged mid-session is the ordinary way to get one — leaves the park
        // record non-empty, and `release_owner_if_clean` therefore leaves this
        // generation owning it indefinitely. A ticker gated on ownership then
        // outlived its own tunnel and went on parking every physical adapter on
        // `static none` every ten seconds with nothing connected: DNS dead
        // machine-wide, UI reading Disconnected. `dns_refresh_active` is cleared
        // by `stop()` and by `Drop`, which are every way out of a session, and
        // `refresh_live_session` re-reads it under the machine-state lock so it
        // cannot interleave with the un-park.
        {
            let state_gen = self.state_gen;
            let session_alive = self.dns_refresh_active.clone();
            session_alive.store(true, Ordering::SeqCst);
            std::thread::spawn(move || {
                loop {
                    std::thread::sleep(crate::vpn::win_machine_state::REFRESH_INTERVAL);
                    if !crate::vpn::win_machine_state::refresh_live_session(
                        state_gen,
                        &session_alive,
                    ) {
                        break;
                    }
                }
                tracing::debug!("DNS park refresh ended for generation {}", state_gen);
            });
        }

        // IPv6: if the node is dual-stacked (backend sent a client_ipv6), ROUTE
        // IPv6 through the tunnel — lift the block installed at the top of start()
        // only now, immediately before the tunnel's own IPv6 address and routes go
        // in. Otherwise the block simply stays in force. If routing setup fails,
        // re-block (never leak).
        if self.config.client_ipv6.is_some() {
            crate::vpn::wfp::unblock_ipv6_dual_stack().await?;
            if let Err(e) = self.configure_ipv6().await {
                tracing::warn!("IPv6 routing setup failed ({}); blocking IPv6 instead", e);
                self.block_ipv6_leaks().await?;
            }
        }

        // Store remaining state (adapter was already stored above, pre-config).
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

        let packet_handle = tokio::spawn(async move {
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
        *self.packet_task.write().await = Some(packet_handle);

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
        let endpoint_host = self
            .config
            .endpoint
            .split(':')
            .next()
            .ok_or_else(|| "Invalid endpoint format: missing host".to_string())?;
        // Endpoint host can be an IP or a hostname. Validate that hostnames
        // contain only safe characters (alphanumeric, dots, hyphens) AND form a
        // well-formed FQDN: per-label length 1-63, no empty labels ('..'), no
        // leading/trailing hyphen per label, no trailing dot. This rejects
        // malformed values (e.g. 'a..b', 'a.-b', 'a-.b') before they reach any
        // system command. Valid endpoint FQDNs are unaffected.
        if endpoint_host.parse::<Ipv4Addr>().is_err() {
            let labels: Vec<&str> = endpoint_host.split('.').collect();
            let valid_labels = labels.iter().all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            });
            if endpoint_host.is_empty() || endpoint_host.len() > 253 || !valid_labels {
                // P6-CLI-D-03: this Err string is logged verbatim by the catch-all handlers
                // in manager.rs / auto_reconnect.rs at levels release builds write.
                return Err(format!(
                    "Invalid endpoint hostname: '{}'",
                    crate::utils::redact::redact_hostname(endpoint_host)
                ));
            }
        }

        // Validate DNS entries (passed to netsh set/add dns)
        for dns in &self.config.dns {
            Ipv4Addr::from_str(dns).map_err(|_| format!("Invalid DNS address: '{}'", dns))?;
        }

        // Validate allowed_ips CIDRs (network portion passed to route add)
        for cidr in &self.config.allowed_ips {
            let parts: Vec<&str> = cidr.split('/').collect();
            if parts.len() != 2 {
                return Err(format!("Invalid CIDR format: '{}'", cidr));
            }
            Ipv4Addr::from_str(parts[0])
                .map_err(|_| format!("Invalid network address in CIDR: '{}'", cidr))?;
            let prefix: u8 = parts[1]
                .parse()
                .map_err(|_| format!("Invalid prefix length in CIDR: '{}'", cidr))?;
            if prefix > 32 {
                return Err(format!("Prefix length out of range in CIDR: '{}'", cidr));
            }
        }

        // Validate MTU is in sane range
        if self.config.mtu < 576 || self.config.mtu > 9000 {
            return Err(format!(
                "Invalid MTU: {} (expected 576-9000)",
                self.config.mtu
            ));
        }

        // P1-dk-allowedips-no-default-coverage: the CIDRs above are only
        // syntax-checked; also refuse a scope that does not cover the full
        // address space (defense in depth — build_vpn_config already enforces
        // this at the choke point every connect path funnels through).
        crate::vpn::validate_tunnel_scope(&self.config)?;

        tracing::debug!("VPN config validation passed");
        Ok(())
    }

    /// Configure the adapter's IP address + MTU.
    ///
    /// Native fast path via the IP Helper API (CreateUnicastIpAddressEntry +
    /// SetIpInterfaceEntry) addressed by interface index — instant, no netsh.
    /// Falls back to netsh if the native calls error, so the adapter is never
    /// left unconfigured.
    async fn configure_adapter(&self) -> Result<(), String> {
        let client_ip = &self.config.client_ip;
        // The per-session tunnel address is assigned by us and maps to a single
        // device row in the backend IPAM, so it identifies the customer. Both
        // sibling paths already redact it (tunnel_linux.rs, tunnel_macos.rs);
        // this one had drifted.
        tracing::debug!("Configuring adapter IP: {}", redact_ip(client_ip));

        let if_index = self.get_adapter_index().await.ok();

        // LOCKDOWN: publish the tunnel interface LUID to the kill switch so
        // always-on mode can permit tunneled traffic by interface. Best-effort —
        // only lockdown mode (off by default) depends on it.
        #[cfg(windows)]
        {
            let mut luid_published = false;
            if let Some(idx) = if_index {
                let mut luid = windows::Win32::NetworkManagement::Ndis::NET_LUID_LH::default();
                // SAFETY: `idx` is the Wintun adapter's interface index; the call
                // fills `luid` and returns NO_ERROR (0) on success.
                let rc = unsafe {
                    windows::Win32::NetworkManagement::IpHelper::ConvertInterfaceIndexToLuid(
                        idx, &mut luid,
                    )
                };
                if rc.0 == 0 {
                    // SAFETY: on success the union's `Value` field holds the LUID.
                    crate::vpn::wfp::set_tunnel_luid(unsafe { luid.Value });
                    luid_published = true;
                    // LOCKDOWN server-switch / reconnect: if the block is already
                    // active (lockdown holds it on continuously), rebuild it NOW with
                    // this NEW interface LUID + the new server IP, so the active block
                    // never permits a stale/freed LUID. On a fresh connect the block
                    // is not active yet — arm() does the first activation.
                    if crate::vpn::wfp::is_lockdown_mode() && crate::vpn::wfp::is_blocking() {
                        if let Err(e) = crate::vpn::wfp::activate_blocking().await {
                            tracing::error!(
                                "Lockdown: failed to re-activate kill switch with new tunnel LUID: {}",
                                e
                            );
                        }
                    }
                } else {
                    tracing::warn!(
                        "Could not resolve tunnel LUID from interface index {} (rc=0x{:08X}); lockdown mode unavailable this session",
                        idx,
                        rc.0
                    );
                }
            }

            // If we could not identify the tunnel interface, an always-on block-all
            // has no way to permit tunneled traffic — it would block the user's own
            // VPN browsing. activate_blocking no longer refuses in that situation
            // (refusing deadlocked the reconnect loop, see wfp.rs), so the decision
            // has to be made here instead: degrade this session to the reactive kill
            // switch. In-memory only; the saved preference is untouched.
            if !luid_published && crate::vpn::wfp::is_lockdown_mode() {
                tracing::warn!(
                    "Lockdown (always-on) unavailable this session — falling back to the \
                     reactive kill switch"
                );
                crate::vpn::wfp::set_lockdown_mode(false);
            }
        }

        let native_ok = match if_index {
            Some(idx) => {
                match set_adapter_ip_mtu_native(idx, client_ip, 24, self.config.mtu.into()) {
                    Ok(()) => {
                        tracing::debug!("Adapter IP + MTU set natively (MTU {})", self.config.mtu);
                        true
                    }
                    Err(e) => {
                        tracing::warn!("Native IP/MTU set failed ({}); falling back to netsh", e);
                        false
                    }
                }
            }
            None => false,
        };

        if !native_ok {
            // Fallback: netsh set address + MTU.
            let output = cmd("netsh")
                .args([
                    "interface",
                    "ip",
                    "set",
                    "address",
                    &format!("name={}", ADAPTER_NAME),
                    "static",
                    client_ip,
                    "255.255.255.0",
                ])
                .output()
                .map_err(|e| format!("Failed to run netsh: {}", e))?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.contains("already") && !stderr.is_empty() {
                    tracing::warn!("netsh set address output: {}", stderr);
                }
            }

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
                if !output.status.success() {
                    tracing::warn!(
                        "Failed to set MTU: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }
        }

        tracing::debug!(
            "Adapter IP configured ({})",
            if native_ok { "native" } else { "netsh" }
        );
        Ok(())
    }

    // ===================================================================
    // SECTION: Routing — configure_routes, get_adapter_index, get_default_gateway,
    //   configure_local_network_routes, parse_cidr (consider future tunnel_routing.rs)
    // ===================================================================

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
                "interface",
                "ip",
                "set",
                "interface",
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

        // Saved for the LAN-sharing routes below. The routes themselves are
        // recorded in the machine-state owner as they are installed — see the
        // record_route calls, and I10 in win_machine_state.
        *self.saved_default_gateway.write().await = Some(default_gateway.clone());

        // CRITICAL: Add host route for the VPN server BEFORE split routes.
        // Without this, the /1 split routes would capture the WireGuard UDP
        // traffic itself, creating a routing loop (encrypted packets re-enter
        // Wintun, get double-encrypted, server can't decrypt → no responses).
        //
        // Native first (CreateIpForwardEntry2 pinned to the physical interface),
        // then route.exe fallback; failing BOTH is fatal.
        let phys_idx = default_route_native().map(|(_, idx)| idx);
        let endpoint_native_ok = match (
            phys_idx,
            endpoint_ip.parse::<Ipv4Addr>(),
            default_gateway.parse::<Ipv4Addr>(),
        ) {
            (Some(idx), Ok(ep), Ok(gw)) => add_route_native(ep, 32, gw, idx, 1).is_ok(),
            _ => false,
        };
        if endpoint_native_ok {
            tracing::info!(
                "Endpoint host route added (native): {} via {}",
                redact_ip(endpoint_ip),
                redact_ip(&default_gateway)
            );
        } else {
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
        }

        // I10 (#100): remember EXACTLY what went in — destination prefix,
        // interface index AND next hop — so the teardown can delete this row and
        // nothing else. Recorded only after the add actually succeeded (both
        // arms above return Err otherwise), because a route we did not install is
        // never ours to delete. With no physical interface index the route is
        // unattributable and deliberately goes unrecorded: at teardown it is left
        // in place rather than removed with an unqualified `route delete`, which
        // is precisely how the old code tore down Cloudflare WARP's and
        // Tailscale's routing.
        if let (Some(idx), Ok(ep), Ok(gw)) = (
            phys_idx,
            endpoint_ip.parse::<Ipv4Addr>(),
            default_gateway.parse::<Ipv4Addr>(),
        ) {
            crate::vpn::win_machine_state::record_route(
                self.state_gen,
                crate::vpn::win_machine_state::OwnedRoute {
                    dest: std::net::IpAddr::V4(ep),
                    prefix_len: 32,
                    next_hop: std::net::IpAddr::V4(gw),
                    if_index: idx,
                },
            );
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
                routes_to_add.push(("0.0.0.0".to_string(), "128.0.0.0".to_string())); // 0.0.0.0/1
                routes_to_add.push(("128.0.0.0".to_string(), "128.0.0.0".to_string()));
            // 128.0.0.0/1
            } else {
                let (network, mask) = self.parse_cidr(allowed_ip)?;
                routes_to_add.push((network, mask));
            }
        }

        // Track what actually landed. The success line below used to print
        // routes_to_add.len() — the ATTEMPTED count — so a run that installed
        // nothing still logged "Routes configured (N entries)".
        let mut installed = 0usize;
        let mut failed_default_split: Vec<String> = Vec::new();

        // I10: the tunnel routes are on-link on the Wintun interface, so the
        // owning row is (network/prefix, if_index, next hop 0.0.0.0). Both the
        // native and the route.exe arm funnel through here so the two cannot
        // record different things.
        let state_gen = self.state_gen;
        let record_tunnel_route = |network: &str, mask: &str| {
            if let (Ok(net), Ok(m)) = (network.parse::<Ipv4Addr>(), mask.parse::<Ipv4Addr>()) {
                crate::vpn::win_machine_state::record_route(
                    state_gen,
                    crate::vpn::win_machine_state::OwnedRoute {
                        dest: std::net::IpAddr::V4(net),
                        prefix_len: u32::from(m).count_ones() as u8,
                        next_hop: std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                        if_index,
                    },
                );
            }
        };

        for (network, mask) in &routes_to_add {
            // The split-default pair IS the tunnel. If either half is missing,
            // traffic for that half leaves over the physical interface in the
            // clear while the UI reports Connected — so these two are mandatory
            // and a failure on them aborts the connect. Linux propagates route
            // failures out of configure_routes() already (tunnel_linux.rs, the
            // `if let Err(e) = configure_routes(..) { return Err(e) }` call
            // site); Windows was the odd one out, logging a warning and
            // continuing. Other allowed_ips stay best-effort: a narrower route
            // failing is a reachability problem, not a plaintext leak.
            let is_default_split =
                mask == "128.0.0.0" && (network == "0.0.0.0" || network == "128.0.0.0");

            tracing::debug!("Adding route: {} mask {} IF {}", network, mask, if_index);

            // Native first (CreateIpForwardEntry2 on the Wintun interface, on-link
            // next hop 0.0.0.0). Fall back to route.exe on any error.
            let native_ok = match (network.parse::<Ipv4Addr>(), mask.parse::<Ipv4Addr>()) {
                (Ok(net), Ok(m)) => {
                    let prefix = u32::from(m).count_ones() as u8;
                    add_route_native(net, prefix, Ipv4Addr::UNSPECIFIED, if_index, 5).is_ok()
                }
                _ => false,
            };
            if native_ok {
                tracing::debug!("Route added natively: {} mask {}", network, mask);
                record_tunnel_route(network, mask);
                installed += 1;
                continue;
            }

            // Use interface index for Wintun adapter - gateway 0.0.0.0 with IF parameter
            match cmd("route")
                .args([
                    "add",
                    network,
                    "mask",
                    mask,
                    "0.0.0.0", // Gateway - use 0.0.0.0 for point-to-point interfaces
                    "metric",
                    "5",
                    "IF",
                    &if_index.to_string(),
                ])
                .output()
            {
                Ok(output) if output.status.success() => {
                    tracing::debug!("Route added successfully: {} mask {}", network, mask);
                    record_tunnel_route(network, mask);
                    installed += 1;
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
                    if is_default_split {
                        failed_default_split.push(format!("{network} mask {mask}"));
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to execute route command for {} mask {}: {}",
                        network,
                        mask,
                        e
                    );
                    if is_default_split {
                        failed_default_split.push(format!("{network} mask {mask}"));
                    }
                }
            }
        }

        if !failed_default_split.is_empty() {
            // Fail the connect rather than come up leaking. start() unwinds and
            // the teardown path removes the half-built tunnel.
            return Err(format!(
                "Refusing to connect: the default-route split could not be installed ({}). \
                 Without it, traffic for that half of the address space would leave over the \
                 physical interface in the clear while the app reported Connected.",
                failed_default_split.join(", ")
            ));
        }

        tracing::info!(
            "Routes configured ({}/{} entries installed + endpoint host route)",
            installed,
            routes_to_add.len()
        );
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

        tracing::info!(
            "Configuring local network sharing routes via {}",
            redact_ip(&default_gateway)
        );

        // I10 (#100): these go out over the PHYSICAL interface via the real
        // gateway, so that is the row that must be recorded. Without the index
        // the teardown used to issue an unqualified `route delete 10.0.0.0 mask
        // 255.0.0.0`, which removes a corporate 10/8 route the client never
        // installed. When the index is unknown we record nothing, and the
        // teardown then leaves these routes in place: a stale RFC1918 route via
        // the real gateway is what the machine wants anyway once the tunnel is
        // gone, whereas deleting another product's is unrecoverable.
        let gateway_if_index = default_route_native().map(|(_, idx)| idx);
        let state_gen = self.state_gen;
        let record_lan_route = |network: &str, mask: &str| {
            if let (Some(idx), Ok(net), Ok(m), Ok(gw)) = (
                gateway_if_index,
                network.parse::<Ipv4Addr>(),
                mask.parse::<Ipv4Addr>(),
                default_gateway.parse::<Ipv4Addr>(),
            ) {
                crate::vpn::win_machine_state::record_route(
                    state_gen,
                    crate::vpn::win_machine_state::OwnedRoute {
                        dest: std::net::IpAddr::V4(net),
                        prefix_len: u32::from(m).count_ones() as u8,
                        next_hop: std::net::IpAddr::V4(gw),
                        if_index: idx,
                    },
                );
            }
        };

        // RFC1918 private address ranges
        let local_routes: [(&str, &str); 3] = [
            ("10.0.0.0", "255.0.0.0"),      // 10.0.0.0/8
            ("172.16.0.0", "255.240.0.0"),  // 172.16.0.0/12
            ("192.168.0.0", "255.255.0.0"), // 192.168.0.0/16
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
                    tracing::debug!(
                        "Local network route added: {} mask {} via {}",
                        network,
                        mask,
                        redact_ip(&default_gateway)
                    );
                    record_lan_route(network, mask);
                    added += 1;
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    tracing::warn!(
                        "Local network route failed for {} mask {}: {}",
                        network,
                        mask,
                        stderr.trim()
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to execute route for {} mask {}: {}",
                        network,
                        mask,
                        e
                    );
                }
            }
        }

        // Also add link-local (169.254.0.0/16) for mDNS/device discovery.
        //
        // This was `let _ = ...output()` while the teardown deleted 169.254.0.0/16
        // unconditionally: the twin of the RFC1918 loop above, missing both the
        // status check and the attribution. Same treatment as its three
        // neighbours now, so only a route that actually went in is recorded and
        // only a recorded route is deleted.
        match cmd("route")
            .args([
                "add",
                "169.254.0.0",
                "mask",
                "255.255.0.0",
                &default_gateway,
                "metric",
                "1",
            ])
            .output()
        {
            Ok(output) if output.status.success() => {
                record_lan_route("169.254.0.0", "255.255.0.0");
            }
            Ok(output) => tracing::debug!(
                "Link-local route not added: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
            Err(e) => tracing::debug!("Link-local route not added: {}", e),
        }

        tracing::info!("Local network sharing: {}/3 routes added", added);
        Ok(())
    }

    // ===================================================================
    // SECTION: DNS — configure_dns, restore_dns
    // The park itself (enumeration, snapshot, suppression, the durable record
    // and who may undo it) lives in win_machine_state; the netsh reads it drives
    // live in tunnel_dns.rs.
    // ===================================================================

    /// Configure DNS servers
    /// SECURITY FIX (Vuln-DNS-1): Disable DNS on all non-VPN adapters to prevent
    /// Windows "Smart Multi-Homed Name Resolution" (SMHNR) from querying ISP DNS
    /// in parallel with the VPN's DNS servers, leaking queries.
    ///
    /// Suppressing SMHNR is a change to the MACHINE, not to this tunnel, so
    /// `win_machine_state` owns it: the enumeration, the durable record, the
    /// per-adapter ordering (read -> record -> park -> verify) and the ownership
    /// token that decides who may undo it. Claiming while a park is already in
    /// force ADOPTS it and re-snapshots nothing — re-reading a parked adapter is
    /// what recorded `static`-with-no-servers as the user's own configuration and
    /// made the loss permanent (issues #98, #102, #105 I5b).
    async fn configure_dns(&self) -> Result<(), String> {
        tracing::debug!("Configuring DNS servers");

        let adapter_name = format!("name={}", ADAPTER_NAME);

        crate::vpn::win_machine_state::claim(self.state_gen);

        // STEP 2: Set DNS on the VPN adapter. Native fast path first
        // (SetInterfaceDnsSettings via the adapter GUID — instant, no
        // subprocess), then fall back to netsh if the native call errors so DNS
        // is never left unset.
        let adapter_guid = {
            let guard = self.adapter.read().await;
            guard.as_ref().map(|a| a.get_guid())
        };
        let native_ok = match adapter_guid {
            Some(guid) => match set_dns_native(guid, &self.config.dns) {
                Ok(()) => true,
                Err(e) => {
                    tracing::warn!("Native DNS set failed ({}); falling back to netsh", e);
                    false
                }
            },
            None => false,
        };

        if !native_ok {
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
                        "validate=no",
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
                        "validate=no",
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
        }

        tracing::debug!(
            "DNS configured (VPN-only, {}): {:?}",
            if native_ok { "native" } else { "netsh" },
            self.config.dns
        );
        Ok(())
    }

    // ===================================================================
    // SECTION: IPv6 — configure_ipv6 (dual-stack), block_ipv6_leaks, unblock_ipv6
    //   (consider future tunnel_ipv6.rs extraction)
    // ===================================================================

    /// Dual-stack: route IPv6 through the tunnel (for nodes that advertise IPv6
    /// via `client_ipv6`). Assigns the IPv6 tunnel address and adds the IPv6
    /// default route (::/0 split into ::/1 + 8000::/1, mirroring the IPv4 split)
    /// on the Wintun interface. All native (IP Helper) — no subprocess. The v4
    /// resolver already answers AAAA queries, so no separate IPv6 DNS is needed.
    async fn configure_ipv6(&self) -> Result<(), String> {
        let client_ipv6 = match &self.config.client_ipv6 {
            Some(s) => s.clone(),
            None => return Ok(()),
        };
        let ip_str = client_ipv6.split('/').next().unwrap_or(&client_ipv6);
        let ip: Ipv6Addr = ip_str
            .parse()
            .map_err(|_| format!("invalid client_ipv6: {}", client_ipv6))?;

        let if_index = self.get_adapter_index().await?;
        set_adapter_ipv6_native(if_index, ip, 128)?;

        // I10, IPv6 twin. These are on-link on the Wintun interface and so die
        // with it, but they are still routes this generation installed, and the
        // owner is the single place that knows about installed routes. Leaving
        // the v6 arm out is exactly the twin drift that has bitten this file
        // twice already.
        let state_gen = self.state_gen;
        let record_v6 = |dest: Ipv6Addr, prefix_len: u8| {
            crate::vpn::win_machine_state::record_route(
                state_gen,
                crate::vpn::win_machine_state::OwnedRoute {
                    dest: std::net::IpAddr::V6(dest),
                    prefix_len,
                    next_hop: std::net::IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                    if_index,
                },
            );
        };

        for cidr in &self.config.allowed_ips_v6 {
            if cidr == "::/0" {
                add_route6_native(Ipv6Addr::UNSPECIFIED, 1, if_index, 5)?; // ::/1
                record_v6(Ipv6Addr::UNSPECIFIED, 1);
                let upper = Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0);
                add_route6_native(upper, 1, if_index, 5)?; // 8000::/1
                record_v6(upper, 1);
            } else if let Some((net, plen)) = cidr.split_once('/') {
                if let (Ok(addr), Ok(len)) = (net.parse::<Ipv6Addr>(), plen.parse::<u8>()) {
                    add_route6_native(addr, len, if_index, 5)?;
                    record_v6(addr, len);
                }
            }
        }

        // LOG-001: the per-session tunnel IPv6 is joinable back to a user by
        // the backend IPAM — redact it in the release log.
        tracing::info!(
            "IPv6 routed through tunnel (dual-stack): {}",
            crate::utils::redact_ip(ip_str)
        );
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
        // Native WFP — a kernel filter blocking outbound IPv6 at the
        // ALE_AUTH_CONNECT_V6 layer (with localhost/DHCPv6 permits), added in a
        // single transaction in microseconds. Replaces the old netsh/PowerShell
        // path, which cost ~21s on AV-heavy machines (netsh `::/0` was rejected,
        // then a ~14s PowerShell `Disable-NetAdapterBinding` fallback).
        tracing::info!("Blocking IPv6 to prevent leaks (native WFP)");
        crate::vpn::wfp::block_ipv6().await
    }

    /// Remove the IPv6 block when disconnecting (native WFP — instant).
    async fn unblock_ipv6(&self) -> Result<(), String> {
        tracing::debug!("Removing IPv6 block (native WFP)");
        crate::vpn::wfp::unblock_ipv6().await?;

        // Best-effort legacy heal, fully non-blocking so disconnect stays
        // instant: versions <= 1.3.19 may have left stale netsh firewall rules
        // and/or a disabled ms_tcpip6 adapter binding (the old PowerShell
        // fallback). Clean both in the background. No-ops once a machine is
        // healed; never delays the user.
        tokio::task::spawn_blocking(|| {
            for rule in [
                "Birdo VPN Block IPv6 Out",
                "Birdo VPN Block IPv6 Out UDP",
                "Birdo VPN Block IPv6 In",
                "Birdo VPN Block IPv6 In UDP",
                "Birdo VPN Block ICMPv6",
                "Birdo VPN Block 6in4",
            ] {
                let _ = cmd("netsh")
                    .args([
                        "advfirewall",
                        "firewall",
                        "delete",
                        "rule",
                        &format!("name={}", rule),
                    ])
                    .output();
            }
            let _ = cmd("powershell")
                .args([
                    "-NoProfile", "-NonInteractive", "-Command",
                    "Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | \
                     Enable-NetAdapterBinding -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction SilentlyContinue",
                ])
                .output();
        });

        Ok(())
    }

    /// Hand the physical adapters back the resolvers they had before this
    /// session parked them, and put the VPN adapter's own DNS back on DHCP.
    ///
    /// Owner-gated. A tunnel that no longer owns the machine state must not
    /// un-park anything: on a reconnect the park is held across the gap and the
    /// INCOMING tunnel owns it, so un-parking here would be issue #98 — the
    /// physical NICs get their ISP resolvers back while a live tunnel carries
    /// traffic and the UI reads Connected.
    async fn restore_dns(&self) -> Result<(), String> {
        if !crate::vpn::win_machine_state::is_owner(self.state_gen) {
            tracing::debug!("DNS restore skipped — this tunnel no longer owns the machine state");
            return Ok(());
        }
        tracing::debug!("Restoring DNS");

        // Restore DNS on VPN adapter (both families — configure_dns disabled both)
        for family in ["ip", "ipv6"] {
            let _ = cmd("netsh")
                .args([
                    "interface",
                    family,
                    "set",
                    "dns",
                    &format!("name={}", ADAPTER_NAME),
                    "dhcp",
                ])
                .output();
        }

        crate::vpn::win_machine_state::release_dns(self.state_gen);

        tracing::debug!("DNS restoration complete");
        Ok(())
    }

    /// Get the default gateway from the routing table
    async fn get_default_gateway(&self) -> Result<String, String> {
        // Native fast path: read the IPv4 routing table via the IP Helper API
        // and pick the lowest-metric default route's next hop. Avoids spawning
        // `route.exe` (~3s under AV). Falls back to `route print` parsing if the
        // native read finds nothing, so routing is never left mis-resolved.
        if let Some(gw) = default_gateway_native() {
            return Ok(gw);
        }

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

    /// Get the interface index of the Wintun adapter.
    ///
    /// Native: ask the wintun adapter directly (it resolves the index from its
    /// NET_LUID under the hood) instead of spawning `netsh show interfaces` and
    /// parsing it (with a PowerShell fallback). Instant, no subprocess, and not
    /// fooled by duplicate/locale-dependent adapter rows.
    async fn get_adapter_index(&self) -> Result<u32, String> {
        let guard = self.adapter.read().await;
        let adapter = guard.as_ref().ok_or("Wintun adapter not created yet")?;
        adapter
            .get_adapter_index()
            .map_err(|e| format!("Failed to get adapter index: {}", e))
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
    #[allow(clippy::too_many_arguments)] // spawned-task plumbing: each Arc is moved in individually
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

        // Adaptive polling: start fast, slow down when idle, then back off HARD
        // when idle is sustained. A connected-but-idle tunnel (screen off, no
        // traffic) previously busy-polled at 500us = 2000 wakeups/s forever; the
        // deep-idle tier drops that to 5ms = 200 wakeups/s after ~1s of silence,
        // a 10x cut in steady-state CPU wakeups. Any packet resets idle_cycles to
        // 0 (below), so only the FIRST packet after >1s idle sees the extra
        // latency; the timer task (update_timers, every 250ms) is unaffected.
        let mut idle_cycles: u32 = 0;
        const IDLE_THRESHOLD: u32 = 100; // brief idle -> slow tier
        const DEEP_IDLE_THRESHOLD: u32 = 2_000; // ~1s sustained idle -> deep-idle tier
        const FAST_POLL_US: u64 = 10; // 10 microseconds when active
        const SLOW_POLL_US: u64 = 500; // 500 microseconds when briefly idle
        const DEEP_POLL_US: u64 = 5_000; // 5ms when idle >1s (200 wakeups/s)

        // FIX-DL: Timer task — boringtun requires periodic update_timers() calls
        // to send keepalives, manage rekeys, and handle cookie responses.
        // Without this the server's session expires and stops sending data.
        let mut last_timer_update = Instant::now();
        const TIMER_INTERVAL: Duration = Duration::from_millis(250);

        // Diagnostic: periodic stats log to verify bidirectional traffic.
        // POWER: at info/5s this was a guaranteed disk write every 5 seconds for
        // the whole session (the file logger appends), which alone keeps the drive
        // from idling. Debug + 60s means release builds (info default) write
        // nothing while connected, and a debug session still gets the diagnostic.
        let mut last_stats_log = Instant::now();
        const STATS_LOG_INTERVAL: Duration = Duration::from_secs(60);

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
                    if idle_cycles > DEEP_IDLE_THRESHOLD {
                        DEEP_POLL_US
                    } else if idle_cycles > IDLE_THRESHOLD {
                        SLOW_POLL_US
                    } else {
                        FAST_POLL_US
                    }
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
                    // write lock we simply skip this iteration (10-500 µs later we retry).
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
                            tracing::debug!(
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
        // I3 LIVENESS, NOT CLAIM. Keying this on `running` alone made a tunnel
        // that the manager's CONNECT_TIMEOUT cancelled before `running` was ever
        // set impossible to stop — even for someone holding it — while it still
        // owned the parked adapters and the installed routes. Ownership is the
        // predicate: if this generation owns machine state there is work to do,
        // whatever the flag says.
        if !self.running.load(Ordering::SeqCst)
            && !crate::vpn::win_machine_state::is_owner(self.state_gen)
        {
            return Ok(());
        }

        tracing::info!("Stopping Wintun tunnel");

        // STEP 0: end the DNS refresh session FIRST, before anything un-parks.
        // A pass that started after the un-park would re-park every physical
        // adapter behind a tunnel that is going away.
        self.dns_refresh_active.store(false, Ordering::SeqCst);

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

        // LOCKDOWN: the tunnel interface is going away — clear its LUID so a
        // stale value can never be permitted on a future kill-switch activation.
        #[cfg(windows)]
        crate::vpn::wfp::clear_tunnel_luid();

        // STEP 3: Network cleanup — run all three in parallel since they
        // are independent and each spawns external processes.
        // Also flush DNS inline (ipconfig /flushdns is ~10ms).
        let _ = cmd("ipconfig").args(["/flushdns"]).output();
        let (dns_r, ipv6_r, route_r) = tokio::join!(
            self.restore_dns(),
            self.unblock_ipv6(),
            self.cleanup_routes(),
        );
        if let Err(e) = dns_r {
            tracing::warn!("DNS restore error: {}", e);
        }
        if let Err(e) = ipv6_r {
            tracing::warn!("IPv6 unblock error: {}", e);
        }
        if let Err(e) = route_r {
            tracing::warn!("Route cleanup error: {}", e);
        }

        // STEP 3.5: Join the packet loop BEFORE releasing the adapter. The loop
        // holds an Arc<Session> that keeps the Wintun adapter alive; the loop is
        // biased on the shutdown signal so it exits within ~1 poll cycle. If we
        // dropped the adapter while the task were still alive, the OS adapter
        // wouldn't be released and the NEXT tunnel (a server switch) would fail
        // to recreate it. 3s cap + abort is a safety net for a wedged task.
        if let Some(handle) = self.packet_task.write().await.take() {
            let abort = handle.abort_handle();
            if tokio::time::timeout(Duration::from_secs(3), handle)
                .await
                .is_err()
            {
                tracing::warn!("Packet loop did not exit within 3s — aborting it");
                abort.abort();
                // Give the abort a moment to unwind + drop the Arc<Session>.
                tokio::time::sleep(Duration::from_millis(100)).await;
            } else {
                tracing::debug!("Packet loop joined cleanly");
            }
        }

        // STEP 4: Close Wintun adapter (now the only remaining Arc<Session>/Adapter)
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

    /// Clean up routes when disconnecting.
    async fn cleanup_routes(&self) -> Result<(), String> {
        self.cleanup_routes_blocking();
        Ok(())
    }

    /// Sync core of route cleanup. Shared by `cleanup_routes()` and the `Drop`
    /// emergency unwind (which cannot await) so the two can never drift.
    ///
    /// ISSUE #100. This used to issue text-mode deletes with no interface and no
    /// gateway:
    ///
    /// ```text
    /// route delete 0.0.0.0   mask 128.0.0.0
    /// route delete 128.0.0.0 mask 128.0.0.0
    /// ```
    ///
    /// which removes EVERY route for that destination and mask, whoever
    /// installed it — Cloudflare WARP and Tailscale both install `/1`
    /// split-defaults, so disconnecting Birdo tore down their routing. The same
    /// defect sat on the endpoint host route and, when `local_network_sharing`
    /// was on, on `10.0.0.0/8` / `172.16.0.0/12` / `192.168.0.0/16` /
    /// `169.254.0.0/16` — a corporate 10/8 route is common, which makes that the
    /// more damaging one. The issue names only the two `/1` lines; fixing only
    /// those is exactly the twin drift this estate keeps re-finding, so all four
    /// sites now go through the machine-state owner, which deletes the exact rows
    /// it recorded at install time and nothing else (I10).
    fn cleanup_routes_blocking(&self) {
        crate::vpn::win_machine_state::release_routes(self.state_gen);
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
        // Unconditionally, and before the ownership test below: this tunnel is
        // being destroyed, so its session is over whether or not it still owns
        // the machine state. A displaced tunnel takes the non-owner return a few
        // lines down, and without this its refresh thread would be the one left
        // parking adapters on behalf of a generation that no longer exists.
        self.dns_refresh_active.store(false, Ordering::SeqCst);

        // I1 SINGLE OWNER, and it is the whole of issue #98.
        //
        // On a reconnect where the teardown was skipped, the manager replaced
        // `Some(old)` with `Some(new)` and DROPPED the old tunnel — whose Drop
        // then un-parked every physical adapter, deleted the `/1` split-default
        // pair and removed the IPv6 block while the NEW tunnel was live and
        // carrying traffic, with the UI showing Connected. Every one of those is
        // machine state, and this tunnel may only touch machine state it owns.
        //
        // Ownership also replaces the old `running` / `dns_modified` /
        // `routes_installed` gate. That gate existed because a connect cancelled
        // by CONNECT_TIMEOUT never set `running` yet had already parked the
        // adapters; the owner knows what was installed, so it cannot disagree
        // with a flag about it.
        if !crate::vpn::win_machine_state::is_owner(self.state_gen) {
            if self.running.load(Ordering::SeqCst) {
                tracing::warn!(
                    "A tunnel was dropped while still marked running but no longer owning the \
                     machine state — leaving DNS, routes and firewall state to their current \
                     owner rather than tearing down a live session"
                );
                self.running.store(false, Ordering::SeqCst);
            }
            return;
        }

        tracing::warn!(
            "WintunTunnel dropped still owning machine state (running={}) — performing \
             emergency cleanup to prevent DNS/route leaks",
            self.running.load(Ordering::SeqCst)
        );
        self.running.store(false, Ordering::SeqCst);

        // Best-effort: flush DNS cache to clear VPN-specific entries
        let _ = cmd("ipconfig").args(["/flushdns"]).output();

        // Best-effort: reset VPN adapter DNS to DHCP (prevents DNS leak).
        //
        // BOTH families. This was the `ip` context only, while `configure_dns`
        // sets the tunnel resolvers and `restore_dns` clears both — the same
        // v4/v6 twin that has drifted twice in this file already.
        for family in ["ip", "ipv6"] {
            let _ = cmd("netsh")
                .args([
                    "interface",
                    family,
                    "set",
                    "dns",
                    &format!("name={}", ADAPTER_NAME),
                    "dhcp",
                ])
                .output();
        }

        // Best-effort: un-park the physical adapters (both families) and remove
        // exactly the routes this generation installed. The same owner-gated,
        // verified code path the clean teardown uses, so the two cannot drift:
        // a cancelled or failed connect and a panic both land here having parked
        // every physical NIC on `static none`, and without this the machine is
        // left with no resolvers on its real interfaces.
        crate::vpn::win_machine_state::release_all(self.state_gen);

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
            .args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                "name=Birdo VPN Block ICMPv6",
            ])
            .output();
        let _ = cmd("netsh")
            .args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                "name=Birdo VPN Block 6in4",
            ])
            .output();
        // Also try legacy rule names
        let _ = cmd("netsh")
            .args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                "name=Birdo Block IPv6",
            ])
            .output();
        // Re-enable IPv6 adapter bindings
        match cmd("powershell")
            .args([
                "-NoProfile", "-NonInteractive", "-Command",
                "Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | Enable-NetAdapterBinding -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction SilentlyContinue",
            ])
            .output()
        {
            Ok(o) if !o.status.success() => {
                tracing::warn!("IPv6 re-enable failed: {}", String::from_utf8_lossy(&o.stderr));
            }
            Err(e) => tracing::warn!("IPv6 re-enable failed: {}", e),
            _ => {}
        }

        tracing::warn!("Emergency cleanup complete — DNS/route state may need manual verification");
    }
}
