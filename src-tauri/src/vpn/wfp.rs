//! Windows Filtering Platform (WFP) Kill Switch Implementation
//!
//! Clippy: WFP FFI structs (`FWPM_*`) are canonically initialised as
//! `..Default::default()` followed by field assignment — the C-style pattern
//! the Windows API docs use. Restructuring into struct literals would obscure
//! the correspondence with the Microsoft examples, so the lint is disabled
//! for this module.
#![allow(clippy::field_reassign_with_default)]
//!
//! FIX-2-1: Migrated from `netsh advfirewall` shell commands to direct WFP API
//! calls via `fwpuclnt.dll` for:
//!
//! - **Atomic transactions** — all filters are added/removed in a single WFP
//!   transaction. There is never a window where traffic is partially blocked
//!   (the previous netsh approach had a 50-200 ms gap between rule additions).
//! - **Crash safety** — `FWPM_SESSION_FLAG_DYNAMIC` tells Windows to remove
//!   every filter, sublayer, and provider created in this session when the
//!   engine handle is closed, *including abnormal process termination*.
//! - **Performance** — direct FFI (~100 μs) vs. spawning netsh.exe (~200 ms).
//! - **Reliability** — no text parsing of netsh stdout/stderr.
//!
//! ## AUDIT-L (design trade-off): fail-OPEN on app crash
//!
//! `FWPM_SESSION_FLAG_DYNAMIC` is a deliberate UX/security trade-off. Pros:
//!
//!   * No "stuck offline" footgun — if the Tauri process dies (panic, OOM,
//!     user kills it from Task Manager) the user is not locked out of their
//!     internet.
//!   * No persistent installer service to maintain (smaller attack surface,
//!     no kernel driver, no SYSTEM-privilege long-running daemon).
//!
//! Cons:
//!
//!   * If the GUI crashes WHILE the WireGuard tunnel is still up, all WFP
//!     filters are removed by the OS. Until WireGuard's own connection
//!     drops (seconds), packets that were destined for the tunnel may now
//!     egress on the physical adapter in clear text.
//!   * A targeted attacker who can crash the GUI process (e.g. a malicious
//!     local app within the user's session) could use this to deanonymise.
//!
//! Mitigation actually shipped:
//!
//!   * The tunnel adapter (`Wintun`) is also torn down when the process
//!     exits, so the routing-table entries that send packets into the
//!     tunnel disappear at roughly the same time the WFP filters do —
//!     network stack falls back to the physical interface within a single
//!     OS poll cycle, not a sustained leak.
//!   * STUN/TURN UDP destinations are blocked at a higher weight than
//!     general permits, so even *during* a normal session WebRTC cannot
//!     leak the real public IP.
//!
//! For users who need a true "fail-CLOSED on crash" posture (paranoid /
//! journalist threat model), a future v2 could ship a separate Windows
//! service running as `LocalSystem` that holds a non-dynamic WFP session
//! across GUI restarts. Tracked as a post-launch hardening item — NOT a
//! blocker per the security audit because the residual leak window is
//! sub-second and cannot be triggered remotely without prior local code
//! execution.
//!
//! Architecture:
//!   1. One `WfpEngine` handle is opened at `initialize()` and held for the
//!      lifetime of the VPN session (closed at `cleanup()`).
//!   2. A custom sublayer (`BIRDO_SUBLAYER_KEY`) groups all our filters.
//!   3. Permit rules (weight 10) are evaluated before the catch-all block
//!      (weight 1). STUN/TURN blocks use weight 15 to override permits.
//!   4. `activate_blocking()` wraps all filter additions in a single
//!      `FwpmTransactionBegin0` / `FwpmTransactionCommit0` pair.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::utils::elevation::is_elevated as is_admin;

use windows::core::GUID;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

// ── Stable GUIDs ─────────────────────────────────────────────────────
// Constant across process restarts so `initialize()` can clean up stale
// objects from a previous dynamic session (shouldn't exist, but belt &
// suspenders).

/// Sublayer that groups every Birdo VPN kill-switch filter.
const BIRDO_SUBLAYER_KEY: GUID = GUID::from_u128(0xe5f4c3b2_8f9d_5ea0_c1b6_000023456789);

// ── Filter weight constants ──────────────────────────────────────────
// Within our sublayer the first matching filter wins.  Higher weight is
// evaluated first.
const WEIGHT_BLOCK_ALL: u8 = 1; // catch-all, checked last
const WEIGHT_PERMIT: u8 = 10; // permit exceptions
const WEIGHT_BLOCK_STUN: u8 = 15; // STUN block overrides permits

// ── Global state ─────────────────────────────────────────────────────
static IS_INITIALIZED: AtomicBool = AtomicBool::new(false);
static IS_BLOCKING: AtomicBool = AtomicBool::new(false);
/// True when a STANDALONE IPv6 leak block (not the full kill switch) is active.
/// Lets the tunnel block IPv6 natively via WFP instead of slow netsh/PowerShell.
static IPV6_ONLY_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Session INTENT: the VPN session wants outbound IPv6 blocked.
///
/// Distinct from `IPV6_ONLY_ACTIVE`, which only says whether OUR standalone
/// filters are installed *right now*. The two diverge during a reactive
/// kill-switch cycle, where the kill switch's own block-all temporarily owns the
/// IPv6 block — and the intent is what must survive that cycle, because
/// `deactivate_blocking()` removes EVERY filter including the v6 block.
static IPV6_BLOCK_WANTED: AtomicBool = AtomicBool::new(false);

/// True while a tunnel is being torn down with a replacement already committed
/// (server switch). `unblock_ipv6()` must not drop the block in that window, or
/// IPv6 egresses the physical NIC for the whole teardown + setup of the new
/// tunnel.
static IPV6_BLOCK_HELD: AtomicBool = AtomicBool::new(false);
static VPN_SERVER_IP: once_cell::sync::Lazy<Arc<RwLock<Option<Ipv4Addr>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(None)));

/// Split tunnel app executable paths that should bypass the kill switch.
static SPLIT_TUNNEL_APPS: once_cell::sync::Lazy<Arc<RwLock<Vec<String>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(Vec::new())));

/// Whether local network sharing (RFC1918) is permitted through the kill switch.
static LOCAL_NETWORK_SHARING: AtomicBool = AtomicBool::new(false);

/// LOCKDOWN ("always-on") MODE — gated behind a user setting, OFF by default.
///
/// When false (default): the kill switch is REACTIVE — the block-all is only
/// installed during a reconnect gap, and steady-state Connected traffic is
/// contained by routing. Small (~5-30s) detection window on a drop, but the
/// block is never active during normal browsing, so it cannot mis-block.
///
/// When true: Mullvad-style ALWAYS-ON. The block-all stays installed the whole
/// time the tunnel is up, and an INTERFACE-scoped permit on the tunnel adapter
/// LUID (see TUNNEL_LUID / add_permit_tunnel_interface) lets tunneled traffic
/// through while everything on the physical NIC stays blocked — so there is NO
/// leak window, including across reconnects. This is the correct zero-window
/// design, but it MUST be device-verified before being enabled by default: an
/// always-on block that mis-resolves the tunnel LUID would block the user's own
/// tunneled traffic. The dynamic WFP session still guarantees crash-safety
/// (filters auto-removed if the process dies).
static LOCKDOWN_MODE: AtomicBool = AtomicBool::new(false);

/// The WireGuard tunnel adapter's interface LUID, published by the tunnel layer
/// once the Wintun adapter exists (0 = unknown). Lockdown mode permits all
/// traffic egressing this interface so tunneled browsing keeps working under the
/// always-on block-all.
static TUNNEL_LUID: AtomicU64 = AtomicU64::new(0);

/// Engine state protected by a standard mutex (WFP calls are blocking FFI,
/// not async, so a tokio mutex would add unnecessary overhead).
static ENGINE: once_cell::sync::Lazy<std::sync::Mutex<Option<WfpEngine>>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(None));

// ── Backward-compat exports for crash cleanup (main.rs) ─────────────
// FIX-2-1: With dynamic sessions the OS cleans up automatically, so the
// netsh-based crash cleanup in main.rs is now a harmless no-op.  We keep
// these constants so the existing `cleanup_on_crash()` still compiles.
const RULE_BLOCK_ALL: &str = "BirdoVPN_BlockAll";
const RULE_PERMIT_VPN: &str = "BirdoVPN_PermitVPN";
const RULE_PERMIT_LOCALHOST: &str = "BirdoVPN_PermitLocalhost";
const RULE_PERMIT_DHCP: &str = "BirdoVPN_PermitDHCP";
const RULE_BLOCK_IPV6: &str = "BirdoVPN_BlockIPv6";
const RULE_BLOCK_STUN: &str = "BirdoVPN_BlockSTUN";
const RULE_BLOCK_TURN: &str = "BirdoVPN_BlockTURN";

/// L-1: Public rule name constants for use in crash cleanup (main.rs)
/// so hardcoded strings don't drift out of sync with the actual values.
/// NOTE: With the WFP migration these are only needed for the legacy
/// netsh cleanup fallback, which is now a harmless no-op.
pub struct RuleNames {
    pub block_all: &'static str,
    pub permit_vpn: &'static str,
    pub permit_localhost: &'static str,
    pub permit_dhcp: &'static str,
    pub block_ipv6: &'static str,
    pub block_stun: &'static str,
    pub block_turn: &'static str,
}

pub static RULE_NAMES: RuleNames = RuleNames {
    block_all: RULE_BLOCK_ALL,
    permit_vpn: RULE_PERMIT_VPN,
    permit_localhost: RULE_PERMIT_LOCALHOST,
    permit_dhcp: RULE_PERMIT_DHCP,
    block_ipv6: RULE_BLOCK_IPV6,
    block_stun: RULE_BLOCK_STUN,
    block_turn: RULE_BLOCK_TURN,
};

// ── WFP engine wrapper ──────────────────────────────────────────────

/// Holds an open WFP engine handle and tracks the filter IDs that we
/// have installed so they can be removed on deactivation.
struct WfpEngine {
    handle: HANDLE,
    filter_ids: Vec<u64>,
    sublayer_added: bool,
    /// Map from permit_id (V4 filter ID) → (app_path, all filter IDs for that app)
    split_tunnel_map: std::collections::HashMap<u64, (String, Vec<u64>)>,
}

// SAFETY: The WFP engine handle is a plain kernel object handle that
// can safely be sent between threads.  All access is serialized by the
// `ENGINE` mutex.
unsafe impl Send for WfpEngine {}

impl WfpEngine {
    // ── Lifecycle ────────────────────────────────────────────────────

    /// Open a WFP engine session with `FWPM_SESSION_FLAG_DYNAMIC`.
    /// All objects created in this session are automatically removed when
    /// the handle is closed (including on process crash).
    fn open() -> Result<Self, String> {
        let session_name = wide_nul("Birdo VPN Kill Switch");

        let mut session = FWPM_SESSION0::default();
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        session.displayData.name = windows::core::PWSTR(session_name.as_ptr() as *mut u16);

        let mut handle = HANDLE::default();
        // SAFETY: All pointers (`session_name`, `session`) are valid, stack-allocated, and
        // live for the duration of this call.  `handle` is an out-param initialised by the
        // OS; on success we take ownership and release via `FwpmEngineClose0` in `close()`.
        let err = unsafe {
            FwpmEngineOpen0(
                windows::core::PCWSTR::null(), // local engine
                RPC_C_AUTHN_WINNT,
                None,           // default auth identity
                Some(&session), // session config
                &mut handle,    // output handle
            )
        };
        if err != 0 {
            return Err(format!("FwpmEngineOpen0 failed: 0x{:08X}", err));
        }
        Ok(WfpEngine {
            handle,
            filter_ids: Vec::new(),
            sublayer_added: false,
            split_tunnel_map: std::collections::HashMap::new(),
        })
    }

    /// Close the engine handle.  All dynamic-session objects are removed
    /// automatically by the OS.
    fn close(&mut self) -> Result<(), String> {
        if !self.handle.is_invalid() {
            // SAFETY: `self.handle` was obtained from a successful `FwpmEngineOpen0`
            // call and has not been closed yet (checked via `is_invalid()` above).
            // After this call the handle is invalidated and never reused.
            let err = unsafe { FwpmEngineClose0(self.handle) };
            if err != 0 {
                return Err(format!("FwpmEngineClose0 failed: 0x{:08X}", err));
            }
            self.handle = HANDLE::default();
            self.filter_ids.clear();
            self.sublayer_added = false;
            self.split_tunnel_map.clear();
        }
        Ok(())
    }

    // ── Transaction helpers ─────────────────────────────────────────

    fn begin_transaction(&self) -> Result<(), String> {
        // SAFETY: `self.handle` is a valid, open WFP engine handle obtained
        // from `FwpmEngineOpen0`.  No aliasing or lifetime concerns.
        let err = unsafe { FwpmTransactionBegin0(self.handle, 0) };
        if err != 0 {
            return Err(format!("FwpmTransactionBegin0 failed: 0x{:08X}", err));
        }
        Ok(())
    }

    fn commit_transaction(&self) -> Result<(), String> {
        // SAFETY: `self.handle` is a valid, open WFP engine handle with an
        // active transaction started by `begin_transaction`.
        let err = unsafe { FwpmTransactionCommit0(self.handle) };
        if err != 0 {
            return Err(format!("FwpmTransactionCommit0 failed: 0x{:08X}", err));
        }
        Ok(())
    }

    fn abort_transaction(&self) {
        // SAFETY: `self.handle` is a valid, open WFP engine handle.  Aborting
        // a non-existent transaction is a benign no-op per WFP semantics.
        let err = unsafe { FwpmTransactionAbort0(self.handle) };
        if err != 0 {
            tracing::warn!("FwpmTransactionAbort0 failed: 0x{:08X}", err);
        }
    }

    // ── Sublayer management ─────────────────────────────────────────

    fn add_sublayer(&mut self) -> Result<(), String> {
        let name = wide_nul("Birdo VPN Kill Switch");
        let desc = wide_nul("Blocks non-VPN traffic to prevent IP leaks");

        let mut sublayer = FWPM_SUBLAYER0::default();
        sublayer.subLayerKey = BIRDO_SUBLAYER_KEY;
        sublayer.displayData.name = windows::core::PWSTR(name.as_ptr() as *mut u16);
        sublayer.displayData.description = windows::core::PWSTR(desc.as_ptr() as *mut u16);
        sublayer.weight = 0xFFFF; // highest priority sublayer

        // SAFETY: `self.handle` is a valid WFP engine handle.  `sublayer` is a
        // stack-allocated struct whose `name`/`description` borrow `wide_nul` locals
        // that outlive this call.  The default `PSECURITY_DESCRIPTOR` is a null sentinel
        // requesting inherited security.
        let err = unsafe {
            FwpmSubLayerAdd0(
                self.handle,
                &sublayer,
                windows::Win32::Security::PSECURITY_DESCRIPTOR::default(),
            )
        };
        // 0x80320009 = FWP_E_ALREADY_EXISTS — benign during re-init
        if err != 0 && err != 0x80320009 {
            return Err(format!("FwpmSubLayerAdd0 failed: 0x{:08X}", err));
        }
        self.sublayer_added = true;
        Ok(())
    }

    fn delete_sublayer(&mut self) {
        if self.sublayer_added {
            // SAFETY: `self.handle` is a valid WFP engine handle.
            // `BIRDO_SUBLAYER_KEY` is a static GUID with 'static lifetime.
            let err = unsafe { FwpmSubLayerDeleteByKey0(self.handle, &BIRDO_SUBLAYER_KEY) };
            // 0x80320013 = FWP_E_SUBLAYER_NOT_FOUND — benign
            if err != 0 && err != 0x80320013 {
                tracing::warn!("FwpmSubLayerDeleteByKey0 failed: 0x{:08X}", err);
            }
            self.sublayer_added = false;
        }
    }

    // ── Single-filter helpers ───────────────────────────────────────

    fn add_filter(&mut self, filter: &FWPM_FILTER0) -> Result<u64, String> {
        let mut id: u64 = 0;
        // SAFETY: `self.handle` is a valid WFP engine handle.  `filter` is a
        // caller-constructed struct whose field pointers are valid for this call.
        // `id` is an out-param written by the OS on success; we track it in
        // `self.filter_ids` for cleanup.
        let err = unsafe {
            FwpmFilterAdd0(
                self.handle,
                filter,
                windows::Win32::Security::PSECURITY_DESCRIPTOR::default(),
                Some(&mut id),
            )
        };
        if err != 0 {
            return Err(format!("FwpmFilterAdd0 failed: 0x{:08X}", err));
        }
        self.filter_ids.push(id);
        Ok(id)
    }

    fn remove_all_filters(&mut self) {
        let ids: Vec<u64> = self.filter_ids.drain(..).collect();
        for id in ids {
            // SAFETY: `self.handle` is a valid WFP engine handle.  `id` was
            // returned by a prior successful `FwpmFilterAdd0` call.
            let err = unsafe { FwpmFilterDeleteById0(self.handle, id) };
            // 0x80320003 = FWP_E_FILTER_NOT_FOUND — benign
            if err != 0 && err != 0x80320003 {
                tracing::debug!("FwpmFilterDeleteById0({}) warn: 0x{:08X}", id, err);
            }
        }
        // Split tunnel map entries reference filter_ids that were just removed
        self.split_tunnel_map.clear();
    }

    // ── High-level filter builders ──────────────────────────────────

    /// Block ALL outbound IPv4 connections (catch-all, lowest weight).
    fn add_block_all_v4(&mut self) -> Result<(), String> {
        let name = wide_nul("Birdo: Block all outbound IPv4");
        let mut filter = self.make_base_filter(
            &name,
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWP_ACTION_BLOCK,
            WEIGHT_BLOCK_ALL,
        );
        filter.numFilterConditions = 0;
        filter.filterCondition = std::ptr::null_mut();
        self.add_filter(&filter)?;
        Ok(())
    }

    /// Block ALL outbound IPv6 connections (prevents IPv6 leaks).
    fn add_block_all_v6(&mut self) -> Result<(), String> {
        let name = wide_nul("Birdo: Block all outbound IPv6");
        let mut filter = self.make_base_filter(
            &name,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            FWP_ACTION_BLOCK,
            WEIGHT_BLOCK_ALL,
        );
        filter.numFilterConditions = 0;
        filter.filterCondition = std::ptr::null_mut();
        self.add_filter(&filter)?;
        Ok(())
    }

    /// Permit IPv6 localhost (::1/128).
    fn add_permit_localhost_v6(&mut self) -> Result<(), String> {
        let name = wide_nul("Birdo: Permit IPv6 localhost");
        // ::1 = 16 bytes, /128 mask = all ones
        let mut addr_mask = FWP_V6_ADDR_AND_MASK {
            addr: Ipv6Addr::LOCALHOST.octets(),
            prefixLength: 128,
        };

        let mut condition = FWPM_FILTER_CONDITION0::default();
        condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.r#type = FWP_V6_ADDR_MASK;
        condition.conditionValue.Anonymous.v6AddrMask = &mut addr_mask;

        let mut filter = self.make_base_filter(
            &name,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            FWP_ACTION_PERMIT,
            WEIGHT_PERMIT,
        );
        filter.numFilterConditions = 1;
        filter.filterCondition = &mut condition;

        self.add_filter(&filter)?;
        Ok(())
    }

    /// Permit DHCPv6 (UDP ports 546-547).
    fn add_permit_dhcpv6(&mut self) -> Result<(), String> {
        let name = wide_nul("Birdo: Permit DHCPv6");

        // Condition 1: protocol == UDP (17)
        let mut cond_proto = FWPM_FILTER_CONDITION0::default();
        cond_proto.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        cond_proto.matchType = FWP_MATCH_EQUAL;
        cond_proto.conditionValue.r#type = FWP_UINT8;
        cond_proto.conditionValue.Anonymous.uint8 = 17; // IPPROTO_UDP

        // Condition 2: remote port in range 546..=547
        let mut port_range = FWP_RANGE0::default();
        port_range.valueLow.r#type = FWP_UINT16;
        port_range.valueLow.Anonymous.uint16 = 546;
        port_range.valueHigh.r#type = FWP_UINT16;
        port_range.valueHigh.Anonymous.uint16 = 547;

        let mut cond_port = FWPM_FILTER_CONDITION0::default();
        cond_port.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        cond_port.matchType = FWP_MATCH_RANGE;
        cond_port.conditionValue.r#type = FWP_RANGE_TYPE;
        cond_port.conditionValue.Anonymous.rangeValue = &mut port_range;

        let mut conditions = [cond_proto, cond_port];
        let mut filter = self.make_base_filter(
            &name,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            FWP_ACTION_PERMIT,
            WEIGHT_PERMIT,
        );
        filter.numFilterConditions = conditions.len() as u32;
        filter.filterCondition = conditions.as_mut_ptr();

        self.add_filter(&filter)?;
        Ok(())
    }

    /// Install the STANDALONE IPv6 block (block-all v6 + localhost/DHCPv6
    /// permits) in a single transaction. Shared by `block_ipv6()` and by
    /// `deactivate_blocking()`, which must rebuild this block after tearing down
    /// the kill switch's filters if the session still wants IPv6 contained.
    fn install_standalone_v6_block(&mut self) -> Result<(), String> {
        self.begin_transaction()?;
        let result = (|| -> Result<(), String> {
            self.add_sublayer()?; // idempotent (ignores ALREADY_EXISTS)
            self.add_block_all_v6()?;
            self.add_permit_localhost_v6()?;
            self.add_permit_dhcpv6()?;
            Ok(())
        })();

        match result {
            Ok(()) => self.commit_transaction(),
            Err(e) => {
                self.abort_transaction();
                Err(e)
            }
        }
    }

    /// Permit a split-tunnel app on the IPv6 layer.
    /// Returns the filter ID on success, or 0 if the app could not be resolved.
    fn add_permit_app_v6(&mut self, exe_path: &str) -> Result<u64, String> {
        let wide_path = wide_nul(exe_path);

        let mut app_id: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
        let err = unsafe {
            FwpmGetAppIdFromFileName0(windows::core::PCWSTR(wide_path.as_ptr()), &mut app_id)
        };
        // Null-guard the out-param so the later `&mut *app_id` is provably sound
        // (see add_permit_app / CodeQL rust/access-invalid-pointer).
        if err != 0 || app_id.is_null() {
            // Non-fatal: skip. The V4 layer only warns when V4 *also* fails, so
            // surface the V6-only failure here — otherwise a split-tunnel app that
            // resolved on V4 but not V6 is left silently IPv4-only.
            tracing::warn!(
                "FwpmGetAppIdFromFileName0 (v6) failed for '{}': 0x{:08X} — split tunnel will be IPv4-only for this app",
                exe_path,
                err
            );
            return Ok(0);
        }

        let label = format!(
            "Birdo: Permit split-tunnel app v6 ({})",
            std::path::Path::new(exe_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(exe_path)
        );
        let name = wide_nul(&label);

        let mut condition = FWPM_FILTER_CONDITION0::default();
        condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
        condition.conditionValue.Anonymous.byteBlob = unsafe { &mut *app_id };

        let mut filter = self.make_base_filter(
            &name,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            FWP_ACTION_PERMIT,
            WEIGHT_PERMIT,
        );
        filter.numFilterConditions = 1;
        filter.filterCondition = &mut condition;

        let result = self.add_filter(&filter);

        unsafe {
            FwpmFreeMemory0(&mut (app_id as *mut std::ffi::c_void));
        }

        result.inspect(|&id| {
            tracing::debug!(
                "Split tunnel permit v6 added for: {} (filter_id={})",
                exe_path,
                id
            );
        })
    }

    /// Block STUN/TURN ports on IPv6 layer (mirrors IPv4 STUN blocking).
    fn add_block_stun_turn_v6(&mut self) -> Result<(), String> {
        self.add_port_range_block_v6("Birdo: Block STUN/UDP v6", 17, 3478, 3497)?;
        self.add_port_range_block_v6("Birdo: Block TURN/TCP v6", 6, 3478, 3497)?;
        self.add_port_range_block_v6("Birdo: Block Google STUN v6", 17, 19302, 19302)?;
        Ok(())
    }

    /// Helper — block a remote port range for a given IP protocol on IPv6 layer.
    fn add_port_range_block_v6(
        &mut self,
        label: &str,
        protocol: u8,
        port_low: u16,
        port_high: u16,
    ) -> Result<(), String> {
        let name = wide_nul(label);

        let mut cond_proto = FWPM_FILTER_CONDITION0::default();
        cond_proto.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        cond_proto.matchType = FWP_MATCH_EQUAL;
        cond_proto.conditionValue.r#type = FWP_UINT8;
        cond_proto.conditionValue.Anonymous.uint8 = protocol;

        let mut port_range = FWP_RANGE0::default();
        port_range.valueLow.r#type = FWP_UINT16;
        port_range.valueLow.Anonymous.uint16 = port_low;
        port_range.valueHigh.r#type = FWP_UINT16;
        port_range.valueHigh.Anonymous.uint16 = port_high;

        let mut cond_port = FWPM_FILTER_CONDITION0::default();
        cond_port.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        cond_port.matchType = FWP_MATCH_RANGE;
        cond_port.conditionValue.r#type = FWP_RANGE_TYPE;
        cond_port.conditionValue.Anonymous.rangeValue = &mut port_range;

        let mut conditions = [cond_proto, cond_port];
        let mut filter = self.make_base_filter(
            &name,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            FWP_ACTION_BLOCK,
            WEIGHT_BLOCK_STUN,
        );
        filter.numFilterConditions = conditions.len() as u32;
        filter.filterCondition = conditions.as_mut_ptr();

        self.add_filter(&filter)?;
        Ok(())
    }

    /// Permit localhost (127.0.0.0/8).
    fn add_permit_localhost(&mut self) -> Result<(), String> {
        let name = wide_nul("Birdo: Permit localhost");
        let mut addr_mask = FWP_V4_ADDR_AND_MASK {
            addr: u32::from(Ipv4Addr::new(127, 0, 0, 0)),
            mask: u32::from(Ipv4Addr::new(255, 0, 0, 0)),
        };

        let mut condition = FWPM_FILTER_CONDITION0::default();
        condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.r#type = FWP_V4_ADDR_MASK;
        condition.conditionValue.Anonymous.v4AddrMask = &mut addr_mask;

        let mut filter = self.make_base_filter(
            &name,
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWP_ACTION_PERMIT,
            WEIGHT_PERMIT,
        );
        filter.numFilterConditions = 1;
        filter.filterCondition = &mut condition;

        self.add_filter(&filter)?;
        Ok(())
    }

    /// Permit DHCP (UDP ports 67-68 for network discovery).
    fn add_permit_dhcp(&mut self) -> Result<(), String> {
        let name = wide_nul("Birdo: Permit DHCP");

        // Condition 1: protocol == UDP (17)
        let mut cond_proto = FWPM_FILTER_CONDITION0::default();
        cond_proto.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        cond_proto.matchType = FWP_MATCH_EQUAL;
        cond_proto.conditionValue.r#type = FWP_UINT8;
        cond_proto.conditionValue.Anonymous.uint8 = 17; // IPPROTO_UDP

        // Condition 2: remote port in range 67..=68
        let mut port_range = FWP_RANGE0::default();
        port_range.valueLow.r#type = FWP_UINT16;
        port_range.valueLow.Anonymous.uint16 = 67;
        port_range.valueHigh.r#type = FWP_UINT16;
        port_range.valueHigh.Anonymous.uint16 = 68;

        let mut cond_port = FWPM_FILTER_CONDITION0::default();
        cond_port.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        cond_port.matchType = FWP_MATCH_RANGE;
        cond_port.conditionValue.r#type = FWP_RANGE_TYPE;
        cond_port.conditionValue.Anonymous.rangeValue = &mut port_range;

        let mut conditions = [cond_proto, cond_port];
        let mut filter = self.make_base_filter(
            &name,
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWP_ACTION_PERMIT,
            WEIGHT_PERMIT,
        );
        filter.numFilterConditions = conditions.len() as u32;
        filter.filterCondition = conditions.as_mut_ptr();

        self.add_filter(&filter)?;
        Ok(())
    }

    /// Permit traffic to a specific VPN server IP (/32).
    fn add_permit_vpn_server(&mut self, ip: Ipv4Addr) -> Result<(), String> {
        let name = wide_nul("Birdo: Permit VPN server");
        let mut addr_mask = FWP_V4_ADDR_AND_MASK {
            addr: u32::from(ip),
            mask: 0xFFFF_FFFF, // /32
        };

        let mut condition = FWPM_FILTER_CONDITION0::default();
        condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.r#type = FWP_V4_ADDR_MASK;
        condition.conditionValue.Anonymous.v4AddrMask = &mut addr_mask;

        let mut filter = self.make_base_filter(
            &name,
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWP_ACTION_PERMIT,
            WEIGHT_PERMIT,
        );
        filter.numFilterConditions = 1;
        filter.filterCondition = &mut condition;

        self.add_filter(&filter)?;
        Ok(())
    }

    /// LOCKDOWN: permit ALL outbound traffic that egresses the tunnel (Wintun)
    /// interface, matched by its interface LUID. This is the load-bearing
    /// primitive for always-on mode: it lets tunneled traffic through while a
    /// block-all on the physical NIC stays in force, so there is no leak window.
    /// Call once per ALE layer (v4 and v6).
    ///
    /// `IP_LOCAL_INTERFACE` matches on the 64-bit interface LUID (FWP_UINT64).
    fn add_permit_tunnel_interface(
        &mut self,
        luid: u64,
        layer: GUID,
        label: &str,
    ) -> Result<(), String> {
        let name = wide_nul(label);
        // The condition value holds a POINTER to the u64; keep it alive until
        // add_filter() copies the filter into WFP (same pattern as the
        // V4_ADDR_AND_MASK in add_permit_vpn_server).
        let mut luid_val: u64 = luid;

        let mut condition = FWPM_FILTER_CONDITION0::default();
        condition.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.r#type = FWP_UINT64;
        condition.conditionValue.Anonymous.uint64 = &mut luid_val;

        let mut filter = self.make_base_filter(&name, layer, FWP_ACTION_PERMIT, WEIGHT_PERMIT);
        filter.numFilterConditions = 1;
        filter.filterCondition = &mut condition;

        self.add_filter(&filter)?;
        Ok(())
    }

    /// Block WebRTC STUN/TURN ports to prevent IP leak via WebRTC.
    /// - UDP 3478-3497 (standard STUN/TURN)
    /// - TCP 3478-3497 (TURN over TCP)
    /// - UDP 19302     (Google STUN — Chrome/Edge)
    fn add_block_stun_turn(&mut self) -> Result<(), String> {
        self.add_port_range_block("Birdo: Block STUN/UDP", 17, 3478, 3497)?;
        self.add_port_range_block("Birdo: Block TURN/TCP", 6, 3478, 3497)?;
        self.add_port_range_block("Birdo: Block Google STUN", 17, 19302, 19309)?;
        Ok(())
    }

    /// Helper — block a remote port range for a given IP protocol.
    fn add_port_range_block(
        &mut self,
        label: &str,
        protocol: u8,
        port_low: u16,
        port_high: u16,
    ) -> Result<(), String> {
        let name = wide_nul(label);

        // Condition 1: IP protocol
        let mut cond_proto = FWPM_FILTER_CONDITION0::default();
        cond_proto.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        cond_proto.matchType = FWP_MATCH_EQUAL;
        cond_proto.conditionValue.r#type = FWP_UINT8;
        cond_proto.conditionValue.Anonymous.uint8 = protocol;

        // Condition 2: remote port range
        let mut port_range = FWP_RANGE0::default();
        port_range.valueLow.r#type = FWP_UINT16;
        port_range.valueLow.Anonymous.uint16 = port_low;
        port_range.valueHigh.r#type = FWP_UINT16;
        port_range.valueHigh.Anonymous.uint16 = port_high;

        let mut cond_port = FWPM_FILTER_CONDITION0::default();
        cond_port.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        cond_port.matchType = FWP_MATCH_RANGE;
        cond_port.conditionValue.r#type = FWP_RANGE_TYPE;
        cond_port.conditionValue.Anonymous.rangeValue = &mut port_range;

        let mut conditions = [cond_proto, cond_port];
        let mut filter = self.make_base_filter(
            &name,
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWP_ACTION_BLOCK,
            WEIGHT_BLOCK_STUN,
        );
        filter.numFilterConditions = conditions.len() as u32;
        filter.filterCondition = conditions.as_mut_ptr();

        self.add_filter(&filter)?;
        Ok(())
    }

    // ── Local network sharing filters ────────────────────────────────

    /// Permit RFC1918 private network traffic (local network sharing).
    /// Adds permit filters for 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    /// so users can access printers, NAS devices, and other LAN resources
    /// while the kill switch is active.
    fn add_permit_local_networks(&mut self) -> Result<(), String> {
        let ranges: [(&str, Ipv4Addr, Ipv4Addr); 3] = [
            (
                "Birdo: Permit LAN 10.0.0.0/8",
                Ipv4Addr::new(10, 0, 0, 0),
                Ipv4Addr::new(255, 0, 0, 0),
            ),
            (
                "Birdo: Permit LAN 172.16.0.0/12",
                Ipv4Addr::new(172, 16, 0, 0),
                Ipv4Addr::new(255, 240, 0, 0),
            ),
            (
                "Birdo: Permit LAN 192.168.0.0/16",
                Ipv4Addr::new(192, 168, 0, 0),
                Ipv4Addr::new(255, 255, 0, 0),
            ),
        ];

        for (label, network, mask) in &ranges {
            let name = wide_nul(label);
            let mut addr_mask = FWP_V4_ADDR_AND_MASK {
                addr: u32::from(*network),
                mask: u32::from(*mask),
            };

            let mut condition = FWPM_FILTER_CONDITION0::default();
            condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
            condition.matchType = FWP_MATCH_EQUAL;
            condition.conditionValue.r#type = FWP_V4_ADDR_MASK;
            condition.conditionValue.Anonymous.v4AddrMask = &mut addr_mask;

            let mut filter = self.make_base_filter(
                &name,
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                FWP_ACTION_PERMIT,
                WEIGHT_PERMIT,
            );
            filter.numFilterConditions = 1;
            filter.filterCondition = &mut condition;

            self.add_filter(&filter)?;
            tracing::debug!("Permitted local network: {}", label);
        }

        // Also permit link-local (169.254.0.0/16) for mDNS/AirPrint discovery
        let name = wide_nul("Birdo: Permit link-local");
        let mut addr_mask = FWP_V4_ADDR_AND_MASK {
            addr: u32::from(Ipv4Addr::new(169, 254, 0, 0)),
            mask: u32::from(Ipv4Addr::new(255, 255, 0, 0)),
        };
        let mut condition = FWPM_FILTER_CONDITION0::default();
        condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.r#type = FWP_V4_ADDR_MASK;
        condition.conditionValue.Anonymous.v4AddrMask = &mut addr_mask;
        let mut filter = self.make_base_filter(
            &name,
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWP_ACTION_PERMIT,
            WEIGHT_PERMIT,
        );
        filter.numFilterConditions = 1;
        filter.filterCondition = &mut condition;
        self.add_filter(&filter)?;

        tracing::info!("Local network sharing: 4 permit filters added (RFC1918 + link-local)");
        Ok(())
    }

    // ── Split tunneling filters ─────────────────────────────────────

    /// Permit all traffic from a specific application executable.
    /// Uses FwpmGetAppIdFromFileName0 to get the WFP app ID blob,
    /// then adds a permit filter matching that app ID.
    fn add_permit_app(&mut self, exe_path: &str) -> Result<u64, String> {
        let wide_path = wide_nul(exe_path);

        // Get the WFP application ID blob for this executable
        let mut app_id: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
        // SAFETY: `wide_path` is a valid null-terminated UTF-16 string.
        // `app_id` is an out-param that receives a pointer to an OS-allocated blob.
        // We free it with `FwpmFreeMemory0` after building the filter.
        let err = unsafe {
            FwpmGetAppIdFromFileName0(windows::core::PCWSTR(wide_path.as_ptr()), &mut app_id)
        };
        // Treat a null out-param as failure too: FwpmGetAppIdFromFileName0 is
        // documented to populate `app_id` on ERROR_SUCCESS, but guarding the
        // pointer explicitly makes the later `&mut *app_id` deref provably sound
        // (and silences CodeQL rust/access-invalid-pointer).
        if err != 0 || app_id.is_null() {
            tracing::warn!(
                "FwpmGetAppIdFromFileName0 failed for '{}': 0x{:08X} — skipping",
                exe_path,
                err
            );
            return Ok(0); // Non-fatal: skip this app rather than fail the whole transaction
        }

        let label = format!(
            "Birdo: Permit split-tunnel app ({})",
            std::path::Path::new(exe_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(exe_path)
        );
        let name = wide_nul(&label);

        let mut condition = FWPM_FILTER_CONDITION0::default();
        condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
        // SAFETY: `app_id` was successfully obtained from FwpmGetAppIdFromFileName0
        // and is valid until we call FwpmFreeMemory0.
        condition.conditionValue.Anonymous.byteBlob = unsafe { &mut *app_id };

        let mut filter = self.make_base_filter(
            &name,
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWP_ACTION_PERMIT,
            WEIGHT_PERMIT,
        );
        filter.numFilterConditions = 1;
        filter.filterCondition = &mut condition;

        let result = self.add_filter(&filter);

        // SAFETY: Free the OS-allocated blob. The filter has been committed
        // (or will be via transaction), so the blob is no longer needed.
        unsafe {
            FwpmFreeMemory0(&mut (app_id as *mut std::ffi::c_void));
        }

        result.inspect(|&id| {
            tracing::debug!(
                "Split tunnel permit added for: {} (filter_id={})",
                exe_path,
                id
            );
        })
    }

    // ── Shared filter template ──────────────────────────────────────

    /// Build a `FWPM_FILTER0` with common fields set.
    /// Caller must fill `numFilterConditions`, `filterCondition`, and
    /// call `add_filter()`.
    fn make_base_filter(
        &self,
        name: &[u16], // null-terminated UTF-16
        layer: GUID,
        action: FWP_ACTION_TYPE,
        weight: u8,
    ) -> FWPM_FILTER0 {
        let mut filter = FWPM_FILTER0::default();
        filter.displayData.name = windows::core::PWSTR(name.as_ptr() as *mut u16);
        filter.flags = FWPM_FILTER_FLAG_NONE;
        filter.layerKey = layer;
        filter.subLayerKey = BIRDO_SUBLAYER_KEY;
        filter.weight.r#type = FWP_UINT8;
        filter.weight.Anonymous.uint8 = weight;
        filter.action.r#type = action;
        filter
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Create a null-terminated UTF-16 string for Win32 wide-char APIs.
fn wide_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0u16)).collect()
}

// ── Public API ───────────────────────────────────────────────────────
// Function signatures are unchanged from the netsh era so that
// `killswitch.rs` and `auto_reconnect.rs` need zero changes.

/// Initialize the kill switch subsystem.
///
/// Opens a WFP engine session with `FWPM_SESSION_FLAG_DYNAMIC`.
pub async fn initialize() -> Result<(), String> {
    if IS_INITIALIZED.load(Ordering::SeqCst) {
        tracing::debug!("Kill switch already initialized");
        return Ok(());
    }

    if !is_admin() {
        return Err("Administrator privileges required for kill switch".to_string());
    }

    tracing::info!("Initializing kill switch (WFP API — FIX-2-1)");

    let engine = WfpEngine::open().map_err(|e| {
        tracing::error!("Failed to open WFP engine: {}", e);
        e
    })?;

    {
        let mut guard = ENGINE
            .lock()
            .map_err(|e| format!("engine lock poisoned: {}", e))?;
        *guard = Some(engine);
    }

    IS_INITIALIZED.store(true, Ordering::SeqCst);
    tracing::info!("Kill switch initialized (WFP dynamic session)");
    Ok(())
}

/// Set the VPN server IP that should be permitted through the kill switch.
pub async fn set_vpn_server(ip: Ipv4Addr) {
    let mut server = VPN_SERVER_IP.write().await;
    *server = Some(ip);
    tracing::debug!("VPN server IP set to: {}", ip);
}

/// Activate the kill switch — block all traffic except VPN, localhost,
/// and DHCP inside a single atomic WFP transaction.
pub async fn activate_blocking() -> Result<(), String> {
    if !IS_INITIALIZED.load(Ordering::SeqCst) {
        return Err("Kill switch not initialized".to_string());
    }

    let vpn_ip = *VPN_SERVER_IP.read().await;

    let mut guard = ENGINE
        .lock()
        .map_err(|e| format!("engine lock poisoned: {}", e))?;
    let engine = guard.as_mut().ok_or("WFP engine not open")?;

    // Snapshot the current WFP bookkeeping so it can be restored if a REFRESH
    // transaction aborts. The teardown of the existing filters now runs INSIDE
    // the transaction (below), so an abort rolls those deletes back and the OLD
    // filter set survives in WFP — our in-memory tracking must then match it.
    let was_blocking = IS_BLOCKING.load(Ordering::SeqCst);
    let saved_filter_ids = engine.filter_ids.clone();
    let saved_sublayer_added = engine.sublayer_added;
    let saved_split_tunnel_map = engine.split_tunnel_map.clone();

    tracing::info!("Activating kill switch (WFP atomic transaction)");
    engine.begin_transaction()?;

    let result = (|| -> Result<(), String> {
        // Refresh path: tear down the existing filters INSIDE the transaction so
        // the delete is atomic with the rebuild. On commit the old->new swap has
        // ZERO gap; on abort the deletes roll back so the old filters keep
        // blocking — closing the leak window that existed when the teardown ran
        // BEFORE begin_transaction().
        if was_blocking {
            tracing::debug!("Kill switch already active — refreshing filters in-transaction");
            engine.remove_all_filters();
            engine.delete_sublayer();
        }
        engine.add_sublayer()?;

        // Block-all rules (low weight, evaluated last)
        engine.add_block_all_v4()?;
        engine.add_block_all_v6()?;

        // Permit exceptions (high weight, evaluated first)
        engine.add_permit_localhost()?;
        engine.add_permit_localhost_v6()?;
        engine.add_permit_dhcp()?;
        engine.add_permit_dhcpv6()?;

        if let Some(ip) = vpn_ip {
            engine.add_permit_vpn_server(ip)?;
            tracing::debug!("VPN server {} permitted through kill switch", ip);
        }

        // CRITICAL (AUDIT-2026-06-19): permit the Birdo client's OWN process.
        //
        // The kill switch's block-all is active during the reconnect gap, but
        // auto-reconnect must reach api.birdo.app — over the PHYSICAL adapter,
        // since the tunnel is down — to fetch a fresh config, and that control
        // plane is NOT the VPN server /32. Without this permit, arming the kill
        // switch blocks auto-reconnect's own API call and reconnect can never
        // succeed. Permitting our own executable lets the client's cert-pinned
        // control-plane HTTPS, its DoH lookups, and its in-process WireGuard
        // socket through, while every OTHER application stays blocked — so user
        // traffic still cannot leak. (We bypass the kill switch only for the VPN
        // client itself, which is exactly the process that must keep talking to
        // the VPN infrastructure to restore the tunnel.)
        match std::env::current_exe()
            .ok()
            .and_then(|p| p.to_str().map(String::from))
        {
            Some(self_exe) => {
                let v4 = engine.add_permit_app(&self_exe)?;
                if v4 != 0 {
                    let _ = engine.add_permit_app_v6(&self_exe)?;
                }
                tracing::info!(
                    "Kill switch: permitted own process for control-plane / reconnect access"
                );
            }
            None => {
                // Fail loud but do not abort the whole transaction: a kill switch
                // that cannot self-permit will break reconnect, but we still want
                // user traffic blocked. Surface it so it is not silent.
                tracing::error!(
                    "Kill switch: could NOT determine own exe path — reconnect may be blocked while the kill switch is active"
                );
            }
        }

        // LOCKDOWN (always-on): permit the tunnel interface so tunneled traffic
        // flows while the block-all on the physical NIC stays in force. This is
        // what makes a continuously-active block-all safe — without it, an
        // always-on block would block the user's own tunneled browsing. We refuse
        // to install the block in lockdown if the tunnel LUID is unknown (aborts
        // the transaction → no filters), rather than silently block everything.
        if LOCKDOWN_MODE.load(Ordering::SeqCst) {
            let luid = TUNNEL_LUID.load(Ordering::SeqCst);
            if luid == 0 {
                return Err(
                    "Lockdown mode: tunnel interface LUID unknown — refusing to install \
                     block-all without a tunnel-interface permit (would block tunneled traffic)"
                        .to_string(),
                );
            }
            engine.add_permit_tunnel_interface(
                luid,
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                "Birdo: Permit tunnel interface (v4)",
            )?;
            engine.add_permit_tunnel_interface(
                luid,
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                "Birdo: Permit tunnel interface (v6)",
            )?;
            tracing::info!(
                "Lockdown: permitted tunnel interface LUID {} (zero-window always-on)",
                luid
            );
        }

        // Local network sharing: permit RFC1918 private ranges
        if LOCAL_NETWORK_SHARING.load(Ordering::SeqCst) {
            engine.add_permit_local_networks()?;
        }

        // Split tunneling: permit traffic from excluded apps (IPv4 + IPv6)
        let split_apps = SPLIT_TUNNEL_APPS.try_read();
        if let Err(e) = &split_apps {
            // Lock poisoned (prior writer panicked) or momentarily contended:
            // split-tunnel permits are skipped this activation. Warn rather than
            // disable silently — otherwise excluded apps get killed by the switch
            // with no indication why.
            tracing::warn!(
                "Split tunnel apps lock unavailable ({}) — skipping split-tunnel permits this activation",
                e
            );
        }
        if let Ok(apps) = split_apps {
            if !apps.is_empty() {
                tracing::info!("Adding split tunnel permits for {} app(s)", apps.len());
                for app_path in apps.iter() {
                    let v4_id = engine.add_permit_app(app_path)?;
                    if v4_id != 0 {
                        let mut ids = vec![v4_id];
                        let v6_id = engine.add_permit_app_v6(app_path)?;
                        if v6_id != 0 {
                            ids.push(v6_id);
                        }
                        engine
                            .split_tunnel_map
                            .insert(v4_id, (app_path.clone(), ids));
                    }
                }
            }
        }

        // WebRTC STUN/TURN leak prevention (highest weight, IPv4 + IPv6)
        engine.add_block_stun_turn()?;
        engine.add_block_stun_turn_v6()?;

        Ok(())
    })();

    match result {
        Ok(()) => {
            engine.commit_transaction()?;
            IS_BLOCKING.store(true, Ordering::SeqCst);
            tracing::info!(
                "Kill switch activated — {} WFP filters committed atomically",
                engine.filter_ids.len()
            );
            Ok(())
        }
        Err(e) => {
            tracing::error!("Filter setup failed, aborting transaction: {}", e);
            engine.abort_transaction();
            if was_blocking {
                // The abort rolled back the in-transaction deletes, so the OLD
                // filter set is still active in WFP. Restore the bookkeeping to
                // match and stay blocking — no leak; IS_BLOCKING stays true.
                engine.filter_ids = saved_filter_ids;
                engine.sublayer_added = saved_sublayer_added;
                engine.split_tunnel_map = saved_split_tunnel_map;
                tracing::warn!(
                    "Kill-switch refresh failed; retained the previous filter set (still blocking)"
                );
            } else {
                // Fresh activation failed and nothing was blocking before — clear
                // bookkeeping and remain unblocked.
                engine.filter_ids.clear();
                engine.sublayer_added = false;
                IS_BLOCKING.store(false, Ordering::SeqCst);
            }
            Err(e)
        }
    }
}

/// Deactivate the kill switch (restore normal traffic).
pub async fn deactivate_blocking() -> Result<(), String> {
    if !IS_BLOCKING.load(Ordering::SeqCst) {
        tracing::debug!("Kill switch not active");
        return Ok(());
    }

    tracing::info!("Deactivating kill switch");

    let mut guard = ENGINE
        .lock()
        .map_err(|e| format!("engine lock poisoned: {}", e))?;
    if let Some(engine) = guard.as_mut() {
        engine.remove_all_filters();
        engine.delete_sublayer();
    }

    IS_BLOCKING.store(false, Ordering::SeqCst);

    // The filters just removed included the kill switch's own IPv6 block. If the
    // session still wants IPv6 contained (a tunnel is up or coming up), rebuild
    // the standalone block in the same call — otherwise a reconnect cycle ends
    // with IPv6 wide open for the rest of the session.
    if v6_state::on_deactivate() {
        let reinstalled = match guard.as_mut() {
            Some(engine) => engine.install_standalone_v6_block(),
            None => Err("WFP engine not open".to_string()),
        };
        match reinstalled {
            Ok(()) => {
                v6_state::mark_installed(true);
                tracing::info!("Standalone IPv6 block re-installed after kill-switch deactivation");
            }
            Err(e) => {
                v6_state::mark_installed(false);
                tracing::error!(
                    "Kill switch deactivated but the standalone IPv6 block could NOT be re-installed: {} — IPv6 may leak",
                    e
                );
                return Err(format!("IPv6 block re-install failed: {}", e));
            }
        }
    }

    tracing::info!("Kill switch deactivated — normal traffic restored");
    Ok(())
}

/// Ownership rules for the standalone IPv6 block, kept engine-free so they can
/// be unit-tested without an elevated WFP session (CI runners are not elevated).
/// Every public IPv6 entry point below routes its decision through here.
mod v6_state {
    use super::{IPV6_BLOCK_HELD, IPV6_BLOCK_WANTED, IPV6_ONLY_ACTIVE, IS_BLOCKING};
    use std::sync::atomic::Ordering;

    /// `block_ipv6()` — record the session intent UNCONDITIONALLY, then report
    /// whether standalone filters still need installing.
    ///
    /// When the kill switch is active it already blocks IPv6, so no standalone
    /// filters are added; the intent is still recorded so `deactivate_blocking()`
    /// re-installs the block when the kill switch's filters go away. Without the
    /// intent, a reconnect cycle (block → kill switch → new tunnel → kill switch
    /// off) left IPv6 unblocked for the rest of the session.
    pub(super) fn on_block() -> bool {
        IPV6_BLOCK_WANTED.store(true, Ordering::SeqCst);
        if IS_BLOCKING.load(Ordering::SeqCst) {
            IPV6_ONLY_ACTIVE.store(false, Ordering::SeqCst); // kill switch owns the block
            return false;
        }
        // Already installed — adding a second identical filter set would just
        // duplicate kernel filters (a server switch re-enters here with the block
        // still held).
        !IPV6_ONLY_ACTIVE.load(Ordering::SeqCst)
    }

    /// `unblock_ipv6()` — report whether the standalone filters must be removed.
    ///
    /// While the kill switch owns the block, or a server switch is holding it
    /// across a teardown, the intent AND `IPV6_ONLY_ACTIVE` are left untouched:
    /// consuming either here is what permanently deleted the block on a reactive
    /// kill-switch cycle.
    pub(super) fn on_unblock() -> bool {
        if IS_BLOCKING.load(Ordering::SeqCst) || IPV6_BLOCK_HELD.load(Ordering::SeqCst) {
            return false;
        }
        IPV6_BLOCK_WANTED.store(false, Ordering::SeqCst);
        IPV6_ONLY_ACTIVE.swap(false, Ordering::SeqCst)
    }

    /// `unblock_ipv6_dual_stack()` — the tunnel ROUTES IPv6, so the session no
    /// longer wants it blocked. Drops the intent even while the kill switch owns
    /// the block (its block-all still covers v6 during the gap, but once it is
    /// deactivated IPv6 must be free to flow through the tunnel), and reports
    /// whether our own standalone filters still need removing.
    pub(super) fn on_dual_stack() -> bool {
        IPV6_BLOCK_WANTED.store(false, Ordering::SeqCst);
        IPV6_BLOCK_HELD.store(false, Ordering::SeqCst);
        if IS_BLOCKING.load(Ordering::SeqCst) {
            return false; // kill switch owns every filter — leave them alone
        }
        IPV6_ONLY_ACTIVE.swap(false, Ordering::SeqCst)
    }

    /// `deactivate_blocking()` — the kill switch's filters (its v6 block
    /// included) have just been removed. Report whether the standalone block must
    /// be rebuilt to honour the session intent.
    pub(super) fn on_deactivate() -> bool {
        IPV6_BLOCK_WANTED.load(Ordering::SeqCst)
    }

    /// `cleanup()` — the session is over (user disconnect / disarm). Drop the
    /// intent BEFORE anything can act on it, so a disconnect never leaves IPv6
    /// blocked with no tunnel to remove the block.
    pub(super) fn on_cleanup() {
        IPV6_BLOCK_WANTED.store(false, Ordering::SeqCst);
        IPV6_BLOCK_HELD.store(false, Ordering::SeqCst);
        IPV6_ONLY_ACTIVE.store(false, Ordering::SeqCst);
    }

    /// Record whether the standalone filters are installed (post-transaction).
    pub(super) fn mark_installed(installed: bool) {
        IPV6_ONLY_ACTIVE.store(installed, Ordering::SeqCst);
    }
}

/// Block ALL outbound IPv6 natively via WFP, WITHOUT the full kill switch.
///
/// This is the fast path for IPv6 leak prevention on connect: a kernel WFP
/// filter at the ALE_AUTH_CONNECT_V6 layer (plus localhost/DHCPv6 permits) added
/// in a single transaction — microseconds, no netsh/PowerShell subprocess. The
/// old netsh `remoteip=::/0` rules were rejected by netsh and fell back to a
/// ~14s PowerShell `Disable-NetAdapterBinding`; this replaces all of that.
///
/// Records the session's IPv6-block intent even when the full kill switch is
/// active (it blocks IPv6 already) so the block is rebuilt if the kill switch is
/// later deactivated.
pub async fn block_ipv6() -> Result<(), String> {
    if !v6_state::on_block() {
        tracing::debug!("IPv6 block already in force — intent recorded, no filters added");
        return Ok(());
    }
    if !IS_INITIALIZED.load(Ordering::SeqCst) {
        initialize().await?;
    }

    let mut guard = ENGINE
        .lock()
        .map_err(|e| format!("engine lock poisoned: {}", e))?;
    let engine = guard.as_mut().ok_or("WFP engine not open")?;

    engine.install_standalone_v6_block()?;
    v6_state::mark_installed(true);
    tracing::info!("IPv6 leak protection enabled (native WFP)");
    Ok(())
}

/// Remove the standalone IPv6 block added by [`block_ipv6`]. Fast, native.
/// No-op if we never added it, if the full kill switch owns the filters, or if a
/// server switch is holding the block across a tunnel teardown.
pub async fn unblock_ipv6() -> Result<(), String> {
    if !v6_state::on_unblock() {
        return Ok(());
    }
    remove_standalone_v6_filters()
}

/// Lift the IPv6 block for a DUAL-STACK tunnel, which routes IPv6 through the
/// tunnel instead of blocking it.
///
/// Unlike [`unblock_ipv6`], this also drops the session's block intent while the
/// kill switch is active, so deactivating the kill switch after a reconnect does
/// not re-install a block that a dual-stack tunnel must not have.
pub async fn unblock_ipv6_dual_stack() -> Result<(), String> {
    if !v6_state::on_dual_stack() {
        return Ok(());
    }
    remove_standalone_v6_filters()
}

/// Drop every filter we hold. Only ever called when the kill switch is NOT
/// active, so the engine holds our standalone IPv6 filters and nothing else.
fn remove_standalone_v6_filters() -> Result<(), String> {
    let mut guard = ENGINE
        .lock()
        .map_err(|e| format!("engine lock poisoned: {}", e))?;
    if let Some(engine) = guard.as_mut() {
        engine.remove_all_filters();
        engine.delete_sublayer();
    }
    tracing::debug!("Standalone IPv6 block removed (native WFP)");
    Ok(())
}

/// Hold the IPv6 block across a tunnel teardown that is immediately followed by
/// a new tunnel (server switch): `unblock_ipv6()` becomes a no-op until the hold
/// is released, so IPv6 stays contained for the whole switch.
///
/// The caller MUST release the hold once the teardown is done, otherwise a later
/// disconnect could not remove the block. `cleanup()` clears it unconditionally.
pub fn hold_ipv6_block(held: bool) {
    IPV6_BLOCK_HELD.store(held, Ordering::SeqCst);
}

/// Update the VPN server IP in an active kill switch.
///
/// Rebuilds all filters atomically to swap the permitted server.
pub async fn update_vpn_server(ip: Ipv4Addr) -> Result<(), String> {
    set_vpn_server(ip).await;

    // In LOCKDOWN mode, do NOT re-activate here: this is called on the connect
    // path BEFORE the new tunnel exists, so TUNNEL_LUID still holds the OLD
    // (about-to-be-freed) adapter's LUID — re-activating now would permit a stale
    // interface LUID that Windows may reassign to a physical NIC. Re-activation
    // in lockdown is driven by the tunnel layer once the NEW adapter publishes
    // its LUID (see tunnel.rs configure_adapter), so the active block always
    // permits the CURRENT tunnel interface. Reactive mode re-activates here as
    // before to swap the server permit.
    if IS_BLOCKING.load(Ordering::SeqCst) && !LOCKDOWN_MODE.load(Ordering::SeqCst) {
        // Re-activate atomically with the new VPN server IP
        activate_blocking().await?;
        tracing::info!("Updated VPN server permit: {}", ip);
    }

    Ok(())
}

/// Check if the kill switch is currently active.
pub fn is_blocking() -> bool {
    IS_BLOCKING.load(Ordering::SeqCst)
}

/// Check if the kill switch is initialized.
///
/// DT-6: the `get_wfp_status` IPC command that read this was removed (never
/// invoked from the UI). Kept as a public status accessor alongside
/// `is_blocking`; allow dead_code until a caller is re-added.
#[allow(dead_code)]
pub fn is_initialized() -> bool {
    IS_INITIALIZED.load(Ordering::SeqCst)
}

/// Enable/disable lockdown (always-on) mode. Takes effect on the next
/// `activate_blocking()`. Driven by the `lockdown_mode` user setting (OFF by
/// default). See LOCKDOWN_MODE for the full semantics.
pub fn set_lockdown_mode(enabled: bool) {
    LOCKDOWN_MODE.store(enabled, Ordering::SeqCst);
    tracing::info!("Kill switch lockdown (always-on) mode set to: {}", enabled);
}

/// Whether lockdown (always-on) mode is enabled.
pub fn is_lockdown_mode() -> bool {
    LOCKDOWN_MODE.load(Ordering::SeqCst)
}

/// Publish the tunnel adapter's interface LUID (from the tunnel layer once the
/// Wintun adapter exists). Lockdown mode permits this interface so tunneled
/// traffic flows under the always-on block-all.
pub fn set_tunnel_luid(luid: u64) {
    TUNNEL_LUID.store(luid, Ordering::SeqCst);
    tracing::debug!("Kill switch tunnel LUID set to: {}", luid);
}

/// Clear the published tunnel LUID (on tunnel teardown).
pub fn clear_tunnel_luid() {
    TUNNEL_LUID.store(0, Ordering::SeqCst);
}

/// Clean up and release all resources.
///
/// Deactivates blocking (if active), then closes the WFP engine handle.
/// Because the session is dynamic, Windows removes any straggling
/// filters automatically.
pub async fn cleanup() -> Result<(), String> {
    tracing::info!("Cleaning up kill switch resources");

    // Drop the IPv6-block intent FIRST: cleanup() is the end of the session (a
    // user-initiated disconnect calls it via killswitch::disarm(), including one
    // issued mid-reconnect), so the deactivate_blocking() below must NOT rebuild
    // a standalone IPv6 block that no tunnel would ever remove.
    v6_state::on_cleanup();

    if IS_BLOCKING.load(Ordering::SeqCst) {
        deactivate_blocking().await?;
    }

    let mut guard = ENGINE
        .lock()
        .map_err(|e| format!("engine lock poisoned: {}", e))?;
    if let Some(engine) = guard.as_mut() {
        engine.close()?;
    }
    *guard = None;

    IS_INITIALIZED.store(false, Ordering::SeqCst);
    tracing::info!("Kill switch cleanup complete");
    Ok(())
}

/// Get kill switch status for display.
///
/// DT-6: previously surfaced via the removed `get_wfp_status` IPC command.
/// Kept as a public status accessor; allow dead_code until a caller is re-added.
#[allow(dead_code)]
pub fn get_status() -> KillSwitchStatus {
    KillSwitchStatus {
        initialized: IS_INITIALIZED.load(Ordering::SeqCst),
        active: IS_BLOCKING.load(Ordering::SeqCst),
        method: "WFP (fwpuclnt.dll)".to_string(),
    }
}

/// Set whether local network sharing (RFC1918) should be permitted.
/// Takes effect on the next `activate_blocking()` call.
pub fn set_local_network_sharing(enabled: bool) {
    LOCAL_NETWORK_SHARING.store(enabled, Ordering::SeqCst);
    tracing::debug!("Local network sharing set to: {}", enabled);
}

/// Set the list of split-tunnel app executable paths.
/// Uses `where.exe` to resolve short names like "chrome.exe" to full paths.
/// Takes effect on the next `activate_blocking()` call.
pub async fn set_split_tunnel_apps(app_names: Vec<String>) {
    let mut resolved_paths = Vec::new();

    for name in &app_names {
        if let Some(path) = resolve_app_path(name) {
            resolved_paths.push(path);
        } else {
            tracing::warn!("Could not resolve split tunnel app '{}' — skipping", name);
        }
    }

    tracing::info!(
        "Split tunnel apps: {} requested, {} resolved to paths",
        app_names.len(),
        resolved_paths.len()
    );

    let mut apps = SPLIT_TUNNEL_APPS.write().await;
    *apps = resolved_paths;
}

/// Resolve an app name or path to a full executable path.
/// Accepts both short names ("chrome.exe") and full paths ("C:\...\chrome.exe").
fn resolve_app_path(name: &str) -> Option<String> {
    // If it's already an absolute path and exists, use it directly
    let path = std::path::Path::new(name);
    if path.is_absolute() && path.exists() {
        return Some(name.to_string());
    }

    // Try to resolve using `where.exe` (searches PATH, App Paths registry, etc.)
    if let Ok(output) = crate::utils::hidden_cmd("where.exe").arg(name).output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(first_line) = stdout.lines().next() {
                let resolved = first_line.trim().to_string();
                if !resolved.is_empty() && std::path::Path::new(&resolved).exists() {
                    tracing::debug!("Resolved '{}' → '{}'", name, resolved);
                    return Some(resolved);
                }
            }
        }
    }

    // Search common install locations
    let program_files =
        std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".to_string());
    let program_files_x86 = std::env::var("ProgramFiles(x86)")
        .unwrap_or_else(|_| "C:\\Program Files (x86)".to_string());
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_default();

    let search_roots = [&program_files, &program_files_x86, &local_app_data];

    for root in &search_roots {
        if root.is_empty() {
            continue;
        }
        // Quick top-level search (one level deep)
        if let Ok(entries) = std::fs::read_dir(root) {
            for entry in entries.flatten() {
                let candidate = entry.path().join(name);
                if candidate.exists() {
                    tracing::debug!("Found '{}' at '{}'", name, candidate.display());
                    return Some(candidate.to_string_lossy().to_string());
                }
                // Check one more level (e.g., "Google\Chrome\Application\chrome.exe")
                if entry.path().is_dir() {
                    if let Ok(sub_entries) = std::fs::read_dir(entry.path()) {
                        for sub in sub_entries.flatten() {
                            let candidate = sub.path().join(name);
                            if candidate.exists() {
                                tracing::debug!("Found '{}' at '{}'", name, candidate.display());
                                return Some(candidate.to_string_lossy().to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    // Last resort: the name couldn't be resolved — skip it rather than
    // sending an invalid path to WFP (which would fail FwpmGetAppIdFromFileName0)
    tracing::debug!("Could not resolve '{}', skipping", name);
    None
}

/// Status information for the kill switch.
#[derive(Debug, Clone, serde::Serialize)]
pub struct KillSwitchStatus {
    pub initialized: bool,
    pub active: bool,
    pub method: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kill-switch flags are process-global statics, so the tests that drive
    /// them must not interleave (cargo test runs them on separate threads).
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Mirrors what the WFP engine holds, so a full reactive kill-switch cycle can
    /// be walked without an elevated WFP session (CI runners are not elevated).
    /// Each method performs exactly the state transitions its real counterpart
    /// does — the decisions all come from `v6_state`, which is the code under test.
    #[derive(Default)]
    struct FakeEngine {
        /// Standalone IPv6 filters (block_all_v6 + localhost/DHCPv6 permits).
        standalone_v6: bool,
        /// The kill switch's own filter set, which includes a block_all_v6.
        killswitch_filters: bool,
    }

    impl FakeEngine {
        /// wfp::block_ipv6()
        fn block_ipv6(&mut self) {
            if v6_state::on_block() {
                self.standalone_v6 = true;
                v6_state::mark_installed(true);
            }
        }

        /// wfp::activate_blocking()
        fn activate_blocking(&mut self) {
            self.killswitch_filters = true;
            IS_BLOCKING.store(true, Ordering::SeqCst);
        }

        /// wfp::unblock_ipv6()
        fn unblock_ipv6(&mut self) {
            if v6_state::on_unblock() {
                self.standalone_v6 = false;
            }
        }

        /// wfp::unblock_ipv6_dual_stack() — the new tunnel routes IPv6 itself.
        fn unblock_ipv6_dual_stack(&mut self) {
            if v6_state::on_dual_stack() {
                self.standalone_v6 = false;
            }
        }

        /// wfp::deactivate_blocking() — removes ALL filters, then honours intent.
        fn deactivate_blocking(&mut self) {
            if !IS_BLOCKING.load(Ordering::SeqCst) {
                return;
            }
            self.killswitch_filters = false;
            self.standalone_v6 = false;
            IS_BLOCKING.store(false, Ordering::SeqCst);
            if v6_state::on_deactivate() {
                self.standalone_v6 = true;
                v6_state::mark_installed(true);
            }
        }

        /// wfp::cleanup() — engine closed, dynamic session drops every filter.
        fn cleanup(&mut self) {
            v6_state::on_cleanup();
            self.killswitch_filters = false;
            self.standalone_v6 = false;
            IS_BLOCKING.store(false, Ordering::SeqCst);
        }

        /// Is outbound IPv6 blocked by SOME filter set right now?
        fn ipv6_blocked(&self) -> bool {
            self.standalone_v6 || self.killswitch_filters
        }
    }

    fn reset_state() {
        IS_BLOCKING.store(false, Ordering::SeqCst);
        IPV6_ONLY_ACTIVE.store(false, Ordering::SeqCst);
        IPV6_BLOCK_WANTED.store(false, Ordering::SeqCst);
        IPV6_BLOCK_HELD.store(false, Ordering::SeqCst);
    }

    /// LEAK-1: a reactive kill-switch cycle must NOT permanently delete the
    /// standalone IPv6 block. Walks the exact sequence that used to lose it:
    /// connect → drop → kill switch → teardown → new tunnel → reconnect success.
    #[test]
    fn reactive_killswitch_cycle_keeps_ipv6_blocked() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_state();
        let mut engine = FakeEngine::default();

        // Connect: standalone v6 block installed.
        engine.block_ipv6();
        assert!(engine.ipv6_blocked(), "connect must block IPv6");
        assert!(IPV6_ONLY_ACTIVE.load(Ordering::SeqCst));

        // Tunnel drops: auto-reconnect arms the kill switch.
        engine.activate_blocking();
        assert!(engine.ipv6_blocked());

        // Old tunnel torn down — the kill switch owns the block, so the intent
        // must survive (this swap is what used to consume it).
        engine.unblock_ipv6();
        assert!(engine.ipv6_blocked(), "kill switch still blocks IPv6");
        assert!(
            IPV6_BLOCK_WANTED.load(Ordering::SeqCst),
            "intent must survive a kill-switch-owned teardown"
        );

        // New tunnel starts while the kill switch is still up: no filters added,
        // but the intent is re-affirmed.
        engine.block_ipv6();
        assert!(engine.ipv6_blocked());

        // Reconnect succeeded: kill switch deactivates and removes ALL filters.
        engine.deactivate_blocking();
        assert!(
            engine.ipv6_blocked(),
            "IPv6 must STILL be blocked after the kill switch is deactivated"
        );
        assert!(IPV6_ONLY_ACTIVE.load(Ordering::SeqCst));

        // And a normal disconnect still lifts it.
        engine.unblock_ipv6();
        assert!(!engine.ipv6_blocked(), "disconnect must restore IPv6");
    }

    /// LEAK-1 edge: a user-initiated disconnect DURING a reconnect goes through
    /// disarm() → cleanup(), which must clear the intent — otherwise IPv6 is left
    /// blocked with no tunnel and nothing to remove the block.
    #[test]
    fn cleanup_clears_ipv6_block_intent() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_state();
        let mut engine = FakeEngine::default();

        engine.block_ipv6();
        engine.activate_blocking(); // reconnect gap
        engine.unblock_ipv6(); // old tunnel torn down, intent held
        assert!(IPV6_BLOCK_WANTED.load(Ordering::SeqCst));

        // User hits Disconnect mid-reconnect.
        engine.cleanup();
        assert!(
            !IPV6_BLOCK_WANTED.load(Ordering::SeqCst),
            "cleanup must clear the IPv6 block intent"
        );
        assert!(!IPV6_ONLY_ACTIVE.load(Ordering::SeqCst));
        assert!(
            !engine.ipv6_blocked(),
            "disconnect must not strand IPv6 blocked"
        );

        // A deactivation after cleanup must not resurrect the block.
        engine.deactivate_blocking();
        assert!(!engine.ipv6_blocked());
    }

    /// LEAK-2(d): a server switch tears the old tunnel down with a new one
    /// already committed. The hold keeps IPv6 blocked across the whole switch.
    #[test]
    fn server_switch_hold_keeps_ipv6_blocked_across_teardown() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_state();
        let mut engine = FakeEngine::default();

        engine.block_ipv6();

        // Manager: hold the block, tear the old tunnel down (stop() unblocks).
        hold_ipv6_block(true);
        engine.unblock_ipv6();
        assert!(
            engine.ipv6_blocked(),
            "IPv6 must stay blocked while the switch holds it"
        );

        // New tunnel's start() re-affirms the block; hold released.
        hold_ipv6_block(false);
        engine.block_ipv6();
        assert!(engine.ipv6_blocked());

        // Normal disconnect afterwards still works.
        engine.unblock_ipv6();
        assert!(!engine.ipv6_blocked());
        reset_state();
    }

    /// LEAK-2: a dual-stack tunnel (backend sent `client_ipv6`) routes IPv6
    /// itself, so `unblock_ipv6_dual_stack()` must drop the session's block
    /// INTENT even while the kill switch still owns the filters — otherwise a
    /// later `deactivate_blocking()` would re-install a standalone block that a
    /// dual-stack tunnel must not have (it would fight the tunnel's own IPv6
    /// routes).
    #[test]
    fn dual_stack_route_clears_intent_even_under_killswitch() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_state();
        let mut engine = FakeEngine::default();

        // Pre-emptive block at the top of start(), same as any other tunnel.
        engine.block_ipv6();
        assert!(IPV6_BLOCK_WANTED.load(Ordering::SeqCst));

        // Tunnel drops mid-session; auto-reconnect arms the kill switch.
        engine.activate_blocking();
        engine.unblock_ipv6(); // old tunnel's stop(); kill switch still owns v6
        assert!(engine.ipv6_blocked(), "kill switch still blocks IPv6");

        // The NEW tunnel is dual-stack: it routes IPv6 itself, so it lifts the
        // pre-emptive block right before installing its own IPv6 routes.
        engine.unblock_ipv6_dual_stack();
        assert!(
            !IPV6_BLOCK_WANTED.load(Ordering::SeqCst),
            "dual-stack tunnel must clear the block intent"
        );
        assert!(
            !IPV6_BLOCK_HELD.load(Ordering::SeqCst),
            "dual-stack tunnel must also release any server-switch hold"
        );

        // Reconnect succeeds — deactivating the kill switch must NOT rebuild a
        // standalone block now that the tunnel wants to route IPv6 itself.
        engine.deactivate_blocking();
        assert!(
            !engine.ipv6_blocked(),
            "a dual-stack tunnel's IPv6 must be free to flow once the kill switch is gone"
        );

        reset_state();
    }
}
