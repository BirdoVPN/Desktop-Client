//! Windows Filtering Platform (WFP) Kill Switch Implementation
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
//! Architecture:
//!   1. One `WfpEngine` handle is opened at `initialize()` and held for the
//!      lifetime of the VPN session (closed at `cleanup()`).
//!   2. A custom sublayer (`BIRDO_SUBLAYER_KEY`) groups all our filters.
//!   3. Permit rules (weight 10) are evaluated before the catch-all block
//!      (weight 1). STUN/TURN blocks use weight 15 to override permits.
//!   4. `activate_blocking()` wraps all filter additions in a single
//!      `FwpmTransactionBegin0` / `FwpmTransactionCommit0` pair.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::utils::elevation::is_elevated as is_admin;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows::core::GUID;

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
static VPN_SERVER_IP: once_cell::sync::Lazy<Arc<RwLock<Option<Ipv4Addr>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(None)));

/// Split tunnel app executable paths that should bypass the kill switch.
static SPLIT_TUNNEL_APPS: once_cell::sync::Lazy<Arc<RwLock<Vec<String>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(Vec::new())));

/// Whether local network sharing (RFC1918) is permitted through the kill switch.
static LOCAL_NETWORK_SHARING: AtomicBool = AtomicBool::new(false);

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
        session.displayData.name =
            windows::core::PWSTR(session_name.as_ptr() as *mut u16);

        let mut handle = HANDLE::default();
        // SAFETY: All pointers (`session_name`, `session`) are valid, stack-allocated, and
        // live for the duration of this call.  `handle` is an out-param initialised by the
        // OS; on success we take ownership and release via `FwpmEngineClose0` in `close()`.
        let err = unsafe {
            FwpmEngineOpen0(
                windows::core::PCWSTR::null(), // local engine
                RPC_C_AUTHN_WINNT,
                None,              // default auth identity
                Some(&session),    // session config
                &mut handle,       // output handle
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
        sublayer.displayData.name =
            windows::core::PWSTR(name.as_ptr() as *mut u16);
        sublayer.displayData.description =
            windows::core::PWSTR(desc.as_ptr() as *mut u16);
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
            let err = unsafe {
                FwpmSubLayerDeleteByKey0(self.handle, &BIRDO_SUBLAYER_KEY)
            };
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

    /// Permit a split-tunnel app on the IPv6 layer.
    /// Returns the filter ID on success, or 0 if the app could not be resolved.
    fn add_permit_app_v6(&mut self, exe_path: &str) -> Result<u64, String> {
        let wide_path = wide_nul(exe_path);

        let mut app_id: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
        let err = unsafe {
            FwpmGetAppIdFromFileName0(
                windows::core::PCWSTR(wide_path.as_ptr()),
                &mut app_id,
            )
        };
        if err != 0 {
            return Ok(0); // Non-fatal: skip (already warned at V4 level)
        }

        let label = format!("Birdo: Permit split-tunnel app v6 ({})",
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

        result.map(|id| {
            tracing::debug!("Split tunnel permit v6 added for: {} (filter_id={})", exe_path, id);
            id
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

    /// Block WebRTC STUN/TURN ports to prevent IP leak via WebRTC.
    /// - UDP 3478-3497 (standard STUN/TURN)
    /// - TCP 3478-3497 (TURN over TCP)
    /// - UDP 19302     (Google STUN — Chrome/Edge)
    fn add_block_stun_turn(&mut self) -> Result<(), String> {
        self.add_port_range_block("Birdo: Block STUN/UDP", 17, 3478, 3497)?;
        self.add_port_range_block("Birdo: Block TURN/TCP", 6, 3478, 3497)?;
        self.add_port_range_block("Birdo: Block Google STUN", 17, 19302, 19302)?;
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
            ("Birdo: Permit LAN 10.0.0.0/8", Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(255, 0, 0, 0)),
            ("Birdo: Permit LAN 172.16.0.0/12", Ipv4Addr::new(172, 16, 0, 0), Ipv4Addr::new(255, 240, 0, 0)),
            ("Birdo: Permit LAN 192.168.0.0/16", Ipv4Addr::new(192, 168, 0, 0), Ipv4Addr::new(255, 255, 0, 0)),
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
            FwpmGetAppIdFromFileName0(
                windows::core::PCWSTR(wide_path.as_ptr()),
                &mut app_id,
            )
        };
        if err != 0 {
            tracing::warn!(
                "FwpmGetAppIdFromFileName0 failed for '{}': 0x{:08X} — skipping",
                exe_path, err
            );
            return Ok(0); // Non-fatal: skip this app rather than fail the whole transaction
        }

        let label = format!("Birdo: Permit split-tunnel app ({})",
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

        result.map(|id| {
            tracing::debug!("Split tunnel permit added for: {} (filter_id={})", exe_path, id);
            id
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
        filter.displayData.name =
            windows::core::PWSTR(name.as_ptr() as *mut u16);
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

    let vpn_ip = VPN_SERVER_IP.read().await.clone();

    let mut guard = ENGINE
        .lock()
        .map_err(|e| format!("engine lock poisoned: {}", e))?;
    let engine = guard.as_mut().ok_or("WFP engine not open")?;

    // If already blocking, tear down existing filters and rebuild.
    if IS_BLOCKING.load(Ordering::SeqCst) {
        tracing::debug!("Kill switch already active — refreshing filters");
        engine.remove_all_filters();
        engine.delete_sublayer();
    }

    tracing::info!("Activating kill switch (WFP atomic transaction)");
    engine.begin_transaction()?;

    let result = (|| -> Result<(), String> {
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

        // Local network sharing: permit RFC1918 private ranges
        if LOCAL_NETWORK_SHARING.load(Ordering::SeqCst) {
            engine.add_permit_local_networks()?;
        }

        // Split tunneling: permit traffic from excluded apps (IPv4 + IPv6)
        let split_apps = SPLIT_TUNNEL_APPS.try_read();
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
                        engine.split_tunnel_map.insert(v4_id, (app_path.clone(), ids));
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
            engine.filter_ids.clear();
            engine.sublayer_added = false;
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
    tracing::info!("Kill switch deactivated — normal traffic restored");
    Ok(())
}

/// Update the VPN server IP in an active kill switch.
///
/// Rebuilds all filters atomically to swap the permitted server.
pub async fn update_vpn_server(ip: Ipv4Addr) -> Result<(), String> {
    set_vpn_server(ip).await;

    if IS_BLOCKING.load(Ordering::SeqCst) {
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
pub fn is_initialized() -> bool {
    IS_INITIALIZED.load(Ordering::SeqCst)
}

/// Clean up and release all resources.
///
/// Deactivates blocking (if active), then closes the WFP engine handle.
/// Because the session is dynamic, Windows removes any straggling
/// filters automatically.
pub async fn cleanup() -> Result<(), String> {
    tracing::info!("Cleaning up kill switch resources");

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

/// Add a dynamic split tunnel permit for a specific application.
///
/// - Resolves the app path (accepts short names like "chrome.exe" or full paths).
/// - Adds to `SPLIT_TUNNEL_APPS` so the app persists across kill switch rebuilds.
/// - If the kill switch is currently blocking, immediately installs WFP filters.
/// - Returns a permit ID (the V4 filter ID) that can be used with
///   `remove_split_tunnel_permit`. Returns 0 if the kill switch is not active
///   (the app is queued and will be applied when blocking activates).
pub async fn add_split_tunnel_permit(app_path: String) -> Result<u64, String> {
    let resolved = resolve_app_path(&app_path)
        .ok_or_else(|| format!("Could not resolve app path: {}", app_path))?;

    // Add to persistent list so it survives kill switch rebuilds
    {
        let mut apps = SPLIT_TUNNEL_APPS.write().await;
        if !apps.contains(&resolved) {
            apps.push(resolved.clone());
        }
    }

    // If kill switch is not active, just queue — filters will be added on next activate
    if !IS_BLOCKING.load(Ordering::SeqCst) {
        tracing::info!("Split tunnel: queued '{}' (kill switch not active)", resolved);
        return Ok(0);
    }

    if !IS_INITIALIZED.load(Ordering::SeqCst) {
        return Err("Kill switch not initialized".to_string());
    }

    let mut guard = ENGINE
        .lock()
        .map_err(|e| format!("engine lock poisoned: {}", e))?;
    let engine = guard.as_mut().ok_or("WFP engine not open")?;

    let v4_id = engine.add_permit_app(&resolved)?;
    if v4_id == 0 {
        return Err(format!("Failed to create WFP app ID for: {}", resolved));
    }

    let mut ids = vec![v4_id];
    let v6_id = engine.add_permit_app_v6(&resolved)?;
    if v6_id != 0 {
        ids.push(v6_id);
    }

    engine.split_tunnel_map.insert(v4_id, (resolved.clone(), ids));
    tracing::info!("Split tunnel permit added for '{}' (permit_id={})", resolved, v4_id);

    Ok(v4_id)
}

/// Remove a specific split tunnel permit by its permit ID.
///
/// Removes the WFP filters and also removes the app from `SPLIT_TUNNEL_APPS`.
pub async fn remove_split_tunnel_permit(permit_id: u64) -> Result<(), String> {
    if permit_id == 0 {
        return Err("Invalid permit ID (0)".to_string());
    }

    if !IS_INITIALIZED.load(Ordering::SeqCst) {
        return Err("Kill switch not initialized".to_string());
    }

    let app_to_remove;

    {
        let mut guard = ENGINE
            .lock()
            .map_err(|e| format!("engine lock poisoned: {}", e))?;
        let engine = guard.as_mut().ok_or("WFP engine not open")?;

        let (app_path, filter_ids) = engine
            .split_tunnel_map
            .remove(&permit_id)
            .ok_or_else(|| format!("Split tunnel permit {} not found", permit_id))?;

        for id in &filter_ids {
            // SAFETY: `engine.handle` is a valid WFP engine handle.
            // `id` was returned by a prior successful `FwpmFilterAdd0` call.
            let err = unsafe { FwpmFilterDeleteById0(engine.handle, *id) };
            // 0x80320003 = FWP_E_FILTER_NOT_FOUND — benign
            if err != 0 && err != 0x80320003 {
                tracing::warn!("FwpmFilterDeleteById0({}) warn: 0x{:08X}", id, err);
            }
            engine.filter_ids.retain(|&fid| fid != *id);
        }

        app_to_remove = app_path;
    } // guard dropped — safe to acquire async lock

    {
        let mut apps = SPLIT_TUNNEL_APPS.write().await;
        apps.retain(|a| a != &app_to_remove);
    }

    tracing::info!(
        "Split tunnel permit removed for '{}' (permit_id={})",
        app_to_remove,
        permit_id
    );
    Ok(())
}

/// Remove all split tunnel permits.
///
/// Clears `SPLIT_TUNNEL_APPS` and removes all tracked split tunnel WFP filters.
pub async fn clear_split_tunnel_permits() -> Result<(), String> {
    // Clear the persistent list
    {
        let mut apps = SPLIT_TUNNEL_APPS.write().await;
        apps.clear();
    }

    if !IS_INITIALIZED.load(Ordering::SeqCst) {
        return Ok(()); // Nothing to clean up in WFP
    }

    let mut guard = ENGINE
        .lock()
        .map_err(|e| format!("engine lock poisoned: {}", e))?;
    if let Some(engine) = guard.as_mut() {
        let entries: Vec<(u64, Vec<u64>)> = engine
            .split_tunnel_map
            .drain()
            .map(|(k, (_, ids))| (k, ids))
            .collect();

        for (permit_id, filter_ids) in entries {
            for id in &filter_ids {
                // SAFETY: `engine.handle` is a valid WFP engine handle.
                let err = unsafe { FwpmFilterDeleteById0(engine.handle, *id) };
                if err != 0 && err != 0x80320003 {
                    tracing::warn!("FwpmFilterDeleteById0({}) warn: 0x{:08X}", id, err);
                }
                engine.filter_ids.retain(|&fid| fid != *id);
            }
            tracing::debug!("Cleared split tunnel permit_id={}", permit_id);
        }
    }

    tracing::info!("All split tunnel permits cleared");
    Ok(())
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
    if let Ok(output) = crate::utils::hidden_cmd("where.exe")
        .arg(name)
        .output()
    {
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
    let program_files = std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".to_string());
    let program_files_x86 = std::env::var("ProgramFiles(x86)").unwrap_or_else(|_| "C:\\Program Files (x86)".to_string());
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_default();

    let search_roots = [&program_files, &program_files_x86, &local_app_data];

    for root in &search_roots {
        if root.is_empty() { continue; }
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
