//! Windows Filtering Platform (WFP): the kill switch, the IPv6 connect-window
//! block and the DNS guard.
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
//! ## What the session holds, and who decides it
//!
//! ONE filter set, installed and replaced as a whole. Its contents are a pure
//! function of a [`Policy`] (`wfp_policy::filter_specs`), which is where the
//! decisions live and where they are tested: the kill switch's block-all with
//! its app-scoped permits (W1-013) at both the connect and the receive-accept
//! layers (W1-014), the LEAK-2 IPv6 block, and the DNS guard (W1-007). Every
//! change — arm, refresh, release, a new relay, a DNS guard, an interface that
//! appeared — computes the next policy and swaps the whole set inside one
//! transaction, so an abort leaves the previous set in force.
//!
//! No persistent filters and no boot-time filters, ever: every object here is
//! created in the dynamic session, so nothing survives the process — see
//! AUDIT-L below for what that costs.
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
//!     general permits — but ONLY while the block-all is active. During a
//!     normal reactive-mode session, and on non-Windows platforms,
//!     WebRTC/STUN is NOT filtered; steady-state protection there relies on
//!     routing all traffic through the tunnel.
//!
//! A true "fail-CLOSED on crash" posture needs a LocalSystem service holding a
//! non-dynamic session across GUI restarts — the next phase (owner decision
//! D1), not this one.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::utils::elevation::is_elevated as is_admin;

use super::wfp_policy::{
    filter_specs, host_only_interfaces, Action, BlockAll, Condition, DnsGuard, FilterSpec,
    InterfaceFacts, Layer, Policy, Relay,
};

use windows::core::GUID;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

// ── Stable GUIDs ─────────────────────────────────────────────────────
// Constant across process restarts so `initialize()` can clean up stale
// objects from a previous dynamic session (shouldn't exist, but belt &
// suspenders).

/// Sublayer that groups every Birdo VPN filter.
const BIRDO_SUBLAYER_KEY: GUID = GUID::from_u128(0xe5f4c3b2_8f9d_5ea0_c1b6_000023456789);

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
/// `deactivate_blocking()` replaces the whole filter set.
static IPV6_BLOCK_WANTED: AtomicBool = AtomicBool::new(false);

/// True while a tunnel is being torn down with a replacement already committed
/// (server switch). `unblock_ipv6()` must not drop the block in that window, or
/// IPv6 egresses the physical NIC for the whole teardown + setup of the new
/// tunnel.
static IPV6_BLOCK_HELD: AtomicBool = AtomicBool::new(false);

/// The relay the block-all lets the tunnel reach: address, port and transport
/// (W1-013). Set on every connect and re-dial, before the handshake.
static RELAY: std::sync::Mutex<Option<Relay>> = std::sync::Mutex::new(None);

/// STEALTH: the xray.exe the client spawned for a Reality tunnel. In stealth
/// mode the WireGuard endpoint is 127.0.0.1:<local_port> and it is THIS
/// process — not ours — that carries the tunnel to the relay over TCP. A
/// lockdown block that did not permit it silently dropped its SYNs: on
/// 2026-09-17 every stealth connect timed out at the handshake while node
/// captures showed zero packets from the PC. Set by XrayManager::start,
/// cleared by stop.
static STEALTH_HELPER_EXE: once_cell::sync::Lazy<Arc<RwLock<Option<String>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(None)));

/// Split tunnel app executable paths that should bypass the kill switch.
static SPLIT_TUNNEL_APPS: once_cell::sync::Lazy<Arc<RwLock<Vec<String>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(Vec::new())));

/// Whether local network sharing (RFC1918) is permitted through the kill switch.
static LOCAL_NETWORK_SHARING: AtomicBool = AtomicBool::new(false);

/// LOCKDOWN ("always-on") MODE — driven by the persisted `lockdown_mode`
/// setting, which DEFAULTS ON on Windows (`AppSettings::default()`, desktop
/// #34, the TunnelVision fix) and is user-switchable in Settings › Security ›
/// "Always-on kill switch". This static is only the pre-connect value: it
/// starts false and `commands::vpn::apply_vpn_settings` sets it from the
/// setting on every connect and settings reapply. (D-21.)
///
/// When false: the kill switch is REACTIVE — the block-all is only
/// installed during a reconnect gap, and steady-state Connected traffic is
/// contained by routing.
///
/// When true (the Windows default): Mullvad-style ALWAYS-ON. The block-all
/// stays installed the whole time the tunnel is up, and an INTERFACE-scoped
/// permit on the tunnel adapter LUID (see TUNNEL_LUID) lets tunneled traffic
/// through while everything on the physical NIC stays blocked — so there is
/// NO leak window, including across reconnects, while the app is running. The
/// dynamic WFP session still guarantees crash-safety (filters auto-removed if
/// the process dies) — which is also why none of this protects anything once
/// the app has exited.
static LOCKDOWN_MODE: AtomicBool = AtomicBool::new(false);

/// The WireGuard tunnel adapter's interface LUID, published by the tunnel layer
/// once the Wintun adapter exists (0 = unknown). Lockdown mode permits all
/// traffic on this interface so tunneled browsing keeps working under the
/// always-on block-all.
static TUNNEL_LUID: AtomicU64 = AtomicU64::new(0);

/// Engine state protected by a standard mutex (WFP calls are blocking FFI,
/// not async, so a tokio mutex would add unnecessary overhead).
static ENGINE: once_cell::sync::Lazy<std::sync::Mutex<Option<WfpEngine>>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(None));

// ── WFP engine wrapper ──────────────────────────────────────────────

/// Holds an open WFP engine handle, the filter IDs we installed and the policy
/// they implement.
struct WfpEngine {
    handle: HANDLE,
    filter_ids: Vec<u64>,
    sublayer_added: bool,
    /// What `filter_ids` implements. Every change starts from this.
    installed: Policy,
}

// SAFETY: The WFP engine handle is a plain kernel object handle that
// can safely be sent between threads.  All access is serialized by the
// `ENGINE` mutex.
unsafe impl Send for WfpEngine {}

/// A WFP app id from `FwpmGetAppIdFromFileName0`, freed with `FwpmFreeMemory0`.
struct AppBlob(*mut FWP_BYTE_BLOB);

impl Drop for AppBlob {
    fn drop(&mut self) {
        // SAFETY: the pointer came from FwpmGetAppIdFromFileName0 and is freed
        // exactly once, here.
        unsafe { FwpmFreeMemory0(&mut (self.0 as *mut std::ffi::c_void)) };
    }
}

/// Resolve an executable's WFP app id. `None` when WFP cannot (the file is
/// missing, or the path cannot be converted to a device path).
fn app_id(path: &str) -> Option<AppBlob> {
    let wide_path = wide_nul(path);
    let mut blob: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
    // SAFETY: `wide_path` is a valid NUL-terminated UTF-16 string for the call;
    // `blob` is an out-param receiving an OS-allocated blob, owned by AppBlob.
    let err =
        unsafe { FwpmGetAppIdFromFileName0(windows::core::PCWSTR(wide_path.as_ptr()), &mut blob) };
    // A null out-param is a failure too, which keeps the later deref sound
    // (CodeQL rust/access-invalid-pointer).
    if err != 0 || blob.is_null() {
        tracing::debug!(
            "FwpmGetAppIdFromFileName0 failed for '{}': 0x{:08X}",
            file_name(path),
            err
        );
        return None;
    }
    Some(AppBlob(blob))
}

fn file_name(path: &str) -> &str {
    std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path)
}

/// Resolve every app the policy names, reporting the failures that change
/// what the kill switch can do.
fn resolve_apps(policy: &Policy) -> HashMap<String, AppBlob> {
    let mut apps = HashMap::new();
    let Some(block) = &policy.block_all else {
        return apps;
    };
    let mut resolve = |path: &str, consequence: &str, error: bool| {
        if apps.contains_key(path) {
            return;
        }
        match app_id(path) {
            Some(blob) => {
                apps.insert(path.to_string(), blob);
            }
            None if error => tracing::error!(
                "Kill switch: no WFP app id for {} — {}",
                file_name(path),
                consequence
            ),
            None => tracing::warn!(
                "Kill switch: no WFP app id for {} — {}",
                file_name(path),
                consequence
            ),
        }
    };
    if let Some(path) = block.self_exe.as_deref() {
        resolve(
            path,
            "the relay permit falls back to address scope and the control plane is blocked \
             while the block is up",
            true,
        );
    }
    if let Some(path) = block.stealth_helper.as_deref() {
        resolve(
            path,
            "the stealth relay permit falls back to address scope",
            true,
        );
    }
    for path in &block.exceptions {
        resolve(path, "this kill-switch exception is skipped", false);
    }
    apps
}

fn layer_key(layer: Layer) -> GUID {
    match layer {
        Layer::ConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        Layer::ConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        Layer::RecvAcceptV4 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        Layer::RecvAcceptV6 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    }
}

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
            installed: Policy::default(),
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
            self.installed = Policy::default();
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
        let desc = wide_nul("Blocks non-VPN traffic to prevent IP and DNS leaks");

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

    // ── Filters ─────────────────────────────────────────────────────

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
    }

    /// Add one filter built from `spec`.
    fn add_spec(
        &mut self,
        spec: &FilterSpec,
        apps: &HashMap<String, AppBlob>,
    ) -> Result<(), String> {
        let name = wide_nul(&spec.name);

        // What the conditions point into. Boxed so every address stays put
        // until FwpmFilterAdd0 has copied the filter.
        let mut v4: Vec<Box<FWP_V4_ADDR_AND_MASK>> = Vec::new();
        let mut v6: Vec<Box<FWP_V6_ADDR_AND_MASK>> = Vec::new();
        let mut ranges: Vec<Box<FWP_RANGE0>> = Vec::new();
        let mut luids: Vec<Box<u64>> = Vec::new();
        let mut conditions: Vec<FWPM_FILTER_CONDITION0> = Vec::with_capacity(spec.conditions.len());

        for condition in &spec.conditions {
            let mut c = FWPM_FILTER_CONDITION0::default();
            c.matchType = FWP_MATCH_EQUAL;
            match condition {
                Condition::RemoteV4 { addr, prefix } => {
                    let mask = if *prefix == 0 {
                        0
                    } else {
                        u32::MAX << (32 - u32::from(*prefix))
                    };
                    let mut value = Box::new(FWP_V4_ADDR_AND_MASK {
                        addr: u32::from(*addr),
                        mask,
                    });
                    c.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                    c.conditionValue.r#type = FWP_V4_ADDR_MASK;
                    c.conditionValue.Anonymous.v4AddrMask = &mut *value;
                    v4.push(value);
                }
                Condition::RemoteV6 { addr, prefix } => {
                    let mut value = Box::new(FWP_V6_ADDR_AND_MASK {
                        addr: addr.octets(),
                        prefixLength: *prefix,
                    });
                    c.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                    c.conditionValue.r#type = FWP_V6_ADDR_MASK;
                    c.conditionValue.Anonymous.v6AddrMask = &mut *value;
                    v6.push(value);
                }
                Condition::Protocol(protocol) => {
                    c.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
                    c.conditionValue.r#type = FWP_UINT8;
                    c.conditionValue.Anonymous.uint8 = *protocol;
                }
                Condition::RemotePort(port) => {
                    c.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
                    c.conditionValue.r#type = FWP_UINT16;
                    c.conditionValue.Anonymous.uint16 = *port;
                }
                Condition::RemotePortRange(low, high) => {
                    let mut value = Box::new(FWP_RANGE0::default());
                    value.valueLow.r#type = FWP_UINT16;
                    value.valueLow.Anonymous.uint16 = *low;
                    value.valueHigh.r#type = FWP_UINT16;
                    value.valueHigh.Anonymous.uint16 = *high;
                    c.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
                    c.matchType = FWP_MATCH_RANGE;
                    c.conditionValue.r#type = FWP_RANGE_TYPE;
                    c.conditionValue.Anonymous.rangeValue = &mut *value;
                    ranges.push(value);
                }
                Condition::LocalPort(port) => {
                    c.fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
                    c.conditionValue.r#type = FWP_UINT16;
                    c.conditionValue.Anonymous.uint16 = *port;
                }
                Condition::LocalInterface(luid) => {
                    // IP_LOCAL_INTERFACE matches on the 64-bit interface LUID.
                    let mut value = Box::new(*luid);
                    c.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
                    c.conditionValue.r#type = FWP_UINT64;
                    c.conditionValue.Anonymous.uint64 = &mut *value;
                    luids.push(value);
                }
                Condition::App(path) => {
                    let blob = apps
                        .get(path)
                        .ok_or_else(|| format!("no app id for {}", file_name(path)))?;
                    c.fieldKey = FWPM_CONDITION_ALE_APP_ID;
                    c.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
                    c.conditionValue.Anonymous.byteBlob = blob.0;
                }
            }
            conditions.push(c);
        }

        let mut filter = FWPM_FILTER0::default();
        filter.displayData.name = windows::core::PWSTR(name.as_ptr() as *mut u16);
        filter.flags = FWPM_FILTER_FLAG_NONE;
        filter.layerKey = layer_key(spec.layer);
        filter.subLayerKey = BIRDO_SUBLAYER_KEY;
        filter.weight.r#type = FWP_UINT8;
        filter.weight.Anonymous.uint8 = spec.weight;
        filter.action.r#type = match spec.action {
            Action::Permit => FWP_ACTION_PERMIT,
            Action::Block => FWP_ACTION_BLOCK,
        };
        filter.numFilterConditions = conditions.len() as u32;
        filter.filterCondition = if conditions.is_empty() {
            std::ptr::null_mut()
        } else {
            conditions.as_mut_ptr()
        };

        let mut id: u64 = 0;
        // SAFETY: `self.handle` is a valid WFP engine handle. `filter` and every
        // pointer inside it (name, conditions, and the boxed values and app
        // blobs they point to) stay alive until this call returns; WFP copies
        // the filter. `id` receives the new filter's id, tracked for removal.
        let err = unsafe {
            FwpmFilterAdd0(
                self.handle,
                &filter,
                windows::Win32::Security::PSECURITY_DESCRIPTOR::default(),
                Some(&mut id),
            )
        };
        drop((v4, v6, ranges, luids));
        if err != 0 {
            return Err(format!(
                "FwpmFilterAdd0 ({}) failed: 0x{:08X}",
                spec.name, err
            ));
        }
        self.filter_ids.push(id);
        Ok(())
    }

    /// Replace the installed filter set with the one `next` calls for, in ONE
    /// transaction. The old filters are deleted INSIDE it, so the swap has no
    /// gap on commit, and an abort rolls the deletes back: the previous set
    /// stays in force and the bookkeeping is restored to match it.
    fn apply(&mut self, next: Policy) -> Result<(), String> {
        let apps = resolve_apps(&next);
        let specs = filter_specs(&next, &|path| apps.contains_key(path));

        let saved_filter_ids = self.filter_ids.clone();
        let saved_sublayer_added = self.sublayer_added;

        self.begin_transaction()?;
        let result = (|| -> Result<(), String> {
            self.remove_all_filters();
            if specs.is_empty() {
                self.delete_sublayer();
                return Ok(());
            }
            self.add_sublayer()?; // idempotent (ignores ALREADY_EXISTS)
            for spec in &specs {
                self.add_spec(spec, &apps)?;
            }
            Ok(())
        })()
        .and_then(|()| self.commit_transaction());

        match result {
            Ok(()) => {
                tracing::debug!("WFP policy applied — {} filters", self.filter_ids.len());
                self.installed = next;
                Ok(())
            }
            Err(e) => {
                tracing::error!("WFP policy change failed, previous filters kept: {}", e);
                self.abort_transaction();
                self.filter_ids = saved_filter_ids;
                self.sublayer_added = saved_sublayer_added;
                Err(e)
            }
        }
    }
}

// P1-ks-wfp-initialize-toctou-handle-leak: last-owner backstop — if an engine
// is ever dropped without an explicit close() (error path, overwrite), release
// the kernel handle so the dynamic session's objects are removed by the OS.
impl Drop for WfpEngine {
    fn drop(&mut self) {
        if let Err(e) = self.close() {
            tracing::warn!("WfpEngine dropped with close error: {}", e);
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Create a null-terminated UTF-16 string for Win32 wide-char APIs.
fn wide_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0u16)).collect()
}

/// Every adapter's LUID, state and whether it has a default gateway, for the
/// host-only exemption of the inbound block. Empty on failure, which exempts
/// nothing (fail closed).
fn interface_facts() -> Vec<InterfaceFacts> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST,
        GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST,
        IF_TYPE_SOFTWARE_LOOPBACK, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows::Win32::Networking::WinSock::AF_UNSPEC;

    const ERROR_BUFFER_OVERFLOW: u32 = 111;
    let flags = GAA_FLAG_INCLUDE_GATEWAYS
        | GAA_FLAG_SKIP_UNICAST
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 16 * 1024;
    // u64-backed so the buffer is 8-byte aligned for IP_ADAPTER_ADDRESSES_LH.
    let mut buf: Vec<u64> = Vec::new();
    for _ in 0..4 {
        buf.clear();
        buf.resize((size as usize).div_ceil(8), 0);
        // SAFETY: `buf` is at least `size` bytes and correctly aligned; `size`
        // is an in/out parameter the OS updates with the required length.
        let rc = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                flags,
                None,
                Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut size,
            )
        };
        if rc == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        if rc != 0 {
            tracing::warn!(
                "GetAdaptersAddresses failed ({}) — no host-only exemptions",
                rc
            );
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut cursor = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !cursor.is_null() {
            // SAFETY: the OS built this list in `buf`; `Next` is either null or
            // points at another entry inside the same buffer.
            let entry = unsafe { &*cursor };
            cursor = entry.Next as *const IP_ADAPTER_ADDRESSES_LH;
            out.push(InterfaceFacts {
                // SAFETY: the union's `Value` is the whole 64-bit LUID.
                luid: unsafe { entry.Luid.Value },
                up: entry.OperStatus == IfOperStatusUp,
                loopback: entry.IfType == IF_TYPE_SOFTWARE_LOOPBACK,
                has_gateway: !entry.FirstGatewayAddress.is_null(),
            });
        }
        return out;
    }
    Vec::new()
}

/// Open the engine if it is not open yet. Caller holds the ENGINE lock.
fn ensure_engine(guard: &mut Option<WfpEngine>) -> Result<&mut WfpEngine, String> {
    if guard.is_none() {
        if !is_admin() {
            return Err("Administrator privileges required for WFP filters".to_string());
        }
        *guard = Some(WfpEngine::open()?);
        IS_INITIALIZED.store(true, Ordering::SeqCst);
        tracing::info!("WFP engine opened (dynamic session)");
    }
    guard
        .as_mut()
        .ok_or_else(|| "WFP engine not open".to_string())
}

fn engine_lock() -> Result<std::sync::MutexGuard<'static, Option<WfpEngine>>, String> {
    ENGINE
        .lock()
        .map_err(|e| format!("engine lock poisoned: {}", e))
}

// ── Public API ───────────────────────────────────────────────────────

/// Initialize the kill switch subsystem.
///
/// Opens a WFP engine session with `FWPM_SESSION_FLAG_DYNAMIC`.
pub async fn initialize() -> Result<(), String> {
    if IS_INITIALIZED.load(Ordering::SeqCst) {
        tracing::debug!("Kill switch already initialized");
        return Ok(());
    }
    // P1-ks-wfp-initialize-toctou-handle-leak: the check, the open and the
    // store happen under ONE lock, so a concurrent initialize() cannot
    // overwrite a stored engine (leaking its handle and its dynamic session).
    let mut guard = engine_lock()?;
    ensure_engine(&mut guard)?;
    Ok(())
}

/// STEALTH: record (or clear) the path of the xray helper so the next
/// block-all permits it — to its relay only (W1-013). Does not re-activate on
/// its own: xray is started before the relay permit moves, and `move_relay`
/// commits the helper's permit together with the relay's.
pub async fn set_stealth_helper_exe(path: Option<String>) {
    let mut helper = STEALTH_HELPER_EXE.write().await;
    if *helper != path {
        tracing::debug!(
            "Kill switch: stealth helper permit {}",
            if path.is_some() { "set" } else { "cleared" }
        );
    }
    *helper = path;
}

/// The block-all as the current settings describe it.
async fn current_block_all() -> BlockAll {
    let tunnel_luid = match TUNNEL_LUID.load(Ordering::SeqCst) {
        0 => None,
        luid => Some(luid),
    };
    let lockdown = LOCKDOWN_MODE.load(Ordering::SeqCst);
    if lockdown && tunnel_luid.is_none() {
        // Installing the block WITHOUT the tunnel permit is strictly MORE
        // restrictive, never less: the relay and control-plane permits still
        // let the reconnect run, and tunnel.rs re-activates with the new LUID
        // the moment the adapter is back. (Refusing here used to deadlock the
        // reconnect loop with the previous block still installed.)
        tracing::warn!(
            "Lockdown: no tunnel interface LUID (tunnel is down) — installing the block-all \
             without a tunnel permit; it is re-installed with the permit as soon as the \
             adapter is published"
        );
    }
    let exceptions = match SPLIT_TUNNEL_APPS.try_read() {
        Ok(apps) => apps.clone(),
        Err(e) => {
            // Contended or poisoned: skip the exceptions this activation, and
            // say so — otherwise excepted apps die with no indication why.
            tracing::warn!(
                "Split tunnel apps lock unavailable ({}) — skipping kill-switch exceptions \
                 this activation",
                e
            );
            Vec::new()
        }
    };
    let self_exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(String::from));
    if self_exe.is_none() {
        tracing::error!(
            "Kill switch: could NOT determine own exe path — reconnect may be blocked while the \
             kill switch is active"
        );
    }
    let stealth_helper = STEALTH_HELPER_EXE.read().await.clone();
    let relay = *RELAY.lock().unwrap_or_else(|e| e.into_inner());
    BlockAll {
        self_exe,
        relay,
        stealth_helper,
        tunnel_luid: tunnel_luid.filter(|_| lockdown),
        lan_sharing: LOCAL_NETWORK_SHARING.load(Ordering::SeqCst),
        exceptions,
        host_only_interfaces: host_only_interfaces(&interface_facts(), tunnel_luid),
    }
}

/// Activate the kill switch — block all traffic except the tunnel's own
/// flows, loopback, DHCP and the configured exceptions, in both directions,
/// inside a single atomic WFP transaction.
pub async fn activate_blocking() -> Result<(), String> {
    if !IS_INITIALIZED.load(Ordering::SeqCst) {
        return Err("Kill switch not initialized".to_string());
    }
    let block = current_block_all().await;

    let mut guard = engine_lock()?;
    let engine = guard.as_mut().ok_or("WFP engine not open")?;
    let was_blocking = IS_BLOCKING.load(Ordering::SeqCst);
    tracing::info!(
        "{} kill switch (WFP atomic transaction)",
        if was_blocking {
            "Refreshing"
        } else {
            "Activating"
        }
    );
    let next = Policy {
        block_all: Some(block),
        ..engine.installed.clone()
    };
    match engine.apply(next) {
        Ok(()) => {
            IS_BLOCKING.store(true, Ordering::SeqCst);
            tracing::info!(
                "Kill switch active — {} WFP filters committed atomically",
                engine.filter_ids.len()
            );
            Ok(())
        }
        Err(e) => {
            if was_blocking {
                tracing::warn!(
                    "Kill-switch refresh failed; retained the previous filter set (still blocking)"
                );
            }
            Err(e)
        }
    }
}

/// Deactivate the kill switch (restore normal traffic). The session's IPv6
/// block and DNS guard stay: they are the tunnel's, not the kill switch's.
pub async fn deactivate_blocking() -> Result<(), String> {
    if !IS_BLOCKING.load(Ordering::SeqCst) {
        tracing::debug!("Kill switch not active");
        return Ok(());
    }
    tracing::info!("Deactivating kill switch");

    let mut guard = engine_lock()?;
    let Some(engine) = guard.as_mut() else {
        IS_BLOCKING.store(false, Ordering::SeqCst);
        return Ok(());
    };
    // The block-all carried the session's IPv6 block. If the session still
    // wants IPv6 contained (a tunnel is up or coming up), the standalone block
    // replaces it IN THE SAME TRANSACTION — otherwise a reconnect cycle ends
    // with IPv6 wide open for the rest of the session.
    let v6_block = v6_state::on_deactivate();
    let next = Policy {
        block_all: None,
        v6_block,
        ..engine.installed.clone()
    };
    engine.apply(next).map_err(|e| {
        tracing::error!(
            "Kill switch could NOT be deactivated ({}) — the block stays in force",
            e
        );
        format!("Kill switch deactivation failed: {}", e)
    })?;
    IS_BLOCKING.store(false, Ordering::SeqCst);
    v6_state::mark_installed(v6_block);
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
    let mut guard = engine_lock()?;
    let engine = ensure_engine(&mut guard)?;
    let next = Policy {
        v6_block: true,
        ..engine.installed.clone()
    };
    engine.apply(next)?;
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
    remove_standalone_v6_block()
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
    remove_standalone_v6_block()
}

/// Drop the standalone IPv6 block, keeping everything else the session holds
/// (the DNS guard in particular).
fn remove_standalone_v6_block() -> Result<(), String> {
    let mut guard = engine_lock()?;
    if let Some(engine) = guard.as_mut() {
        let next = Policy {
            v6_block: false,
            ..engine.installed.clone()
        };
        engine.apply(next)?;
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

/// Forget the session's IPv6-block intent WITHOUT tearing down the WFP engine.
///
/// For the one path where the session ends but the kill switch is still armed and
/// about to be deactivated: auto-reconnect giving up. There, the caller wants full
/// connectivity restored, so the intent must be dropped BEFORE `deactivate_blocking()`
/// runs — otherwise it replaces the kill-switch filters with a standalone IPv6
/// block for a session that no longer exists, blackholing IPv6 for the rest of
/// the run with nothing left to remove it.
pub fn clear_ipv6_block_intent() {
    v6_state::on_cleanup();
}

/// Point the relay permit at a new relay (W1-013: address, port AND the
/// transport, so the permit can be scoped to the process and protocol that
/// carry the tunnel), and with `engage` put the block-all up — in ONE
/// transaction, so the block and the new relay's permit come into force
/// together (REVIEW-WIN2-001, `wfp_policy::after_relay_move`).
///
/// Runs on the connect and re-dial paths BEFORE the handshake that needs the
/// permit. A block already in force is rebuilt here in lockdown too. In a live
/// switch TUNNEL_LUID still names the outgoing adapter, so the rebuilt block
/// keeps permitting that interface — our own, and already permitted by the
/// block it replaces; the tunnel layer re-bakes the block with the NEW
/// adapter's LUID once it is published (tunnel.rs `configure_adapter`).
pub(crate) async fn move_relay(relay: Relay, engage: bool) -> Result<(), String> {
    *RELAY.lock().unwrap_or_else(|e| e.into_inner()) = Some(relay);
    // The exit node a customer chose: redacted like every other sink for it.
    tracing::debug!(
        "Kill switch relay set to {}:{} ({:?})",
        crate::utils::redact_ip(&relay.ip.to_string()),
        relay.port,
        relay.transport
    );
    if !IS_INITIALIZED.load(Ordering::SeqCst) {
        // No engine of the kill switch's own: nothing can be blocking.
        return if engage {
            Err("Kill switch not initialized".to_string())
        } else {
            Ok(())
        };
    }
    let block = current_block_all().await;
    let mut guard = engine_lock()?;
    let Some(engine) = guard.as_mut() else {
        return if engage {
            Err("WFP engine not open".to_string())
        } else {
            Ok(())
        };
    };
    let Some(next) = crate::vpn::wfp_policy::after_relay_move(&engine.installed, block, engage)
    else {
        return Ok(());
    };
    engine.apply(next)?;
    IS_BLOCKING.store(true, Ordering::SeqCst);
    tracing::info!(
        "Kill switch {} with the relay permit on {} — {} WFP filters committed atomically",
        if engage { "engaged" } else { "rebuilt" },
        crate::utils::redact_ip(&relay.ip.to_string()),
        engine.filter_ids.len()
    );
    Ok(())
}

/// Install (`Some`) or lift (`None`) the DNS guard (W1-007). Synchronous: it is
/// driven by the machine-state owner, which must be callable from `Drop`.
///
/// Installing opens the engine if nothing has yet; lifting with no engine is a
/// no-op — the dynamic session that held it is already gone.
pub(crate) fn set_dns_guard(dns_guard: Option<DnsGuard>) -> Result<(), String> {
    let mut guard = engine_lock()?;
    if dns_guard.is_none() && guard.is_none() {
        return Ok(());
    }
    let engine = ensure_engine(&mut guard)?;
    let installing = dns_guard.is_some();
    let next = Policy {
        dns_guard,
        ..engine.installed.clone()
    };
    engine.apply(next)?;
    tracing::info!(
        "DNS guard {}",
        if installing {
            "installed — DNS only through the tunnel"
        } else {
            "lifted"
        }
    );
    Ok(())
}

/// A default route came or went: re-derive which interfaces are host-only
/// virtual networks, so an uplink that got its gateway after the block was
/// installed stops being exempt from the inbound block. Cheap when nothing
/// changed. Called from the network-events thread.
pub fn refresh_after_network_change() {
    if !IS_BLOCKING.load(Ordering::SeqCst) {
        return;
    }
    let Ok(mut guard) = engine_lock() else {
        return;
    };
    let Some(engine) = guard.as_mut() else {
        return;
    };
    let Some(block) = engine.installed.block_all.clone() else {
        return;
    };
    let tunnel = TUNNEL_LUID.load(Ordering::SeqCst);
    let host_only = host_only_interfaces(&interface_facts(), (tunnel != 0).then_some(tunnel));
    if host_only == block.host_only_interfaces {
        return;
    }
    let next = Policy {
        block_all: Some(BlockAll {
            host_only_interfaces: host_only,
            ..block
        }),
        ..engine.installed.clone()
    };
    if let Err(e) = engine.apply(next) {
        tracing::warn!("Could not refresh the inbound exemptions: {}", e);
    }
}

/// Check if the kill switch is currently active.
pub fn is_blocking() -> bool {
    IS_BLOCKING.load(Ordering::SeqCst)
}

/// Enable/disable lockdown (always-on) mode. Takes effect on the next
/// `activate_blocking()`. Driven by the `lockdown_mode` user setting (ON by
/// default). See LOCKDOWN_MODE for the full semantics.
pub fn set_lockdown_mode(enabled: bool) {
    LOCKDOWN_MODE.store(enabled, Ordering::SeqCst);
    tracing::info!("Kill switch lockdown (always-on) mode set to: {}", enabled);
}

/// Whether lockdown (always-on) mode is enabled.
pub fn is_lockdown_mode() -> bool {
    LOCKDOWN_MODE.load(Ordering::SeqCst)
}

/// The relay the block-all currently lets the tunnel reach.
pub(crate) fn current_relay() -> Option<Relay> {
    *RELAY.lock().unwrap_or_else(|e| e.into_inner())
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

/// Clean up and release all resources: the end of the session.
///
/// Closing the engine removes every filter at once — the dynamic session owns
/// them — so nothing needs deleting one by one first.
pub async fn cleanup() -> Result<(), String> {
    tracing::info!("Cleaning up kill switch resources");

    // Drop the IPv6-block intent FIRST: cleanup() is the end of the session (a
    // user-initiated disconnect calls it via killswitch::disarm(), including one
    // issued mid-reconnect), so nothing may rebuild a standalone IPv6 block
    // that no tunnel would ever remove.
    v6_state::on_cleanup();

    let mut guard = engine_lock()?;
    // P1-ks-wfp-initialize-toctou-handle-leak: even if close() errors, drop the
    // engine and clear IS_INITIALIZED — otherwise the module believes it is
    // initialized with an engine whose handle may be invalid, and every later
    // activation fails. Drop on WfpEngine retries the close as a backstop.
    let close_result = match guard.as_mut() {
        Some(engine) => engine.close(),
        None => Ok(()),
    };
    *guard = None;

    IS_BLOCKING.store(false, Ordering::SeqCst);
    IS_INITIALIZED.store(false, Ordering::SeqCst);
    close_result?;
    tracing::info!("Kill switch cleanup complete");
    Ok(())
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
///
/// W1-044: this runs on every connect and settings reapply, and resolving a
/// short name spawns `where.exe` and walks Program Files two levels deep. That
/// work now runs on the blocking pool — it used to run inside this async fn and
/// pin a runtime worker for seconds — and its result is reused while the
/// requested list is unchanged and every resolved path still exists.
pub async fn set_split_tunnel_apps(app_names: Vec<String>) {
    let resolved_paths =
        match tokio::task::spawn_blocking(move || resolve_split_tunnel_apps(&app_names)).await {
            Ok(paths) => paths,
            Err(e) => {
                tracing::warn!(
                    "Kill-switch exception resolution failed ({}) — none applied",
                    e
                );
                Vec::new()
            }
        };

    let mut apps = SPLIT_TUNNEL_APPS.write().await;
    *apps = resolved_paths;
}

/// The last resolution: (requested names, resolved paths).
static RESOLVED_SPLIT_TUNNEL: std::sync::Mutex<Option<(Vec<String>, Vec<String>)>> =
    std::sync::Mutex::new(None);

/// A cached resolution stands only while the request is unchanged, every name
/// resolved, and every path still exists — so an app that moved to a new
/// versioned folder, or was installed since, is resolved again.
fn can_reuse_resolution(
    requested: &[String],
    resolved: &[String],
    now: &[String],
    exists: impl Fn(&str) -> bool,
) -> bool {
    requested == now && resolved.len() == requested.len() && resolved.iter().all(|p| exists(p))
}

fn resolve_split_tunnel_apps(app_names: &[String]) -> Vec<String> {
    let mut cache = RESOLVED_SPLIT_TUNNEL
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some((requested, resolved)) = cache.as_ref() {
        if can_reuse_resolution(requested, resolved, app_names, |p| {
            std::path::Path::new(p).exists()
        }) {
            return resolved.clone();
        }
    }

    let mut resolved_paths = Vec::new();
    for name in app_names {
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
    *cache = Some((app_names.to_vec(), resolved_paths.clone()));
    resolved_paths
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

#[cfg(test)]
mod split_tunnel_resolution_tests {
    use super::can_reuse_resolution;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn an_unchanged_request_reuses_the_resolution() {
        let req = v(&["chrome.exe"]);
        let res = v(&[r"C:\Apps\chrome.exe"]);
        assert!(can_reuse_resolution(&req, &res, &req, |_| true));
    }

    #[test]
    fn anything_that_could_have_changed_resolves_again() {
        let req = v(&["chrome.exe", "slack.exe"]);
        let res = v(&[r"C:\Apps\chrome.exe", r"C:\Apps\slack.exe"]);
        // A different list.
        assert!(!can_reuse_resolution(
            &req,
            &res,
            &v(&["chrome.exe"]),
            |_| true
        ));
        // A path that moved (an app updated into a versioned folder).
        assert!(!can_reuse_resolution(&req, &res, &req, |p| !p.contains("slack")));
        // A name that did not resolve last time may resolve now.
        let partial = v(&[r"C:\Apps\chrome.exe"]);
        assert!(!can_reuse_resolution(&req, &partial, &req, |_| true));
    }
}

/// Nothing WFP holds may outlive the process: no provider, no persistent or
/// boot-time object, one DYNAMIC session. That is what makes a crash, an End
/// task or an uninstall of a killed app unable to leave a filter (or the DNS
/// guard) behind, and why the uninstaller has none to remove (W1-008).
#[cfg(test)]
mod lifetime_tests {
    #[test]
    fn every_wfp_object_lives_in_the_dynamic_session() {
        let text = include_str!("wfp.rs");
        assert!(text.contains("session.flags = FWPM_SESSION_FLAG_DYNAMIC;"));
        // Built at run time so this file does not match its own needles.
        for needle in [
            ["FwpmProvider", "Add0"].concat(),
            ["FWPM_FILTER_FLAG_", "PERSISTENT"].concat(),
            ["FWPM_FILTER_FLAG_", "BOOTTIME"].concat(),
            ["FWPM_SUBLAYER_FLAG_", "PERSISTENT"].concat(),
        ] {
            assert!(!text.contains(&needle), "wfp.rs uses {needle}");
        }
    }
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

    /// LEAK-1 regression (review): auto-reconnect GIVING UP must not re-install a
    /// standalone IPv6 block for a session that is over. The give-up branch clears
    /// the intent (clear_ipv6_block_intent → on_cleanup) BEFORE deactivating, so
    /// deactivate_blocking() sees no intent and leaves IPv6 open. Without the
    /// clear, deactivation would rebuild the block with no tunnel behind it and
    /// blackhole IPv6 for the rest of the run.
    #[test]
    fn give_up_branch_does_not_reinstall_ipv6_block() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_state();
        let mut engine = FakeEngine::default();

        // Connect (non-dual-stack — every production session today), then a flaky
        // network: drop, arm kill switch, each failed retry no-ops the unblock.
        engine.block_ipv6();
        engine.activate_blocking();
        engine.unblock_ipv6(); // old tunnel torn down; intent held under kill switch
        assert!(IPV6_BLOCK_WANTED.load(Ordering::SeqCst));

        // Max attempts reached: the give-up branch clears the intent, THEN
        // deactivates the kill switch to restore connectivity.
        clear_ipv6_block_intent();
        engine.deactivate_blocking();

        assert!(
            !engine.ipv6_blocked(),
            "give-up must leave IPv6 OPEN — a rebuilt block would have no tunnel to remove it"
        );
        assert!(!IPV6_BLOCK_WANTED.load(Ordering::SeqCst));
        assert!(!IPV6_ONLY_ACTIVE.load(Ordering::SeqCst));
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

    /// W15 (tunnel.rs `bring_up_dual_stack`): when a dual-stack tunnel's IPv6
    /// configure FAILS, `unblock_ipv6_dual_stack()` is never called, so the
    /// pre-emptive block AND its intent must survive — through a reactive
    /// kill-switch cycle too — until the session ends. The old
    /// unblock-then-configure order dropped the intent first and then
    /// re-blocked; this walks the state the new order leaves behind.
    #[test]
    fn failed_dual_stack_configure_retains_the_block_intent() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_state();
        let mut engine = FakeEngine::default();

        // Top of start(): pre-emptive block.
        engine.block_ipv6();
        assert!(engine.ipv6_blocked());
        assert!(IPV6_BLOCK_WANTED.load(Ordering::SeqCst));

        // configure_ipv6() fails -> no unblock_ipv6_dual_stack() call at all.
        // (Nothing to do here: the absence of the call IS the behaviour.)
        assert!(engine.ipv6_blocked(), "block must still be in force");
        assert!(
            IPV6_BLOCK_WANTED.load(Ordering::SeqCst),
            "intent must be retained when configure fails"
        );
        assert!(IPV6_ONLY_ACTIVE.load(Ordering::SeqCst));

        // The session carries on IPv4-only; a later drop + reactive kill
        // switch + recovery must keep IPv6 blocked, exactly as for a v4-only
        // tunnel.
        engine.activate_blocking();
        engine.unblock_ipv6(); // old tunnel's stop(); kill switch owns v6
        engine.deactivate_blocking();
        assert!(
            engine.ipv6_blocked(),
            "after a reactive cycle the standalone block must be rebuilt"
        );

        // Only the user's disconnect lifts it.
        engine.cleanup();
        assert!(!engine.ipv6_blocked());
        assert!(!IPV6_BLOCK_WANTED.load(Ordering::SeqCst));

        reset_state();
    }
}
