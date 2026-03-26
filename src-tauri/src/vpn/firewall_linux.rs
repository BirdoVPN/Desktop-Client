//! Linux firewall (iptables) kill switch implementation
//!
//! Blocks all non-VPN traffic using iptables when the VPN disconnects unexpectedly.
//! Uses a dedicated chain (BIRDO_KILLSWITCH) to avoid conflicting with user rules.
//!
//! Equivalent to WFP on Windows and pf on macOS.

#![allow(dead_code)]

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};

/// Tracks whether iptables blocking rules are active
pub(crate) static IPTABLES_BLOCKING: AtomicBool = AtomicBool::new(false);

/// Custom chain name for Birdo VPN kill switch rules
const CHAIN_NAME: &str = "BIRDO_KILLSWITCH";

/// Run an iptables command, returning Ok on success.
fn iptables(args: &[&str]) -> Result<(), String> {
    let output = crate::utils::hidden_cmd("iptables")
        .args(args)
        .output()
        .map_err(|e| format!("iptables command failed: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("iptables {} failed: {}", args.join(" "), stderr));
    }
    Ok(())
}

/// Check if our custom chain exists.
fn chain_exists() -> bool {
    crate::utils::hidden_cmd("iptables")
        .args(["-L", CHAIN_NAME, "-n"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Create the BIRDO_KILLSWITCH chain if it doesn't exist.
fn ensure_chain() -> Result<(), String> {
    if !chain_exists() {
        iptables(&["-N", CHAIN_NAME])?;
    }
    Ok(())
}

/// Activate blocking: block all traffic except loopback, DHCP, and VPN server.
pub async fn activate_blocking(server_ip: Option<Ipv4Addr>) -> Result<(), String> {
    tracing::info!("Activating Linux iptables kill switch");

    ensure_chain()?;

    // Flush our chain first (idempotent)
    let _ = iptables(&["-F", CHAIN_NAME]);

    // Allow loopback
    iptables(&["-A", CHAIN_NAME, "-o", "lo", "-j", "ACCEPT"])?;
    iptables(&["-A", CHAIN_NAME, "-i", "lo", "-j", "ACCEPT"])?;

    // Allow DHCP (UDP 67/68) so the system can maintain its network lease
    iptables(&["-A", CHAIN_NAME, "-p", "udp", "--dport", "67", "-j", "ACCEPT"])?;
    iptables(&["-A", CHAIN_NAME, "-p", "udp", "--dport", "68", "-j", "ACCEPT"])?;

    // Allow traffic to VPN server IP
    if let Some(ip) = server_ip {
        iptables(&["-A", CHAIN_NAME, "-d", &ip.to_string(), "-j", "ACCEPT"])?;
        iptables(&["-A", CHAIN_NAME, "-s", &ip.to_string(), "-j", "ACCEPT"])?;
    }

    // Allow traffic on the TUN interface (birdo0)
    iptables(&["-A", CHAIN_NAME, "-o", "birdo0", "-j", "ACCEPT"])?;
    iptables(&["-A", CHAIN_NAME, "-i", "birdo0", "-j", "ACCEPT"])?;

    // Allow established/related connections (for responses to allowed traffic)
    iptables(&["-A", CHAIN_NAME, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])?;

    // Drop everything else
    iptables(&["-A", CHAIN_NAME, "-j", "DROP"])?;

    // Insert our chain into the OUTPUT and INPUT chains at the top
    // First remove any existing references (ignore errors)
    let _ = iptables(&["-D", "OUTPUT", "-j", CHAIN_NAME]);
    let _ = iptables(&["-D", "INPUT", "-j", CHAIN_NAME]);
    let _ = iptables(&["-D", "FORWARD", "-j", CHAIN_NAME]);

    iptables(&["-I", "OUTPUT", "1", "-j", CHAIN_NAME])?;
    iptables(&["-I", "INPUT", "1", "-j", CHAIN_NAME])?;
    iptables(&["-I", "FORWARD", "1", "-j", CHAIN_NAME])?;

    IPTABLES_BLOCKING.store(true, Ordering::SeqCst);
    tracing::info!("Linux iptables kill switch activated");
    Ok(())
}

/// Deactivate blocking: remove our chain from the filter table.
pub async fn deactivate_blocking() -> Result<(), String> {
    tracing::info!("Deactivating Linux iptables kill switch");

    // Remove jumps to our chain
    let _ = iptables(&["-D", "OUTPUT", "-j", CHAIN_NAME]);
    let _ = iptables(&["-D", "INPUT", "-j", CHAIN_NAME]);
    let _ = iptables(&["-D", "FORWARD", "-j", CHAIN_NAME]);

    // Flush and delete our chain
    if chain_exists() {
        let _ = iptables(&["-F", CHAIN_NAME]);
        let _ = iptables(&["-X", CHAIN_NAME]);
    }

    IPTABLES_BLOCKING.store(false, Ordering::SeqCst);
    tracing::info!("Linux iptables kill switch deactivated");
    Ok(())
}

/// Check if iptables blocking is currently active.
pub fn is_blocking() -> bool {
    IPTABLES_BLOCKING.load(Ordering::SeqCst)
}

/// Emergency cleanup — called from panic handler.
/// Uses raw Command to avoid async runtime dependency.
pub fn emergency_cleanup() {
    let _ = std::process::Command::new("iptables")
        .args(["-D", "OUTPUT", "-j", CHAIN_NAME])
        .output();
    let _ = std::process::Command::new("iptables")
        .args(["-D", "INPUT", "-j", CHAIN_NAME])
        .output();
    let _ = std::process::Command::new("iptables")
        .args(["-D", "FORWARD", "-j", CHAIN_NAME])
        .output();
    let _ = std::process::Command::new("iptables")
        .args(["-F", CHAIN_NAME])
        .output();
    let _ = std::process::Command::new("iptables")
        .args(["-X", CHAIN_NAME])
        .output();
}
