//! DNS management for WintunTunnel
//!
//! Extracted from tunnel.rs — handles DNS configuration, snapshot/restore,
//! and non-VPN adapter enumeration.

use std::process::Command;
use tracing;

use super::tunnel::{WintunTunnel, AdapterDnsSnapshot};
use crate::utils::redact_ip;

/// Hidden command helper
fn cmd(program: &str) -> Command {
    crate::utils::hidden_cmd(program)
}

/// SEC-C4 FIX: Encode PowerShell script as Base64 UTF-16LE
fn base64_encode_utf16le(script: &str) -> String {
    use base64::Engine;
    let utf16: Vec<u8> = script.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    base64::engine::general_purpose::STANDARD.encode(&utf16)
}

impl WintunTunnel {
    /// Get list of non-VPN adapter names using PowerShell Get-NetAdapter.
    pub(super) fn get_non_vpn_adapters() -> Vec<String> {
        let ps_script = format!(
            "Get-NetAdapter -Physical | Where-Object {{ $_.Name -ne '{}' -and $_.Status -eq 'Up' }} | Select-Object -ExpandProperty Name",
            super::tunnel::ADAPTER_NAME
        );
        let encoded = base64_encode_utf16le(&ps_script);

        match cmd("powershell")
            .args(["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded])
            .output()
        {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                stdout.lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect()
            }
            _ => {
                // Fallback: use netsh
                match cmd("netsh")
                    .args(["interface", "show", "interface"])
                    .output()
                {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        stdout.lines()
                            .filter(|l| l.contains("Connected") && !l.contains(super::tunnel::ADAPTER_NAME))
                            .filter_map(|l| l.split_whitespace().last().map(String::from))
                            .collect()
                    }
                    Err(_) => Vec::new(),
                }
            }
        }
    }

    /// Capture current DNS configuration for an adapter before modification.
    pub(super) fn snapshot_adapter_dns(adapter_name: &str) -> Option<AdapterDnsSnapshot> {
        let output = cmd("netsh")
            .args(["interface", "ipv4", "show", "dns", adapter_name])
            .output()
            .ok()?;
        let stdout = String::from_utf8_lossy(&output.stdout);

        let servers: Vec<String> = stdout
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.starts_with(|c: char| c.is_ascii_digit()) {
                    Some(trimmed.to_string())
                } else {
                    None
                }
            })
            .collect();

        Some(AdapterDnsSnapshot {
            adapter_name: adapter_name.to_string(),
            dns_servers: servers,
        })
    }
}
