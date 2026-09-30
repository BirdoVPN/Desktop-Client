//! One-time removal of the Windows Firewall rules BirdoVPN <= 1.3.19 created
//! (W1-036).
//!
//! Those builds blocked IPv6, and implemented the kill switch, with PERSISTENT
//! `netsh advfirewall` rules, which survive reboots. Every build since deleted
//! them on EVERY disconnect, in the tunnel's `Drop` and in the panic hook —
//! seconds of AV-scanned process spawns each time, on machines healed long
//! ago. The heal still matters in one case: a machine that jumps from
//! <= 1.3.19 straight to this build would otherwise keep IPv6 (or, with a
//! stranded kill-switch rule, everything) blocked by rules nothing else would
//! ever remove. So it runs exactly once per install, in the background at
//! start-up, and a marker file records that it did.
//!
//! Every name here is one of ours, so deleting it can only ever remove
//! something BirdoVPN created.

use std::path::{Path, PathBuf};

/// Every rule name a pre-WFP build could have left: the IPv6 blocks the tunnel
/// installed and the kill-switch set (`BirdoVPN_*`).
pub(crate) const LEGACY_RULE_NAMES: [&str; 14] = [
    "Birdo VPN Block IPv6 Out",
    "Birdo VPN Block IPv6 Out UDP",
    "Birdo VPN Block IPv6 In",
    "Birdo VPN Block IPv6 In UDP",
    "Birdo VPN Block ICMPv6",
    "Birdo VPN Block 6in4",
    "Birdo Block IPv6",
    "BirdoVPN_BlockAll",
    "BirdoVPN_PermitVPN",
    "BirdoVPN_PermitLocalhost",
    "BirdoVPN_PermitDHCP",
    "BirdoVPN_BlockIPv6",
    "BirdoVPN_BlockSTUN",
    "BirdoVPN_BlockTURN",
];

fn marker_path() -> Option<PathBuf> {
    let mut dir = dirs::data_dir()?;
    dir.push("BirdoVPN");
    Some(dir.join("legacy-firewall-cleanup.done"))
}

/// Delete every legacy rule with `delete`, unless `marker` says it was done.
fn run_once_with(marker: &Path, mut delete: impl FnMut(&str)) {
    if marker.exists() {
        return;
    }
    for rule in LEGACY_RULE_NAMES {
        delete(rule);
    }
    if let Some(dir) = marker.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Err(e) = std::fs::write(marker, b"1") {
        tracing::debug!("Legacy firewall cleanup marker not written: {}", e);
    }
}

/// Run the heal once per install, on a background thread.
pub fn spawn_once() {
    let Some(marker) = marker_path() else {
        return;
    };
    std::thread::spawn(move || {
        run_once_with(&marker, |rule| {
            let _ = crate::utils::hidden_cmd("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    &format!("name={rule}"),
                ])
                .output();
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heals_every_legacy_rule_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("BirdoVPN").join("done");
        let mut deleted = Vec::new();
        run_once_with(&marker, |rule| deleted.push(rule.to_string()));
        assert_eq!(deleted.len(), LEGACY_RULE_NAMES.len());
        assert!(marker.exists());

        let mut again = 0;
        run_once_with(&marker, |_| again += 1);
        assert_eq!(again, 0, "the heal ran twice");
    }

    /// The names are ours alone — deleting one can never touch another
    /// product's rule.
    #[test]
    fn every_name_is_a_birdo_name() {
        for rule in LEGACY_RULE_NAMES {
            assert!(rule.starts_with("Birdo"), "{rule}");
        }
    }

    /// W1-036: the per-disconnect and per-unwind copies are gone.
    #[test]
    fn the_hot_paths_no_longer_delete_firewall_rules() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        // Built at run time so the source scan cannot match this file.
        let needle = ["adv", "firewall"].concat();
        for file in ["vpn/tunnel.rs", "main.rs"] {
            let text = std::fs::read_to_string(dir.join(file)).expect("read source");
            assert!(
                !text.contains(&needle),
                "{file} deletes firewall rules again"
            );
            assert!(!text.contains("Remove-NetFirewallRule"), "{file}");
        }
    }
}
