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
//!
//! The marker is written only after a pass that VERIFIABLY ran
//! (REVIEW-WIN-011): the firewall service answered before and after it, and
//! every delete completed. It used to be written whatever happened, so a heal
//! that ran while the firewall service (MpsSvc) was unavailable left a
//! <= 1.3.19 upgrader's persistent rules — `BirdoVPN_BlockAll` among them,
//! which blocks everything — in place for good, with no later build ever
//! trying again.

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

/// What one `delete rule` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Deleted {
    /// The command ran to completion. netsh exits non-zero both for "No rules
    /// match" and for a failure, and its text is localised, so this cannot
    /// tell them apart; the firewall-service probe around the pass is what
    /// rules out the failure.
    Completed,
    /// The command could not be run.
    Failed,
}

/// Delete every legacy rule with `delete`, unless `marker` says it was done.
/// `firewall_answers` probes that the firewall service is up; the marker is
/// written only when it answered before AND after the pass and every delete
/// completed. Otherwise the next start tries again.
fn run_once_with(
    marker: &Path,
    mut firewall_answers: impl FnMut() -> bool,
    mut delete: impl FnMut(&str) -> Deleted,
) {
    if marker.exists() {
        return;
    }
    if !firewall_answers() {
        tracing::warn!(
            "Legacy firewall cleanup postponed: the Windows Firewall service did not answer"
        );
        return;
    }
    let mut complete = true;
    for rule in LEGACY_RULE_NAMES {
        if delete(rule) == Deleted::Failed {
            complete = false;
        }
    }
    if !complete || !firewall_answers() {
        tracing::warn!("Legacy firewall cleanup incomplete; it will run again at the next start");
        return;
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
        let netsh = |args: &[&str]| crate::utils::hidden_cmd("netsh").args(args).output();
        run_once_with(
            &marker,
            // Read-only, and it fails while the firewall service is stopped.
            || {
                netsh(&["advfirewall", "show", "currentprofile"])
                    .is_ok_and(|out| out.status.success())
            },
            |rule| {
                let name = format!("name={rule}");
                match netsh(&["advfirewall", "firewall", "delete", "rule", &name]) {
                    Ok(_) => Deleted::Completed,
                    Err(_) => Deleted::Failed,
                }
            },
        );
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
        run_once_with(
            &marker,
            || true,
            |rule| {
                deleted.push(rule.to_string());
                Deleted::Completed
            },
        );
        assert_eq!(deleted.len(), LEGACY_RULE_NAMES.len());
        assert!(marker.exists());

        let mut again = 0;
        run_once_with(
            &marker,
            || true,
            |_| {
                again += 1;
                Deleted::Completed
            },
        );
        assert_eq!(again, 0, "the heal ran twice");
    }

    /// REVIEW-WIN-011: a pass that did not verifiably run — the firewall
    /// service down before or after it, or a delete that could not be run —
    /// writes no marker, and the next start runs the heal again.
    #[test]
    fn an_unverified_pass_is_retried_at_the_next_start() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("BirdoVPN").join("done");

        // MpsSvc down: nothing is attempted, nothing is recorded.
        let mut attempted = 0;
        run_once_with(
            &marker,
            || false,
            |_| {
                attempted += 1;
                Deleted::Completed
            },
        );
        assert_eq!(attempted, 0);
        assert!(!marker.exists(), "marker written with the firewall down");

        // One delete could not be run.
        run_once_with(
            &marker,
            || true,
            |rule| {
                if rule == "BirdoVPN_BlockAll" {
                    Deleted::Failed
                } else {
                    Deleted::Completed
                }
            },
        );
        assert!(!marker.exists(), "marker written over a failed delete");

        // The service went away during the pass.
        let mut probes = 0;
        run_once_with(
            &marker,
            || {
                probes += 1;
                probes == 1
            },
            |_| Deleted::Completed,
        );
        assert!(
            !marker.exists(),
            "marker written after the service vanished"
        );

        // A clean pass at the next start finishes the job.
        run_once_with(&marker, || true, |_| Deleted::Completed);
        assert!(marker.exists());
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
