//! System-tray state, driven from Rust.
//!
//! W1-023: the icon, tooltip and menu used to be set by the webview through
//! `set_tray_state`, from a poll that ran only while the Home tab was mounted
//! — 15 s apart when hidden, and not at all behind the biometric lock. A VPN
//! lives in the tray, so the tray showed "Connected" long after a drop. They
//! now follow the `vpn-status-changed` choke point (`VpnManager`'s published
//! status), which needs no window at all. Copy is the canonical vocabulary
//! (audit/P1-parity.md).
//!
//! The icons are embedded at build time so they ship inside the exe.

use tauri::image::Image;
use tauri::menu::MenuItem;
use tauri::{AppHandle, Manager, Wry};

/// Handles to the tray context-menu items whose `enabled` state must track the
/// live VPN connection state. Stored in Tauri-managed state at setup time so
/// `apply_tray_status` can flip them.
///
/// Without this, the tray "Disconnect" item was created `enabled: false` and
/// never re-enabled — so it was permanently greyed out even while connected.
pub struct TrayMenuItems {
    pub connect: MenuItem<Wry>,
    pub disconnect: MenuItem<Wry>,
}

/// Decode an embedded PNG (RGBA, as emitted by `tauri icon`) into a Tauri
/// `Image`. Uses the `png` crate directly so we avoid tauri's `image-png`
/// feature (the moxcms/pxfm colour chain); png 0.18 stays the leaner, known-good
/// decode path on the pinned 1.96 toolchain. Returns an owned image so it can
/// outlive the byte slice.
pub fn load_tray_image(bytes: &[u8]) -> Result<Image<'static>, String> {
    // png 0.18: `Decoder<R>` requires `R: BufRead + Seek`; a `Cursor` over the
    // embedded bytes satisfies both.
    let decoder = png::Decoder::new(std::io::Cursor::new(bytes));
    let mut reader = decoder.read_info().map_err(|e| e.to_string())?;
    // png 0.18: `output_buffer_size()` is an `Option` (None on overflow).
    let mut buf = vec![
        0u8;
        reader
            .output_buffer_size()
            .ok_or("tray PNG size overflows")?
    ];
    let info = reader.next_frame(&mut buf).map_err(|e| e.to_string())?;
    let (w, h) = (info.width, info.height);
    let rgba = match info.color_type {
        png::ColorType::Rgba => {
            buf.truncate(info.buffer_size());
            buf
        }
        png::ColorType::Rgb => {
            let src = &buf[..info.buffer_size()];
            let mut out = Vec::with_capacity((w as usize) * (h as usize) * 4);
            for px in src.chunks_exact(3) {
                out.extend_from_slice(px);
                out.push(255);
            }
            out
        }
        other => return Err(format!("unsupported tray PNG color type: {other:?}")),
    };
    Ok(Image::new_owned(rgba, w, h))
}

/// Which embedded icon the tray shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayIcon {
    Connected,
    Connecting,
    Disconnected,
}

/// What the tray shows for a status. Pure, so the mapping is unit-tested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayPresentation {
    pub icon: TrayIcon,
    pub tooltip: String,
    pub connect_enabled: bool,
    pub disconnect_enabled: bool,
}

pub fn tray_presentation(status: &crate::commands::vpn::VpnStatus) -> TrayPresentation {
    let (icon, label) = match status.state {
        "connected" if status.multi_hop.is_some() => (TrayIcon::Connected, "Protected · Multi-Hop"),
        "connected" => (TrayIcon::Connected, "Protected"),
        "connecting" => (TrayIcon::Connecting, "Connecting…"),
        "reconnecting" => (TrayIcon::Connecting, "Reconnecting…"),
        "switching" => (TrayIcon::Connecting, "Switching server…"),
        "disconnecting" => (TrayIcon::Connecting, "Disconnecting…"),
        "error" => (TrayIcon::Disconnected, "Connection error"),
        _ => (TrayIcon::Disconnected, "Not connected"),
    };
    let tooltip = if status.kill_switch_blocking {
        // The tray is often the only visible surface: say that the machine is
        // offline on purpose, and why, rather than a state name.
        "BirdoVPN — Kill Switch — all traffic blocked".to_string()
    } else {
        match (status.state, status.server_name.as_deref()) {
            ("connected", Some(location)) => format!("BirdoVPN — {label}\nvia {location}"),
            _ => format!("BirdoVPN — {label}"),
        }
    };
    let idle = matches!(status.state, "disconnected" | "error");
    TrayPresentation {
        icon,
        tooltip,
        connect_enabled: idle,
        // Disconnect works in every state but "already there" (contract §3.1),
        // and is always offered while the block holds the machine offline.
        disconnect_enabled: !matches!(status.state, "disconnected" | "disconnecting")
            || status.kill_switch_blocking,
    }
}

/// Apply `status` to the tray. A no-op before the tray exists.
pub fn apply_tray_status(app: &AppHandle, status: &crate::commands::vpn::VpnStatus) {
    let Some(tray) = app.tray_by_id("main") else {
        return;
    };
    let presentation = tray_presentation(status);
    let bytes: &[u8] = match presentation.icon {
        TrayIcon::Connected => include_bytes!("../../icons/tray-connected.png"),
        TrayIcon::Connecting => include_bytes!("../../icons/tray-connecting.png"),
        TrayIcon::Disconnected => include_bytes!("../../icons/tray-disconnected.png"),
    };
    match load_tray_image(bytes) {
        Ok(icon) => {
            let _ = tray.set_icon(Some(icon));
        }
        Err(e) => tracing::warn!("Tray icon could not be decoded: {}", e),
    }
    let _ = tray.set_tooltip(Some(presentation.tooltip.as_str()));
    if let Some(items) = app.try_state::<TrayMenuItems>() {
        let _ = items.connect.set_enabled(presentation.connect_enabled);
        let _ = items
            .disconnect
            .set_enabled(presentation.disconnect_enabled);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::vpn::VpnStatus;

    fn status(state: &'static str) -> VpnStatus {
        VpnStatus {
            state,
            phase: None,
            reconnect_attempt: None,
            reconnect_max: None,
            kill_switch_blocking: false,
            error: None,
            server_id: None,
            multi_hop: None,
            gave_up: None,
            seq: 1,
            bytes_sent: 0,
            bytes_received: 0,
            connected_at: None,
            server_name: None,
            stealth_active: false,
            quantum_active: false,
            pq_mode: crate::vpn::birdo_pq::PqMode::Disabled,
            dns_degraded: vec![],
        }
    }

    #[test]
    fn canonical_copy_per_state() {
        let mut connected = status("connected");
        connected.server_name = Some("Amsterdam".into());
        let p = tray_presentation(&connected);
        assert_eq!(p.icon, TrayIcon::Connected);
        assert_eq!(p.tooltip, "BirdoVPN — Protected\nvia Amsterdam");
        assert!(!p.connect_enabled && p.disconnect_enabled);

        for (state, text, icon) in [
            ("connecting", "BirdoVPN — Connecting…", TrayIcon::Connecting),
            (
                "reconnecting",
                "BirdoVPN — Reconnecting…",
                TrayIcon::Connecting,
            ),
            (
                "switching",
                "BirdoVPN — Switching server…",
                TrayIcon::Connecting,
            ),
            (
                "disconnected",
                "BirdoVPN — Not connected",
                TrayIcon::Disconnected,
            ),
            (
                "error",
                "BirdoVPN — Connection error",
                TrayIcon::Disconnected,
            ),
        ] {
            let p = tray_presentation(&status(state));
            assert_eq!(p.tooltip, text, "{state}");
            assert_eq!(p.icon, icon, "{state}");
        }
    }

    /// W2-003: tray Disconnect must work while connecting and reconnecting,
    /// and Quick Connect from an error.
    #[test]
    fn disconnect_is_offered_in_every_active_state() {
        for state in [
            "connecting",
            "reconnecting",
            "switching",
            "connected",
            "error",
        ] {
            assert!(
                tray_presentation(&status(state)).disconnect_enabled,
                "{state}"
            );
        }
        for state in ["disconnected", "disconnecting"] {
            assert!(
                !tray_presentation(&status(state)).disconnect_enabled,
                "{state}"
            );
        }
        assert!(tray_presentation(&status("error")).connect_enabled);
        assert!(!tray_presentation(&status("reconnecting")).connect_enabled);
    }

    #[test]
    fn blocking_says_so_and_keeps_disconnect_available() {
        let mut blocked = status("error");
        blocked.kill_switch_blocking = true;
        let p = tray_presentation(&blocked);
        assert_eq!(p.tooltip, "BirdoVPN — Kill Switch — all traffic blocked");
        assert!(p.disconnect_enabled);
    }

    #[test]
    fn multi_hop_reads_as_such() {
        let mut mh = status("connected");
        mh.multi_hop = Some(crate::vpn::manager::MultiHopStatus {
            entry_id: "a".into(),
            entry_name: "Frankfurt".into(),
            exit_id: "b".into(),
            exit_name: "Reykjavik".into(),
        });
        assert_eq!(
            tray_presentation(&mh).tooltip,
            "BirdoVPN — Protected · Multi-Hop"
        );
    }
}
