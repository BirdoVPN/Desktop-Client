//! System-tray state command.
//!
//! The tray icon + tooltip reflect the live VPN connection state. The frontend
//! drives this by calling `set_tray_state` whenever the connection state (or the
//! current server) changes — there's no native polling loop, so the single
//! source of truth stays the app store.
//!
//! `state` is one of: "connected" (green), "connecting" (amber — covers every
//! in-progress phase), anything else → "disconnected" (slate). The icons are
//! embedded at build time so they ship inside the exe.

use tauri::image::Image;
use tauri::AppHandle;

/// Decode an embedded PNG (RGBA, as emitted by `tauri icon`) into a Tauri
/// `Image`. Uses the `png` crate directly so we avoid tauri's `image-png`
/// feature (which pulls edition2024 deps incompatible with the pinned 1.83
/// toolchain). Returns an owned image so it can outlive the byte slice.
pub fn load_tray_image(bytes: &[u8]) -> Result<Image<'static>, String> {
    let decoder = png::Decoder::new(bytes);
    let mut reader = decoder.read_info().map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; reader.output_buffer_size()];
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

#[tauri::command]
pub fn set_tray_state(app: AppHandle, state: String, tooltip: String) -> Result<(), String> {
    // Tray may not exist yet during very early startup — treat as a no-op.
    let Some(tray) = app.tray_by_id("main") else {
        tracing::debug!(
            state = %state,
            "set_tray_state: tray 'main' not initialized yet — discarding update"
        );
        return Ok(());
    };

    let bytes: &[u8] = match state.as_str() {
        "connected" => include_bytes!("../../icons/tray-connected.png"),
        "connecting" => include_bytes!("../../icons/tray-connecting.png"),
        _ => include_bytes!("../../icons/tray-disconnected.png"),
    };

    let icon = load_tray_image(bytes)?;
    tray.set_icon(Some(icon)).map_err(|e| e.to_string())?;
    tray.set_tooltip(Some(tooltip.as_str()))
        .map_err(|e| e.to_string())?;
    Ok(())
}
