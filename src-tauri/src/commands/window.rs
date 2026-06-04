//! Window placement command.
//!
//! Pins the frameless window to a corner of the monitor it's currently on
//! (multi-monitor aware via `current_monitor`), or — for "free" — restores the
//! native title bar so it can be dragged anywhere. Driven by the persisted
//! `windowCorner` preference: applied on startup and whenever the user changes
//! it in Settings.

use tauri::{AppHandle, Manager, PhysicalPosition};

/// Breathing room from the monitor edges for the top/left/right sides.
const EDGE_MARGIN: i32 = 8;
/// Reserve at the bottom so bottom-anchored placements clear the Windows
/// taskbar (Tauri's monitor API exposes full size, not the work area).
const TASKBAR_RESERVE: i32 = 48;

#[tauri::command]
pub fn set_window_position(app: AppHandle, corner: String) -> Result<(), String> {
    let Some(win) = app.get_webview_window("main") else {
        return Ok(());
    };

    // "free" → bring back native window chrome so it's movable.
    if corner == "free" {
        win.set_decorations(true).map_err(|e| e.to_string())?;
        return Ok(());
    }

    // Pinned corner → frameless + a computed position on the current monitor.
    win.set_decorations(false).map_err(|e| e.to_string())?;

    let monitor = match win.current_monitor().map_err(|e| e.to_string())? {
        Some(m) => Some(m),
        None => win.primary_monitor().map_err(|e| e.to_string())?,
    };
    let Some(mon) = monitor else {
        let _ = win.set_position(PhysicalPosition::new(0, 0));
        return Ok(());
    };

    let mpos = mon.position();
    let msize = mon.size();
    let wsize = win.outer_size().map_err(|e| e.to_string())?;

    let (mw, mh) = (msize.width as i32, msize.height as i32);
    let (ww, wh) = (wsize.width as i32, wsize.height as i32);
    let left = mpos.x + EDGE_MARGIN;
    let top = mpos.y + EDGE_MARGIN;
    let right = mpos.x + mw - ww - EDGE_MARGIN;
    let bottom = mpos.y + mh - wh - TASKBAR_RESERVE;

    let (x, y) = match corner.as_str() {
        "top-right" => (right, top),
        "bottom-left" => (left, bottom),
        "bottom-right" => (right, bottom),
        _ => (left, top), // "top-left" (default)
    };
    win.set_position(PhysicalPosition::new(x, y))
        .map_err(|e| e.to_string())?;
    Ok(())
}
