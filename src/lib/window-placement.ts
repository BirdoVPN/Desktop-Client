/**
 * Window size and placement from the monitor's WORK AREA (W2-020).
 *
 * The Rust placement pinned bottom corners at `monitor height − window height
 * − 48 physical px`, because "Tauri's monitor API exposes full size, not the
 * work area". Tauri 2 does expose the work area (Rust `Monitor::work_area()`,
 * JS `Monitor.workArea`, @tauri-apps/api ≥ 2.2). And 48 physical px is a
 * 100%-scale taskbar: at 150% the taskbar is 72 px and the bottom navigation
 * sat under it; at 175% on a 1080p panel the 640 logical px window is 1120
 * physical px, taller than the screen, so its title bar was placed off-screen
 * and a pinned window cannot be dragged back.
 *
 * So: place against the work area (whichever edge the taskbar is on), and when
 * the work area is shorter than the window, shrink the window's height (down
 * to MIN_WINDOW_HEIGHT; every screen scrolls) instead of overflowing.
 */
import { getCurrentWindow, currentMonitor, primaryMonitor } from '@tauri-apps/api/window';
import { LogicalSize, PhysicalPosition } from '@tauri-apps/api/dpi';
import type { WindowCorner } from '@/store/app-store';

export const WINDOW_WIDTH = 380;
export const WINDOW_HEIGHT = 640;
/** Must match `minHeight` in src-tauri/tauri.conf.json. */
export const MIN_WINDOW_HEIGHT = 520;
/** Breathing room from the work-area edges, in logical px. */
const EDGE_MARGIN = 8;

export interface PhysicalRect {
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface Placement {
  /** Physical position of the window's top-left corner. */
  x: number;
  y: number;
  /** The window's height in logical px (its width is always WINDOW_WIDTH). */
  logicalHeight: number;
}

/** Pure placement maths, in physical pixels in and out. */
export function computePlacement(
  corner: Exclude<WindowCorner, 'free'>,
  workArea: PhysicalRect,
  scale: number,
): Placement {
  const s = scale > 0 ? scale : 1;
  const margin = Math.round(EDGE_MARGIN * s);
  const fitLogical = Math.floor((workArea.height - 2 * margin) / s);
  const logicalHeight = Math.max(MIN_WINDOW_HEIGHT, Math.min(WINDOW_HEIGHT, fitLogical));
  const w = Math.round(WINDOW_WIDTH * s);
  const h = Math.round(logicalHeight * s);

  const left = workArea.x + margin;
  const right = workArea.x + workArea.width - w - margin;
  const top = workArea.y + margin;
  const bottom = workArea.y + workArea.height - h - margin;

  const x = corner === 'top-right' || corner === 'bottom-right' ? right : left;
  const y = corner === 'bottom-left' || corner === 'bottom-right' ? bottom : top;
  // Never above or left of the work area: the title bar must stay reachable
  // even on a display too small for MIN_WINDOW_HEIGHT.
  return { x: Math.max(workArea.x, x), y: Math.max(workArea.y, y), logicalHeight };
}

/**
 * Apply the saved preference: 'free' restores the native title bar (movable);
 * a corner removes it and pins the window there, sized to fit.
 */
export async function applyWindowPlacement(corner: WindowCorner): Promise<void> {
  const win = getCurrentWindow();
  await win.setDecorations(corner === 'free');
  if (corner === 'free') return;
  const mon = (await currentMonitor()) ?? (await primaryMonitor());
  if (!mon) return;
  const wa = mon.workArea;
  const p = computePlacement(
    corner,
    { x: wa.position.x, y: wa.position.y, width: wa.size.width, height: wa.size.height },
    mon.scaleFactor,
  );
  await win.setSize(new LogicalSize(WINDOW_WIDTH, p.logicalHeight));
  await win.setPosition(new PhysicalPosition(p.x, p.y));
}
