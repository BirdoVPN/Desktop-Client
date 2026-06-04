/**
 * WindowControls — minimize + close-to-tray buttons.
 *
 * The window is frameless (decorations:false) and pinned to the top-left
 * corner, so the native title-bar buttons are gone. This tiny overlay restores
 * those affordances: minimize sends the window to the taskbar; close hides it
 * to the system tray (mirroring the CloseRequested handler in main.rs — the app
 * keeps running in the tray, where "Quit Birdo VPN" fully exits).
 *
 * Rendered once at the App root so it sits above every screen. It is the only
 * interactive chrome at the very top of the window; nothing here is a drag
 * region (the window is intentionally non-movable).
 */
import { getCurrentWindow } from '@tauri-apps/api/window';
import { Minus, X } from 'lucide-react';

const win = getCurrentWindow();

export function WindowControls() {
  return (
    <div className="absolute right-1.5 top-1.5 z-[100] flex items-center gap-1">
      <button
        type="button"
        aria-label="Minimize"
        title="Minimize"
        onClick={() => {
          void win.minimize();
        }}
        className="flex h-6 w-6 items-center justify-center rounded-md text-white/45 transition-colors hover:bg-white/10 hover:text-white/90 focus:outline-none focus-visible:ring-1 focus-visible:ring-white/30"
      >
        <Minus size={13} strokeWidth={2.5} />
      </button>
      <button
        type="button"
        aria-label="Close to tray"
        title="Close to tray"
        onClick={() => {
          void win.hide();
        }}
        className="flex h-6 w-6 items-center justify-center rounded-md text-white/45 transition-colors hover:bg-red-500/80 hover:text-white focus:outline-none focus-visible:ring-1 focus-visible:ring-white/30"
      >
        <X size={13} strokeWidth={2.5} />
      </button>
    </div>
  );
}
