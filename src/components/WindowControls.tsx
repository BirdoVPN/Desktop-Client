/**
 * WindowControls — minimize + close-to-tray buttons.
 *
 * The window is frameless (decorations:false) and pinned to a corner, so the
 * native title-bar buttons are gone. This overlay restores them: minimize sends
 * the window to the taskbar; close hides it to the system tray (mirroring the
 * CloseRequested handler in main.rs — the app keeps running in the tray, where
 * "Quit Birdo VPN" fully exits).
 *
 * Positioned bottom-right. When the bottom tab nav is visible (authenticated
 * tab-root screens) the cluster lifts above it so it never overlaps the Settings
 * tab; on login / consent / pushed sub-screens it sits in the very corner.
 */
import { getCurrentWindow } from '@tauri-apps/api/window';
import { Minus, X } from 'lucide-react';
import { useAppStore } from '@/store/app-store';
import { useShallow } from 'zustand/react/shallow';

const win = getCurrentWindow();

export function WindowControls() {
  const { navVisible, isFree } = useAppStore(
    useShallow((s) => ({
      navVisible: s.isAuthenticated && s.hasAcceptedConsent && s.navStack.length === 0,
      isFree: s.windowCorner === 'free',
    })),
  );

  // In "free" mode the native title bar is back, so its buttons handle this.
  if (isFree) return null;

  return (
    <div
      className={`absolute right-1.5 z-[100] flex items-center gap-1 ${
        navVisible ? 'bottom-[66px]' : 'bottom-1.5'
      }`}
    >
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
