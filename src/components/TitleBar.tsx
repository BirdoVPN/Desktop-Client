/**
 * TitleBar — slim custom window chrome for the frameless window.
 *
 * A thin top strip: Birdo mark + name on the left, minimize + close-to-tray on
 * the right. Replaces the floating controls. Minimize sends the window to the
 * taskbar; close hides to the system tray (mirrors main.rs CloseRequested — the
 * app keeps running in the tray, "Quit Birdo VPN" there fully exits).
 *
 * Hidden in "Free (draggable)" window mode, where the native OS title bar is
 * restored and owns these controls.
 */
import { getCurrentWindow } from '@tauri-apps/api/window';
import { Minus, X } from 'lucide-react';
import { AppIconMark } from '@/components/birdo';
import { useAppStore } from '@/store/app-store';
import { white } from '@/lib/birdo-theme';

const win = getCurrentWindow();

export function TitleBar() {
  const isFree = useAppStore((s) => s.windowCorner === 'free');
  if (isFree) return null;

  return (
    <div
      className="relative z-[100] flex h-8 shrink-0 select-none items-center justify-between border-b border-white/[0.06] px-2.5"
      // No backdrop-filter: a blur() that samples the continuously-repainting
      // globe canvas behind it smears into vertical "stretched line" streaks on
      // many WebView2 GPUs. A near-opaque solid fill reads the same and is safe.
      style={{ backgroundColor: 'rgba(11,11,16,0.97)' }}
    >
      <div className="flex items-center gap-1.5">
        <AppIconMark size={15} style={{ borderRadius: 4 }} />
        <span
          className="text-[11px] font-semibold tracking-wide"
          style={{ color: white.w80 }}
        >
          Birdo VPN
        </span>
      </div>
      <div className="flex items-center gap-0.5">
        <button
          type="button"
          aria-label="Minimize"
          title="Minimize"
          onClick={() => {
            win.minimize().catch((e) => console.error('Failed to minimize window:', e));
          }}
          className="flex h-6 w-7 items-center justify-center rounded text-white/45 transition-colors hover:bg-white/10 hover:text-white/90 focus:outline-none focus-visible:ring-1 focus-visible:ring-white/40"
        >
          <Minus size={13} strokeWidth={2.5} />
        </button>
        <button
          type="button"
          aria-label="Close to tray"
          title="Close to tray"
          onClick={() => {
            win.hide().catch((e) => console.error('Failed to hide window:', e));
          }}
          className="flex h-6 w-7 items-center justify-center rounded text-white/45 transition-colors hover:bg-red-500/80 hover:text-white focus:outline-none focus-visible:ring-1 focus-visible:ring-white/40"
        >
          <X size={13} strokeWidth={2.5} />
        </button>
      </div>
    </div>
  );
}
