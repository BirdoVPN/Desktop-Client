/**
 * LiveAnnouncer — the polite live region that tells a screen-reader user what
 * the VPN is doing (W2-016). Before this, the pill was a plain div: nobody
 * using Narrator heard the tunnel connect, drop, reconnect or fail — the core
 * state of the app. One region for the whole app (not a live region per
 * banner), so a single change is announced once.
 */
import { errorCopy, giveUpMessage } from '@/lib/errors';
import { KILL_SWITCH_BLOCKING_TEXT, statusPill } from '@/lib/vpn-display';
import { useAppStore } from '@/store/app-store';
import { selectDisplayState } from '@/store/selectors';

export function LiveAnnouncer() {
  // A string, so the selector's result compares by value and an unrelated
  // store write never re-announces.
  const text = useAppStore((s) => {
    const state = selectDisplayState(s);
    const parts = [`VPN status: ${statusPill(state, !!s.liveMultiHop).text}`];
    if (s.killSwitchBlocking) parts.push(KILL_SWITCH_BLOCKING_TEXT);
    if (s.giveUp) {
      parts.push(giveUpMessage(s.giveUp.kind, s.giveUp.attempts, s.killSwitchBlocking));
    } else {
      const err = s.vpnError ?? s.commandError;
      if (err && err.code !== 'cancelled') parts.push(errorCopy(err, 'vpn').message);
    }
    return parts.join('. ');
  });
  return (
    <div
      role="status"
      aria-live="polite"
      aria-atomic="true"
      className="sr-only"
      data-testid="vpn-announcer"
      // Still heard while a dialog makes the rest of the app inert.
      data-modal-exempt
    >
      {text}
    </div>
  );
}
