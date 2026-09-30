/**
 * What each connection state LOOKS like and what the main button DOES — pure
 * functions, so every state is pinned by a table test instead of by reading a
 * 1700-line component.
 *
 * Wording is the canonical table in P1-parity.md ("Connection states"): the
 * pill never shows an engine phase ("Authenticating", "Rekeying") or a bare
 * "Error", and a danger pill reading "Kill Switch" — which looked like the
 * setting, not "you are blocked" — is gone in favour of a separate chip.
 */
import type { VpnState } from '@/lib/ipc';

export type PillTone = 'neutral' | 'success' | 'warning' | 'danger';
export type PillIcon = 'wifi-off' | 'sync' | 'alert' | null;

export interface PillSpec {
  text: string;
  tone: PillTone;
  icon: PillIcon;
  pulse: boolean;
}

export function statusPill(state: VpnState, multiHop = false): PillSpec {
  switch (state) {
    case 'connected':
      return {
        text: multiHop ? 'Protected · Multi-Hop' : 'Protected',
        tone: 'success',
        icon: null,
        pulse: true,
      };
    case 'connecting':
      return { text: 'Connecting…', tone: 'warning', icon: 'sync', pulse: false };
    case 'switching':
      return { text: 'Switching server…', tone: 'warning', icon: 'sync', pulse: false };
    case 'reconnecting':
      return { text: 'Reconnecting…', tone: 'warning', icon: 'sync', pulse: false };
    case 'disconnecting':
      return { text: 'Disconnecting…', tone: 'warning', icon: 'sync', pulse: false };
    case 'error':
      return { text: 'Connection error', tone: 'danger', icon: 'alert', pulse: false };
    case 'disconnected':
      return { text: 'Not connected', tone: 'neutral', icon: 'wifi-off', pulse: false };
  }
}

export const KILL_SWITCH_BLOCKING_TEXT = 'Kill Switch — all traffic blocked';
export const KILL_SWITCH_PENDING_TEXT = 'Kill Switch arms once connected';

/**
 * The kill-switch chip under the pill (iOS HomeView): "blocking" only while
 * Rust says the block is really engaged with no tunnel, and the honest neutral
 * "arms once connected" while it is on but idle (P1-parity-019).
 */
export function killSwitchChip(
  state: VpnState,
  blocking: boolean,
  killSwitchEnabled: boolean,
): 'blocking' | 'pending' | null {
  if (blocking) return 'blocking';
  if (killSwitchEnabled && (state === 'disconnected' || state === 'error')) return 'pending';
  return null;
}

/** How the Connect button is painted (see CompactConnectButton). */
export type ConnectLook = 'idle' | 'connected' | 'busy' | 'multiHopReady' | 'multiHopBlocked' | 'stop';

export interface ConnectCta {
  /** What a click does. `none` = the button is disabled. */
  action: 'connect' | 'disconnect' | 'none';
  label: string;
  /** Show the spinner. Independent of `action`: a busy button can still be pressed. */
  busy: boolean;
  look: ConnectLook;
}

/**
 * The main button, per state. Disconnect is NEVER gated on state (W2-003,
 * W2-004, W2-005, W2-025): in `connecting` it cancels the dial, in
 * `reconnecting` / `switching` it is the way out of a loop that can run for
 * minutes with traffic blocked, and whenever the kill switch is holding the
 * block it releases it. It used to be disabled in all of those, reading
 * "Connecting…", while the tray's Disconnect did nothing.
 *
 * `error` without a block offers Connect, as on iOS/Android: there is no
 * tunnel and no block, so the useful action is to try again.
 */
export function connectCta(
  state: VpnState,
  o: { blocking: boolean; multiHopArmed: boolean; multiHopReady: boolean },
): ConnectCta {
  switch (state) {
    case 'connecting':
      return { action: 'disconnect', label: 'Cancel', busy: true, look: 'busy' };
    case 'switching':
    case 'reconnecting':
      return { action: 'disconnect', label: 'Disconnect', busy: true, look: 'busy' };
    case 'disconnecting':
      return { action: 'none', label: 'Disconnecting…', busy: true, look: 'busy' };
    case 'connected':
      return { action: 'disconnect', label: 'Disconnect', busy: false, look: 'connected' };
    case 'error':
    case 'disconnected':
      if (o.blocking) return { action: 'disconnect', label: 'Disconnect', busy: false, look: 'stop' };
      if (o.multiHopArmed && !o.multiHopReady) {
        return { action: 'none', label: 'Choose entry & exit', busy: false, look: 'multiHopBlocked' };
      }
      if (o.multiHopArmed) {
        return { action: 'connect', label: 'Connect Multi-Hop', busy: false, look: 'multiHopReady' };
      }
      return { action: 'connect', label: 'Connect', busy: false, look: 'idle' };
  }
}
