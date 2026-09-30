/**
 * Ending a session, the two ways it happens.
 */
import { invoke } from '@tauri-apps/api/core';
import { useAppStore } from '@/store/app-store';
import { selectTunnelActive } from '@/store/selectors';

/**
 * Rust ended the session (contract §3.3: it has already torn the tunnel down
 * and cleared the tokens) — drop to Login and say why. Idempotent: the
 * `session-expired` event and the command that tripped it usually both arrive.
 */
export function endSession(reason: 'expired' | 'revoked'): void {
  const s = useAppStore.getState();
  if (!s.isAuthenticated) return;
  s.logout();
  s.setSessionEndedReason(reason);
}

/**
 * The user signs out (W2-005). One implementation for Home, Profile and every
 * future caller: the two copies this replaces each disconnected only in
 * connected / connecting / reconnecting, so signing out after a failed switch
 * — the state in which Rust deliberately HOLDS the kill-switch block — landed
 * on Login with the machine firewalled and every control that could release
 * it behind the sign-in.
 *
 * Rust's `logout` performs the same teardown itself in v2 (contract §3.2);
 * disconnecting first anyway keeps this correct against a backend that does
 * not, and `disconnect_vpn` is valid in every state (§3.1).
 */
export async function signOut(): Promise<void> {
  if (selectTunnelActive(useAppStore.getState())) {
    try {
      await invoke('disconnect_vpn');
    } catch {
      /* best effort — Rust's logout tears down too */
    }
  }
  try {
    await invoke('logout');
  } catch {
    /* best effort — local state is cleared regardless */
  }
  useAppStore.getState().logout();
}
