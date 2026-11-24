/**
 * Ending a session, the two ways it happens.
 */
import { invoke } from '@tauri-apps/api/core';
import { clearHeldDeletion } from '@/lib/held-deletion';
import { useAppStore } from '@/store/app-store';
import { selectTunnelActive } from '@/store/selectors';

/**
 * Rust ended the session (contract §3.3: it has already torn the tunnel down
 * and cleared the tokens) — drop to Login and say why. Idempotent: the
 * `session-expired` event and the command that tripped it usually both arrive.
 *
 * MR-2517: `deleted` is Rust's word for a refresh refused after a deletion
 * whose answer was lost (the heartbeat's, or any request's): Rust has cleared
 * what a deletion clears, and Login says the account is deleted, whatever
 * arrived first (`endDeletedSession`).
 */
export function endSession(reason: 'expired' | 'revoked' | 'deleted'): void {
  if (reason === 'deleted') {
    endDeletedSession();
    return;
  }
  const s = useAppStore.getState();
  if (!s.isAuthenticated) return;
  // MR-2335: the next account must not inherit this one's held deletion.
  clearHeldDeletion();
  s.logout();
  s.setSessionEndedReason(reason);
}

/**
 * A command answered `session_expired` (REVIEW-WIN-012). Rust ends the
 * session by itself only when the refresh is rejected; an `Unauthorized`
 * after a good refresh, or a call with no session, reaches only the UI. Left
 * there, Login sat over a live tunnel and a running reconnect loop that
 * nothing watched any more. So Rust is told to end it too (the same teardown
 * as §3.3, idempotent), and the UI drops to Login at once.
 */
export function expireSession(): void {
  if (!useAppStore.getState().isAuthenticated) return;
  invoke('end_expired_session').catch(() => {
    /* best effort: the UI is signed out either way */
  });
  endSession('expired');
}

/**
 * MR-2483: a retried deletion found the account already gone (the first
 * try's 2xx could not be read, MR-2370). Rust's `delete_account` has already
 * ended the session and cleared everything a confirmed deletion clears; drop
 * to Login and say the account is gone.
 *
 * Synchronous, and it wins whatever the order: the refresh that found the
 * session dead may also have sent `session-expired`. If that arrived first,
 * `endSession('expired')` signed out and this corrects the reason; if it
 * arrives after, `endSession` finds nobody signed in and does nothing.
 */
export function endDeletedSession(): void {
  const s = useAppStore.getState();
  clearHeldDeletion();
  if (s.isAuthenticated) s.logout();
  s.setSessionEndedReason('deleted');
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
  // MR-2335: signing out cancelled any held deletion on the server.
  clearHeldDeletion();
  useAppStore.getState().logout();
}
