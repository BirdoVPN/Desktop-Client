/**
 * MR-2335: reading the held deletion from the server into the shared state
 * (`@/lib/held-deletion`), and cancelling it.
 *
 * `command`, not `invoke`: a session that has ended takes the ordinary
 * session-expired path. It is never read as "the deletion went through".
 */
import { useEffect } from 'react';
import { errorCopy } from '@/lib/errors';
import {
  clearHeldDeletion,
  finishHeldDeletionRead,
  startHeldDeletionRead,
  useHeldDeletion,
  type HeldDeletion,
} from '@/lib/held-deletion';
import { toIpcError } from '@/lib/ipc';
import { command } from '@/session/command';

/**
 * How long a sign-out waits for the list before it goes ahead without it.
 * The request itself may take reqwest's 30 s; nobody waits that long to sign
 * out.
 */
export const HOLD_READ_WAIT_MS = 3000;

/**
 * Read `GET /auth/pending-changes` now. A hold that vanished (the server
 * cancels it on a sign-out everywhere, a number rotation, a password or 2FA
 * change) is simply gone; a read that FAILS keeps what is known, because an
 * outage is not "no hold". Never rejects: true once the server answered,
 * false when the read failed.
 */
export function refreshHeldDeletion(): Promise<boolean> {
  const token = startHeldDeletionRead();
  return command<unknown>('list_pending_changes')
    .then((items) => {
      finishHeldDeletionRead(token, items);
      return true;
    })
    .catch(() => false);
}

/**
 * `refreshHeldDeletion`, waited for at most `ms`: false when the read failed
 * or is still out by then (it carries on, and still updates the state).
 */
export function refreshHeldDeletionWithin(ms: number = HOLD_READ_WAIT_MS): Promise<boolean> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(false), ms);
    void refreshHeldDeletion().then((answered) => {
      clearTimeout(timer);
      resolve(answered);
    });
  });
}

/** The held deletion, read when the caller mounts and on every window focus. */
export function usePendingDeletion(): { hold: HeldDeletion | null; refresh: () => void } {
  const hold = useHeldDeletion();
  useEffect(() => {
    const read = () => void refreshHeldDeletion();
    read();
    window.addEventListener('focus', read);
    return () => window.removeEventListener('focus', read);
  }, []);
  return { hold, refresh: () => void refreshHeldDeletion() };
}

/**
 * Cancel a held deletion. Cancelled now (200) or gone already (404
 * `pending_change_not_found`): either way nothing is held any more, so the
 * shared state is cleared AT ONCE, and the list is then read again. The
 * banner and the sign-out warnings must not linger on a re-read that fails
 * or is slow. Rejects (and changes nothing) when the cancel itself failed.
 */
export async function cancelHeldDeletion(id: string): Promise<{ alreadyGone: boolean }> {
  const result = await command<{ cancelled?: boolean; alreadyGone?: boolean } | null>(
    'cancel_pending_change',
    { id },
  );
  clearHeldDeletion();
  void refreshHeldDeletion();
  return { alreadyGone: result?.alreadyGone === true };
}

/** A failed cancel, in words. */
export function cancelErrorText(e: unknown): string {
  const err = toIpcError(e);
  return err.code === 'unknown'
    ? "Couldn't cancel the deletion. Please try again."
    : errorCopy(err).message;
}
