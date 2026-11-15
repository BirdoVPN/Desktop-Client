/**
 * MR-2335: reading the held deletion from the server into the shared state
 * (`@/lib/held-deletion`).
 *
 * `command`, not `invoke`: a session that has ended takes the ordinary
 * session-expired path. It is never read as "the deletion went through".
 */
import { useEffect } from 'react';
import {
  finishHeldDeletionRead,
  startHeldDeletionRead,
  useHeldDeletion,
  type HeldDeletion,
} from '@/lib/held-deletion';
import { command } from '@/session/command';

/**
 * Read `GET /auth/pending-changes` now. A hold that vanished (the server
 * cancels it on a sign-out elsewhere, a number rotation, a password or 2FA
 * change) is simply gone; a read that FAILS keeps what is known, because an
 * outage is not "no hold". Never rejects.
 */
export function refreshHeldDeletion(): Promise<void> {
  const token = startHeldDeletionRead();
  return command<unknown>('list_pending_changes')
    .then((items) => finishHeldDeletionRead(token, items))
    .catch(() => {
      /* keep what is known */
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
