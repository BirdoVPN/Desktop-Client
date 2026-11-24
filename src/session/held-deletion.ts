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

// The newest read started: a read whose answer was dropped waits for it.
let newestRead: { token: number; settled: Promise<boolean> } | null = null;

/**
 * MR-2532, owner decision 2026-11-24 ("never refresh at sign-out"): a request
 * of the Sign Out flow (the dialog's read, Profile's check before it, the
 * cancel-first) is sent once with the access token on file, never refreshed
 * on a 401, and not at all when that token is unusable. Such a read that did
 * not answer leaves the "could not check" caution; such a cancel, the dialog's
 * Retry / Sign out anyway. It never ends the session as expired either.
 */
export interface SignOutRequest {
  signingOut?: boolean;
}

/**
 * Read `GET /auth/pending-changes` now. A hold that vanished (the server
 * cancels it on a sign-out everywhere, a number rotation, a password or 2FA
 * change) is simply gone; a read that FAILS keeps what is known, because an
 * outage is not "no hold". Never rejects.
 *
 * True once an answer was APPLIED, false when the read failed. An answer
 * dropped because a newer read started is not "answered": this waits for
 * that newer read and settles with it. One dropped because the state was
 * written since (a hold noted from a 202, a cancel) counts as answered: that
 * write is newer than the answer.
 */
export function refreshHeldDeletion({ signingOut = false }: SignOutRequest = {}): Promise<boolean> {
  const token = startHeldDeletionRead();
  const read = signingOut
    ? command<unknown>('list_pending_changes', { signingOut: true })
    : command<unknown>('list_pending_changes');
  const settled = read.then(
    (items): boolean | Promise<boolean> => {
      if (finishHeldDeletionRead(token, items)) return true;
      const newer = newestRead;
      return newer !== null && newer.token > token ? newer.settled : true;
    },
    () => false,
  );
  newestRead = { token, settled };
  return settled;
}

/**
 * `refreshHeldDeletion`, waited for at most `ms`: false when the read failed
 * or is still out by then (it carries on, and still updates the state).
 */
export function refreshHeldDeletionWithin(
  ms: number = HOLD_READ_WAIT_MS,
  request: SignOutRequest = {},
): Promise<boolean> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(false), ms);
    void refreshHeldDeletion(request).then((answered) => {
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
 *
 * `reread: false` when the session is about to end (the cancel before a
 * sign-out): a read then could race the sign-out, come back 401 and turn a
 * deliberate sign-out into "session expired". `signingOut` for that same
 * cancel ([SignOutRequest]).
 */
export async function cancelHeldDeletion(
  id: string,
  { reread = true, signingOut = false }: { reread?: boolean } & SignOutRequest = {},
): Promise<{ alreadyGone: boolean }> {
  const result = await command<{ cancelled?: boolean; alreadyGone?: boolean } | null>(
    'cancel_pending_change',
    signingOut ? { id, signingOut: true } : { id },
  );
  clearHeldDeletion();
  if (reread) void refreshHeldDeletion();
  return { alreadyGone: result?.alreadyGone === true };
}

/** A failed cancel, in words. */
export function cancelErrorText(e: unknown): string {
  const err = toIpcError(e);
  return err.code === 'unknown'
    ? "Couldn't cancel the deletion. Please try again."
    : errorCopy(err).message;
}
