/**
 * MR-2335: the account's deletion on its 24-hour hold, as ONE shared state.
 *
 * Every surface that must know about it reads this: the Profile banner, the
 * Profile and the Home sign-out confirmations, the number-replacement dialog.
 * It used to be local to Profile, so a user who filed a hold there and signed
 * out from Home cancelled the deletion without being told.
 *
 * Three writers, ordered by one counter so a slow one can never undo a newer
 * fact:
 *  - `noteHeldDeletion`: the server just named the hold (the 202, or the 409
 *    for one already waiting). Known at once: the warnings do not wait for, or
 *    depend on, a list read that may be slow or fail.
 *  - `clearHeldDeletion`: it was cancelled (200), was gone already (404), or
 *    the session ended.
 *  - a list read (`startHeldDeletionRead` / `finishHeldDeletionRead`): the
 *    server's answer replaces what is known, unless anything was written
 *    after the read STARTED. A read that fails changes nothing.
 *
 * In memory only, never persisted: nothing ever concludes from it that the
 * account was deleted.
 */
import { useSyncExternalStore } from 'react';

/** A held account deletion: the id to cancel it by, and when it applies. */
export interface HeldDeletion {
  id: string;
  applyAfter: string;
}

let held: HeldDeletion | null = null;
// Bumped by every write and by every read that starts.
let version = 0;
const listeners = new Set<() => void>();

function publish(next: HeldDeletion | null) {
  if (held?.id === next?.id && held?.applyAfter === next?.applyAfter) return;
  held = next;
  listeners.forEach((listener) => listener());
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function getHeldDeletion(): HeldDeletion | null {
  return held;
}

/** The held deletion, re-rendering whoever reads it when it changes. */
export function useHeldDeletion(): HeldDeletion | null {
  return useSyncExternalStore(subscribe, getHeldDeletion, getHeldDeletion);
}

/** The server named the hold (202 / 409): it is known from now. */
export function noteHeldDeletion(hold: HeldDeletion): void {
  version += 1;
  publish(hold);
}

/** Cancelled, gone already, or the session ended: nothing is held. */
export function clearHeldDeletion(): void {
  version += 1;
  publish(null);
}

/** A list read starts; pass the token to `finishHeldDeletionRead`. */
export function startHeldDeletionRead(): number {
  version += 1;
  return version;
}

/** The read's answer, dropped if anything was written or read since it started. */
export function finishHeldDeletionRead(token: number, items: unknown): void {
  if (token === version) publish(heldDeletionOf(items));
}

/** The account's held deletion in what `list_pending_changes` returned, if any. */
export function heldDeletionOf(items: unknown): HeldDeletion | null {
  if (!Array.isArray(items)) return null;
  for (const item of items) {
    if (typeof item !== 'object' || item === null) continue;
    const row = item as Record<string, unknown>;
    if (row.action !== 'account_delete') continue;
    if (typeof row.id !== 'string' || !row.id) continue;
    if (typeof row.applyAfter !== 'string' || !row.applyAfter) continue;
    return { id: row.id, applyAfter: row.applyAfter };
  }
  return null;
}

/** `applyAfter` in the viewer's local time, or null if it is not a date. */
export function holdTimeText(applyAfter: string): string | null {
  const at = new Date(applyAfter);
  return Number.isNaN(at.getTime()) ? null : at.toLocaleString();
}

/** "on <local time>", or "within 24 hours" when the time cannot be read. */
export function holdWhen(applyAfter: string): string {
  const at = holdTimeText(applyAfter);
  return at ? `on ${at}` : 'within 24 hours';
}

/** What ends a hold besides Cancel: said wherever a hold is shown. */
export const SIGN_OUT_CANCELS_HOLD = 'Signing out of this app, or signing out everywhere, also cancels it.';

/**
 * The sign-out confirmations (Profile and Home) while a hold is known. The
 * server cancels a hold when the app session that asked for it signs out, or
 * on a sign-out everywhere.
 */
export function signOutWithHoldText(applyAfter: string): string {
  return (
    `Your account is waiting to be deleted ${holdWhen(applyAfter)}. Signing out cancels that ` +
    'deletion, so your account will NOT be deleted. To delete it, stay signed in until then.'
  );
}

/** The number-replacement dialog while a hold is known. */
export function rotationWithHoldText(applyAfter: string): string {
  return (
    `Your account is waiting to be deleted ${holdWhen(applyAfter)}. Replacing the account number ` +
    'cancels that deletion, so your account will NOT be deleted.'
  );
}
