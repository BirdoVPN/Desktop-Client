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
 * Where the hold came from decides what signing out does to it (birdo-web
 * #883, `heldDeletionVoided`): the server drops a hold when the session that
 * filed it is gone, and never one filed without a session (the website) or
 * by another device's session. So `filedHere` is set only by THIS session's
 * 202, and a list read keeps it only while the id is the same. Everything
 * else is "not known to be filed here".
 *
 * In memory only, never persisted: nothing ever concludes from it that the
 * account was deleted.
 */
import { useSyncExternalStore } from 'react';

/** A held account deletion: the id to cancel it by, and when it applies. */
export interface HeldDeletion {
  id: string;
  applyAfter: string;
  /** This app session's own 202 filed it: signing out of this app voids it. */
  filedHere: boolean;
}

let held: HeldDeletion | null = null;
// Bumped by every write and by every read that starts.
let version = 0;
// Bumped by every clear (a cancel, the end of a session). A note made for an
// earlier generation is dropped: a 202 that arrives after the session ended
// must not put the old account's hold back for the next one.
let generation = 0;
const listeners = new Set<() => void>();

function publish(next: HeldDeletion | null) {
  if (held?.id === next?.id && held?.applyAfter === next?.applyAfter && held?.filedHere === next?.filedHere) {
    return;
  }
  held = next;
  listeners.forEach((listener) => listener());
}

/** `filedHere` survives only while it is the same hold. */
function filedHereStill(id: string): boolean {
  return held?.id === id && held.filedHere;
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

/** Take it before sending a hold request; pass it to `noteHeldDeletion`. */
export function heldDeletionGeneration(): number {
  return generation;
}

/**
 * The server named the hold: it is known from now. `filedHere` only for this
 * session's 202; a 409 for a hold already waiting may name one filed on the
 * website or another device (it stays `filedHere` if it is the same hold this
 * session filed). `generation` is `heldDeletionGeneration()` from before the
 * request: if anything was cleared since (the session ended), the answer
 * belongs to what was cleared and is dropped.
 */
export function noteHeldDeletion(
  hold: Pick<HeldDeletion, 'id' | 'applyAfter'>,
  { filedHere, generation: asOf }: { filedHere: boolean; generation: number },
): void {
  if (asOf !== generation) return;
  version += 1;
  publish({ id: hold.id, applyAfter: hold.applyAfter, filedHere: filedHere || filedHereStill(hold.id) });
}

/** Cancelled, gone already, or the session ended: nothing is held. */
export function clearHeldDeletion(): void {
  generation += 1;
  version += 1;
  publish(null);
}

/** A list read starts; pass the token to `finishHeldDeletionRead`. */
export function startHeldDeletionRead(): number {
  version += 1;
  return version;
}

/**
 * The read's answer, dropped if anything was written or read since it
 * started. Returns whether it was applied: a dropped answer says nothing
 * about now (a newer read may still be out).
 */
export function finishHeldDeletionRead(token: number, items: unknown): boolean {
  if (token !== version) return false;
  const listed = heldDeletionOf(items);
  publish(listed && { ...listed, filedHere: filedHereStill(listed.id) });
  return true;
}

/**
 * The account's held deletion in what `list_pending_changes` returned, if any.
 * The list does not say which session filed it: never `filedHere` by itself.
 */
export function heldDeletionOf(items: unknown): HeldDeletion | null {
  if (!Array.isArray(items)) return null;
  for (const item of items) {
    if (typeof item !== 'object' || item === null) continue;
    const row = item as Record<string, unknown>;
    if (row.action !== 'account_delete') continue;
    if (typeof row.id !== 'string' || !row.id) continue;
    if (typeof row.applyAfter !== 'string' || !row.applyAfter) continue;
    return { id: row.id, applyAfter: row.applyAfter, filedHere: false };
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

/** What ends a hold this app session filed, besides Cancel. */
export const SIGN_OUT_CANCELS_HOLD = 'Signing out of this app, or signing out everywhere, also cancels it.';

/** A hold not known to be filed here: this app's sign-out leaves it in place. */
export const SIGN_OUT_KEEPS_HOLD =
  'Signing out of this app does not cancel a deletion asked for on the website or another device.';

/** The sentence about signing out that fits where the hold came from. */
export function signOutHoldNote(hold: Pick<HeldDeletion, 'filedHere'>): string {
  return hold.filedHere ? SIGN_OUT_CANCELS_HOLD : SIGN_OUT_KEEPS_HOLD;
}

/**
 * The sign-out confirmations (Profile and Home) while a hold is known. The
 * server voids a hold when the app session that filed it signs out (or on a
 * sign-out everywhere); a hold filed on the website or by another device
 * stays, whatever this app does. Nothing absolute ("will NOT be deleted"):
 * the server's sign-out is best effort, so for a hold filed here the app
 * cancels it itself before signing out, and says so if that fails.
 */
export function signOutWithHoldText(hold: HeldDeletion): string {
  const waiting = `Your account is waiting to be deleted ${holdWhen(hold.applyAfter)}.`;
  return hold.filedHere
    ? `${waiting} Signing out of this app cancels that deletion. To delete it, stay signed in until then.`
    : `${waiting} ${SIGN_OUT_KEEPS_HOLD} To keep your account, cancel the deletion.`;
}

/**
 * The sign-out confirmation when the list could not be read and no hold is
 * known. A failed read usually means offline, when the server's sign-out
 * fails too: nothing is promised about what signing out does.
 */
export const HOLD_UNCHECKED_CAUTION =
  "We couldn't check whether a deletion is waiting. If you asked for one, signing out may not cancel it. " +
  'To keep your account, cancel the deletion in Profile or on the website.';

/** Signing out cancels a hold filed here first; that cancel failed. */
export function signOutCancelFailedText(reason: string, hold: Pick<HeldDeletion, 'applyAfter'>): string {
  return (
    `${reason} The deletion is still scheduled ${holdWhen(hold.applyAfter)}. Retry, or sign out ` +
    'anyway: the deletion may then still go ahead.'
  );
}

/** The number-replacement dialog while a hold is known. */
export function rotationWithHoldText(applyAfter: string): string {
  return (
    `Your account is waiting to be deleted ${holdWhen(applyAfter)}. Replacing the account number ` +
    'cancels that deletion.'
  );
}
