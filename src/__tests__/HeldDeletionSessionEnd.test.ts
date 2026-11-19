/**
 * MR-2335: ending a session clears the held deletion, through the REAL
 * session module (`DeletionHold.test.tsx` mocks it, so it cannot see this).
 * The next account to sign in on this machine must not inherit the previous
 * one's hold, nor its warnings.
 *
 * Run: npx vitest run src/__tests__/HeldDeletionSessionEnd.test.ts
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { invoke } from '@tauri-apps/api/core';
import {
  clearHeldDeletion,
  getHeldDeletion,
  heldDeletionGeneration,
  noteHeldDeletion,
} from '@/lib/held-deletion';
import { endDeletedSession, endSession, expireSession, signOut } from '@/session/session';
import { useAppStore } from '@/store/app-store';

vi.mock('@tauri-apps/api/core');

const HOLD = { id: 'cmhold0000000000000000001', applyAfter: '2026-11-16T12:00:00.000Z' };

/** Signed in, with a deletion this session filed on hold. */
function signedInWithAHold() {
  useAppStore.getState().logout();
  useAppStore.setState({ isAuthenticated: true });
  clearHeldDeletion();
  noteHeldDeletion(HOLD, { filedHere: true, generation: heldDeletionGeneration() });
  expect(getHeldDeletion()).toEqual({ ...HOLD, filedHere: true });
}

beforeEach(() => {
  vi.mocked(invoke).mockReset();
  vi.mocked(invoke).mockResolvedValue(undefined);
});

describe('ending a session clears the held deletion', () => {
  it('signing out', async () => {
    signedInWithAHold();
    await signOut();
    expect(vi.mocked(invoke)).toHaveBeenCalledWith('logout');
    expect(useAppStore.getState().isAuthenticated).toBe(false);
    expect(getHeldDeletion()).toBeNull();
  });

  it("signing out while Rust's logout fails (it is best effort): cleared all the same", async () => {
    signedInWithAHold();
    vi.mocked(invoke).mockRejectedValue(new Error('offline'));
    await signOut();
    expect(useAppStore.getState().isAuthenticated).toBe(false);
    expect(getHeldDeletion()).toBeNull();
  });

  it('a session Rust ended (endSession)', () => {
    signedInWithAHold();
    endSession('revoked');
    expect(useAppStore.getState().isAuthenticated).toBe(false);
    expect(getHeldDeletion()).toBeNull();
  });

  it('a session that expired (expireSession)', () => {
    signedInWithAHold();
    expireSession();
    expect(vi.mocked(invoke)).toHaveBeenCalledWith('end_expired_session');
    expect(getHeldDeletion()).toBeNull();
  });

  it("a late answer for the ended session is not let back in", () => {
    signedInWithAHold();
    const before = heldDeletionGeneration();
    endSession('expired');
    noteHeldDeletion(HOLD, { filedHere: true, generation: before });
    expect(getHeldDeletion()).toBeNull();
  });

  it('an account a retried deletion found already deleted (endDeletedSession, MR-2483)', () => {
    signedInWithAHold();
    endDeletedSession();
    expect(useAppStore.getState().isAuthenticated).toBe(false);
    expect(useAppStore.getState().sessionEndedReason).toBe('deleted');
    expect(getHeldDeletion()).toBeNull();
    // Rust already signed out: no second command.
    expect(vi.mocked(invoke)).not.toHaveBeenCalled();
  });
});

/**
 * MR-2483: the refresh that found the session gone with the account may also
 * have sent `session-expired`, before or after the deletion's own answer.
 * Login says "deleted" either way, never "your session expired".
 */
describe('an already-deleted account wins over session-expired, in either order', () => {
  it('session-expired first', () => {
    signedInWithAHold();
    endSession('expired');
    endDeletedSession();
    expect(useAppStore.getState().isAuthenticated).toBe(false);
    expect(useAppStore.getState().sessionEndedReason).toBe('deleted');
  });

  it('session-expired after', () => {
    signedInWithAHold();
    endDeletedSession();
    endSession('expired');
    expect(useAppStore.getState().isAuthenticated).toBe(false);
    expect(useAppStore.getState().sessionEndedReason).toBe('deleted');
  });
});
