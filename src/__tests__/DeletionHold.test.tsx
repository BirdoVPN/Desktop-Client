/**
 * MR-2335 (MR-179 hold fallback, birdo-web #883): "Delete in 24 hours".
 *
 * - The dialog offers the hold only when the preflight says
 *   `stepUpHoldAvailable === true`, and only to an account with a factor the
 *   hold stands in for (the number, the e-mailed code).
 * - The hold sends the password (and the 2FA code once asked), never the
 *   number or the code, through `request_deletion_hold`, not `delete_account`.
 * - Its answer is a PENDING deletion: the dialog shows when it applies and a
 *   Cancel button. Nobody is signed out, nothing is disconnected.
 * - Profile shows a banner while an `account_delete` hold is listed, with
 *   Cancel; the list is read on open and on window focus, and a hold that is
 *   gone is simply not shown.
 * - Signing out of this app voids only a hold THIS session filed (its 202);
 *   one listed, or named by a 409, may come from the website or another
 *   device and stays (birdo-web #883). The dialog, the banner and both
 *   sign-out confirmations say which, and both confirmations offer Cancel
 *   deletion.
 * - Nothing ever concludes "account deleted": an ended session takes the
 *   ordinary session-expired path, and an unexpected answer assumes nothing.
 * - The hold is ONE shared state (`@/lib/held-deletion`): the Home sign-out
 *   dialog and the number-replacement dialog warn too, the hold the 202 named
 *   is known without a list read, a cancel clears it at once, and a slow old
 *   read can never put it back.
 *
 * Run: npx vitest run src/__tests__/DeletionHold.test.tsx
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { invoke } from '@tauri-apps/api/core';
import { HOLD_OFFER_CODE, HOLD_OFFER_NUMBER, Profile } from '@/screens/Profile';
import { HOLD_UNEXPECTED } from '@/screens/profile/DeleteAccountDialog';
import { ReplaceAccountNumberDialog, type RotationStep } from '@/screens/profile/ReplaceAccountNumberDialog';
import { SignOutDialog } from '@/components/home/SignOutDialog';
import {
  clearHeldDeletion,
  getHeldDeletion,
  heldDeletionGeneration,
  heldDeletionOf,
  HOLD_UNCHECKED_CAUTION,
  holdTimeText,
  noteHeldDeletion,
  rotationWithHoldText,
  SIGN_OUT_CANCELS_HOLD,
  SIGN_OUT_KEEPS_HOLD,
  signOutWithHoldText,
} from '@/lib/held-deletion';
import { HOLD_READ_WAIT_MS, refreshHeldDeletion } from '@/session/held-deletion';
import { expireSession, signOut } from '@/session/session';
import type { ConnectionState } from '@/store/app-store';

vi.mock('@tauri-apps/api/core');
vi.mock('@tauri-apps/plugin-opener', () => ({ openUrl: vi.fn().mockResolvedValue(undefined) }));
// The two ways a session ends, as spies: the tests assert WHICH one ran.
vi.mock('@/session/session', () => ({ signOut: vi.fn(), expireSession: vi.fn(), endSession: vi.fn() }));

function stripMotion(props: Record<string, unknown>) {
  const {
    initial: _i,
    animate: _a,
    exit: _e,
    transition: _t,
    whileHover: _h,
    whileTap: _p,
    ...rest
  } = props;
  return rest;
}
vi.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: React.PropsWithChildren<Record<string, unknown>>) => (
      <div {...(stripMotion(props) as React.HTMLAttributes<HTMLDivElement>)}>{children}</div>
    ),
    button: ({ children, ...props }: React.PropsWithChildren<Record<string, unknown>>) => (
      <button {...(stripMotion(props) as React.ButtonHTMLAttributes<HTMLButtonElement>)}>
        {children}
      </button>
    ),
  },
  AnimatePresence: ({ children }: React.PropsWithChildren) => <>{children}</>,
}));

const logout = vi.fn();
const setConnectionState = vi.fn();
const setCurrentServer = vi.fn();
const mockStoreState = {
  connectionState: 'connected' as ConnectionState,
  account: {
    email: null,
    plan: 'OPERATIVE',
    accountId: 'acct',
    maxDevices: 5,
    activeDevices: 1,
    expiresAt: null,
    bandwidthUsed: 0,
    bandwidthLimit: 0,
    status: 'active',
    hasPassword: false,
  },
  userEmail: null,
  setAccount: vi.fn(),
  logout,
  setAuthenticated: vi.fn(),
  pushRoute: vi.fn(),
  setConnectionState,
  setCurrentServer,
  setVpnIp: vi.fn(),
};
vi.mock('@/store/app-store', () => {
  const useAppStore = vi.fn((selector) => selector(mockStoreState));
  (useAppStore as unknown as { getState: () => typeof mockStoreState }).getState = () =>
    mockStoreState;
  return { useAppStore };
});
vi.mock('zustand/react/shallow', () => ({ useShallow: (fn: unknown) => fn }));

const mockedInvoke = vi.mocked(invoke);
const calls = (cmd: string) => mockedInvoke.mock.calls.filter(([c]) => c === cmd);

const APPLY_AFTER = '2026-11-15T12:00:00.000Z';
const HOLD_ID = 'cmhold0000000000000000001';
const HELD = { pendingChangeId: HOLD_ID, applyAfter: APPLY_AFTER, message: null, alreadyPending: false };
/** The sign-out warnings while that hold is known (Profile and Home alike), by origin. */
const SIGN_OUT_FILED_HERE = signOutWithHoldText({ id: HOLD_ID, applyAfter: APPLY_AFTER, filedHere: true });
const SIGN_OUT_FILED_ELSEWHERE = signOutWithHoldText({ id: HOLD_ID, applyAfter: APPLY_AFTER, filedHere: false });

// The number replacement: fake numbers only.
const CURRENT_NUMBER = '111122223333444455556666';
const NEW_NUMBER = '777788889999000011112222';
const rotationStep = (fields: Partial<RotationStep>): RotationStep => ({
  refusal: null,
  newNumber: null,
  expiresInSeconds: null,
  retryAfterSecs: null,
  ...fields,
});

let preflightResult: () => Promise<unknown>;
let holdResult: () => Promise<unknown>;
let listResult: () => Promise<unknown>;
let cancelResult: () => Promise<unknown>;
// The number replacement (MR-1707): step 1 and step 2.
let prepareResult: () => Promise<unknown>;
let rotateResult: () => Promise<unknown>;

const preflight = (stepUpFactors: string[], stepUpHoldAvailable: unknown, stepUpEnforced = true) => () =>
  Promise.resolve({
    storeSubscriptionsStillBilling: [],
    webSubscriptionWillBeCancelled: false,
    stepUpFactors,
    stepUpEnforced,
    stepUpHoldAvailable,
  });

const refusal = (code: string, message = 'x') => ({ code, message, retryable: false, retry_after_secs: null });

beforeEach(() => {
  clearHeldDeletion();
  mockedInvoke.mockReset();
  vi.mocked(signOut).mockReset();
  vi.mocked(expireSession).mockReset();
  logout.mockReset();
  setConnectionState.mockReset();
  setCurrentServer.mockReset();
  mockStoreState.account.hasPassword = false;
  preflightResult = preflight(['account_number'], true);
  holdResult = () => Promise.resolve(HELD);
  listResult = () => Promise.resolve([]);
  cancelResult = () => Promise.resolve({ cancelled: true, alreadyGone: false });
  prepareResult = () => Promise.resolve(rotationStep({ newNumber: NEW_NUMBER }));
  rotateResult = () => Promise.resolve(rotationStep({}));
  mockedInvoke.mockImplementation((cmd: string) => {
    if (cmd === 'deletion_preflight') return preflightResult();
    if (cmd === 'request_deletion_hold') return holdResult();
    if (cmd === 'list_pending_changes') return listResult();
    if (cmd === 'cancel_pending_change') return cancelResult();
    if (cmd === 'rotate_anonymous_number_prepare') return prepareResult();
    if (cmd === 'rotate_anonymous_number_confirm') return rotateResult();
    if (cmd === 'delete_account') return Promise.reject(new Error('delete_account must not be called'));
    return Promise.resolve(undefined);
  });
});

async function openDialog() {
  render(<Profile />);
  await userEvent.click(screen.getByRole('button', { name: /delete account/i }));
}

/** Nothing that ends a session happened. */
function nobodySignedOut() {
  expect(calls('delete_account')).toHaveLength(0);
  expect(calls('logout')).toHaveLength(0);
  expect(logout).not.toHaveBeenCalled();
  expect(signOut).not.toHaveBeenCalled();
  expect(setConnectionState).not.toHaveBeenCalled();
  expect(setCurrentServer).not.toHaveBeenCalled();
}

describe('the hold offer', () => {
  it('is shown for an anonymous account when holdAvailable is true', async () => {
    await openDialog();
    expect(await screen.findByRole('button', { name: HOLD_OFFER_NUMBER })).toBeInTheDocument();
  });

  it('is shown whether or not the step-up is enforced (its own switch)', async () => {
    preflightResult = preflight(['account_number'], true, false);
    await openDialog();
    expect(await screen.findByRole('button', { name: HOLD_OFFER_NUMBER })).toBeInTheDocument();
  });

  it('names the e-mailed code for an SSO account', async () => {
    preflightResult = preflight(['email_code'], true);
    await openDialog();
    expect(await screen.findByRole('button', { name: HOLD_OFFER_CODE })).toBeInTheDocument();
  });

  it.each([false, 'true', 1, null, undefined])('is NOT shown when holdAvailable is %s', async (value) => {
    preflightResult = preflight(['account_number'], value);
    await openDialog();
    await screen.findByLabelText('Account number');
    expect(screen.queryByRole('button', { name: /delete in 24 hours/i })).not.toBeInTheDocument();
  });

  it('is NOT shown to a password-only account, nor when the preflight failed', async () => {
    mockStoreState.account.hasPassword = true;
    preflightResult = preflight(['password', 'two_factor'], true);
    await openDialog();
    await waitFor(() => expect(calls('deletion_preflight')).toHaveLength(1));
    expect(screen.queryByRole('button', { name: /delete in 24 hours/i })).not.toBeInTheDocument();
  });
});

describe('asking for the hold', () => {
  it('sends the confirmation (never the number) through request_deletion_hold, and shows the pending state', async () => {
    await openDialog();
    await userEvent.click(await screen.findByRole('button', { name: HOLD_OFFER_NUMBER }));
    // The number field is gone: the hold stands in for it.
    expect(screen.queryByLabelText('Account number')).not.toBeInTheDocument();
    expect(screen.getByText(/24 hours from now unless you cancel it first/)).toBeInTheDocument();
    // Before asking: signing out (here or everywhere) cancels it.
    expect(screen.getByText(new RegExp(SIGN_OUT_CANCELS_HOLD))).toBeInTheDocument();
    const submit = screen.getByRole('button', { name: 'Delete in 24 hours' });
    expect(submit).toBeDisabled();
    await userEvent.type(screen.getByPlaceholderText('DELETE'), 'DELETE');
    await userEvent.click(submit);

    expect(await screen.findByText(`Your account will be deleted on ${holdTimeText(APPLY_AFTER)}.`)).toBeInTheDocument();
    expect(calls('request_deletion_hold')[0][1]).toStrictEqual({ request: { password: 'DELETE' } });
    expect(screen.getByRole('button', { name: 'Cancel deletion' })).toBeInTheDocument();
    // And once it is pending.
    expect(screen.getByText(new RegExp(SIGN_OUT_CANCELS_HOLD))).toBeInTheDocument();
    // A 202 is not a deletion: nobody is signed out, nothing disconnected.
    nobodySignedOut();
    // The Profile banner reads the list again.
    expect(calls('list_pending_changes').length).toBeGreaterThanOrEqual(2);
  });

  it('a password account with 2FA sends the password and, once asked, the code', async () => {
    mockStoreState.account.hasPassword = true;
    preflightResult = preflight(['password', 'account_number', 'two_factor'], true);
    const answers = [() => Promise.reject(refusal('two_factor_required')), () => Promise.resolve(HELD)];
    holdResult = () => answers.shift()!();
    await openDialog();
    await userEvent.click(await screen.findByRole('button', { name: HOLD_OFFER_NUMBER }));
    await userEvent.type(screen.getByPlaceholderText('••••••••'), 'hunter2');
    await userEvent.click(screen.getByRole('button', { name: 'Delete in 24 hours' }));
    await userEvent.type(await screen.findByLabelText('Two-factor code'), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Delete in 24 hours' }));
    await screen.findByRole('button', { name: 'Cancel deletion' });
    expect(calls('request_deletion_hold')[1][1]).toStrictEqual({
      request: { password: 'hunter2', two_factor_code: '123456' },
    });
    nobodySignedOut();
  });

  it('a hold already waiting (409 change_already_pending) is shown with Cancel', async () => {
    holdResult = () => Promise.resolve({ ...HELD, alreadyPending: true, message: 'A deletion is already on hold.' });
    await openDialog();
    await userEvent.click(await screen.findByRole('button', { name: HOLD_OFFER_NUMBER }));
    await userEvent.type(screen.getByPlaceholderText('DELETE'), 'DELETE');
    await userEvent.click(screen.getByRole('button', { name: 'Delete in 24 hours' }));
    expect(await screen.findByText(/already waiting; nothing new was filed/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Cancel deletion' })).toBeInTheDocument();
    // H1: it may have been asked for on the website or another device, so
    // this app's sign-out is NOT said to cancel it.
    expect(screen.getByText(new RegExp(SIGN_OUT_KEEPS_HOLD))).toBeInTheDocument();
    expect(screen.queryByText(new RegExp(SIGN_OUT_CANCELS_HOLD))).not.toBeInTheDocument();
    expect(getHeldDeletion()).toBeNull(); // the follow-up read listed nothing
    nobodySignedOut();
  });

  it('the 202 marks the hold "filed here"; a later 409 for the same hold keeps it, another hold does not', async () => {
    listResult = () => new Promise(() => {}); // no list read answers
    await openDialog();
    await userEvent.click(await screen.findByRole('button', { name: HOLD_OFFER_NUMBER }));
    await userEvent.type(screen.getByPlaceholderText('DELETE'), 'DELETE');
    await userEvent.click(screen.getByRole('button', { name: 'Delete in 24 hours' }));
    await screen.findByRole('button', { name: 'Close' });
    expect(getHeldDeletion()).toEqual({ id: HOLD_ID, applyAfter: APPLY_AFTER, filedHere: true });
    // The dialog's notice and the Profile banner behind it.
    expect(screen.getAllByText(new RegExp(SIGN_OUT_CANCELS_HOLD))).toHaveLength(2);
    expect(screen.queryByText(new RegExp(SIGN_OUT_KEEPS_HOLD))).not.toBeInTheDocument();
    // What the dialog notes for a 409 (`filedHere: false`).
    act(() => noteHeldDeletion({ id: HOLD_ID, applyAfter: APPLY_AFTER }, { filedHere: false, generation: heldDeletionGeneration() }));
    expect(getHeldDeletion()?.filedHere).toBe(true);
    act(() => noteHeldDeletion({ id: 'cmother', applyAfter: APPLY_AFTER }, { filedHere: false, generation: heldDeletionGeneration() }));
    expect(getHeldDeletion()?.filedHere).toBe(false);
  });

  it('Cancel cancels the hold by its id and says the account stays', async () => {
    await openDialog();
    await userEvent.click(await screen.findByRole('button', { name: HOLD_OFFER_NUMBER }));
    await userEvent.type(screen.getByPlaceholderText('DELETE'), 'DELETE');
    await userEvent.click(screen.getByRole('button', { name: 'Delete in 24 hours' }));
    await userEvent.click(await screen.findByRole('button', { name: 'Cancel deletion' }));
    expect(await screen.findByText(/The deletion is cancelled/)).toBeInTheDocument();
    expect(calls('cancel_pending_change')[0][1]).toStrictEqual({ id: HOLD_ID });
    nobodySignedOut();
  });

  it('a hold that was gone already (404) says so instead of failing', async () => {
    cancelResult = () => Promise.resolve({ cancelled: false, alreadyGone: true });
    await openDialog();
    await userEvent.click(await screen.findByRole('button', { name: HOLD_OFFER_NUMBER }));
    await userEvent.type(screen.getByPlaceholderText('DELETE'), 'DELETE');
    await userEvent.click(screen.getByRole('button', { name: 'Delete in 24 hours' }));
    await userEvent.click(await screen.findByRole('button', { name: 'Cancel deletion' }));
    expect(await screen.findByText(/no longer waiting/)).toBeInTheDocument();
  });

  it.each([
    [refusal('hold_unavailable', 'A delayed deletion is not available. Nothing was deleted.'), 'A delayed deletion is not available. Nothing was deleted.'],
    [
      refusal('rate_limited', 'You have asked for a delayed deletion too many times today. Please try again tomorrow.'),
      'You have asked for a delayed deletion too many times today. Please try again tomorrow.',
    ],
    [refusal('step_up_unavailable'), "We couldn't check this request just now. Nothing was deleted. Please try again in a minute."],
    // An unreadable 202 or any other 2xx (Rust: server_error): nothing is assumed.
    [refusal('server_error', 'Nothing is assumed deleted.'), HOLD_UNEXPECTED],
    [refusal('invalid_credentials', 'Incorrect password'), 'Incorrect password. Please try again.'],
  ])('a refused hold (%o) shows why and signs nobody out', async (rejection, shown) => {
    holdResult = () => Promise.reject(rejection);
    await openDialog();
    await userEvent.click(await screen.findByRole('button', { name: HOLD_OFFER_NUMBER }));
    await userEvent.type(screen.getByPlaceholderText('DELETE'), 'DELETE');
    await userEvent.click(screen.getByRole('button', { name: 'Delete in 24 hours' }));
    expect(await screen.findByText(shown)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Cancel deletion' })).not.toBeInTheDocument();
    nobodySignedOut();
  });

  it('an answer without a usable hold is an error, never a pending state', async () => {
    holdResult = () => Promise.resolve({ pendingChangeId: '', applyAfter: APPLY_AFTER });
    await openDialog();
    await userEvent.click(await screen.findByRole('button', { name: HOLD_OFFER_NUMBER }));
    await userEvent.type(screen.getByPlaceholderText('DELETE'), 'DELETE');
    await userEvent.click(screen.getByRole('button', { name: 'Delete in 24 hours' }));
    expect(await screen.findByText(HOLD_UNEXPECTED)).toBeInTheDocument();
    expect(HOLD_UNEXPECTED).toMatch(/nothing is assumed/);
    expect(HOLD_UNEXPECTED).toMatch(/was not deleted/);
    expect(screen.queryByRole('button', { name: 'Cancel deletion' })).not.toBeInTheDocument();
    nobodySignedOut();
  });

  it('a hold request that meets an ended session takes the session-expired path, not "deleted"', async () => {
    holdResult = () => Promise.reject(refusal('session_expired', 'Your session has expired. Sign in again.'));
    await openDialog();
    await userEvent.click(await screen.findByRole('button', { name: HOLD_OFFER_NUMBER }));
    await userEvent.type(screen.getByPlaceholderText('DELETE'), 'DELETE');
    await userEvent.click(screen.getByRole('button', { name: 'Delete in 24 hours' }));
    await waitFor(() => expect(expireSession).toHaveBeenCalledTimes(1));
    expect(screen.queryByText(/has been deleted/i)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Cancel deletion' })).not.toBeInTheDocument();
    nobodySignedOut();
  });

  it('Back returns to the immediate deletion with the number field', async () => {
    await openDialog();
    await userEvent.click(await screen.findByRole('button', { name: HOLD_OFFER_NUMBER }));
    await userEvent.click(screen.getByRole('button', { name: 'Back' }));
    expect(screen.getByLabelText('Account number')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /delete my account/i })).toBeInTheDocument();
  });
});

describe('signing out while a deletion is on hold', () => {
  const listed = [{ id: HOLD_ID, action: 'account_delete', applyAfter: APPLY_AFTER }];

  it('a listed hold (origin unknown): asks first, says signing out may not cancel it; Stay keeps both', async () => {
    listResult = () => Promise.resolve(listed);
    render(<Profile />);
    await screen.findByRole('button', { name: 'Cancel deletion' });
    await userEvent.click(screen.getByRole('button', { name: /^sign out/i }));
    const dialog = await screen.findByRole('dialog', { name: 'Sign out?' });
    expect(within(dialog).getByRole('alert')).toHaveTextContent(SIGN_OUT_FILED_ELSEWHERE);
    expect(SIGN_OUT_FILED_ELSEWHERE).toContain(`on ${holdTimeText(APPLY_AFTER)}`);
    // The common wording (iOS #624, Android #623): nothing about where it came from.
    expect(SIGN_OUT_FILED_ELSEWHERE).toBe(
      `Your account will be deleted on ${holdTimeText(APPLY_AFTER)}. ` +
        'Signing out of this app may not cancel this deletion. To keep your account, cancel the deletion.',
    );
    expect(SIGN_OUT_FILED_ELSEWHERE).not.toMatch(/website|another device|Signing out cancels/);
    expect(within(dialog).getByRole('button', { name: 'Cancel deletion' })).toBeInTheDocument();
    expect(signOut).not.toHaveBeenCalled();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Stay signed in' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(signOut).not.toHaveBeenCalled();
    expect(calls('cancel_pending_change')).toHaveLength(0);
  });

  it('confirming signs out the ordinary way; a hold not filed here is not cancelled by the app', async () => {
    listResult = () => Promise.resolve(listed);
    render(<Profile />);
    await screen.findByRole('button', { name: 'Cancel deletion' });
    await userEvent.click(screen.getByRole('button', { name: /^sign out/i }));
    const dialog = await screen.findByRole('dialog', { name: 'Sign out?' });
    await waitFor(() => expect(within(dialog).getByRole('button', { name: 'Sign out' })).toBeEnabled());
    await userEvent.click(within(dialog).getByRole('button', { name: 'Sign out' }));
    expect(signOut).toHaveBeenCalledTimes(1);
    expect(calls('cancel_pending_change')).toHaveLength(0);
    expect(calls('delete_account')).toHaveLength(0);
  });

  it('Cancel deletion in the sign-out confirmation cancels the hold and keeps the user signed in', async () => {
    const answers = [() => Promise.resolve(listed), () => Promise.resolve(listed)];
    listResult = () => (answers.shift() ?? (() => Promise.resolve([])))();
    render(<Profile />);
    await screen.findByRole('button', { name: 'Cancel deletion' });
    await userEvent.click(screen.getByRole('button', { name: /^sign out/i }));
    const dialog = await screen.findByRole('dialog', { name: 'Sign out?' });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel deletion' }));
    expect(await within(dialog).findByText('The deletion is cancelled. Your account stays as it is.')).toBeInTheDocument();
    expect(calls('cancel_pending_change')).toEqual([['cancel_pending_change', { id: HOLD_ID }]]);
    expect(within(dialog).queryByRole('alert')).not.toBeInTheDocument();
    expect(getHeldDeletion()).toBeNull();
    nobodySignedOut();
  });

  it('M2: a click before the opening read answers waits for the read; no hold: signs out, no dialog', async () => {
    const read = deferred<unknown>();
    listResult = () => read.promise;
    render(<Profile />);
    // Clicked at once: Profile's own opening read is still out.
    await userEvent.click(screen.getByRole('button', { name: /^sign out/i }));
    expect(signOut).not.toHaveBeenCalled();
    // The row is disabled while the read is out.
    expect(screen.queryByRole('button', { name: /^sign out/i })).not.toBeInTheDocument();
    await act(async () => {
      read.resolve([]);
    });
    await waitFor(() => expect(signOut).toHaveBeenCalledTimes(1));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('L1: a read that does not answer within 3 s opens the confirmation, which says it could not check', async () => {
    vi.useFakeTimers();
    try {
      listResult = () => new Promise(() => {});
      render(<Profile />);
      fireEvent.click(screen.getByRole('button', { name: /^sign out/i }));
      expect(signOut).not.toHaveBeenCalled();
      await act(async () => {
        vi.advanceTimersByTime(HOLD_READ_WAIT_MS + 100);
      });
      const dialog = screen.getByRole('dialog', { name: 'Sign out?' });
      // The dialog asks once more, for at most as long, then says it could not check.
      await act(async () => {
        vi.advanceTimersByTime(HOLD_READ_WAIT_MS + 100);
      });
      expect(within(dialog).getByText(HOLD_UNCHECKED_CAUTION)).toBeInTheDocument();
      expect(within(dialog).getByRole('button', { name: 'Sign out' })).toBeEnabled();
      expect(signOut).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it('M2: a click before the opening read answers, and the read finds a hold: it asks first', async () => {
    const read = deferred<unknown>();
    listResult = () => read.promise;
    render(<Profile />);
    await userEvent.click(screen.getByRole('button', { name: /^sign out/i }));
    expect(signOut).not.toHaveBeenCalled();
    await act(async () => {
      read.resolve(listed);
    });
    const dialog = await screen.findByRole('dialog', { name: 'Sign out?' });
    expect(within(dialog).getByRole('alert')).toHaveTextContent(SIGN_OUT_FILED_ELSEWHERE);
    expect(signOut).not.toHaveBeenCalled();
  });
});

/** A promise the test settles when it chooses. */
function deferred<V>() {
  let resolve!: (value: V) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<V>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe('the Home sign-out dialog (SignOutDialog, opened from the Connect screen)', () => {
  const listed = [{ id: HOLD_ID, action: 'account_delete', applyAfter: APPLY_AFTER }];

  it('reads the list on opening; a listed hold: the date, "may not cancel", and Cancel deletion', async () => {
    listResult = () => Promise.resolve(listed);
    render(<SignOutDialog open stillConnected={false} onClose={() => {}} />);
    expect(await screen.findByRole('alert')).toHaveTextContent(SIGN_OUT_FILED_ELSEWHERE);
    expect(SIGN_OUT_FILED_ELSEWHERE).toContain(`on ${holdTimeText(APPLY_AFTER)}`);
    expect(screen.getByRole('button', { name: 'Cancel deletion' })).toBeInTheDocument();
    expect(calls('list_pending_changes')).toHaveLength(1);
    expect(signOut).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    expect(signOut).toHaveBeenCalledTimes(1);
    // Not filed here: the app does not cancel it on the way out.
    expect(calls('cancel_pending_change')).toHaveLength(0);
  });

  it('a hold filed in Profile is known here at once, even when the list read fails, and "cancels" is said', async () => {
    // What the dialog does with the 202: straight into the shared state.
    noteHeldDeletion({ id: HOLD_ID, applyAfter: APPLY_AFTER }, { filedHere: true, generation: heldDeletionGeneration() });
    listResult = () => Promise.reject(refusal('network_offline'));
    render(<SignOutDialog open stillConnected onClose={() => {}} />);
    // No waiting on the read: the warning is in the first paint.
    expect(screen.getByRole('alert')).toHaveTextContent(SIGN_OUT_FILED_HERE);
    expect(SIGN_OUT_FILED_HERE).toBe(
      `Signing out cancels the deletion of your account that is scheduled for ${holdTimeText(APPLY_AFTER)}.`,
    );
    // M1: nothing absolute; the server's sign-out is best effort.
    expect(SIGN_OUT_FILED_HERE).not.toMatch(/will NOT be deleted/);
    expect(screen.getByRole('button', { name: 'Cancel deletion' })).toBeInTheDocument();
    await waitFor(() => expect(calls('list_pending_changes')).toHaveLength(1));
    expect(screen.getByRole('alert')).toHaveTextContent(SIGN_OUT_FILED_HERE);
  });

  it('a listed hold keeps "filed here" only while it is the same hold', async () => {
    noteHeldDeletion({ id: HOLD_ID, applyAfter: APPLY_AFTER }, { filedHere: true, generation: heldDeletionGeneration() });
    const answers = [() => Promise.resolve(listed), () => Promise.resolve([{ ...listed[0], id: 'cmother' }])];
    listResult = () => answers.shift()!();
    const { unmount } = render(<SignOutDialog open stillConnected={false} onClose={() => {}} />);
    await waitFor(() => expect(calls('list_pending_changes')).toHaveLength(1));
    expect(getHeldDeletion()).toEqual({ id: HOLD_ID, applyAfter: APPLY_AFTER, filedHere: true });
    expect(screen.getByRole('alert')).toHaveTextContent(SIGN_OUT_FILED_HERE);
    unmount();
    render(<SignOutDialog open stillConnected={false} onClose={() => {}} />);
    await waitFor(() => expect(getHeldDeletion()?.id).toBe('cmother'));
    expect(getHeldDeletion()?.filedHere).toBe(false);
    expect(screen.getByRole('alert')).toHaveTextContent(SIGN_OUT_KEEPS_HOLD);
  });

  it('Sign out waits for the opening read, so the warning cannot be skipped by a fast click', async () => {
    const read = deferred<unknown>();
    listResult = () => read.promise;
    render(<SignOutDialog open stillConnected={false} onClose={() => {}} />);
    const button = screen.getByRole('button', { name: 'Sign out' });
    expect(button).toBeDisabled();
    await act(async () => {
      read.resolve(listed);
    });
    expect(await screen.findByRole('alert')).toHaveTextContent(SIGN_OUT_FILED_ELSEWHERE);
    expect(button).toBeEnabled();
    expect(signOut).not.toHaveBeenCalled();
  });

  it('without a hold (the read answered) it asks only the usual question', async () => {
    render(<SignOutDialog open stillConnected={false} onClose={() => {}} />);
    await waitFor(() => expect(screen.getByRole('button', { name: 'Sign out' })).toBeEnabled());
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.queryByText(HOLD_UNCHECKED_CAUTION)).not.toBeInTheDocument();
    expect(screen.getByText('Are you sure you want to sign out?')).toBeInTheDocument();
    // No deletion text: the plain Cancel stays.
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    expect(signOut).toHaveBeenCalledTimes(1);
  });

  it('L1: a read that fails and no hold known: the generic caution, and signing out is not blocked', async () => {
    listResult = () => Promise.reject(refusal('network_offline'));
    render(<SignOutDialog open stillConnected={false} onClose={() => {}} />);
    await waitFor(() => expect(screen.getByRole('button', { name: 'Sign out' })).toBeEnabled());
    expect(screen.getByRole('note')).toHaveTextContent(
      "We couldn't check whether a deletion is waiting. Signing out may not cancel it. " +
        "To keep your account, stay signed in and cancel it once you're online.",
    );
    // LOW-1: offline, the server sign-out fails too; nothing is promised.
    expect(HOLD_UNCHECKED_CAUTION).not.toMatch(/signing out cancels it/i);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    // Next to text about a deletion, the dismiss button is not a bare "Cancel".
    expect(screen.getByRole('button', { name: 'Stay signed in' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Cancel' })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    expect(signOut).toHaveBeenCalledTimes(1);
  });

  it('L1: a read that does not answer: Sign out waits about 3 s, not 30, then works with the caution', async () => {
    vi.useFakeTimers();
    try {
      listResult = () => new Promise(() => {});
      render(<SignOutDialog open stillConnected={false} onClose={() => {}} />);
      expect(screen.getByRole('button', { name: 'Sign out' })).toBeDisabled();
      await act(async () => {
        vi.advanceTimersByTime(HOLD_READ_WAIT_MS - 100);
      });
      expect(screen.getByRole('button', { name: 'Sign out' })).toBeDisabled();
      expect(screen.queryByText(HOLD_UNCHECKED_CAUTION)).not.toBeInTheDocument();
      await act(async () => {
        vi.advanceTimersByTime(200);
      });
      expect(HOLD_READ_WAIT_MS).toBe(3000);
      expect(screen.getByRole('button', { name: 'Sign out' })).toBeEnabled();
      expect(screen.getByText(HOLD_UNCHECKED_CAUTION)).toBeInTheDocument();
      fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
      expect(signOut).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('signing out with a hold filed here: the app cancels it first (M1)', () => {
  const listed = [{ id: HOLD_ID, action: 'account_delete', applyAfter: APPLY_AFTER }];

  /** A hold this session filed, still listed under the same id. */
  async function openWithHoldFiledHere() {
    noteHeldDeletion({ id: HOLD_ID, applyAfter: APPLY_AFTER }, { filedHere: true, generation: heldDeletionGeneration() });
    listResult = () => Promise.resolve(listed);
    render(<SignOutDialog open stillConnected={false} onClose={() => {}} />);
    await waitFor(() => expect(calls('list_pending_changes')).toHaveLength(1));
    expect(getHeldDeletion()?.filedHere).toBe(true);
  }

  it('confirming cancels the deletion by its id BEFORE signing out', async () => {
    await openWithHoldFiledHere();
    await userEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    await waitFor(() => expect(signOut).toHaveBeenCalledTimes(1));
    // MR-2532: in the Sign Out's mode (once, never refreshed).
    expect(calls('cancel_pending_change')).toEqual([['cancel_pending_change', { id: HOLD_ID, signingOut: true }]]);
    const cancelAt = mockedInvoke.mock.invocationCallOrder[
      mockedInvoke.mock.calls.findIndex(([c]) => c === 'cancel_pending_change')
    ];
    expect(cancelAt).toBeLessThan(vi.mocked(signOut).mock.invocationCallOrder[0]);
    // LOW-3: no list read after the cancel (only the dialog's opening read):
    // one could race the sign-out and end it as "session expired".
    expect(calls('list_pending_changes')).toHaveLength(1);
  });

  it('LOW-3: Cancel deletion WITHOUT signing out still reads the list again', async () => {
    await openWithHoldFiledHere();
    listResult = () => Promise.resolve([]); // the server no longer lists it
    await userEvent.click(screen.getByRole('button', { name: 'Cancel deletion' }));
    expect(await screen.findByText('The deletion is cancelled. Your account stays as it is.')).toBeInTheDocument();
    await waitFor(() => expect(calls('list_pending_changes')).toHaveLength(2));
    expect(signOut).not.toHaveBeenCalled();
  });

  it('a cancel that fails signs nobody out: the deletion is still scheduled; Retry cancels, then signs out', async () => {
    const answers = [
      () => Promise.reject(refusal('network_offline')),
      () => Promise.resolve({ cancelled: true, alreadyGone: false }),
    ];
    cancelResult = () => answers.shift()!();
    await openWithHoldFiledHere();
    await userEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    const failure = await screen.findByText(/The deletion is still scheduled/);
    expect(failure).toHaveTextContent(`still scheduled on ${holdTimeText(APPLY_AFTER)}`);
    expect(failure).toHaveTextContent('Retry, or sign out anyway: the deletion may then still go ahead.');
    expect(signOut).not.toHaveBeenCalled();
    expect(getHeldDeletion()).toEqual({ id: HOLD_ID, applyAfter: APPLY_AFTER, filedHere: true });
    expect(screen.queryByRole('button', { name: 'Sign out' })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
    await waitFor(() => expect(signOut).toHaveBeenCalledTimes(1));
    expect(calls('cancel_pending_change')).toHaveLength(2);
    expect(calls('list_pending_changes')).toHaveLength(1); // LOW-3: no re-read on the way out
  });

  it('Sign out anyway signs out without cancelling again, leaving the deletion as it is', async () => {
    cancelResult = () => Promise.reject(refusal('network_offline'));
    await openWithHoldFiledHere();
    await userEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    await screen.findByText(/The deletion is still scheduled/);
    await userEvent.click(screen.getByRole('button', { name: 'Sign out anyway' }));
    await waitFor(() => expect(signOut).toHaveBeenCalledTimes(1));
    expect(calls('cancel_pending_change')).toHaveLength(1);
  });
});

/**
 * MR-2532, owner decision 2026-11-24 ("never refresh at sign-out"): the Sign
 * Out flow's own requests (the dialog's read, Profile's check before it, the
 * cancel-first) ask Rust for the Sign Out's mode: once with the access token
 * on file, never refreshed on a 401, not sent when it is unusable
 * (`BirdoApi::sign_out_request`). The page's own reads and the dialog's
 * Cancel deletion (the user stays) are ordinary requests.
 */
describe('MR-2532: the Sign Out flow never refreshes', () => {
  const listed = [{ id: HOLD_ID, action: 'account_delete', applyAfter: APPLY_AFTER }];
  // What Rust answers for a Sign Out request it did not send, or that got a 401.
  const notSent = () => Promise.reject(refusal('unknown', 'This could not be checked before signing out.'));

  it("the dialog's read and its cancel-first go in the Sign Out's mode", async () => {
    noteHeldDeletion({ id: HOLD_ID, applyAfter: APPLY_AFTER }, { filedHere: true, generation: heldDeletionGeneration() });
    listResult = () => Promise.resolve(listed);
    render(<SignOutDialog open stillConnected onClose={() => {}} />);
    await waitFor(() => expect(calls('list_pending_changes')).toHaveLength(1));
    expect(calls('list_pending_changes')[0]).toEqual(['list_pending_changes', { signingOut: true }]);
    await userEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    await waitFor(() => expect(signOut).toHaveBeenCalledTimes(1));
    expect(calls('cancel_pending_change')).toEqual([['cancel_pending_change', { id: HOLD_ID, signingOut: true }]]);
  });

  it("Profile's check before Sign out goes in that mode; the page's own read does not", async () => {
    render(<Profile />);
    await waitFor(() => expect(calls('list_pending_changes')).toHaveLength(1));
    expect(calls('list_pending_changes')[0]).toEqual(['list_pending_changes']);
    await userEvent.click(screen.getByRole('button', { name: /^sign out/i }));
    await waitFor(() => expect(signOut).toHaveBeenCalledTimes(1));
    expect(calls('list_pending_changes')[1]).toEqual(['list_pending_changes', { signingOut: true }]);
  });

  it('a read Rust did not send (no usable access token) is "could not check", never an expired session', async () => {
    listResult = notSent;
    render(<SignOutDialog open stillConnected onClose={() => {}} />);
    expect(await screen.findByText(HOLD_UNCHECKED_CAUTION)).toBeInTheDocument();
    expect(expireSession).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    await waitFor(() => expect(signOut).toHaveBeenCalledTimes(1));
  });

  it('a cancel-first Rust did not send blocks the Sign Out, never ends it as expired', async () => {
    noteHeldDeletion({ id: HOLD_ID, applyAfter: APPLY_AFTER }, { filedHere: true, generation: heldDeletionGeneration() });
    listResult = () => Promise.resolve(listed);
    cancelResult = notSent;
    render(<SignOutDialog open stillConnected onClose={() => {}} />);
    await waitFor(() => expect(calls('list_pending_changes')).toHaveLength(1));
    await userEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    expect(await screen.findByText(/The deletion is still scheduled/)).toBeInTheDocument();
    expect(signOut).not.toHaveBeenCalled();
    expect(expireSession).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Sign out anyway' })).toBeEnabled();
  });
});

describe('the hold as shared state', () => {
  const listed = [{ id: HOLD_ID, action: 'account_delete', applyAfter: APPLY_AFTER }];

  it('the hold the 202 named is shown and warned about even though every later list read fails', async () => {
    // Profile's opening read finds nothing; every read after it fails.
    const answers = [() => Promise.resolve([])];
    listResult = () => (answers.shift() ?? (() => Promise.reject(refusal('network_offline'))))();
    await openDialog();
    await userEvent.click(await screen.findByRole('button', { name: HOLD_OFFER_NUMBER }));
    await userEvent.type(screen.getByPlaceholderText('DELETE'), 'DELETE');
    await userEvent.click(screen.getByRole('button', { name: 'Delete in 24 hours' }));
    await screen.findByRole('button', { name: 'Close' });
    // The follow-up read was made, and failed.
    await waitFor(() => expect(calls('list_pending_changes').length).toBeGreaterThanOrEqual(2));
    expect(getHeldDeletion()).toEqual({ id: HOLD_ID, applyAfter: APPLY_AFTER, filedHere: true });
    await userEvent.click(screen.getByRole('button', { name: 'Close' }));
    // The banner, from the 202 alone; filed here, so this app's sign-out cancels it.
    expect(screen.getByRole('status')).toHaveTextContent(
      `Your account will be deleted on ${holdTimeText(APPLY_AFTER)}.`,
    );
    expect(screen.getByRole('status')).toHaveTextContent(SIGN_OUT_CANCELS_HOLD);
    // And the Profile sign-out asks first.
    await userEvent.click(screen.getByRole('button', { name: /^sign out/i }));
    expect(await screen.findByText(SIGN_OUT_FILED_HERE)).toBeInTheDocument();
    expect(signOut).not.toHaveBeenCalled();
  });

  it('a successful cancel clears the banner at once, even when the re-read fails', async () => {
    const answers = [() => Promise.resolve(listed)];
    listResult = () => (answers.shift() ?? (() => Promise.reject(refusal('network_offline'))))();
    render(<Profile />);
    await userEvent.click(await screen.findByRole('button', { name: 'Cancel deletion' }));
    await waitFor(() => expect(screen.queryByRole('status')).not.toBeInTheDocument());
    expect(calls('cancel_pending_change')[0][1]).toStrictEqual({ id: HOLD_ID });
    await waitFor(() => expect(calls('list_pending_changes')).toHaveLength(2));
    expect(getHeldDeletion()).toBeNull();
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
  });

  it('a cancel answered "already gone" (404) clears it too', async () => {
    const answers = [() => Promise.resolve(listed)];
    listResult = () => (answers.shift() ?? (() => Promise.reject(refusal('network_offline'))))();
    cancelResult = () => Promise.resolve({ cancelled: false, alreadyGone: true });
    render(<Profile />);
    await userEvent.click(await screen.findByRole('button', { name: 'Cancel deletion' }));
    await waitFor(() => expect(screen.queryByRole('status')).not.toBeInTheDocument());
    expect(getHeldDeletion()).toBeNull();
  });

  it('an older list read that resolves after a cancel does not put the hold back', async () => {
    const stale = deferred<unknown>();
    const answers = [
      () => Promise.resolve(listed), // Profile opens: the hold is listed
      () => stale.promise, // a focus read, still out when the user cancels
      () => Promise.resolve([]), // the re-read after the cancel
    ];
    listResult = () => answers.shift()!();
    render(<Profile />);
    await screen.findByRole('button', { name: 'Cancel deletion' });
    act(() => {
      window.dispatchEvent(new Event('focus'));
    });
    await waitFor(() => expect(calls('list_pending_changes')).toHaveLength(2));
    await userEvent.click(screen.getByRole('button', { name: 'Cancel deletion' }));
    await waitFor(() => expect(screen.queryByRole('status')).not.toBeInTheDocument());
    await waitFor(() => expect(calls('list_pending_changes')).toHaveLength(3));
    // Now the old read answers with the hold it saw before the cancel.
    await act(async () => {
      stale.resolve(listed);
    });
    expect(getHeldDeletion()).toBeNull();
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Cancel deletion' })).not.toBeInTheDocument();
  });

  it('an older list read that resolves after a 202 does not hide the new hold', async () => {
    const stale = deferred<unknown>();
    noteHeldDeletion({ id: 'cmold', applyAfter: APPLY_AFTER }, { filedHere: true, generation: heldDeletionGeneration() });
    clearHeldDeletion();
    const answers = [() => stale.promise];
    listResult = () => (answers.shift() ?? (() => Promise.reject(refusal('network_offline'))))();
    render(<Profile />); // its opening read is still out
    await waitFor(() => expect(calls('list_pending_changes')).toHaveLength(1));
    act(() => noteHeldDeletion({ id: HOLD_ID, applyAfter: APPLY_AFTER }, { filedHere: true, generation: heldDeletionGeneration() }));
    await act(async () => {
      stale.resolve([]); // it saw no hold, before the 202
    });
    expect(getHeldDeletion()).toEqual({ id: HOLD_ID, applyAfter: APPLY_AFTER, filedHere: true });
    expect(screen.getByRole('status')).toBeInTheDocument();
  });

  it('L3: a 202 that arrives after the session ended does not put the old account\'s hold back', async () => {
    const request = deferred<unknown>();
    holdResult = () => request.promise;
    await openDialog();
    await userEvent.click(await screen.findByRole('button', { name: HOLD_OFFER_NUMBER }));
    await userEvent.type(screen.getByPlaceholderText('DELETE'), 'DELETE');
    await userEvent.click(screen.getByRole('button', { name: 'Delete in 24 hours' }));
    await waitFor(() => expect(calls('request_deletion_hold')).toHaveLength(1));
    const readsBefore = calls('list_pending_changes').length;
    // The session ends while the request is out (`endSession` / `signOut` clear the shared hold).
    act(() => clearHeldDeletion());
    await act(async () => {
      request.resolve(HELD);
    });
    expect(getHeldDeletion()).toBeNull();
    expect(screen.queryByRole('status')).not.toBeInTheDocument(); // no banner
    // Nor a list read on behalf of the session that ended.
    expect(calls('list_pending_changes')).toHaveLength(readsBefore);
  });

  it('L3: a note made before the last clear is dropped; one made after it is kept', () => {
    const before = heldDeletionGeneration();
    clearHeldDeletion();
    noteHeldDeletion({ id: HOLD_ID, applyAfter: APPLY_AFTER }, { filedHere: true, generation: before });
    expect(getHeldDeletion()).toBeNull();
    noteHeldDeletion({ id: HOLD_ID, applyAfter: APPLY_AFTER }, { filedHere: true, generation: heldDeletionGeneration() });
    expect(getHeldDeletion()).toEqual({ id: HOLD_ID, applyAfter: APPLY_AFTER, filedHere: true });
  });

  it('the number-replacement dialog warns that a new number cancels the deletion, only while a hold is known', async () => {
    listResult = () => new Promise(() => {}); // only what is already known
    const { unmount } = render(<ReplaceAccountNumberDialog open hasPassword={false} onDismiss={() => {}} />);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    unmount();
    // Any origin: a new number cancels every held deletion.
    noteHeldDeletion({ id: HOLD_ID, applyAfter: APPLY_AFTER }, { filedHere: false, generation: heldDeletionGeneration() });
    render(<ReplaceAccountNumberDialog open hasPassword={false} onDismiss={() => {}} />);
    expect(screen.getByRole('alert')).toHaveTextContent(rotationWithHoldText(APPLY_AFTER));
    expect(rotationWithHoldText(APPLY_AFTER)).toMatch(/Replacing the account number cancels that deletion/);
    expect(rotationWithHoldText(APPLY_AFTER)).toContain(`on ${holdTimeText(APPLY_AFTER)}`);
    expect(rotationWithHoldText(APPLY_AFTER)).not.toMatch(/will NOT be deleted/);
  });

  /** The replacement dialog, from step 1 to the confirm step. */
  async function toRotationConfirmStep() {
    await userEvent.type(screen.getByLabelText('Current account number'), CURRENT_NUMBER);
    await userEvent.click(screen.getByRole('button', { name: 'Get a new number' }));
    await screen.findByTestId('new-account-number');
    await userEvent.click(screen.getByRole('checkbox', { name: "I've saved it" }));
    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));
    await screen.findByLabelText('New account number');
  }

  it('L4: the replacement dialog reads the list when it opens, and warns again at the confirm step', async () => {
    listResult = () => Promise.resolve(listed); // filed on the website, say: not known here before
    render(<ReplaceAccountNumberDialog open hasPassword={false} onDismiss={() => {}} />);
    expect(await screen.findByRole('alert')).toHaveTextContent(rotationWithHoldText(APPLY_AFTER));
    expect(calls('list_pending_changes')).toHaveLength(1);
    await toRotationConfirmStep();
    expect(screen.getByRole('note')).toHaveTextContent(rotationWithHoldText(APPLY_AFTER));
  });

  it('L2: a confirmed replacement clears the hold at once, then reads the list again', async () => {
    // The opening read lists the hold; the read after the replacement never answers.
    const answers = [() => Promise.resolve(listed)];
    listResult = () => (answers.shift() ?? (() => new Promise(() => {})))();
    render(<ReplaceAccountNumberDialog open hasPassword={false} onDismiss={() => {}} />);
    await screen.findByRole('alert');
    expect(getHeldDeletion()?.id).toBe(HOLD_ID);
    await toRotationConfirmStep();
    await userEvent.type(screen.getByLabelText('New account number'), NEW_NUMBER);
    await userEvent.click(screen.getByRole('button', { name: 'Replace number' }));
    await waitFor(() => expect(calls('rotate_anonymous_number_confirm')).toHaveLength(1));
    await waitFor(() => expect(getHeldDeletion()).toBeNull());
    expect(calls('list_pending_changes')).toHaveLength(2);
  });
});

describe('the Profile banner', () => {
  const listed = [
    { id: 'cmpw', action: 'password_set', applyAfter: APPLY_AFTER },
    { id: HOLD_ID, action: 'account_delete', description: 'delete the account', applyAfter: APPLY_AFTER },
  ];

  it('shows a held deletion with its local time, and Cancel removes it', async () => {
    const answers = [() => Promise.resolve(listed), () => Promise.resolve([])];
    listResult = () => (answers.shift() ?? (() => Promise.resolve([])))();
    render(<Profile />);
    expect(await screen.findByText(`Your account will be deleted on ${holdTimeText(APPLY_AFTER)}.`)).toBeInTheDocument();
    // Listed, so not known to be filed here: this app's sign-out does not cancel it.
    expect(screen.getByText(new RegExp(SIGN_OUT_KEEPS_HOLD))).toBeInTheDocument();
    expect(screen.queryByText(new RegExp(SIGN_OUT_CANCELS_HOLD))).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Cancel deletion' }));
    await waitFor(() =>
      expect(screen.queryByText(/Your account will be deleted on/)).not.toBeInTheDocument(),
    );
    expect(calls('cancel_pending_change')[0][1]).toStrictEqual({ id: HOLD_ID });
    nobodySignedOut();
  });

  it('a cancel answered "already gone" also reads the list again', async () => {
    const answers = [() => Promise.resolve(listed), () => Promise.resolve([])];
    listResult = () => (answers.shift() ?? (() => Promise.resolve([])))();
    cancelResult = () => Promise.resolve({ cancelled: false, alreadyGone: true });
    render(<Profile />);
    await userEvent.click(await screen.findByRole('button', { name: 'Cancel deletion' }));
    await waitFor(() => expect(calls('list_pending_changes')).toHaveLength(2));
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Cancel deletion' })).not.toBeInTheDocument());
  });

  it('reads the list again on window focus; a hold that vanished is simply gone', async () => {
    const answers = [() => Promise.resolve(listed), () => Promise.resolve([])];
    listResult = () => (answers.shift() ?? (() => Promise.resolve([])))();
    render(<Profile />);
    await screen.findByRole('button', { name: 'Cancel deletion' });
    act(() => {
      window.dispatchEvent(new Event('focus'));
    });
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Cancel deletion' })).not.toBeInTheDocument());
    expect(calls('list_pending_changes')).toHaveLength(2);
    expect(screen.queryByText(/error/i)).not.toBeInTheDocument();
  });

  it('shows nothing for other pending changes, an older server or a failed read', async () => {
    listResult = () => Promise.resolve([listed[0]]);
    const { unmount } = render(<Profile />);
    await waitFor(() => expect(calls('list_pending_changes')).toHaveLength(1));
    expect(screen.queryByRole('button', { name: 'Cancel deletion' })).not.toBeInTheDocument();
    unmount();
    listResult = () => Promise.reject(refusal('server_unavailable'));
    render(<Profile />);
    await waitFor(() => expect(calls('list_pending_changes')).toHaveLength(2));
    expect(screen.queryByRole('button', { name: 'Cancel deletion' })).not.toBeInTheDocument();
  });

  it('a failed cancel says so and keeps the banner', async () => {
    listResult = () => Promise.resolve(listed);
    cancelResult = () => Promise.reject(refusal('network_offline'));
    render(<Profile />);
    await userEvent.click(await screen.findByRole('button', { name: 'Cancel deletion' }));
    expect(await screen.findByText(/No internet connection/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Cancel deletion' })).toBeInTheDocument();
  });

  it('a remembered hold plus a dead session is NOT "account deleted": the session-expired path runs', async () => {
    const answers = [
      () => Promise.resolve(listed),
      () => Promise.reject(refusal('session_expired', 'Your session has expired. Sign in again.')),
    ];
    listResult = () => answers.shift()!();
    render(<Profile />);
    await screen.findByRole('button', { name: 'Cancel deletion' });
    act(() => {
      window.dispatchEvent(new Event('focus'));
    });
    // The ordinary path for an ended session, once. Nothing here decides the
    // account is gone: no deletion sign-out, no "deleted" wording.
    await waitFor(() => expect(expireSession).toHaveBeenCalledTimes(1));
    expect(screen.queryByText(/has been deleted/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/account (was|is) deleted/i)).not.toBeInTheDocument();
    nobodySignedOut();
  });

  it('heldDeletionOf reads only a usable account_delete row', () => {
    // The list does not say which session filed it: never "filed here" by itself.
    expect(heldDeletionOf(listed)).toEqual({ id: HOLD_ID, applyAfter: APPLY_AFTER, filedHere: false });
    for (const bad of [undefined, null, {}, 'x', [{ action: 'account_delete' }], [{ id: 'a', action: 'account_delete' }], [null]]) {
      expect(heldDeletionOf(bad)).toBeNull();
    }
  });
});

describe('overlapping list reads (LOW-2): a dropped answer is not "answered"', () => {
  const listed = [{ id: HOLD_ID, action: 'account_delete', applyAfter: APPLY_AFTER }];

  it('two overlapping reads: the first, answering after the second started, settles only with the second', async () => {
    const first = deferred<unknown>();
    const second = deferred<unknown>();
    const answers = [() => first.promise, () => second.promise];
    listResult = () => answers.shift()!();
    let firstAnswered: boolean | undefined;
    const firstRead = refreshHeldDeletion().then((answered) => {
      firstAnswered = answered;
    });
    const secondRead = refreshHeldDeletion();
    await act(async () => {
      first.resolve([]); // dropped: a newer read is out
    });
    expect(firstAnswered).toBeUndefined();
    expect(getHeldDeletion()).toBeNull();
    await act(async () => {
      second.resolve(listed);
    });
    await firstRead;
    expect(firstAnswered).toBe(true);
    expect(await secondRead).toBe(true);
    expect(getHeldDeletion()?.id).toBe(HOLD_ID);
  });

  it("Profile's Sign out row, overtaken by a newer read, waits for it: then asks first", async () => {
    const rowRead = deferred<unknown>();
    const focusRead = deferred<unknown>();
    const answers = [() => Promise.resolve([]), () => rowRead.promise, () => focusRead.promise];
    listResult = () => (answers.shift() ?? (() => new Promise(() => {})))();
    render(<Profile />);
    await waitFor(() => expect(calls('list_pending_changes')).toHaveLength(1));
    await userEvent.click(screen.getByRole('button', { name: /^sign out/i }));
    await waitFor(() => expect(calls('list_pending_changes')).toHaveLength(2));
    act(() => {
      window.dispatchEvent(new Event('focus')); // a newer read starts
    });
    await waitFor(() => expect(calls('list_pending_changes')).toHaveLength(3));
    await act(async () => {
      rowRead.resolve([]); // the row's own read answers, but it is dropped
    });
    expect(signOut).not.toHaveBeenCalled();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    await act(async () => {
      focusRead.resolve(listed);
    });
    expect(await screen.findByRole('dialog', { name: 'Sign out?' })).toBeInTheDocument();
    expect(signOut).not.toHaveBeenCalled();
  });

  it('the sign-out dialog, its opening read overtaken by a newer one, keeps Sign out disabled until that answers', async () => {
    const openingRead = deferred<unknown>();
    const newerRead = deferred<unknown>();
    const answers = [() => openingRead.promise, () => newerRead.promise];
    listResult = () => (answers.shift() ?? (() => new Promise(() => {})))();
    render(<SignOutDialog open stillConnected={false} onClose={() => {}} />);
    await waitFor(() => expect(calls('list_pending_changes')).toHaveLength(1));
    act(() => {
      void refreshHeldDeletion();
    });
    await act(async () => {
      openingRead.resolve([]); // dropped
    });
    expect(screen.getByRole('button', { name: 'Sign out' })).toBeDisabled();
    expect(screen.queryByRole('note')).not.toBeInTheDocument();
    await act(async () => {
      newerRead.resolve([]);
    });
    expect(screen.getByRole('button', { name: 'Sign out' })).toBeEnabled();
    expect(screen.queryByRole('note')).not.toBeInTheDocument();
  });
});
