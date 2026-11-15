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
 * - Signing out cancels the hold on the server: the dialog, the banner and a
 *   sign-out confirmation (only while a hold is listed) say so.
 * - Nothing ever concludes "account deleted": an ended session takes the
 *   ordinary session-expired path, and an unexpected answer assumes nothing.
 * - The hold is ONE shared state (`@/lib/held-deletion`): the Home sign-out
 *   dialog warns too, the hold the 202 named is known without a list read, and
 *   a cancel clears it at once.
 *
 * Run: npx vitest run src/__tests__/DeletionHold.test.tsx
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { invoke } from '@tauri-apps/api/core';
import { HOLD_OFFER_CODE, HOLD_OFFER_NUMBER, Profile } from '@/screens/Profile';
import { HOLD_UNEXPECTED } from '@/screens/profile/DeleteAccountDialog';
import { SignOutDialog } from '@/components/home/SignOutDialog';
import {
  clearHeldDeletion,
  getHeldDeletion,
  heldDeletionOf,
  holdTimeText,
  noteHeldDeletion,
  SIGN_OUT_CANCELS_HOLD,
  signOutWithHoldText,
} from '@/lib/held-deletion';
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
/** The sign-out warning while that hold is known (Profile and Home alike). */
const SIGN_OUT_WITH_HOLD = signOutWithHoldText(APPLY_AFTER);

let preflightResult: () => Promise<unknown>;
let holdResult: () => Promise<unknown>;
let listResult: () => Promise<unknown>;
let cancelResult: () => Promise<unknown>;

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
  mockedInvoke.mockImplementation((cmd: string) => {
    if (cmd === 'deletion_preflight') return preflightResult();
    if (cmd === 'request_deletion_hold') return holdResult();
    if (cmd === 'list_pending_changes') return listResult();
    if (cmd === 'cancel_pending_change') return cancelResult();
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
    nobodySignedOut();
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

  it('asks first, saying that signing out cancels the deletion; Stay keeps both', async () => {
    listResult = () => Promise.resolve(listed);
    render(<Profile />);
    await screen.findByRole('button', { name: 'Cancel deletion' });
    await userEvent.click(screen.getByRole('button', { name: /^sign out/i }));
    expect(await screen.findByText(SIGN_OUT_WITH_HOLD)).toBeInTheDocument();
    expect(screen.getByRole('dialog', { name: 'Sign out?' })).toBeInTheDocument();
    expect(SIGN_OUT_WITH_HOLD).toMatch(/Signing out cancels that deletion/);
    expect(SIGN_OUT_WITH_HOLD).toContain(`on ${holdTimeText(APPLY_AFTER)}`);
    expect(SIGN_OUT_WITH_HOLD).toMatch(/will NOT be deleted/);
    expect(signOut).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole('button', { name: 'Stay signed in' }));
    expect(screen.queryByText(SIGN_OUT_WITH_HOLD)).not.toBeInTheDocument();
    expect(signOut).not.toHaveBeenCalled();
    expect(calls('cancel_pending_change')).toHaveLength(0);
  });

  it('confirming signs out the ordinary way (the server cancels the hold)', async () => {
    listResult = () => Promise.resolve(listed);
    render(<Profile />);
    await screen.findByRole('button', { name: 'Cancel deletion' });
    await userEvent.click(screen.getByRole('button', { name: /^sign out/i }));
    await screen.findByText(SIGN_OUT_WITH_HOLD);
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Sign out' }));
    expect(signOut).toHaveBeenCalledTimes(1);
    expect(calls('delete_account')).toHaveLength(0);
  });

  it('without a hold, Sign out signs out at once, as before', async () => {
    render(<Profile />);
    await waitFor(() => expect(calls('list_pending_changes')).toHaveLength(1));
    await userEvent.click(screen.getByRole('button', { name: /^sign out/i }));
    expect(signOut).toHaveBeenCalledTimes(1);
    expect(screen.queryByText(SIGN_OUT_WITH_HOLD)).not.toBeInTheDocument();
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

  it('reads the list on opening and warns, with the date, that signing out cancels the deletion', async () => {
    listResult = () => Promise.resolve(listed);
    render(<SignOutDialog open stillConnected={false} onClose={() => {}} />);
    expect(await screen.findByRole('alert')).toHaveTextContent(SIGN_OUT_WITH_HOLD);
    expect(SIGN_OUT_WITH_HOLD).toContain(`on ${holdTimeText(APPLY_AFTER)}`);
    expect(calls('list_pending_changes')).toHaveLength(1);
    expect(signOut).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    expect(signOut).toHaveBeenCalledTimes(1);
  });

  it('a hold filed in Profile is known here at once, even when the list read fails', async () => {
    // What the dialog does with the 202: straight into the shared state.
    noteHeldDeletion({ id: HOLD_ID, applyAfter: APPLY_AFTER });
    listResult = () => Promise.reject(refusal('network_offline'));
    render(<SignOutDialog open stillConnected onClose={() => {}} />);
    // No waiting on the read: the warning is in the first paint.
    expect(screen.getByRole('alert')).toHaveTextContent(SIGN_OUT_WITH_HOLD);
    await waitFor(() => expect(calls('list_pending_changes')).toHaveLength(1));
    expect(screen.getByRole('alert')).toHaveTextContent(SIGN_OUT_WITH_HOLD);
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
    expect(await screen.findByRole('alert')).toHaveTextContent(SIGN_OUT_WITH_HOLD);
    expect(button).toBeEnabled();
    expect(signOut).not.toHaveBeenCalled();
  });

  it('without a hold it asks only the usual question, and a failed read does not block signing out', async () => {
    listResult = () => Promise.reject(refusal('network_offline'));
    render(<SignOutDialog open stillConnected={false} onClose={() => {}} />);
    await waitFor(() => expect(screen.getByRole('button', { name: 'Sign out' })).toBeEnabled());
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.getByText('Are you sure you want to sign out?')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    expect(signOut).toHaveBeenCalledTimes(1);
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
    expect(getHeldDeletion()).toEqual({ id: HOLD_ID, applyAfter: APPLY_AFTER });
    await userEvent.click(screen.getByRole('button', { name: 'Close' }));
    // The banner, from the 202 alone.
    expect(screen.getByRole('status')).toHaveTextContent(
      `Your account will be deleted on ${holdTimeText(APPLY_AFTER)}.`,
    );
    // And the Profile sign-out asks first.
    await userEvent.click(screen.getByRole('button', { name: /^sign out/i }));
    expect(await screen.findByText(SIGN_OUT_WITH_HOLD)).toBeInTheDocument();
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
    expect(screen.getByText(new RegExp(SIGN_OUT_CANCELS_HOLD))).toBeInTheDocument();
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
    expect(heldDeletionOf(listed)).toEqual({ id: HOLD_ID, applyAfter: APPLY_AFTER });
    for (const bad of [undefined, null, {}, 'x', [{ action: 'account_delete' }], [{ id: 'a', action: 'account_delete' }], [null]]) {
      expect(heldDeletionOf(bad)).toBeNull();
    }
  });
});
