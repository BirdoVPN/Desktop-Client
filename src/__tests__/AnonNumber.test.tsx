/**
 * The anonymous account number (MR-1707 Desktop; birdo-web #850).
 *
 *  - Display: a full 24-digit number as before (masked until asked, copyable);
 *    the server's MASK (`********************1234`) shown as it is, with no
 *    reveal, no copy button and the "Shown once…" line; the synthetic
 *    `anon_…@anonymous.local` address never shown, whichever form it takes.
 *  - Replacement, two phases behind a flag that is OFF: no entry point while
 *    off; step 1 (prepare) then the number shown once with "I've saved it";
 *    step 2 (confirm) with the number re-typed; each refusal worded; and the
 *    lost-confirm case, where the number is still on hand to try again.
 *  - No number reaches the logs or storage.
 *
 * Fake numbers only.
 *
 * Run: npx vitest run src/__tests__/AnonNumber.test.tsx
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { invoke } from '@tauri-apps/api/core';
import { Profile } from '@/screens/Profile';
import {
  ReplaceAccountNumberDialog,
  ROTATION_COPY,
  type RotationStep,
} from '@/screens/profile/ReplaceAccountNumberDialog';
import { MASKED_NUMBER_NOTE } from '@/screens/profile/ProfileCards';
import { FEATURES } from '@/lib/features';
import { defaultSettings, useAppStore } from '@/store/app-store';
import { anonymityPatch, isMaskedAccountNumber, resolveAnonymousAccount } from '@/utils/helpers';

vi.mock('@tauri-apps/api/core');
vi.mock('@tauri-apps/plugin-opener', () => ({ openUrl: vi.fn().mockResolvedValue(undefined) }));
vi.mock('@/lib/features', async (importOriginal) => {
  const original = await importOriginal<typeof import('@/lib/features')>();
  return { ...original, anonNumberRotationEnabled: vi.fn(() => false) };
});

import { anonNumberRotationEnabled } from '@/lib/features';

const mockedInvoke = vi.mocked(invoke);
const flag = vi.mocked(anonNumberRotationEnabled);
const callsTo = (cmd: string) => mockedInvoke.mock.calls.filter(([c]) => c === cmd);

const FULL = '111122223333444455556666';
const MASK = '********************6666';
const NEW_NUMBER = '777788889999000011112222';
const NEW_PRETTY = '7777 8888 9999 0000 1111 2222';
const CURRENT_PRETTY = '1111 2222 3333 4444 5555 6666';

const step = (fields: Partial<RotationStep>): RotationStep => ({
  refusal: null,
  newNumber: null,
  expiresInSeconds: null,
  retryAfterSecs: null,
  ...fields,
});

function setAnonymous(accountNumber: string | null, email: string | null = null) {
  useAppStore.setState({
    account: {
      ...useAppStore.getState().account,
      email,
      isAnonymous: true,
      accountNumber,
      plan: 'RECON',
    },
  });
}

beforeEach(() => {
  mockedInvoke.mockReset();
  mockedInvoke.mockResolvedValue(undefined);
  flag.mockReturnValue(false);
  useAppStore.getState().logout();
  useAppStore.setState({ isAuthenticated: true, settings: { ...defaultSettings } });
});
afterEach(cleanup);

describe('the flag', () => {
  it('is OFF in the shipped build', () => {
    expect(FEATURES.anonNumberRotation).toBe(false);
  });
});

describe('the number on Profile', () => {
  it('a full number: masked until asked, with the reveal and copy buttons (unchanged)', async () => {
    setAnonymous(FULL);
    render(<Profile />);
    expect(screen.getByTestId('account-number')).toHaveTextContent('•••• •••• •••• •••• •••• 6666');
    expect(screen.getByRole('button', { name: 'Copy account number' })).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Show account number' }));
    expect(screen.getByTestId('account-number')).toHaveTextContent(CURRENT_PRETTY);
    expect(screen.queryByText(MASKED_NUMBER_NOTE)).not.toBeInTheDocument();
  });

  it('a masked number: the mask, no copy, no reveal, and the "Shown once" line', () => {
    setAnonymous(MASK);
    render(<Profile />);
    expect(screen.getByTestId('account-number')).toHaveTextContent('•••• •••• •••• •••• •••• 6666');
    expect(screen.queryByRole('button', { name: 'Copy account number' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /show account number/i })).not.toBeInTheDocument();
    expect(
      screen.getByText('Shown once at sign-up or when you replace it. Replace it if you lost it.'),
    ).toBeInTheDocument();
    // Not even the stars are printed raw.
    expect(document.body.textContent).not.toContain('*');
  });

  it.each([
    ['a full number', FULL, `anon_${FULL}@anonymous.local`],
    ['a masked number', MASK, `anon_${MASK}@anonymous.local`],
    ['no number', null, `anon_${MASK}@anonymous.local`],
  ])('never shows the synthetic address (%s)', (_name, number, email) => {
    setAnonymous(number, email);
    useAppStore.setState({ userEmail: email });
    render(<Profile />);
    expect(screen.getAllByText('Anonymous account').length).toBeGreaterThan(0);
    expect(document.body.textContent).not.toContain('anon_');
    expect(document.body.textContent).not.toContain('@anonymous.local');
  });

  it('no replace button while the flag is off, even when masked', () => {
    setAnonymous(MASK);
    render(<Profile />);
    expect(screen.queryByRole('button', { name: 'Replace account number' })).not.toBeInTheDocument();
  });

  it('the replace button appears only with the flag on, and opens the dialog', async () => {
    flag.mockReturnValue(true);
    setAnonymous(MASK);
    render(<Profile />);
    await userEvent.click(screen.getByRole('button', { name: 'Replace account number' }));
    expect(await screen.findByLabelText('Current account number')).toBeInTheDocument();
  });
});

describe('what the store accepts from get_auth_state', () => {
  it('takes a full number and a mask, nothing else', () => {
    expect(anonymityPatch({ is_anonymous: true, account_number: FULL })).toEqual({
      isAnonymous: true,
      accountNumber: FULL,
    });
    expect(anonymityPatch({ is_anonymous: true, account_number: MASK })).toEqual({
      isAnonymous: true,
      accountNumber: MASK,
    });
    for (const bad of ['', '12345', '****', '1234********************', '********************abcd', 'anon_x@anonymous.local']) {
      expect(anonymityPatch({ is_anonymous: true, account_number: bad })).toEqual({ isAnonymous: true });
    }
  });

  it('isMaskedAccountNumber: stars then digits, 24 long', () => {
    expect(isMaskedAccountNumber(MASK)).toBe(true);
    expect(isMaskedAccountNumber(FULL)).toBe(false);
    expect(isMaskedAccountNumber('********************66')).toBe(false);
    expect(resolveAnonymousAccount({ isAnonymous: true, accountNumber: MASK }).accountNumber).toBe(MASK);
  });
});

describe('replacing the number', () => {
  const onDismiss = vi.fn();
  const renderDialog = (hasPassword = false) =>
    render(<ReplaceAccountNumberDialog open hasPassword={hasPassword} onDismiss={onDismiss} />);

  const typeCurrent = async () => {
    await userEvent.type(screen.getByLabelText('Current account number'), FULL);
  };
  const doPrepare = async () => {
    await typeCurrent();
    await userEvent.click(screen.getByRole('button', { name: 'Get a new number' }));
  };
  const reply = (prepare: RotationStep | Error, confirm?: RotationStep | Error) =>
    mockedInvoke.mockImplementation(async (cmd: string) => {
      const answer = cmd === 'rotate_anonymous_number_prepare' ? prepare : cmd === 'rotate_anonymous_number_confirm' ? confirm : undefined;
      if (answer instanceof Error) throw answer;
      return answer;
    });
  const toConfirmStep = async () => {
    await doPrepare();
    await screen.findByTestId('new-account-number');
    await userEvent.click(screen.getByRole('checkbox', { name: "I've saved it" }));
    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));
    await screen.findByLabelText('New account number');
  };
  const retype = async () => {
    await userEvent.type(screen.getByLabelText('New account number'), NEW_NUMBER);
    await userEvent.click(screen.getByRole('button', { name: 'Replace number' }));
  };

  beforeEach(() => onDismiss.mockReset());

  it('step 1 sends the current number (digits only) and nothing else for a password-less account', async () => {
    reply(step({ newNumber: NEW_NUMBER, expiresInSeconds: 600 }));
    renderDialog();
    expect(screen.queryByLabelText('Password')).not.toBeInTheDocument();
    await doPrepare();
    await screen.findByTestId('new-account-number');
    expect(callsTo('rotate_anonymous_number_prepare')).toEqual([
      ['rotate_anonymous_number_prepare', { request: { currentNumber: FULL } }],
    ]);
    // Nothing is confirmed by step 1.
    expect(callsTo('rotate_anonymous_number_confirm')).toHaveLength(0);
  });

  it('sends the password and the two-factor code when the account has them', async () => {
    reply(step({ newNumber: NEW_NUMBER }));
    renderDialog(true);
    // The button waits for the password.
    await typeCurrent();
    expect(screen.getByRole('button', { name: 'Get a new number' })).toBeDisabled();
    await userEvent.type(screen.getByLabelText('Password'), 'correct horse');
    await userEvent.type(screen.getByLabelText(/Two-factor code/), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Get a new number' }));
    await screen.findByTestId('new-account-number');
    expect(callsTo('rotate_anonymous_number_prepare')[0][1]).toEqual({
      request: { currentNumber: FULL, password: 'correct horse', twoFactorCode: '123456' },
    });
  });

  it('shows the new number once, with a copy button, and Continue waits for "I\'ve saved it"', async () => {
    reply(step({ newNumber: NEW_NUMBER }));
    renderDialog();
    await doPrepare();
    expect(await screen.findByTestId('new-account-number')).toHaveTextContent(NEW_PRETTY);
    expect(screen.getByRole('button', { name: 'Copy new account number' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Continue' })).toBeDisabled();
    await userEvent.click(screen.getByRole('checkbox', { name: "I've saved it" }));
    expect(screen.getByRole('button', { name: 'Continue' })).toBeEnabled();
    // The proof is not kept: it is gone from the form once step 1 passed.
    expect(document.body.textContent).not.toContain(CURRENT_PRETTY);
  });

  it('step 2 needs the whole new number re-typed, sends digits only, then says it is done', async () => {
    reply(step({ newNumber: NEW_NUMBER }), step({}));
    renderDialog();
    await toConfirmStep();
    expect(screen.getByRole('button', { name: 'Replace number' })).toBeDisabled();
    await userEvent.type(screen.getByLabelText('New account number'), NEW_NUMBER.slice(0, 20));
    expect(screen.getByRole('button', { name: 'Replace number' })).toBeDisabled();
    await userEvent.type(screen.getByLabelText('New account number'), NEW_NUMBER.slice(20));
    await userEvent.click(screen.getByRole('button', { name: 'Replace number' }));
    expect(await screen.findByText(ROTATION_COPY.done)).toBeInTheDocument();
    expect(callsTo('rotate_anonymous_number_confirm')).toEqual([
      ['rotate_anonymous_number_confirm', { newNumber: NEW_NUMBER }],
    ]);
    // The identity is read again (Rust holds the fresh tokens).
    expect(callsTo('get_auth_state')).toHaveLength(1);
    // The number is gone from the dialog once it is done.
    expect(document.body.textContent).not.toContain(NEW_PRETTY);
    await userEvent.click(screen.getByRole('button', { name: 'OK' }));
    expect(onDismiss).toHaveBeenCalled();
  });

  it('403 anon_number_rotation_disabled: "not available yet", and nothing was started', async () => {
    reply(step({ refusal: 'disabled' }));
    renderDialog();
    await doPrepare();
    expect(await screen.findByRole('alert')).toHaveTextContent(ROTATION_COPY.disabled);
    expect(screen.queryByTestId('new-account-number')).not.toBeInTheDocument();
  });

  it('401: says the proof did not check out, naming what was asked', async () => {
    reply(step({ refusal: 'unauthorized' }));
    renderDialog(true);
    await typeCurrent();
    await userEvent.type(screen.getByLabelText('Password'), 'wrong');
    await userEvent.click(screen.getByRole('button', { name: 'Get a new number' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'That did not check out. Check the current number, the password, or sign in again if your session ended.',
    );
  });

  it('429: says how long to wait', async () => {
    reply(step({ refusal: 'rate_limited', retryAfterSecs: 600 }));
    renderDialog();
    await doPrepare();
    expect(await screen.findByRole('alert')).toHaveTextContent('about 10 minutes');
  });

  it('409 rotation_not_pending: expired, back to step 1, the number is dropped', async () => {
    reply(step({ newNumber: NEW_NUMBER }), step({ refusal: 'not_pending' }));
    renderDialog();
    await toConfirmStep();
    await retype();
    expect(await screen.findByRole('alert')).toHaveTextContent(ROTATION_COPY.notPending);
    expect(screen.getByLabelText('Current account number')).toBeInTheDocument();
    expect(document.body.textContent).not.toContain(NEW_PRETTY);
  });

  it('409 rotation_account_changed: start again', async () => {
    reply(step({ newNumber: NEW_NUMBER }), step({ refusal: 'account_changed' }));
    renderDialog();
    await toConfirmStep();
    await retype();
    expect(await screen.findByRole('alert')).toHaveTextContent(ROTATION_COPY.accountChanged);
    expect(screen.getByLabelText('Current account number')).toBeInTheDocument();
  });

  it('400 mismatch: stays on step 2 so the number can be corrected', async () => {
    reply(step({ newNumber: NEW_NUMBER }), step({ refusal: 'mismatch' }));
    renderDialog();
    await toConfirmStep();
    await retype();
    expect(await screen.findByRole('alert')).toHaveTextContent(ROTATION_COPY.mismatch);
    expect(screen.getByLabelText('New account number')).toBeInTheDocument();
  });

  it('429 at confirm: says how long to wait and stays on step 2', async () => {
    reply(step({ newNumber: NEW_NUMBER }), step({ refusal: 'rate_limited', retryAfterSecs: 30 }));
    renderDialog();
    await toConfirmStep();
    await retype();
    expect(await screen.findByRole('alert')).toHaveTextContent('30 seconds');
    expect(screen.getByLabelText('New account number')).toBeInTheDocument();
  });

  it('401 at confirm: the session ended; the old number still works', async () => {
    reply(step({ newNumber: NEW_NUMBER }), step({ refusal: 'unauthorized' }));
    renderDialog();
    await toConfirmStep();
    await retype();
    expect(await screen.findByRole('alert')).toHaveTextContent(ROTATION_COPY.confirmSessionEnded);
  });

  it('a lost confirm: the number is still on hand to read again and to try again', async () => {
    const lost = Object.assign(new Error('offline'), { code: 'network_offline', message: 'offline' });
    reply(step({ newNumber: NEW_NUMBER }), lost);
    renderDialog();
    await toConfirmStep();
    await retype();
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument());
    // Still on step 2, not "done", and nothing was dropped.
    expect(screen.queryByText(ROTATION_COPY.done)).not.toBeInTheDocument();
    // Read it again...
    await userEvent.click(screen.getByRole('button', { name: 'Show the number again' }));
    expect(screen.getByTestId('new-account-number')).toHaveTextContent(NEW_PRETTY);
    // ...and try again: the second confirm goes through.
    reply(step({ newNumber: NEW_NUMBER }), step({}));
    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));
    await userEvent.clear(screen.getByLabelText('New account number'));
    await retype();
    expect(await screen.findByText(ROTATION_COPY.done)).toBeInTheDocument();
    expect(callsTo('rotate_anonymous_number_prepare')).toHaveLength(1);
    expect(callsTo('rotate_anonymous_number_confirm')).toHaveLength(2);
  });

  it('writes no number to the console or to browser storage', async () => {
    const spies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((m) => vi.spyOn(console, m).mockImplementation(() => {}));
    reply(step({ newNumber: NEW_NUMBER }), step({}));
    renderDialog();
    await toConfirmStep();
    await retype();
    await screen.findByText(ROTATION_COPY.done);
    for (const spy of spies) {
      expect(JSON.stringify(spy.mock.calls)).not.toMatch(/\d{12}/);
      spy.mockRestore();
    }
    for (const store of [localStorage, sessionStorage]) {
      expect(JSON.stringify(Object.entries(store))).not.toContain(NEW_NUMBER);
      expect(JSON.stringify(Object.entries(store))).not.toContain(FULL);
    }
  });
});
