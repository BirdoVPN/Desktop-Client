/**
 * Sign-in (W2-012, W2-027, W2-045, P1-parity-008, -034).
 *
 * Run: npx vitest run src/__tests__/LoginScreen.test.tsx
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { invoke } from '@tauri-apps/api/core';
import { Login } from '@/components/Login';
import { useAppStore } from '@/store/app-store';
import { SESSION_EXPIRED_COPY } from '@/lib/errors';

vi.mock('@tauri-apps/api/core');
vi.mock('@tauri-apps/plugin-shell', () => ({ open: vi.fn().mockResolvedValue(undefined) }));

const mockedInvoke = vi.mocked(invoke);

beforeEach(() => {
  mockedInvoke.mockReset();
  mockedInvoke.mockResolvedValue(undefined);
  useAppStore.getState().logout();
  useAppStore.setState({ sessionEndedReason: null });
});

describe('Email sign-in', () => {
  it('Sign in is disabled until the email looks valid and a password is entered, and nothing is sent', async () => {
    render(<Login />);
    const submit = screen.getByRole('button', { name: 'Sign in' });
    expect(submit).toBeDisabled();
    await userEvent.type(screen.getByRole('textbox', { name: 'Email' }), 'not-an-email');
    await userEvent.type(screen.getByLabelText('Password'), 'x');
    expect(submit).toBeDisabled();
    await userEvent.clear(screen.getByRole('textbox', { name: 'Email' }));
    await userEvent.type(screen.getByRole('textbox', { name: 'Email' }), 'me@example.com');
    expect(submit).toBeEnabled();
    expect(mockedInvoke).not.toHaveBeenCalledWith('login', expect.anything());
  });

  it('a refused sign-in shows mapped copy, never the raw ApiError text', async () => {
    mockedInvoke.mockImplementation(async (cmd: string) =>
      cmd === 'login' ? { success: false, message: 'Authentication failed' } : undefined,
    );
    render(<Login />);
    await userEvent.type(screen.getByRole('textbox', { name: 'Email' }), 'me@example.com');
    await userEvent.type(screen.getByLabelText('Password'), 'wrong');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      "Couldn't sign in. Check your email and password and try again.",
    );
    expect(screen.queryByText('Authentication failed')).not.toBeInTheDocument();
  });

  it('a v2 rejection is mapped by code: a pin failure is not "unable to reach the server"', async () => {
    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === 'login') throw { code: 'cert_pin_failed', message: 'your connection is being intercepted' };
      return undefined;
    });
    render(<Login />);
    await userEvent.type(screen.getByRole('textbox', { name: 'Email' }), 'me@example.com');
    await userEvent.type(screen.getByLabelText('Password'), 'pw');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(/intercepting secure connections/);
    expect(alert).not.toHaveTextContent(/reach/);
  });

  it('shows why the session ended, and clears it on a successful sign-in (W2-006)', async () => {
    useAppStore.setState({ sessionEndedReason: 'expired' });
    mockedInvoke.mockImplementation(async (cmd: string) =>
      cmd === 'login' ? { success: true, user: { email: 'me@example.com' } } : undefined,
    );
    render(<Login />);
    expect(screen.getByText(SESSION_EXPIRED_COPY)).toBeInTheDocument();
    await userEvent.type(screen.getByRole('textbox', { name: 'Email' }), 'me@example.com');
    await userEvent.type(screen.getByLabelText('Password'), 'pw');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    await waitFor(() => expect(useAppStore.getState().isAuthenticated).toBe(true));
    expect(useAppStore.getState().sessionEndedReason).toBeNull();
  });
});

describe('Creating an account (W2-027)', () => {
  it('"Sign up" opens the Anonymous tab with Create focused — not the web sign-in page', async () => {
    render(<Login />);
    await userEvent.click(screen.getByRole('button', { name: 'Sign up' }));
    expect(screen.getByRole('tab', { name: 'Anonymous' })).toHaveAttribute('aria-selected', 'true');
    expect(await screen.findByRole('button', { name: 'Create a new anonymous account' })).toHaveFocus();
  });

  it('Create comes first on the Anonymous tab and has its own loading state', async () => {
    let finish: (v: unknown) => void = () => {};
    mockedInvoke.mockImplementation((cmd: string) =>
      cmd === 'register_anonymous' ? new Promise((r) => (finish = r)) : Promise.resolve(undefined),
    );
    render(<Login />);
    await userEvent.click(screen.getByRole('tab', { name: 'Anonymous' }));
    await screen.findByRole('button', { name: 'Create a new anonymous account' });
    const buttons = screen.getAllByRole('button').map((b) => b.textContent);
    expect(buttons.indexOf('Create a new anonymous account')).toBeLessThan(buttons.indexOf('Sign in'));
    await userEvent.click(screen.getByRole('button', { name: 'Create a new anonymous account' }));
    expect(screen.getByRole('button', { name: /Creating/ })).toBeInTheDocument();
    // The sign-in button does NOT claim to be creating (the old shared flag).
    expect(screen.getByRole('button', { name: 'Sign in' })).toBeInTheDocument();
    finish({ success: true, user: { account_id: '123456789012345678901234' } });
    expect(await screen.findByText('1234 5678 9012 3456 7890 1234')).toBeInTheDocument();
    expect(screen.getByText('Save your account number')).toBeInTheDocument();
  });

  it('the account number field groups digits in fours with spaces and sends digits only', async () => {
    mockedInvoke.mockImplementation(async (cmd: string) =>
      cmd === 'login_anonymous' ? { success: true } : undefined,
    );
    render(<Login />);
    await userEvent.click(screen.getByRole('tab', { name: 'Anonymous' }));
    const field = await screen.findByRole('textbox', { name: 'Account number' });
    await userEvent.type(field, '123456789012345678901234');
    expect(field).toHaveValue('1234 5678 9012 3456 7890 1234');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    await waitFor(() =>
      expect(mockedInvoke).toHaveBeenCalledWith('login_anonymous', {
        request: { anonymousId: '123456789012345678901234', password: null },
      }),
    );
  });
});

// WIN-FIX-3: the identity Login hydrates after a sign-in carries hasPassword.
// It used not to, so a new anonymous or SSO account kept the default `true`:
// the delete dialog asked for a password the account does not have, with
// Delete disabled, until the app was restarted.
describe('After a sign-in', () => {
  const anonymousAuthState = {
    is_authenticated: true,
    email: null,
    account_id: 'acc-1',
    plan: null,
    has_password: false,
    is_anonymous: true,
    account_number: '123456789012345678901234',
  };

  it('a new anonymous account is known to have no password', async () => {
    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === 'register_anonymous') return { success: true, user: { account_id: '123456789012345678901234' } };
      if (cmd === 'get_auth_state') return anonymousAuthState;
      return undefined;
    });
    render(<Login />);
    await userEvent.click(screen.getByRole('tab', { name: 'Anonymous' }));
    await userEvent.click(await screen.findByRole('button', { name: 'Create a new anonymous account' }));
    await userEvent.click(await screen.findByRole('button', { name: "I've saved it — continue" }));
    await waitFor(() => expect(useAppStore.getState().isAuthenticated).toBe(true));
    expect(useAppStore.getState().account.hasPassword).toBe(false);
    expect(useAppStore.getState().account.isAnonymous).toBe(true);
  });

  it('an SSO account is known to have no password', async () => {
    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === 'native_oauth_login') return { success: true };
      if (cmd === 'get_auth_state') return { ...anonymousAuthState, email: 'sso@example.com', is_anonymous: false };
      return undefined;
    });
    render(<Login />);
    await userEvent.click(screen.getByRole('tab', { name: 'SSO' }));
    await userEvent.click(await screen.findByRole('button', { name: 'Continue with Google' }));
    await waitFor(() => expect(useAppStore.getState().isAuthenticated).toBe(true));
    expect(useAppStore.getState().account.hasPassword).toBe(false);
  });
});

describe('SSO', () => {
  it('offers Continue with Apple and calls the same command with provider "apple" (P1-parity-008)', async () => {
    mockedInvoke.mockImplementation(() => new Promise(() => {}));
    render(<Login />);
    await userEvent.click(screen.getByRole('tab', { name: 'SSO' }));
    expect(
      await screen.findByText('Continue with your Google, GitHub or Apple account — no password needed.'),
    ).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Continue with Apple' }));
    expect(mockedInvoke).toHaveBeenCalledWith('native_oauth_login', { provider: 'apple' });
    expect(screen.getByText('Finish signing in with Apple in your browser, then return here.')).toBeInTheDocument();
  });

  it('the method switcher is a real tablist (W2-035)', () => {
    render(<Login />);
    const tabs = screen.getAllByRole('tab');
    expect(tabs.map((t) => t.textContent)).toEqual(['Email', 'Anonymous', 'SSO']);
    expect(screen.getByRole('tabpanel')).toBeInTheDocument();
  });
});
