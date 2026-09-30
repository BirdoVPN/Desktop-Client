/**
 * In-app account deletion (audit 2026-09-29: C-2 / P0-6, A-8 / C-9).
 *
 * - The store-billing warning is shown BEFORE the user confirms.
 * - The dialog never disconnects the VPN itself: the Rust command does, only
 *   after the server confirmed (second-pass #15). A refusal leaves it up.
 * - A server refusal is SHOWN (by its error code: a wrong password reads
 *   "Incorrect password. Please try again.", never Rust's raw text — W2-012)
 *   and signs nobody out.
 * - Store subscriptions the server reports as still billing are listed after
 *   a confirmed deletion, and every way out of that notice signs out.
 *
 * Run: npx vitest run src/__tests__/DeleteAccountDialog.test.tsx
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { invoke } from '@tauri-apps/api/core';
import {
  Profile,
  PREFLIGHT_WEB_CANCELLED,
  STORE_BILLING_WARNING,
  preflightStoreWarning,
} from '@/screens/Profile';
import type { ConnectionState } from '@/store/app-store';

vi.mock('@tauri-apps/api/core');
vi.mock('@tauri-apps/plugin-shell', () => ({ open: vi.fn().mockResolvedValue(undefined) }));

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
const setAuthenticated = vi.fn();
const setConnectionState = vi.fn();
const mockStoreState = {
  connectionState: 'connected' as ConnectionState,
  account: {
    email: 'user@example.com',
    plan: 'OPERATIVE',
    accountId: 'acct',
    maxDevices: 5,
    activeDevices: 1,
    expiresAt: null,
    bandwidthUsed: 0,
    bandwidthLimit: 0,
    status: 'active',
    hasPassword: true,
  },
  userEmail: 'user@example.com',
  setAccount: vi.fn(),
  logout,
  setAuthenticated,
  pushRoute: vi.fn(),
  setConnectionState,
  setCurrentServer: vi.fn(),
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
let deleteResult: () => Promise<unknown>;
let preflightResult: () => Promise<unknown>;

beforeEach(() => {
  mockedInvoke.mockReset();
  logout.mockReset();
  setAuthenticated.mockReset();
  setConnectionState.mockReset();
  mockStoreState.connectionState = 'connected';
  deleteResult = () => Promise.resolve({ storeSubscriptionsStillBilling: [] });
  // Default: the preflight has nothing to say (an older backend answers 404).
  preflightResult = () => Promise.reject('Not Found');
  mockedInvoke.mockImplementation((cmd: string) => {
    if (cmd === 'delete_account') return deleteResult();
    if (cmd === 'deletion_preflight') return preflightResult();
    return Promise.resolve(undefined);
  });
});

async function openAndConfirm() {
  render(<Profile />);
  await userEvent.click(screen.getByRole('button', { name: /delete account/i }));
  expect(screen.getByText(STORE_BILLING_WARNING)).toBeInTheDocument();
  await userEvent.type(screen.getByPlaceholderText('••••••••'), 'hunter2');
  await userEvent.click(screen.getByRole('button', { name: /delete my account/i }));
}

/** The v2 rejection for a wrong password (contract WINDOWS-IPC-V2 §2). */
const WRONG_PASSWORD = {
  code: 'invalid_credentials',
  message: 'Incorrect password',
  retryable: true,
  retry_after_secs: null,
};

const calls = () => mockedInvoke.mock.calls.map(([cmd]) => cmd);

describe('Delete account dialog', () => {
  it('warns that store subscriptions are not cancelled, before anything is sent', async () => {
    render(<Profile />);
    await userEvent.click(screen.getByRole('button', { name: /delete account/i }));
    expect(STORE_BILLING_WARNING).toMatch(/does not cancel an App Store or Google Play subscription/);
    expect(STORE_BILLING_WARNING).toMatch(/web subscription bought on birdo\.app is cancelled automatically/);
    expect(screen.getByText(STORE_BILLING_WARNING)).toBeInTheDocument();
    expect(calls()).not.toContain('delete_account');
  });

  it('shows the tunnel as down only after the server confirmed the deletion', async () => {
    await openAndConfirm();
    await waitFor(() => expect(calls()).toContain('logout'));
    // Second-pass #15: the Rust delete_account disconnects between the 2xx and
    // clearing local state; the dialog must not disconnect before asking.
    expect(calls()).not.toContain('disconnect_vpn');
    expect(mockedInvoke).toHaveBeenCalledWith('delete_account', {
      request: { password: 'hunter2' },
    });
    expect(setConnectionState).toHaveBeenCalledWith('disconnected');
    expect(logout).toHaveBeenCalled();
  });

  it('a refused deletion leaves the VPN connected', async () => {
    deleteResult = () => Promise.reject(WRONG_PASSWORD);
    await openAndConfirm();
    await screen.findByText('Incorrect password. Please try again.');
    expect(calls()).not.toContain('disconnect_vpn');
    expect(setConnectionState).not.toHaveBeenCalled();
  });

  it('shows the server refusal and signs nobody out', async () => {
    deleteResult = () => Promise.reject(WRONG_PASSWORD);
    await openAndConfirm();
    expect(await screen.findByText('Incorrect password. Please try again.')).toBeInTheDocument();
    expect(calls()).not.toContain('logout');
    expect(logout).not.toHaveBeenCalled();
  });

  it('never shows a legacy raw error string; an unclassified refusal gets a sentence about deleting', async () => {
    deleteResult = () => Promise.reject('Account deletion failed: HTTP 502 from api');
    await openAndConfirm();
    expect(
      await screen.findByText("Couldn't delete your account. Please try again."),
    ).toBeInTheDocument();
    expect(screen.queryByText(/HTTP 502/)).not.toBeInTheDocument();
    expect(logout).not.toHaveBeenCalled();
  });

  it('lists store subscriptions still billing, and OK finishes the sign-out', async () => {
    deleteResult = () =>
      Promise.resolve({ storeSubscriptionsStillBilling: ['Apple App Store', 'Google Play'] });
    await openAndConfirm();
    expect(await screen.findByText('Apple App Store')).toBeInTheDocument();
    expect(screen.getByText('Google Play')).toBeInTheDocument();
    expect(logout).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole('button', { name: /^ok$/i }));
    await waitFor(() => expect(logout).toHaveBeenCalled());
  });

  it('Escape on the notice also signs out rather than stranding a deleted account', async () => {
    deleteResult = () => Promise.resolve({ storeSubscriptionsStillBilling: ['Google Play'] });
    await openAndConfirm();
    await screen.findByText('Google Play');
    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(logout).toHaveBeenCalled());
  });

  it('names the stores the preflight reports, before anything is sent', async () => {
    preflightResult = () =>
      Promise.resolve({
        storeSubscriptionsStillBilling: ['Google Play'],
        webSubscriptionWillBeCancelled: true,
      });
    render(<Profile />);
    await userEvent.click(screen.getByRole('button', { name: /delete account/i }));
    expect(await screen.findByText(preflightStoreWarning(['Google Play']))).toBeInTheDocument();
    expect(screen.getByText(PREFLIGHT_WEB_CANCELLED)).toBeInTheDocument();
    expect(screen.queryByText(STORE_BILLING_WARNING)).not.toBeInTheDocument();
    expect(calls()).toContain('deletion_preflight');
    expect(calls()).not.toContain('delete_account');
  });

  it('a failed preflight keeps the static warning and never blocks the deletion', async () => {
    preflightResult = () => Promise.reject('Service temporarily unavailable');
    await openAndConfirm();
    await waitFor(() => expect(logout).toHaveBeenCalled());
    expect(mockedInvoke).toHaveBeenCalledWith('delete_account', {
      request: { password: 'hunter2' },
    });
  });

  it('tolerates a backend that returns nothing', async () => {
    deleteResult = () => Promise.resolve(null);
    await openAndConfirm();
    await waitFor(() => expect(logout).toHaveBeenCalled());
  });
});
