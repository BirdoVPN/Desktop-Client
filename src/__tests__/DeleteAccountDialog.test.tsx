/**
 * In-app account deletion (audit 2026-09-29: C-2 / P0-6, A-8 / C-9).
 *
 * - The store-billing warning is shown BEFORE the user confirms.
 * - The VPN is disconnected before the deletion request (Android parity).
 * - A server refusal shows the server's message and signs nobody out.
 * - Store subscriptions the server reports as still billing are listed after
 *   a confirmed deletion, and every way out of that notice signs out.
 *
 * Run: npx vitest run src/__tests__/DeleteAccountDialog.test.tsx
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { invoke } from '@tauri-apps/api/core';
import { Profile, STORE_BILLING_WARNING } from '@/screens/Profile';
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

beforeEach(() => {
  mockedInvoke.mockReset();
  logout.mockReset();
  setAuthenticated.mockReset();
  setConnectionState.mockReset();
  mockStoreState.connectionState = 'connected';
  deleteResult = () => Promise.resolve({ storeSubscriptionsStillBilling: [] });
  mockedInvoke.mockImplementation((cmd: string) => {
    if (cmd === 'delete_account') return deleteResult();
    return Promise.resolve(undefined);
  });
});

async function openAndConfirm() {
  render(<Profile />);
  await userEvent.click(screen.getByRole('button', { name: /delete account/i }));
  expect(screen.getByText(STORE_BILLING_WARNING)).toBeInTheDocument();
  await userEvent.type(screen.getByPlaceholderText('••••••••'), 'hunter2');
  await userEvent.click(screen.getByRole('button', { name: /delete forever/i }));
}

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

  it('disconnects the VPN before asking the server to delete', async () => {
    await openAndConfirm();
    await waitFor(() => expect(calls()).toContain('logout'));
    const order = calls();
    expect(order.indexOf('disconnect_vpn')).toBeGreaterThanOrEqual(0);
    expect(order.indexOf('disconnect_vpn')).toBeLessThan(order.indexOf('delete_account'));
    expect(mockedInvoke).toHaveBeenCalledWith('delete_account', {
      request: { password: 'hunter2' },
    });
    expect(setConnectionState).toHaveBeenCalledWith('disconnected');
    expect(logout).toHaveBeenCalled();
  });

  it('skips the disconnect when not connected', async () => {
    mockStoreState.connectionState = 'disconnected';
    await openAndConfirm();
    await waitFor(() => expect(calls()).toContain('delete_account'));
    expect(calls()).not.toContain('disconnect_vpn');
  });

  it('shows the server refusal and signs nobody out', async () => {
    deleteResult = () => Promise.reject('Account deletion failed: Incorrect password');
    await openAndConfirm();
    expect(
      await screen.findByText('Account deletion failed: Incorrect password'),
    ).toBeInTheDocument();
    expect(calls()).not.toContain('logout');
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

  it('tolerates a backend that returns nothing', async () => {
    deleteResult = () => Promise.resolve(null);
    await openAndConfirm();
    await waitFor(() => expect(logout).toHaveBeenCalled());
  });
});
