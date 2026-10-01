/**
 * Versioned re-consent (owner decision D7).
 *
 * The consent flag used to be a boolean, so a user who accepted one text never
 * saw the next. The store now keeps the VERSION accepted; an existing user
 * (the old boolean, migrated to version 1) sees the current text exactly once,
 * nothing asks the server who they are before they accept, and Decline still
 * quits.
 *
 * Run: npx vitest run src/__tests__/ReConsent.test.tsx
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { invoke } from '@tauri-apps/api/core';
import { exit } from '@tauri-apps/plugin-process';
import App from '@/App';
import { useAppStore } from '@/store/app-store';
import { CONSENT_VERSION } from '@/lib/consent';

vi.mock('@tauri-apps/api/core');
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn(async () => () => {}) }));
vi.mock('@tauri-apps/api/window', () => ({
  getCurrentWindow: () => ({
    isVisible: async () => true,
    onScaleChanged: async () => () => {},
    setDecorations: async () => {},
    setSize: async () => {},
    setPosition: async () => {},
    minimize: async () => {},
    close: async () => {},
  }),
  currentMonitor: async () => null,
  primaryMonitor: async () => null,
}));
vi.mock('@tauri-apps/plugin-process', () => ({ exit: vi.fn().mockResolvedValue(undefined), relaunch: vi.fn() }));
vi.mock('@tauri-apps/plugin-shell', () => ({ open: vi.fn() }));
vi.mock('@tauri-apps/plugin-notification', () => ({
  isPermissionGranted: vi.fn().mockResolvedValue(false),
  requestPermission: vi.fn().mockResolvedValue('denied'),
  sendNotification: vi.fn(),
}));

const mockedInvoke = vi.mocked(invoke);
const callsTo = (cmd: string) => mockedInvoke.mock.calls.filter(([c]) => c === cmd);

beforeEach(() => {
  vi.mocked(exit).mockClear();
  mockedInvoke.mockReset();
  mockedInvoke.mockImplementation(async (cmd: string) => {
    switch (cmd) {
      case 'check_biometric_available':
        return { available: false, enabled: false, method: 'none' };
      case 'get_auth_state':
        return { is_authenticated: false, email: null, account_id: null, plan: null };
      default:
        return null;
    }
  });
  useAppStore.getState().logout();
});

const agree = () => screen.findByRole('button', { name: /i agree & continue/i });

describe('versioned re-consent (D7)', () => {
  it('a user who accepted the older text sees the current one, and nothing asks the server first', async () => {
    useAppStore.setState({ acceptedConsentVersion: 1 });
    render(<App />);
    await userEvent.click(await agree());

    expect(useAppStore.getState().acceptedConsentVersion).toBe(CONSENT_VERSION);
    await waitFor(() => expect(callsTo('get_auth_state')).toHaveLength(1));
    expect(screen.queryByRole('button', { name: /i agree & continue/i })).not.toBeInTheDocument();
  });

  it('holds the sign-in check until the user has answered', async () => {
    useAppStore.setState({ acceptedConsentVersion: 1 });
    render(<App />);
    await agree();
    expect(callsTo('get_auth_state')).toHaveLength(0);
  });

  it('declining the new text still quits', async () => {
    useAppStore.setState({ acceptedConsentVersion: 1 });
    render(<App />);
    await userEvent.click(await screen.findByRole('button', { name: /^decline$/i }));
    await waitFor(() => expect(exit).toHaveBeenCalledWith(0));
    expect(callsTo('get_auth_state')).toHaveLength(0);
    expect(useAppStore.getState().acceptedConsentVersion).toBe(1);
  });

  it('the current version is asked for once: no screen on the next start', async () => {
    useAppStore.setState({ acceptedConsentVersion: CONSENT_VERSION });
    render(<App />);
    await waitFor(() => expect(callsTo('get_auth_state')).toHaveLength(1));
    expect(screen.queryByRole('button', { name: /i agree & continue/i })).not.toBeInTheDocument();
  });
});
