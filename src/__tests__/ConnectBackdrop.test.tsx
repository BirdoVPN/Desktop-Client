/**
 * No animated background behind the Connect tab (owner, 2026-10-21), as on
 * Android: BirdoNavGraph shows PixelCanvas on every route but Home, because
 * the globe is that screen's backdrop (A2-019).
 *
 *  - The window's grid is UNMOUNTED on Connect, not hidden, so nothing keeps
 *    redrawing behind the globe; it comes back on the other tabs and on the
 *    sign-in screen.
 *  - A sub-screen pushed over Connect (Plans & Pricing) brings its own grid,
 *    and the globe under it stops turning: nobody can see it.
 *
 * Run: npx vitest run src/__tests__/ConnectBackdrop.test.tsx
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, render, screen, waitFor } from '@testing-library/react';
import { invoke } from '@tauri-apps/api/core';
import App from '@/App';
import { defaultSettings, useAppStore } from '@/store/app-store';
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
vi.mock('@tauri-apps/plugin-opener', () => ({ openUrl: vi.fn() }));
vi.mock('@tauri-apps/plugin-notification', () => ({
  isPermissionGranted: vi.fn().mockResolvedValue(false),
  requestPermission: vi.fn().mockResolvedValue('denied'),
  sendNotification: vi.fn(),
}));

const mockedInvoke = vi.mocked(invoke);
let signedIn = true;

beforeEach(() => {
  signedIn = true;
  mockedInvoke.mockReset();
  mockedInvoke.mockImplementation(async (cmd: string) => {
    switch (cmd) {
      case 'check_biometric_available':
        return { available: false, enabled: false, method: 'none' };
      case 'get_auth_state':
        return { is_authenticated: signedIn, email: null, account_id: signedIn ? 'acct-test' : null, plan: null };
      default:
        return null;
    }
  });
  useAppStore.getState().logout();
  useAppStore.setState({
    acceptedConsentVersion: CONSENT_VERSION,
    settings: { ...defaultSettings },
    tab: 'home',
    notice: null,
  });
});

const grids = () => document.querySelectorAll('canvas').length;
const globeMap = () => document.querySelector<HTMLElement>('.birdo-globe__map');

describe('Connect tab backdrop', () => {
  it('has no pixel grid on Connect, and the grid comes back on the other tabs', async () => {
    render(<App />);
    await screen.findByTestId('connect-button');
    await waitFor(() => expect(grids()).toBe(0));

    act(() => useAppStore.getState().setTab('profile'));
    await waitFor(() => expect(grids()).toBe(1));

    act(() => useAppStore.getState().setTab('home'));
    await screen.findByTestId('connect-button');
    await waitFor(() => expect(grids()).toBe(0));
  });

  it('keeps the grid on the sign-in screen', async () => {
    signedIn = false;
    render(<App />);
    await screen.findByRole('button', { name: /sign in/i });
    expect(grids()).toBe(1);
  });

  it('a sub-screen over Connect brings its own grid, and the globe under it stops turning', async () => {
    render(<App />);
    await screen.findByTestId('connect-button');
    await waitFor(() => expect(grids()).toBe(0));
    expect(globeMap()?.style.animationPlayState).toBe('running');

    act(() => useAppStore.getState().pushRoute('pricing'));
    await waitFor(() => expect(globeMap()?.style.animationPlayState).toBe('paused'));
    // The pushed screen's own grid; the window's stays unmounted.
    expect(grids()).toBe(1);

    act(() => useAppStore.getState().popRoute());
    await waitFor(() => expect(globeMap()?.style.animationPlayState).toBe('running'));
    await waitFor(() => expect(grids()).toBe(0));
  });
});
