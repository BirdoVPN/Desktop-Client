/**
 * Settings › About › Licences (MR-1685): the row opens the Licences screen,
 * which shows the notices file the package ships (read by Rust's
 * `get_third_party_notices`), and says so plainly when a build has none.
 *
 * Run: npx vitest run src/__tests__/Licences.test.tsx
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { invoke } from '@tauri-apps/api/core';
import { Settings } from '@/components/Settings';
import { Licences, NOTICES_MISSING_COPY } from '@/screens/Licences';
import { defaultSettings, useAppStore } from '@/store/app-store';
import { resetUpdater } from '@/session/updater';

vi.mock('@tauri-apps/api/core');
vi.mock('@tauri-apps/plugin-shell', () => ({ open: vi.fn().mockResolvedValue(undefined) }));
vi.mock('@tauri-apps/plugin-process', () => ({ relaunch: vi.fn() }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn(async () => () => {}) }));

const mockedInvoke = vi.mocked(invoke);
const NOTICES = 'THIRD-PARTY SOFTWARE NOTICES - BirdoVPN\n\nXray-core v26.3.27\n  source: https://github.com/XTLS/Xray-core at v26.3.27';

beforeEach(() => {
  resetUpdater();
  useAppStore.getState().logout();
  useAppStore.setState({ isAuthenticated: true, settings: { ...defaultSettings }, navStack: [] });
  mockedInvoke.mockReset();
  mockedInvoke.mockImplementation(async (cmd: string) => {
    if (cmd === 'check_biometric_available') return { available: false, enabled: false, method: 'none' };
    if (cmd === 'get_app_version') return '1.4.47';
    if (cmd === 'get_third_party_notices') return NOTICES;
    return undefined;
  });
});

describe('Licences (MR-1685)', () => {
  it('is a row in Settings › About that opens the Licences screen', async () => {
    render(<Settings />);
    await userEvent.click(screen.getByRole('button', { name: /Licences/ }));
    expect(useAppStore.getState().navStack).toEqual(['licences']);
  });

  it('shows the notices the package ships, read through get_third_party_notices', async () => {
    render(<Licences />);
    const notices = await screen.findByLabelText('Third-party software notices');
    expect(notices.textContent).toBe(NOTICES);
    expect(mockedInvoke).toHaveBeenCalledWith('get_third_party_notices');
  });

  it('says the notices are missing when the build bundled none', async () => {
    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === 'get_third_party_notices') throw { code: 'unknown', message: 'not in this build' };
      return undefined;
    });
    render(<Licences />);
    expect(await screen.findByText(NOTICES_MISSING_COPY)).toBeInTheDocument();
    expect(screen.queryByLabelText('Third-party software notices')).not.toBeInTheDocument();
  });

  it('goes back with the top bar', async () => {
    useAppStore.setState({ navStack: ['licences'] });
    render(<Licences />);
    await userEvent.click(screen.getByRole('button', { name: 'Back' }));
    expect(useAppStore.getState().navStack).toEqual([]);
  });
});
