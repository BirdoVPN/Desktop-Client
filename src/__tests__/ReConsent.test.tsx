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
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { invoke } from '@tauri-apps/api/core';
import { exit } from '@tauri-apps/plugin-process';
import App from '@/App';
import { defaultSettings, useAppStore } from '@/store/app-store';
import { CONSENT_VERSION } from '@/lib/consent';
import { CONSENT_NOT_SAVED_COPY, CONSENT_RESAVED_COPY } from '@/session/consent-sync';

// Start Minimized keeps the window hidden at launch (REVIEW-WIN2-010).
const appWindow = vi.hoisted(() => ({ visible: true }));

vi.mock('@tauri-apps/api/core');
// A scripted event bus: a test emits what Rust would.
const handlers = vi.hoisted(() => new Map<string, Set<(e: { payload: unknown }) => void>>());
vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn(async (name: string, cb: (e: { payload: unknown }) => void) => {
    if (!handlers.has(name)) handlers.set(name, new Set());
    handlers.get(name)!.add(cb);
    return () => handlers.get(name)?.delete(cb);
  }),
}));
async function emit(name: string, payload?: unknown) {
  await act(async () => {
    handlers.get(name)?.forEach((cb) => cb({ payload }));
  });
}
vi.mock('@tauri-apps/api/window', () => ({
  getCurrentWindow: () => ({
    isVisible: async () => appWindow.visible,
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
const callsTo = (cmd: string) => mockedInvoke.mock.calls.filter(([c]) => c === cmd);

beforeEach(() => {
  handlers.clear();
  appWindow.visible = true;
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
  useAppStore.setState({ notice: null });
});

const agree = () => screen.findByRole('button', { name: /i agree & continue/i });

describe('versioned re-consent (D7)', () => {
  it('a user who accepted the older text sees the current one, and nothing asks the server first', async () => {
    useAppStore.setState({ acceptedConsentVersion: 1 });
    render(<App />);
    await userEvent.click(await agree());

    expect(useAppStore.getState().acceptedConsentVersion).toBe(CONSENT_VERSION);
    await waitFor(() => expect(callsTo('get_auth_state')).toHaveLength(1));
    // The screen leaves through its exit animation, which can outlast the
    // sign-in check under a loaded test run.
    await waitFor(() =>
      expect(screen.queryByRole('button', { name: /i agree & continue/i })).not.toBeInTheDocument(),
    );
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

  it('behind Start Minimized, the consent the app waits for brings the window up (REVIEW-WIN2-010)', async () => {
    appWindow.visible = false;
    useAppStore.setState({ acceptedConsentVersion: 1 });
    render(<App />);
    await agree();
    await waitFor(() => expect(callsTo('show_main_window')).toHaveLength(1));
  });

  it('a visible window, or nothing to answer, is left alone', async () => {
    useAppStore.setState({ acceptedConsentVersion: 1 });
    const { unmount } = render(<App />);
    await agree();
    unmount();

    appWindow.visible = false;
    useAppStore.setState({ acceptedConsentVersion: CONSENT_VERSION });
    render(<App />);
    await waitFor(() => expect(callsTo('get_auth_state')).toHaveLength(1));
    expect(callsTo('show_main_window')).toHaveLength(0);
  });
});

/**
 * MR-1607: Rust keeps its own record of the consent accepted, which the tray's
 * Quick Connect asks before it dials (it used to dial behind the consent
 * screen). The store writes it whenever it holds the current text; a refused
 * tray connect brings the window up on the consent screen, or repairs a
 * record that fell behind.
 */
describe("Rust's consent record (MR-1607)", () => {
  /** Rust's record answers what it holds after the write. */
  function answerRecord(answer: (version: number) => unknown) {
    const scripted = mockedInvoke.getMockImplementation();
    mockedInvoke.mockImplementation(async (cmd, args, options) =>
      cmd === 'record_consent' ? answer((args as { version: number }).version) : scripted?.(cmd, args, options),
    );
  }

  it('an install that accepted this text in an earlier build is migrated at start, with no second consent screen', async () => {
    answerRecord((v) => v);
    useAppStore.setState({ acceptedConsentVersion: CONSENT_VERSION });
    render(<App />);
    await waitFor(() => expect(callsTo('record_consent')).toEqual([['record_consent', { version: CONSENT_VERSION }]]));
    await waitFor(() => expect(callsTo('get_auth_state')).toHaveLength(1));
    expect(screen.queryByRole('button', { name: /i agree & continue/i })).not.toBeInTheDocument();
  });

  // MR-2016: an older acceptance is written as it is, which takes Rust's
  // record down with it, so the tray waits for the consent screen; then the
  // accept writes the current text. On main nothing was written until the
  // accept, and a record left at the current text kept the tray dialling.
  it('an older acceptance takes the record down at start, and the accept writes the current text', async () => {
    answerRecord((v) => v);
    useAppStore.setState({ acceptedConsentVersion: 1 });
    render(<App />);
    const button = await agree();
    await waitFor(() => expect(callsTo('record_consent')).toEqual([['record_consent', { version: 1 }]]));
    await userEvent.click(button);
    await waitFor(() =>
      expect(callsTo('record_consent')).toEqual([
        ['record_consent', { version: 1 }],
        ['record_consent', { version: CONSENT_VERSION }],
      ]),
    );
  });

  // MR-2016: the webview lost its storage (no acceptance at all) while Rust's
  // record still says accepted: the consent screen is up, and the start-up
  // write takes the record to 0, so the tray's Quick Connect is refused.
  it('a webview that lost its consent takes the record down with it', async () => {
    answerRecord((v) => v);
    useAppStore.setState({ acceptedConsentVersion: 0 });
    render(<App />);
    await agree();
    await waitFor(() => expect(callsTo('record_consent')).toEqual([['record_consent', { version: 0 }]]));
  });

  it('a tray Quick Connect refused behind the consent screen leaves the screen up and writes nothing more', async () => {
    answerRecord((v) => v);
    useAppStore.setState({ acceptedConsentVersion: 1 });
    render(<App />);
    await agree();
    await waitFor(() => expect(callsTo('record_consent')).toHaveLength(1));
    await emit('consent-required');
    expect(callsTo('record_consent')).toHaveLength(1);
    expect(useAppStore.getState().notice).toBeNull();
    expect(screen.getByRole('button', { name: /i agree & continue/i })).toBeInTheDocument();
  });

  it("a refusal over a record that fell behind writes it again, and says to try again", async () => {
    answerRecord((v) => v);
    useAppStore.setState({ acceptedConsentVersion: CONSENT_VERSION });
    render(<App />);
    await waitFor(() => expect(callsTo('record_consent')).toHaveLength(1));
    await emit('consent-required');
    await waitFor(() => expect(useAppStore.getState().notice?.text).toBe(CONSENT_RESAVED_COPY));
    expect(callsTo('record_consent')).toHaveLength(2);
  });

  it('a record Rust still cannot write is said plainly', async () => {
    answerRecord(() => {
      throw { code: 'unknown', message: 'disk full', retryable: true };
    });
    useAppStore.setState({ acceptedConsentVersion: CONSENT_VERSION });
    render(<App />);
    await waitFor(() => expect(callsTo('record_consent')).toHaveLength(1));
    await emit('consent-required');
    await waitFor(() => expect(useAppStore.getState().notice?.text).toBe(CONSENT_NOT_SAVED_COPY));
  });
});

// MR-1516 (owner decision 2026-10-07): a re-consent's crash-report toggle
// starts from the stored choice. It used to start OFF every time, so accepting
// a newer text quietly turned reports off for a user who had turned them on.
describe('the crash-report toggle on a re-consent (MR-1516)', () => {
  const crashToggle = () => screen.findByRole('switch', { name: /send crash reports/i });

  it('starts from the stored choice, and accepting keeps it', async () => {
    useAppStore.setState({ acceptedConsentVersion: 1, settings: { ...defaultSettings, crashReportsEnabled: true } });
    render(<App />);
    expect(await crashToggle()).toHaveAttribute('aria-checked', 'true');
    await userEvent.click(await agree());
    await waitFor(() => expect(callsTo('set_crash_reports_enabled')).toEqual([['set_crash_reports_enabled', { enabled: true }]]));
  });

  it('a first consent still starts OFF, whatever the store holds', async () => {
    useAppStore.setState({ acceptedConsentVersion: 0, settings: { ...defaultSettings, crashReportsEnabled: true } });
    render(<App />);
    expect(await crashToggle()).toHaveAttribute('aria-checked', 'false');
  });

  it('a stored OFF stays OFF', async () => {
    useAppStore.setState({ acceptedConsentVersion: 1, settings: { ...defaultSettings, crashReportsEnabled: false } });
    render(<App />);
    expect(await crashToggle()).toHaveAttribute('aria-checked', 'false');
  });
});
