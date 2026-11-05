/**
 * MR-2199, the Desktop half of birdo-web #808: an account with no address on
 * file gets no e-mail about a terms change, so `GET /auth/me` names the notices
 * that apply and the signed-in shell shows them until their effective date.
 *
 * The timing is why this file uses a fake clock. The 2026-10-30 notice runs for
 * about 30 days, longer than `setTimeout` can hold, and a laptop sleeps through
 * timers, so both are pinned here.
 *
 * Against the real store. Rust's tolerance for a bad `termsNotices` is pinned in
 * src-tauri/src/api/tests.rs; the link's scope in OpenerLinks.test.tsx.
 *
 * Run: npx vitest run src/__tests__/TermsNoticeBanners.test.tsx
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen } from '@testing-library/react';
import { invoke } from '@tauri-apps/api/core';
import { openUrl } from '@tauri-apps/plugin-opener';
import App from '@/App';
import { TERMS_NOTICE_TICK_MS, TermsNoticeBanners } from '@/components/TermsNoticeBanners';
import { CONSENT_VERSION } from '@/lib/consent';
import { defaultSettings, useAppStore, type TermsNotice } from '@/store/app-store';

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
vi.mock('@tauri-apps/plugin-opener', () => ({ openUrl: vi.fn().mockResolvedValue(undefined) }));
vi.mock('@tauri-apps/plugin-notification', () => ({
  isPermissionGranted: vi.fn().mockResolvedValue(false),
  requestPermission: vi.fn().mockResolvedValue('denied'),
  sendNotification: vi.fn(),
}));

const mockedInvoke = vi.mocked(invoke);
const mockedOpenUrl = vi.mocked(openUrl);

const T0 = Date.parse('2026-11-05T12:00:00.000Z');
const HOUR = 60 * 60_000;
const DAY = 24 * HOUR;
const LINK = 'See every change';

const at = (ms: number) => new Date(ms).toISOString();
const notice = (over: Partial<TermsNotice> = {}): TermsNotice => ({
  version: '2026-10-30',
  text: 'We have changed our Terms of Service.',
  effectiveAt: at(T0 + 30 * DAY),
  path: '/legal/changes',
  ...over,
});
const hold = (...termsNotices: TermsNotice[]) => useAppStore.getState().setAccount({ termsNotices });
const lines = () => [...document.querySelectorAll('.birdo-banner p')].map((p) => p.textContent);
/** An `act` per tick, as in the app: each next timer is armed by the render the last one caused. */
const advance = (ms: number) => {
  for (let left = ms; left > 0; left -= TERMS_NOTICE_TICK_MS) {
    act(() => vi.advanceTimersByTime(Math.min(left, TERMS_NOTICE_TICK_MS)));
  }
};

beforeEach(() => {
  mockedInvoke.mockReset();
  mockedOpenUrl.mockClear();
  useAppStore.getState().logout();
});

describe('the terms notice banners', () => {
  beforeEach(() => {
    vi.useFakeTimers({ now: T0 });
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('shows one line per entry, in the order sent', () => {
    hold(notice({ version: 'b', text: 'Second by date, first as sent.' }), notice({ version: 'a', text: 'Then this.' }));
    render(<TermsNoticeBanners />);
    expect(lines()).toEqual(['Second by date, first as sent.', 'Then this.']);
  });

  it('shows the text exactly as sent', () => {
    const text = '  Two  spaces, <b>markup</b> & a date: 5 December 2026.  ';
    hold(notice({ text }));
    render(<TermsNoticeBanners />);
    expect(lines()).toEqual([text]);
    expect(document.querySelector('.birdo-banner b')).toBeNull();
  });

  it('takes no room at all when no notice applies', () => {
    const { container } = render(<TermsNoticeBanners />);
    expect(container).toBeEmptyDOMElement();
  });

  it('is neutral, never red', () => {
    hold(notice());
    render(<TermsNoticeBanners />);
    const html = document.querySelector('.birdo-banner')?.outerHTML.toLowerCase() ?? '';
    expect(html).not.toBe('');
    expect(html).not.toContain('#f87171');
    expect(html.replace(/\s/g, '')).not.toContain('248,113,113');
  });

  it('cannot be dismissed: the one control is the link', () => {
    hold(notice());
    render(<TermsNoticeBanners />);
    expect(screen.getAllByRole('button').map((b) => b.textContent)).toEqual([LINK]);
    fireEvent.click(screen.getByRole('button', { name: LINK }));
    expect(lines()).toHaveLength(1);
  });

  it('opens the website at the path the server named', () => {
    hold(notice());
    render(<TermsNoticeBanners />);
    fireEvent.click(screen.getByRole('button', { name: LINK }));
    expect(mockedOpenUrl.mock.calls).toEqual([['https://birdo.app/legal/changes']]);
  });

  it.each([
    ['another host', '//evil.example/legal'],
    ['a scheme', 'https://evil.example/legal'],
    ['no leading slash', 'legal/changes'],
    ['whitespace', '/legal/ changes'],
    ['a backslash', '/\\evil.example'],
    ['empty', ''],
    ['nothing Rust could read', null],
  ])('a refused path (%s) keeps the text and has no link', (_name, path) => {
    hold(notice({ path }));
    render(<TermsNoticeBanners />);
    expect(lines()).toHaveLength(1);
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });

  it("one entry's refused path leaves the other's link alone", () => {
    hold(notice({ version: 'a', path: '//evil.example' }), notice({ version: 'b' }));
    render(<TermsNoticeBanners />);
    expect(lines()).toHaveLength(2);
    expect(screen.getAllByRole('button', { name: LINK })).toHaveLength(1);
  });

  it('goes the moment the time reaches effectiveAt, with the app open', () => {
    hold(notice({ effectiveAt: at(T0 + 90_000) }));
    render(<TermsNoticeBanners />);
    advance(89_999);
    expect(lines()).toHaveLength(1);
    advance(1);
    expect(lines()).toEqual([]);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('is not shown at or after effectiveAt', () => {
    hold(notice({ version: 'now', effectiveAt: at(T0) }), notice({ version: 'past', effectiveAt: at(T0 - 1) }));
    render(<TermsNoticeBanners />);
    expect(lines()).toEqual([]);
  });

  it('drops each entry at its own date', () => {
    hold(
      notice({ version: 'late', text: 'Late.', effectiveAt: at(T0 + 3 * HOUR) }),
      notice({ version: 'early', text: 'Early.', effectiveAt: at(T0 + HOUR) }),
    );
    render(<TermsNoticeBanners />);
    expect(lines()).toEqual(['Late.', 'Early.']);
    advance(HOUR);
    expect(lines()).toEqual(['Late.']);
    advance(2 * HOUR);
    expect(lines()).toEqual([]);
  });

  it('holds a date further off than setTimeout can reach', () => {
    const setTimeoutSpy = vi.spyOn(globalThis, 'setTimeout');
    hold(notice());
    render(<TermsNoticeBanners />);
    advance(HOUR);
    expect(lines()).toHaveLength(1);
    // Once a minute, not the storm a 30-day delay would be (it fires at once).
    const delays = setTimeoutSpy.mock.calls.map(([, ms]) => ms ?? 0);
    expect(Math.max(...delays)).toBe(TERMS_NOTICE_TICK_MS);
    expect(delays).toHaveLength(61);
    setTimeoutSpy.mockRestore();
  });

  it('a machine that slept past the date drops it within a tick of waking', () => {
    hold(notice({ effectiveAt: at(T0 + 2 * HOUR) }));
    render(<TermsNoticeBanners />);
    // The clock moved and no timer ran: what sleep does.
    vi.setSystemTime(T0 + 9 * HOUR);
    advance(TERMS_NOTICE_TICK_MS);
    expect(lines()).toEqual([]);
  });

  it.each([
    '',
    'soon',
    '2099',
    'December 5, 2099',
    '5 Dec 2099',
    '2099-12-05',
    '2099-12-05T00:00:00',
    '2099-13-45T00:00:00.000Z',
  ])('does not show an entry whose effectiveAt is bad (%j)', (effectiveAt) => {
    hold(notice({ effectiveAt }));
    render(<TermsNoticeBanners />);
    expect(lines()).toEqual([]);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('a bad entry does not take a good one with it', () => {
    hold(notice({ version: 'bad', effectiveAt: 'soon' }), notice({ version: 'blank', text: '  ' }), notice({ text: 'Good.' }));
    render(<TermsNoticeBanners />);
    expect(lines()).toEqual(['Good.']);
  });

  it('calls nothing: no acknowledgement, no fetch, on show, click or expiry', () => {
    hold(notice({ effectiveAt: at(T0 + HOUR) }));
    render(<TermsNoticeBanners />);
    fireEvent.click(screen.getByRole('button', { name: LINK }));
    advance(HOUR);
    expect(lines()).toEqual([]);
    expect(mockedInvoke).not.toHaveBeenCalled();
  });

  it('is kept in memory only, and ends with the session', () => {
    hold(notice({ text: 'Marker-for-the-storage-check.' }));
    // The store's persist middleware writes on every change.
    expect(localStorage.getItem('birdo-vpn-storage')).not.toBeNull();
    expect(localStorage.getItem('birdo-vpn-storage')).not.toContain('Marker-for-the-storage-check');

    useAppStore.getState().logout();
    expect(useAppStore.getState().account.termsNotices).toEqual([]);
  });
});

describe('from get_auth_state to the shell', () => {
  it('shows what the answer carried', async () => {
    mockedInvoke.mockImplementation(async (cmd: string) => {
      switch (cmd) {
        case 'check_biometric_available':
          return { available: false, enabled: false, method: 'none' };
        case 'get_auth_state':
          return {
            is_authenticated: true,
            email: 'member@anonymous.local',
            account_id: 'acct-test',
            plan: null,
            terms_notices: [notice({ effectiveAt: '2099-12-05T00:00:00.000Z', text: 'From the profile.' })],
          };
        default:
          return null;
      }
    });
    useAppStore.setState({ acceptedConsentVersion: CONSENT_VERSION, settings: { ...defaultSettings }, tab: 'home' });

    render(<App />);

    expect(await screen.findByText('From the profile.', {}, { timeout: 5000 })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: LINK })).toBeInTheDocument();
  });
});
