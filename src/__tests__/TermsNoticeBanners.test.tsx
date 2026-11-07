/**
 * MR-2199, the Desktop half of birdo-web #808: an account with no address on
 * file gets no e-mail about a terms change, so `GET /auth/me` names the notices
 * that apply and the Connect tab shows them until their effective date.
 *
 * The timing is why this file uses a fake clock. The 2026-10-30 notice runs for
 * about 30 days, longer than `setTimeout` can hold, and a laptop sleeps through
 * timers, so both are pinned here.
 *
 * The layout (owner, smoke test of 1.4.51, 7 November 2026: above every tab the
 * notices took a third of the window and the scroll cap cut the second off
 * mid-sentence): Connect tab only, one row clamped to two lines, Details and
 * Dismiss, "+N more" for the rest. Dismissal is kept on this device per version.
 *
 * Against the real store. Rust's tolerance for a bad `termsNotices` is pinned in
 * src-tauri/src/api/tests.rs; the link's scope in OpenerLinks.test.tsx; the shell
 * not drawing it in AppShellClientConfig.test.tsx; its place among the Home
 * banners in HomeBanners.test.tsx.
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
const LINK = 'Details';
const DISMISS = 'Dismiss';
const STORAGE = 'birdo-vpn-storage';

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
/** Each button by the name a user hears: its label, or its text. */
const buttons = () => screen.queryAllByRole('button').map((b) => b.getAttribute('aria-label') ?? b.textContent);
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
  // Kept across sign-out on purpose (this device's), so each test starts clean.
  useAppStore.setState({ dismissedTermsNotices: [] });
});

describe('the terms notice banners', () => {
  beforeEach(() => {
    vi.useFakeTimers({ now: T0 });
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('shows the first entry in the order sent, not the earliest by date', () => {
    hold(
      notice({ version: 'b', text: 'Second by date, first as sent.', effectiveAt: at(T0 + 40 * DAY) }),
      notice({ version: 'a', text: 'Then this.' }),
    );
    render(<TermsNoticeBanners />);
    expect(lines()).toEqual(['Second by date, first as sent.']);
  });

  it('shows the text exactly as sent', () => {
    const text = '  Two  spaces, <b>markup</b> & a date: 5 December 2026.  ';
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

  it('is one compact row: the text clamped to two lines, all of it in the tooltip, no scroll box', () => {
    const text =
      'We have changed our Terms of Service, Privacy Policy and related policies. Most changes already apply. ' +
      'The changes to who may use an account, the free-plan pause and the paid-plan connection limits take ' +
      'effect for you on 1 December 2026.';
    hold(notice({ text }));
    const { container } = render(<TermsNoticeBanners />);
    const p = container.querySelector('.birdo-banner p');
    expect(p).toHaveClass('line-clamp-2');
    expect(p).toHaveAttribute('title', text);
    // The cut is visual only: the whole sentence is in the page for a screen reader.
    expect(p?.textContent).toBe(text);
    // What cut the second notice in half on 1.4.51: a height cap that scrolls.
    expect(container.innerHTML).not.toMatch(/overflow-y-auto|overflow-auto|max-h-/);
    expect(container.querySelectorAll('.birdo-banner')).toHaveLength(1);
  });

  it('has two controls: Details and Dismiss, each described by the notice', () => {
    hold(notice());
    render(<TermsNoticeBanners />);
    expect(buttons()).toEqual([LINK, DISMISS]);
    const textId = document.querySelector('.birdo-banner p')?.id;
    expect(textId).toBeTruthy();
    expect(screen.getByRole('button', { name: LINK })).toHaveAttribute('aria-describedby', textId);
    expect(screen.getByRole('button', { name: DISMISS })).toHaveAttribute('aria-describedby', textId);
  });

  it('opens the website at the path the server named, and Details leaves the notice up', () => {
    hold(notice());
    render(<TermsNoticeBanners />);
    fireEvent.click(screen.getByRole('button', { name: LINK }));
    expect(mockedOpenUrl.mock.calls).toEqual([['https://birdo.app/legal/changes']]);
    expect(lines()).toHaveLength(1);
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
    expect(buttons()).toEqual([DISMISS]);
  });

  it("one entry's refused path leaves the other's link alone", () => {
    hold(notice({ version: 'a', path: '//evil.example' }), notice({ version: 'b' }));
    render(<TermsNoticeBanners />);
    expect(screen.queryByRole('button', { name: LINK })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: '+1 more' }));
    expect(mockedOpenUrl.mock.calls).toEqual([['https://birdo.app/legal/changes']]);

    fireEvent.click(screen.getByRole('button', { name: DISMISS }));
    expect(buttons()).toEqual([LINK, DISMISS]);
  });

  describe('more than one in force', () => {
    it('shows the first, with "+1 more" that opens the list of changes', () => {
      hold(notice({ version: 'a', text: 'First.' }), notice({ version: 'b', text: 'Second.' }));
      render(<TermsNoticeBanners />);
      expect(lines()).toEqual(['First.']);
      expect(document.querySelectorAll('.birdo-banner')).toHaveLength(1);
      expect(buttons()).toEqual([LINK, DISMISS, '+1 more']);

      fireEvent.click(screen.getByRole('button', { name: '+1 more' }));
      expect(mockedOpenUrl.mock.calls).toEqual([['https://birdo.app/legal/changes']]);
    });

    it('counts every other one', () => {
      hold(notice({ version: 'a' }), notice({ version: 'b' }), notice({ version: 'c' }));
      render(<TermsNoticeBanners />);
      expect(screen.getByRole('button', { name: '+2 more' })).toBeInTheDocument();
    });

    it('dismissing the first brings up the next, and "+N more" goes with the last', () => {
      hold(notice({ version: 'a', text: 'First.' }), notice({ version: 'b', text: 'Second.' }));
      render(<TermsNoticeBanners />);
      fireEvent.click(screen.getByRole('button', { name: DISMISS }));
      expect(lines()).toEqual(['Second.']);
      expect(screen.queryByRole('button', { name: /more$/ })).not.toBeInTheDocument();
    });

    it('a dismissed one is not counted', () => {
      useAppStore.getState().dismissTermsNotice('b');
      hold(notice({ version: 'a', text: 'First.' }), notice({ version: 'b', text: 'Second.' }));
      render(<TermsNoticeBanners />);
      expect(lines()).toEqual(['First.']);
      expect(buttons()).toEqual([LINK, DISMISS]);
    });

    it('with no readable link among the rest, "+1 more" falls back to the first one\'s', () => {
      hold(notice({ version: 'a' }), notice({ version: 'b', path: null }));
      render(<TermsNoticeBanners />);
      fireEvent.click(screen.getByRole('button', { name: '+1 more' }));
      expect(mockedOpenUrl.mock.calls).toEqual([['https://birdo.app/legal/changes']]);
    });

    it('with no readable link at all, "+1 more" is said, not offered', () => {
      hold(notice({ version: 'a', path: null }), notice({ version: 'b', path: '' }));
      render(<TermsNoticeBanners />);
      expect(buttons()).toEqual([DISMISS]);
      expect(screen.getByText('+1 more')).toBeInTheDocument();
    });
  });

  describe('Dismiss', () => {
    it('hides that version, and it stays hidden after a remount', () => {
      hold(notice({ version: 'v1' }));
      const first = render(<TermsNoticeBanners />);
      fireEvent.click(screen.getByRole('button', { name: DISMISS }));
      expect(lines()).toEqual([]);
      expect(useAppStore.getState().dismissedTermsNotices).toEqual(['v1']);

      first.unmount();
      const { container } = render(<TermsNoticeBanners />);
      expect(container).toBeEmptyDOMElement();
    });

    it('stays hidden after a restart: the version is kept in the local store, the text is not', async () => {
      hold(notice({ version: 'v1', text: 'Marker-for-the-dismiss-check.' }));
      render(<TermsNoticeBanners />);
      fireEvent.click(screen.getByRole('button', { name: DISMISS }));

      const blob = localStorage.getItem(STORAGE) ?? '{}';
      expect(JSON.parse(blob).state.dismissedTermsNotices).toEqual(['v1']);
      expect(blob).not.toContain('Marker-for-the-dismiss-check');

      // A restart: memory empty, the stored blob read back.
      useAppStore.setState({ dismissedTermsNotices: [] });
      localStorage.setItem(STORAGE, blob);
      await act(() => useAppStore.persist.rehydrate());
      expect(useAppStore.getState().dismissedTermsNotices).toEqual(['v1']);
      expect(lines()).toEqual([]);
    });

    it('a new version shows again', () => {
      hold(notice({ version: 'v1', text: 'Old.' }));
      render(<TermsNoticeBanners />);
      fireEvent.click(screen.getByRole('button', { name: DISMISS }));
      expect(lines()).toEqual([]);

      act(() => hold(notice({ version: 'v2', text: 'New.' })));
      expect(lines()).toEqual(['New.']);
    });

    it('is this device\'s: kept across sign-out', () => {
      hold(notice({ version: 'v1' }));
      render(<TermsNoticeBanners />);
      fireEvent.click(screen.getByRole('button', { name: DISMISS }));
      act(() => useAppStore.getState().logout());
      act(() => hold(notice({ version: 'v1' })));
      expect(lines()).toEqual([]);
    });

    it('keeps a bounded list, newest last', () => {
      for (let i = 0; i < 25; i++) useAppStore.getState().dismissTermsNotice(`v${i}`);
      useAppStore.getState().dismissTermsNotice('v24');
      const kept = useAppStore.getState().dismissedTermsNotices;
      expect(kept).toHaveLength(20);
      expect(kept[0]).toBe('v5');
      expect(kept[kept.length - 1]).toBe('v24');
    });

    it('arms no timer for a notice that is not shown', () => {
      hold(notice({ version: 'v1', effectiveAt: at(T0 + HOUR) }));
      render(<TermsNoticeBanners />);
      expect(vi.getTimerCount()).toBe(1);
      fireEvent.click(screen.getByRole('button', { name: DISMISS }));
      expect(vi.getTimerCount()).toBe(0);
    });
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
    expect(lines()).toEqual(['Late.']);
    expect(screen.getByRole('button', { name: '+1 more' })).toBeInTheDocument();
    advance(HOUR);
    expect(lines()).toEqual(['Late.']);
    expect(screen.queryByRole('button', { name: '+1 more' })).not.toBeInTheDocument();
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
    expect(screen.queryByRole('button', { name: /more$/ })).not.toBeInTheDocument();
  });

  it('calls nothing: no acknowledgement, no fetch, on show, click, dismissal or expiry', () => {
    hold(notice({ version: 'a', effectiveAt: at(T0 + HOUR) }), notice({ version: 'b', effectiveAt: at(T0 + HOUR) }));
    render(<TermsNoticeBanners />);
    fireEvent.click(screen.getByRole('button', { name: LINK }));
    fireEvent.click(screen.getByRole('button', { name: '+1 more' }));
    fireEvent.click(screen.getByRole('button', { name: DISMISS }));
    advance(HOUR);
    expect(lines()).toEqual([]);
    expect(mockedInvoke).not.toHaveBeenCalled();
  });

  it('is kept in memory only, and ends with the session', () => {
    hold(notice({ text: 'Marker-for-the-storage-check.' }));
    // The store's persist middleware writes on every change.
    expect(localStorage.getItem(STORAGE)).not.toBeNull();
    expect(localStorage.getItem(STORAGE)).not.toContain('Marker-for-the-storage-check');

    useAppStore.getState().logout();
    expect(useAppStore.getState().account.termsNotices).toEqual([]);
  });
});

describe('from get_auth_state to the Connect tab', () => {
  it('shows what the answer carried on Connect, and on no other tab', async () => {
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

    for (const [tab, label] of [
      ['settings', 'Settings'],
      ['profile', 'Profile'],
      ['limit', 'Limit'],
    ] as const) {
      act(() => useAppStore.getState().setTab(tab));
      expect(screen.getByRole('tab', { name: label, selected: true })).toBeInTheDocument();
      expect(screen.queryByText('From the profile.')).not.toBeInTheDocument();
    }

    act(() => useAppStore.getState().setTab('home'));
    expect(await screen.findByText('From the profile.')).toBeInTheDocument();
  });
});
