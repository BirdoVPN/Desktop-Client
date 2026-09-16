/**
 * `useClientConfig` -- the BirdoShield fleet-gate fetch (PR #162 review, must-fix 2).
 *
 * THE GAP THIS FILLS: before this file, the decision the whole PR is about --
 * "an unknown answer means AVAILABLE" -- had no test anywhere. The reviewer
 * inverted all three guards at once (the `typeof === 'boolean'` check to
 * `true`, the setter to `!!cfg?.dnsFilteringAvailable`, and the silent
 * `.catch()` to `setDnsFilteringAvailable(false)`) and the full 156-test suite
 * stayed green. That mutant is exactly the failure the PR says cannot happen:
 * an offline client, or one talking to a web deploy that predates
 * birdo-web#465, hiding a feature that works and silently dropping the
 * filtering the user chose.
 *
 * These tests run against the REAL store, not a mock, so the store default,
 * the setter and the guards are wired end to end; `BirdoShieldToggle.test.tsx`
 * stubs the store module and therefore cannot reach any of this.
 *
 * Run: npx vitest run src/__tests__/useClientConfig.test.tsx
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, waitFor, act } from '@testing-library/react';
import { invoke } from '@tauri-apps/api/core';
import {
  useClientConfig,
  GATE_REFETCH_MIN_INTERVAL_MS,
  GATE_POLL_INTERVAL_MS,
} from '@/hooks/useClientConfig';
import { useAppStore } from '@/store/app-store';

vi.mock('@tauri-apps/api/core');

// The hook subscribes to the `app-shown` Tauri event (tray restore). The mock
// hands the registered handler back so a test can fire a restore, and records
// whether the hook unsubscribed.
// `vi.hoisted` because the factory runs while the module graph is imported,
// before any plain `const` in this file has been initialised.
const tray = vi.hoisted(() => ({
  shownHandlers: [] as Array<() => void>,
  unlistenCalls: 0,
}));
vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn(async (event: string, handler: () => void) => {
    if (event === 'app-shown') tray.shownHandlers.push(handler);
    return () => {
      tray.unlistenCalls += 1;
    };
  }),
}));

const mockedInvoke = vi.mocked(invoke);

const gate = () => useAppStore.getState().dnsFilteringAvailable;

/**
 * Drive the effect and wait until the fetch has actually settled, so a "still
 * available" assertion is a real observation and not just a race the test won.
 */
async function runHook() {
  renderHook(() => useClientConfig());
  await waitFor(() => expect(mockedInvoke).toHaveBeenCalledTimes(1));
  // Flush the .then/.catch microtasks queued by the settled invoke promise.
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

// The hook throttles on Date.now(), so the clock is driven explicitly rather
// than slept through.
let clock = 1_700_000_000_000;
let dateNowSpy: ReturnType<typeof vi.spyOn> | undefined;
const advance = (ms: number) => {
  clock += ms;
};

beforeEach(() => {
  mockedInvoke.mockReset();
  tray.shownHandlers.length = 0;
  tray.unlistenCalls = 0;
  clock = 1_700_000_000_000;
  dateNowSpy = vi.spyOn(Date, 'now').mockImplementation(() => clock);
  setHidden(false);
  // The shipped default. Every "unknown" case below asserts this survives.
  useAppStore.setState({ dnsFilteringAvailable: true });
});

afterEach(() => {
  dateNowSpy?.mockRestore();
  setHidden(false);
});

/** jsdom leaves `document.hidden` a fixed `false`; make it settable. */
function setHidden(hidden: boolean) {
  Object.defineProperty(document, 'hidden', {
    configurable: true,
    get: () => hidden,
  });
}

/** Fire the DOM event the browser fires when the window is shown or hidden. */
function fireVisibilityChange(hidden: boolean) {
  setHidden(hidden);
  act(() => {
    document.dispatchEvent(new Event('visibilitychange'));
  });
}

/** Alt-tab back to the window. */
function fireWindowFocus() {
  act(() => {
    window.dispatchEvent(new Event('focus'));
  });
}

/** What `restore_and_focus` in src-tauri/src/main.rs emits on a tray restore. */
function fireTrayRestore() {
  act(() => {
    tray.shownHandlers.forEach((h) => h());
  });
}

/** Let the .then/.catch of any fetch just started settle. */
async function flush() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

describe('useClientConfig -> dnsFilteringAvailable', () => {
  it('asks the Rust side for the client config exactly once per mount', async () => {
    mockedInvoke.mockResolvedValue({ dnsFilteringAvailable: true });
    await runHook();
    expect(mockedInvoke).toHaveBeenCalledTimes(1);
    expect(mockedInvoke).toHaveBeenCalledWith('get_client_config');
  });

  it('an explicit false from the server disables the gate', async () => {
    mockedInvoke.mockResolvedValue({ dnsFilteringAvailable: false });
    await runHook();
    expect(gate()).toBe(false);
  });

  it('an explicit true re-enables it', async () => {
    useAppStore.setState({ dnsFilteringAvailable: false });
    mockedInvoke.mockResolvedValue({ dnsFilteringAvailable: true });
    await runHook();
    expect(gate()).toBe(true);
  });

  // ── Unknown must never read as "off" ────────────────────────────────────
  //
  // WHAT THESE ACTUALLY KILL, measured rather than assumed (PR #162 review,
  // must-fix 3 -- the PR body used to credit the setter edit on its own):
  //
  //  - `typeof … === 'boolean'` -> `true`, setter untouched: 3 fail (absent,
  //    JSON null, non-boolean). The whole-payload-null case still passes,
  //    because `cfg.dnsFilteringAvailable` on `null` throws inside the `.then`
  //    and the silent `.catch` swallows it, leaving the default standing.
  //  - both relaxed at once (guard dropped AND the setter coerced to
  //    `!!cfg?.dnsFilteringAvailable`): 3 fail (absent, JSON null, whole
  //    payload null). The non-boolean case survives that one, since
  //    `!!'false'` is `true` -- the right answer for the wrong reason.
  //  - the setter coerced to `!!cfg?.dnsFilteringAvailable` ON ITS OWN, inside
  //    the surviving `typeof` guard: nothing fails, and nothing can. Inside
  //    that guard the value is already a boolean, so `!!` is the identity
  //    function and the edit is a no-op no test could distinguish. The guard,
  //    not the setter, is what carries the rule.
  describe('an unknown answer leaves the gate AVAILABLE', () => {
    it('the field is absent (a web deploy that predates birdo-web#465)', async () => {
      mockedInvoke.mockResolvedValue({ version: 1, certPins: {} });
      await runHook();
      expect(gate()).toBe(true);
    });

    it('the field is JSON null (Rust Option<bool> = None serialises this way)', async () => {
      mockedInvoke.mockResolvedValue({ dnsFilteringAvailable: null });
      await runHook();
      expect(gate()).toBe(true);
    });

    // NOT a shape today's Rust path can produce: `handle_response_from` maps an
    // empty 2xx body to `b"null"`, and `serde_json::from_slice::<
    // ClientConfigResponse>(b"null")` errors, so an empty body arrives as a
    // REJECTION (covered by the failed-fetch block below), not as a `null`
    // resolve. This pins the frontend contract anyway: the hook's own type says
    // `ClientConfig | null`, and `cfg?.` is what makes that type honest. Drop the
    // optional chain and this is the test that catches the TypeError.
    it('the whole payload is null (the hook types the resolve as nullable)', async () => {
      mockedInvoke.mockResolvedValue(null);
      await runHook();
      expect(gate()).toBe(true);
    });

    it('the value is a non-boolean the frontend must not coerce', async () => {
      mockedInvoke.mockResolvedValue({ dnsFilteringAvailable: 'false' });
      await runHook();
      expect(gate()).toBe(true);
    });
  });

  // ── The headline case: the fetch fails ──────────────────────────────────
  //
  // This is the branch the PR body calls one of the four places the decision
  // is made, and it was the one with no guard of its own. A `.catch()` that
  // sets `false` turns every offline launch, 500, 429 or DNS hiccup into a
  // greyed-out BirdoShield row on a fleet where filtering works.
  describe('a failed fetch leaves the gate AVAILABLE', () => {
    it('a network error does not disable the row', async () => {
      mockedInvoke.mockRejectedValue(new Error('error sending request'));
      await runHook();
      expect(gate()).toBe(true);
    });

    it('a rate-limit / server error string from the Tauri command does not either', async () => {
      // Tauri commands reject with a String, not an Error.
      mockedInvoke.mockRejectedValue('Failed to get client config: HTTP 429');
      await runHook();
      expect(gate()).toBe(true);
    });

    it('a failure does not clobber a false the server already gave us', async () => {
      useAppStore.setState({ dnsFilteringAvailable: false });
      mockedInvoke.mockRejectedValue(new Error('offline'));
      await runHook();
      expect(gate()).toBe(false);
    });

    it('the rejection is handled -- no unhandled promise escapes the hook', async () => {
      const unhandled = vi.fn();
      process.on('unhandledRejection', unhandled);
      mockedInvoke.mockRejectedValue(new Error('offline'));
      await runHook();
      process.off('unhandledRejection', unhandled);
      expect(unhandled).not.toHaveBeenCalled();
    });
  });

  // The store field is deliberately NOT persisted: it is a property of the
  // fleet, not of this install, and a stale `false` in localStorage would
  // outlive the rollout it describes.
  it('never writes the gate to localStorage', async () => {
    mockedInvoke.mockResolvedValue({ dnsFilteringAvailable: false });
    await runHook();
    expect(gate()).toBe(false);
    const persisted = window.localStorage.getItem('birdo-vpn-storage') ?? '';
    expect(persisted).not.toContain('dnsFilteringAvailable');
  });

  // — The gate has to stay fresh, not merely be fetched once ———————-
  //
  // PR #162 review, must-fix 1. The hook used to be a single mount effect, and
  // the PR justified that with the route's `s-maxage=3600`: "a gate switched
  // OFF leaves the row usable for up to the same hour". That bounded the age
  // of a RESPONSE at fetch time, not the age of this client's value. AppShell
  // mounts once per authenticated session, and BirdoVPN closes to the tray
  // (`src-tauri/src/main.rs` turns the close button into `hide()`), so a
  // client left in the tray kept its mount-time answer for DAYS — reading ON
  // and switchable long after `DNS_FILTERING_ENABLED` went off. These tests
  // fail if any trigger, or the throttle that keeps them cheap, is removed.
  describe('re-reads the gate when the user comes back to the window', () => {
    const outsideThrottle = () => advance(GATE_REFETCH_MIN_INTERVAL_MS + 1);

    async function mountedHook() {
      mockedInvoke.mockResolvedValue({ dnsFilteringAvailable: true });
      const view = renderHook(() => useClientConfig());
      await waitFor(() => expect(mockedInvoke).toHaveBeenCalledTimes(1));
      await flush();
      return view;
    }

    it('on visibilitychange back to visible', async () => {
      await mountedHook();
      outsideThrottle();
      fireVisibilityChange(false);
      await waitFor(() => expect(mockedInvoke).toHaveBeenCalledTimes(2));
    });

    it('on window focus — alt-tab back need not change document.hidden', async () => {
      await mountedHook();
      outsideThrottle();
      fireWindowFocus();
      await waitFor(() => expect(mockedInvoke).toHaveBeenCalledTimes(2));
    });

    it('on a tray restore (the `app-shown` event main.rs emits)', async () => {
      await mountedHook();
      expect(tray.shownHandlers).toHaveLength(1);
      outsideThrottle();
      fireTrayRestore();
      await waitFor(() => expect(mockedInvoke).toHaveBeenCalledTimes(2));
    });

    it('NOT on the way to hidden — a window being minimised is not a return', async () => {
      await mountedHook();
      outsideThrottle();
      fireVisibilityChange(true);
      await flush();
      expect(mockedInvoke).toHaveBeenCalledTimes(1);
    });

    it('picks up a gate that was switched off while the app sat in the tray', async () => {
      // The whole point, end to end: mount while the fleet gate is on, sit in
      // the tray while it is switched off, come back.
      await mountedHook();
      expect(gate()).toBe(true);

      mockedInvoke.mockResolvedValue({ dnsFilteringAvailable: false });
      advance(3 * 24 * 60 * 60 * 1000); // three days in the tray
      fireTrayRestore();

      await waitFor(() => expect(gate()).toBe(false));
    });

    it('throttles: returns inside the minimum interval do not refetch', async () => {
      await mountedHook();

      // Inside the window: three different triggers, no second request.
      advance(GATE_REFETCH_MIN_INTERVAL_MS - 1);
      fireWindowFocus();
      fireVisibilityChange(false);
      fireTrayRestore();
      await flush();
      expect(mockedInvoke).toHaveBeenCalledTimes(1);

      // Past it: exactly one more, and the next trigger is throttled again.
      outsideThrottle();
      fireWindowFocus();
      await waitFor(() => expect(mockedInvoke).toHaveBeenCalledTimes(2));
      fireWindowFocus();
      await flush();
      expect(mockedInvoke).toHaveBeenCalledTimes(2);
    });

    it('throttles on the request being STARTED, so an in-flight fetch is not doubled', async () => {
      // `lastFetchAt` is stamped before the invoke, not after it resolves: a
      // slow request must not let a second trigger through behind it.
      let resolveFirst: (v: unknown) => void = () => {};
      mockedInvoke.mockImplementationOnce(
        () => new Promise((res) => { resolveFirst = res; }),
      );
      renderHook(() => useClientConfig());
      await waitFor(() => expect(mockedInvoke).toHaveBeenCalledTimes(1));

      advance(GATE_REFETCH_MIN_INTERVAL_MS - 1);
      fireWindowFocus();
      await flush();
      expect(mockedInvoke).toHaveBeenCalledTimes(1);

      act(() => resolveFirst({ dnsFilteringAvailable: false }));
      await flush();
      expect(gate()).toBe(false);
    });

    it('stops listening on unmount — no fetch after the shell is gone', async () => {
      const { unmount } = await mountedHook();
      unmount();
      // `listen` resolves a promise, so the unsubscribe lands a microtask late.
      await flush();

      expect(tray.unlistenCalls).toBe(1);
      outsideThrottle();
      fireWindowFocus();
      fireVisibilityChange(false);
      await flush();
      expect(mockedInvoke).toHaveBeenCalledTimes(1);
    });
  });

  // — A bound that holds only AT a return is not a bound on what is read ——
  //
  // PR #162 review, must-fix 1 (round 5). EVERY trigger in the block above is
  // a RETURN to the window: mount, visibilitychange→visible, window focus and
  // the `app-shown` tray event. Not one of them fires while the window simply
  // stays open — and staying open is what a window does between the user
  // coming back to it and the user reading the row.
  //
  // Measured on the round-4 code: mount the hook, flip the server answer to
  // `false`, advance the clock three days with no visibilitychange, no focus
  // and no `app-shown`, and `invoke` had been called exactly once with the
  // gate still `true`. AppShell mounts once per authenticated session, so that
  // was a whole session on a three-day-old answer, for a user who came back
  // once and then left the 380x640 window up. `GATE_POLL_INTERVAL_MS` is what
  // closes that, and these tests are that measurement kept.
  //
  // Only `setInterval`/`clearInterval` are faked here: `Date.now` is already
  // spied above (the throttle reads it) and `setTimeout` has to stay real for
  // `@testing-library`'s own async plumbing, so the poll clock and the
  // throttle clock are stepped together by `idle()`.
  describe('re-reads the gate while the window just stays open', () => {
    beforeEach(() => {
      vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    /** Mount with the window visible, first fetch settled, gate available. */
    async function mountedVisible() {
      mockedInvoke.mockResolvedValue({ dnsFilteringAvailable: true });
      const view = renderHook(() => useClientConfig());
      await flush();
      expect(mockedInvoke).toHaveBeenCalledTimes(1);
      return view;
    }

    /** Time passing with the window open and NOTHING else happening. */
    async function idle(ms: number) {
      advance(ms);
      await act(async () => {
        vi.advanceTimersByTime(ms);
        await Promise.resolve();
        await Promise.resolve();
      });
    }

    it('picks up a gate switched off with no return to the window at all', async () => {
      await mountedVisible();
      mockedInvoke.mockResolvedValue({ dnsFilteringAvailable: false });

      await idle(GATE_REFETCH_MIN_INTERVAL_MS + GATE_POLL_INTERVAL_MS);

      expect(mockedInvoke).toHaveBeenCalledTimes(2);
      expect(gate()).toBe(false);
    });

    it('three days of a visible, untouched window do not keep serving the mount-time answer', async () => {
      // Verbatim the round-4 measurement, which ended here with one invoke and
      // a gate still reading `true`.
      await mountedVisible();
      expect(gate()).toBe(true);
      mockedInvoke.mockResolvedValue({ dnsFilteringAvailable: false });

      await idle(3 * 24 * 60 * 60 * 1000);

      expect(gate()).toBe(false);
    });

    it('does not poll while hidden — nobody is reading, and the return triggers cover it', async () => {
      await mountedVisible();
      setHidden(true);

      await idle(GATE_REFETCH_MIN_INTERVAL_MS + GATE_POLL_INTERVAL_MS * 10);

      expect(mockedInvoke).toHaveBeenCalledTimes(1);
    });

    it('the tick obeys the same throttle — it asks, the throttle answers', async () => {
      await mountedVisible();

      await idle(GATE_POLL_INTERVAL_MS);
      await idle(GATE_POLL_INTERVAL_MS);
      expect(mockedInvoke).toHaveBeenCalledTimes(1);

      await idle(GATE_REFETCH_MIN_INTERVAL_MS);
      expect(mockedInvoke).toHaveBeenCalledTimes(2);
    });

    it('stops polling on unmount — the interval is cleared, not leaked', async () => {
      const { unmount } = await mountedVisible();
      unmount();

      await idle(GATE_REFETCH_MIN_INTERVAL_MS + GATE_POLL_INTERVAL_MS * 5);

      expect(mockedInvoke).toHaveBeenCalledTimes(1);
    });
  });
});
