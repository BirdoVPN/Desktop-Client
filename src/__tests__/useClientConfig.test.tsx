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
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor, act } from '@testing-library/react';
import { invoke } from '@tauri-apps/api/core';
import { useClientConfig } from '@/hooks/useClientConfig';
import { useAppStore } from '@/store/app-store';

vi.mock('@tauri-apps/api/core');

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

beforeEach(() => {
  mockedInvoke.mockReset();
  // The shipped default. Every "unknown" case below asserts this survives.
  useAppStore.setState({ dnsFilteringAvailable: true });
});

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
});
