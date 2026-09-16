/**
 * `GET /api/client-config` → the BirdoShield fleet gate (`dnsFilteringAvailable`).
 *
 * WHY THIS IS A HOOK AND NOT AN INLINE EFFECT (PR #162 review, must-fix 2):
 * the three guards below ARE the feature. "Unknown means available" is decided
 * here and nowhere else, and the failure it prevents is asymmetric — a wrongly
 * `false` value hides filtering the user chose and paid attention to, while a
 * wrongly-available one costs a greyed-out row appearing a moment late. While
 * this lived inline in a 1700-line Dashboard nothing could reach it: all three
 * guards could be inverted at once (`typeof … === 'boolean'` → `true`, the
 * setter → `!!cfg?.dnsFilteringAvailable`, the `.catch()` → `set(false)`) and
 * the whole suite stayed green. `src/__tests__/useClientConfig.test.tsx` kills
 * each of those mutants against the REAL store.
 */
import { useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { useAppStore } from '@/store/app-store';

/**
 * The slice of `/api/client-config` this client acts on. The route also serves
 * cert pins, per-plan feature maps and consent copy; the desktop client reads
 * none of them (pins are vendored and enforced at build time), and the Rust
 * `ClientConfigResponse` deliberately models only this field.
 *
 * `null` is as real as `undefined`: an older web deploy predating birdo-web#465
 * omits the key, and JSON `null` survives the Rust `Option<bool>` the same way.
 */
export interface ClientConfig {
  dnsFilteringAvailable?: boolean | null;
}

/**
 * Floor between two gate fetches, in milliseconds.
 *
 * The refetches below are driven by user actions (focusing the window,
 * restoring from the tray), and a user can produce those as fast as they can
 * alt-tab. This is what stops that becoming a request per focus change; it is
 * also the in-flight guard, because the timestamp is taken BEFORE the invoke
 * rather than after it resolves. Five minutes stays far inside the endpoint's
 * 60 req/min bucket, and it is the only term this client itself adds to the
 * staleness bound documented on `useClientConfig`.
 */
export const GATE_REFETCH_MIN_INTERVAL_MS = 5 * 60_000;

/**
 * How often the gate is re-checked while the window is VISIBLE, in ms.
 *
 * Deliberately shorter than the throttle above, and doing a different job:
 * this is the tick that asks "may I fetch yet?", and
 * `GATE_REFETCH_MIN_INTERVAL_MS` is what answers. Together they bound a
 * visible window's value at throttle + tick, with no user action required —
 * see the staleness section on `useClientConfig` for why a bound that only
 * holds at the instant the user RETURNS to the window is not a bound on what
 * the user reads.
 *
 * The tick does nothing while `document.hidden`: a hidden window has no
 * reader, and the return triggers are what cover coming back to it.
 */
export const GATE_POLL_INTERVAL_MS = 60_000;

/**
 * Sync the fleet gate into the store, and keep it synced.
 *
 * CALL IT FROM `AppShell`, NOT FROM A TAB ROOT (PR #162 review, must-fix 1).
 * An earlier revision called this from `Dashboard` and justified it with
 * "VpnSettings is a pushed sub-screen only reachable through it". That was
 * FALSE: `Settings.tsx` is the only component that pushes the `vpnSettings`
 * route, and `AppShell` renders Settings and Dashboard mutually exclusively,
 * so Dashboard is not on the path to this screen at all. A `birdo://settings`
 * cold launch sets `tab` to 'settings' before the shell first renders, which
 * left the gate at its `true` default for the entire session and showed
 * BirdoShield ON and switchable with `DNS_FILTERING_ENABLED` off. `AppShell`
 * is the component that is mounted for every authenticated session whatever
 * the tab, which is the property this fetch actually needs.
 *
 * Unauthenticated, so it does not wait on sign-in state. Every fetch is a plain
 * 200: the client sends no `If-None-Match` and reqwest keeps no HTTP cache, so
 * each one pulls the whole public payload. That is cheap (small, public route)
 * and it fails harmlessly — a 429 from the endpoint's 60 req/min bucket lands
 * in the catch below and leaves the gate at its "available" default.
 *
 * ── STALENESS: what actually bounds it ─────────────────────────────────────
 *
 * An earlier revision claimed a gate switched OFF left the row usable "for up
 * to the same hour", citing the route's `s-maxage=3600`. That was false in the
 * dishonest direction, and why is worth keeping: a cache header bounds how old
 * a RESPONSE may be when it is fetched. It says nothing about how long ago
 * this client last fetched one. On mount alone that gap is unbounded in
 * practice — `AppShell` mounts once per authenticated session, and BirdoVPN is
 * a close-to-tray app (`src-tauri/src/main.rs` turns the window's close button
 * into `hide()` and keeps the process alive), so a client parked in the tray
 * kept its mount-time answer for as long as the user left it there. Days, with
 * the row reading ON and switchable after the gate went off.
 *
 * So the gate is re-read on two independent kinds of trigger.
 *
 * (a) RETURNS to the window, which cover the app having been away:
 *
 *  - `visibilitychange`, on the way to visible — the shape Dashboard's status
 *    poll already uses;
 *  - window `focus` — alt-tab back, which need not change `document.hidden`;
 *  - the `app-shown` Tauri event — emitted by `restore_and_focus` in
 *    `src-tauri/src/main.rs` for a tray click, the tray "Show Window" item, a
 *    deep link, a single-instance relaunch and the post-SSO return. This is
 *    the one that covers a real close-to-tray, where a hidden webview may see
 *    no visibility or focus event at all.
 *
 * (b) A POLL while the window is visible (`GATE_POLL_INTERVAL_MS`).
 *
 * (b) exists because EVERY trigger in (a) is a return, and nothing in that
 * list fires while the window simply stays open. Measured on the round-4 code
 * — mount the hook, flip the server answer to `false`, advance the clock three
 * days with no `visibilitychange`, no `focus` and no `app-shown` — `invoke`
 * was called exactly once and the gate was still `true`. `AppShell` mounts
 * once per authenticated session, so that was a whole session: a user who came
 * back, left the 380x640 window up and walked into Settings → VPN two hours
 * later read a two-hour-old gate. A bound that holds only AT the instant of a
 * return is not a bound on the value the user reads, because reading the row
 * is not a return.
 *
 * Each trigger, tick included, is throttled to one fetch per
 * `GATE_REFETCH_MIN_INTERVAL_MS`.
 *
 * THE REAL BOUND is therefore:
 *
 *  - window visible: the value on screen was fetched at most
 *    `GATE_REFETCH_MIN_INTERVAL_MS + GATE_POLL_INTERVAL_MS` ago, with no user
 *    action required to make that true;
 *  - coming back from hidden: at most `GATE_REFETCH_MIN_INTERVAL_MS` before
 *    that return;
 *
 * …plus, in both cases, however stale the answer already was when it arrived.
 * birdo-web's `app/api/client-config/route.ts` sets `Cache-Control: public,
 * max-age=300, stale-while-revalidate=3600` and `CDN-Cache-Control: public,
 * s-maxage=3600, stale-while-revalidate=86400` on its normal path, so a shared
 * cache in front of the route may hand back an answer up to an hour old, and
 * older still on the request that arrives while it revalidates. (On its
 * cert-pins-read-failure path the same route sends `no-store, max-age=0,
 * must-revalidate` / `s-maxage=10`, which is tighter — the hour is the bound
 * either way.) reqwest keeps no cache of its own, so nothing on this side adds
 * to that except the throttle.
 *
 * What is still NOT bounded: the fetch is asynchronous, so the first paint
 * after a return — and the paint in the tick that discovers a change — shows
 * the previous value for one round trip. A stale-ON row for one request is the
 * residue; a stale-ON row for a whole tray-resident session, or for a whole
 * session with the window left open, is what this removes.
 * `src/__tests__/useClientConfig.test.tsx` fails if any of the three return
 * triggers, the visible poll, or the throttle is dropped.
 *
 * Which direction each error costs, unchanged:
 *
 *  - trailing a gate that has just been switched ON: the row reads OFF and
 *    disabled while the tunnel really is filtering. `settingsToRust` sends
 *    `dns_filtering: settings.dnsFiltering` regardless of the gate, so the
 *    user's stored preference is still honoured server-side — the screen
 *    understates what is happening, which is the safe direction.
 *  - trailing a gate that has just been switched OFF: the row stays usable,
 *    which is the direction that lies, and the one the refetch above bounds.
 */
export function useClientConfig(): void {
  const setDnsFilteringAvailable = useAppStore((s) => s.setDnsFilteringAvailable);

  useEffect(() => {
    let cancelled = false;
    let lastFetchAt = 0;

    const fetchGate = (force: boolean) => {
      const now = Date.now();
      // Taken BEFORE the invoke, so an in-flight request throttles the next
      // trigger too and no separate dedupe flag is needed. A failed fetch
      // throttles as well: the store default already stands, and retrying a
      // broken network on every alt-tab buys nothing.
      if (!force && now - lastFetchAt < GATE_REFETCH_MIN_INTERVAL_MS) return;
      lastFetchAt = now;

      invoke<ClientConfig | null>('get_client_config')
        .then((cfg) => {
          if (cancelled) return;
          // GUARD 1: only an explicit boolean is a signal. A web deploy that
          // predates the field sends nothing (undefined) or `null` — that is
          // "unknown", NOT "off". `!!cfg?.dnsFilteringAvailable` here would
          // turn every such deploy into a fleet-wide false and hide a working
          // feature.
          if (typeof cfg?.dnsFilteringAvailable === 'boolean') {
            setDnsFilteringAvailable(cfg.dnsFilteringAvailable);
          }
        })
        // GUARD 2: the catch deliberately does NOTHING. The store default is
        // `true`; an offline client, a 500, a 429 or a cold start must leave
        // the row usable. Setting `false` here is precisely the bug this PR
        // exists to prevent, one layer down.
        .catch(() => {
          /* silent — the store default (available) stands */
        });
    };

    // Mount: forced past the throttle, since `lastFetchAt` starts at 0 anyway
    // and the intent ("always fetch once") should not read as an accident.
    fetchGate(true);

    const onVisibility = () => {
      if (!document.hidden) fetchGate(false);
    };
    const onFocus = () => fetchGate(false);

    document.addEventListener('visibilitychange', onVisibility);
    window.addEventListener('focus', onFocus);
    // The visible poll. Every listener above is a RETURN to the window; this
    // is the only trigger that fires while the window just stays open, which
    // is what a user does between opening the app and reading the row. Skipped
    // while hidden — nobody is reading it then, and the listeners above are
    // what cover coming back.
    const poll = window.setInterval(() => {
      if (!document.hidden) fetchGate(false);
    }, GATE_POLL_INTERVAL_MS);
    // `listen` resolves to its own unlisten fn. The catch covers a teardown
    // that beats the subscription, and any host without the event plugin
    // (a bare jsdom render, say).
    const unlistenShown = listen('app-shown', () => fetchGate(false));

    return () => {
      cancelled = true;
      document.removeEventListener('visibilitychange', onVisibility);
      window.removeEventListener('focus', onFocus);
      window.clearInterval(poll);
      unlistenShown.then((off) => off()).catch(() => {});
    };
  }, [setDnsFilteringAvailable]);
}
