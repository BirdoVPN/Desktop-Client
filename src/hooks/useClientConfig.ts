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
 * Sync the fleet gate into the store. Fire-and-forget, once per mount.
 *
 * Lives on the Dashboard because that is already the screen that pulls the
 * server-side state the settings screens render (`get_subscription_status`),
 * and VpnSettings is a pushed sub-screen only reachable through it.
 *
 * Unauthenticated, so it runs regardless of sign-in state. It is a plain 200
 * every time: the client sends no `If-None-Match` and reqwest keeps no HTTP
 * cache, so a remount (the Dashboard unmounts on every tab switch) is a full
 * refetch of the whole payload. That is tolerable because the route is public
 * and small, and because its rate limit (60 req/min) failing closed is
 * harmless here — a 429 lands in the catch below and leaves the gate at its
 * "available" default.
 *
 * STALENESS, and which direction it errs in: the route is served with
 * `s-maxage=3600, stale-while-revalidate=86400`, so this value can trail the
 * real fleet gate by up to an hour, longer while SWR is revalidating.
 *
 *  - trailing a gate that has just been switched ON: the row reads OFF and
 *    disabled while the tunnel really is filtering. `settingsToRust` sends
 *    `dns_filtering: settings.dnsFiltering` regardless of the gate, so the
 *    user's stored preference is still honoured server-side — the screen
 *    understates what is happening, which is the safe direction.
 *  - trailing a gate that has just been switched OFF: the row stays usable
 *    for up to the same hour. That is the dishonest direction, and it is
 *    bounded because the gate is a deliberate fleet rollout switch, not an
 *    incident toggle — it moves on a deploy, not on a page load.
 */
export function useClientConfig(): void {
  const setDnsFilteringAvailable = useAppStore((s) => s.setDnsFilteringAvailable);

  useEffect(() => {
    invoke<ClientConfig | null>('get_client_config')
      .then((cfg) => {
        // GUARD 1: only an explicit boolean is a signal. A web deploy that
        // predates the field sends nothing (undefined) or `null` — that is
        // "unknown", NOT "off". `!!cfg?.dnsFilteringAvailable` here would turn
        // every such deploy into a fleet-wide false and hide a working feature.
        if (typeof cfg?.dnsFilteringAvailable === 'boolean') {
          setDnsFilteringAvailable(cfg.dnsFilteringAvailable);
        }
      })
      // GUARD 2: the catch deliberately does NOTHING. The store default is
      // `true`; an offline client, a 500, a 429 or a cold start must leave the
      // row usable. Setting `false` here is precisely the bug this PR exists to
      // prevent, one layer down.
      .catch(() => {
        /* silent — the store default (available) stands */
      });
  }, [setDnsFilteringAvailable]);
}
