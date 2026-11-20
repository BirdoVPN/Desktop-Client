/**
 * MR-2492 [RETRY-RULE-PARITY]: where a connect nobody clicked may go when the
 * server it was meant for cannot be used. The owner's rule (2026-11-19,
 * MR-2212 Q2 + Q6) is the same on every client:
 *   * a server the CLIENT chose (`automatic`) may move to the best other
 *     server, in any country;
 *   * a location the USER chose never leaves its country without a click:
 *     the same city first, then another server in the same country, else
 *     nothing;
 *   * only servers /vpn/servers lists online and open to this plan
 *     (`pickBestServer`, the one best-server rule);
 *   * ONE move: the caller dials the answer once and never asks again.
 *
 * The twin of iOS `RelayRetry.next` (Mobile #645,
 * `iosApp/iosApp/Services/RelayRetry.swift`); `server-choice.test.ts` runs
 * its cases. The one desktop dial with no click that can go somewhere other
 * than the server on record is Auto-Connect at launch, when that server is
 * offline, out of the plan or gone (`planUnattendedConnect` in
 * `session/vpn-actions.ts`). A dial that fails shows its error and waits for
 * the user, except a server whose first handshake never comes: Rust retries
 * that one ONCE on another server by the same rule, so a user's pick only
 * within its country (MR-2514, `relay_retry::after_no_handshake`,
 * `commands::session`).
 */
import type { Server } from '@/store/app-store';
import { pickBestServer } from '@/lib/ipc';

/**
 * Who chose a server (iOS `SelectionOrigin`). `user` is the safe default: a
 * server recorded before the origin was (an older build) reads as the user's.
 */
export type SelectionOrigin = 'user' | 'automatic';

/** How far a move goes from the server that cannot be used. */
export type Reach = 'same-city' | 'same-country' | 'other-country';

export interface ServerChoice {
  server: Server;
  reach: Reach;
}

const normalized = (s: string): string => s.trim().toLowerCase();

/**
 * The server to use instead of `failedId`, or null. The first rule that
 * applies wins:
 *   1. another server in the SAME city and country;
 *   2. `automatic`: the best of all the other servers, in any country;
 *   3. `user`: the best other server in the SAME country;
 *   4. nothing.
 * null when `failedId` is not in `servers`: without its country, a user's
 * choice cannot be kept, so nothing moves.
 */
export function nextServer(
  failedId: string,
  servers: readonly Server[],
  origin: SelectionOrigin,
): ServerChoice | null {
  const failed = servers.find((s) => s.id === failedId);
  if (!failed) return null;
  const others = servers.filter((s) => s.id !== failedId);
  const country = normalized(failed.countryCode);
  const city = normalized(failed.city);
  const inCountry = others.filter((s) => country !== '' && normalized(s.countryCode) === country);
  const sibling = city === '' ? null : pickBestServer(inCountry.filter((s) => normalized(s.city) === city));
  if (sibling) return { server: sibling, reach: 'same-city' };
  if (origin === 'automatic') {
    const best = pickBestServer(others);
    if (!best) return null;
    const sameCountry = country !== '' && normalized(best.countryCode) === country;
    return { server: best, reach: sameCountry ? 'same-country' : 'other-country' };
  }
  const best = pickBestServer(inCountry);
  return best ? { server: best, reach: 'same-country' } : null;
}
