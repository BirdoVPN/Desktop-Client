/**
 * MR-2492 [RETRY-RULE-PARITY]: where a connect nobody clicked may go when the
 * server it was meant for cannot be used. The cases of iOS
 * `RelayRetryTests.swift` (Mobile #645), on the desktop's `Server`.
 *
 * Owner rule, 2026-11-19 (MR-2212 Q2 + Q6), the same on every client: a
 * server the client chose may move to another server in any country; a
 * location the user chose never leaves its country; never a server the list
 * shows offline (a jurisdiction hold depools the node) or one this plan
 * cannot use; ONE move.
 *
 * Run: npx vitest run src/lib/server-choice.test.ts
 */
import { describe, it, expect } from 'vitest';
import type { Server } from '@/store/app-store';
import { nextServer, type SelectionOrigin } from './server-choice';

const node = (id: string, extra: Partial<Server> = {}): Server => ({
  id,
  name: id,
  country: '',
  countryCode: 'DE',
  city: 'Frankfurt',
  load: 10,
  isPremium: false,
  isHighSpeed: false,
  isPortForwarding: false,
  isOnline: true,
  isAccessible: true,
  ...extra,
});

const ORIGINS: SelectionOrigin[] = ['automatic', 'user'];

/** `birdo-infra:deploy/fleet-nodes.conf`: 10 relays, 10 cities, 9 countries. */
const FLEET = [
  node('ams', { countryCode: 'NL', city: 'Amsterdam', load: 30 }),
  node('fra', { countryCode: 'DE', city: 'Frankfurt', load: 10 }),
  node('lon', { countryCode: 'GB', city: 'London', load: 25 }),
  node('lax', { countryCode: 'US', city: 'Los Angeles', load: 40 }),
  node('nyc', { countryCode: 'US', city: 'New York', load: 15 }),
  node('sao', { countryCode: 'BR', city: 'São Paulo', load: 35 }),
  node('sin', { countryCode: 'SG', city: 'Singapore', load: 45 }),
  node('sto', { countryCode: 'SE', city: 'Stockholm', load: 20 }),
  node('tyo', { countryCode: 'JP', city: 'Tokyo', load: 50 }),
  node('yyz', { countryCode: 'CA', city: 'Toronto', load: 55 }),
];

describe('the same city first, whoever chose', () => {
  it.each(ORIGINS)('%s: the least-loaded usable server in the same city', (origin) => {
    const list = [
      node('a'),
      node('b', { load: 40 }),
      node('c', { load: 5 }),
      node('far', { countryCode: 'NL', city: 'Amsterdam', load: 0 }),
    ];
    expect(nextServer('a', list, origin)).toEqual({ server: list[2], reach: 'same-city' });
  });

  it('case and spaces in the location are ignored', () => {
    const list = [node('a'), node('b', { countryCode: 'de', city: ' frankfurt ' })];
    expect(nextServer('a', list, 'user')?.server.id).toBe('b');
  });

  it('an empty city has no siblings', () => {
    const list = [node('a', { city: '' }), node('b', { city: '' })];
    expect(nextServer('a', list, 'user')?.reach).toBe('same-country');
  });
});

describe('the fleet as it is: one server per city', () => {
  it('a server the client chose always has somewhere to go; a user\'s only inside its country', () => {
    for (const failed of FLEET) {
      const auto = nextServer(failed.id, FLEET, 'automatic');
      expect(auto, failed.id).not.toBeNull();
      expect(auto?.server.id, failed.id).not.toBe(failed.id);
      const user = nextServer(failed.id, FLEET, 'user');
      if (failed.countryCode === 'US') {
        expect(user?.server.countryCode, failed.id).toBe('US');
        expect(user?.reach, failed.id).toBe('same-country');
      } else {
        expect(user, `${failed.id}: a user's location never leaves its country`).toBeNull();
      }
    }
    expect(nextServer('nyc', FLEET, 'user')?.server.id).toBe('lax');
    expect(nextServer('lax', FLEET, 'user')?.server.id).toBe('nyc');
  });
});

describe("the client's own pick may move to another country", () => {
  it('to the best of the other servers', () => {
    const list = [
      node('fra'),
      node('ams', { countryCode: 'NL', city: 'Amsterdam', load: 30 }),
      node('sto', { countryCode: 'SE', city: 'Stockholm', load: 20 }),
    ];
    expect(nextServer('fra', list, 'automatic')).toEqual({ server: list[2], reach: 'other-country' });
  });

  it('reported as same-country when the best one is in its own country', () => {
    const list = [
      node('nyc', { countryCode: 'US', city: 'New York' }),
      node('lax', { countryCode: 'US', city: 'Los Angeles', load: 1 }),
      node('ams', { countryCode: 'NL', city: 'Amsterdam', load: 50 }),
    ];
    expect(nextServer('nyc', list, 'automatic')?.reach).toBe('same-country');
  });
});

describe('a server the user chose never leaves its country', () => {
  it('no other server in its country: nothing, however empty the others', () => {
    const list = [
      node('fra'),
      node('ams', { countryCode: 'NL', city: 'Amsterdam', load: 0 }),
      node('lon', { countryCode: 'GB', city: 'London', load: 0 }),
    ];
    expect(nextServer('fra', list, 'user')).toBeNull();
  });

  it('another server in its country, never an emptier one abroad', () => {
    const list = [
      node('nyc', { countryCode: 'US', city: 'New York' }),
      node('lax', { countryCode: 'US', city: 'Los Angeles', load: 70 }),
      node('yyz', { countryCode: 'CA', city: 'Toronto', load: 0 }),
    ];
    expect(nextServer('nyc', list, 'user')).toEqual({ server: list[1], reach: 'same-country' });
  });

  it('the same city before the rest of the country', () => {
    const list = [
      node('nyc', { countryCode: 'US', city: 'New York' }),
      node('nyc2', { countryCode: 'US', city: 'New York', load: 80 }),
      node('lax', { countryCode: 'US', city: 'Los Angeles', load: 0 }),
    ];
    expect(nextServer('nyc', list, 'user')).toEqual({ server: list[1], reach: 'same-city' });
  });

  it('its country matched whatever the case', () => {
    const list = [
      node('nyc', { countryCode: 'US', city: 'New York' }),
      node('lax', { countryCode: ' us ', city: 'Los Angeles' }),
    ];
    expect(nextServer('nyc', list, 'user')?.server.id).toBe('lax');
  });

  it('no known country: it stays put', () => {
    const list = [
      node('a', { countryCode: ' ', city: '' }),
      node('b', { countryCode: ' ', city: '', load: 0 }),
      node('c', { countryCode: 'NL', city: 'Amsterdam', load: 0 }),
    ];
    expect(nextServer('a', list, 'user')).toBeNull();
  });
});

describe('never a held or ineligible server, never the one that failed', () => {
  it.each(ORIGINS)('%s: offline and out-of-plan servers are skipped', (origin) => {
    const list = [
      node('nyc', { countryCode: 'US', city: 'New York' }),
      node('nyc-held', { countryCode: 'US', city: 'New York', load: 0, isOnline: false }),
      node('lax-paid', { countryCode: 'US', city: 'Los Angeles', load: 0, isAccessible: false }),
      node('lax-held', { countryCode: 'US', city: 'Los Angeles', load: 0, isOnline: false }),
      node('lax', { countryCode: 'US', city: 'Los Angeles', load: 90 }),
    ];
    expect(nextServer('nyc', list, origin)?.server.id).toBe('lax');
  });

  it('only ineligible servers left: nothing', () => {
    const list = [
      node('fra'),
      node('ams', { countryCode: 'NL', city: 'Amsterdam', load: 0, isOnline: false }),
      node('lon', { countryCode: 'GB', city: 'London', load: 0, isAccessible: false }),
    ];
    expect(nextServer('fra', list, 'automatic')).toBeNull();
  });

  it.each(ORIGINS)('%s: the failed server is never the answer', (origin) => {
    expect(nextServer('a', [node('a', { load: 0 })], origin)).toBeNull();
  });

  it.each(ORIGINS)('%s: a server not in the list moves nothing', (origin) => {
    const list = [node('a'), node('b', { countryCode: 'NL', city: 'Amsterdam' })];
    expect(nextServer('zzz', list, origin)).toBeNull();
  });
});
