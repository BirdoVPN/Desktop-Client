/**
 * pickBestServer against the fixture Rust's `pick_quick_connect_server` runs
 * too (REVIEW-WIN-008): one rule, pinned on both sides of the boundary, so the
 * Connect button, auto-connect and the tray cannot land on different nodes.
 *
 * Run: npx vitest run src/lib/ipc.test.ts
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseQuotaWarning, parseServers, pickBestServer, toIpcError } from './ipc';

interface Case {
  name: string;
  servers: unknown[];
  expect: string | null;
}

const FIXTURE = resolve(
  import.meta.dirname,
  '../../src-tauri/src/commands/fixtures/best_server.json',
);
const { cases } = JSON.parse(readFileSync(FIXTURE, 'utf8')) as { cases: Case[] };

describe('pickBestServer: the shared best-server rule', () => {
  it('has cases to run', () => {
    expect(cases.length).toBeGreaterThanOrEqual(5);
  });

  it.each(cases.map((c) => [c.name, c] as const))('%s', (_name, c) => {
    expect(pickBestServer(parseServers(c.servers))?.id ?? null).toBe(c.expect);
  });

  it('does not depend on the order the list arrives in', () => {
    for (const c of cases) {
      const reversed = parseServers([...c.servers].reverse());
      expect(pickBestServer(reversed)?.id ?? null, c.name).toBe(c.expect);
    }
  });
});

/** birdo-web #590, contract v2 §2 and §4. */
describe('the Free allowance on the wire', () => {
  it('quota_exceeded is a known code, not folded into unknown', () => {
    expect(toIpcError({ code: 'quota_exceeded', message: 'x', retryable: false }).code).toBe('quota_exceeded');
  });

  it('quota-warning carries the seconds left, when the server said', () => {
    expect(parseQuotaWarning({ secondsRemaining: 540 })).toEqual({ secondsRemaining: 540 });
    expect(parseQuotaWarning({ seconds_remaining: 60 })).toEqual({ secondsRemaining: 60 });
    expect(parseQuotaWarning({ secondsRemaining: null })).toEqual({ secondsRemaining: null });
    expect(parseQuotaWarning({ secondsRemaining: -3 })).toEqual({ secondsRemaining: null });
    expect(parseQuotaWarning(undefined)).toEqual({ secondsRemaining: null });
  });
});
