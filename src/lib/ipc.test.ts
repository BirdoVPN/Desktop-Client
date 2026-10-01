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
import { parseServers, pickBestServer } from './ipc';

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
