/**
 * Source guards for two documented limitations, in the style of the repo's
 * other guard tests: they read the documents and the app's source.
 *
 *  - SMART APP CONTROL (MR-680): with the kill switch on, a reconnect gap or a
 *    held block drops Windows' own cloud lookups, so Smart App Control blocks
 *    a NEW unsigned program (os error 4551) until the tunnel is back. That is
 *    documented for users (CODE_SIGNING.md, "What Users See") and in the kill
 *    switch's description (WINDOWS-LEAK-VALIDATION.md), and the filters the
 *    latter names must be ones wfp_policy.rs installs.
 *  - F-001 RESULTS (MR-1665): no cell of the bench's Results table is left
 *    blank (a check nobody ran says NOT RUN), and the 2026-09-20 fleet runs
 *    sit in rows 1, 6 and 7, labelled as fleet runs, not a client machine.
 *
 * Run: npx vitest run src/__tests__/LimitationDocsGuard.test.ts
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

function repoRoot(): string {
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    if (existsSync(resolve(dir, 'src-tauri/Cargo.toml'))) return dir;
    dir = resolve(dir, '..');
  }
  throw new Error('repository root not found');
}

const ROOT = repoRoot();
const read = (path: string) => readFileSync(resolve(ROOT, path), 'utf8').replace(/\r/g, '');
const flat = (text: string) => text.replace(/\s+/g, ' ');

/** `### <title>` up to the next `##`/`###` heading; '' when absent. */
function section(doc: string, title: string): string {
  const start = doc.indexOf(`\n### ${title}\n`);
  if (start < 0) return '';
  const rest = doc.slice(start + 1);
  const end = rest.slice(4).search(/\n#{2,3} /);
  return end < 0 ? rest : rest.slice(0, end + 4);
}

describe('Smart App Control is a documented limitation (MR-680)', () => {
  const users = flat(section(read('docs/CODE_SIGNING.md'), 'Windows Smart App Control'));
  const checklist = read('docs/WINDOWS-LEAK-VALIDATION.md');
  const killSwitch = flat(checklist.split(/\n\s*\n/).find((p) => p.includes('Smart App Control (MR-680)')) ?? '');
  const wfp = read('src-tauri/src/vpn/wfp_policy.rs');

  it('users are told when it happens, what it hits, and what to do', () => {
    expect(users).toContain('os error 4551');
    expect(users).toMatch(/reconnect gap/);
    expect(users).toMatch(/kill switch holds the block/);
    expect(users).toMatch(/new, unsigned/);
    expect(users).toMatch(/Released BirdoVPN builds are Authenticode-signed/);
    expect(users).toMatch(/\*\*Disconnect\*\* lifts it/);
  });

  it("the kill switch's description says why there is no permit, and links the users' note", () => {
    expect(killSwitch).toMatch(/A permit was not added/);
    expect(killSwitch).toContain('(./CODE_SIGNING.md#windows-smart-app-control)');
  });

  it('every filter it names is one wfp_policy.rs installs', () => {
    const names = [...killSwitch.matchAll(/`(Birdo: [^`]+)`/g)].map((m) => m[1]);
    expect(names).toEqual([
      'Birdo: Permit the tunnel interface',
      'Birdo: Permit DNS to the tunnel resolvers',
      'Birdo: Block all outbound IPv4',
      'Birdo: Block all outbound IPv6',
      'Birdo: Block DNS outside the tunnel',
    ]);
    const blockAll = /^Birdo: Block all (outbound|inbound) IPv[46]$/;
    for (const name of names) {
      const installed = blockAll.test(name)
        ? wfp.includes('format!("Birdo: Block all {direction} {family}")')
        : wfp.includes(`"${name}"`);
      expect(installed, name).toBe(true);
    }
  });
});

describe('the F-001 Results table holds what was recorded (MR-1665)', () => {
  const doc = read('release/patches/F-001-desktop-ipv6-leak.md');
  const results = doc.slice(doc.indexOf('\n## Results\n'));
  const rows = results
    .split('\n')
    .filter((line) => /^\| (\d|P\d) /.test(line))
    .map((line) => line.split('|').slice(1, -1).map((cell) => cell.trim()));
  const row = (step: string) => rows.find(([name]) => name.startsWith(`${step} `)) ?? [];

  it('has every step and parity check, and no blank cell', () => {
    expect(rows.map(([name]) => name.split(' ')[0])).toEqual(
      ['1', '2', '3', '4', '5', '6', '7', '8', '9', 'P1', 'P2', 'P3'],
    );
    for (const cells of rows) {
      expect(cells, cells[0]).toHaveLength(4);
      for (const cell of cells) expect(cell, cells[0]).not.toBe('');
      expect(cells[3], cells[0]).not.toMatch(/= *$/);
    }
  });

  it('rows 1, 6 and 7 carry the 2026-09-20 fleet runs, labelled as fleet runs', () => {
    for (const step of ['1', '6', '7']) {
      const [, result, date, notes] = row(step);
      expect(result, step).toMatch(/Fleet (sweep|run), not a client machine/);
      expect(date, step).toBe('2026-09-20');
      expect(notes, step).toMatch(/\[S[12]\]/);
    }
  });

  it('a check with no record says NOT RUN, and cites the search', () => {
    for (const step of ['2', '3', '4', '5', '8', '9', 'P1', 'P2', 'P3']) {
      const [, result, , notes] = row(step);
      expect(result, step).toBe('NOT RUN');
      expect(notes, step).toContain('[S4]');
    }
  });
});
