/**
 * Source guards for three things that regress quietly, in the style of the
 * repo's other guard tests: they read the source, not a render.
 *
 *  - PALETTE (P1-parity-005): the Windows "connected" green, the indigo
 *    Operative gradient and the globe's own green diverged from the iOS /
 *    Android tokens. Those values must not come back.
 *  - CONTRAST (W2-018): the theme itself says w40 fails WCAG AA for text;
 *    text uses of it were hints, legal lines, the version footer.
 *  - VOCABULARY (P1-parity-034 and the canonical tables): retired UI strings
 *    must not reappear, and status text uses "…", never "...".
 *
 * Comments are stripped first: several explain what the old wording was.
 *
 * Run: npx vitest run src/__tests__/CopyAndPaletteGuard.test.ts
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, resolve, relative } from 'node:path';

function srcDir(): string {
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    if (existsSync(resolve(dir, 'src/App.tsx'))) return resolve(dir, 'src');
    dir = resolve(dir, '..');
  }
  throw new Error('src/ not found');
}

function files(dir: string, exts: RegExp): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      if (name === '__tests__' || name === '__mocks__' || name === 'assets') continue;
      out.push(...files(p, exts));
    } else if (exts.test(name) && !/\.test\.tsx?$/.test(name)) {
      out.push(p);
    }
  }
  return out;
}

/** Drop block and line comments (not inside strings — good enough for this source). */
function stripComments(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"`])\/\/.*$/gm, '$1');
}

const SRC = srcDir();
const sources = files(SRC, /\.(ts|tsx|css)$/).map((f) => ({
  file: relative(SRC, f),
  text: stripComments(readFileSync(f, 'utf8')),
}));

function offenders(re: RegExp): string[] {
  const hits: string[] = [];
  for (const { file, text } of sources) {
    text.split('\n').forEach((line, i) => {
      if (re.test(line)) hits.push(`${file}:${i + 1}: ${line.trim()}`);
    });
  }
  return hits;
}

describe('palette (P1-parity-005)', () => {
  it('scans a non-trivial source tree', () => {
    expect(sources.length).toBeGreaterThan(40);
  });

  it('no Windows-only greens or indigo remain', () => {
    expect(offenders(/#(22C55E|4ADE80|44D17E|6366F1|4338CA)\b/i)).toEqual([]);
  });
});

describe('contrast (W2-018)', () => {
  it('no text is set in w40 (decorative icons and dividers only)', () => {
    expect(
      offenders(/text-w40|text-white\/(30|40)\b|placeholder:text-w40|style=\{\{\s*color:\s*white\.w40\s*\}\}/),
    ).toEqual([]);
  });
});

describe('motion (W2-034)', () => {
  it('animation durations come from the motion tokens, not literals', () => {
    expect(offenders(/duration:\s*0?\.\d/)).toEqual([]);
    expect(offenders(/stiffness:|damping:/)).toEqual([]);
  });
});

describe('vocabulary (P1-parity-034, canonical tables)', () => {
  const RETIRED = [
    'Log Out',
    'Logging out',
    'Uptime',
    'Anonymous ID',
    'Delete forever',
    'Register at birdo.app',
    'Two-Factor Auth',
    'Biometric Unlock',
    'Secured via',
    'Connection Lost',
    'VPN Connected',
    'VPN Disconnected',
    'Rekeying',
    'Authenticating',
    'Stealth Mode · Premium',
    'No rules yet',
    'Choose a server / Tap',
  ];

  it.each(RETIRED)('"%s" is not a UI string any more', (phrase) => {
    const quoted = new RegExp(`['"\`>]\\s*${phrase.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`);
    expect(offenders(quoted)).toEqual([]);
  });

  it('no mobile "Tap" on a desktop', () => {
    expect(offenders(/['"`>][^'"`<\n]*\bTap (to|Connect|the)\b/)).toEqual([]);
  });

  it('status and loading text uses the ellipsis "…", never three dots', () => {
    expect(offenders(/['"`>][^'"`<\n]*[A-Za-z]\.\.\.\s*['"`<]/)).toEqual([]);
  });
});
