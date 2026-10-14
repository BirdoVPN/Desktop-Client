/**
 * MR-1607: the consent version is defined once on each side of the IPC
 * boundary — here for the consent screen, in `src-tauri/src/commands/consent.rs`
 * for the record the tray's Quick Connect asks — and the two must move
 * together. A bump of one alone would hold the tray back for ever (Rust newer)
 * or let it dial before the new text was accepted (Rust older). Rust pins the
 * same pair (`the_rust_and_ui_versions_agree`).
 *
 * Run: npx vitest run src/lib/consent.test.ts
 */
import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { CONSENT_VERSION, hasCurrentConsent } from '@/lib/consent';

function findUp(rel: string): string {
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    const candidate = resolve(dir, rel);
    if (existsSync(candidate)) return candidate;
    const parent = resolve(dir, '..');
    if (parent === dir) break;
    dir = parent;
  }
  return resolve(process.cwd(), rel);
}

describe('CONSENT_VERSION (MR-1607)', () => {
  it('is the version Rust refuses unattended connects below', () => {
    const rust = readFileSync(findUp('src-tauri/src/commands/consent.rs'), 'utf8');
    const m = rust.match(/^pub const CONSENT_VERSION: u32 = (\d+);/m);
    expect(m, 'pub const CONSENT_VERSION in commands/consent.rs').not.toBeNull();
    expect(Number(m![1])).toBe(CONSENT_VERSION);
  });

  it('an older acceptance is not the current one', () => {
    expect(hasCurrentConsent(CONSENT_VERSION - 1)).toBe(false);
    expect(hasCurrentConsent(CONSENT_VERSION)).toBe(true);
  });
});
