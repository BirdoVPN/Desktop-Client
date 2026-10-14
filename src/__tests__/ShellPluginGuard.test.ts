/**
 * MR-713 (owner decision 2026-10-14): the Tauri shell plugin is gone, crate,
 * npm package, plugin init, capability and config, and must not come back.
 * Links open through @tauri-apps/plugin-opener (see OpenerLinks.test.tsx and
 * src-tauri/src/commands/capability_scope_tests.rs).
 *
 * The shell plugin carried a process-spawning `Command` API this app never
 * used; one re-added `shell:` permission or a stray import re-ships it, and
 * nothing else would notice. This reads the files that would have to change:
 * every capability, both manifests and both lockfiles, tauri.conf.json, the
 * Rust sources and everything under src/ (tests included, so a test cannot
 * keep mocking the old package either).
 *
 * Run: npx vitest run src/__tests__/ShellPluginGuard.test.ts
 */
import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

function repoRoot(): string {
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    if (existsSync(resolve(dir, 'src-tauri/Cargo.toml')) && existsSync(resolve(dir, 'package.json'))) return dir;
    dir = resolve(dir, '..');
  }
  throw new Error('repo root (package.json + src-tauri/Cargo.toml) not found');
}

function walk(dir: string, keep: (name: string) => boolean): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p, keep));
    else if (keep(name)) out.push(p);
  }
  return out;
}

const ROOT = repoRoot();
const read = (p: string) => readFileSync(p, 'utf8');
const rel = (p: string) => relative(ROOT, p).replace(/\\/g, '/');

// The package names, in every spelling a dependency can take.
const PACKAGE = /tauri-plugin-shell|tauri_plugin_shell|@tauri-apps\/plugin-shell/;
// A shell permission identifier: shell:allow-open, shell:default, ...
const PERMISSION = /\bshell:[a-z][a-z-]*/;

const capabilityFiles = walk(resolve(ROOT, 'src-tauri/capabilities'), () => true);
const manifestFiles = ['src-tauri/Cargo.toml', 'src-tauri/Cargo.lock', 'package.json', 'package-lock.json'].map(
  (p) => resolve(ROOT, p),
);
const rustFiles = walk(resolve(ROOT, 'src-tauri/src'), (n) => n.endsWith('.rs'));
// This file spells the names out to look for them, so it is the one file skipped.
const frontendFiles = walk(resolve(ROOT, 'src'), () => true).filter(
  (p) => rel(p) !== 'src/__tests__/ShellPluginGuard.test.ts',
);

// Read once, at load (as CopyAndPaletteGuard does): the walk covers a few MB
// and the per-test timeout should measure the checks, not the disk.
const text = new Map<string, string>(
  [...capabilityFiles, ...manifestFiles, ...rustFiles, ...frontendFiles].map((f) => [f, read(f)]),
);

function hits(files: string[], re: RegExp): string[] {
  const out: string[] = [];
  for (const f of files) {
    const body = text.get(f) ?? read(f);
    if (!re.test(body)) continue;
    body.split('\n').forEach((line, i) => {
      if (re.test(line)) out.push(`${rel(f)}:${i + 1}: ${line.trim()}`);
    });
  }
  return out;
}

describe('the shell plugin is not coming back (MR-713)', () => {
  it('the walk sees the files it is meant to (a guard over nothing passes)', () => {
    expect(capabilityFiles.map(rel)).toContain('src-tauri/capabilities/default.json');
    expect(rustFiles.map(rel)).toContain('src-tauri/src/main.rs');
    expect(rustFiles.map(rel)).toContain('src-tauri/src/commands/oauth.rs');
    expect(frontendFiles.map(rel)).toContain('src/components/Login.tsx');
    expect(frontendFiles.map(rel)).toContain('src/__tests__/OpenerLinks.test.tsx');
    // ...and that the opener really is what replaced it.
    expect(read(resolve(ROOT, 'src-tauri/Cargo.toml'))).toMatch(/^tauri-plugin-opener = /m);
    expect(read(resolve(ROOT, 'src-tauri/src/main.rs'))).toContain('tauri_plugin_opener::init()');
    expect(JSON.parse(read(resolve(ROOT, 'package.json'))).dependencies).toHaveProperty('@tauri-apps/plugin-opener');
  });

  it('no capability grants a shell: permission', () => {
    expect(hits(capabilityFiles, PERMISSION)).toEqual([]);
  });

  it('no manifest or lockfile names the shell plugin', () => {
    expect(hits([...capabilityFiles, ...manifestFiles], PACKAGE)).toEqual([]);
  });

  it('no Rust source uses the shell plugin crate', () => {
    expect(hits(rustFiles, PACKAGE)).toEqual([]);
  });

  it('nothing under src/ imports, mocks or names the shell plugin or its permissions', () => {
    expect(hits(frontendFiles, PACKAGE)).toEqual([]);
    expect(hits(frontendFiles, PERMISSION)).toEqual([]);
  });

  it('tauri.conf.json carries no shell plugin config', () => {
    const conf = JSON.parse(read(resolve(ROOT, 'src-tauri/tauri.conf.json')));
    expect(Object.keys(conf.plugins ?? {})).not.toContain('shell');
    expect(hits([resolve(ROOT, 'src-tauri/tauri.conf.json')], PERMISSION)).toEqual([]);
  });
});
