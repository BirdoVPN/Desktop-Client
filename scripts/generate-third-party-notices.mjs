#!/usr/bin/env node
// ============================================================================
// THIRD-PARTY-NOTICES generator (MR-1685).
//
// Writes the notices file every desktop package ships at
// resources/THIRD-PARTY-NOTICES.txt (bundle.resources is "resources/*") and
// that Settings › About › Licences shows. Run by release.yml in each build
// job before `tauri build`, by nsis-installer.yml on PRs, and by tests.yml for
// all four release targets. Uses only node, cargo and what `npm ci` installed:
// no licence tool is added to the build.
//
//   node scripts/generate-third-party-notices.mjs --target <rust triple>
//        [--out src-tauri/resources/THIRD-PARTY-NOTICES.txt]
//        [--xray <bundled xray binary>] [--xray-license <LICENSE from the Xray zip>]
//        [--wintun-license <LICENSE.txt from the Wintun zip>] [--release]
//
// What it lists, and from where:
//  * Rust crates compiled into the release binary for --target: `cargo tree
//    -e normal,no-proc-macro --target <t>` over src-tauri/Cargo.lock. Normal
//    edges only: no dev-dependencies, no build scripts' dependencies and no
//    proc macros, none of which is linked. (`cargo metadata`'s resolve is NOT
//    used for the set: it unifies dev-dependency features and lists ~30
//    crates the release never builds, openssl among them.) Package
//    directories and licence fields come from `cargo metadata`.
//  * npm packages in the shipped UI bundle: package-lock.json entries that
//    are neither `dev` nor `devOptional`, i.e. package.json `dependencies`
//    and what they pull in. Read from node_modules (run `npm ci` first).
//  * Xray-core: its licence (MPL-2.0), "source: https://github.com/XTLS/
//    Xray-core at <XRAY_VERSION>" (the version release.yml downloads), and
//    the Go modules linked into the binary, read from the binary's own Go
//    build information with --xray. Each module must be listed, with its
//    licence, in third_party/licenses/xray-go-modules.json; GPL/LGPL/MPL ones
//    get a source pointer at their version and their texts (GPL-3.0 among
//    them).
//  * Wintun (Windows targets): its Prebuilt Binaries License.
//
// Every licence text is printed in full, once, and each component names the
// texts that apply to it. A component's own LICENSE/COPYING/NOTICE files are
// used where it ships them; one that ships none gets the standard text of
// each licence it declares from third_party/licenses/ (MIT, BSD and Zlib with the
// package's authors as the copyright line). A licence with neither fails the
// run: the fix is to add its text there, not to skip the package.
//
// --xray-license / --wintun-license: the licence file from the archive the
// build actually downloaded; it must match the committed copy, so a changed
// upstream licence fails the release instead of shipping the old text.
// --release: --xray and --xray-license are required (and --wintun-license on
// Windows) - release.yml and nsis-installer.yml pass it.
//
// Output is deterministic (no dates): the same inputs give the same bytes,
// which is what the post-bundle gates compare against.
// ============================================================================
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tauriDir = path.join(repo, 'src-tauri');
const licensesDir = path.join(repo, 'third_party', 'licenses');

function fail(message) {
  console.error(`::error::third-party notices: ${message}`);
  process.exit(1);
}

// ── Arguments ───────────────────────────────────────────────────────────────
const args = { out: path.join(tauriDir, 'resources', 'THIRD-PARTY-NOTICES.txt') };
{
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    const value = () => {
      if (i + 1 >= argv.length) fail(`${flag} needs a value`);
      return argv[++i];
    };
    switch (flag) {
      case '--target': args.target = value(); break;
      case '--out': args.out = path.resolve(value()); break;
      case '--xray': args.xray = path.resolve(value()); break;
      case '--xray-license': args.xrayLicense = path.resolve(value()); break;
      case '--wintun-license': args.wintunLicense = path.resolve(value()); break;
      case '--release': args.release = true; break;
      default: fail(`unknown argument ${flag}`);
    }
  }
}
if (!args.target) fail('--target <rust target triple> is required');
const windows = args.target.includes('windows');
if (args.release) {
  if (!args.xray) fail('--release needs --xray <the bundled xray binary>');
  if (!args.xrayLicense) fail('--release needs --xray-license <LICENSE from the Xray zip>');
  if (windows && !args.wintunLicense) fail('--release on Windows needs --wintun-license <LICENSE.txt from the Wintun zip>');
}

// ── Helpers ─────────────────────────────────────────────────────────────────
/** LF line ends, no BOM, no trailing spaces, no blank lines at either end. */
function normalize(text) {
  return text
    .replace(/^\uFEFF/, '')
    .replace(/\r\n?/g, '\n')
    .split('\n')
    .map((line) => line.replace(/\s+$/, ''))
    .join('\n')
    .replace(/^\n+|\n+$/g, '');
}

function readText(file) {
  return normalize(fs.readFileSync(file, 'utf8'));
}

function committed(name) {
  const file = path.join(licensesDir, name);
  if (!fs.existsSync(file)) fail(`missing committed licence text third_party/licenses/${name}`);
  return readText(file);
}

/** Byte order with no locale, so every OS sorts the same way. */
const byKey = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

function run(cmd, cmdArgs, cwd) {
  const r = spawnSync(cmd, cmdArgs, { cwd, encoding: 'utf8', maxBuffer: 512 * 1024 * 1024 });
  if (r.error) fail(`${cmd} ${cmdArgs.join(' ')}: ${r.error.message}`);
  if (r.status !== 0) fail(`${cmd} ${cmdArgs.join(' ')} exited ${r.status}:\n${r.stderr}`);
  return r.stdout;
}

/** The value of the one line in release.yml that matches `re` (group 1). */
function releasePin(re, what) {
  const yml = fs.readFileSync(path.join(repo, '.github', 'workflows', 'release.yml'), 'utf8').replace(/\r/g, '');
  const hits = [...yml.matchAll(re)];
  if (hits.length !== 1) fail(`release.yml: expected one ${what}, found ${hits.length}`);
  return hits[0][1];
}

// ── Licence texts: each printed once, numbered by first use ────────────────
const texts = [];
const textIndex = new Map();

/** Register a text; returns its id ("T3"). Identical texts (whitespace aside) share one id. */
function addText(body, origin) {
  const key = body.replace(/\s+/g, ' ').trim();
  let entry = textIndex.get(key);
  if (!entry) {
    entry = { id: `T${texts.length + 1}`, body, origin, more: 0 };
    texts.push(entry);
    textIndex.set(key, entry);
  } else {
    entry.more += 1;
  }
  return entry.id;
}

const LICENSE_FILE = /^(licen[cs]e|copying|copyright|notice|unlicense)([-._].*)?$/i;
// LICENSE.spdx (the Tauri packages) is SPDX metadata naming the licences, not
// their text: @tauri-apps/plugin-* ship nothing else, and get the standard
// texts instead.
const NOT_A_TEXT = /\.spdx$/i;

/** The licence files a package ships at its root (plus Cargo's license-file). */
function licenseFiles(dir, extra) {
  const found = new Set();
  for (const name of fs.readdirSync(dir)) {
    const file = path.join(dir, name);
    if (LICENSE_FILE.test(name) && !NOT_A_TEXT.test(name) && fs.statSync(file).isFile()) found.add(file);
  }
  if (extra) {
    const file = path.resolve(dir, extra);
    if (fs.existsSync(file) && fs.statSync(file).isFile()) found.add(file);
  }
  return [...found].sort(byKey);
}

/** SPDX ids in an expression ("MIT OR Apache-2.0", the old "MIT/Apache-2.0"). */
function spdxIds(expression) {
  return [...new Set(
    expression
      .replace(/[()]/g, ' ')
      .split(/\s+(?:OR|AND)\s+|\s*\/\s*|\s+WITH\s+\S+/)
      .map((s) => s.trim())
      .filter(Boolean),
  )];
}

// Standard texts for a package that ships no licence file. MIT, BSD and Zlib carry
// a copyright line, filled with the package's own authors.
const TEMPLATED = new Set(['MIT', 'BSD-2-Clause', 'BSD-3-Clause', 'Zlib']);

function fallbackTexts(label, expression, authors) {
  const ids = [];
  const declared = spdxIds(expression);
  if (declared.length === 0) fail(`${label} ships no licence file and declares no SPDX licence`);
  for (const id of declared) {
    const file = path.join(licensesDir, `${id}.txt`);
    if (!fs.existsSync(file)) {
      fail(`${label} ships no licence file and declares ${id}, which has no standard text in third_party/licenses/${id}.txt - add it`);
    }
    let body = readText(file);
    if (TEMPLATED.has(id)) {
      const holders = authors.length ? authors.join(', ') : `the ${label.split(' ')[0]} authors`;
      body = `Copyright (c) ${holders}\n\n${body}`;
    }
    ids.push(addText(body, `${id} (standard text; ${label} ships no licence file)`));
  }
  return ids;
}

function componentTexts(label, dir, expression, authors, licenseFile) {
  const files = licenseFiles(dir, licenseFile);
  if (files.length === 0) return fallbackTexts(label, expression, authors);
  return files.map((file) => addText(readText(file), `${path.basename(file)} of ${label}`));
}

// ── Bundled programs ────────────────────────────────────────────────────────
const appVersion = JSON.parse(fs.readFileSync(path.join(tauriDir, 'tauri.conf.json'), 'utf8')).version;
const xrayVersion = releasePin(/^\s*XRAY_VERSION: (v[0-9][0-9.]*)$/gm, 'XRAY_VERSION');
const programs = [];

{
  const mpl = committed('MPL-2.0.txt');
  if (args.xrayLicense && readText(args.xrayLicense) !== mpl) {
    fail(`the Xray ${xrayVersion} archive's LICENSE differs from third_party/licenses/MPL-2.0.txt - review the change and update the committed copy`);
  }
  const xray = {
    name: `Xray-core ${xrayVersion}`,
    file: windows ? 'resources/xray.exe' : 'resources/xray',
    license: 'MPL-2.0',
    texts: [addText(mpl, `LICENSE of Xray-core ${xrayVersion}`)],
    lines: [`source: https://github.com/XTLS/Xray-core at ${xrayVersion}`],
  };
  if (args.xray) {
    const modules = goModules(args.xray);
    const table = JSON.parse(fs.readFileSync(path.join(licensesDir, 'xray-go-modules.json'), 'utf8'));
    const unknown = modules.filter((m) => !table[m.path]);
    if (unknown.length) {
      fail(
        `the xray binary links Go modules with no licence entry in third_party/licenses/xray-go-modules.json: ` +
          `${unknown.map((m) => `${m.path} ${m.version}`).join(', ')}. Check each one's licence and add it ` +
          '(with `source` and `texts` if it is GPL, LGPL or MPL).',
      );
    }
    const copyleft = modules.filter((m) => table[m.path].texts);
    for (const m of copyleft) {
      if (!table[m.path].source) fail(`xray-go-modules.json: ${m.path} has texts but no source`);
    }
    if (copyleft.length) {
      xray.lines.push('', 'Go modules linked into this xray binary whose licence requires their source to be offered:');
      for (const m of copyleft) {
        const entry = table[m.path];
        const ids = entry.texts.map((t) => addText(committed(t), `${t.replace(/^xray\//, '')} (${m.path})`));
        xray.lines.push(`  ${m.path} ${m.version} - ${entry.license} [${[...new Set(ids)].join(', ')}]`);
        xray.lines.push(`    source: ${entry.source} at ${m.version}`);
      }
      if (copyleft.some((m) => /\bGPL/.test(table[m.path].license))) {
        xray.lines.push(
          '',
          'Because GPL-3.0 modules are linked into it, this xray binary as a whole is distributed under',
          'the terms of the GNU General Public License version 3; the MPL-2.0 files in it stay available',
          `under MPL-2.0 too. Its complete corresponding source is Xray-core at ${xrayVersion} (above),`,
          'whose go.mod and go.sum pin every module listed below. BirdoVPN runs xray as a separate program.',
        );
      }
    }
    xray.lines.push('', 'All Go modules linked into this xray binary (from its embedded build information):');
    for (const m of modules) xray.lines.push(`  ${m.path} ${m.version} - ${table[m.path].license}`);
  } else {
    xray.lines.push('', 'Go modules: not read in this run (no --xray binary given; release builds pass it).');
  }
  programs.push(xray);
}

if (windows) {
  const wintunVersion = releasePin(/wintun-([0-9][0-9.]*[0-9])\.zip"$/gm, 'Wintun download URL');
  const text = committed('wintun-LICENSE.txt');
  if (args.wintunLicense && readText(args.wintunLicense) !== text) {
    fail(`the Wintun ${wintunVersion} archive's LICENSE.txt differs from third_party/licenses/wintun-LICENSE.txt - review the change and update the committed copy`);
  }
  programs.push({
    name: `Wintun ${wintunVersion} (WireGuard LLC)`,
    file: 'resources/wintun.dll',
    license: 'Prebuilt Binaries License',
    texts: [addText(text, `LICENSE.txt of Wintun ${wintunVersion}`)],
    lines: [
      `source: https://www.wintun.net (the unmodified wintun.dll from wintun-${wintunVersion}.zip)`,
      'BirdoVPN uses wintun.dll only through the API in wintun.h.',
    ],
  });
}

/** Go modules from a Go binary's build information (Go 1.18+ inline format). */
function goModules(file) {
  const buf = fs.readFileSync(file);
  const at = buf.indexOf(Buffer.from('\xff Go buildinf:', 'latin1'));
  if (at < 0) fail(`${file}: no Go build information - is this the xray binary?`);
  if ((buf[at + 15] & 2) === 0) fail(`${file}: Go build information in the pre-Go 1.18 format`);
  let p = at + 32;
  const uvarint = () => {
    let x = 0;
    for (let shift = 0; ; shift += 7) {
      const b = buf[p++];
      x += (b & 0x7f) * 2 ** shift;
      if (b < 0x80) return x;
    }
  };
  const str = () => {
    const n = uvarint();
    const s = buf.subarray(p, p + n).toString('utf8');
    p += n;
    return s;
  };
  str(); // the Go version
  const info = str();
  // 16-byte sentinels on either side of the module text.
  const lines = info.length > 32 ? info.slice(16, -16).split('\n') : [];
  if (!lines.some((l) => /^mod\tgithub\.com\/xtls\/xray-core\t/.test(l))) {
    fail(`${file}: its build information is not github.com/xtls/xray-core's`);
  }
  const modules = [];
  for (const line of lines) {
    const [kind, modPath, version] = line.split('\t');
    if (kind === '=>') fail(`${file}: a replaced module (${line.trim()}): extend the generator to name the replacement's source`);
    if (kind === 'dep') modules.push({ path: modPath, version });
  }
  if (modules.length === 0) fail(`${file}: no Go modules in its build information`);
  return modules.sort((a, b) => byKey(a.path, b.path));
}

// ── Rust crates ─────────────────────────────────────────────────────────────
const crates = [];
{
  const tree = run(
    'cargo',
    ['tree', '--locked', '-e', 'normal,no-proc-macro', '--target', args.target, '--prefix', 'none', '--format', '{p}'],
    tauriDir,
  );
  const linked = new Set();
  for (const line of tree.split('\n')) {
    const m = /^(\S+) v(\S+)/.exec(line.trim());
    if (m) linked.add(`${m[1]} ${m[2]}`);
  }
  const metadata = JSON.parse(
    run('cargo', ['metadata', '--locked', '--format-version', '1', '--filter-platform', args.target], tauriDir),
  );
  const root = metadata.packages.find((p) => p.id === metadata.resolve.root);
  const packages = new Map(metadata.packages.map((p) => [`${p.name} ${p.version}`, p]));
  const linkedPackages = [...linked].map((key) => {
    const pkg = packages.get(key);
    if (!pkg) fail(`cargo tree lists ${key}, which cargo metadata does not`);
    return pkg;
  });
  // Sorted before the texts are numbered, so [T..] ids rise down the list.
  linkedPackages.sort((a, b) => byKey(a.name, b.name) || byKey(a.version, b.version));
  for (const pkg of linkedPackages) {
    if (pkg.id === root.id) continue;
    const label = `${pkg.name} ${pkg.version}`;
    if (!pkg.license && !pkg.license_file) fail(`crate ${label} declares no licence`);
    const expression = pkg.license || `see ${pkg.license_file}`;
    crates.push({
      name: pkg.name,
      version: pkg.version,
      license: expression,
      url: pkg.repository || pkg.homepage || `https://crates.io/crates/${pkg.name}`,
      texts: componentTexts(label, path.dirname(pkg.manifest_path), pkg.license || '', pkg.authors || [], pkg.license_file),
    });
  }
  if (crates.length < 100) fail(`only ${crates.length} crates for ${args.target} - cargo tree output not understood`);
}

// ── npm packages ────────────────────────────────────────────────────────────
const npmPackages = [];
{
  const lock = JSON.parse(fs.readFileSync(path.join(repo, 'package-lock.json'), 'utf8'));
  const shipped = Object.entries(lock.packages)
    .filter(([key, entry]) => key.startsWith('node_modules/') && !entry.dev && !entry.devOptional)
    .map(([key, entry]) => ({ key, entry, name: key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length) }))
    .sort((a, b) => byKey(a.name, b.name) || byKey(a.entry.version, b.entry.version) || byKey(a.key, b.key));
  for (const { key, entry, name } of shipped) {
    const dir = path.join(repo, key);
    const pkgJson = path.join(dir, 'package.json');
    if (!fs.existsSync(pkgJson)) fail(`${key} is not installed - run \`npm ci\` first`);
    const manifest = JSON.parse(fs.readFileSync(pkgJson, 'utf8'));
    const license = entry.license || manifest.license;
    if (!license) fail(`npm package ${name} ${entry.version} declares no licence`);
    const repoUrl = typeof manifest.repository === 'string' ? manifest.repository : manifest.repository?.url;
    // `author` is the standard field; the Tauri packages use `authors`.
    const people = [manifest.author, ...[manifest.authors, manifest.contributors].flatMap((v) => (Array.isArray(v) ? v : []))];
    const authors = people.map((p) => (typeof p === 'string' ? p : p?.name)).filter(Boolean);
    npmPackages.push({
      name,
      version: entry.version,
      license,
      url: (repoUrl || manifest.homepage || `https://www.npmjs.com/package/${name}`).replace(/^git\+/, ''),
      texts: componentTexts(`${name} ${entry.version}`, dir, license, authors),
    });
  }
  if (npmPackages.length === 0) fail('no npm packages found in package-lock.json');
}

// ── Render ──────────────────────────────────────────────────────────────────
const rule = '='.repeat(78);
const out = [];
out.push(
  `THIRD-PARTY SOFTWARE NOTICES - BirdoVPN ${appVersion} (${args.target})`,
  '',
  'BirdoVPN includes the third-party software listed below. Each component is',
  'distributed under its own licence; the full text of every licence is in',
  'section 4, and each component names the texts [T1], [T2], ... that apply to it.',
  'Generated by scripts/generate-third-party-notices.mjs from src-tauri/Cargo.lock,',
  'package-lock.json and the programs bundled in this build.',
  '',
  rule,
  '1. Programs bundled with BirdoVPN',
  rule,
);
for (const p of programs) {
  out.push('', `${p.name} - ${p.file}`, `  Licence: ${p.license} [${p.texts.join(', ')}]`);
  for (const line of p.lines) out.push(line ? `  ${line}` : '');
}
const listing = (title, items) => {
  out.push('', rule, title, rule, '');
  for (const c of items) out.push(`${c.name} ${c.version} - ${c.license} - ${c.url} [${[...new Set(c.texts)].join(', ')}]`);
};
listing(`2. Rust crates compiled into BirdoVPN (${crates.length})`, crates);
listing(`3. npm packages in the BirdoVPN user interface (${npmPackages.length})`, npmPackages);
out.push('', rule, `4. Licence texts (${texts.length})`, rule);
for (const t of texts) {
  const more = t.more ? ` (and ${t.more} more identical)` : '';
  out.push('', `----- [${t.id}] ${t.origin}${more} `.padEnd(78, '-'), '', t.body);
}
const body = `${out.join('\n')}\n`;

fs.mkdirSync(path.dirname(args.out), { recursive: true });
fs.writeFileSync(args.out, body, 'utf8');
console.log(
  `Wrote ${path.relative(repo, args.out)}: ${crates.length} crates, ${npmPackages.length} npm packages, ` +
    `${programs.length} bundled programs, ${texts.length} licence texts, ${body.length} bytes (${args.target})`,
);
