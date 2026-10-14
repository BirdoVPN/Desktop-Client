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
//  * Other code and assets in the UI bundle (third_party/licenses/
//    bundle-extras.json): the Inter font, and the devDependencies whose own
//    code the build copies in (Tailwind's Preflight, Vite's modulepreload
//    polyfill, rolldown's runtime helpers).
//  * Xray-core: its licence (MPL-2.0) and its source: first the release
//    asset BirdoVPN-<version>-corresponding-source.tar.gz of THIS version
//    (scripts/lib/corresponding-source.mjs; owner decision 2026-10-14, L1),
//    which carries the Xray-core source at the commit XRAY_VERSION names
//    (the version release.yml downloads) and the zip of every Go module it
//    links, then the upstream repository at that tag. With --xray, the Go
//    toolchain and every Go module linked into the binary, read from the
//    binary's own Go build information. Each must be in
//    third_party/licenses/xray-go-modules.json with exactly the linked
//    version and its vendored licence files (scripts/vendor-xray-go-
//    licences.mjs) and the `zipSha256` of the zip the asset mirrors;
//    GPL/LGPL/MPL ones also need `source`, and get the path of their zip in
//    that asset plus their upstream at their version, and the GPL-3.0 text.
//  * Wintun (Windows targets): its Prebuilt Binaries License.
//
// Every licence text is printed in full, once, and each component names the
// texts that apply to it. A component's own LICENSE/COPYING/NOTICE files are
// used where it ships them; one that ships none gets its project's licence
// files from third_party/licenses/package-licences.json, or else the
// standard text of each licence it declares from third_party/licenses/
// (MIT, BSD and Zlib with the package's authors as the copyright line). A
// licence with no text fails the run: the fix is to add its text there, not
// to skip the package.
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
import { readGoBuildInfo } from './lib/go-buildinfo.mjs';
import { COPYLEFT, moduleZipMember, sourceAssetUrl, xrayModuleProblems, xrayTagArchiveMember } from './lib/corresponding-source.mjs';

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

function readJson(name) {
  return JSON.parse(fs.readFileSync(path.join(licensesDir, name), 'utf8'));
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

/** Committed texts (paths under third_party/licenses/), registered; returns their ids. */
function committedTexts(paths, label) {
  return [...new Set(paths.map((t) => addText(committed(t), `${path.basename(t)} of ${label}`)))];
}

const LICENSE_FILE = /^(licen[cs]e|copying|copyright|notice|unlicense)([-._].*)?$/i;
// LICENSE.spdx (the Tauri packages) is SPDX metadata naming the licences, not
// their text: @tauri-apps/plugin-* ship nothing else, and get their project's
// licence files from package-licences.json instead.
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

// Standard texts, the last resort for a package that ships no licence file and
// has no entry in package-licences.json. MIT, BSD and Zlib carry a copyright
// line, filled with the package's own authors.
const TEMPLATED = new Set(['MIT', 'BSD-2-Clause', 'BSD-3-Clause', 'Zlib']);
const packageLicences = readJson('package-licences.json');

function fallbackTexts(name, label, expression, authors) {
  const upstream = packageLicences[name];
  if (upstream) return committedTexts(upstream.texts, `${label} (from ${upstream.from})`);
  const ids = [];
  const declared = spdxIds(expression);
  if (declared.length === 0) fail(`${label} ships no licence file and declares no SPDX licence`);
  for (const id of declared) {
    const file = path.join(licensesDir, `${id}.txt`);
    if (!fs.existsSync(file)) {
      fail(`${label} ships no licence file and declares ${id}, which has no standard text in third_party/licenses/${id}.txt - add its project's licence files to package-licences.json, or the standard text`);
    }
    let body = readText(file);
    if (TEMPLATED.has(id)) {
      const holders = authors.length ? authors.join(', ') : `the ${name} authors`;
      body = `Copyright (c) ${holders}\n\n${body}`;
    }
    ids.push(addText(body, `${id} (standard text; ${label} ships no licence file)`));
  }
  return ids;
}

function componentTexts(name, label, dir, expression, authors, licenseFile) {
  const files = licenseFiles(dir, licenseFile);
  if (files.length === 0) return fallbackTexts(name, label, expression, authors);
  return files.map((file) => addText(readText(file), `${path.basename(file)} of ${label}`));
}

// ── Bundled programs ────────────────────────────────────────────────────────
const appVersion = JSON.parse(fs.readFileSync(path.join(tauriDir, 'tauri.conf.json'), 'utf8')).version;
const xrayVersion = releasePin(/^\s*XRAY_VERSION: (v[0-9][0-9.]*)$/gm, 'XRAY_VERSION');
const programs = [];
// The release asset that mirrors the source (L1). Release builds of this
// version publish it; every build names it, so the notices are the same
// whichever job wrote them.
const sourceAsset = sourceAssetUrl(appVersion);

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
    lines: [
      `source: ${sourceAsset}`,
      `  (published with BirdoVPN ${appVersion}: ${xrayTagArchiveMember(xrayVersion)} in it is the Xray-core`,
      `  source at the commit the ${xrayVersion} tag names, and xray/go-modules/ the source of every Go`,
      '  module listed below, at the version linked)',
      `upstream: https://github.com/XTLS/Xray-core at ${xrayVersion}`,
    ],
  };
  if (args.xray) {
    let info;
    try {
      info = readGoBuildInfo(args.xray);
    } catch (e) {
      fail(e.message);
    }
    if (info.main !== 'github.com/xtls/xray-core') fail(`${args.xray} is ${info.main}, not github.com/xtls/xray-core`);
    const table = readJson('xray-go-modules.json');
    const refresh =
      'Run `node scripts/vendor-xray-go-licences.mjs <the four release xray binaries>`, review what it ' +
      'marks NEW, and commit third_party/licenses/.';
    const toolchain = table.toolchain || {};
    if (toolchain.version !== info.goVersion) {
      fail(`the xray binary was built by ${info.goVersion}; xray-go-modules.json has the Go licence of ${toolchain.version || 'none'}. ${refresh}`);
    }
    const problems = xrayModuleProblems(info.modules, table);
    if (problems.length) fail(`xray's Go modules do not match third_party/licenses/xray-go-modules.json:\n  ${problems.join('\n  ')}\n${refresh}`);

    const goIds = committedTexts(toolchain.texts, `Go ${info.goVersion.replace(/^go/, '')}`);
    xray.lines.push(
      '',
      'Built with Go, whose standard library and runtime are linked into it:',
      `  Go ${info.goVersion.replace(/^go/, '')} - ${toolchain.license} [${goIds.join(', ')}]`,
      `    source: ${toolchain.source} at ${info.goVersion}`,
      '',
      'Go modules linked into it (from its embedded build information); the source of each is',
      `xray/go-modules/<module>@<version>.zip in ${sourceAsset}:`,
    );
    const copyleft = [];
    for (const m of info.modules) {
      const e = table.modules[m.path];
      const ids = committedTexts(e.texts, `${m.path} ${m.version}`);
      xray.lines.push(`  ${m.path} ${m.version} - ${e.license} [${ids.join(', ')}]`);
      if (COPYLEFT.test(e.license)) copyleft.push({ ...m, e });
    }
    if (copyleft.length) {
      xray.lines.push('', 'Of those, the ones whose licence requires their source to be offered:');
      for (const m of copyleft) {
        xray.lines.push(
          `  ${m.path} ${m.version} - ${m.e.license}`,
          `    source: ${moduleZipMember(m.path, m.version)} in ${sourceAsset}`,
          `    upstream: ${m.e.source} at ${m.version}`,
        );
      }
    }
    if (copyleft.some((m) => /\bGPL/.test(m.e.license))) {
      xray.lines.push(
        '',
        'Because GPL-3.0 modules are linked into it, this xray binary as a whole is distributed under',
        'the terms of the GNU General Public License version 3; the MPL-2.0 files in it stay available',
        'under MPL-2.0 too. Its complete corresponding source is the release asset named above, on the',
        `same release page as this version of BirdoVPN: the Xray-core ${xrayVersion} source, whose go.mod`,
        'and go.sum pin every module listed here, and the source of every one of those modules at the',
        'version linked. (The Go standard library and runtime are part of the Go toolchain, a System',
        "Library in the GPL-3.0's terms; their source is above.) BirdoVPN runs xray as a separate program.",
      );
    }
  } else {
    xray.lines.push('', 'Go toolchain and modules: not read in this run (no --xray binary given; release builds pass it).');
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
    crates.push({
      name: pkg.name,
      version: pkg.version,
      license: pkg.license || `see ${pkg.license_file}`,
      url: pkg.repository || pkg.homepage || `https://crates.io/crates/${pkg.name}`,
      texts: componentTexts(pkg.name, label, path.dirname(pkg.manifest_path), pkg.license || '', pkg.authors || [], pkg.license_file),
    });
  }
  if (crates.length < 100) fail(`only ${crates.length} crates for ${args.target} - cargo tree output not understood`);
}

// ── npm packages, and the rest of the UI bundle ─────────────────────────────
const lock = JSON.parse(fs.readFileSync(path.join(repo, 'package-lock.json'), 'utf8'));

function installed(key) {
  const dir = path.join(repo, key);
  const pkgJson = path.join(dir, 'package.json');
  if (!fs.existsSync(pkgJson)) fail(`${key} is not installed - run \`npm ci\` first`);
  return { dir, manifest: JSON.parse(fs.readFileSync(pkgJson, 'utf8')) };
}

const npmUrl = (manifest, name) => {
  const repoUrl = typeof manifest.repository === 'string' ? manifest.repository : manifest.repository?.url;
  return (repoUrl || manifest.homepage || `https://www.npmjs.com/package/${name}`).replace(/^git\+/, '');
};

const npmPackages = [];
{
  const shipped = Object.entries(lock.packages)
    .filter(([key, entry]) => key.startsWith('node_modules/') && !entry.dev && !entry.devOptional)
    .map(([key, entry]) => ({ key, entry, name: key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length) }))
    .sort((a, b) => byKey(a.name, b.name) || byKey(a.entry.version, b.entry.version) || byKey(a.key, b.key));
  for (const { key, entry, name } of shipped) {
    const { dir, manifest } = installed(key);
    const license = entry.license || manifest.license;
    if (!license) fail(`npm package ${name} ${entry.version} declares no licence`);
    // `author` is the standard field; the Tauri packages use `authors`.
    const people = [manifest.author, ...[manifest.authors, manifest.contributors].flatMap((v) => (Array.isArray(v) ? v : []))];
    const authors = people.map((p) => (typeof p === 'string' ? p : p?.name)).filter(Boolean);
    npmPackages.push({
      name,
      version: entry.version,
      license,
      url: npmUrl(manifest, name),
      texts: componentTexts(name, `${name} ${entry.version}`, dir, license, authors),
    });
  }
  if (npmPackages.length === 0) fail('no npm packages found in package-lock.json');
}

const uiExtras = [];
{
  const extras = readJson('bundle-extras.json');
  for (const a of extras.assets) {
    if (!fs.existsSync(path.join(repo, a.file))) fail(`bundle-extras.json: ${a.file} does not exist - update the entry`);
    uiExtras.push({
      line: `${a.name} ${a.version} - ${a.license} - ${a.url}`,
      what: `${a.what} (${a.file})`,
      texts: committedTexts(a.texts, `${a.name} ${a.version}`),
    });
  }
  for (const d of extras.devPackages) {
    const key = `node_modules/${d.package}`;
    const entry = lock.packages[key];
    if (!entry) fail(`bundle-extras.json: ${d.package} is not in package-lock.json - update the entry`);
    const { dir, manifest } = installed(key);
    const label = `${d.package} ${entry.version}`;
    const files = licenseFiles(dir);
    if (files.length === 0) fail(`${label} ships no licence file`);
    const ids = files.map((file) => {
      let body = readText(file);
      if (d.cutAt) {
        const at = body.indexOf(d.cutAt);
        if (at < 0) fail(`bundle-extras.json: "${d.cutAt}" is not in ${label}'s ${path.basename(file)} - update cutAt`);
        body = normalize(body.slice(0, at));
      }
      return addText(body, `${path.basename(file)} of ${label}`);
    });
    uiExtras.push({
      line: `${d.package} ${entry.version} - ${entry.license || manifest.license} - ${npmUrl(manifest, d.package)}`,
      what: d.what,
      texts: [...new Set(ids)],
    });
  }
}

// ── Render ──────────────────────────────────────────────────────────────────
const rule = '='.repeat(78);
const out = [];
out.push(
  `THIRD-PARTY SOFTWARE NOTICES - BirdoVPN ${appVersion} (${args.target})`,
  '',
  'BirdoVPN includes the third-party software listed below. Each component is',
  'distributed under its own licence; the full text of every licence is in',
  'section 5, and each component names the texts [T1], [T2], ... that apply to it.',
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
const heading = (title) => out.push('', rule, title, rule, '');
const listing = (title, items) => {
  heading(title);
  for (const c of items) out.push(`${c.name} ${c.version} - ${c.license} - ${c.url} [${[...new Set(c.texts)].join(', ')}]`);
};
listing(`2. Rust crates compiled into BirdoVPN (${crates.length})`, crates);
listing(`3. npm packages in the BirdoVPN user interface (${npmPackages.length})`, npmPackages);
heading(`4. Other code and assets in the BirdoVPN user interface (${uiExtras.length})`);
for (const x of uiExtras) out.push(`${x.line} [${x.texts.join(', ')}]`, `  ${x.what}`);
out.push('', rule, `5. Licence texts (${texts.length})`, rule);
for (const t of texts) {
  const more = t.more ? ` (and ${t.more} more identical)` : '';
  out.push('', `----- [${t.id}] ${t.origin}${more} `.padEnd(78, '-'), '', t.body);
}
const body = `${out.join('\n')}\n`;

fs.mkdirSync(path.dirname(args.out), { recursive: true });
fs.writeFileSync(args.out, body, 'utf8');
console.log(
  `Wrote ${path.relative(repo, args.out)}: ${crates.length} crates, ${npmPackages.length} npm packages, ` +
    `${uiExtras.length} other UI items, ${programs.length} bundled programs, ${texts.length} licence texts, ` +
    `${Buffer.byteLength(body)} bytes (${args.target})`,
);
