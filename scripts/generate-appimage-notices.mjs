#!/usr/bin/env node
// ============================================================================
// AppImage-only notices: the system libraries the AppImage bundles (owner
// decision 2026-10-14, L2: list them in the notices).
//
// The .deb uses the libraries the user's system provides; the AppImage
// carries its own, copied by Tauri's bundler (linuxdeploy and its GTK plugin)
// from the Ubuntu system it is built on: WebKitGTK, GTK, GLib, libsoup and
// everything they link, about 175 files from about 100 packages. This script
// lists every one of them in the AppImage's copy of THIRD-PARTY-NOTICES.txt,
// after the sections every package carries:
//
//   node scripts/generate-appimage-notices.mjs --appdir <unpacked AppImage>
//        --base <this build's THIRD-PARTY-NOTICES.txt> --out <file>
//        [--doc-root /usr/share/doc] [--licenses-root /usr/share/common-licenses]
//        [--os-release /etc/os-release] [--host-root /] [--multiarch <triplet>]
//
// Run on the build host, right after `tauri build` made the AppImage, by
// scripts/ci/appimage-notices.sh (release.yml's build-linux, and the PR
// workflow linux-packages.yml), which then re-bundles the AppImage with the
// result. For every ELF file under usr/ in the AppImage (shared libraries,
// GTK/GIO/gdk-pixbuf modules, WebKitGTK's helper programs), except BirdoVPN's
// own (usr/bin/<binary>, usr/lib/<productName>/, already in sections 1-4):
//  * the Ubuntu package it came from: `dpkg -S` on the build host, by its
//    path below usr/lib (linuxdeploy copies a library into usr/lib/ under the
//    name it was loaded by, and keeps a module's directory below its
//    multiarch lib dir), falling back to the host file it resolves to;
//  * that package's version, and its source package and exact version
//    (`dpkg-query`), with where to get that source: `apt-get source` or the
//    Launchpad page of that exact upload;
//  * the package's copyright file (/usr/share/doc/<package>/copyright) in
//    full, and the full text of every licence it refers to in
//    /usr/share/common-licenses (where Debian keeps the GPL and LGPL texts
//    that copyright files cite rather than repeat).
// It FAILS when a file maps to no package or to more than one, when a package
// has no copyright file, or when a cited common licence is missing: the fix
// is never to leave a library out. scripts/ci/verify-bundled-xray.sh checks
// the final AppImage: every ELF file under usr/ must be listed here.
//
// dpkg and dpkg-query are taken from PATH (a fixture can stand in for them:
// scripts/ci/appimage-notices.tests.sh). Output is deterministic for a given
// AppImage and build host. Node built-ins only.
// ============================================================================
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function fail(message) {
  console.error(`::error::AppImage notices: ${message}`);
  process.exit(1);
}

// ── Arguments ───────────────────────────────────────────────────────────────
const MULTIARCH = { x64: 'x86_64-linux-gnu', arm64: 'aarch64-linux-gnu' };
const args = {
  docRoot: '/usr/share/doc',
  licensesRoot: '/usr/share/common-licenses',
  osRelease: '/etc/os-release',
  hostRoot: '/',
  multiarch: MULTIARCH[process.arch] || `${process.arch}-linux-gnu`,
};
{
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    const value = () => {
      if (i + 1 >= argv.length) fail(`${flag} needs a value`);
      return argv[++i];
    };
    switch (flag) {
      case '--appdir': args.appdir = path.resolve(value()); break;
      case '--base': args.base = path.resolve(value()); break;
      case '--out': args.out = path.resolve(value()); break;
      case '--doc-root': args.docRoot = value(); break;
      case '--licenses-root': args.licensesRoot = value(); break;
      case '--os-release': args.osRelease = value(); break;
      case '--host-root': args.hostRoot = value(); break;
      case '--multiarch': args.multiarch = value(); break;
      default: fail(`unknown argument ${flag}`);
    }
  }
}
for (const required of ['appdir', 'base', 'out']) if (!args[required]) fail(`--${required} is required`);

// ── Helpers ─────────────────────────────────────────────────────────────────
/** LF line ends, no BOM, no trailing spaces, no blank lines at either end (as the main generator). */
function normalize(text) {
  return text
    .replace(/^\uFEFF/, '')
    .replace(/\r\n?/g, '\n')
    .split('\n')
    .map((line) => line.replace(/\s+$/, ''))
    .join('\n')
    .replace(/^\n+|\n+$/g, '');
}
const byKey = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

function run(cmd, cmdArgs, okStatuses = [0]) {
  const r = spawnSync(cmd, cmdArgs, { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 });
  if (r.error) fail(`${cmd}: ${r.error.message}`);
  if (!okStatuses.includes(r.status)) fail(`${cmd} ${cmdArgs.slice(0, 3).join(' ')} ... exited ${r.status}:\n${r.stderr}`);
  return r.stdout;
}

const host = (p) => path.join(args.hostRoot, p);

// ── What the AppImage carries ───────────────────────────────────────────────
const productName = JSON.parse(fs.readFileSync(path.join(repo, 'src-tauri', 'tauri.conf.json'), 'utf8')).productName;
const binaryName = (() => {
  const toml = fs.readFileSync(path.join(repo, 'src-tauri', 'Cargo.toml'), 'utf8');
  const pkg = toml.split(/^\[/m).find((s) => s.startsWith('package]'));
  const m = pkg && /^\s*name\s*=\s*"([^"]+)"/m.exec(pkg);
  if (!m) fail('src-tauri/Cargo.toml: no [package] name');
  return m[1];
})();
const isOwn = (rel) => rel === `usr/bin/${binaryName}` || rel.startsWith(`usr/lib/${productName}/`);

if (!fs.existsSync(path.join(args.appdir, 'usr'))) fail(`${args.appdir} has no usr/ - not an unpacked AppImage`);
const ELF = Buffer.from([0x7f, 0x45, 0x4c, 0x46]);
const elfFiles = [];
(function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => byKey(a.name, b.name))) {
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(file);
    else if (entry.isFile()) {
      const head = Buffer.alloc(4);
      const fd = fs.openSync(file, 'r');
      const read = fs.readSync(fd, head, 0, 4, 0);
      fs.closeSync(fd);
      if (read === 4 && head.equals(ELF)) elfFiles.push(path.relative(args.appdir, file).split(path.sep).join('/'));
    }
    // Symlinks are not followed: linuxdeploy's links point at files inside
    // the AppDir, which are listed under their own paths.
  }
})(path.join(args.appdir, 'usr'));
elfFiles.sort(byKey);
const own = elfFiles.filter(isOwn);
const bundled = elfFiles.filter((rel) => !isOwn(rel));
if (bundled.length === 0) fail(`no bundled library under ${args.appdir}/usr - is this the AppImage?`);

// ── Which package each came from ────────────────────────────────────────────
// Where a file below usr/lib/ in the AppImage was on the build host.
const libBases = [`/usr/lib/${args.multiarch}`, `/lib/${args.multiarch}`, '/usr/lib', '/lib'];
const hostCandidates = (rel) =>
  rel.startsWith('usr/lib/') ? libBases.map((b) => `${b}/${rel.slice('usr/lib/'.length)}`) : [`/${rel}`, `/${rel.slice('usr/'.length)}`];

/** `dpkg -S` over many patterns at once: path -> [packages]. Unmatched patterns are not an error here. */
function dpkgSearch(patterns) {
  const owners = new Map();
  if (patterns.length === 0) return owners;
  const out = run('dpkg', ['-S', ...patterns], [0, 1]);
  for (const line of out.split('\n')) {
    if (!line || line.startsWith('diversion by') || line.startsWith('local diversion')) continue;
    const m = /^(.+?): (\/.*)$/.exec(line);
    if (!m) continue;
    const pkgs = m[1].split(',').map((s) => s.trim()).filter(Boolean);
    owners.set(m[2], [...new Set([...(owners.get(m[2]) || []), ...pkgs])]);
  }
  return owners;
}

const owners = dpkgSearch([...new Set(bundled.map((rel) => `*/${path.posix.basename(rel)}`))].sort(byKey));
const packageOf = new Map(); // rel -> { pkg, hostPath }
const problems = [];
const unresolved = [];
const pick = (rel, candidates, lookup) => {
  const found = new Map();
  for (const c of candidates) for (const pkg of lookup.get(c) || []) found.set(pkg, found.get(pkg) || c);
  return found;
};
for (const rel of bundled) {
  const found = pick(rel, hostCandidates(rel), owners);
  if (found.size === 1) {
    const [[pkg, hostPath]] = [...found];
    packageOf.set(rel, { pkg, hostPath });
  } else if (found.size > 1) problems.push(`${rel}: more than one package owns it (${[...found].map(([p, h]) => `${p} ${h}`).join(', ')})`);
  else unresolved.push(rel);
}
// A name no package ships (e.g. a soname link ldconfig made): the file it
// resolves to on the build host, and that file's package.
if (unresolved.length) {
  const real = new Map(); // rel -> [host real paths]
  const hostRoot = fs.realpathSync(args.hostRoot);
  for (const rel of unresolved) {
    const paths = [];
    for (const c of hostCandidates(rel)) {
      if (!fs.existsSync(host(c))) continue;
      const r = `/${path.relative(hostRoot, fs.realpathSync(host(c))).split(path.sep).join('/')}`;
      paths.push(r, r.startsWith('/usr/') ? r.slice(4) : `/usr${r}`); // usrmerge: dpkg knows one spelling
    }
    real.set(rel, [...new Set(paths)]);
  }
  const owners2 = dpkgSearch([...new Set([...real.values()].flat())].sort(byKey));
  for (const rel of unresolved) {
    const found = pick(rel, real.get(rel), owners2);
    if (found.size === 1) {
      const [[pkg, hostPath]] = [...found];
      packageOf.set(rel, { pkg, hostPath });
    } else if (found.size > 1) problems.push(`${rel}: more than one package owns it (${[...found].map(([p, h]) => `${p} ${h}`).join(', ')})`);
    else problems.push(`${rel}: no installed package owns it (dpkg -S, at ${hostCandidates(rel).join(', ')}) - a library from outside the package manager cannot be listed with its source`);
  }
}
if (problems.length) fail(`bundled files the notices cannot account for:\n  ${problems.join('\n  ')}`);

// ── The packages ────────────────────────────────────────────────────────────
const pkgNames = [...new Set([...packageOf.values()].map((v) => v.pkg))].sort(byKey);
const FIELDS = '${binary:Package}\\t${Package}\\t${Architecture}\\t${Version}\\t${source:Package}\\t${source:Version}\\n';
const packages = new Map();
for (const line of run('dpkg-query', ['-W', `-f=${FIELDS}`, ...pkgNames]).split('\n')) {
  const [query, name, arch, version, srcName, srcVersion] = line.split('\t');
  if (!query) continue;
  if (!name || !version || !srcName || !srcVersion) fail(`dpkg-query gave an incomplete line for ${query}: ${JSON.stringify(line)}`);
  const entry = { name, arch, version, srcName, srcVersion, files: [] };
  packages.set(query, entry);
  if (!packages.has(name)) packages.set(name, entry); // dpkg -S may name it with or without :arch
}
for (const [rel, { pkg, hostPath }] of packageOf) {
  const p = packages.get(pkg) || packages.get(pkg.replace(/:[^:]+$/, ''));
  if (!p) fail(`dpkg-query does not know ${pkg} (owner of ${rel})`);
  p.files.push(rel);
  // The mapping, for the build log.
  console.log(`  ${rel} <- ${hostPath} (${p.name} ${p.version})`);
}

// ── Licence texts: each printed once, numbered by first use ────────────────
const texts = [];
const textIndex = new Map();
function addText(body, origin) {
  const key = body.replace(/\s+/g, ' ').trim();
  let entry = textIndex.get(key);
  if (!entry) {
    entry = { id: `A${texts.length + 1}`, body, origin, more: 0 };
    texts.push(entry);
    textIndex.set(key, entry);
  } else entry.more += 1;
  return entry.id;
}
const CITED = /\/usr\/share\/common-licenses\/([A-Za-z0-9][A-Za-z0-9.+_-]*)/g;

const listed = [...new Map([...packages.values()].map((p) => [`${p.name}:${p.arch}`, p])).values()].sort(
  (a, b) => byKey(a.name, b.name) || byKey(a.arch, b.arch),
);
for (const p of listed) {
  const copyrightFile = path.posix.join(args.docRoot, p.name, 'copyright');
  if (!fs.existsSync(copyrightFile)) {
    problems.push(`${p.name} ${p.version}: no ${copyrightFile} - its licence cannot be shipped`);
    continue;
  }
  const copyright = normalize(fs.readFileSync(copyrightFile, 'utf8'));
  p.texts = [addText(copyright, `/usr/share/doc/${p.name}/copyright`)];
  for (const m of copyright.matchAll(CITED)) {
    // A sentence's full stop is not part of the name; "GPL-2+" means GPL-2,
    // and so does "GPL-2.0" (pango's copyright file cites that; Debian's
    // file is GPL-2).
    const cited = m[1].replace(/\.+$/, '');
    const bare = cited.replace(/\+$/, '');
    const name = [cited, bare, bare.replace(/\.0$/, '')].find((n) => fs.existsSync(path.posix.join(args.licensesRoot, n)));
    if (!name) {
      problems.push(`${p.name}: its copyright file cites /usr/share/common-licenses/${cited}, which this host does not have`);
      continue;
    }
    const file = path.posix.join(args.licensesRoot, name);
    const id = addText(normalize(fs.readFileSync(file, 'utf8')), `/usr/share/common-licenses/${name}`);
    if (!p.texts.includes(id)) p.texts.push(id);
  }
  // DEP-5 copyright files name their licences in License: fields.
  p.licences = /^Format:\s*\S*copyright-format/m.test(copyright)
    ? [...new Set([...copyright.matchAll(/^License:[ \t]*(\S[^\n]*)$/gm)].map((m) => m[1].trim()))]
    : [];
  p.files.sort(byKey);
}
if (problems.length) fail(`packages whose licence cannot be shipped:\n  ${problems.join('\n  ')}`);

// ── Render ──────────────────────────────────────────────────────────────────
const base = fs.readFileSync(args.base, 'utf8');
if (!base.endsWith('\n') || base.includes('\r')) fail(`${args.base} is not an LF text file ending in a newline - is it the generated notices?`);
if (base.includes('AppImage only:')) fail(`${args.base} already has the AppImage section - pass the notices every package carries`);
const osName = (() => {
  try {
    const m = /^PRETTY_NAME="?([^"\n]*)"?$/m.exec(fs.readFileSync(args.osRelease, 'utf8'));
    return m ? m[1] : 'the build system';
  } catch {
    return 'the build system';
  }
})();

const rule = '='.repeat(78);
const out = [];
const fileCount = listed.reduce((n, p) => n + p.files.length, 0);
out.push(
  '',
  rule,
  `6. AppImage only: bundled system libraries (${listed.length} packages, ${fileCount} files)`,
  rule,
  '',
  'This section is in the AppImage\'s copy of this file only. The .deb uses the',
  'libraries your system provides; the AppImage carries its own: WebKitGTK, GTK,',
  'GLib, libsoup and what they link, copied from the system it was built on',
  `(${osName}). Every one is listed below under the Ubuntu package it came from,`,
  'with that package\'s copyright file and every licence text the copyright file',
  'cites ([A1], [A2], ... in section 7). The complete source of each package is',
  'its Ubuntu source package at the exact version given: run',
  '`apt-get source <source package>=<version>` on Ubuntu (with deb-src enabled),',
  'or download it from the Launchpad page shown.',
  '',
  `BirdoVPN's own programs in the AppImage (sections 1 to 4 above):`,
  ...own.map((rel) => `    ${rel}`),
);
for (const p of listed) {
  out.push(
    '',
    `${p.name} ${p.version} (${p.arch}) [${p.texts.join(', ')}]`,
    `  source: Ubuntu source package ${p.srcName} ${p.srcVersion}`,
    `    apt-get source ${p.srcName}=${p.srcVersion}`,
    `    https://launchpad.net/ubuntu/+source/${p.srcName}/${p.srcVersion}`,
    p.licences.length ? `  licences named in its copyright file: ${p.licences.join('; ')}` : '  licence: as its copyright file says',
    '  files:',
    ...p.files.map((rel) => `    ${rel}`),
  );
}
out.push('', rule, `7. AppImage licence texts (${texts.length})`, rule);
for (const t of texts) {
  const more = t.more ? ` (and ${t.more} more identical)` : '';
  out.push('', `----- [${t.id}] ${t.origin}${more} `.padEnd(78, '-'), '', t.body);
}
const body = `${base}${out.join('\n')}\n`;

fs.mkdirSync(path.dirname(args.out), { recursive: true });
fs.writeFileSync(args.out, body, 'utf8');
console.log(
  `Wrote ${args.out}: ${fileCount} bundled files from ${listed.length} packages, ${own.length} of BirdoVPN's own, ` +
    `${texts.length} licence texts, ${Buffer.byteLength(body)} bytes (${Buffer.byteLength(body) - Buffer.byteLength(base)} for the AppImage section)`,
);
