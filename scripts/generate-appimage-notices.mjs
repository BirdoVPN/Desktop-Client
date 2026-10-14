#!/usr/bin/env node
// ============================================================================
// AppImage-only notices: everything the AppImage carries besides BirdoVPN
// (owner decision 2026-10-14, L2: list them in the notices; review round 1 of
// #298: every file, and the runtime).
//
// The .deb uses the libraries the user's system provides; the AppImage
// carries its own, copied by Tauri's bundler (linuxdeploy and its GTK plugin)
// from the Ubuntu system it is built on (WebKitGTK, GTK, GLib, libsoup and
// everything they link, with their typelibs, GSettings schemas and copyright
// files), plus the AppImage runtime at the start of the file and the AppRun
// launcher. This script lists every one of them in the AppImage's copy of
// THIRD-PARTY-NOTICES.txt, after the sections every package carries:
//
//   node scripts/generate-appimage-notices.mjs --appdir <unpacked AppImage>
//        --appimage <the .AppImage> --runtime-file <the pinned runtime>
//        --base <this build's THIRD-PARTY-NOTICES.txt> --out <file>
//        [--doc-root /usr/share/doc] [--licenses-root /usr/share/common-licenses]
//        [--os-release /etc/os-release] [--host-root /] [--multiarch <triplet>]
//        [--runtime-pins third_party/licenses/appimage-runtime.json]
//
// Run on the build host, right after `tauri build` made the AppImage, by
// scripts/ci/appimage-notices.sh (release.yml's build-linux, and the PR
// workflow linux-packages.yml), which then re-bundles the AppImage with the
// result. EVERY regular file in the AppImage is accounted for, and listed as
// a line "    <path>":
//  * BirdoVPN's own: usr/bin/<binary>, usr/lib/<productName>/, its .desktop
//    file and icons (sections 1-4 cover them);
//  * AppRun.wrapped: AppImageKit's AppRun, which must be the pinned bytes
//    (appimage-runtime.json), with its licence;
//  * AppRun and apprun-hooks/: the files linuxdeploy and its GTK plugin
//    write, with their licence;
//  * the caches the bundler generates from the listed modules and schemas
//    (loaders.cache, immodules.cache, giomodule.cache, gschemas.compiled);
//  * everything else - libraries, modules, WebKitGTK's helpers, typelibs,
//    schemas, copyright files - by the Ubuntu package that owns the host file
//    it was copied from: each candidate host path (below the multiarch lib
//    dir for usr/lib/), resolved through symlinks first, so an unversioned
//    libfoo.so copy is credited to the runtime package that ships the real
//    file, not the -dev package that ships the link; then `dpkg -S`. With
//    the package's version, its source package and exact version
//    (`dpkg-query`: `apt-get source` or the Launchpad page of that upload),
//    its copyright file in full and every /usr/share/common-licenses text it
//    cites.
// And the runtime, which is not a file in the AppImage but its first bytes:
// the --appimage's leading ELF must be the pinned --runtime-file byte for byte,
// except the three sections appimagetool fills in (.digest_md5, .upd_info,
// .sha256_sig). It is listed with its commit, licence and the libraries it
// links statically (libfuse, LGPL-2.1, in full), and the corresponding-source
// asset that mirrors their source.
// It FAILS on any file it cannot account for: the fix is never to leave one
// out. scripts/ci/verify-bundled-xray.sh checks the final AppImage the same
// way (every file listed, the runtime's commit, these notices starting with
// the generic ones).
//
// dpkg and dpkg-query are taken from PATH (a fixture can stand in for them:
// scripts/ci/appimage-notices.tests.sh). Output is deterministic for a given
// AppImage and build host. Node built-ins only.
// ============================================================================
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runtimeMember, runtimeSourceFile, sourceAssetUrl } from './lib/corresponding-source.mjs';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const licensesDir = path.join(repo, 'third_party', 'licenses');

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
  runtimePins: path.join(licensesDir, 'appimage-runtime.json'),
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
      case '--appimage': args.appimage = path.resolve(value()); break;
      case '--runtime-file': args.runtimeFile = path.resolve(value()); break;
      case '--base': args.base = path.resolve(value()); break;
      case '--out': args.out = path.resolve(value()); break;
      case '--doc-root': args.docRoot = value(); break;
      case '--licenses-root': args.licensesRoot = value(); break;
      case '--os-release': args.osRelease = value(); break;
      case '--host-root': args.hostRoot = value(); break;
      case '--multiarch': args.multiarch = value(); break;
      case '--runtime-pins': args.runtimePins = path.resolve(value()); break;
      default: fail(`unknown argument ${flag}`);
    }
  }
}
for (const required of ['appdir', 'appimage', 'runtimeFile', 'base', 'out']) {
  if (!args[required]) fail(`--${required.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)} is required`);
}

// ── Helpers ─────────────────────────────────────────────────────────────────
/** LF line ends, no BOM, no trailing spaces, no blank lines at either end (as the main generator). */
function normalize(text) {
  return (text.charCodeAt(0) === 0xfeff ? text.slice(1) : text)
    .replace(/\r\n?/g, '\n')
    .split('\n')
    .map((line) => line.replace(/\s+$/, ''))
    .join('\n')
    .replace(/^\n+|\n+$/g, '');
}
const byKey = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

function run(cmd, cmdArgs, okStatuses = [0]) {
  const r = spawnSync(cmd, cmdArgs, { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 });
  if (r.error) fail(`${cmd}: ${r.error.message}`);
  if (!okStatuses.includes(r.status)) fail(`${cmd} ${cmdArgs.slice(0, 3).join(' ')} ... exited ${r.status}:\n${r.stderr}`);
  return r.stdout;
}

const host = (p) => path.join(args.hostRoot, p);
const pins = JSON.parse(fs.readFileSync(args.runtimePins, 'utf8'));
const appVersion = JSON.parse(fs.readFileSync(path.join(repo, 'src-tauri', 'tauri.conf.json'), 'utf8')).version;
const asset = sourceAssetUrl(appVersion);

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
/** Committed texts (paths under third_party/licenses/), registered; returns their ids. */
function committedTexts(paths, label) {
  return [
    ...new Set(
      paths.map((t) => {
        const file = path.join(licensesDir, t);
        if (!fs.existsSync(file)) fail(`missing committed licence text third_party/licenses/${t}`);
        return addText(normalize(fs.readFileSync(file, 'utf8')), `${path.basename(t)} of ${label}`);
      }),
    ),
  ];
}

// ── The runtime: the AppImage's first bytes ────────────────────────────────
/** An ELF64 little-endian file's size (end of its section headers) and named sections. */
function elf64(buf, what) {
  if (buf.length < 64 || buf.readUInt32BE(0) !== 0x7f454c46 || buf[4] !== 2 || buf[5] !== 1) fail(`${what} is not a little-endian ELF64 file`);
  const shoff = Number(buf.readBigUInt64LE(0x28));
  const shentsize = buf.readUInt16LE(0x3a);
  const shnum = buf.readUInt16LE(0x3c);
  const shstrndx = buf.readUInt16LE(0x3e);
  const size = shoff + shentsize * shnum;
  if (size > buf.length || shstrndx >= shnum) fail(`${what}: its section headers are not where its ELF header says`);
  const header = (i) => {
    const o = shoff + i * shentsize;
    return { nameAt: buf.readUInt32LE(o), offset: Number(buf.readBigUInt64LE(o + 0x18)), size: Number(buf.readBigUInt64LE(o + 0x20)) };
  };
  const strtab = header(shstrndx);
  const sections = [];
  for (let i = 0; i < shnum; i++) {
    const s = header(i);
    const start = strtab.offset + s.nameAt;
    sections.push({ name: buf.toString('latin1', start, buf.indexOf(0, start)), offset: s.offset, size: s.size });
  }
  return { size, sections };
}
const FILLED = new Set(['.digest_md5', '.upd_info', '.sha256_sig']); // what appimagetool writes into the runtime
{
  const runtime = fs.readFileSync(args.runtimeFile);
  if (sha256(runtime) !== pins.runtime.sha256) fail(`${args.runtimeFile} is not the pinned runtime (${pins.runtime.sha256})`);
  const fd = fs.openSync(args.appimage, 'r');
  const head = Buffer.alloc(runtime.length);
  const read = fs.readSync(fd, head, 0, runtime.length, 0);
  fs.closeSync(fd);
  const want = elf64(runtime, 'the pinned runtime');
  const got = elf64(head.subarray(0, read), `the start of ${args.appimage}`);
  if (want.size !== runtime.length || got.size !== want.size) {
    fail(`${args.appimage}'s runtime is ${got.size} bytes, the pinned type2-runtime ${pins.runtime.commit.slice(0, 7)} ${want.size}: not the pinned runtime (LDAI_RUNTIME_FILE not used?)`);
  }
  const a = Buffer.from(runtime);
  const b = Buffer.from(head);
  for (const s of want.sections.filter((x) => FILLED.has(x.name))) {
    a.fill(0, s.offset, s.offset + s.size);
    b.fill(0, s.offset, s.offset + s.size);
  }
  if (!a.equals(b)) fail(`${args.appimage} does not start with the pinned type2-runtime ${pins.runtime.commit} - the bundler used another runtime`);
  console.log(`runtime: ${args.appimage} starts with type2-runtime ${pins.runtime.commit}, as pinned`);
}

// ── What the AppImage carries ───────────────────────────────────────────────
const productName = JSON.parse(fs.readFileSync(path.join(repo, 'src-tauri', 'tauri.conf.json'), 'utf8')).productName;
const binaryName = (() => {
  const toml = fs.readFileSync(path.join(repo, 'src-tauri', 'Cargo.toml'), 'utf8');
  const pkg = toml.split(/^\[/m).find((s) => s.startsWith('package]'));
  const m = pkg && /^\s*name\s*=\s*"([^"]+)"/m.exec(pkg);
  if (!m) fail('src-tauri/Cargo.toml: no [package] name');
  return m[1];
})();
const isOwn = (rel) =>
  rel === `usr/bin/${binaryName}` ||
  rel.startsWith(`usr/lib/${productName}/`) ||
  rel === `usr/share/applications/${productName}.desktop` ||
  (rel.startsWith('usr/share/icons/hicolor/') && rel.endsWith(`/apps/${binaryName}.png`) && rel.split('/').length === 7) ||
  rel === `${productName}.png`;
const GENERATED_CACHES = new Set(['loaders.cache', 'immodules.cache', 'giomodule.cache', 'gschemas.compiled']);

if (!fs.existsSync(path.join(args.appdir, 'usr'))) fail(`${args.appdir} has no usr/ - not an unpacked AppImage`);
const allFiles = [];
(function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(file);
    else if (entry.isFile()) allFiles.push(path.relative(args.appdir, file).split(path.sep).join('/'));
    // Symlinks are not followed: linuxdeploy's links point at files inside
    // the AppDir, which are listed under their own paths.
  }
})(args.appdir);
allFiles.sort(byKey);

const own = [];
const caches = [];
const tooling = new Map(); // rel -> pin entry (AppRun.wrapped, AppRun, hooks)
const toMap = [];
const toolingPins = [pins.apprun, ...pins.generated];
for (const rel of allFiles) {
  const pin = toolingPins.find((t) => t.file === rel);
  if (isOwn(rel)) own.push(rel);
  else if (pin) tooling.set(rel, pin);
  else if (GENERATED_CACHES.has(path.posix.basename(rel))) caches.push(rel);
  else toMap.push(rel);
}
for (const t of toolingPins) if (!tooling.has(t.file)) fail(`the AppImage has no ${t.file} - the bundler changed; review appimage-runtime.json`);
{
  const actual = sha256(fs.readFileSync(path.join(args.appdir, pins.apprun.file)));
  if (actual !== pins.apprun.sha256) fail(`${pins.apprun.file} is ${actual}, not the pinned AppRun ${pins.apprun.sha256} (Tauri's AppRun download, appimage-runtime.json)`);
}
if (!toMap.some((rel) => rel.startsWith('usr/lib/'))) fail(`no bundled library under ${args.appdir}/usr/lib - is this the AppImage?`);

// ── Which package each came from ────────────────────────────────────────────
// Where a file in the AppImage was on the build host: below usr/lib/, under
// the multiarch lib dirs (linuxdeploy flattens libraries into usr/lib/ and
// keeps a module's directory below its lib dir); anything else at its path.
const libBases = [`/usr/lib/${args.multiarch}`, `/lib/${args.multiarch}`, '/usr/lib', '/lib'];
const hostCandidates = (rel) => (rel.startsWith('usr/lib/') ? libBases.map((b) => `${b}/${rel.slice('usr/lib/'.length)}`) : [`/${rel}`]);
const hostRoot = fs.realpathSync(args.hostRoot);
/** The real files a bundled file can have come from, in both usrmerge spellings dpkg may know. */
function realCandidates(rel) {
  const out = new Set();
  for (const c of hostCandidates(rel)) {
    if (!fs.existsSync(host(c))) continue;
    const real = `/${path.relative(hostRoot, fs.realpathSync(host(c))).split(path.sep).join('/')}`;
    out.add(real);
    out.add(real.startsWith('/usr/') ? real.slice(4) : `/usr${real}`);
  }
  return [...out];
}

/** `dpkg -S` over many literal paths at once: path -> [packages]. Unowned paths are not an error here. */
function dpkgSearch(paths) {
  const owners = new Map();
  if (paths.length === 0) return owners;
  const out = run('dpkg', ['-S', ...paths], [0, 1]);
  for (const line of out.split('\n')) {
    if (!line || line.startsWith('diversion by') || line.startsWith('local diversion')) continue;
    const m = /^(.+?): (\/.*)$/.exec(line);
    if (!m) continue;
    const pkgs = m[1].split(',').map((s) => s.trim()).filter(Boolean);
    owners.set(m[2], [...new Set([...(owners.get(m[2]) || []), ...pkgs])]);
  }
  return owners;
}

const reals = new Map(toMap.map((rel) => [rel, realCandidates(rel)]));
const owners = dpkgSearch([...new Set([...reals.values()].flat())].sort(byKey));
const packageOf = new Map(); // rel -> { pkg, hostPath }
const problems = [];
for (const rel of toMap) {
  const found = new Map();
  for (const c of reals.get(rel)) for (const pkg of owners.get(c) || []) if (!found.has(pkg)) found.set(pkg, c);
  if (found.size === 1) {
    const [[pkg, hostPath]] = [...found];
    packageOf.set(rel, { pkg, hostPath });
  } else if (found.size > 1) problems.push(`${rel}: more than one package owns it (${[...found].map(([p, h]) => `${p} ${h}`).join(', ')})`);
  else {
    const where = reals.get(rel).length ? reals.get(rel).join(', ') : `none of ${hostCandidates(rel).join(', ')} exists on this host`;
    problems.push(`${rel}: no installed package owns it (${where}) - a file from outside the package manager cannot be listed with its source`);
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
  console.log(`  ${rel} <- ${hostPath} (${p.name} ${p.version})`); // the mapping, for the build log
}

const CITED = /\/usr\/share\/common-licenses\/([A-Za-z0-9][A-Za-z0-9.+_-]*)/g;
const listed = [...new Map([...packages.values()].map((p) => [`${p.name}:${p.arch}`, p])).values()].sort(
  (a, b) => byKey(a.name, b.name) || byKey(a.arch, b.arch),
);
// Numbered after the runtime's and the launcher's texts, which come first.
const runtimeIds = committedTexts(pins.runtime.texts, `type2-runtime ${pins.runtime.commit.slice(0, 7)}`);
for (const l of pins.linked) l.ids = committedTexts(l.texts, `${l.name} ${l.version}`);
for (const t of toolingPins) t.ids = committedTexts(t.texts, t.name || t.file);
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
    const id = addText(normalize(fs.readFileSync(path.posix.join(args.licensesRoot, name), 'utf8')), `/usr/share/common-licenses/${name}`);
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
const rt = pins.runtime;
out.push(
  '',
  rule,
  `6. AppImage only: what the AppImage carries besides BirdoVPN (${allFiles.length} files)`,
  rule,
  '',
  'This section is in the AppImage\'s copy of this file only. The .deb uses the',
  'libraries your system provides; the AppImage carries its own: WebKitGTK, GTK,',
  'GLib, libsoup and what they link, copied from the system it was built on',
  `(${osName}).`,
  'It also starts with the AppImage runtime. Every file in it is listed below:',
  'BirdoVPN\'s own, the runtime and launcher, the caches the bundler generates,',
  'and each Ubuntu package the rest came from, with that package\'s copyright',
  'file and every licence text the copyright file cites ([A1], [A2], ... in',
  'section 7). The complete source of each package is its Ubuntu source package',
  'at the exact version given: run `apt-get source <source package>=<version>`',
  'on Ubuntu (with deb-src enabled), or download it from the Launchpad page',
  'shown.',
  '',
  `BirdoVPN's own files in the AppImage (sections 1 to 4 above):`,
  ...own.map((rel) => `    ${rel}`),
  '',
  'The AppImage runtime: the program at the start of the .AppImage file, before',
  'the files below, which mounts them and starts BirdoVPN.',
  `  AppImage type2-runtime ${rt.commit.slice(0, 7)} - commit ${rt.commit} - ${rt.license} [${runtimeIds.join(', ')}]`,
  `    source: ${runtimeMember(runtimeSourceFile(rt.commit))} in ${asset}`,
  `    upstream: ${rt.repository} at ${rt.commit}`,
  "    the unmodified runtime-x86_64 type2-runtime's CI built from that commit",
  `      (SHA-256 ${rt.sha256}; ${rt.url}, ${rt.published.slice(0, 10)}),`,
  `      ${rt.build}`,
  '  Linked statically into it:',
);
for (const l of pins.linked) {
  out.push(`    ${l.name} ${l.version} - ${l.license} [${l.ids.join(', ')}]${l.note ? ` - ${l.note}` : ''}`);
  if (l.mirror) out.push(`      source: ${runtimeMember(l.mirror.file)} in ${asset}`);
  out.push(`      upstream: ${l.upstream}`);
}
out.push(
  '  libfuse\'s library is under the LGPL-2.1: the asset above holds the runtime\'s',
  '  source and build scripts with libfuse\'s and squashfuse\'s source, and its',
  '  README says how to rebuild the runtime against a modified libfuse and put it',
  '  in front of these files.',
  '',
  'The launcher, and the files linuxdeploy writes:',
);
for (const t of toolingPins) {
  out.push(
    `  ${t.name || t.file} - ${t.license} [${t.ids.join(', ')}]`,
    `    ${t.note || t.what}`,
    `    upstream: ${t.upstream}`,
    '  files:',
    `    ${t.file}`,
  );
}
out.push(
  '',
  'Generated when the AppImage is built, from the modules and schemas listed below',
  '(gdk-pixbuf-query-loaders, gtk-query-immodules-3.0, gio-querymodules,',
  'glib-compile-schemas); index data with no licence of their own:',
  ...caches.map((rel) => `    ${rel}`),
  '',
  `From Ubuntu packages (${listed.length} packages, ${fileCount} files):`,
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

// Every file is listed exactly as the gate looks for it.
for (const rel of allFiles) if (!body.includes(`\n    ${rel}\n`)) fail(`internal: ${rel} is not listed`);

fs.mkdirSync(path.dirname(args.out), { recursive: true });
fs.writeFileSync(args.out, body, 'utf8');
console.log(
  `Wrote ${args.out}: ${allFiles.length} files (${own.length} BirdoVPN's own, ${tooling.size} launcher/linuxdeploy, ` +
    `${caches.length} generated caches, ${fileCount} from ${listed.length} Ubuntu packages), the type2-runtime ` +
    `${rt.commit.slice(0, 7)} runtime with ${pins.linked.length} static libraries, ${texts.length} licence texts, ` +
    `${Buffer.byteLength(body)} bytes (${Buffer.byteLength(body) - Buffer.byteLength(base)} for the AppImage section)`,
);
