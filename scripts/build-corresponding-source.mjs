#!/usr/bin/env node
// ============================================================================
// Builds the corresponding-source asset every Desktop release publishes
// (owner decisions 2026-10-14: L1, mirror the source per release; L2, the
// AppImage's own components; review round 1 of #298).
//
//   node scripts/build-corresponding-source.mjs --out-dir <dir> [--download-dir <dir>]
//
// Writes <dir>/BirdoVPN-<version>-corresponding-source.tar.gz (name, URL and
// member paths: scripts/lib/corresponding-source.mjs; THIRD-PARTY-NOTICES.txt
// points at that URL). Under BirdoVPN-<version>-corresponding-source/:
//   xray/Xray-core-<XRAY_VERSION>.tar      the Xray-core source: `git archive`
//                                          of the pinned commit
//   xray/go-modules/<module>@<version>.zip the module zip of EVERY Go module the
//                                          four bundled xray binaries link (the
//                                          GPL-3.0 binary's corresponding
//                                          source includes the permissive ones)
//   appimage-runtime/type2-runtime-<commit>.tar  the AppImage runtime's source
//   appimage-runtime/fuse-<v>.tar.xz, squashfuse-<v>.tar.gz  the two libraries
//                                          it links statically that the
//                                          runtime's build compiles from source
//   README.txt                             versions, hashes, how they map to
//                                          the binaries, how to rebuild/relink
//
// Everything is checked before anything is written; any failure exits 1:
//  * the four Xray release zips release.yml bundles (XRAY_VERSION and the
//    XRAY_*_SHA256 pins) are downloaded and checked, and each binary's Go
//    build information is matched against third_party/licenses/xray-go-
//    modules.json by the same gate the notices generator uses
//    (xrayModuleProblems), so the modules mirrored are exactly the ones, at
//    exactly the versions, the shipped binaries link;
//  * the Xray-core source is fetched with git at XRAY_SOURCE_COMMIT, which
//    must be what the XRAY_VERSION tag names, and whose tree must be
//    XRAY_SOURCE_TREE (content-addressed: GitHub regenerating its tag
//    tarballs cannot change it); each binary must carry the commit's
//    abbreviation (Xray-core's release build stamps it in);
//  * each module zip must hash to its zipSha256 pin, and its Go checksum
//    (dirhash h1:) must equal its line in that source's own go.sum;
//  * the type2-runtime source is fetched with git at the pinned commit and
//    tree (third_party/licenses/appimage-runtime.json), the libfuse and
//    squashfuse tarballs must hash to their pins, and the runtime's own
//    build script must pin those same two hashes.
//
// Deterministic for a given git and node: fixed tar headers, sorted members,
// gzip with no timestamp, `git archive` with a fixed umask and no line-ending
// conversion. tests.yml builds it twice and compares. Node built-ins and git
// only: no new dependency. Run by release.yml's corresponding-source job (its
// output is a release asset, in SHA256SUMS.txt and so under the Sigstore
// signature) and by tests.yml on every PR. --download-dir keeps the
// downloads between runs (each is checked again every time).
// ============================================================================
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { readGoBuildInfo } from './lib/go-buildinfo.mjs';
import {
  moduleZipMember,
  runtimeMember,
  runtimeSourceFile,
  sourceAssetName,
  sourceAssetRoot,
  sourceAssetUrl,
  xrayModuleProblems,
  xrayTagArchiveMember,
} from './lib/corresponding-source.mjs';
import { zipEntries } from './lib/zip.mjs';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function fail(message) {
  console.error(`::error::corresponding source: ${message}`);
  process.exit(1);
}

const args = {};
{
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i += 2) {
    if (i + 1 >= argv.length) fail(`${argv[i]} needs a value`);
    if (argv[i] === '--out-dir') args.outDir = path.resolve(argv[i + 1]);
    else if (argv[i] === '--download-dir') args.downloadDir = path.resolve(argv[i + 1]);
    else fail(`unknown argument ${argv[i]}`);
  }
  if (!args.outDir) fail('usage: node scripts/build-corresponding-source.mjs --out-dir <dir> [--download-dir <dir>]');
}
const downloadDir = args.downloadDir || fs.mkdtempSync(path.join(os.tmpdir(), 'corresponding-source-'));
fs.mkdirSync(downloadDir, { recursive: true });

const byKey = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

// ── Pins ────────────────────────────────────────────────────────────────────
const releaseYml = fs.readFileSync(path.join(repo, '.github', 'workflows', 'release.yml'), 'utf8').replace(/\r/g, '');
function releasePin(name, valueRe) {
  const hits = [...releaseYml.matchAll(new RegExp(`^\\s*${name}: (${valueRe})$`, 'gm'))];
  if (hits.length !== 1) fail(`release.yml: expected one ${name}, found ${hits.length}`);
  return hits[0][1];
}
const HEX64 = '[0-9a-f]{64}';
const HEX40 = '[0-9a-f]{40}';
const xrayVersion = releasePin('XRAY_VERSION', 'v[0-9][0-9.]*');
const xrayCommit = releasePin('XRAY_SOURCE_COMMIT', HEX40);
const xrayTree = releasePin('XRAY_SOURCE_TREE', HEX40);
// The four binaries release.yml bundles, and what ships each.
const PLATFORMS = [
  { zip: 'Xray-windows-64.zip', pin: 'XRAY_WINDOWS_SHA256', binary: 'xray.exe',
    ships: "the Windows installer, as resources\\xray.exe (release builds add BirdoVPN's Authenticode signature to it)" },
  { zip: 'Xray-linux-64.zip', pin: 'XRAY_LINUX_SHA256', binary: 'xray',
    ships: 'the .deb and the AppImage, as usr/lib/BirdoVPN/resources/xray' },
  { zip: 'Xray-macos-arm64-v8a.zip', pin: 'XRAY_MACOS_ARM64_SHA256', binary: 'xray',
    ships: 'the Apple silicon .dmg and .app, as Contents/Resources/resources/xray' },
  { zip: 'Xray-macos-64.zip', pin: 'XRAY_MACOS_AMD64_SHA256', binary: 'xray',
    ships: 'the Intel .dmg and .app, as Contents/Resources/resources/xray' },
];
for (const p of PLATFORMS) p.sha = releasePin(p.pin, HEX64);

const licences = path.join(repo, 'third_party', 'licenses');
const appVersion = JSON.parse(fs.readFileSync(path.join(repo, 'src-tauri', 'tauri.conf.json'), 'utf8')).version;
const table = JSON.parse(fs.readFileSync(path.join(licences, 'xray-go-modules.json'), 'utf8'));
const runtimePins = JSON.parse(fs.readFileSync(path.join(licences, 'appimage-runtime.json'), 'utf8'));

// ── Downloads ───────────────────────────────────────────────────────────────
// The URLs are built from release.yml, the pin files and the binaries' build
// information: only these upstreams, and only well-formed paths, are fetched.
const ALLOWED_URL = new RegExp(
  '^https://(' +
    [
      'github\\.com/XTLS/Xray-core/releases/download/v[0-9.]+/Xray-[a-z0-9-]+\\.zip',
      'proxy\\.golang\\.org/[a-z0-9._~!/-]+/@v/[A-Za-z0-9._~!+-]+\\.zip',
      'github\\.com/libfuse/libfuse/releases/download/fuse-[0-9.]+/fuse-[0-9.]+\\.tar\\.xz',
      'github\\.com/vasi/squashfuse/archive/[0-9.]+\\.tar\\.gz',
    ].join('|') +
    ')$',
);
const GIT_REPOS = new Set(['https://github.com/XTLS/Xray-core', 'https://github.com/AppImage/type2-runtime']);

/** A pinned download: reused from --download-dir when it still hashes to the pin. */
async function pinned(url, expected, cacheName, what) {
  if (!ALLOWED_URL.test(url)) return fail(`refusing to fetch ${url}: not one of the pinned upstreams`);
  const cached = path.join(downloadDir, cacheName.replace(/[^A-Za-z0-9._@-]/g, '_'));
  if (fs.existsSync(cached)) {
    const buf = fs.readFileSync(cached);
    if (sha256(buf) === expected) return buf;
  }
  let buf;
  for (let attempt = 1; ; attempt++) {
    try {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      buf = Buffer.from(await res.arrayBuffer());
      break;
    } catch (e) {
      if (attempt >= 3) fail(`GET ${url}: ${e.message}`);
      console.log(`GET ${url}: ${e.message} (attempt ${attempt}/3) - retrying`);
      await new Promise((resolve) => setTimeout(resolve, attempt * 5000));
    }
  }
  const actual = sha256(buf);
  if (actual !== expected) fail(`${what}: SHA-256 ${actual}, pinned ${expected} (${url})`);
  fs.writeFileSync(cached, buf);
  console.log(`verified ${url} (${actual})`);
  return buf;
}

function git(gitArgs, opts = {}) {
  const r = spawnSync('git', ['-c', 'core.autocrlf=false', '-c', 'tar.umask=0022', ...gitArgs], {
    maxBuffer: 1024 * 1024 * 1024,
    encoding: opts.binary ? 'buffer' : 'utf8',
  });
  if (r.error) fail(`git ${gitArgs.join(' ')}: ${r.error.message}`);
  if (r.status !== 0) fail(`git ${gitArgs.join(' ')} exited ${r.status}:\n${r.stderr}`);
  return r.stdout;
}

/** `git archive` of exactly <commit>, which must have <tree>, under <prefix>/. */
function gitSource(url, commit, tree, prefix) {
  if (!GIT_REPOS.has(url)) return fail(`refusing to fetch ${url}: not one of the pinned upstreams`);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'source-git-'));
  try {
    git(['init', '-q', dir]);
    git(['-C', dir, 'fetch', '-q', '--depth', '1', `${url}.git`, commit]);
    const got = git(['-C', dir, 'rev-parse', 'FETCH_HEAD']).trim();
    if (got !== commit) fail(`${url}: fetched ${got}, pinned ${commit}`);
    const gotTree = git(['-C', dir, 'rev-parse', 'FETCH_HEAD^{tree}']).trim();
    if (gotTree !== tree) fail(`${url}: commit ${commit} has tree ${gotTree}, pinned ${tree}`);
    const tar = git(['-C', dir, 'archive', '--format=tar', `--prefix=${prefix}/`, 'FETCH_HEAD'], { binary: true });
    console.log(`verified ${url} at ${commit} (tree ${tree}), ${tar.length} bytes of source`);
    return tar;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/** Go module proxy path escaping: an upper-case letter becomes "!" + lower case. */
const escapePath = (s) => s.replace(/[A-Z]/g, (c) => `!${c.toLowerCase()}`);

// ── The binaries: what they link ────────────────────────────────────────────
const linked = new Map(); // module path -> { version, platforms: [] }
let goVersion = '';
for (const p of PLATFORMS) {
  const zip = await pinned(`https://github.com/XTLS/Xray-core/releases/download/${xrayVersion}/${p.zip}`, p.sha, `${xrayVersion}-${p.zip}`, p.zip);
  let bin;
  try {
    const members = zipEntries(zip).filter((e) => e.name === p.binary);
    if (members.length !== 1) throw new Error(`expected one ${p.binary} at its root, found ${members.length}`);
    bin = members[0].read();
  } catch (e) {
    fail(`${p.zip}: ${e.message}`);
  }
  let info;
  try {
    info = readGoBuildInfo(bin, `${p.zip}: ${p.binary}`);
  } catch (e) {
    fail(e.message);
  }
  if (info.main !== 'github.com/xtls/xray-core') fail(`${p.zip}: ${p.binary} is ${info.main}, not github.com/xtls/xray-core`);
  if (goVersion && info.goVersion !== goVersion) fail(`the binaries were built by different Go versions (${goVersion}, ${info.goVersion})`);
  goVersion = info.goVersion;
  const problems = xrayModuleProblems(info.modules, table);
  if (problems.length) {
    fail(
      `${p.zip}: xray's Go modules do not match third_party/licenses/xray-go-modules.json:\n  ${problems.join('\n  ')}\n` +
        'Run `node scripts/vendor-xray-go-licences.mjs <the four release xray binaries>` and review what it marks NEW.',
    );
  }
  if (!bin.includes(Buffer.from(xrayCommit.slice(0, 7), 'latin1'))) {
    fail(
      `${p.zip}: ${p.binary} does not carry ${xrayCommit.slice(0, 7)}, the abbreviation of XRAY_SOURCE_COMMIT. ` +
        "Xray-core's release build stamps the commit in (-X core.build=); if upstream changed that, check by hand " +
        'that the binaries come from this commit before changing this check.',
    );
  }
  p.binarySha = sha256(bin);
  p.platform = `${info.settings.GOOS || '?'}/${info.settings.GOARCH || '?'}`;
  p.settings = Object.entries(info.settings).map(([k, v]) => `${k}=${v}`);
  for (const m of info.modules) {
    const seen = linked.get(m.path);
    if (seen && seen.version !== m.version) fail(`${m.path} is ${seen.version} in one binary and ${m.version} in ${p.zip}`);
    if (seen) seen.platforms.push(p.platform);
    else linked.set(m.path, { version: m.version, platforms: [p.platform] });
  }
}

// ── The Xray-core source ────────────────────────────────────────────────────
/** The members of a tar (ustar + pax, as `git archive` writes), with the pax global records. */
function readTar(tar) {
  const members = new Map();
  const global = {};
  let pending = null;
  const pax = (data) => {
    const records = {};
    const text = data.toString('utf8');
    for (let p = 0; p < text.length; ) {
      const space = text.indexOf(' ', p);
      const len = Number.parseInt(text.slice(p, space), 10);
      if (!(len > 0)) break;
      const record = text.slice(space + 1, p + len - 1);
      const eq = record.indexOf('=');
      records[record.slice(0, eq)] = record.slice(eq + 1);
      p += len;
    }
    return records;
  };
  for (let p = 0; p + 512 <= tar.length; ) {
    const h = tar.subarray(p, p + 512);
    if (h.every((b) => b === 0)) break;
    const field = (o, n) => {
      const raw = h.subarray(o, o + n);
      const end = raw.indexOf(0);
      return raw.subarray(0, end < 0 ? n : end).toString('utf8');
    };
    const size = Number.parseInt(field(124, 12).trim() || '0', 8);
    const type = field(156, 1) || '0';
    const prefix = field(345, 155);
    let name = prefix ? `${prefix}/${field(0, 100)}` : field(0, 100);
    const data = tar.subarray(p + 512, p + 512 + size);
    p += 512 + Math.ceil(size / 512) * 512;
    if (type === 'g') Object.assign(global, pax(data));
    else if (type === 'x') pending = pax(data);
    else {
      if (pending?.path) name = pending.path;
      pending = null;
      members.set(name, { type, data, mtime: Number.parseInt(field(136, 12).trim() || '0', 8) });
    }
  }
  return { members, global };
}

const XRAY_REPO = 'https://github.com/XTLS/Xray-core';
{
  // The tag must name the pinned commit (a lightweight tag points at it, an
  // annotated one peels to it).
  const refs = git(['ls-remote', `${XRAY_REPO}.git`, `refs/tags/${xrayVersion}`, `refs/tags/${xrayVersion}^{}`]);
  const shas = refs.split('\n').filter(Boolean).map((l) => l.split('\t'));
  const peeled = (shas.find(([, r]) => r.endsWith('^{}')) || shas.find(([, r]) => r === `refs/tags/${xrayVersion}`) || [])[0];
  if (peeled !== xrayCommit) fail(`${XRAY_REPO}: tag ${xrayVersion} is ${peeled || 'missing'}, XRAY_SOURCE_COMMIT is ${xrayCommit}`);
}
const xrayRoot = `Xray-core-${xrayVersion.replace(/^v/, '')}`;
const xrayTar = gitSource(XRAY_REPO, xrayCommit, xrayTree, xrayRoot);
const { members: xrayMembers, global: xrayGlobal } = readTar(xrayTar);
const goSum = xrayMembers.get(`${xrayRoot}/go.sum`);
const xrayDir = xrayMembers.get(`${xrayRoot}/`);
if (!goSum || !xrayDir) fail(`the Xray-core ${xrayVersion} source has no ${xrayRoot}/go.sum`);
if (xrayGlobal.comment !== xrayCommit) fail(`git archive recorded ${xrayGlobal.comment}, expected ${xrayCommit}`);
const goSumHashes = new Map();
for (const line of goSum.data.toString('utf8').split('\n')) {
  const [mod, version, hash] = line.trim().split(/\s+/);
  if (hash && !version.endsWith('/go.mod')) goSumHashes.set(`${mod} ${version}`, hash);
}

// ── The module zips ─────────────────────────────────────────────────────────
/** The Go checksum of a module zip: golang.org/x/mod/sumdb/dirhash Hash1 over its members. */
function goModuleHash(zip) {
  const entries = zipEntries(zip).sort((a, b) => byKey(a.name, b.name));
  let summary = '';
  for (const e of entries) {
    if (e.name.includes('\n')) throw new Error(`a member name with a newline: ${JSON.stringify(e.name)}`);
    summary += `${sha256(e.read())}  ${e.name}\n`;
  }
  return `h1:${createHash('sha256').update(summary).digest('base64')}`;
}

const modules = [];
for (const [modPath, { version, platforms }] of [...linked].sort(([a], [b]) => byKey(a, b))) {
  const e = table.modules[modPath];
  const url = `https://proxy.golang.org/${escapePath(modPath)}/@v/${escapePath(version)}.zip`;
  const zip = await pinned(url, e.zipSha256, `${modPath}@${version}.zip`, `${modPath}@${version}.zip (zipSha256 in xray-go-modules.json)`);
  let h1;
  try {
    const prefix = `${modPath}@${version}/`;
    const stray = zipEntries(zip).find((z) => !z.name.startsWith(prefix));
    if (stray) throw new Error(`member ${stray.name} is outside ${prefix}`);
    h1 = goModuleHash(zip);
  } catch (err) {
    fail(`${url}: ${err.message}`);
  }
  const pinnedH1 = goSumHashes.get(`${modPath} ${version}`);
  if (!pinnedH1) fail(`${modPath} ${version} is not in the ${xrayVersion} go.sum - the binaries do not come from this source`);
  if (pinnedH1 !== h1) fail(`${url}: Go checksum ${h1}, the ${xrayVersion} go.sum pins ${pinnedH1}`);
  modules.push({ path: modPath, version, url, zip, h1, platforms, license: e.license, sha: e.zipSha256 });
}
console.log(`verified ${modules.length} module zips against their pins and the ${xrayVersion} go.sum`);

// ── The AppImage runtime's sources ──────────────────────────────────────────
const rt = runtimePins.runtime;
const runtimeTar = gitSource(rt.repository, rt.commit, rt.tree, `type2-runtime-${rt.commit}`);
const runtimeFiles = [{ file: runtimeSourceFile(rt.commit), data: runtimeTar }];
{
  const script = readTar(runtimeTar).members.get(`type2-runtime-${rt.commit}/scripts/common/install-dependencies.sh`);
  if (!script) fail(`type2-runtime ${rt.commit} has no scripts/common/install-dependencies.sh - its build changed; review the pins`);
  for (const lib of runtimePins.linked.filter((l) => l.mirror)) {
    const { file, url, sha256: want } = lib.mirror;
    // The build script downloads the same URL and checks its hash under the URL's file name.
    const fetched = url.slice(url.lastIndexOf('/') + 1);
    const text = script.data.toString('utf8');
    if (!text.includes(url) || !text.includes(`${want}  ${fetched}`)) {
      fail(`type2-runtime ${rt.commit}'s build does not fetch ${url} pinned at ${want} - the mirrored ${lib.name} would not be what the runtime links`);
    }
    runtimeFiles.push({ file, data: await pinned(url, want, file, `${lib.name} ${lib.version} source (appimage-runtime.json)`) });
  }
}

// ── README ──────────────────────────────────────────────────────────────────
const assetUrl = sourceAssetUrl(appVersion);
const wrap = (text, indent = '') => {
  const lines = [];
  let line = '';
  for (const word of text.split(' ')) {
    if (line && line.length + 1 + word.length > 78 - indent.length) {
      lines.push(indent + line);
      line = word;
    } else line = line ? `${line} ${word}` : word;
  }
  if (line) lines.push(indent + line);
  return lines;
};
const heading = (t, c = '-') => [t, c.repeat(t.length), ''];
const short = xrayCommit.slice(0, 7);
const readme = [
  ...heading(`BirdoVPN ${appVersion}: corresponding source of its bundled third-party programs`, '='),
  ...wrap(
    `This archive is an asset of the BirdoVPN ${appVersion} release, on the same page as its installers, and its ` +
      "SHA-256 is in that release's Sigstore-signed SHA256SUMS.txt:",
  ),
  `  ${assetUrl}`,
  '',
  ...wrap(
    'It holds the complete corresponding source of two programs BirdoVPN ships but did not write: Xray-core, ' +
      'which every package bundles and runs as a separate process, and the AppImage runtime, which starts the ' +
      'Linux AppImage. THIRD-PARTY-NOTICES.txt in each package lists them with their licences.',
  ),
  '',
  ...heading(`1. Xray-core ${xrayVersion}`),
  ...wrap(
    `BirdoVPN bundles the unmodified Xray-core ${xrayVersion} binaries XTLS publishes. Xray-core is under the ` +
      'MPL-2.0; Go modules under the GPL-3.0-or-later and the LGPL-3.0 are linked into it, so each binary as a ' +
      'whole is under the GPL-3.0, whose corresponding source covers every module linked into it. This part ' +
      'holds the Xray-core source and the source of every one of those modules, at exactly the version linked.',
  ),
  '',
  xrayTagArchiveMember(xrayVersion),
  `  The Xray-core source at commit ${xrayCommit}`,
  `  (tree ${xrayTree}), the commit its ${xrayVersion} tag names, made with \`git archive\`.`,
  "  Its go.mod and go.sum pin every module below. Licence: MPL-2.0.",
  '',
  'xray/go-modules/<module>@<version>.zip',
  ...wrap(
    'The module zip the Go module proxy (https://proxy.golang.org) serves for each module and version, byte for ' +
      "byte; each one's Go checksum equals its line in the source's go.sum. Linked into all four binaries unless " +
      'noted.',
    '  ',
  ),
  '',
];
for (const m of modules) {
  const where = m.platforms.length === PLATFORMS.length ? '' : `  (linked into ${m.platforms.join(', ')} only)`;
  readme.push(`  ${m.path} ${m.version} - ${m.license}${where}`, `    SHA-256 ${m.sha}  ${m.h1}`);
}
readme.push(
  '',
  ...wrap(
    `The Go standard library and runtime (${goVersion}) are linked in too. They are part of the Go toolchain, a ` +
      'System Library in the GPL-3.0\'s terms, and their source is at https://go.googlesource.com/go at ' +
      `${goVersion}.`,
  ),
  '',
  'How this maps to the binaries:',
  '',
  ...wrap(
    `XTLS built each binary below from that commit with ${goVersion}. Each one's embedded Go build information ` +
      '(`go version -m <binary>`) names that Go version and every module version above, and each carries the ' +
      `build string ${short}, the commit's abbreviation. The release that published this archive checked all ` +
      'of this, and would have refused to publish otherwise.',
  ),
  '',
);
for (const p of PLATFORMS) {
  readme.push(
    `  ${p.zip}: ${p.binary} (${p.platform})`,
    `    ${p.zip} SHA-256 ${p.sha}`,
    `      https://github.com/XTLS/Xray-core/releases/download/${xrayVersion}/${p.zip}`,
    `    ${p.binary} SHA-256 ${p.binarySha}`,
    `    build settings: ${p.settings.join(' ')}`,
    ...wrap(`in BirdoVPN: ${p.ships}`, '    '),
    '',
  );
}
readme.push(
  'Rebuilding: unpack the source and, in it, build as Xray-core\'s own release workflow does',
  '(.github/workflows/release.yml in the source), with ' + goVersion + ' and the settings above:',
  `  CGO_ENABLED=0 GOOS=<os> GOARCH=<arch> go build -o xray -trimpath -buildvcs=false \\`,
  '    -gcflags="all=-l=4" \\',
  `    -ldflags="-X github.com/xtls/xray-core/core.build=${short} -s -w -buildid=" ./main`,
  ...wrap(
    '`go build` downloads the modules go.sum pins; the zips here are byte-identical to what the module proxy ' +
      'serves for those versions.',
  ),
  '',
);
const linkedLibs = runtimePins.linked.map((l) => `${l.name} ${l.version} (${l.license})`).join(', ');
readme.push(
  ...heading(`2. The AppImage runtime (type2-runtime ${rt.release})`),
  ...wrap(
    "The Linux AppImage starts with the AppImage project's type2-runtime: the program that mounts the rest of " +
      `the file and starts BirdoVPN. It is the unmodified runtime-x86_64 of its ${rt.release} release ` +
      `(${rt.url}, SHA-256 ${rt.sha256}), built from commit ${rt.commit}. The runtime is under the MIT licence ` +
      `and links statically: ${linkedLibs}. libfuse's library is under the LGPL-2.1, so this part holds the ` +
      "runtime's source with its build scripts, and libfuse's and squashfuse's, which that build compiles from " +
      'source. zstd, zlib, mimalloc and musl come from Alpine Linux 3.21\'s packages, under permissive licences.',
  ),
  '',
  runtimeMember(runtimeSourceFile(rt.commit)),
  `  The type2-runtime source at commit ${rt.commit} (tree ${rt.tree}), made with \`git archive\`.`,
  '  Its patches/libfuse/mount.c.diff is applied to libfuse; its BUILD.md and scripts/ build the runtime.',
);
for (const lib of runtimePins.linked.filter((l) => l.mirror)) {
  readme.push(
    runtimeMember(lib.mirror.file),
    `  ${lib.name} ${lib.version} (${lib.license}), as ${lib.mirror.url}`,
    `  SHA-256 ${lib.mirror.sha256}, the hash the runtime's build script checks.`,
  );
}
readme.push(
  '',
  'Relinking with a modified libfuse (LGPL-2.1 section 6):',
  ...wrap(
    "1. Build the runtime as its CI does (BUILD.md; scripts/docker/build-with-docker.sh or scripts/chroot/" +
      'build.sh): scripts/common/install-dependencies.sh unpacks fuse-3.15.0.tar.xz, applies the patch and installs ' +
      'it as a static library, then builds squashfuse 0.5.2; scripts/build-runtime.sh compiles src/runtime/runtime.c ' +
      'against them. To use your own libfuse, change it before that step.',
    '  ',
  ),
  ...wrap(
    '2. Put the new runtime in front of BirdoVPN\'s AppImage contents: run `<BirdoVPN AppImage> --appimage-extract`, ' +
      'then `appimagetool --runtime-file <your runtime> squashfs-root BirdoVPN.AppImage` ' +
      '(https://github.com/AppImage/appimagetool).',
    '  ',
  ),
  '',
);
const readmeText = `${readme.join('\n')}\n`;

// ── The archive ─────────────────────────────────────────────────────────────
/** One ustar member: fixed owner, mode and time; long paths split into prefix/name. */
function tarMember(name, data, mtime) {
  const h = Buffer.alloc(512);
  let prefix = '';
  let base = name;
  if (Buffer.byteLength(name) > 100) {
    const cut = name.lastIndexOf('/', 155);
    if (cut <= 0 || Buffer.byteLength(name.slice(cut + 1)) > 100) fail(`path too long for a ustar header: ${name}`);
    prefix = name.slice(0, cut);
    base = name.slice(cut + 1);
  }
  const put = (offset, length, value) => h.write(value, offset, length, 'utf8');
  const octal = (offset, length, value) => put(offset, length, `${value.toString(8).padStart(length - 1, '0')}\0`);
  put(0, 100, base);
  octal(100, 8, 0o644);
  octal(108, 8, 0);
  octal(116, 8, 0);
  octal(124, 12, data.length);
  octal(136, 12, mtime);
  put(148, 8, '        ');
  put(156, 1, '0');
  put(257, 6, 'ustar\0');
  put(263, 2, '00');
  put(265, 32, 'root');
  put(297, 32, 'root');
  put(345, 155, prefix);
  let sum = 0;
  for (const b of h) sum += b;
  put(148, 8, `${sum.toString(8).padStart(6, '0')}\0 `);
  const pad = Buffer.alloc((512 - (data.length % 512)) % 512);
  return [h, data, pad];
}

const root = sourceAssetRoot(appVersion);
const files = [
  ['README.txt', Buffer.from(readmeText, 'utf8')],
  [xrayTagArchiveMember(xrayVersion), xrayTar],
  ...modules.map((m) => [moduleZipMember(m.path, m.version), m.zip]),
  ...runtimeFiles.map((f) => [runtimeMember(f.file), f.data]),
].sort(([a], [b]) => byKey(a, b));
const parts = [];
for (const [name, data] of files) parts.push(...tarMember(`${root}/${name}`, data, xrayDir.mtime));
parts.push(Buffer.alloc(1024));
const gz = zlib.gzipSync(Buffer.concat(parts), { level: 6 });
gz[9] = 3; // gzip OS byte: "Unix" on every OS, so Windows and Linux runs give the same bytes

fs.mkdirSync(args.outDir, { recursive: true });
const out = path.join(args.outDir, sourceAssetName(appVersion));
fs.writeFileSync(out, gz);
console.log(
  `Wrote ${out}: ${gz.length} bytes, SHA-256 ${sha256(gz)}\n` +
    `  Xray-core ${xrayVersion} (${xrayCommit}), ${modules.length} Go module zips, ` +
    `type2-runtime ${rt.commit} with ${runtimeFiles.length - 1} library source(s)\n` +
    `  notices URL: ${assetUrl}`,
);
