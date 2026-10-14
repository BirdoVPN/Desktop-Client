#!/usr/bin/env node
// ============================================================================
// Builds the Xray corresponding-source asset every Desktop release publishes
// (owner decision 2026-10-14, L1: mirror the source per release).
//
//   node scripts/build-xray-source-archive.mjs --out-dir <dir>
//
// Writes <dir>/BirdoVPN-<version>-xray-corresponding-source.tar.gz (the name
// and URL are in scripts/lib/xray-source.mjs; THIRD-PARTY-NOTICES.txt points
// at that URL), holding, under BirdoVPN-<version>-xray-corresponding-source/:
//   Xray-core-<XRAY_VERSION>.tar.gz   the upstream tag archive, byte for byte
//   go-modules/<module>@<version>.zip the module zip of every GPL, LGPL and MPL
//                                     Go module the bundled binaries link,
//                                     byte for byte from proxy.golang.org
//   README.txt                        versions, hashes, and how they map to
//                                     the binaries
//
// Everything is checked before anything is written; any failure exits 1:
//  * the four Xray release zips release.yml bundles (its XRAY_VERSION and
//    XRAY_*_SHA256 pins) are downloaded and checked, and each binary's Go
//    build information is read (scripts/lib/go-buildinfo.mjs) and matched
//    against third_party/licenses/xray-go-modules.json by the same gate the
//    notices generator uses (xrayModuleProblems): so the modules mirrored are
//    exactly the ones, at exactly the versions, the shipped binaries link;
//  * the tag archive must hash to release.yml's XRAY_SOURCE_SHA256, and each
//    binary must carry the abbreviated commit of the archive (Xray-core's
//    release build stamps it in with -X core.build=);
//  * each module zip must hash to its zipSha256 pin in xray-go-modules.json,
//    and its Go checksum (dirhash h1:) must equal the line in the tag
//    archive's own go.sum, i.e. it is the module source Xray-core pins.
//
// Deterministic: the same inputs give the same bytes (fixed tar headers,
// sorted members, gzip with no timestamp), so tests.yml can build it twice
// and compare. Built-in fetch, crypto and zlib only: no new dependency. Run
// by release.yml's xray-source job (its output is a release asset, in
// SHA256SUMS.txt and so under the Sigstore signature) and by tests.yml on
// every PR, so a stale pin fails the PR, not release day.
// ============================================================================
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { readGoBuildInfo } from './lib/go-buildinfo.mjs';
import {
  COPYLEFT,
  moduleZipMember,
  sourceAssetName,
  sourceAssetRoot,
  sourceAssetUrl,
  xrayModuleProblems,
  xrayTagArchiveMember,
} from './lib/xray-source.mjs';
import { zipEntries } from './lib/zip.mjs';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function fail(message) {
  console.error(`::error::xray source archive: ${message}`);
  process.exit(1);
}

const argv = process.argv.slice(2);
if (argv.length !== 2 || argv[0] !== '--out-dir') fail('usage: node scripts/build-xray-source-archive.mjs --out-dir <dir>');
const outDir = path.resolve(argv[1]);

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
const xrayVersion = releasePin('XRAY_VERSION', 'v[0-9][0-9.]*');
const sourceSha = releasePin('XRAY_SOURCE_SHA256', HEX64);
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

const appVersion = JSON.parse(fs.readFileSync(path.join(repo, 'src-tauri', 'tauri.conf.json'), 'utf8')).version;
const table = JSON.parse(fs.readFileSync(path.join(repo, 'third_party', 'licenses', 'xray-go-modules.json'), 'utf8'));

// ── Downloads ───────────────────────────────────────────────────────────────
// The URLs are built from release.yml, xray-go-modules.json and the binaries'
// build information: only the two upstreams, and only well-formed paths, are
// ever fetched (the vendor script applies the same rule).
const ALLOWED_URL =
  /^https:\/\/(github\.com\/XTLS\/Xray-core\/(releases\/download\/v[0-9.]+\/Xray-[a-z0-9-]+\.zip|archive\/refs\/tags\/v[0-9.]+\.tar\.gz)|proxy\.golang\.org\/[a-z0-9._~!/-]+\/@v\/[A-Za-z0-9._~!+-]+\.zip)$/;
async function download(url) {
  if (!ALLOWED_URL.test(url)) return fail(`refusing to fetch ${url}: not a Xray-core release/tag archive or a Go module proxy zip URL`);
  for (let attempt = 1; ; attempt++) {
    try {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return Buffer.from(await res.arrayBuffer());
    } catch (e) {
      if (attempt >= 3) fail(`GET ${url}: ${e.message}`);
      console.log(`GET ${url}: ${e.message} (attempt ${attempt}/3) - retrying`);
      await new Promise((resolve) => setTimeout(resolve, attempt * 5000));
    }
  }
}

async function pinned(url, expected, what) {
  const buf = await download(url);
  const actual = sha256(buf);
  if (actual !== expected) fail(`${what}: SHA-256 ${actual}, pinned ${expected} (${url})`);
  console.log(`verified ${url} (${actual})`);
  return buf;
}

/** Go module proxy path escaping: an upper-case letter becomes "!" + lower case. */
const escapePath = (s) => s.replace(/[A-Z]/g, (c) => `!${c.toLowerCase()}`);

// ── The binaries: what they link ────────────────────────────────────────────
const linked = new Map(); // module path -> { version, platforms: [] }
let goVersion = '';
for (const p of PLATFORMS) {
  const zip = await pinned(`https://github.com/XTLS/Xray-core/releases/download/${xrayVersion}/${p.zip}`, p.sha, p.zip);
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
  p.binarySha = sha256(bin);
  p.bytes = bin;
  p.platform = `${info.settings.GOOS || '?'}/${info.settings.GOARCH || '?'}`;
  p.settings = Object.entries(info.settings).map(([k, v]) => `${k}=${v}`);
  for (const m of info.modules) {
    if (!COPYLEFT.test(table.modules[m.path].license)) continue;
    const seen = linked.get(m.path);
    if (seen && seen.version !== m.version) fail(`${m.path} is ${seen.version} in one binary and ${m.version} in ${p.zip}`);
    if (seen) seen.platforms.push(p.platform);
    else linked.set(m.path, { version: m.version, platforms: [p.platform] });
  }
}
if (linked.size === 0) fail('no GPL, LGPL or MPL module is linked - nothing to mirror? The module table or the reader is wrong.');

// ── The tag archive ─────────────────────────────────────────────────────────
/** The members of a tar (ustar + pax, as `git archive` writes), with the pax global records. */
function readTar(tar) {
  const members = new Map();
  const global = {};
  let pending = null;
  const pax = (data) => {
    const records = {};
    let p = 0;
    const text = data.toString('utf8');
    while (p < text.length) {
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

const tagUrl = `https://github.com/XTLS/Xray-core/archive/refs/tags/${xrayVersion}.tar.gz`;
const tagArchive = await pinned(tagUrl, sourceSha, `the Xray-core ${xrayVersion} tag archive (XRAY_SOURCE_SHA256)`);
const { members: tagMembers, global: tagGlobal } = readTar(zlib.gunzipSync(tagArchive));
const tagRoot = `Xray-core-${xrayVersion.replace(/^v/, '')}`;
const tagDir = tagMembers.get(`${tagRoot}/`) || tagMembers.get(tagRoot);
const goSum = tagMembers.get(`${tagRoot}/go.sum`);
if (!tagDir || !goSum) fail(`${tagUrl}: no ${tagRoot}/ with a go.sum - not the Xray-core tag archive`);
const commit = tagGlobal.comment || '';
if (!/^[0-9a-f]{40}$/.test(commit)) fail(`${tagUrl}: no commit id in its pax header (got '${commit}')`);
for (const p of PLATFORMS) {
  if (!p.bytes.includes(Buffer.from(commit.slice(0, 7), 'latin1'))) {
    fail(
      `${p.zip}: ${p.binary} does not carry ${commit.slice(0, 7)}, the commit of the ${xrayVersion} tag archive. ` +
        "Xray-core's release build stamps the commit in (-X core.build=); if upstream changed that, check by hand " +
        'that the binaries come from this tag before changing this check.',
    );
  }
  delete p.bytes;
}
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
  const zip = await pinned(url, e.zipSha256, `${modPath}@${version}.zip (zipSha256 in xray-go-modules.json)`);
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
  if (!pinnedH1) fail(`${modPath} ${version} is not in the ${xrayVersion} tag archive's go.sum - the binaries do not come from this source`);
  if (pinnedH1 !== h1) fail(`${url}: Go checksum ${h1}, the ${xrayVersion} go.sum pins ${pinnedH1}`);
  console.log(`verified ${modPath}@${version}: ${h1} matches go.sum`);
  modules.push({ path: modPath, version, url, zip, h1, platforms, license: e.license, source: e.source, sha: sha256(zip) });
}

// ── README ──────────────────────────────────────────────────────────────────
const assetUrl = sourceAssetUrl(appVersion);
const wrap = (text, indent) => {
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
const title = `BirdoVPN ${appVersion}: corresponding source of the bundled Xray-core ${xrayVersion}`;
const readme = [
  title,
  '='.repeat(title.length),
  '',
  ...wrap(
    `BirdoVPN ${appVersion} bundles Xray-core ${xrayVersion}, the unmodified program XTLS publishes, and runs it ` +
      'as a separate process. Xray-core is under the MPL-2.0, and Go modules whose licences require their source ' +
      `to be offered are linked into it (${[...new Set(modules.map((m) => m.license))].sort(byKey).join('; ')}). ` +
      "This archive is the complete corresponding source of those binaries: Xray-core's own tag archive, whose " +
      'go.mod and go.sum pin every module they link, and the source of each of those modules at exactly the ' +
      'version linked. It is an asset of the BirdoVPN release, on the same page as the installers, and its ' +
      "SHA-256 is in that release's Sigstore-signed SHA256SUMS.txt:",
    '',
  ),
  `  ${assetUrl}`,
  '',
  'Contents',
  '--------',
  '',
  xrayTagArchiveMember(xrayVersion),
  `  The Xray-core ${xrayVersion} tag archive, as GitHub serves it:`,
  `    ${tagUrl}`,
  `  SHA-256 ${sourceSha}`,
  `  Commit ${commit} (from the archive's pax header).`,
  '  Licence: MPL-2.0.',
  '',
];
for (const m of modules) {
  readme.push(
    moduleZipMember(m.path, m.version),
    '  The module zip the Go module proxy serves for this version:',
    `    ${m.url}`,
    `  SHA-256 ${m.sha}`,
    `  Go checksum ${m.h1}, equal to its line in the tag archive's go.sum.`,
    `  Licence: ${m.license}`,
    `  Upstream: ${m.source} at ${m.version}`,
    `  Linked into: ${m.platforms.join(', ')}`,
    '',
  );
}
readme.push('How this maps to the binaries', '-----------------------------', '');
readme.push(
  ...wrap(
    `XTLS built each binary below from that tag with ${goVersion}. Each one's embedded Go build information ` +
      '(`go version -m <binary>`) names that Go version and every module version listed above, and each ' +
      `carries the build string ${commit.slice(0, 7)}, the tag's commit. The release that published this ` +
      "archive checked all of this, and refused to publish otherwise. BirdoVPN's own build of the notices " +
      'reads the same build information from the binary it bundles.',
    '',
  ),
  '',
);
for (const p of PLATFORMS) {
  readme.push(
    `${p.zip}: ${p.binary} (${p.platform})`,
    `  ${p.zip} SHA-256 ${p.sha}`,
    `    https://github.com/XTLS/Xray-core/releases/download/${xrayVersion}/${p.zip}`,
    `  ${p.binary} SHA-256 ${p.binarySha}`,
    `  build settings: ${p.settings.join(' ')}`,
    ...wrap(`in BirdoVPN: ${p.ships}`, '  '),
    '',
  );
}
readme.push(
  'Rebuilding',
  '----------',
  '',
  ...wrap(
    `Unpack the tag archive and build ./main with ${goVersion} as Xray-core's own release workflow does ` +
      `(.github/workflows/release.yml in the archive), with -ldflags "-X github.com/xtls/xray-core/core.build=${commit.slice(0, 7)} ` +
      '-s -w -buildid=" and the build settings above. `go build` downloads the modules go.sum pins; the zips ' +
      'here are byte-identical to what the Go module proxy serves for those versions.',
    '',
  ),
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
  [xrayTagArchiveMember(xrayVersion), tagArchive],
  ...modules.map((m) => [moduleZipMember(m.path, m.version), m.zip]),
].sort(([a], [b]) => byKey(a, b));
const parts = [];
for (const [name, data] of files) parts.push(...tarMember(`${root}/${name}`, data, tagDir.mtime));
parts.push(Buffer.alloc(1024));
const gz = zlib.gzipSync(Buffer.concat(parts), { level: 9 });
gz[9] = 3; // gzip OS byte: "Unix" on every OS, so Windows and Linux runs give the same bytes

fs.mkdirSync(outDir, { recursive: true });
const out = path.join(outDir, sourceAssetName(appVersion));
fs.writeFileSync(out, gz);
console.log(
  `Wrote ${out}: ${gz.length} bytes, SHA-256 ${sha256(gz)}\n` +
    `  Xray-core ${xrayVersion} (${commit}) and ${modules.length} module zip(s): ` +
    `${modules.map((m) => `${m.path}@${m.version}`).join(', ')}\n` +
    `  notices URL: ${assetUrl}`,
);
