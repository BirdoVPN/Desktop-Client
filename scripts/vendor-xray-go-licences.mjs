#!/usr/bin/env node
// ============================================================================
// Vendors the licence files of every Go module linked into the bundled xray,
// and of the Go toolchain that built it (MR-1685). Maintainer-run, on each
// Xray bump; NOT run by CI. The notices generator
// (scripts/generate-third-party-notices.mjs) then fails any build whose xray
// links a module or Go version that does not match what is vendored here.
//
//   node scripts/vendor-xray-go-licences.mjs <xray binary> [<xray binary>...]
//
// Pass all four release binaries (Windows, Linux, macOS arm64 and x64, from
// the zips release.yml downloads and checks): the module sets differ per OS
// (golang.zx2c4.com/wintun is Windows-only, vishvananda/* Linux-only).
//
// For each module@version the binaries link, it downloads
// https://proxy.golang.org/<module>/@v/<version>.zip (Go's module proxy;
// the zip is the exact module source `go build` used, checked by go.sum),
// and copies the LICENSE*/COPYING*/COPYRIGHT*/NOTICE* files at the module
// root to third_party/licenses/xray/<module>@<version>/. The Go licence comes
// from the Go repository at the toolchain's tag. Then it rewrites
// third_party/licenses/xray-go-modules.json: `version` and the vendored
// `texts` for each module (other texts listed there, such as GPL-3.0.txt,
// are kept), the `toolchain` entry, and `"license": "UNREVIEWED"` for a
// module seen for the first time - the generator refuses that until a person
// has read the module's licence and filled in its SPDX id (and `source`, for
// GPL, LGPL or MPL). Older vendored versions of a module are removed.
//
// Built-in fetch and zlib only (Node 18+): no new dependency.
// ============================================================================
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { readGoBuildInfo } from './lib/go-buildinfo.mjs';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const licensesDir = path.join(repo, 'third_party', 'licenses');
const vendorDir = path.join(licensesDir, 'xray');
const tablePath = path.join(licensesDir, 'xray-go-modules.json');
const LICENSE_FILE = /^(licen[cs]e|copying|copyright|notice|unlicense)([-._].*)?$/i;

function die(message) {
  console.error(`vendor-xray-go-licences: ${message}`);
  process.exit(1);
}

const binaries = process.argv.slice(2);
if (binaries.length === 0) die('usage: node scripts/vendor-xray-go-licences.mjs <xray binary> [<xray binary>...]');

// ── What the binaries link ──────────────────────────────────────────────────
const linked = new Map();
let goVersion = '';
for (const bin of binaries) {
  let info;
  try {
    info = readGoBuildInfo(bin);
  } catch (e) {
    die(e.message);
  }
  if (info.main !== 'github.com/xtls/xray-core') die(`${bin} is ${info.main}, not github.com/xtls/xray-core`);
  if (goVersion && goVersion !== info.goVersion) die(`the binaries were built by different Go versions (${goVersion}, ${info.goVersion})`);
  goVersion = info.goVersion;
  for (const m of info.modules) {
    const seen = linked.get(m.path);
    if (seen && seen !== m.version) die(`${m.path} is ${seen} in one binary and ${m.version} in another`);
    linked.set(m.path, m.version);
  }
}

// ── Download helpers ────────────────────────────────────────────────────────
async function download(url) {
  const res = await fetch(url);
  if (!res.ok) die(`GET ${url}: HTTP ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

/** Go module proxy path escaping: an upper-case letter becomes "!" + lower case. */
const escapePath = (s) => s.replace(/[A-Z]/g, (c) => `!${c.toLowerCase()}`);

/** The files at the root of a zip whose name passes `keep`, as { name: Buffer }. */
function unzipRoot(zip, prefix, keep) {
  let eocd = -1;
  for (let i = zip.length - 22; i >= Math.max(0, zip.length - 65557); i--) {
    if (zip.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) die('not a zip archive (no end of central directory)');
  const count = zip.readUInt16LE(eocd + 10);
  let p = zip.readUInt32LE(eocd + 16);
  if (p === 0xffffffff) die('ZIP64 archive: not supported');
  const out = {};
  for (let i = 0; i < count; i++) {
    if (zip.readUInt32LE(p) !== 0x02014b50) die('corrupt zip central directory');
    const method = zip.readUInt16LE(p + 10);
    const size = zip.readUInt32LE(p + 20);
    const nameLen = zip.readUInt16LE(p + 28);
    const extraLen = zip.readUInt16LE(p + 30);
    const commentLen = zip.readUInt16LE(p + 32);
    const local = zip.readUInt32LE(p + 42);
    const name = zip.subarray(p + 46, p + 46 + nameLen).toString('utf8');
    p += 46 + nameLen + extraLen + commentLen;
    if (!name.startsWith(prefix)) continue;
    const base = name.slice(prefix.length);
    if (base.includes('/') || !keep(base)) continue;
    if (zip.readUInt32LE(local) !== 0x04034b50) die(`corrupt zip local header for ${name}`);
    const start = local + 30 + zip.readUInt16LE(local + 26) + zip.readUInt16LE(local + 28);
    const data = zip.subarray(start, start + size);
    if (method === 0) out[base] = Buffer.from(data);
    else if (method === 8) out[base] = zlib.inflateRawSync(data);
    else die(`${name}: zip compression method ${method} not supported`);
  }
  return out;
}

/** Replace third_party/licenses/xray/<dir>@*\/ with exactly `files`; returns the texts' paths. */
function vendor(dirName, version, files) {
  const parent = path.join(vendorDir, path.dirname(dirName));
  const leaf = path.basename(dirName);
  fs.mkdirSync(parent, { recursive: true });
  for (const old of fs.readdirSync(parent)) {
    if (old.startsWith(`${leaf}@`)) fs.rmSync(path.join(parent, old), { recursive: true, force: true });
  }
  const target = path.join(parent, `${leaf}@${version}`);
  fs.mkdirSync(target, { recursive: true });
  const texts = [];
  for (const [name, data] of Object.entries(files).sort(([a], [b]) => (a < b ? -1 : 1))) {
    fs.writeFileSync(path.join(target, name), data);
    texts.push(`xray/${dirName}@${version}/${name}`);
  }
  return texts;
}

// ── Vendor ──────────────────────────────────────────────────────────────────
const table = fs.existsSync(tablePath) ? JSON.parse(fs.readFileSync(tablePath, 'utf8')) : {};
const modules = table.modules || {};
const keepOthers = (entry, dirName) => (entry.texts || []).filter((t) => !t.startsWith(`xray/${dirName}@`));

for (const [modPath, version] of [...linked].sort(([a], [b]) => (a < b ? -1 : 1))) {
  const url = `https://proxy.golang.org/${escapePath(modPath)}/@v/${escapePath(version)}.zip`;
  const files = unzipRoot(await download(url), `${modPath}@${version}/`, (n) => LICENSE_FILE.test(n));
  if (Object.keys(files).length === 0) die(`${modPath}@${version} has no licence file at its root - vendor its licence by hand`);
  const entry = modules[modPath] || { license: 'UNREVIEWED' };
  const texts = vendor(modPath, version, files);
  modules[modPath] = { ...entry, version, texts: [...texts, ...keepOthers(entry, modPath)] };
  console.log(`${modPath} ${version}: ${Object.keys(files).join(', ')}${entry.license === 'UNREVIEWED' ? '  <- NEW: review its licence' : ''}`);
}
for (const modPath of Object.keys(modules)) {
  if (!linked.has(modPath)) console.log(`not linked by these binaries (left as is): ${modPath}`);
}

// The Go toolchain's standard library and runtime are linked into every Go binary.
const goLicense = Buffer.from(
  (await download(`https://go.googlesource.com/go/+/refs/tags/${goVersion}/LICENSE?format=TEXT`)).toString('ascii'),
  'base64',
);
if (!/Copyright .* The Go Authors/.test(goLicense.toString('utf8'))) die(`the ${goVersion} LICENSE does not look like Go's`);
const toolchain = {
  version: goVersion,
  license: 'BSD-3-Clause',
  source: 'https://go.googlesource.com/go',
  texts: vendor('go', goVersion, { LICENSE: goLicense }),
};
console.log(`Go toolchain ${goVersion}: LICENSE`);

const sorted = Object.fromEntries(Object.entries(modules).sort(([a], [b]) => (a < b ? -1 : 1)));
fs.writeFileSync(tablePath, `${JSON.stringify({ _comment: table._comment, toolchain, modules: sorted }, null, 2)}\n`);
console.log(`Updated ${path.relative(repo, tablePath)}. Review every module marked NEW before committing.`);
