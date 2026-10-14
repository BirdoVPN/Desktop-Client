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
// For every module it also records `zipSha256`, the SHA-256 of the module
// zip it downloaded: each release mirrors every linked module's zip in its
// corresponding-source asset (scripts/build-corresponding-source.mjs), which
// refuses a zip that does not match (and checks it against Xray's go.sum).
// For the toolchain it records the official source archive's name and the
// SHA-256 go.dev publishes for it (`srcArchive`, `srcSha256`): the asset
// mirrors that too.
//
// Built-in fetch, crypto and zlib only (Node 18+): no new dependency.
// ============================================================================
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readGoBuildInfo } from './lib/go-buildinfo.mjs';
import { zipEntries } from './lib/zip.mjs';

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
// Only well-formed module paths and versions go into a URL, and only to the
// Go module proxy and the Go repository: nothing else read from a binary
// leaves this machine.
const MODULE_PATH = /^[a-z0-9][a-z0-9._~-]*(\/[A-Za-z0-9._~-]+)+$/;
const MODULE_VERSION = /^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+incompatible)?$/;
const GO_VERSION = /^go1\.\d+(\.\d+)?$/;

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
  if (GO_VERSION.test(info.goVersion)) goVersion = info.goVersion;
  else die(`${bin}: unexpected Go version '${info.goVersion}'`);
  for (const m of info.modules) {
    const seen = linked.get(m.path);
    if (seen && seen !== m.version) die(`${m.path} is ${seen} in one binary and ${m.version} in another`);
    if (MODULE_PATH.test(m.path) && MODULE_VERSION.test(m.version)) linked.set(m.path, m.version);
    else die(`${bin}: unexpected module '${m.path}' '${m.version}'`);
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
  const out = {};
  try {
    for (const entry of zipEntries(zip)) {
      if (!entry.name.startsWith(prefix)) continue;
      const base = entry.name.slice(prefix.length);
      if (base.includes('/') || !keep(base)) continue;
      out[base] = entry.read();
    }
  } catch (e) {
    die(`${prefix}: ${e.message}`);
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
let table;
try {
  table = JSON.parse(fs.readFileSync(tablePath, 'utf8'));
} catch (e) {
  die(`cannot read ${path.relative(repo, tablePath)}: ${e.message}`);
}
const modules = table.modules || {};
const keepOthers = (entry, dirName) => (entry.texts || []).filter((t) => !t.startsWith(`xray/${dirName}@`));

for (const [modPath, version] of [...linked].sort(([a], [b]) => (a < b ? -1 : 1))) {
  const url = `https://proxy.golang.org/${escapePath(modPath)}/@v/${escapePath(version)}.zip`;
  const zip = await download(url);
  const files = unzipRoot(zip, `${modPath}@${version}/`, (n) => LICENSE_FILE.test(n));
  if (Object.keys(files).length === 0) die(`${modPath}@${version} has no licence file at its root - vendor its licence by hand`);
  const entry = { ...(modules[modPath] || { license: 'UNREVIEWED' }) };
  delete entry.zipSha256; // the hash of this run's zip, below, or none
  const texts = vendor(modPath, version, files);
  const zipSha256 = createHash('sha256').update(zip).digest('hex');
  modules[modPath] = { ...entry, version, texts: [...texts, ...keepOthers(entry, modPath)], zipSha256 };
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
// The official source archive of that toolchain, which the corresponding-
// source asset mirrors (review round 2 of #298): its SHA-256 as go.dev
// publishes it.
const releases = JSON.parse((await download('https://go.dev/dl/?mode=json&include=all')).toString('utf8'));
const srcFile = (releases.find((r) => r.version === goVersion)?.files || []).find((f) => f.kind === 'source');
if (!srcFile || !/^[0-9a-f]{64}$/.test(srcFile.sha256 || '')) die(`go.dev/dl lists no source archive for ${goVersion}`);
const toolchain = {
  version: goVersion,
  license: 'BSD-3-Clause',
  source: 'https://go.googlesource.com/go',
  texts: vendor('go', goVersion, { LICENSE: goLicense }),
  srcArchive: srcFile.filename,
  srcSha256: srcFile.sha256,
};
console.log(`Go toolchain ${goVersion}: LICENSE; ${srcFile.filename} ${srcFile.sha256}`);

const sorted = Object.fromEntries(Object.entries(modules).sort(([a], [b]) => (a < b ? -1 : 1)));
fs.writeFileSync(tablePath, `${JSON.stringify({ _comment: table._comment, toolchain, modules: sorted }, null, 2)}\n`);
console.log(`Updated ${path.relative(repo, tablePath)}. Review every module marked NEW before committing.`);
