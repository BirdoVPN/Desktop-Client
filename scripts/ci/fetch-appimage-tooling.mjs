#!/usr/bin/env node
// ============================================================================
// Pins what Tauri's AppImage bundler would otherwise download unpinned
// (owner decision 2026-10-14, L2, review round 1 of #298):
//
//  * the AppImage runtime: linuxdeploy-plugin-appimage's appimagetool fetches
//    type2-runtime's moving `continuous` build on every run unless it is given
//    one (LDAI_RUNTIME_FILE -> appimagetool --runtime-file). This downloads the
//    pinned release's runtime-x86_64, refuses any other bytes, and exports
//    LDAI_RUNTIME_FILE (and APPIMAGE_RUNTIME_FILE, for the notices step).
//  * AppRun: Tauri copies AppRun-x86_64 from its tool cache, downloading it
//    only when the cache has none. This puts the pinned bytes there first.
//
//   node scripts/ci/fetch-appimage-tooling.mjs --out-dir <dir>
//
// Pins: third_party/licenses/appimage-runtime.json. The variables go to
// $GITHUB_ENV when set (CI), else are printed as `export` lines. Run before
// `tauri build` by release.yml's build-linux and linux-packages.yml;
// scripts/generate-appimage-notices.mjs then checks the AppImage really
// carries exactly this runtime and this AppRun. Node built-ins only.
// ============================================================================
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

function fail(message) {
  console.error(`::error::AppImage tooling: ${message}`);
  process.exit(1);
}

const argv = process.argv.slice(2);
if (argv.length !== 2 || argv[0] !== '--out-dir') fail('usage: node scripts/ci/fetch-appimage-tooling.mjs --out-dir <dir>');
const outDir = path.resolve(argv[1]);
const pins = JSON.parse(fs.readFileSync(path.join(repo, 'third_party', 'licenses', 'appimage-runtime.json'), 'utf8'));

const ALLOWED_URL =
  /^https:\/\/github\.com\/(AppImage\/type2-runtime|tauri-apps\/binary-releases)\/releases\/download\/[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/;

async function pinned(url, expected) {
  if (!ALLOWED_URL.test(url)) return fail(`refusing to fetch ${url}: not a pinned AppImage tooling URL`);
  for (let attempt = 1; ; attempt++) {
    try {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const buf = Buffer.from(await res.arrayBuffer());
      const actual = createHash('sha256').update(buf).digest('hex');
      if (actual !== expected) fail(`${url}: SHA-256 ${actual}, pinned ${expected} (third_party/licenses/appimage-runtime.json)`);
      console.log(`verified ${url} (${actual})`);
      return buf;
    } catch (e) {
      if (attempt >= 3) fail(`GET ${url}: ${e.message}`);
      console.log(`GET ${url}: ${e.message} (attempt ${attempt}/3) - retrying`);
      await new Promise((resolve) => setTimeout(resolve, attempt * 5000));
    }
  }
}

const write = (file, data) => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, data, { mode: 0o755 });
  fs.chmodSync(file, 0o755);
};

const runtime = path.join(outDir, 'runtime-x86_64');
write(runtime, await pinned(pins.runtime.url, pins.runtime.sha256));

// Tauri's tool cache: dirs::cache_dir()/tauri, i.e. $XDG_CACHE_HOME or ~/.cache.
const cacheHome = process.env.XDG_CACHE_HOME || path.join(os.homedir(), '.cache');
const apprun = path.join(cacheHome, 'tauri', 'AppRun-x86_64');
write(apprun, await pinned(pins.apprun.url, pins.apprun.sha256));

const lines = [`LDAI_RUNTIME_FILE=${runtime}`, `APPIMAGE_RUNTIME_FILE=${runtime}`];
if (process.env.GITHUB_ENV) fs.appendFileSync(process.env.GITHUB_ENV, `${lines.join('\n')}\n`);
else for (const l of lines) console.log(`export ${l}`);
console.log(
  `AppImage runtime: type2-runtime ${pins.runtime.release} (${pins.runtime.commit}) at ${runtime}; ` +
    `AppRun: ${pins.apprun.sha256} at ${apprun}`,
);
