// Reads the build information the Go toolchain embeds in every binary it
// links (Go 1.18+ inline format; what `go version -m <binary>` prints): the
// Go version, the main module and every dependency module with its version.
// Works on ELF, PE and Mach-O alike: the blob is found by its magic, not by
// section. Used by scripts/generate-third-party-notices.mjs,
// scripts/vendor-xray-go-licences.mjs (MR-1685) and
// scripts/build-xray-source-archive.mjs. Throws on anything it cannot read;
// callers decide how to fail.
import fs from 'node:fs';

const MAGIC = Buffer.from('\xff Go buildinf:', 'latin1');

/**
 * @param {string | Buffer} file a path, or the binary's bytes
 * @param {string} [label] the name to use in errors (default: the path)
 * @returns {{ goVersion: string, main: string, modules: { path: string, version: string }[],
 *   settings: Record<string, string> }} modules sorted by path; settings are the
 *   `build` lines (GOOS, GOARCH, -trimpath, ...).
 */
export function readGoBuildInfo(file, label = typeof file === 'string' ? file : 'binary') {
  const buf = Buffer.isBuffer(file) ? file : fs.readFileSync(file);
  file = label;
  const at = buf.indexOf(MAGIC);
  if (at < 0) throw new Error(`${file}: no Go build information - is this a Go binary?`);
  if ((buf[at + 15] & 2) === 0) throw new Error(`${file}: Go build information in the pre-Go 1.18 format`);
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
  const goVersion = str();
  const info = str();
  // 16-byte sentinels on either side of the module text.
  const lines = info.length > 32 ? info.slice(16, -16).split('\n') : [];
  let main = '';
  const modules = [];
  const settings = {};
  for (const line of lines) {
    const [kind, modPath, version] = line.split('\t');
    if (kind === 'mod') main = modPath;
    if (kind === 'dep') modules.push({ path: modPath, version });
    if (kind === 'build' && modPath.indexOf('=') > 0) {
      settings[modPath.slice(0, modPath.indexOf('='))] = modPath.slice(modPath.indexOf('=') + 1);
    }
    // A replaced module's source is the replacement: nothing here names it.
    if (kind === '=>') throw new Error(`${file}: a replaced module (${line.trim()}) - its licence source is the replacement; handle it by hand`);
  }
  if (!/^go1\.\d+/.test(goVersion)) throw new Error(`${file}: unexpected Go version '${goVersion}'`);
  if (!main) throw new Error(`${file}: no main module in its build information`);
  if (modules.length === 0) throw new Error(`${file}: no dependency modules in its build information`);
  modules.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return { goVersion, main, modules, settings };
}
