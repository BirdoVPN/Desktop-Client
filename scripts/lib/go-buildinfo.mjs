// Reads the build information the Go toolchain embeds in every binary it
// links (Go 1.18+ inline format; what `go version -m <binary>` prints): the
// Go version, the main module and every dependency module with its version.
// Works on ELF, PE and Mach-O alike: the blob is found by its magic, not by
// section. Used by scripts/generate-third-party-notices.mjs and
// scripts/vendor-xray-go-licences.mjs (MR-1685). Throws on anything it cannot
// read; callers decide how to fail.
import fs from 'node:fs';

const MAGIC = Buffer.from('\xff Go buildinf:', 'latin1');

/**
 * @returns {{ goVersion: string, main: string, modules: { path: string, version: string }[] }}
 *   modules sorted by path.
 */
export function readGoBuildInfo(file) {
  const buf = fs.readFileSync(file);
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
  for (const line of lines) {
    const [kind, modPath, version] = line.split('\t');
    if (kind === 'mod') main = modPath;
    if (kind === 'dep') modules.push({ path: modPath, version });
    // A replaced module's source is the replacement: nothing here names it.
    if (kind === '=>') throw new Error(`${file}: a replaced module (${line.trim()}) - its licence source is the replacement; handle it by hand`);
  }
  if (!/^go1\.\d+/.test(goVersion)) throw new Error(`${file}: unexpected Go version '${goVersion}'`);
  if (!main) throw new Error(`${file}: no main module in its build information`);
  if (modules.length === 0) throw new Error(`${file}: no dependency modules in its build information`);
  modules.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return { goVersion, main, modules };
}
