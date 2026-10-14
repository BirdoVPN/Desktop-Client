// Reads a zip archive held in memory: its members' names and, on demand,
// their bytes. Built-in zlib only. Enough for the archives the licence and
// source scripts read: Go module zips from proxy.golang.org and Xray-core's
// release zips (stored or deflated members, no ZIP64, no encryption). Used by
// scripts/vendor-xray-go-licences.mjs and scripts/build-xray-source-archive.mjs.
// Throws on anything it cannot read; callers decide how to fail.
import zlib from 'node:zlib';

/** @returns {{ name: string, read: () => Buffer }[]} in central-directory order. */
export function zipEntries(zip) {
  let eocd = -1;
  for (let i = zip.length - 22; i >= Math.max(0, zip.length - 65557); i--) {
    if (zip.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error('not a zip archive (no end of central directory)');
  const count = zip.readUInt16LE(eocd + 10);
  let p = zip.readUInt32LE(eocd + 16);
  if (p === 0xffffffff || count === 0xffff) throw new Error('ZIP64 archive: not supported');
  const entries = [];
  for (let i = 0; i < count; i++) {
    if (zip.readUInt32LE(p) !== 0x02014b50) throw new Error('corrupt zip central directory');
    const flags = zip.readUInt16LE(p + 8);
    const method = zip.readUInt16LE(p + 10);
    const size = zip.readUInt32LE(p + 20);
    const rawSize = zip.readUInt32LE(p + 24);
    const nameLen = zip.readUInt16LE(p + 28);
    const extraLen = zip.readUInt16LE(p + 30);
    const commentLen = zip.readUInt16LE(p + 32);
    const local = zip.readUInt32LE(p + 42);
    const name = zip.subarray(p + 46, p + 46 + nameLen).toString('utf8');
    p += 46 + nameLen + extraLen + commentLen;
    const read = () => {
      if (flags & 1) throw new Error(`${name}: encrypted zip member`);
      if (zip.readUInt32LE(local) !== 0x04034b50) throw new Error(`corrupt zip local header for ${name}`);
      const start = local + 30 + zip.readUInt16LE(local + 26) + zip.readUInt16LE(local + 28);
      const data = zip.subarray(start, start + size);
      let out;
      if (method === 0) out = Buffer.from(data);
      else if (method === 8) out = zlib.inflateRawSync(data);
      else throw new Error(`${name}: zip compression method ${method} not supported`);
      if (out.length !== rawSize) throw new Error(`${name}: ${out.length} bytes unpacked, the zip says ${rawSize}`);
      return out;
    };
    entries.push({ name, read });
  }
  return entries;
}
