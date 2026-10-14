#!/usr/bin/env node
// ============================================================================
// Verifies a Tauri updater signature (<bundle>.sig) against a public key, as
// the in-app updater does, with node's own Ed25519 and BLAKE2b (no minisign
// tool). linux-packages.yml signs its PR build with a throwaway key made by
// `tauri signer generate` (never the real one) and runs this on the FINAL
// AppImage: proof that scripts/ci/appimage-notices.sh's re-bundle signed the
// bytes that ship, not the first bundle it replaced (review round 1 of #298).
//
//   node scripts/ci/verify-updater-signature.mjs <bundle> <bundle.sig> <key.pub>
//
// Formats (minisign, which Tauri's signer writes; .sig and .pub are base64 of
// the minisign text files): the signature line is base64 of
// alg(2) || key id(8) || Ed25519 signature(64), over BLAKE2b-512(file) when
// alg is "ED" (prehashed) or the file itself when "Ed"; the global signature
// covers signature(64) || the trusted comment. The public key line is base64
// of "Ed" || key id(8) || Ed25519 key(32). Exits 1 on any mismatch.
// ============================================================================
import { createHash, createPublicKey, verify } from 'node:crypto';
import fs from 'node:fs';

function fail(message) {
  console.error(`::error::updater signature: ${message}`);
  process.exit(1);
}

const [bundle, sigFile, pubFile] = process.argv.slice(2);
if (!pubFile) fail('usage: node scripts/ci/verify-updater-signature.mjs <bundle> <bundle.sig> <key.pub>');

/** The lines of a minisign text file stored base64-encoded, as Tauri writes .sig and .pub. */
const minisignLines = (file) => {
  const raw = fs.readFileSync(file, 'utf8').trim();
  const text = raw.startsWith('untrusted comment:') ? raw : Buffer.from(raw, 'base64').toString('utf8');
  return text.split('\n').map((l) => l.replace(/\r$/, ''));
};

const pubLines = minisignLines(pubFile);
const pub = Buffer.from(pubLines[1] || '', 'base64');
if (pub.length !== 42 || pub.toString('latin1', 0, 2) !== 'Ed') fail(`${pubFile} is not a minisign Ed25519 public key`);
const key = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), pub.subarray(10)]), format: 'der', type: 'spki' });

const sigLines = minisignLines(sigFile);
const sig = Buffer.from(sigLines[1] || '', 'base64');
const trusted = sigLines[2] || '';
const global = Buffer.from(sigLines[3] || '', 'base64');
if (sig.length !== 74 || !trusted.startsWith('trusted comment: ') || global.length !== 64) fail(`${sigFile} is not a minisign signature`);
const alg = sig.toString('latin1', 0, 2);
if (!sig.subarray(2, 10).equals(pub.subarray(2, 10))) fail(`${sigFile} was made with key id ${sig.subarray(2, 10).toString('hex')}, ${pubFile} is ${pub.subarray(2, 10).toString('hex')}`);

const data = fs.readFileSync(bundle);
let message;
if (alg === 'ED') message = createHash('blake2b512').update(data).digest();
else if (alg === 'Ed') message = data;
else fail(`${sigFile}: unknown signature algorithm ${JSON.stringify(alg)}`);
if (!verify(null, message, key, sig.subarray(10))) fail(`${sigFile} does not verify ${bundle} - the signature is not over these bytes`);
if (!verify(null, Buffer.concat([sig.subarray(10), Buffer.from(trusted.slice('trusted comment: '.length), 'utf8')]), key, global)) {
  fail(`${sigFile}: the trusted comment's signature does not verify`);
}
console.log(`OK: ${sigFile} verifies ${bundle} (${data.length} bytes; ${trusted})`);
