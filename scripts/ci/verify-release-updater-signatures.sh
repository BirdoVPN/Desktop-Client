#!/usr/bin/env bash
# ============================================================================
# MR-2072 (AUD-DESK-21): release.yml's release job runs this over the assets
# it is about to publish, before SHA256SUMS.txt and the GitHub Release. Until
# then the release only checked that each updater .sig EXISTED: a .sig made
# with another key, over other bytes or with an edited trusted comment
# shipped, and every installed client then refused the update.
#
#   verify-release-updater-signatures.sh <release-files-dir> <tauri.conf.json>
#
# Two checks, each over the whole directory tree:
#   1. every bundle the update server serves (-setup.exe, .AppImage,
#      .app.tar.gz: the suffixes birdo-web's updates.controller.ts matches)
#      has its <bundle>.sig;
#   2. every .sig has its bundle next to it and verifies it against
#      plugins.updater.pubkey in tauri.conf.json - the key compiled into the
#      app, so the one the in-app updater checks with. The check is
#      verify-updater-signature.mjs (node's Ed25519 + BLAKE2b, both the file
#      signature and the trusted comment's global signature; no minisign).
# Any failure exits 1, after listing every bad file.
#
# Self-test, with throwaway keys from the locked tauri CLI:
# verify-release-updater-signatures.tests.sh (tests.yml, every PR).
# ============================================================================
set -euo pipefail

usage='usage: verify-release-updater-signatures.sh <release-files-dir> <tauri.conf.json>'
here=$(cd "$(dirname "$0")" && pwd)
dir=${1:?$usage}
conf=${2:?$usage}
[ -d "$dir" ] || { echo "::error::$dir is not a directory"; exit 1; }

base=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
if command -v cygpath >/dev/null 2>&1; then base=$(cygpath -u "$base"); fi
pub=$(mktemp "$base/updater-pubkey.XXXXXX")
trap 'rm -f "${pub:?}"' EXIT

# plugins.updater.pubkey is base64 of the minisign public key file, exactly as
# `tauri signer generate` writes <key>.pub, so it goes to the verifier as one.
node -e '
const fs = require("fs");
const conf = process.argv[1];
const key = JSON.parse(fs.readFileSync(conf, "utf8"))?.plugins?.updater?.pubkey;
if (typeof key !== "string" || !key.trim()) {
  console.error(`::error::${conf} has no plugins.updater.pubkey`);
  process.exit(1);
}
fs.writeFileSync(process.argv[2], key.trim());
' "$conf" "$pub"

fail=0

while IFS= read -r f; do
  if [ ! -f "$f.sig" ]; then
    echo "::error::$(basename "$f") has no updater signature $(basename "$f").sig"
    fail=1
  fi
done < <(find "$dir" -type f \( -name '*-setup.exe' -o -name '*.AppImage' -o -name '*.app.tar.gz' \) | sort)

sigs=0
while IFS= read -r s; do
  sigs=$((sigs + 1))
  f=${s%.sig}
  if [ ! -f "$f" ]; then
    echo "::error::$(basename "$s") has no bundle $(basename "$f") next to it"
    fail=1
    continue
  fi
  node "$here/verify-updater-signature.mjs" "$f" "$s" "$pub" </dev/null || fail=1
done < <(find "$dir" -type f -name '*.sig' | sort)

if [ "$sigs" -eq 0 ]; then
  echo "::error::no updater .sig under $dir"
  fail=1
fi
if [ "$fail" -ne 0 ]; then
  echo "::error::updater signatures do not verify against plugins.updater.pubkey in $conf - refusing to publish"
  exit 1
fi
echo "OK: all $sigs updater signature(s) under $dir verify against plugins.updater.pubkey in $conf"
