#!/usr/bin/env bash
# ============================================================================
# Self-test for scripts/ci/verify-release-updater-signatures.sh (MR-2072), run
# by tests.yml on every PR. Two THROWAWAY updater keys, A and B, are made here
# with the locked tauri CLI (`tauri signer generate`, as linux-packages.yml
# makes its PR key; never the release key, which a PR has no access to). Key A
# signs fake bundles with `tauri signer sign` (the signer `tauri build` runs)
# under the names tauri gives them; they are then laid out as release.yml's
# release job lays out release-files/ after its rename. The fixture
# tauri.conf.json carries key A's public key.
#
#   pass  every bundle signed with key A
#   pass  no macOS bundles (the Mac App Store app is live)
#   fail  a bundle changed after signing (one byte appended)
#   fail  a bundle changed after signing (one bit flipped, same size)
#   fail  a bundle signed with key B (wrong key)
#   fail  key B's signature relabelled with key A's key id (Ed25519 itself)
#   fail  tauri.conf.json carries key B's public key (wrong key)
#   fail  the repo's own tauri.conf.json (the release key) against key A
#   fail  a .sig whose trusted comment was edited (the global signature)
#   fail  another bundle's .sig (same key, other bytes)
#   fail  a bundle with no .sig; a .sig with no bundle; no .sig at all
#   fail  tauri.conf.json without plugins.updater.pubkey, or with a pubkey
#         that is not a minisign Ed25519 public key
#   and   release.yml's release job runs the gate on release-files with
#         src-tauri/tauri.conf.json, unconditionally, before SHA256SUMS.txt
#         and the GitHub Release
#
# Usage, from the repo root after `npm ci`:
#   bash scripts/ci/verify-release-updater-signatures.tests.sh
# ============================================================================
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
gate="$here/verify-release-updater-signatures.sh"
release_yml="$root/.github/workflows/release.yml"
repo_conf="$root/src-tauri/tauri.conf.json"
tauri="$root/node_modules/.bin/tauri"

base=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
if command -v cygpath >/dev/null 2>&1; then base=$(cygpath -u "$base"); fi
work=$(mktemp -d "$base/updater-sig-selftest.XXXXXX")
trap 'rm -rf "${work:?}"' EXIT

failures=0
bad() {
  echo "::error::updater signature gate self-test: $*"
  failures=$((failures + 1))
}
die() {
  echo "::error::updater signature gate self-test: $*"
  exit 1
}

[ -x "$tauri" ] || die "no $tauri - run npm ci first (the locked @tauri-apps/cli signs the fixtures)"
# The locked CLI with the key given here, never one from the environment.
signer() {
  env -u TAURI_SIGNING_PRIVATE_KEY -u TAURI_SIGNING_PRIVATE_KEY_PATH -u TAURI_SIGNING_PRIVATE_KEY_PASSWORD \
    "$tauri" signer "$@" >/dev/null
}
keygen() { # keygen <name>: $work/<name>.key + $work/<name>.key.pub, no password
  signer generate --ci -w "$work/$1.key" -p ""
  [ -s "$work/$1.key" ] && [ -s "$work/$1.key.pub" ] || die "tauri signer generate wrote no key $1"
}
sign() { # sign <key name> <file>: writes <file>.sig
  rm -f "$2.sig"
  signer sign -f "$work/$1.key" -p "" "$2"
  [ -s "$2.sig" ] || die "tauri signer sign wrote no $2.sig"
}
flip() { # flip one bit in the middle of <file>; same size
  node -e 'const fs = require("fs"); const b = fs.readFileSync(process.argv[1]); b[b.length >> 1] ^= 1; fs.writeFileSync(process.argv[1], b);' "$1"
}
sig_edit() { # sig_edit comment <sig> | sig_edit keyid <sig> <key.pub>: edit a .sig in place
  node -e '
const fs = require("fs");
const [mode, file, pubFile] = process.argv.slice(1);
const lines = (f) => Buffer.from(fs.readFileSync(f, "utf8").trim(), "base64").toString("utf8").split("\n");
const l = lines(file);
if (mode === "comment") {
  l[2] += " (edited)";
} else {
  const sig = Buffer.from(l[1], "base64");
  Buffer.from(lines(pubFile)[1], "base64").copy(sig, 2, 2, 10);
  l[1] = sig.toString("base64");
}
fs.writeFileSync(file, Buffer.from(l.join("\n"), "utf8").toString("base64"));
' "$@"
}
conf() { # conf <file> [pubkey]: a tauri.conf.json with that plugins.updater.pubkey (none if empty)
  node -e '
const [file, key] = process.argv.slice(1);
require("fs").writeFileSync(file, JSON.stringify({ plugins: { updater: key ? { pubkey: key } : {} } }, null, 2));
' "$1" "${2:-}"
}

keygen a
keygen b
conf "$work/conf-a.json" "$(cat "$work/a.key.pub")"
conf "$work/conf-b.json" "$(cat "$work/b.key.pub")"
conf "$work/conf-none.json"
conf "$work/conf-junk.json" "$(printf 'untrusted comment: not a key\nAAAA\n' | base64 | tr -d '\n')"

# The signed release: each bundle signed under tauri's name, then moved to the
# name the release publishes it under (a signature covers bytes, not names).
pristine="$work/pristine"
bundle() { # bundle <tauri name> <path under release-files>
  local src="$work/bundle/$1" dest="$pristine/$2"
  mkdir -p "$(dirname "$src")" "$(dirname "$dest")"
  printf 'not a real bundle: %s\n' "$1" >"$src"
  sign a "$src"
  mv "$src" "$dest"
  mv "$src.sig" "$dest.sig"
}
bundle BirdoVPN_9.9.9_x64-setup.exe windows/BirdoVPN_9.9.9_Windows_x64-setup.exe
bundle arm64/BirdoVPN.app.tar.gz macos-arm64/BirdoVPN-macos-arm64.app.tar.gz
bundle x64/BirdoVPN.app.tar.gz macos-x64/BirdoVPN-macos-x64.app.tar.gz
# Assets the release ships with no updater signature. Linux: the .deb only
# (owner decision 2026-10-28), which apt/dpkg upgrades; no updater bundle.
mkdir -p "$pristine/linux"
printf 'not a real package\n' >"$pristine/linux/BirdoVPN_9.9.9_Linux_amd64.deb"
printf 'not a real disk image\n' >"$pristine/macos-arm64/BirdoVPN_9.9.9_macOS_aarch64.dmg"
mkdir -p "$pristine/source"
printf 'not a real archive\n' >"$pristine/source/BirdoVPN-9.9.9-corresponding-source.tar.gz"

win=windows/BirdoVPN_9.9.9_Windows_x64-setup.exe
arm=macos-arm64/BirdoVPN-macos-arm64.app.tar.gz
x64=macos-x64/BirdoVPN-macos-x64.app.tar.gz

scenario() { # scenario <name>: prints $work/<name>, a copy of the signed release
  cp -R "$pristine" "$work/$1"
  printf '%s\n' "$work/$1"
}
expect_pass() { # expect_pass <what> <dir> <conf>
  local out
  if out=$(bash "$gate" "$2" "$3" 2>&1); then
    echo "ok   pass: $1"
  else
    bad "$1: expected PASS, the gate failed: $out"
  fi
}
expect_fail() { # expect_fail <what> <dir> <conf> <what the gate must say>
  local out
  if out=$(bash "$gate" "$2" "$3" 2>&1); then
    bad "$1: expected FAIL, the gate passed: $out"
  elif ! grep -qF -- "$4" <<<"$out"; then
    bad "$1: the gate failed, but without '$4': $out"
  else
    echo "ok   fail: $1"
  fi
}

expect_pass "every bundle signed with key A" "$pristine" "$work/conf-a.json"

d=$(scenario no-macos)
rm -r "$d/macos-arm64" "$d/macos-x64"
expect_pass "no macOS bundles (the Mac App Store app is live)" "$d" "$work/conf-a.json"

d=$(scenario appended)
printf 'x' >>"$d/$win"
expect_fail "a bundle changed after signing (one byte appended)" "$d" "$work/conf-a.json" 'the signature is not over these bytes'

d=$(scenario flipped)
flip "$d/$x64"
expect_fail "a bundle changed after signing (one bit flipped, same size)" "$d" "$work/conf-a.json" 'the signature is not over these bytes'

d=$(scenario signed-with-b)
sign b "$d/$x64"
expect_fail "a bundle signed with key B (wrong key)" "$d" "$work/conf-a.json" 'was made with key id'

d=$(scenario relabelled-b)
sign b "$d/$arm"
sig_edit keyid "$d/$arm.sig" "$work/a.key.pub"
expect_fail "key B's signature relabelled with key A's key id" "$d" "$work/conf-a.json" 'the signature is not over these bytes'

expect_fail "tauri.conf.json carries key B's public key (wrong key)" "$pristine" "$work/conf-b.json" 'was made with key id'
expect_fail "the repo's own tauri.conf.json (the release key) against key A" "$pristine" "$repo_conf" 'was made with key id'

d=$(scenario edited-comment)
sig_edit comment "$d/$win.sig"
expect_fail "a .sig whose trusted comment was edited" "$d" "$work/conf-a.json" "the trusted comment's signature does not verify"

d=$(scenario swapped)
cp "$d/$arm.sig" "$d/$win.sig"
expect_fail "another bundle's .sig (same key, other bytes)" "$d" "$work/conf-a.json" 'the signature is not over these bytes'

d=$(scenario missing-sig)
rm "$d/$arm.sig"
expect_fail "a bundle with no .sig" "$d" "$work/conf-a.json" 'has no updater signature BirdoVPN-macos-arm64.app.tar.gz.sig'

d=$(scenario orphan-sig)
rm "$d/$win"
expect_fail "a .sig with no bundle" "$d" "$work/conf-a.json" 'has no bundle BirdoVPN_9.9.9_Windows_x64-setup.exe'

d=$(scenario no-sigs)
find "$d" -name '*.sig' -delete
expect_fail "no .sig at all" "$d" "$work/conf-a.json" 'no updater .sig under'

expect_fail "tauri.conf.json without plugins.updater.pubkey" "$pristine" "$work/conf-none.json" 'has no plugins.updater.pubkey'
expect_fail "a pubkey that is not a minisign Ed25519 public key" "$pristine" "$work/conf-junk.json" 'is not a minisign Ed25519 public key'

# release.yml: the release job runs the gate over release-files with the
# repo's tauri.conf.json, in a step with no `if:` and no continue-on-error,
# before it signs SHA256SUMS.txt and creates the GitHub Release.
call='bash scripts/ci/verify-release-updater-signatures.sh release-files src-tauri/tauri.conf.json'
line_of() { { grep -nF -- "$1" "$release_yml" || true; } | head -n 1 | cut -d: -f1; }
job=$({ grep -nE '^  release:$' "$release_yml" || true; } | head -n 1 | cut -d: -f1)
at=$(line_of "$call")
sums=$(line_of '- name: Generate + Sigstore-sign the unified SHA256SUMS.txt')
publish=$(line_of '- name: Create GitHub Release')
if [ -z "$job" ] || [ -z "$at" ] || [ -z "$sums" ] || [ -z "$publish" ]; then
  bad "release.yml: the release job does not run '$call' (release job line ${job:-none}, gate line ${at:-none})"
else
  next_job=$(awk -v s="$job" 'NR > s && /^  [A-Za-z0-9_-]+:$/ { print NR; exit }' "$release_yml")
  step=$(head -n "$at" "$release_yml" | grep -nE '^      - (name|uses):' | tail -n 1 | cut -d: -f1)
  if [ "$at" -lt "$job" ] || { [ -n "$next_job" ] && [ "$at" -gt "$next_job" ]; } || [ "$at" -gt "$sums" ] || [ "$at" -gt "$publish" ]; then
    bad "release.yml: '$call' (line $at) must be in the release job (line $job), before SHA256SUMS.txt (line $sums) and the GitHub Release (line $publish)"
  elif sed -n "${step},${at}p" "$release_yml" | grep -qE '^        (if|continue-on-error):'; then
    bad "release.yml: the gate's step (line $step) has an if: or continue-on-error"
  else
    echo "ok   release.yml runs the gate in the release job (line $at), unconditionally, before SHA256SUMS.txt and the GitHub Release"
  fi
fi

[ "$failures" -eq 0 ] || die "$failures check(s) failed"
echo "OK: the gate passes a correctly signed release and fails every tampered, wrongly keyed or unsigned one"
