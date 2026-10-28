#!/usr/bin/env bash
# ============================================================================
# Self-test for scripts/ci/verify-bundled-xray.sh (the macOS + Linux
# post-bundle xray gate in release.yml).
#
# Builds FAKE packages in each shape the gate understands and asserts the
# gate's exit code for every scenario. A gate that can be edited into a no-op
# is worse than none, so every failure path is proven to still fail:
#
#   pass   .app dir, .app.tar.gz; .deb (Linux); .dmg (macOS);
#          upper-case expected hash; several artifacts in one call
#   fail   one byte rewritten after hashing (the v1.4.40/41 defect)
#          no resources/xray at all
#          xray present but not under resources/ (the app would not find it)
#          xray not executable
#          two xrays (ambiguous; .deb)
#          hash not compiled into the app binary (stale option_env!)
#          a dotfile under resources/ (.app, .deb; #256's .gitkeep)
#          empty / non-hex expected hash (GITHUB_ENV never set)
#          no resources/THIRD-PARTY-NOTICES.txt, or not this build's (MR-1685)
#          NOTICES_FILE unset or naming a missing file
#          missing artifact, unknown artifact kind, tarball with two .app dirs
#          an .AppImage: Linux ships the .deb only (owner decision 2026-10-28,
#          MR-2020/MR-2041/MR-2042), so the gate no longer takes one
#          one bad artifact among good ones still fails the whole call
# ============================================================================
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
gate="$here/verify-bundled-xray.sh"
[ -f "$gate" ] || { echo "::error::gate script missing: $gate"; exit 1; }

work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/xray-gate-selftest.XXXXXX")"
trap 'rm -rf "$work"' EXIT

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# A deterministic pseudo-binary payload.
payload="$work/payload.bin"
LC_ALL=C awk 'BEGIN { for (i = 0; i < 4096; i++) printf "%c", (i * 7 + 13) % 256 }' </dev/null >"$payload"
good_sha="$(sha256_of "$payload")"
# The notices this "build" generated (check 7). Exported: every gate run
# below inherits it, as release.yml's steps do.
notices="$work/THIRD-PARTY-NOTICES.txt"
printf 'THIRD-PARTY SOFTWARE NOTICES - fixture

Xray-core v0.0.0
' >"$notices"
export NOTICES_FILE="$notices"
other_sha="$(printf 'not the payload' | { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi; } | awk '{print $1}')"

# --- fixture builders ---------------------------------------------------------
# make_app <dir.app> [xray_rel] [compiled_sha] [xray_mode] [bytes_file]
make_app() {
  local app="$1" rel="${2-Contents/Resources/resources/xray}" compiled="${3-$good_sha}" mode="${4-755}" bytes="${5-$payload}"
  mkdir -p "$app/Contents/MacOS"
  printf 'MACHO-STUB\0option_env:%s\0' "$compiled" >"$app/Contents/MacOS/birdo-vpn-desktop"
  chmod 755 "$app/Contents/MacOS/birdo-vpn-desktop"
  if [ -n "$rel" ]; then
    mkdir -p "$(dirname "$app/$rel")"
    cp "$bytes" "$app/$rel"
    chmod "$mode" "$app/$rel"
  fi
  mkdir -p "$app/Contents/Resources/resources"
  cp "$notices" "$app/Contents/Resources/resources/THIRD-PARTY-NOTICES.txt"
}

# make_linux_root <root> [xray_rel] [compiled_sha] [xray_mode] [bytes_file]
make_linux_root() {
  local root="$1" rel="${2-usr/lib/BirdoVPN/resources/xray}" compiled="${3-$good_sha}" mode="${4-755}" bytes="${5-$payload}"
  mkdir -p "$root/usr/bin"
  printf 'ELF-STUB\0option_env:%s\0' "$compiled" >"$root/usr/bin/birdo-vpn-desktop"
  chmod 755 "$root/usr/bin/birdo-vpn-desktop"
  if [ -n "$rel" ]; then
    mkdir -p "$(dirname "$root/$rel")"
    cp "$bytes" "$root/$rel"
    chmod "$mode" "$root/$rel"
  fi
  mkdir -p "$root/usr/lib/BirdoVPN/resources"
  cp "$notices" "$root/usr/lib/BirdoVPN/resources/THIRD-PARTY-NOTICES.txt"
}

make_tar() { # make_tar <out.app.tar.gz> <dir containing the .app(s)>
  tar -czf "$1" -C "$2" .
}

# --- assertions ---------------------------------------------------------------
failures=0
passes=0
expect() { # expect <exit-code> <case> [must-mention] -- <gate args...>
  local want="$1" case="$2" mention="$3"
  shift 4
  local out code=0
  out="$(bash "$gate" "$@" 2>&1)" || code=$?
  if [ "$code" -eq "$want" ] && { [ -z "$mention" ] || printf '%s' "$out" | grep -qF -- "$mention"; }; then
    passes=$((passes + 1))
    echo "PASS  $case (exit $code)"
  else
    failures=$((failures + 1))
    local why=""
    if [ -n "$mention" ]; then why=" mentioning \"$mention\""; fi
    echo "FAIL  $case: expected exit $want$why, got exit $code"
    echo "----- output -----"
    echo "$out"
    echo "------------------"
  fi
}

tampered="$work/tampered.bin"
cp "$payload" "$tampered"
printf '\377' | dd of="$tampered" bs=1 seek=100 conv=notrunc 2>/dev/null

# macOS shapes (work on any OS: they are plain directories / tarballs)
make_app "$work/good/BirdoVPN.app"
make_tar "$work/good.app.tar.gz" "$work/good"
expect 0 '.app directory passes' 'OK: every artifact' -- "$good_sha" "$work/good/BirdoVPN.app"
expect 0 '.app.tar.gz passes' 'OK: every artifact' -- "$good_sha" "$work/good.app.tar.gz"
expect 0 'upper-case expected hash passes' '' -- "$(printf '%s' "$good_sha" | tr 'a-f' 'A-F')" "$work/good.app.tar.gz"

make_app "$work/rewritten/BirdoVPN.app" Contents/Resources/resources/xray "$good_sha" 755 "$tampered"
make_tar "$work/rewritten.app.tar.gz" "$work/rewritten"
expect 1 'byte rewritten after hashing fails' 'v1.4.40/v1.4.41' -- "$good_sha" "$work/rewritten.app.tar.gz"

make_app "$work/noxray/BirdoVPN.app" ''
make_tar "$work/noxray.app.tar.gz" "$work/noxray"
expect 1 'no resources/xray fails' 'no resources/xray' -- "$good_sha" "$work/noxray.app.tar.gz"

make_app "$work/misplaced/BirdoVPN.app" Contents/Resources/xray
make_tar "$work/misplaced.app.tar.gz" "$work/misplaced"
expect 1 'xray outside resources/ fails' 'no resources/xray' -- "$good_sha" "$work/misplaced.app.tar.gz"

make_app "$work/noexec/BirdoVPN.app" Contents/Resources/resources/xray "$good_sha" 644
make_tar "$work/noexec.app.tar.gz" "$work/noexec"
expect 1 'non-executable xray fails' 'not executable' -- "$good_sha" "$work/noexec.app.tar.gz"

make_app "$work/stale/BirdoVPN.app" Contents/Resources/resources/xray "$other_sha"
expect 1 'hash not compiled into the app fails' 'was not compiled into the app' -- "$good_sha" "$work/stale/BirdoVPN.app"

# #256: bundle.resources' "resources/*" glob shipped resources/.gitkeep. Any
# dotfile under resources/ fails, however deep; one elsewhere is not its
# business.
make_app "$work/gitkeep/BirdoVPN.app"
: >"$work/gitkeep/BirdoVPN.app/Contents/Resources/resources/.gitkeep"
make_tar "$work/gitkeep.app.tar.gz" "$work/gitkeep"
expect 1 '.app.tar.gz with resources/.gitkeep fails' 'Contents/Resources/resources/.gitkeep - a dotfile under resources/' -- "$good_sha" "$work/gitkeep.app.tar.gz"
make_app "$work/dsstore/BirdoVPN.app"
mkdir -p "$work/dsstore/BirdoVPN.app/Contents/Resources/resources/pf"
: >"$work/dsstore/BirdoVPN.app/Contents/Resources/resources/pf/.DS_Store"
: >"$work/dsstore/BirdoVPN.app/Contents/.hidden-elsewhere"
expect 1 '.app with a nested dotfile under resources/ fails' 'resources/pf/.DS_Store - a dotfile under resources/' -- "$good_sha" "$work/dsstore/BirdoVPN.app"
make_app "$work/elsewhere/BirdoVPN.app"
: >"$work/elsewhere/BirdoVPN.app/Contents/.hidden-elsewhere"
expect 0 'a dotfile outside resources/ passes' 'OK: every artifact' -- "$good_sha" "$work/elsewhere/BirdoVPN.app"

make_app "$work/two/A.app"
make_app "$work/two/B.app"
make_tar "$work/two.app.tar.gz" "$work/two"
expect 1 'tarball with two .app dirs fails' 'exactly one top-level .app' -- "$good_sha" "$work/two.app.tar.gz"

# MR-1685: the notices this build generated, in every package.
make_app "$work/nonotices/BirdoVPN.app"
rm "$work/nonotices/BirdoVPN.app/Contents/Resources/resources/THIRD-PARTY-NOTICES.txt"
make_tar "$work/nonotices.app.tar.gz" "$work/nonotices"
expect 1 '.app.tar.gz without THIRD-PARTY-NOTICES.txt fails' 'found 0 - the package would ship without its third-party licence notices' -- "$good_sha" "$work/nonotices.app.tar.gz"
make_app "$work/oldnotices/BirdoVPN.app"
printf 'notices from another build
' >"$work/oldnotices/BirdoVPN.app/Contents/Resources/resources/THIRD-PARTY-NOTICES.txt"
expect 1 '.app with another build'"'"'s notices fails' 'is not the file this build generated' -- "$good_sha" "$work/oldnotices/BirdoVPN.app"
make_app "$work/misplacednotices/BirdoVPN.app"
mv "$work/misplacednotices/BirdoVPN.app/Contents/Resources/resources/THIRD-PARTY-NOTICES.txt" "$work/misplacednotices/BirdoVPN.app/Contents/Resources/"
expect 1 'notices outside resources/ fails' 'found 0' -- "$good_sha" "$work/misplacednotices/BirdoVPN.app"
NOTICES_FILE='' expect 1 'NOTICES_FILE unset fails' 'NOTICES_FILE must name' -- "$good_sha" "$work/good.app.tar.gz"
NOTICES_FILE="$work/no-such-notices.txt" expect 1 'NOTICES_FILE naming a missing file fails' 'NOTICES_FILE must name' -- "$good_sha" "$work/good.app.tar.gz"

expect 1 'empty expected hash fails' 'never captured XRAY_BINARY_SHA256' -- '' "$work/good.app.tar.gz"
expect 1 'non-hex expected hash fails' 'not 64 hex' -- 'not-a-sha' "$work/good.app.tar.gz"
expect 1 'missing artifact fails' 'not found' -- "$good_sha" "$work/does-not-exist.app.tar.gz"
expect 1 'unknown artifact kind fails' 'unknown artifact kind' -- "$good_sha" "$payload"
# Owner decision 2026-10-28: Linux ships the .deb only. An AppImage, however
# well formed, is not a package the gate passes.
cp "$payload" "$work/BirdoVPN_9.9.9_amd64.AppImage"
expect 1 'an .AppImage is no longer accepted (Linux ships the .deb only)' 'Linux ships no AppImage' -- "$good_sha" "$work/BirdoVPN_9.9.9_amd64.AppImage"
expect 1 'one bad artifact among good ones fails' 'v1.4.40/v1.4.41' -- "$good_sha" "$work/good.app.tar.gz" "$work/rewritten.app.tar.gz" "$work/good/BirdoVPN.app"
expect 0 'several good artifacts in one call pass' '' -- "$good_sha" "$work/good.app.tar.gz" "$work/good/BirdoVPN.app"

# Linux shapes: the .deb (dpkg-deb, so the Linux leg only)
if command -v dpkg-deb >/dev/null 2>&1; then
  for v in good bad gitkeep nonotices two; do
    d="$work/deb-$v"
    case "$v" in
      good) make_linux_root "$d" ;;
      bad) make_linux_root "$d" usr/lib/BirdoVPN/resources/xray "$good_sha" 755 "$tampered" ;;
      gitkeep)
        make_linux_root "$d"
        : >"$d/usr/lib/BirdoVPN/resources/.gitkeep" # v1.4.46's .deb
        ;;
      nonotices)
        make_linux_root "$d"
        rm "$d/usr/lib/BirdoVPN/resources/THIRD-PARTY-NOTICES.txt"
        ;;
      two)
        make_linux_root "$d"
        make_linux_root "$d" usr/lib/birdo-vpn-desktop/resources/xray
        ;;
    esac
    mkdir -p "$d/DEBIAN"
    printf 'Package: birdo-selftest\nVersion: 1.0\nArchitecture: amd64\nMaintainer: ci\nDescription: gate fixture\n' >"$d/DEBIAN/control"
    dpkg-deb --root-owner-group --build "$d" "$work/$v.deb" >/dev/null
  done
  expect 0 '.deb passes' 'OK: every artifact' -- "$good_sha" "$work/good.deb"
  expect 1 '.deb with rewritten xray fails' 'v1.4.40/v1.4.41' -- "$good_sha" "$work/bad.deb"
  expect 1 '.deb without THIRD-PARTY-NOTICES.txt fails' 'found 0' -- "$good_sha" "$work/nonotices.deb"
  expect 1 '.deb with resources/.gitkeep fails' 'usr/lib/BirdoVPN/resources/.gitkeep - a dotfile under resources/' -- "$good_sha" "$work/gitkeep.deb"
  expect 1 '.deb with two xrays (ambiguous) fails' 'ambiguous' -- "$good_sha" "$work/two.deb"
else
  echo "SKIP  .deb scenarios (no dpkg-deb on this OS; the Linux leg runs them)"
fi

if command -v hdiutil >/dev/null 2>&1; then
  hdiutil create -quiet -fs HFS+ -volname BirdoGood -srcfolder "$work/good" -format UDZO "$work/good.dmg"
  hdiutil create -quiet -fs HFS+ -volname BirdoBad -srcfolder "$work/rewritten" -format UDZO "$work/bad.dmg"
  expect 0 '.dmg passes' 'OK: every artifact' -- "$good_sha" "$work/good.dmg"
  expect 1 '.dmg with rewritten xray fails' 'v1.4.40/v1.4.41' -- "$good_sha" "$work/bad.dmg"
  # Not a disk image at all: the bounded attach retry must give up and fail
  # closed (3 attempts), never pass or hang.
  cp "$payload" "$work/garbage.dmg"
  expect 1 'unmountable .dmg fails after the bounded attach retry' 'hdiutil attach failed (3 attempts)' -- "$good_sha" "$work/garbage.dmg"
else
  echo "SKIP  .dmg scenarios (no hdiutil on this OS; the macOS leg runs them)"
fi

echo "verify-bundled-xray self-test: $passes passed, $failures failed"
if [ "$failures" -gt 0 ]; then
  echo "::error::verify-bundled-xray self-test: $failures scenario(s) failed"
  exit 1
fi
