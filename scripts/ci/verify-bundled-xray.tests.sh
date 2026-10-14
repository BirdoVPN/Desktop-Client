#!/usr/bin/env bash
# ============================================================================
# Self-test for scripts/ci/verify-bundled-xray.sh (the macOS + Linux
# post-bundle xray gate in release.yml).
#
# Builds FAKE packages in each shape the gate understands and asserts the
# gate's exit code for every scenario. A gate that can be edited into a no-op
# is worse than none, so every failure path is proven to still fail:
#
#   pass   .app dir, .app.tar.gz, fake .AppImage; .deb (Linux); .dmg (macOS);
#          upper-case expected hash; several artifacts in one call
#   fail   one byte rewritten after hashing (the v1.4.40/41 defect)
#          no resources/xray at all
#          xray present but not under resources/ (the app would not find it)
#          xray not executable
#          two xrays (ambiguous)
#          hash not compiled into the app binary (stale option_env!)
#          a dotfile under resources/ (.app, AppImage, .deb; #256's .gitkeep)
#          empty / non-hex expected hash (GITHUB_ENV never set)
#          no resources/THIRD-PARTY-NOTICES.txt, or not this build's (MR-1685)
#          NOTICES_FILE unset or naming a missing file
#          (AppImage) its notices are not its own (APPIMAGE_NOTICES_FILE), or
#          that is unset; a file its notices do not list, a library or not,
#          anywhere in it; a runtime other than the one they name, or none
#          named; notices that do not begin with the generic ones (owner
#          decision 2026-10-14, L2; review round 1 of #298) - listed files
#          and a symlink pass
#          missing artifact, unknown artifact kind, tarball with two .app dirs
#          one bad artifact among good ones still fails the whole call
#
# The fake AppImage is a shell script that implements the runtime's
# --appimage-extract interface; the real runtime path was verified against
# the published v1.4.45 AppImage when this gate was written.
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
# The AppImage's own notices: the same, plus the section listing what only
# the AppImage carries (scripts/ci/appimage-notices.sh): its runtime by
# commit, and one "    <path>" line per file. make_appimage puts this file
# in every fake AppImage, whose runtime reports runtime_commit.
runtime_commit=dd6cebedcbddde9c82f89b011e8e1d40b6e43868
appimage_section() { # appimage_section [runtime line]
  printf '\n6. AppImage only: what the AppImage carries besides BirdoVPN (fixture)\n\n'
  printf '    usr/bin/birdo-vpn-desktop\n    usr/lib/BirdoVPN/resources/xray\n    usr/lib/BirdoVPN/resources/THIRD-PARTY-NOTICES.txt\n'
  printf '%s\n' "${1-  AppImage type2-runtime 20251108 - commit $runtime_commit - MIT [A1]}"
  printf 'libfixture1 1.0-1 (amd64) [A2]\n  files:\n    usr/lib/libfixture.so.1\n    usr/lib/girepository-1.0/Fixture-1.0.typelib\n'
}
appimage_notices="$work/THIRD-PARTY-NOTICES.appimage.txt"
{ cat "$notices"; appimage_section; } >"$appimage_notices"
export APPIMAGE_NOTICES_FILE="$appimage_notices"
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

# make_appimage <out.AppImage> <root> [keep|<notices file>] [runtime commit]: a
# shell script that unpacks <root> into ./squashfs-root on --appimage-extract
# and names its runtime's commit on --appimage-version, like the real AppImage
# runtime. Its notices become the AppImage's own (or the given file), unless
# `keep`.
make_appimage() {
  local out="$1" root="$2" with="${3-$appimage_notices}" commit="${4-$runtime_commit}"
  local own="$root/usr/lib/BirdoVPN/resources/THIRD-PARTY-NOTICES.txt"
  if [ -f "$own" ] && [ "$with" != keep ]; then cp "$with" "$own"; fi
  tar -czf "$out.payload.tgz" -C "$root" .
  cat >"$out" <<EOF
#!/bin/sh
if [ "\$1" = "--appimage-version" ]; then
  echo "AppImage runtime version: https://github.com/AppImage/type2-runtime/commit/$(printf '%.7s' "$commit")" >&2
  exit 0
fi
[ "\$1" = "--appimage-extract" ] || exit 64
mkdir -p squashfs-root && tar -xzf '$out.payload.tgz' -C squashfs-root
EOF
  chmod 755 "$out"
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
expect 1 'one bad artifact among good ones fails' 'v1.4.40/v1.4.41' -- "$good_sha" "$work/good.app.tar.gz" "$work/rewritten.app.tar.gz" "$work/good/BirdoVPN.app"
expect 0 'several good artifacts in one call pass' '' -- "$good_sha" "$work/good.app.tar.gz" "$work/good/BirdoVPN.app"

# Linux shapes
make_linux_root "$work/lroot-good"
make_appimage "$work/good.AppImage" "$work/lroot-good"
expect 0 'AppImage passes' 'OK: every artifact' -- "$good_sha" "$work/good.AppImage"

make_linux_root "$work/lroot-gitkeep"
: >"$work/lroot-gitkeep/usr/lib/BirdoVPN/resources/.gitkeep"
make_appimage "$work/gitkeep.AppImage" "$work/lroot-gitkeep"
expect 1 'AppImage with resources/.gitkeep fails' 'usr/lib/BirdoVPN/resources/.gitkeep - a dotfile under resources/' -- "$good_sha" "$work/gitkeep.AppImage"

make_linux_root "$work/lroot-two"
make_linux_root "$work/lroot-two" usr/lib/birdo-vpn-desktop/resources/xray
make_appimage "$work/two.AppImage" "$work/lroot-two"
expect 1 'two xrays (ambiguous) fails' 'ambiguous' -- "$good_sha" "$work/two.AppImage"

make_linux_root "$work/lroot-bad" usr/lib/BirdoVPN/resources/xray "$good_sha" 755 "$tampered"
make_appimage "$work/bad.AppImage" "$work/lroot-bad"
expect 1 'AppImage with rewritten xray fails' 'v1.4.40/v1.4.41' -- "$good_sha" "$work/bad.AppImage"

make_linux_root "$work/lroot-nonotices"
rm "$work/lroot-nonotices/usr/lib/BirdoVPN/resources/THIRD-PARTY-NOTICES.txt"
make_appimage "$work/nonotices.AppImage" "$work/lroot-nonotices"
expect 1 'AppImage without THIRD-PARTY-NOTICES.txt fails' 'found 0 - the package would ship without its third-party licence notices' -- "$good_sha" "$work/nonotices.AppImage"

# L2 (owner decision 2026-10-14; review round 1 of #298): the AppImage carries
# its own notices, which list every file in it and its runtime. A fake ELF is
# the 4-byte magic and a little.
fake_elf() { mkdir -p "$(dirname "$1")" && printf '\177ELF\002\001\001\000fixture' >"$1"; }
make_linux_root "$work/lroot-libs"
fake_elf "$work/lroot-libs/usr/lib/libfixture.so.1"
mkdir -p "$work/lroot-libs/usr/lib/girepository-1.0"
printf 'typelib, not ELF\n' >"$work/lroot-libs/usr/lib/girepository-1.0/Fixture-1.0.typelib"
ln -s libfixture.so.1 "$work/lroot-libs/usr/lib/libfixture-link.so"
make_appimage "$work/libs.AppImage" "$work/lroot-libs"
expect 0 'AppImage whose files are all listed passes (a symlink is not a file to list)' 'files    : all 5 files in it are listed' -- "$good_sha" "$work/libs.AppImage"

make_linux_root "$work/lroot-unlisted"
fake_elf "$work/lroot-unlisted/usr/lib/libfixture.so.1"
fake_elf "$work/lroot-unlisted/usr/lib/gtk-3.0/3.0.0/immodules/im-unlisted.so"
make_appimage "$work/unlisted.AppImage" "$work/lroot-unlisted"
expect 1 'AppImage with a library its notices do not list fails' 'usr/lib/gtk-3.0/3.0.0/immodules/im-unlisted.so is in the AppImage but not listed' -- "$good_sha" "$work/unlisted.AppImage"

make_linux_root "$work/lroot-apprun"
printf '#!/bin/sh\necho linuxdeploy-style launcher\n' >"$work/lroot-apprun/AppRun"
chmod 755 "$work/lroot-apprun/AppRun"
make_appimage "$work/apprun.AppImage" "$work/lroot-apprun"
expect 1 'AppImage with an unlisted file outside usr/ (a non-ELF executable) fails' 'AppRun is in the AppImage but not listed' -- "$good_sha" "$work/apprun.AppImage"

make_linux_root "$work/lroot-runtime"
make_appimage "$work/runtime.AppImage" "$work/lroot-runtime" "$appimage_notices" 0123456789abcdef0123456789abcdef01234567
expect 1 'AppImage whose runtime is not the one its notices name fails' 'the bundler used another runtime' -- "$good_sha" "$work/runtime.AppImage"

{ cat "$notices"; appimage_section ''; } >"$work/no-runtime-notices.txt"
make_linux_root "$work/lroot-noruntime"
make_appimage "$work/noruntime.AppImage" "$work/lroot-noruntime" "$work/no-runtime-notices.txt"
APPIMAGE_NOTICES_FILE="$work/no-runtime-notices.txt" expect 1 'AppImage notices that name no runtime fail' 'its notices name no AppImage runtime' -- "$good_sha" "$work/noruntime.AppImage"

{ printf 'notices from another build\n'; appimage_section; } >"$work/other-base-notices.txt"
make_linux_root "$work/lroot-otherbase"
make_appimage "$work/otherbase.AppImage" "$work/lroot-otherbase" "$work/other-base-notices.txt"
APPIMAGE_NOTICES_FILE="$work/other-base-notices.txt" expect 1 'AppImage notices that do not begin with the generic ones fail' 'do not begin with the generic notices' -- "$good_sha" "$work/otherbase.AppImage"

make_linux_root "$work/lroot-generic"
make_appimage "$work/generic.AppImage" "$work/lroot-generic" keep
expect 1 'AppImage carrying the generic notices, not its own, fails' 'is not the file this build generated' -- "$good_sha" "$work/generic.AppImage"
APPIMAGE_NOTICES_FILE='' expect 1 'APPIMAGE_NOTICES_FILE unset fails an AppImage' 'APPIMAGE_NOTICES_FILE must name' -- "$good_sha" "$work/good.AppImage"
APPIMAGE_NOTICES_FILE="$work/no-such-notices.txt" expect 1 'APPIMAGE_NOTICES_FILE naming a missing file fails' 'APPIMAGE_NOTICES_FILE must name' -- "$good_sha" "$work/good.AppImage"
APPIMAGE_NOTICES_FILE='' expect 0 'APPIMAGE_NOTICES_FILE is not needed without an AppImage' 'OK: every artifact' -- "$good_sha" "$work/good.app.tar.gz"

if command -v dpkg-deb >/dev/null 2>&1; then
  for v in good bad gitkeep nonotices; do
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
    esac
    mkdir -p "$d/DEBIAN"
    printf 'Package: birdo-selftest\nVersion: 1.0\nArchitecture: amd64\nMaintainer: ci\nDescription: gate fixture\n' >"$d/DEBIAN/control"
    dpkg-deb --root-owner-group --build "$d" "$work/$v.deb" >/dev/null
  done
  expect 0 '.deb passes' 'OK: every artifact' -- "$good_sha" "$work/good.deb"
  expect 1 '.deb with rewritten xray fails' 'v1.4.40/v1.4.41' -- "$good_sha" "$work/bad.deb"
  expect 1 '.deb without THIRD-PARTY-NOTICES.txt fails' 'found 0' -- "$good_sha" "$work/nonotices.deb"
  expect 1 '.deb with resources/.gitkeep fails' 'usr/lib/BirdoVPN/resources/.gitkeep - a dotfile under resources/' -- "$good_sha" "$work/gitkeep.deb"
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
