#!/usr/bin/env bash
# ============================================================================
# Post-bundle gate (macOS + Linux): the xray INSIDE each shipped package must
# hash to the value the app was compiled with (XRAY_BINARY_SHA256), and the
# app's main binary must actually carry that value.
#
# WHY THIS EXISTS (register MR-720 / MR-736): release.yml has gated the
# Windows installer since F4 (scripts/ci/verify-bundled-xray-hash.ps1), but
# the macOS and Linux packages were never inspected after bundling. A bundle
# that dropped resources/xray, or a step that rewrote it after the hash was
# captured (codesign, strip, a bundler change - the v1.4.40/v1.4.41 Windows
# defect), shipped silently: xray.rs verify_xray_integrity() then refuses
# the binary on every stealth connect, on every machine.
#
# Usage:
#   NOTICES_FILE=src-tauri/resources/THIRD-PARTY-NOTICES.txt \
#   APPIMAGE_NOTICES_FILE=<the AppImage's own notices, needed with an .AppImage> \
#     scripts/ci/verify-bundled-xray.sh <expected-sha256> <artifact> [<artifact>...]
#
# Artifact kinds, chosen by name:
#   *.app         macOS bundle dir  -> Contents/Resources/resources/xray
#   *.app.tar.gz  macOS updater tar -> one *.app inside, as above
#   *.dmg         macOS disk image  -> one *.app at the volume root (hdiutil)
#   *.deb         Debian package    -> usr/lib/<product>/resources/xray (dpkg-deb)
#   *.AppImage    AppImage          -> same layout (the runtime's --appimage-extract)
# These are the paths src-tauri/src/vpn/xray.rs find_xray_binary() probes.
#
# For EVERY artifact all of these must hold, or the script exits 1 with a
# ::error:: line per failure (all artifacts are checked before exiting):
#   1. <expected-sha256> is 64 hex chars (empty = GITHUB_ENV was never set);
#   2. exactly one xray at the shipped path (none = no stealth engine,
#      several = ambiguous);
#   3. it is an executable regular file (xray.rs execs it);
#   4. its SHA-256 equals <expected-sha256>;
#   5. a file in the app's binary dir (Contents/MacOS, usr/bin) contains the
#      exact <expected-sha256> string - i.e. the value really was compiled in
#      via option_env!, not just exported to a later step;
#   6. no dotfile anywhere under resources/. bundle.resources is the glob
#      "resources/*", which matches dotfiles: v1.4.46's .deb carried
#      usr/lib/BirdoVPN/resources/.gitkeep (#256). The build jobs now delete
#      the tracked src-tauri/resources/.gitkeep before bundling; this proves
#      they did. (The Windows twin: nsis-install-smoke.ps1.)
#   7. exactly one resources/THIRD-PARTY-NOTICES.txt, a regular file
#      byte-identical to the file NOTICES_FILE names - the notices this
#      build generated (scripts/generate-third-party-notices.mjs). MR-1685:
#      every package ships Xray-core's and the GPL modules' licences, the
#      Xray source pointer and every crate's and npm package's licence, and
#      Settings › About › Licences reads this file. NOTICES_FILE is required:
#      unset, empty or missing fails before any artifact is opened.
#      An AppImage's file is instead byte-identical to APPIMAGE_NOTICES_FILE:
#      the same notices plus the sections listing the system libraries that
#      only the AppImage bundles (scripts/ci/appimage-notices.sh; owner
#      decision 2026-10-14, L2). Unset, empty or missing fails that AppImage.
#   8. (AppImage only) EVERY regular file in it - libraries, modules,
#      WebKitGTK's helpers, typelibs, schemas, AppRun, AppRun.wrapped, the
#      hooks, BirdoVPN's own - is listed, as a line "    <path>", in those
#      notices: a file the bundler added after the notices were generated
#      fails the release instead of shipping unlisted (review round 1 of #298).
#   9. (AppImage only) its runtime is the one those notices name: the commit
#      in their "AppImage type2-runtime ... - commit <sha> -" line is the one
#      the runtime reports (--appimage-version).
#  10. (AppImage only) those notices begin with the generic notices
#      (NOTICES_FILE), byte for byte: the AppImage adds sections, it does not
#      ship different ones.
#
# Self-test: scripts/ci/verify-bundled-xray.tests.sh (tests.yml runs it on
# Linux and macOS on every PR), with fixtures for each failure path.
# ============================================================================
set -euo pipefail

fail_count=0
err() {
  echo "::error::verify-bundled-xray: $*"
  fail_count=$((fail_count + 1))
}

if [ "$#" -lt 2 ]; then
  echo "::error::usage: $0 <expected-sha256> <artifact> [<artifact>...]"
  exit 2
fi

expected="$1"
shift
if ! printf '%s' "$expected" | grep -qE '^[0-9a-fA-F]{64}$'; then
  echo "::error::verify-bundled-xray: expected SHA-256 is not 64 hex chars (got '$expected'). An empty value means the build never captured XRAY_BINARY_SHA256 - the app would refuse xray at runtime."
  exit 1
fi
expected_lc="$(printf '%s' "$expected" | tr 'A-F' 'a-f')"
notices="${NOTICES_FILE:-}"
appimage_notices="${APPIMAGE_NOTICES_FILE:-}"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

if [ -z "$notices" ] || [ ! -s "$notices" ]; then
  echo "::error::verify-bundled-xray: NOTICES_FILE must name this build's generated THIRD-PARTY-NOTICES.txt (got '$notices') - without it no package can be checked for its third-party notices (MR-1685)"
  exit 1
fi

work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/xray-gate.XXXXXX")"
mounts=()
cleanup() {
  local m
  for m in "${mounts[@]+"${mounts[@]}"}"; do
    hdiutil detach -quiet "$m" >/dev/null 2>&1 || hdiutil detach -force -quiet "$m" >/dev/null 2>&1 || true
  done
  rm -rf "$work"
}
trap cleanup EXIT

# Collect the paths matching a find expression under a root into the global
# array `found` (bash 3.2 on macOS has no mapfile).
collect() {
  local root="$1"
  shift
  found=()
  local f
  while IFS= read -r f; do
    found+=("$f")
  done < <(find "$root" "$@" 2>/dev/null | LC_ALL=C sort)
}

# check_tree <label> <root> <macos|linux> <expected notices file>
# Applies checks 2-7 to an unpacked artifact tree.
check_tree() {
  local label="$1" root="$2" kind="$3" want_notices="$4"
  local want_sha
  want_sha="$(sha256_of "$want_notices")"
  local xray_pattern bin_pattern resources_pattern notices_pattern
  case "$kind" in
    macos)
      xray_pattern='*/Contents/Resources/resources/xray'
      bin_pattern='*/Contents/MacOS/*'
      resources_pattern='*/Contents/Resources/resources/*'
      notices_pattern='*/Contents/Resources/resources/THIRD-PARTY-NOTICES.txt'
      ;;
    linux)
      xray_pattern='*/usr/lib/*/resources/xray'
      bin_pattern='*/usr/bin/*'
      resources_pattern='*/usr/lib/*/resources/*'
      notices_pattern='*/usr/lib/*/resources/THIRD-PARTY-NOTICES.txt'
      ;;
  esac

  # Check 7, also before the early returns below.
  collect "$root" -path "$notices_pattern" ! -type d
  if [ "${#found[@]}" -ne 1 ]; then
    err "$label: expected one resources/THIRD-PARTY-NOTICES.txt, found ${#found[@]} - the package would ship without its third-party licence notices (MR-1685)"
  elif [ -L "${found[0]}" ] || [ ! -f "${found[0]}" ]; then
    err "$label: ${found[0]#"$root"/} is not a regular file"
  elif [ "$(sha256_of "${found[0]}")" != "$want_sha" ]; then
    err "$label: the bundled THIRD-PARTY-NOTICES.txt is not the file this build generated ($want_notices)"
  else
    echo "  notices  : ${found[0]#"$root"/} is this build's ($want_notices, $want_sha)"
  fi

  # Check 6 first: the checks below return early on a missing xray.
  collect "$root" -path "$resources_pattern" -name '.*'
  local dot
  for dot in "${found[@]+"${found[@]}"}"; do
    err "$label: ${dot#"$root"/} - a dotfile under resources/ ships in the package (bundle.resources' \"resources/*\" glob matches dotfiles; delete it before bundling, as the build jobs do src-tauri/resources/.gitkeep)"
  done

  collect "$root" -path "$xray_pattern" ! -type d
  if [ "${#found[@]}" -eq 0 ]; then
    err "$label: no resources/xray at the shipped path ($xray_pattern) - the package ships no stealth engine"
    return 0
  fi
  if [ "${#found[@]}" -gt 1 ]; then
    err "$label: ambiguous - ${#found[@]} resources/xray members: ${found[*]}"
    return 0
  fi
  local xray="${found[0]}"
  if [ -L "$xray" ] || [ ! -f "$xray" ]; then
    err "$label: $xray is not a regular file"
    return 0
  fi
  if [ ! -x "$xray" ]; then
    err "$label: $xray is not executable - xray.rs could not exec it"
  fi

  local actual
  actual="$(sha256_of "$xray")"
  echo "  xray     : ${xray#"$root"/} ($(wc -c <"$xray" | tr -d ' ') bytes)"
  echo "  expected : $expected_lc"
  echo "  actual   : $actual"
  if [ "$actual" != "$expected_lc" ]; then
    err "$label: bundled xray hash $actual != compiled-in XRAY_BINARY_SHA256 $expected_lc. The app's integrity check would refuse this xray on every stealth connect (the v1.4.40/v1.4.41 defect: something rewrote xray after the hash was captured)."
  fi

  collect "$root" -path "$bin_pattern" -type f
  if [ "${#found[@]}" -eq 0 ]; then
    err "$label: no app binary at $bin_pattern"
    return 0
  fi
  local bin carrier=""
  for bin in "${found[@]}"; do
    if LC_ALL=C grep -aqF "$expected_lc" "$bin"; then
      carrier="$bin"
      break
    fi
  done
  if [ -z "$carrier" ]; then
    err "$label: no binary under $bin_pattern contains $expected_lc - XRAY_BINARY_SHA256 was not compiled into the app (option_env! saw a different or empty value)"
  else
    echo "  compiled : ${carrier#"$root"/} carries the expected hash"
  fi
}

# check_appimage_contents <label> <AppImage> <root> <notices file>
# Checks 8-10 on an AppImage unpacked at <root>.
check_appimage_contents() {
  local label="$1" appimage="$2" root="$3" list="$4"
  local f rel total=0 missing=0
  # Check 8: every regular file, wherever it is.
  collect "$root" -type f
  for f in "${found[@]+"${found[@]}"}"; do
    total=$((total + 1))
    rel="${f#"$root"/}"
    if ! grep -qxF -- "    $rel" "$list"; then
      missing=$((missing + 1))
      err "$label: $rel is in the AppImage but not listed in its notices ($list) - every file the AppImage carries must be listed with its source and licence (owner decision 2026-10-14, L2)"
    fi
  done
  if [ "$missing" -eq 0 ]; then
    echo "  files    : all $total files in it are listed in its notices"
  fi
  # Check 9: the runtime.
  local commit reported
  commit="$(sed -nE 's/^  AppImage type2-runtime .* - commit ([0-9a-f]{40}) - .*$/\1/p' "$list")"
  if [ "$(printf '%s\n' "$commit" | grep -c .)" -ne 1 ]; then
    err "$label: its notices name no AppImage runtime (one '  AppImage type2-runtime ... - commit <sha> -' line) - the runtime at the start of the file would ship unlisted"
  else
    reported="$("$appimage" --appimage-version 2>&1 || true)"
    if printf '%s' "$reported" | grep -qF "/commit/${commit:0:7}"; then
      echo "  runtime  : type2-runtime ${commit:0:7}, as its notices say"
    else
      err "$label: its runtime reports '$reported', its notices name type2-runtime $commit - the bundler used another runtime (LDAI_RUNTIME_FILE, scripts/ci/fetch-appimage-tooling.sh)"
    fi
  fi
  # Check 10: the generic notices first, then the AppImage's sections.
  if ! head -c "$(wc -c <"$notices" | tr -d ' ')" "$list" | cmp -s - "$notices"; then
    err "$label: its notices ($list) do not begin with the generic notices ($notices) byte for byte"
  fi
}

n=0
for artifact in "$@"; do
  n=$((n + 1))
  label="$(basename "$artifact")"
  echo "== $label"
  dest="$work/$n"
  mkdir -p "$dest"
  case "$artifact" in
    *.app)
      if [ ! -d "$artifact" ]; then err "$label: not found (expected an .app directory)"; continue; fi
      check_tree "$label" "$(cd "$(dirname "$artifact")" && pwd)/$(basename "$artifact")" macos "$notices"
      ;;
    *.app.tar.gz)
      if [ ! -f "$artifact" ]; then err "$label: not found"; continue; fi
      if ! tar -xzf "$artifact" -C "$dest"; then err "$label: tar could not extract it"; continue; fi
      collect "$dest" -mindepth 1 -maxdepth 1 -name '*.app' -type d
      if [ "${#found[@]}" -ne 1 ]; then err "$label: expected exactly one top-level .app, found ${#found[@]}"; continue; fi
      check_tree "$label" "$dest" macos "$notices"
      ;;
    *.dmg)
      if [ ! -f "$artifact" ]; then err "$label: not found"; continue; fi
      if ! command -v hdiutil >/dev/null 2>&1; then err "$label: hdiutil not available - a .dmg can only be gated on macOS"; continue; fi
      mkdir -p "$dest/mnt"
      # Bounded retry: a transient "Resource busy" from hdiutil (seen right
      # after a DMG is written) must not block a release. A DMG that cannot
      # be mounted at all still fails after the third attempt.
      attached=false
      for attempt in 1 2 3; do
        if hdiutil attach -nobrowse -readonly -noautoopen -mountpoint "$dest/mnt" "$artifact" >/dev/null; then
          attached=true
          break
        fi
        if [ "$attempt" -lt 3 ]; then
          echo "  hdiutil attach failed (attempt $attempt/3); retrying in $((attempt * 5))s"
          sleep $((attempt * 5))
        fi
      done
      if [ "$attached" != true ]; then
        err "$label: hdiutil attach failed (3 attempts)"
        continue
      fi
      mounts+=("$dest/mnt")
      collect "$dest/mnt" -mindepth 1 -maxdepth 1 -name '*.app' -type d
      if [ "${#found[@]}" -ne 1 ]; then err "$label: expected exactly one .app at the volume root, found ${#found[@]}"; continue; fi
      check_tree "$label" "$dest/mnt" macos "$notices"
      ;;
    *.deb)
      if [ ! -f "$artifact" ]; then err "$label: not found"; continue; fi
      if ! dpkg-deb -x "$artifact" "$dest"; then err "$label: dpkg-deb could not extract it"; continue; fi
      check_tree "$label" "$dest" linux "$notices"
      ;;
    *.AppImage)
      if [ ! -f "$artifact" ]; then err "$label: not found"; continue; fi
      if [ -z "$appimage_notices" ] || [ ! -s "$appimage_notices" ]; then
        err "$label: APPIMAGE_NOTICES_FILE must name the AppImage's own generated notices, with its bundled libraries (scripts/ci/appimage-notices.sh) - got '$appimage_notices'"
        continue
      fi
      abs="$(cd "$(dirname "$artifact")" && pwd)/$(basename "$artifact")"
      if [ ! -x "$abs" ]; then
        # Never change the mode of the file we ship; run a copy instead.
        cp "$abs" "$dest/runtime.AppImage"
        chmod +x "$dest/runtime.AppImage"
        abs="$dest/runtime.AppImage"
      fi
      # The AppImage runtime (static, no FUSE needed for extraction) unpacks
      # its own squashfs into ./squashfs-root.
      if ! (cd "$dest" && "$abs" --appimage-extract >/dev/null); then err "$label: --appimage-extract failed"; continue; fi
      check_tree "$label" "$dest/squashfs-root" linux "$appimage_notices"
      check_appimage_contents "$label" "$abs" "$dest/squashfs-root" "$appimage_notices"
      ;;
    *)
      err "$label: unknown artifact kind (expected .app, .app.tar.gz, .dmg, .deb or .AppImage)"
      ;;
  esac
done

if [ "$fail_count" -gt 0 ]; then
  echo "verify-bundled-xray: $fail_count failure(s) across $n artifact(s)"
  exit 1
fi
echo "OK: every artifact ($n) ships an executable resources/xray matching the compiled-in XRAY_BINARY_SHA256 ($expected_lc), this build's resources/THIRD-PARTY-NOTICES.txt (an AppImage: its own, listing every library it bundles), and no dotfile under resources/"
