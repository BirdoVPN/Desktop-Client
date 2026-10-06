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
#   scripts/ci/verify-bundled-xray.sh <expected-sha256> <artifact> [<artifact>...]
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
#      via option_env!, not just exported to a later step.
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

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

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

# check_tree <label> <root> <macos|linux>
# Applies checks 2-5 to an unpacked artifact tree.
check_tree() {
  local label="$1" root="$2" kind="$3"
  local xray_pattern bin_pattern
  case "$kind" in
    macos)
      xray_pattern='*/Contents/Resources/resources/xray'
      bin_pattern='*/Contents/MacOS/*'
      ;;
    linux)
      xray_pattern='*/usr/lib/*/resources/xray'
      bin_pattern='*/usr/bin/*'
      ;;
  esac

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
      check_tree "$label" "$(cd "$(dirname "$artifact")" && pwd)/$(basename "$artifact")" macos
      ;;
    *.app.tar.gz)
      if [ ! -f "$artifact" ]; then err "$label: not found"; continue; fi
      if ! tar -xzf "$artifact" -C "$dest"; then err "$label: tar could not extract it"; continue; fi
      collect "$dest" -mindepth 1 -maxdepth 1 -name '*.app' -type d
      if [ "${#found[@]}" -ne 1 ]; then err "$label: expected exactly one top-level .app, found ${#found[@]}"; continue; fi
      check_tree "$label" "$dest" macos
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
      check_tree "$label" "$dest/mnt" macos
      ;;
    *.deb)
      if [ ! -f "$artifact" ]; then err "$label: not found"; continue; fi
      if ! dpkg-deb -x "$artifact" "$dest"; then err "$label: dpkg-deb could not extract it"; continue; fi
      check_tree "$label" "$dest" linux
      ;;
    *.AppImage)
      if [ ! -f "$artifact" ]; then err "$label: not found"; continue; fi
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
      check_tree "$label" "$dest/squashfs-root" linux
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
echo "OK: every artifact ($n) ships an executable resources/xray matching the compiled-in XRAY_BINARY_SHA256 ($expected_lc)"
