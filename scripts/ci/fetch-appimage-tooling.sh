#!/usr/bin/env bash
# ============================================================================
# Pins what Tauri's AppImage bundler would otherwise download unpinned
# (owner decision 2026-10-14, L2, review round 1 of #298):
#
#  * the AppImage runtime: linuxdeploy-plugin-appimage's appimagetool fetches
#    type2-runtime's moving `continuous` build on every run unless it is given
#    one (LDAI_RUNTIME_FILE -> appimagetool --runtime-file). This downloads the
#    pinned release's runtime-x86_64, refuses any other bytes, and exports
#    LDAI_RUNTIME_FILE (and APPIMAGE_RUNTIME_FILE, for the notices step).
#  * AppRun: Tauri copies AppRun-x86_64 from its tool cache, downloading it
#    only when the cache has none. This puts the pinned bytes there first.
#
#   bash scripts/ci/fetch-appimage-tooling.sh <out dir>
#
# Pins: third_party/licenses/appimage-runtime.json (read with node). The
# variables go to $GITHUB_ENV when set (CI), else are printed as `export`
# lines. Run before `tauri build` by release.yml's build-linux and
# linux-packages.yml; scripts/generate-appimage-notices.mjs then checks the
# AppImage really carries exactly this runtime and this AppRun. curl and
# sha256sum only.
# ============================================================================
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "::error::usage: $0 <out dir>"
  exit 2
fi
out="$1"
pins=third_party/licenses/appimage-runtime.json
pin() { node -e 'const p = require(require("path").resolve(process.argv[1])); console.log(process.argv[2].split(".").reduce((o, k) => o[k], p))' "$pins" "$1"; }

# fetch <url> <sha256> <file>: only from the two pinned release pages.
fetch() {
  case "$1" in
    https://github.com/AppImage/type2-runtime/releases/download/* | https://github.com/tauri-apps/binary-releases/releases/download/*) ;;
    *)
      echo "::error::refusing to fetch $1: not a pinned AppImage tooling URL"
      exit 1
      ;;
  esac
  mkdir -p "$(dirname "$3")"
  curl -fsSL --retry 3 "$1" -o "$3.part"
  if ! echo "$2  $3.part" | sha256sum -c - >/dev/null; then
    echo "::error::$1: SHA-256 $(sha256sum "$3.part" | cut -d' ' -f1), pinned $2 ($pins)"
    rm -f "$3.part"
    exit 1
  fi
  mv "$3.part" "$3"
  chmod 0755 "$3"
  echo "verified $1 ($2)"
}

runtime="$(cd "$(dirname "$out")" && pwd)/$(basename "$out")/runtime-x86_64"
fetch "$(pin runtime.url)" "$(pin runtime.sha256)" "$runtime"
# Tauri's tool cache: dirs::cache_dir()/tauri, i.e. $XDG_CACHE_HOME or ~/.cache.
apprun="${XDG_CACHE_HOME:-$HOME/.cache}/tauri/AppRun-x86_64"
fetch "$(pin apprun.url)" "$(pin apprun.sha256)" "$apprun"

if [ -n "${GITHUB_ENV:-}" ]; then
  printf 'LDAI_RUNTIME_FILE=%s\nAPPIMAGE_RUNTIME_FILE=%s\n' "$runtime" "$runtime" >>"$GITHUB_ENV"
else
  printf 'export LDAI_RUNTIME_FILE=%s\nexport APPIMAGE_RUNTIME_FILE=%s\n' "$runtime" "$runtime"
fi
echo "AppImage runtime: type2-runtime $(pin runtime.release) ($(pin runtime.commit)) at $runtime; AppRun at $apprun"
