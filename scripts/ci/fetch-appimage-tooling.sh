#!/usr/bin/env bash
# ============================================================================
# Pins what Tauri's AppImage bundler would otherwise download unpinned
# (owner decision 2026-10-14, L2, review rounds 1-2 of #298):
#
#  * the AppImage runtime: linuxdeploy-plugin-appimage's appimagetool fetches
#    whatever type2-runtime's moving `continuous` build is that day, unless it
#    is given one (LDAI_RUNTIME_FILE -> appimagetool --runtime-file). The pin
#    is the build BirdoVPN 1.4.46 shipped (type2-runtime 8f39b89). This takes
#    it from type2-runtime's continuous release while that still serves those
#    bytes, and otherwise rebuilds it from 1.4.46's own release asset (its
#    first bytes, with the .digest_md5 section appimagetool fills in set back
#    to zero). Either way it must hash to the pin, or this fails. Exports
#    LDAI_RUNTIME_FILE (and APPIMAGE_RUNTIME_FILE, for the notices step).
#  * AppRun: Tauri copies AppRun-x86_64 from its tool cache, downloading it
#    only when the cache has none. This puts the pinned bytes there first.
#
#   bash scripts/ci/fetch-appimage-tooling.sh <out dir>
#   APPIMAGE_RUNTIME_FROM_FALLBACK=1 ...   take the runtime from 1.4.46's
#                                          AppImage even if continuous serves it
#
# Pins: third_party/licenses/appimage-runtime.json (read with node). The
# variables go to $GITHUB_ENV when set (CI), else are printed as `export`
# lines. Run before `tauri build` by release.yml's build-linux and
# linux-packages.yml (which also proves the fallback); scripts/generate-
# appimage-notices.mjs then checks the AppImage really carries exactly this
# runtime and this AppRun. curl, dd and sha256sum only.
# ============================================================================
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "::error::usage: $0 <out dir>"
  exit 2
fi
out="$1"
pins=third_party/licenses/appimage-runtime.json
pin() { node -e 'const p = require(require("path").resolve(process.argv[1])); console.log(process.argv[2].split(".").reduce((o, k) => o[k], p))' "$pins" "$1"; }

# download <url> <file>: only from the pinned release pages.
download() {
  case "$1" in
    https://github.com/AppImage/type2-runtime/releases/download/* | \
      https://github.com/tauri-apps/binary-releases/releases/download/* | \
      https://github.com/BirdoVPN/Desktop-Client/releases/download/*) ;;
    *)
      echo "::error::refusing to fetch $1: not a pinned AppImage tooling URL"
      exit 1
      ;;
  esac
  mkdir -p "$(dirname "$2")"
  curl -fsSL --retry 3 "$1" -o "$2"
}
sha_of() { sha256sum "$1" | cut -d' ' -f1; }
# install <file> <sha256> <dest>: the file becomes <dest> only if it hashes to the pin.
install_pinned() {
  if [ "$(sha_of "$1")" != "$2" ]; then
    echo "::error::$1: SHA-256 $(sha_of "$1"), pinned $2 ($pins)"
    exit 1
  fi
  mv "$1" "$3"
  chmod 0755 "$3"
}

mkdir -p "$out"
dir="$(cd "$out" && pwd)"
runtime="$dir/runtime-x86_64"
want="$(pin runtime.sha256)"
from=""
if [ -z "${APPIMAGE_RUNTIME_FROM_FALLBACK:-}" ]; then
  if download "$(pin runtime.url)" "$runtime.part" && [ "$(sha_of "$runtime.part")" = "$want" ]; then
    from="$(pin runtime.url)"
  else
    echo "::notice::$(pin runtime.url) no longer serves the pinned runtime ($want) - rebuilding it from $(pin runtime.fallback.url)"
  fi
fi
if [ -z "$from" ]; then
  download "$(pin runtime.fallback.url)" "$dir/fallback.AppImage"
  if [ "$(sha_of "$dir/fallback.AppImage")" != "$(pin runtime.fallback.sha256)" ]; then
    echo "::error::$(pin runtime.fallback.url): SHA-256 $(sha_of "$dir/fallback.AppImage"), pinned $(pin runtime.fallback.sha256)"
    exit 1
  fi
  head -c "$(pin runtime.fallback.bytes)" "$dir/fallback.AppImage" >"$runtime.part"
  dd if=/dev/zero of="$runtime.part" bs=1 seek="$(pin runtime.fallback.zero.0)" count="$(pin runtime.fallback.zero.1)" conv=notrunc status=none
  rm -f "$dir/fallback.AppImage"
  from="$(pin runtime.fallback.url) (its runtime, .digest_md5 zeroed)"
fi
install_pinned "$runtime.part" "$want" "$runtime"
echo "verified the runtime from $from ($want)"

# Tauri's tool cache: dirs::cache_dir()/tauri, i.e. $XDG_CACHE_HOME or ~/.cache.
apprun="${XDG_CACHE_HOME:-$HOME/.cache}/tauri/AppRun-x86_64"
download "$(pin apprun.url)" "$apprun.part"
install_pinned "$apprun.part" "$(pin apprun.sha256)" "$apprun"
echo "verified $(pin apprun.url) ($(pin apprun.sha256))"

if [ -n "${GITHUB_ENV:-}" ]; then
  printf 'LDAI_RUNTIME_FILE=%s\nAPPIMAGE_RUNTIME_FILE=%s\n' "$runtime" "$runtime" >>"$GITHUB_ENV"
else
  printf 'export LDAI_RUNTIME_FILE=%s\nexport APPIMAGE_RUNTIME_FILE=%s\n' "$runtime" "$runtime"
fi
echo "AppImage runtime: type2-runtime $(pin runtime.release) ($(pin runtime.commit)) at $runtime; AppRun at $apprun"
