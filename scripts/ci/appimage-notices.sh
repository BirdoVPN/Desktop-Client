#!/usr/bin/env bash
# ============================================================================
# The AppImage's own THIRD-PARTY-NOTICES.txt (owner decision 2026-10-14, L2:
# list the system libraries it bundles in its notices).
#
# Usage, from the repo root, after `tauri build` made the .deb and AppImage:
#   bash scripts/ci/appimage-notices.sh <rust target> <out file> [tauri bundle args...]
#
#  1. unpacks the AppImage `tauri build` just made (its runtime's
#     --appimage-extract, as the post-bundle gate does);
#  2. scripts/generate-appimage-notices.mjs writes <out file>: this build's
#     notices (src-tauri/resources/THIRD-PARTY-NOTICES.txt, which the .deb
#     keeps) plus the AppImage-only sections: every library in that AppImage,
#     its Ubuntu package, source package and version, copyright file and
#     cited licence texts;
#  3. re-bundles ONLY the AppImage with <out file> as resources/THIRD-PARTY-
#     NOTICES.txt: `tauri bundle --bundles appimage` (nothing is recompiled:
#     same app binary, same xray; the updater .sig is made again, so the old
#     pair is deleted first and a stale .sig cannot survive), then puts the
#     generic file back for the .deb's gate.
# Which libraries linuxdeploy bundles is only known once it has run, hence
# the second bundle. The post-bundle gate (verify-bundled-xray.sh with
# APPIMAGE_NOTICES_FILE=<out file>) then checks the FINAL AppImage: its
# notices must be <out file> byte for byte, and every ELF file in it must be
# listed there. [tauri bundle args]: what the build passed, e.g. --config.
# ============================================================================
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "::error::usage: $0 <rust target> <out file> [tauri bundle args...]"
  exit 2
fi
target="$1"
out="$2"
shift 2
generic=src-tauri/resources/THIRD-PARTY-NOTICES.txt
dir="src-tauri/target/$target/release/bundle/appimage"
if [ ! -s "$generic" ]; then
  echo "::error::$generic is missing - generate this build's notices before tauri build"
  exit 1
fi

shopt -s nullglob
appimages=("$dir"/*.AppImage)
if [ "${#appimages[@]}" -ne 1 ]; then
  echo "::error::expected one AppImage in $dir, found ${#appimages[@]}"
  exit 1
fi
appimage="${appimages[0]}"

work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/appimage-notices.XXXXXX")"
saved="$work/THIRD-PARTY-NOTICES.generic.txt"
cp "$generic" "$saved"
restore() {
  cp "$saved" "$generic"
  rm -rf "$work"
}
trap restore EXIT

# Run a copy: never change the mode of a file that ships.
cp "$appimage" "$work/built.AppImage"
chmod +x "$work/built.AppImage"
(cd "$work" && ./built.AppImage --appimage-extract >/dev/null)
node scripts/generate-appimage-notices.mjs --appdir "$work/squashfs-root" --base "$generic" --out "$out"

had_sig=false
if [ -f "$appimage.sig" ]; then had_sig=true; fi
cp "$out" "$generic"
rm -f "$appimage" "$appimage.sig"
npx tauri bundle --bundles appimage --target "$target" "$@"
cp "$saved" "$generic"

appimages=("$dir"/*.AppImage)
if [ "${#appimages[@]}" -ne 1 ]; then
  echo "::error::the re-bundle left ${#appimages[@]} AppImages in $dir"
  exit 1
fi
if [ "$had_sig" = true ] && [ ! -s "${appimages[0]}.sig" ]; then
  echo "::error::the first bundle had an updater signature and the re-bundle made none: ${appimages[0]}.sig"
  exit 1
fi
echo "Re-bundled ${appimages[0]} with its own notices: $out"
