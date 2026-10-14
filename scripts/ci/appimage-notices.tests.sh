#!/usr/bin/env bash
# ============================================================================
# Self-test for scripts/generate-appimage-notices.mjs (owner decision
# 2026-10-14, L2: the AppImage lists everything it carries; review round 1 of
# #298) and its agreement with the post-bundle gate (scripts/ci/verify-
# bundled-xray.sh, checks 8-10), with no AppImage build and no WebKitGTK.
#
# A fake build host (a directory with usr/, a usrmerge lib -> usr/lib link,
# /usr/share/doc and /usr/share/common-licenses), a fake dpkg and dpkg-query
# on PATH answering from a small package database, a fake runtime ELF with
# the sections appimagetool fills in, and a fake unpacked AppImage:
#
#   pass   flattened usr/lib/<soname>; an unversioned libfoo.so copy, which is
#          credited to the runtime package that ships the real file, not the
#          -dev package that ships the link; a library registered under
#          /lib/<triplet> (usrmerge); a GTK module below its multiarch dir,
#          with a GTK 2 file of the same name as a decoy; WebKitGTK's helper;
#          a soname link no package ships (resolved on the host); a typelib, a
#          GSettings schema and a copyright file by their packages; BirdoVPN's
#          own files; AppRun.wrapped, AppRun and the GTK hook with their
#          licences; the generated caches; the runtime, its commit and the
#          libraries it links (libfuse's LGPL-2.1 in full); the base notices
#          kept byte for byte; a cited common licence (and a cited GPL-2.0 as
#          Debian's GPL-2) in full; identical copyright files printed once;
#          DEP-5 licence names; deterministic output; the gate passes an
#          AppImage carrying the result, and fails it once a file the notices
#          do not list is added
#   fail   a file no package owns; a file two packages own; a package with no
#          copyright file; a cited common licence missing on the host; base
#          notices that already have the AppImage section; a directory that
#          is not an unpacked AppImage; an AppImage whose runtime is not the
#          pinned one (outside the sections appimagetool fills in); a runtime
#          file that is not the pinned one; an AppRun.wrapped that is not the
#          pinned AppRun
#
# tests.yml runs it on Linux on every PR. The real mapping runs on the
# ubuntu-22.04 build in linux-packages.yml (PRs) and release.yml.
# ============================================================================
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
gen="$repo/scripts/generate-appimage-notices.mjs"
gate="$here/verify-bundled-xray.sh"
work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/appimage-notices-selftest.XXXXXX")"
trap 'rm -rf "$work"' EXIT

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# --- the fake dpkg ------------------------------------------------------------
mkdir -p "$work/bin"
cat >"$work/bin/dpkg" <<'EOF'
#!/usr/bin/env bash
# dpkg -S <path>... over $FAKE_DPKG_DB ("<package>: <path>" lines). As
# dpkg, an unmatched path exits 1.
[ "${1-}" = -S ] || { echo "fake dpkg: only -S" >&2; exit 2; }
shift
rc=0
for pat in "$@"; do
  hit=0
  while IFS= read -r line; do
    p="${line#*: }"
    # shellcheck disable=SC2254 # the pattern is meant to glob, as dpkg's do
    case "$p" in $pat) echo "$line"; hit=1 ;; esac
  done <"$FAKE_DPKG_DB"
  if [ "$hit" -eq 0 ]; then echo "dpkg-query: no path found matching pattern $pat" >&2; rc=1; fi
done
exit "$rc"
EOF
cat >"$work/bin/dpkg-query" <<'EOF'
#!/usr/bin/env bash
# dpkg-query -W -f=<format> <package>...: the package's line from
# $FAKE_DPKG_PACKAGES, already in the generator's field order.
[ "${1-}" = -W ] || { echo "fake dpkg-query: only -W" >&2; exit 2; }
shift 2
rc=0
for q in "$@"; do
  if ! awk -F '\t' -v q="$q" 'BEGIN { s = 1 } $1 == q { print; s = 0 } END { exit s }' "$FAKE_DPKG_PACKAGES"; then
    echo "dpkg-query: no packages found matching $q" >&2
    rc=1
  fi
done
exit "$rc"
EOF
chmod +x "$work/bin/dpkg" "$work/bin/dpkg-query"
export PATH="$work/bin:$PATH"

# --- the fake build host ------------------------------------------------------
H="$work/host"
T=x86_64-linux-gnu
mkdir -p "$H/usr/lib/$T/gtk-3.0/3.0.0/immodules" "$H/usr/lib/$T/gtk-2.0/2.10.0/immodules" \
  "$H/usr/lib/$T/webkit2gtk-4.1" "$H/usr/lib/$T/girepository-1.0" "$H/usr/share/glib-2.0/schemas" \
  "$H/usr/share/doc" "$H/usr/share/common-licenses"
ln -s usr/lib "$H/lib" # usrmerge
hostfile() { mkdir -p "$(dirname "$H/$1")" && printf 'host file %s\n' "$1" >"$H/$1"; }
hostfile "usr/lib/$T/libgtk-3.so.0.2404.29"
ln -s libgtk-3.so.0.2404.29 "$H/usr/lib/$T/libgtk-3.so.0"
ln -s libgtk-3.so.0 "$H/usr/lib/$T/libgtk-3.so" # what libgtk-3-dev ships
hostfile "usr/lib/$T/gtk-3.0/3.0.0/immodules/im-thai.so"
hostfile "usr/lib/$T/gtk-2.0/2.10.0/immodules/im-thai.so"
hostfile "usr/lib/$T/libz.so.1.2.11"
ln -s libz.so.1.2.11 "$H/usr/lib/$T/libz.so.1"
hostfile "usr/lib/$T/webkit2gtk-4.1/WebKitWebProcess"
hostfile "usr/lib/$T/libsoname.so.3.0.1"
ln -s libsoname.so.3.0.1 "$H/usr/lib/$T/libsoname.so.3" # made by ldconfig, in no package
hostfile "usr/lib/$T/girepository-1.0/Gtk-3.0.typelib"
hostfile "usr/share/glib-2.0/schemas/org.gtk.Settings.FileChooser.gschema.xml"

db="$work/dpkg.db"
cat >"$db" <<EOF
libgtk-3-0:amd64: /usr/lib/$T/libgtk-3.so.0.2404.29
libgtk-3-0:amd64: /usr/lib/$T/libgtk-3.so.0
libgtk-3-dev:amd64: /usr/lib/$T/libgtk-3.so
libgtk-3-0:amd64: /usr/lib/$T/gtk-3.0/3.0.0/immodules/im-thai.so
libgtk-3-0:amd64: /usr/share/doc/libgtk-3-0/copyright
libgtk2.0-0:amd64: /usr/lib/$T/gtk-2.0/2.10.0/immodules/im-thai.so
zlib1g:amd64: /lib/$T/libz.so.1.2.11
zlib1g:amd64: /lib/$T/libz.so.1
libwebkit2gtk-4.1-0:amd64: /usr/lib/$T/webkit2gtk-4.1/WebKitWebProcess
libsoname3:amd64: /usr/lib/$T/libsoname.so.3.0.1
gir1.2-gtk-3.0:amd64: /usr/lib/$T/girepository-1.0/Gtk-3.0.typelib
libgtk-3-common: /usr/share/glib-2.0/schemas/org.gtk.Settings.FileChooser.gschema.xml
EOF
export FAKE_DPKG_DB="$db"
pkgs="$work/packages.tsv"
printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
  'libgtk-3-0:amd64' libgtk-3-0 amd64 3.24.33-1ubuntu2.2 'gtk+3.0' 3.24.33-1ubuntu2.2 \
  'libgtk-3-dev:amd64' libgtk-3-dev amd64 3.24.33-1ubuntu2.2 'gtk+3.0' 3.24.33-1ubuntu2.2 \
  'libgtk-3-common' libgtk-3-common all 3.24.33-1ubuntu2.2 'gtk+3.0' 3.24.33-1ubuntu2.2 \
  'gir1.2-gtk-3.0:amd64' gir1.2-gtk-3.0 amd64 3.24.33-1ubuntu2.2 'gtk+3.0' 3.24.33-1ubuntu2.2 \
  'zlib1g:amd64' zlib1g amd64 1:1.2.11.dfsg-2ubuntu9.2 zlib 1:1.2.11.dfsg-2ubuntu9.2 \
  'libwebkit2gtk-4.1-0:amd64' libwebkit2gtk-4.1-0 amd64 2.48.7-0ubuntu0.22.04.1 webkit2gtk 2.48.7-0ubuntu0.22.04.1 \
  'libsoname3:amd64' libsoname3 amd64 3.0.1-1 soname-fixture 3.0.1-1 >"$pkgs"
export FAKE_DPKG_PACKAGES="$pkgs"

doc="$H/usr/share/doc"
licences="$H/usr/share/common-licenses"
for p in libgtk-3-0 libgtk-3-common gir1.2-gtk-3.0 zlib1g libwebkit2gtk-4.1-0 libsoname3; do mkdir -p "$doc/$p"; done
cat >"$doc/libgtk-3-0/copyright" <<'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: gtk+3.0

Files: *
Copyright: The GTK Team
License: LGPL-2+

License: LGPL-2+
 On Debian systems, the complete text of the GNU Library General Public
 License can be found in /usr/share/common-licenses/LGPL-2.
EOF
cp "$doc/libgtk-3-0/copyright" "$doc/libgtk-3-common/copyright"
cp "$doc/libgtk-3-0/copyright" "$doc/gir1.2-gtk-3.0/copyright"
printf 'zlib fixture copyright\r\n(C) 1995 Jean-loup Gailly and Mark Adler   \r\n' >"$doc/zlib1g/copyright"
cp "$doc/zlib1g/copyright" "$doc/libsoname3/copyright"
cat >"$doc/libwebkit2gtk-4.1-0/copyright" <<'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/

Files: *
Copyright: The WebKit authors
License: BSD-2-clause and LGPL-2.1+

License: LGPL-2.1+
 See /usr/share/common-licenses/LGPL-2.1.
 Parts: GPL-2+, see /usr/share/common-licenses/GPL-2.0 (sic, as pango's file).
EOF
printf 'FIXTURE LGPL-2 FULL TEXT\n' >"$licences/LGPL-2"
printf 'FIXTURE LGPL-2.1 FULL TEXT\n' >"$licences/LGPL-2.1"
printf 'FIXTURE GPL-2 FULL TEXT\n' >"$licences/GPL-2"
printf 'PRETTY_NAME="Ubuntu 22.04.5 LTS"\nNAME="Ubuntu"\n' >"$work/os-release"

# --- the fake runtime: an ELF64 with the sections appimagetool fills in -------
make_runtime() { # make_runtime <out> <code bytes>
  node -e '
    const fs = require("fs");
    const [out, code] = process.argv.slice(1);
    const names = ["", ".shstrtab", ".text", ".digest_md5", ".upd_info", ".sha256_sig"];
    const strtab = Buffer.from(names.join("\0") + "\0");
    const nameAt = {}; let o = 0;
    for (const n of names) { nameAt[n] = o; o += Buffer.byteLength(n) + 1; }
    const body = { ".text": Buffer.from(code), ".digest_md5": Buffer.alloc(16), ".upd_info": Buffer.alloc(32), ".sha256_sig": Buffer.alloc(32), ".shstrtab": strtab };
    const parts = [Buffer.alloc(64)]; let at = 64; const placed = {};
    for (const n of [".text", ".digest_md5", ".upd_info", ".sha256_sig", ".shstrtab"]) { placed[n] = [at, body[n].length]; parts.push(body[n]); at += body[n].length; }
    const shoff = at; const sh = Buffer.alloc(64 * names.length);
    names.forEach((n, i) => { if (!n) return; const b = i * 64; sh.writeUInt32LE(nameAt[n], b); sh.writeUInt32LE(1, b + 4);
      sh.writeBigUInt64LE(BigInt(placed[n][0]), b + 0x18); sh.writeBigUInt64LE(BigInt(placed[n][1]), b + 0x20); });
    const h = parts[0]; h.writeUInt32BE(0x7f454c46, 0); h[4] = 2; h[5] = 1; h[6] = 1;
    h.writeBigUInt64LE(BigInt(shoff), 0x28); h.writeUInt16LE(64, 0x34); h.writeUInt16LE(64, 0x3a);
    h.writeUInt16LE(names.length, 0x3c); h.writeUInt16LE(1, 0x3e);
    fs.writeFileSync(out, Buffer.concat([...parts, sh]));
  ' "$1" "$2"
}
runtime="$work/runtime-x86_64"
make_runtime "$runtime" 'fixture runtime code'
# What appimagetool makes of it: the digest section filled in, the squashfs after.
patch_bytes() { # patch_bytes <file> <offset> <bytes>
  node -e 'const fs = require("fs"); const [f, o, s] = process.argv.slice(1); const b = fs.readFileSync(f); b.write(s, Number(o), "latin1"); fs.writeFileSync(f, b);' "$@"
}
digest_at=$((64 + 20)) # the .digest_md5 section follows the 20-byte .text
appimage="$work/BirdoVPN.AppImage"
cp "$runtime" "$appimage"
patch_bytes "$appimage" "$digest_at" 'md5md5md5md5md5!'
printf 'hsqs fixture squashfs' >>"$appimage"

apprun_bytes="$work/AppRun-x86_64"
printf '\177ELF AppImageKit AppRun fixture' >"$apprun_bytes"
pins="$work/appimage-runtime.json"
node -e '
  const fs = require("fs");
  const [real, out, rtSha, apprunSha] = process.argv.slice(1);
  const p = JSON.parse(fs.readFileSync(real, "utf8"));
  p.runtime.sha256 = rtSha;
  p.apprun.sha256 = apprunSha;
  fs.writeFileSync(out, JSON.stringify(p, null, 2));
' "$repo/third_party/licenses/appimage-runtime.json" "$pins" "$(sha256_of "$runtime")" "$(sha256_of "$apprun_bytes")"
runtime_commit="$(node -p 'require(process.argv[1]).runtime.commit' "$pins")"

# --- the fake unpacked AppImage -----------------------------------------------
fake_elf() { mkdir -p "$(dirname "$1")" && printf '\177ELF\002\001\001\000%s' "${2-fixture}" >"$1"; }
appdir="$work/AppDir"
fake_elf "$appdir/usr/lib/BirdoVPN/resources/xray" 'xray payload'
chmod 755 "$appdir/usr/lib/BirdoVPN/resources/xray"
xray_sha="$(sha256_of "$appdir/usr/lib/BirdoVPN/resources/xray")"
fake_elf "$appdir/usr/bin/birdo-vpn-desktop" "option_env:$xray_sha"
chmod 755 "$appdir/usr/bin/birdo-vpn-desktop"
mkdir -p "$appdir/usr/share/applications" "$appdir/usr/share/icons/hicolor/32x32/apps" "$appdir/apprun-hooks"
printf '[Desktop Entry]\nName=BirdoVPN\n' >"$appdir/usr/share/applications/BirdoVPN.desktop"
printf 'png' >"$appdir/usr/share/icons/hicolor/32x32/apps/birdo-vpn-desktop.png"
printf 'png' >"$appdir/BirdoVPN.png"
ln -s BirdoVPN.png "$appdir/.DirIcon"
ln -s usr/share/applications/BirdoVPN.desktop "$appdir/BirdoVPN.desktop"
cp "$apprun_bytes" "$appdir/AppRun.wrapped"
printf '#! /usr/bin/env bash\n# autogenerated by linuxdeploy\n' >"$appdir/AppRun"
printf '# hook\n' >"$appdir/apprun-hooks/linuxdeploy-plugin-gtk.sh"
fake_elf "$appdir/usr/lib/libgtk-3.so.0"
fake_elf "$appdir/usr/lib/libgtk-3.so"
fake_elf "$appdir/usr/lib/libz.so.1"
fake_elf "$appdir/usr/lib/libsoname.so.3"
fake_elf "$appdir/usr/lib/gtk-3.0/3.0.0/immodules/im-thai.so"
ln -s gtk-3.0/3.0.0/immodules/im-thai.so "$appdir/usr/lib/im-thai.so"
fake_elf "$appdir/usr/lib/x86_64-linux-gnu/webkit2gtk-4.1/WebKitWebProcess"
mkdir -p "$appdir/usr/lib/girepository-1.0" "$appdir/usr/share/glib-2.0/schemas" "$appdir/usr/share/doc/libgtk-3-0" \
  "$appdir/usr/lib/gdk-pixbuf-2.0/2.10.0"
printf 'typelib\n' >"$appdir/usr/lib/girepository-1.0/Gtk-3.0.typelib"
printf '<schemalist/>\n' >"$appdir/usr/share/glib-2.0/schemas/org.gtk.Settings.FileChooser.gschema.xml"
printf 'compiled\n' >"$appdir/usr/share/glib-2.0/schemas/gschemas.compiled"
printf 'cache\n' >"$appdir/usr/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache"
cp "$doc/libgtk-3-0/copyright" "$appdir/usr/share/doc/libgtk-3-0/copyright"
base="$work/base-notices.txt"
printf 'THIRD-PARTY SOFTWARE NOTICES - fixture\n\n5. Licence texts (0)\n' >"$base"
cp "$base" "$appdir/usr/lib/BirdoVPN/resources/THIRD-PARTY-NOTICES.txt"

# --- assertions ---------------------------------------------------------------
failures=0
passes=0
ok() { passes=$((passes + 1)); echo "PASS  $1"; }
bad() { failures=$((failures + 1)); echo "FAIL  $1"; }
generate() { # generate <appdir> <base> <out> [more args]
  local a="$1" b="$2" o="$3"
  shift 3
  node "$gen" --appdir "$a" --appimage "$appimage" --runtime-file "$runtime" --runtime-pins "$pins" \
    --base "$b" --out "$o" --doc-root "$doc" --licenses-root "$licences" \
    --os-release "$work/os-release" --host-root "$H" --multiarch "$T" "$@"
}
expect_fail() { # expect_fail <case> <must-mention> <appdir> [more args]
  local c="$1" m="$2" a="$3" out code=0
  shift 3
  out="$(generate "$a" "$base" "$work/never.txt" "$@" 2>&1)" || code=$?
  if [ "$code" -eq 1 ] && printf '%s' "$out" | grep -qF -- "$m"; then ok "$c (exit 1)"; else
    bad "$c: expected exit 1 mentioning \"$m\", got exit $code"
    echo "$out"
  fi
}
has() { # has <case> <file> <exact line>
  if grep -qxF -- "$3" "$2"; then ok "$1"; else bad "$1: no line \"$3\" in $2"; fi
}
contains() { # contains <case> <file> <fixed string>
  if grep -qF -- "$3" "$2"; then ok "$1"; else bad "$1: \"$3\" is not in $2"; fi
}
hasnt() { # hasnt <case> <file> <fixed string>
  if grep -qF -- "$3" "$2"; then bad "$1: \"$3\" is in $2"; else ok "$1"; fi
}

out="$work/appimage-notices.txt"
if generate "$appdir" "$base" "$out"; then ok 'the fixture AppImage generates (exit 0)'; else bad 'the fixture AppImage did not generate'; fi
if [ "$(head -c "$(wc -c <"$base")" "$out" | sha256_of /dev/stdin)" = "$(sha256_of "$base")" ]; then ok 'the base notices are kept byte for byte'; else bad 'the base notices were changed'; fi
contains 'section heading' "$out" '6. AppImage only: what the AppImage carries besides BirdoVPN (20 files)'
has 'the runtime, by commit' "$out" "  AppImage type2-runtime 20251108 - commit $runtime_commit - MIT [A1]"
contains 'libfuse, statically linked, LGPL-2.1' "$out" '    libfuse 3.15.0 - LGPL-2.1-only [A2, A3]'
contains "libfuse's LGPL-2.1 text in full" "$out" 'GNU LESSER GENERAL PUBLIC LICENSE'
contains 'the runtime source in the asset' "$out" "    source: appimage-runtime/type2-runtime-$runtime_commit.tar in https://github.com/BirdoVPN/Desktop-Client/releases/download/v"
has 'AppRun.wrapped listed' "$out" '    AppRun.wrapped'
has 'AppRun listed' "$out" '    AppRun'
has 'the GTK hook listed' "$out" '    apprun-hooks/linuxdeploy-plugin-gtk.sh'
has 'a generated cache listed' "$out" '    usr/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache'
has 'gschemas.compiled listed' "$out" '    usr/share/glib-2.0/schemas/gschemas.compiled'
has "BirdoVPN's own binary" "$out" '    usr/bin/birdo-vpn-desktop'
has "BirdoVPN's own xray" "$out" '    usr/lib/BirdoVPN/resources/xray'
has "BirdoVPN's own .desktop file" "$out" '    usr/share/applications/BirdoVPN.desktop'
has "BirdoVPN's own icon" "$out" '    usr/share/icons/hicolor/32x32/apps/birdo-vpn-desktop.png'
has 'GTK source package and version' "$out" '  source: Ubuntu source package gtk+3.0 3.24.33-1ubuntu2.2'
has 'apt-get source line' "$out" '    apt-get source gtk+3.0=3.24.33-1ubuntu2.2'
has 'Launchpad URL of the exact upload' "$out" '    https://launchpad.net/ubuntu/+source/webkit2gtk/2.48.7-0ubuntu0.22.04.1'
has 'flattened soname from /usr/lib/<triplet>' "$out" '    usr/lib/libgtk-3.so.0'
has 'the unversioned libgtk-3.so copy is listed' "$out" '    usr/lib/libgtk-3.so'
hasnt '... and credited to libgtk-3-0, not the -dev package that ships the link' "$out" 'libgtk-3-dev'
has 'GTK module below its multiarch dir' "$out" '    usr/lib/gtk-3.0/3.0.0/immodules/im-thai.so'
hasnt 'the GTK 2 decoy of the same name is not chosen' "$out" 'libgtk2.0-0'
contains 'usrmerge: zlib registered under /lib/<triplet>' "$out" 'zlib1g 1:1.2.11.dfsg-2ubuntu9.2 (amd64) ['
has 'WebKitGTK helper program' "$out" '    usr/lib/x86_64-linux-gnu/webkit2gtk-4.1/WebKitWebProcess'
has 'a soname link no package ships, resolved on the host' "$out" '    usr/lib/libsoname.so.3'
has 'a typelib by its package' "$out" '    usr/lib/girepository-1.0/Gtk-3.0.typelib'
contains '... gir1.2-gtk-3.0' "$out" 'gir1.2-gtk-3.0 3.24.33-1ubuntu2.2 (amd64)'
has 'a schema by its package' "$out" '    usr/share/glib-2.0/schemas/org.gtk.Settings.FileChooser.gschema.xml'
contains '... libgtk-3-common' "$out" 'libgtk-3-common 3.24.33-1ubuntu2.2 (all)'
has 'a copied copyright file by its package' "$out" '    usr/share/doc/libgtk-3-0/copyright'
has 'DEP-5 licence names' "$out" '  licences named in its copyright file: LGPL-2+'
has 'a non-DEP-5 copyright file' "$out" '  licence: as its copyright file says'
has 'the cited LGPL-2 text in full' "$out" 'FIXTURE LGPL-2 FULL TEXT'
has 'the cited LGPL-2.1 text in full (trailing full stop dropped)' "$out" 'FIXTURE LGPL-2.1 FULL TEXT'
has "a cited GPL-2.0 is Debian's GPL-2" "$out" 'FIXTURE GPL-2 FULL TEXT'
contains 'identical copyright files printed once' "$out" '(and 2 more identical)'
has 'copyright text normalised (CRLF, trailing spaces)' "$out" '(C) 1995 Jean-loup Gailly and Mark Adler'
hasnt 'symlinks are not listed' "$out" '    usr/lib/im-thai.so'
if grep -q $'\r' "$out"; then bad 'output has CR line ends'; else ok 'output is LF only'; fi
generate "$appdir" "$base" "$work/again.txt" >/dev/null
if cmp -s "$out" "$work/again.txt"; then ok 'deterministic: a second run gives the same bytes'; else bad 'a second run gave different bytes'; fi

# The generator's list and the gate's checks 8-10 agree: an AppImage carrying
# this file passes the gate; one more file added afterwards fails it.
# shellcheck disable=SC2016 # each "$1" belongs to the generated script
make_appimage() { # make_appimage <out.AppImage> <root>
  tar -czf "$1.payload.tgz" -C "$2" .
  {
    printf '#!/bin/sh\n'
    printf 'if [ "$1" = --appimage-version ]; then echo "AppImage runtime version: https://github.com/AppImage/type2-runtime/commit/%.7s" >&2; exit 0; fi\n' "$runtime_commit"
    printf '[ "$1" = --appimage-extract ] || exit 64\nmkdir -p squashfs-root && tar -xzf %s -C squashfs-root\n' "'$1.payload.tgz'"
  } >"$1"
  chmod 755 "$1"
}
cp -R "$appdir" "$work/final"
cp "$out" "$work/final/usr/lib/BirdoVPN/resources/THIRD-PARTY-NOTICES.txt"
make_appimage "$work/final.AppImage" "$work/final"
code=0
gate_out="$(NOTICES_FILE="$base" APPIMAGE_NOTICES_FILE="$out" bash "$gate" "$xray_sha" "$work/final.AppImage" 2>&1)" || code=$?
if [ "$code" -eq 0 ] && printf '%s' "$gate_out" | grep -qF 'files    : all 20 files in it are listed' && printf '%s' "$gate_out" | grep -qF 'runtime  : type2-runtime'; then
  ok 'the gate passes the AppImage carrying the generated notices'
else
  bad "the gate did not pass the generated notices (exit $code)"
  echo "$gate_out"
fi
printf 'extra\n' >"$work/final/usr/share/extra-data.txt"
make_appimage "$work/extra.AppImage" "$work/final"
code=0
gate_out="$(NOTICES_FILE="$base" APPIMAGE_NOTICES_FILE="$out" bash "$gate" "$xray_sha" "$work/extra.AppImage" 2>&1)" || code=$?
if [ "$code" -eq 1 ] && printf '%s' "$gate_out" | grep -qF 'usr/share/extra-data.txt is in the AppImage but not listed'; then ok 'the gate fails a file added after the notices were made'; else
  bad "the gate did not fail an unlisted file (exit $code)"
  echo "$gate_out"
fi

# Failure paths.
cp -R "$appdir" "$work/unowned"
fake_elf "$work/unowned/usr/lib/libnobody.so.1"
expect_fail 'a file no package owns fails' 'usr/lib/libnobody.so.1: no installed package owns it' "$work/unowned"

cp -R "$appdir" "$work/twice"
fake_elf "$work/twice/usr/lib/libdup.so.1"
hostfile "usr/lib/$T/libdup.so.1"
hostfile "usr/lib/libdup.so.1"
cp "$db" "$work/dpkg-dup.db"
printf '%s\n' "liba:amd64: /usr/lib/$T/libdup.so.1" 'libb:amd64: /usr/lib/libdup.so.1' >>"$work/dpkg-dup.db"
FAKE_DPKG_DB="$work/dpkg-dup.db" expect_fail 'a file two packages own fails' 'usr/lib/libdup.so.1: more than one package owns it' "$work/twice"

mv "$doc/zlib1g/copyright" "$work/zlib-copyright"
expect_fail 'a package with no copyright file fails' 'zlib1g 1:1.2.11.dfsg-2ubuntu9.2: no' "$appdir"
mv "$work/zlib-copyright" "$doc/zlib1g/copyright"

mv "$licences/LGPL-2.1" "$work/lgpl-2.1"
expect_fail 'a cited common licence missing on the host fails' 'cites /usr/share/common-licenses/LGPL-2.1, which this host does not have' "$appdir"
mv "$work/lgpl-2.1" "$licences/LGPL-2.1"

expect_fail 'base notices that already have the AppImage section fail' 'already has the AppImage section' "$appdir" --base "$out"
mkdir -p "$work/empty"
expect_fail 'a directory that is not an unpacked AppImage fails' 'has no usr/' "$work/empty"

other="$work/Other.AppImage"
cp "$appimage" "$other"
patch_bytes "$other" 66 'X' # inside the runtime's code, outside the filled sections
expect_fail 'an AppImage whose runtime is not the pinned one fails' 'does not start with the pinned type2-runtime' "$appdir" --appimage "$other"
make_runtime "$work/runtime-other" 'other runtime code!!'
expect_fail 'a runtime file that is not the pinned one fails' 'is not the pinned runtime' "$appdir" --runtime-file "$work/runtime-other"
cp -R "$appdir" "$work/apprun"
printf 'another AppRun' >"$work/apprun/AppRun.wrapped"
expect_fail 'an AppRun.wrapped that is not the pinned AppRun fails' 'not the pinned AppRun' "$work/apprun"

echo "appimage-notices self-test: $passes passed, $failures failed"
if [ "$failures" -gt 0 ]; then
  echo "::error::appimage-notices self-test: $failures check(s) failed"
  exit 1
fi
