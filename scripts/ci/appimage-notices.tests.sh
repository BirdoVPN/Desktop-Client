#!/usr/bin/env bash
# ============================================================================
# Self-test for scripts/generate-appimage-notices.mjs (owner decision
# 2026-10-14, L2: the AppImage lists every system library it bundles), and
# for its agreement with the post-bundle gate (scripts/ci/verify-bundled-
# xray.sh, check 8), with no AppImage build and no WebKitGTK installed.
#
# A fake unpacked AppImage, a fake dpkg and dpkg-query on PATH (answering from
# a small package database), a fake /usr/share/doc and /usr/share/common-
# licenses, and a fake build host for the soname-link fallback:
#
#   pass   flattened usr/lib/<soname> from /usr/lib/<triplet> and from /lib/
#          <triplet> (usrmerge); a GTK module below its multiarch dir, with a
#          GTK 2 file of the same name as a decoy; WebKitGTK's helper program;
#          a soname link no package ships (resolved on the host); BirdoVPN's
#          own binary and xray listed as its own; the base notices kept byte
#          for byte; a copyright file's cited common licence included in
#          full; identical copyright files printed once; DEP-5 licence names;
#          output deterministic; non-ELF files, symlinks and AppRun ignored;
#          the gate passes an AppImage carrying the result, and fails it once
#          a library the notices do not list is added
#   fail   a library no package owns; a library two packages own; a package
#          with no copyright file; a cited common licence missing on the
#          host; base notices that already have the AppImage section; a
#          directory that is not an unpacked AppImage
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
# dpkg -S <pattern>... over $FAKE_DPKG_DB ("<package>: <path>" lines). As
# dpkg, a pattern's * also matches "/", and an unmatched pattern exits 1.
[ "${1-}" = -S ] || { echo "fake dpkg: only -S" >&2; exit 2; }
shift
rc=0
for pat in "$@"; do
  hit=0
  while IFS= read -r line; do
    p="${line#*: }"
    # shellcheck disable=SC2254 # the pattern is meant to glob
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
db="$work/dpkg.db"
cat >"$db" <<'EOF'
libgtk-3-0:amd64: /usr/lib/x86_64-linux-gnu/libgtk-3.so.0
libgtk-3-0:amd64: /usr/lib/x86_64-linux-gnu/gtk-3.0/3.0.0/immodules/im-thai.so
libgtk2.0-0:amd64: /usr/lib/x86_64-linux-gnu/gtk-2.0/2.10.0/immodules/im-thai.so
zlib1g:amd64: /lib/x86_64-linux-gnu/libz.so.1
libwebkit2gtk-4.1-0:amd64: /usr/lib/x86_64-linux-gnu/webkit2gtk-4.1/WebKitWebProcess
libsoname3:amd64: /usr/lib/x86_64-linux-gnu/libsoname.so.3.0.1
EOF
export FAKE_DPKG_DB="$db"
pkgs="$work/packages.tsv"
printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
  'libgtk-3-0:amd64' libgtk-3-0 amd64 3.24.33-1ubuntu2.2 'gtk+3.0' 3.24.33-1ubuntu2.2 \
  'libgtk2.0-0:amd64' libgtk2.0-0 amd64 2.24.33-2ubuntu2.1 'gtk+2.0' 2.24.33-2ubuntu2.1 \
  'zlib1g:amd64' zlib1g amd64 1:1.2.11.dfsg-2ubuntu9.2 zlib 1:1.2.11.dfsg-2ubuntu9.2 \
  'libwebkit2gtk-4.1-0:amd64' libwebkit2gtk-4.1-0 amd64 2.48.7-0ubuntu0.22.04.1 webkit2gtk 2.48.7-0ubuntu0.22.04.1 \
  'libsoname3:amd64' libsoname3 amd64 3.0.1-1 soname-fixture 3.0.1-1 >"$pkgs"
export FAKE_DPKG_PACKAGES="$pkgs"

doc="$work/doc"
licences="$work/common-licenses"
mkdir -p "$doc/libgtk-3-0" "$doc/zlib1g" "$doc/libwebkit2gtk-4.1-0" "$doc/libsoname3" "$licences"
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
printf 'zlib fixture copyright\r\n(C) 1995 Jean-loup Gailly and Mark Adler   \r\n' >"$doc/zlib1g/copyright"
cp "$doc/zlib1g/copyright" "$doc/libsoname3/copyright"
cat >"$doc/libwebkit2gtk-4.1-0/copyright" <<'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/

Files: *
Copyright: The WebKit authors
License: BSD-2-clause and LGPL-2.1+

License: LGPL-2.1+
 See /usr/share/common-licenses/LGPL-2.1.
EOF
printf 'FIXTURE LGPL-2 FULL TEXT\n' >"$licences/LGPL-2"
printf 'FIXTURE LGPL-2.1 FULL TEXT\n' >"$licences/LGPL-2.1"
printf 'PRETTY_NAME="Ubuntu 22.04.5 LTS"\nNAME="Ubuntu"\n' >"$work/os-release"
hostroot="$work/host"
mkdir -p "$hostroot/usr/lib/x86_64-linux-gnu"
: >"$hostroot/usr/lib/x86_64-linux-gnu/libsoname.so.3.0.1"
ln -s libsoname.so.3.0.1 "$hostroot/usr/lib/x86_64-linux-gnu/libsoname.so.3"

# --- the fake unpacked AppImage -----------------------------------------------
fake_elf() { mkdir -p "$(dirname "$1")" && printf '\177ELF\002\001\001\000%s' "${2-fixture}" >"$1"; }
appdir="$work/AppDir"
fake_elf "$appdir/usr/lib/BirdoVPN/resources/xray" 'xray payload'
chmod 755 "$appdir/usr/lib/BirdoVPN/resources/xray"
xray_sha="$(sha256_of "$appdir/usr/lib/BirdoVPN/resources/xray")"
fake_elf "$appdir/usr/bin/birdo-vpn-desktop" "option_env:$xray_sha"
chmod 755 "$appdir/usr/bin/birdo-vpn-desktop"
fake_elf "$appdir/usr/lib/libgtk-3.so.0"
fake_elf "$appdir/usr/lib/libz.so.1"
fake_elf "$appdir/usr/lib/libsoname.so.3"
fake_elf "$appdir/usr/lib/gtk-3.0/3.0.0/immodules/im-thai.so"
ln -s gtk-3.0/3.0.0/immodules/im-thai.so "$appdir/usr/lib/im-thai.so"
fake_elf "$appdir/usr/lib/x86_64-linux-gnu/webkit2gtk-4.1/WebKitWebProcess"
mkdir -p "$appdir/usr/lib/girepository-1.0"
printf 'typelib\n' >"$appdir/usr/lib/girepository-1.0/Gtk-3.0.typelib"
fake_elf "$appdir/AppRun.wrapped"
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
  node "$gen" --appdir "$a" --base "$b" --out "$o" --doc-root "$doc" --licenses-root "$licences" \
    --os-release "$work/os-release" --host-root "$hostroot" --multiarch x86_64-linux-gnu "$@"
}
expect_fail() { # expect_fail <case> <must-mention> <appdir> [base]
  local out code=0
  out="$(generate "$3" "${4-$base}" "$work/never.txt" 2>&1)" || code=$?
  if [ "$code" -eq 1 ] && printf '%s' "$out" | grep -qF -- "$2"; then ok "$1 (exit 1)"; else
    bad "$1: expected exit 1 mentioning \"$2\", got exit $code"
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
has 'section heading' "$out" '6. AppImage only: bundled system libraries (4 packages, 5 files)'
has 'GTK package line with its texts' "$out" 'libgtk-3-0 3.24.33-1ubuntu2.2 (amd64) [A1, A2]'
has 'GTK source package and version' "$out" '  source: Ubuntu source package gtk+3.0 3.24.33-1ubuntu2.2'
has 'apt-get source line' "$out" '    apt-get source gtk+3.0=3.24.33-1ubuntu2.2'
has 'Launchpad URL of the exact upload' "$out" '    https://launchpad.net/ubuntu/+source/webkit2gtk/2.48.7-0ubuntu0.22.04.1'
has 'flattened soname from /usr/lib/<triplet>' "$out" '    usr/lib/libgtk-3.so.0'
has 'GTK module below its multiarch dir' "$out" '    usr/lib/gtk-3.0/3.0.0/immodules/im-thai.so'
hasnt 'the GTK 2 decoy of the same name is not chosen' "$out" 'libgtk2.0-0'
has 'usrmerge: zlib registered under /lib/<triplet>' "$out" 'zlib1g 1:1.2.11.dfsg-2ubuntu9.2 (amd64) [A3]'
has 'WebKitGTK helper program' "$out" '    usr/lib/x86_64-linux-gnu/webkit2gtk-4.1/WebKitWebProcess'
has 'a soname link no package ships, resolved on the host' "$out" 'libsoname3 3.0.1-1 (amd64) [A3]'
has "BirdoVPN's own binary listed as its own" "$out" '    usr/bin/birdo-vpn-desktop'
has "BirdoVPN's own xray listed as its own" "$out" '    usr/lib/BirdoVPN/resources/xray'
has 'DEP-5 licence names' "$out" '  licences named in its copyright file: LGPL-2+'
has 'a non-DEP-5 copyright file' "$out" '  licence: as its copyright file says'
has 'the cited LGPL-2 text in full' "$out" 'FIXTURE LGPL-2 FULL TEXT'
has 'the cited LGPL-2.1 text in full (trailing full stop dropped)' "$out" 'FIXTURE LGPL-2.1 FULL TEXT'
contains 'identical copyright files printed once' "$out" '----- [A3] /usr/share/doc/libsoname3/copyright (and 1 more identical) -'
has 'copyright text normalised (CRLF, trailing spaces)' "$out" '(C) 1995 Jean-loup Gailly and Mark Adler'
hasnt 'AppRun is not a bundled system library' "$out" 'AppRun'
hasnt 'non-ELF files are not listed' "$out" 'Gtk-3.0.typelib'
hasnt 'symlinks are not listed' "$out" '    usr/lib/im-thai.so'
if grep -q $'\r' "$out"; then bad 'output has CR line ends'; else ok 'output is LF only'; fi
generate "$appdir" "$base" "$work/again.txt" >/dev/null
if cmp -s "$out" "$work/again.txt"; then ok 'deterministic: a second run gives the same bytes'; else bad 'a second run gave different bytes'; fi

# The generator's list and the gate's check 8 agree: an AppImage carrying
# this file passes the gate; one more library bundled afterwards fails it.
make_appimage() { # make_appimage <out.AppImage> <root>
  tar -czf "$1.payload.tgz" -C "$2" .
  # shellcheck disable=SC2016 # the "$1" is the generated script's own argument
  printf '#!/bin/sh\n[ "$1" = "--appimage-extract" ] || exit 64\nmkdir -p squashfs-root && tar -xzf %s -C squashfs-root\n' "'$1.payload.tgz'" >"$1"
  chmod 755 "$1"
}
cp -R "$appdir" "$work/final"
cp "$out" "$work/final/usr/lib/BirdoVPN/resources/THIRD-PARTY-NOTICES.txt"
make_appimage "$work/final.AppImage" "$work/final"
code=0
gate_out="$(NOTICES_FILE="$base" APPIMAGE_NOTICES_FILE="$out" bash "$gate" "$xray_sha" "$work/final.AppImage" 2>&1)" || code=$?
if [ "$code" -eq 0 ] && printf '%s' "$gate_out" | grep -qF 'libraries: all 7 ELF files under usr/ are listed'; then ok 'the gate passes the AppImage carrying the generated notices'; else
  bad "the gate did not pass the generated notices (exit $code)"
  echo "$gate_out"
fi
fake_elf "$work/final/usr/lib/libextra.so.9"
make_appimage "$work/extra.AppImage" "$work/final"
code=0
gate_out="$(NOTICES_FILE="$base" APPIMAGE_NOTICES_FILE="$out" bash "$gate" "$xray_sha" "$work/extra.AppImage" 2>&1)" || code=$?
if [ "$code" -eq 1 ] && printf '%s' "$gate_out" | grep -qF 'usr/lib/libextra.so.9 is bundled but not listed'; then ok 'the gate fails a library bundled after the notices were made'; else
  bad "the gate did not fail an unlisted library (exit $code)"
  echo "$gate_out"
fi

# Failure paths.
cp -R "$appdir" "$work/unowned"
fake_elf "$work/unowned/usr/lib/libnobody.so.1"
expect_fail 'a library no package owns fails' 'usr/lib/libnobody.so.1: no installed package owns it' "$work/unowned"

cp -R "$appdir" "$work/twice"
fake_elf "$work/twice/usr/lib/libdup.so.1"
cp "$db" "$work/dpkg-dup.db"
printf '%s\n' 'liba:amd64: /usr/lib/x86_64-linux-gnu/libdup.so.1' 'libb:amd64: /lib/x86_64-linux-gnu/libdup.so.1' >>"$work/dpkg-dup.db"
FAKE_DPKG_DB="$work/dpkg-dup.db" expect_fail 'a library two packages own fails' 'usr/lib/libdup.so.1: more than one package owns it' "$work/twice"

mv "$doc/zlib1g/copyright" "$work/zlib-copyright"
expect_fail 'a package with no copyright file fails' 'zlib1g 1:1.2.11.dfsg-2ubuntu9.2: no' "$appdir"
mv "$work/zlib-copyright" "$doc/zlib1g/copyright"

mv "$licences/LGPL-2.1" "$work/lgpl-2.1"
expect_fail 'a cited common licence missing on the host fails' 'cites /usr/share/common-licenses/LGPL-2.1, which this host does not have' "$appdir"
mv "$work/lgpl-2.1" "$licences/LGPL-2.1"

expect_fail 'base notices that already have the AppImage section fail' 'already has the AppImage section' "$appdir" "$out"
mkdir -p "$work/empty"
expect_fail 'a directory that is not an unpacked AppImage fails' 'has no usr/' "$work/empty"

echo "appimage-notices self-test: $passes passed, $failures failed"
if [ "$failures" -gt 0 ]; then
  echo "::error::appimage-notices self-test: $failures check(s) failed"
  exit 1
fi
