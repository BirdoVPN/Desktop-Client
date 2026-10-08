#!/usr/bin/env bash
# ============================================================================
# Inspects what `tauri build --bundles nsis` GENERATED: the installer, and the
# NSIS script the bundler rendered and handed to makensis
# (.github/workflows/nsis-installer.yml runs this after a real build).
#
# scripts/ci/check-nsis-hook-macros.sh reads the template strings compiled
# into the @tauri-apps/cli binary. This reads the rendered output, which is
# what actually ships:
#   1. exactly one <productName>_<version>_x64-setup.exe was produced;
#   2. installer.nsi !includes the hook file (the same bytes as
#      src-tauri/nsis-hooks.nsh). Without the include every hook is gone and
#      the installer still builds;
#   3. every NSIS_HOOK_* macro the hook file defines is one the generated
#      template invokes. The template wraps each call in !ifmacrodef, so a
#      renamed or misspelt hook is skipped without a word. A definition is
#      read whatever the whitespace after !macro, and with its whole name
#      (NSIS_HOOK_PREINSTALL2 is not NSIS_HOOK_PREINSTALL);
#   4. the hook calls CheckIfAppIsRunning on exactly one line, exactly as the
#      generated template does, in the full-path form
#      "$INSTDIR\${MAINBINARYNAME}.exe". tauri-bundler 2.10.0 (@tauri-apps/cli
#      2.12) turned the macro's first parameter from an executable name into a
#      path for Restart Manager; the hook's bare name still compiled and
#      silently matched nothing (REVIEW-WIN2-008). The line count is what
#      catches a second call the form comparison cannot see, such as one with
#      unquoted arguments.
#
# NSIS keywords are case-insensitive: `!Macro`, `!INSERTMACRO` and `!Include`
# compile like the lower-case forms. Every keyword is therefore matched in any
# case, and a call written in another case is compared in the template's
# lower-case form. Macro names and arguments still have to match exactly.
#
# Usage, from the repo root after the build:
#   check-generated-nsis.sh [nsis-dir] [hook] [bundle-dir]
# Defaults: src-tauri/target/release/nsis/x64, src-tauri/nsis-hooks.nsh,
# src-tauri/target/release/bundle/nsis. Self-test (run by the same job):
# scripts/ci/check-generated-nsis.tests.sh.
# ============================================================================
set -euo pipefail

nsis_dir=${1:-src-tauri/target/release/nsis/x64}
hook=${2:-src-tauri/nsis-hooks.nsh}
bundle_dir=${3:-src-tauri/target/release/bundle/nsis}

# Literal NSIS text, not shell expansions.
# shellcheck disable=SC2016
want_call='!insertmacro CheckIfAppIsRunning "$INSTDIR\${MAINBINARYNAME}.exe" "${PRODUCTNAME}"'
# The keywords in any case. Bracket expressions behave the same in every grep
# and sed (GNU on the runners, BSD on a Mac), unlike grep -i or sed's I flag.
kw_include='![Ii][Nn][Cc][Ll][Uu][Dd][Ee]'
kw_macro='![Mm][Aa][Cc][Rr][Oo]'
kw_insertmacro='![Ii][Nn][Ss][Ee][Rr][Tt][Mm][Aa][Cc][Rr][Oo]'
call_re="$kw_insertmacro"' CheckIfAppIsRunning "[^"]*" "[^"]*"'
# Any call at all, whatever its arguments: call_re only sees the quoted form.
any_call_re="^[[:space:]]*$kw_insertmacro"'[[:space:]]+CheckIfAppIsRunning([[:space:]]|$)'

fail() {
  echo "::error::check-generated-nsis: $*"
  exit 1
}
# The bundler writes its .nsi/.nsh files as UTF-8 with a BOM, and a Windows
# checkout gives the hook CRLF line endings: compare plain text.
plain() { sed -e '1s/^\xEF\xBB\xBF//' -e 's/\r$//' "$1"; }
# An !include path as the .nsi spells it (absolute Windows, or relative to the
# script's own folder) -> a path this shell can open.
resolve() {
  case "$1" in
    [A-Za-z]:[\\/]* | /*)
      if command -v cygpath >/dev/null 2>&1; then cygpath -u "$1"; else printf '%s\n' "$1"; fi
      ;;
    *) printf '%s/%s\n' "$nsis_dir" "${1//\\//}" ;;
  esac
}
lines() { if [ -z "$1" ]; then echo 0; else printf '%s\n' "$1" | wc -l | tr -d ' '; fi; }
# A call as the template spells it: the keyword in lower case.
lower_kw() { sed "s/^$kw_insertmacro /!insertmacro /"; }

nsi="$nsis_dir/installer.nsi"
[ -f "$nsi" ] || fail "no generated script at $nsi - did tauri build the nsis bundle?"
[ -f "$hook" ] || fail "hook file missing: $hook"

# -- 1. the installer ---------------------------------------------------------
product=$(node -p "require('./src-tauri/tauri.conf.json').productName")
version=$(node -p "require('./src-tauri/tauri.conf.json').version")
shopt -s nullglob
installers=("$bundle_dir"/*-setup.exe)
shopt -u nullglob
[ "${#installers[@]}" -eq 1 ] || fail "expected one *-setup.exe in $bundle_dir, found ${#installers[@]}"
name=${installers[0]##*/}
[ "$name" = "${product}_${version}_x64-setup.exe" ] ||
  fail "the installer is $name; tauri.conf.json says ${product}_${version}_x64-setup.exe"
size=$(wc -c <"${installers[0]}" | tr -d ' ')
[ "$size" -gt 1000000 ] || fail "$name is only $size bytes"
echo "OK 1/4 installer: $name ($size bytes)"

# -- 2. the hook file is included --------------------------------------------
included=()
while IFS= read -r inc; do
  path=$(resolve "$inc")
  if [ -f "$path" ] && cmp -s "$path" "$hook"; then included+=("$inc"); fi
done < <(plain "$nsi" | sed -n 's/^[[:space:]]*'"$kw_include"' "\([^"]*\)"[[:space:]]*$/\1/p')
[ "${#included[@]}" -eq 1 ] ||
  fail "installer.nsi includes $hook ${#included[@]} times (want 1): bundle.windows.nsis.installerHooks is not reaching the bundler, so no hook is in the installer"
echo "OK 2/4 installer.nsi includes ${included[0]} (the same bytes as $hook)"

# -- 3. every hook the file defines is one the template invokes --------------
defined=$(plain "$hook" | sed -n 's/^[[:space:]]*'"$kw_macro"'[[:space:]]\{1,\}\(NSIS_HOOK_[A-Za-z0-9_]*\).*$/\1/p' | sort -u)
invoked=$(plain "$nsi" | sed -n 's/^[[:space:]]*'"$kw_insertmacro"'[[:space:]]\{1,\}\(NSIS_HOOK_[A-Za-z0-9_]*\)[[:space:]]*$/\1/p' | sort -u)
[ -n "$defined" ] || fail "$hook defines no NSIS_HOOK_* macro"
[ -n "$invoked" ] || fail "installer.nsi invokes no NSIS_HOOK_* macro: the bundler's hook points changed - re-check $hook by hand"
dead=$(comm -23 <(printf '%s\n' "$defined") <(printf '%s\n' "$invoked") | tr '\n' ' ')
[ -z "$dead" ] ||
  fail "hook never invoked: $hook defines [ ${dead}] but the generated template invokes only [ $(tr '\n' ' ' <<<"$invoked")]; !ifmacrodef skips the rest silently"
echo "OK 3/4 hooks defined and invoked: $(tr '\n' ' ' <<<"$defined")"

# -- 4. CheckIfAppIsRunning: the template's form, and the full path ----------
sig=$(cat "$nsis_dir"/*.nsh | tr -d '\r' | grep -oE "$kw_macro"' CheckIfAppIsRunning [A-Za-z_]+ [A-Za-z_]+' | sort -u || true)
template=$(plain "$nsi" | grep -oE "$call_re" | lower_kw | sort -u || true)
ours=$(plain "$hook" | grep -oE "$call_re" | lower_kw | sort -u || true)
call_lines=$(plain "$hook" | grep -cE "$any_call_re" || true)
echo "   generated macro:  ${sig:-<not found>}"
echo "   template calls:   ${template:-<not found>}"
echo "   hook calls:       ${ours:-<not found>} (on $call_lines line(s))"
[ -n "$sig" ] || fail "no CheckIfAppIsRunning macro in the generated $nsis_dir/*.nsh - the hook's call cannot compile against it; re-check by hand"
[ "$call_lines" -eq 1 ] ||
  fail "$hook calls CheckIfAppIsRunning on $call_lines lines (want exactly 1): the form checks below see only calls with quoted arguments, so any other call would ship unchecked"
[ "$(lines "$template")" -eq 1 ] ||
  fail "the generated template calls CheckIfAppIsRunning in $(lines "$template") forms (want 1) - decide by hand which one the hook must use"
[ "$(lines "$ours")" -eq 1 ] || fail "$hook calls CheckIfAppIsRunning in $(lines "$ours") forms (want 1; REVIEW-WIN2-008 depends on it)"
[ "$ours" = "$template" ] ||
  fail "call form mismatch: $hook calls [$ours] but the generated template ($sig) calls [$template]"
[ "$ours" = "$want_call" ] ||
  fail "call form mismatch: $hook calls [$ours]; the uninstall hook must pass the full path [$want_call]"
echo "OK 4/4 the hook calls CheckIfAppIsRunning exactly as the generated template does, with the full path"
