#!/usr/bin/env bash
# ============================================================================
# Self-test for scripts/ci/check-nsis-language.sh, run by nsis-installer.yml
# right after the real check. It runs against COPIES of the generated script
# and of the repo's English.nsh, and against a stand-in for the CLI binary that
# holds just the built-in English strings the real check reads out of
# node_modules/@tauri-apps/cli-*/*.node:
#
#   pass  the generated script, the repo's English.nsh and the CLI, unmodified
#   fail  deleteAppData is back to the template's "Delete the application data"
#   fail  English.nsh lacks a string the CLI defines (the label would be empty)
#   fail  the CLI gains a string English.nsh lacks (the next bundler bump)
#   fail  the CLI rewords a string (English.nsh would ship the stale wording)
#   fail  English.nsh defines a string the CLI no longer does
#   fail  the script no longer includes English.nsh (customLanguageFiles not applied)
#
# Usage, from the repo root after the build:
#   check-nsis-language.tests.sh [nsis-dir] [lang-file] [cli-dir]   (defaults as the check's)
# ============================================================================
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
check="$here/check-nsis-language.sh"
nsis_dir=${1:-src-tauri/target/release/nsis/x64}
lang=${2:-src-tauri/nsis/English.nsh}
cli_dir=${3:-node_modules/@tauri-apps}

base=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
if command -v cygpath >/dev/null 2>&1; then base=$(cygpath -u "$base"); fi
work=$(mktemp -d "$base/nsis-language-selftest.XXXXXX")
trap 'rm -rf "$work"' EXIT

failures=0
bad() {
  echo "::error::check-nsis-language self-test: $*"
  failures=$((failures + 1))
}
die() {
  echo "::error::check-nsis-language self-test: $*"
  exit 1
}
# A path the generated script could !include (drive-letter form on Windows).
nsis_path() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s\n' "$1"; fi; }

shopt -s nullglob
bins=("$cli_dir"/cli-*/*.node)
shopt -u nullglob
[ "${#bins[@]}" -gt 0 ] || die "no @tauri-apps/cli native binary under $cli_dir - run npm ci first"
# shellcheck disable=SC2016 # a literal ${LANG_ENGLISH}
strings=$(grep -a -o -h -E 'LangString [A-Za-z0-9_]+ \$\{LANG_ENGLISH\} "[^"]*"' "${bins[@]}" | sort -u || true)
[ -n "$strings" ] || die "the CLI binary has no built-in English strings - the real check says why"

# fixture <name>: $work/<name>/x64 = a copy of the generated folder whose
# English.nsh !include points at $work/<name>/English.nsh, a copy of the
# repo's; $work/<name>/cli/cli-fixture/fixture.node = the CLI's strings.
fixture() {
  local d="$work/$1" to n
  mkdir -p "$d/cli/cli-fixture"
  cp -R "$nsis_dir" "$d/x64"
  cp "$lang" "$d/English.nsh"
  printf '%s\n' "$strings" >"$d/cli/cli-fixture/fixture.node"
  to=$(nsis_path "$d/English.nsh")
  n=$(grep -c '^[[:space:]]*!include ".*English\.nsh"' "$d/x64/installer.nsi" || true)
  [ "$n" -eq 1 ] || die "the generated installer.nsi has $n English.nsh includes - cannot build fixtures"
  sed -i "s|^\([[:space:]]*!include \"\).*English\.nsh\"|\1$to\"|" "$d/x64/installer.nsi"
}

# mutate <file> <sed-expr> <text that must (or, with !, must not) appear afterwards>
mutate() {
  sed -i "$2" "$1"
  case "$3" in
    '!'*) ! grep -qF -- "${3#!}" "$1" || die "mutation '$2' did not apply to $1" ;;
    *) grep -qF -- "$3" "$1" || die "mutation '$2' did not apply to $1" ;;
  esac
}

# expect <pass|fail> <name> [error text the failure must carry]
expect() {
  local want=$1 name=$2 needle=${3:-} out rc=0
  out=$(bash "$check" "$work/$name/x64" "$work/$name/English.nsh" "$work/$name/cli" 2>&1) || rc=$?
  if [ "$want" = pass ]; then
    if [ "$rc" -eq 0 ]; then echo "ok   pass: $name"; else bad "$name should pass, exited $rc:"$'\n'"$out"; fi
  elif [ "$rc" -eq 0 ]; then
    bad "$name should FAIL the check but passed:"$'\n'"$out"
  elif ! grep -qF -- "$needle" <<<"$out"; then
    bad "$name failed, but not with '$needle':"$'\n'"$out"
  else
    echo "ok   fail: $name ($needle)"
  fi
}

# Literal NSIS text in the sed expressions below, not shell expansions.
# shellcheck disable=SC2016
{
  fixture unmodified
  expect pass unmodified

  fixture template-wording
  mutate "$work/template-wording/English.nsh" \
    's/^\(LangString deleteAppData ${LANG_ENGLISH}\) ".*"/\1 "Delete the application data"/' \
    'LangString deleteAppData ${LANG_ENGLISH} "Delete the application data"'
  expect fail template-wording 'does not say'

  fixture string-missing
  mutate "$work/string-missing/English.nsh" '/^LangString createDesktop /d' '!LangString createDesktop '
  expect fail string-missing 'the locked CLI defines [ createDesktop ] but'

  fixture cli-adds-string
  printf '%s\n' 'LangString birdoNewString ${LANG_ENGLISH} "New upstream string"' >>"$work/cli-adds-string/cli/cli-fixture/fixture.node"
  expect fail cli-adds-string 'the locked CLI defines [ birdoNewString ] but'

  fixture cli-rewords
  mutate "$work/cli-rewords/cli/cli-fixture/fixture.node" \
    's/"Create desktop shortcut"/"Create a desktop shortcut"/' '"Create a desktop shortcut"'
  expect fail cli-rewords '[ createDesktop ] in'

  fixture extra-string
  printf '%s\n' 'LangString birdoExtra ${LANG_ENGLISH} "Not upstream"' >>"$work/extra-string/English.nsh"
  expect fail extra-string 'that the locked CLI no longer does'

  fixture not-included
  sed -i '/^[[:space:]]*!include ".*English\.nsh"/d' "$work/not-included/x64/installer.nsi"
  expect fail not-included 'customLanguageFiles is not reaching the bundler'
}

if [ "$failures" -ne 0 ]; then
  echo "::error::check-nsis-language self-test: $failures scenario(s) wrong"
  exit 1
fi
echo "OK - check-nsis-language.sh passes the generated script and fails every regression scenario"
