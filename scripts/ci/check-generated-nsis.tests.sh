#!/usr/bin/env bash
# ============================================================================
# Self-test for scripts/ci/check-generated-nsis.sh, run by nsis-installer.yml
# right after the real check, against COPIES of the script the build just
# generated. A gate that can be edited into a no-op is worse than none, so
# every run proves that the regressions it exists for still fail it:
#
#   pass  the generated script and the repo's hook, unmodified
#   fail  the hook calls CheckIfAppIsRunning with the bare "${MAINBINARYNAME}.exe"
#         (REVIEW-WIN2-008: what tauri-bundler 2.10.0 silently broke)
#   fail  the template calls it in a form the hook does not (the next bundler change)
#   fail  the template AND the hook both use the bare name: they agree, and
#         the hook still does not pass the full path
#   fail  the hook adds a second, unquoted call, which the form comparison
#         cannot see
#   fail  a hook macro is renamed (the template's !ifmacrodef skips it silently),
#         also behind two spaces or a tab after !macro, and by a suffix
#         (NSIS_HOOK_PREUNINSTALL2 must not read as NSIS_HOOK_PREUNINSTALL)
#   fail  the script no longer includes the hook (installerHooks not applied)
#
# Usage, from the repo root after the build:
#   check-generated-nsis.tests.sh [nsis-dir] [hook] [bundle-dir]   (defaults as the check's)
# ============================================================================
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
check="$here/check-generated-nsis.sh"
nsis_dir=${1:-src-tauri/target/release/nsis/x64}
hook=${2:-src-tauri/nsis-hooks.nsh}
bundle_dir=${3:-src-tauri/target/release/bundle/nsis}

base=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
if command -v cygpath >/dev/null 2>&1; then base=$(cygpath -u "$base"); fi
work=$(mktemp -d "$base/nsis-check-selftest.XXXXXX")
trap 'rm -rf "$work"' EXIT

failures=0
bad() {
  echo "::error::check-generated-nsis self-test: $*"
  failures=$((failures + 1))
}
# A path the generated script could !include (drive-letter form on Windows).
nsis_path() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s\n' "$1"; fi; }

# fixture <name>: $work/<name>/x64 = a copy of the generated folder whose
# hook !include points at $work/<name>/nsis-hooks.nsh, a copy of the hook.
fixture() {
  local d="$work/$1"
  mkdir -p "$d"
  cp -R "$nsis_dir" "$d/x64"
  cp "$hook" "$d/nsis-hooks.nsh"
  local to n
  to=$(nsis_path "$d/nsis-hooks.nsh")
  n=$(grep -c '^[[:space:]]*!include ".*nsis-hooks\.nsh"' "$d/x64/installer.nsi" || true)
  [ "$n" -eq 1 ] || {
    echo "::error::check-generated-nsis self-test: the generated installer.nsi has $n nsis-hooks.nsh includes - cannot build fixtures"
    exit 1
  }
  sed -i "s|^\([[:space:]]*!include \"\).*nsis-hooks\.nsh\"|\1$to\"|" "$d/x64/installer.nsi"
}

# mutate <file> <sed-expr> <text that must appear afterwards>: a mutation
# that silently fails to apply would turn a must-fail case into a pass.
mutate() {
  sed -i "$2" "$1"
  grep -qF -- "$3" "$1" || {
    echo "::error::check-generated-nsis self-test: mutation '$2' did not apply to $1"
    exit 1
  }
}

# expect <pass|fail> <name> [error text the failure must carry]
expect() {
  local want=$1 name=$2 needle=${3:-} out rc=0
  out=$(bash "$check" "$work/$name/x64" "$work/$name/nsis-hooks.nsh" "$bundle_dir" 2>&1) || rc=$?
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

# Literal NSIS text in the sed expressions and needles below, not shell expansions.
# shellcheck disable=SC2016
{
  fixture unmodified
  expect pass unmodified

  fixture bare-name-hook
  mutate "$work/bare-name-hook/nsis-hooks.nsh" \
    's/CheckIfAppIsRunning "\$INSTDIR\\\${MAINBINARYNAME}\.exe"/CheckIfAppIsRunning "${MAINBINARYNAME}.exe"/' \
    'CheckIfAppIsRunning "${MAINBINARYNAME}.exe"'
  expect fail bare-name-hook 'call form mismatch'

  fixture template-changed
  mutate "$work/template-changed/x64/installer.nsi" \
    's/CheckIfAppIsRunning "\$INSTDIR\\\${MAINBINARYNAME}\.exe"/CheckIfAppIsRunning "${MAINBINARYNAME}"/' \
    'CheckIfAppIsRunning "${MAINBINARYNAME}"'
  expect fail template-changed 'call form mismatch'

  # The two agree, so only the full-path assertion (want_call) can fail it.
  fixture bare-name-both
  mutate "$work/bare-name-both/nsis-hooks.nsh" \
    's/CheckIfAppIsRunning "\$INSTDIR\\\${MAINBINARYNAME}\.exe"/CheckIfAppIsRunning "${MAINBINARYNAME}.exe"/' \
    'CheckIfAppIsRunning "${MAINBINARYNAME}.exe"'
  mutate "$work/bare-name-both/x64/installer.nsi" \
    's/CheckIfAppIsRunning "\$INSTDIR\\\${MAINBINARYNAME}\.exe"/CheckIfAppIsRunning "${MAINBINARYNAME}.exe"/' \
    'CheckIfAppIsRunning "${MAINBINARYNAME}.exe"'
  expect fail bare-name-both 'must pass the full path'

  # Unquoted arguments: invisible to the quoted-form comparison.
  fixture second-unquoted-call
  mutate "$work/second-unquoted-call/nsis-hooks.nsh" \
    '/^[[:space:]]*!insertmacro CheckIfAppIsRunning "/a\  !insertmacro CheckIfAppIsRunning ${MAINBINARYNAME}.exe "${PRODUCTNAME}"' \
    '!insertmacro CheckIfAppIsRunning ${MAINBINARYNAME}.exe "${PRODUCTNAME}"'
  expect fail second-unquoted-call 'calls CheckIfAppIsRunning on 2 lines'

  fixture renamed-hook
  mutate "$work/renamed-hook/nsis-hooks.nsh" \
    's/!macro NSIS_HOOK_PREUNINSTALL/!macro NSIS_HOOK_PRE_UNINSTALL/' \
    '!macro NSIS_HOOK_PRE_UNINSTALL'
  expect fail renamed-hook 'hook never invoked'

  # NSIS takes any whitespace after !macro; the check must read it too.
  fixture renamed-hook-two-spaces
  mutate "$work/renamed-hook-two-spaces/nsis-hooks.nsh" \
    's/!macro NSIS_HOOK_PREUNINSTALL/!macro  NSIS_HOOK_PRE_UNINSTALL/' \
    '!macro  NSIS_HOOK_PRE_UNINSTALL'
  expect fail renamed-hook-two-spaces 'hook never invoked'

  fixture renamed-hook-tab
  mutate "$work/renamed-hook-tab/nsis-hooks.nsh" \
    's/!macro NSIS_HOOK_PREUNINSTALL/!macro\tNSIS_HOOK_PRE_UNINSTALL/' \
    $'!macro\tNSIS_HOOK_PRE_UNINSTALL'
  expect fail renamed-hook-tab 'hook never invoked'

  # A name that merely STARTS with a real hook's name is another macro.
  fixture renamed-hook-suffix
  mutate "$work/renamed-hook-suffix/nsis-hooks.nsh" \
    's/!macro NSIS_HOOK_PREUNINSTALL/!macro NSIS_HOOK_PREUNINSTALL2/' \
    '!macro NSIS_HOOK_PREUNINSTALL2'
  expect fail renamed-hook-suffix 'hook never invoked'

  fixture not-included
  sed -i '/^[[:space:]]*!include ".*nsis-hooks\.nsh"/d' "$work/not-included/x64/installer.nsi"
  expect fail not-included 'installerHooks is not reaching the bundler'
}

if [ "$failures" -ne 0 ]; then
  echo "::error::check-generated-nsis self-test: $failures scenario(s) wrong"
  exit 1
fi
echo "OK - check-generated-nsis.sh passes the generated script and fails every regression scenario"
