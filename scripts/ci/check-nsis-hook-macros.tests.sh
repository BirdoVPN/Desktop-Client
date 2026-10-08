#!/usr/bin/env bash
# ============================================================================
# Self-test for scripts/ci/check-nsis-hook-macros.sh, run by tests.yml right
# after the real check. It runs against COPIES of the hook and against a
# small stand-in for the CLI binary, which holds just the template strings
# that the real check reads out of node_modules/@tauri-apps/cli-*/*.node. A
# gate that can be edited into a no-op is worse than none:
#
#   pass  the repo's hook against the locked CLI's strings, unmodified
#   pass  the hook's one call spells the keyword !INSERTMACRO (NSIS keywords
#         are case-insensitive: it is the same call)
#   fail  the hook passes the bare "${MAINBINARYNAME}.exe" (REVIEW-WIN2-008)
#   fail  a second, unquoted call, which the form comparison cannot see;
#         also when it spells the keyword !INSERTMACRO or !InsertMacro
#   fail  the hook no longer calls the macro
#   fail  the CLI's templates no longer carry the macro
#
# Usage, from the repo root after `npm ci`:
#   check-nsis-hook-macros.tests.sh [hook] [cli-dir]   (defaults as the check's)
# ============================================================================
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
check="$here/check-nsis-hook-macros.sh"
hook=${1:-src-tauri/nsis-hooks.nsh}
cli_dir=${2:-node_modules/@tauri-apps}

base=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
if command -v cygpath >/dev/null 2>&1; then base=$(cygpath -u "$base"); fi
work=$(mktemp -d "$base/nsis-hook-macros-selftest.XXXXXX")
trap 'rm -rf "$work"' EXIT

failures=0
bad() {
  echo "::error::check-nsis-hook-macros self-test: $*"
  failures=$((failures + 1))
}

shopt -s nullglob
bins=("$cli_dir"/cli-*/*.node)
shopt -u nullglob
[ "${#bins[@]}" -gt 0 ] || {
  echo "::error::check-nsis-hook-macros self-test: no @tauri-apps/cli native binary under $cli_dir - run npm ci first"
  exit 1
}
# The stand-in binary: only the strings the check reads, one per line.
strings_file="$work/template-strings.txt"
grep -a -o -h -e '!macro CheckIfAppIsRunning [A-Za-z_]* [A-Za-z_]*' \
  -e '!insertmacro CheckIfAppIsRunning "[^"]*" "[^"]*"' "${bins[@]}" | sort -u >"$strings_file" || true
[ -s "$strings_file" ] || {
  echo "::error::check-nsis-hook-macros self-test: the CLI binary has no CheckIfAppIsRunning strings - the real check says why"
  exit 1
}

# fixture <name> [template-strings]: $work/<name>/hook.nsh, a copy of the
# hook, and $work/<name>/cli/cli-fixture/fixture.node holding those strings.
fixture() {
  local d="$work/$1"
  mkdir -p "$d/cli/cli-fixture"
  cp "$hook" "$d/hook.nsh"
  cp "${2:-$strings_file}" "$d/cli/cli-fixture/fixture.node"
}

# mutate <file> <sed-expr> <text that must appear afterwards>: a mutation
# that silently fails to apply would turn a must-fail case into a pass.
mutate() {
  sed -i "$2" "$1"
  grep -qF -- "$3" "$1" || {
    echo "::error::check-nsis-hook-macros self-test: mutation '$2' did not apply to $1"
    exit 1
  }
}

# expect <pass|fail> <name> [error text the failure must carry]
expect() {
  local want=$1 name=$2 needle=${3:-} out rc=0
  out=$(bash "$check" "$work/$name/hook.nsh" "$work/$name/cli" 2>&1) || rc=$?
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

  fixture upper-case-call
  mutate "$work/upper-case-call/hook.nsh" \
    's/!insertmacro CheckIfAppIsRunning "/!INSERTMACRO CheckIfAppIsRunning "/' \
    '!INSERTMACRO CheckIfAppIsRunning "$INSTDIR\${MAINBINARYNAME}.exe"'
  expect pass upper-case-call

  fixture bare-name
  mutate "$work/bare-name/hook.nsh" \
    's/CheckIfAppIsRunning "\$INSTDIR\\\${MAINBINARYNAME}\.exe"/CheckIfAppIsRunning "${MAINBINARYNAME}.exe"/' \
    'CheckIfAppIsRunning "${MAINBINARYNAME}.exe"'
  expect fail bare-name 'match the template'

  fixture second-unquoted-call
  mutate "$work/second-unquoted-call/hook.nsh" \
    '/^[[:space:]]*!insertmacro CheckIfAppIsRunning "/a\  !insertmacro CheckIfAppIsRunning ${MAINBINARYNAME}.exe "${PRODUCTNAME}"' \
    '!insertmacro CheckIfAppIsRunning ${MAINBINARYNAME}.exe "${PRODUCTNAME}"'
  expect fail second-unquoted-call 'calls CheckIfAppIsRunning on 2 lines'

  fixture second-call-upper-case
  mutate "$work/second-call-upper-case/hook.nsh" \
    '/^[[:space:]]*!insertmacro CheckIfAppIsRunning "/a\  !INSERTMACRO CheckIfAppIsRunning ${MAINBINARYNAME}.exe "${PRODUCTNAME}"' \
    '!INSERTMACRO CheckIfAppIsRunning ${MAINBINARYNAME}.exe "${PRODUCTNAME}"'
  expect fail second-call-upper-case 'calls CheckIfAppIsRunning on 2 lines'

  fixture second-call-mixed-case
  mutate "$work/second-call-mixed-case/hook.nsh" \
    '/^[[:space:]]*!insertmacro CheckIfAppIsRunning "/a\  !InsertMacro CheckIfAppIsRunning "${MAINBINARYNAME}.exe" "${PRODUCTNAME}"' \
    '!InsertMacro CheckIfAppIsRunning "${MAINBINARYNAME}.exe" "${PRODUCTNAME}"'
  expect fail second-call-mixed-case 'calls CheckIfAppIsRunning on 2 lines'

  fixture no-call
  mutate "$work/no-call/hook.nsh" \
    '/^[[:space:]]*!insertmacro CheckIfAppIsRunning /d' \
    'NSIS_HOOK_PREUNINSTALL'
  expect fail no-call 'no longer calls CheckIfAppIsRunning'

  : >"$work/empty-strings.txt"
  fixture template-gone "$work/empty-strings.txt"
  expect fail template-gone 'is gone from the @tauri-apps/cli templates'
}

if [ "$failures" -ne 0 ]; then
  echo "::error::check-nsis-hook-macros self-test: $failures scenario(s) wrong"
  exit 1
fi
echo "OK - check-nsis-hook-macros.sh passes the hook and fails every regression scenario"
