#!/usr/bin/env bash
# src-tauri/nsis-hooks.nsh calls the bundler template's own
# CheckIfAppIsRunning macro (REVIEW-WIN2-008: stop a running BirdoVPN before
# the uninstall reconcile). tauri-bundler 2.10.0 (@tauri-apps/cli 2.12)
# changed that macro's first parameter from an executable NAME to a full PATH
# handed to Restart Manager. A hook still passing the bare name compiled
# cleanly and silently matched nothing, and no PR job built the installer
# then. (.github/workflows/nsis-installer.yml now does, on the PRs that touch
# its paths, and checks the generated script with check-generated-nsis.sh.)
#
# The NSIS templates are compiled into the installed @tauri-apps/cli native
# binary. This requires the hook to call the macro exactly the way that
# template calls it, so the next bundler change to the macro fails the PR
# instead of shipping. NSIS keywords are case-insensitive (`!INSERTMACRO` is
# `!insertmacro`), so the keyword is matched in any case and compared in the
# template's lower-case form; the macro name and arguments must match exactly.
#
# Usage, from the repo root after `npm ci`:
#   check-nsis-hook-macros.sh [hook] [cli-dir]
# Defaults: src-tauri/nsis-hooks.nsh, node_modules/@tauri-apps (whose
# cli-*/*.node is the native binary). Self-test (tests.yml runs it next):
# scripts/ci/check-nsis-hook-macros.tests.sh.
set -euo pipefail

hook=${1:-src-tauri/nsis-hooks.nsh}
cli_dir=${2:-node_modules/@tauri-apps}
# The keywords in any case. Bracket expressions behave the same in every grep
# and sed (GNU on the runners, BSD on a Mac), unlike grep -i or sed's I flag.
kw_macro='![Mm][Aa][Cc][Rr][Oo]'
kw_insertmacro='![Ii][Nn][Ss][Ee][Rr][Tt][Mm][Aa][Cc][Rr][Oo]'
call="$kw_insertmacro"' CheckIfAppIsRunning "[^"]*" "[^"]*"'
# Any call at all, whatever its arguments: $call only sees the quoted form, so
# a second call with unquoted arguments would otherwise ship unchecked.
any_call="^[[:space:]]*$kw_insertmacro"'[[:space:]]+CheckIfAppIsRunning([[:space:]]|$)'
# A call as the template spells it: the keyword in lower case.
lower_kw() { sed "s/^$kw_insertmacro /!insertmacro /"; }

[ -f "$hook" ] || {
  echo "::error::hook file missing: $hook"
  exit 1
}
shopt -s nullglob
bins=("$cli_dir"/cli-*/*.node)
if [ "${#bins[@]}" -eq 0 ]; then
  echo "::error::no @tauri-apps/cli native binary under $cli_dir - run npm ci first"
  exit 1
fi

sig=$(grep -a -o -h "$kw_macro"' CheckIfAppIsRunning [A-Za-z_]* [A-Za-z_]*' "${bins[@]}" | sort -u || true)
template=$(grep -a -o -h "$call" "${bins[@]}" | lower_kw | sort -u || true)
ours=$(tr -d '\r' <"$hook" | grep -o "$call" | lower_kw | sort -u || true)
call_lines=$(tr -d '\r' <"$hook" | grep -cE "$any_call" || true)

echo "bundler macro:  ${sig:-<not found>}"
echo "template calls: ${template:-<not found>}"
echo "hook calls:     ${ours:-<not found>} (on $call_lines line(s))"

if [ -z "$sig" ] || [ -z "$template" ]; then
  echo "::error::CheckIfAppIsRunning is gone from the @tauri-apps/cli templates - re-check $hook's NSIS_HOOK_PREUNINSTALL by hand"
  exit 1
fi
if [ "$(printf '%s\n' "$template" | wc -l)" -ne 1 ]; then
  echo "::error::the bundled template calls CheckIfAppIsRunning in more than one form; decide by hand which one $hook must use"
  exit 1
fi
if [ -z "$ours" ]; then
  echo "::error::$hook no longer calls CheckIfAppIsRunning (REVIEW-WIN2-008 depends on it)"
  exit 1
fi
if [ "$call_lines" -ne 1 ]; then
  echo "::error::$hook calls CheckIfAppIsRunning on $call_lines lines (want exactly 1): only a call with quoted arguments is compared with the template below"
  exit 1
fi
if [ "$ours" != "$template" ]; then
  echo "::error::$hook calls the macro as [$ours] but the bundled template ($sig) calls it as [$template] - match the template"
  exit 1
fi
echo "OK - $hook calls CheckIfAppIsRunning exactly as the bundled tauri-bundler template does"
