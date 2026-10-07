#!/usr/bin/env bash
# src-tauri/nsis-hooks.nsh calls the bundler template's own
# CheckIfAppIsRunning macro (REVIEW-WIN2-008: stop a running BirdoVPN before
# the uninstall reconcile). tauri-bundler 2.10.0 (@tauri-apps/cli 2.12)
# changed that macro's first parameter from an executable NAME to a full PATH
# handed to Restart Manager. A hook still passing the bare name compiled
# cleanly and silently matched nothing, and PR builds run `tauri build
# --no-bundle`, so no other job would ever see it.
#
# The NSIS templates are compiled into the installed @tauri-apps/cli native
# binary. This requires the hook to call the macro exactly the way that
# template calls it, so the next bundler change to the macro fails the PR
# instead of shipping. Run from the repo root after `npm ci`.
set -euo pipefail

hook=src-tauri/nsis-hooks.nsh
call='!insertmacro CheckIfAppIsRunning "[^"]*" "[^"]*"'

shopt -s nullglob
bins=(node_modules/@tauri-apps/cli-*/*.node)
if [ "${#bins[@]}" -eq 0 ]; then
  echo "::error::no @tauri-apps/cli native binary under node_modules - run npm ci first"
  exit 1
fi

sig=$(grep -a -o -h '!macro CheckIfAppIsRunning [A-Za-z_]* [A-Za-z_]*' "${bins[@]}" | sort -u || true)
template=$(grep -a -o -h "$call" "${bins[@]}" | sort -u || true)
ours=$(tr -d '\r' < "$hook" | grep -o "$call" | sort -u || true)

echo "bundler macro:  ${sig:-<not found>}"
echo "template calls: ${template:-<not found>}"
echo "hook calls:     ${ours:-<not found>}"

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
if [ "$ours" != "$template" ]; then
  echo "::error::$hook calls the macro as [$ours] but the bundled template ($sig) calls it as [$template] - match the template"
  exit 1
fi
echo "OK - $hook calls CheckIfAppIsRunning exactly as the bundled tauri-bundler template does"
