#!/usr/bin/env bash
# No pipe into an early-exiting `grep -q` where pipefail is on (MR-2391).
#
# GitHub runs every `shell: bash` step as `bash -eo pipefail`, and this repo's
# CI scripts turn pipefail on themselves. There, `producer | grep -q pat` fails
# at random: grep -q exits at its first match, a producer still writing (a
# long test log, a file larger than the pipe buffer) dies of SIGPIPE (141),
# and pipefail makes 141 the pipeline's status - a match reported as a miss.
# Dependabot #423's macOS cross-check went red that way with every test green.
#
# Feed grep a here-string instead; it has no writer to kill:
#   grep -qE -- "$pat" <<<"$var"           not  echo "$var" | grep -qE "$pat"
#   grep -qE -- "$pat" <<<"$(producer)"    not  producer | grep -qE "$pat"
#
# Scans every YAML file under .github/ (each bash step runs under pipefail)
# and every tracked shell script that sets pipefail. Comment lines are skipped.
# Run: bash .github/scripts/check-no-pipe-into-grep-q.sh   (exit 0 = clean)
set -euo pipefail

# A `|` that is not half of `||`, optional VAR=value prefixes, grep / egrep /
# fgrep, then - before a `|`, `;`, `&` or `)` ends that command - a short-option
# cluster holding q (-q, -qE, -Eq, -qxF, -iqE ...) or --quiet / --silent.
re='(^|[^|])[|][[:space:]]*([[:alpha:]_][[:alnum:]_]*=[^[:space:]]*[[:space:]]+)*(grep|egrep|fgrep)([[:space:]]+[^|;&)[:space:]]+)*[[:space:]]+(-[[:alpha:]]*q[[:alpha:]]*|--quiet|--silent)([[:space:]]|$)'

scan() { # scan <name> < text : print "<name>:<line>: <text>" for each offending line
  local name="$1" n=0 line
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    if [[ $line =~ ^[[:space:]]*# ]]; then continue; fi
    if [[ $line =~ $re ]]; then printf '%s:%s: %s\n' "$name" "$n" "$line"; fi
  done
}

# Self-test first: a guard whose pattern quietly stopped matching is a green
# light for exactly the flake it exists to stop. `@P@` stands for the pipe
# character so this file does not trip its own scan.
must_flag=(
  '          if ! echo "$out" @P@ grep -qE '\''test result: ok\. 5 passed'\''; then'
  'if printf '\''%s'\'' "$message" @P@ grep -qxE '\''release:[[:space:]]*draft'\''; then'
  '    @P@ grep -qiE '\''fall(s@P@ing)? back to classical'\''; then'
  'x @P@ grep -E -q foo'
  'x @P@ grep -Eq foo'
  'x@P@grep -q foo'
  'x @P@ egrep --quiet foo'
  'x @P@ grep -F --silent foo'
  'x @P@ LC_ALL=C grep -qF -- "$y"'
  'x @P@ grep -qv foo && echo ok'
)
must_pass=(
  'if ! grep -qE '\''test result: ok\. 5 passed'\'' <<<"$out"; then'
  'grep -qE -- "$pat" <<<"$(sed -n 1,9p "$f")"'
  'grep -q foo file @P@@P@ exit 1'
  'x @P@ grep -E foo'
  'n=$(x @P@ grep -c foo)'
  '[ "$(x @P@ grep -c foo)" -eq 0 ]'
  'x @P@ grep foo && [ "$a" -eq 1 ]'
  'x @P@ grep -oE foo; [ "$a" -eq 1 ]'
  '          # never echo "$out" @P@ grep -q foo'
)
selftest_failed=0
for c in "${must_flag[@]}"; do
  if [ -z "$(scan case <<<"${c//@P@/|}")" ]; then
    echo "self-test FAIL: not flagged: ${c//@P@/|}"
    selftest_failed=1
  fi
done
for c in "${must_pass[@]}"; do
  if [ -n "$(scan case <<<"${c//@P@/|}")" ]; then
    echo "self-test FAIL: wrongly flagged: ${c//@P@/|}"
    selftest_failed=1
  fi
done
if [ "$selftest_failed" -ne 0 ]; then
  echo "::error::check-no-pipe-into-grep-q.sh: its own self-test failed - the pattern no longer means what it says"
  exit 1
fi
echo "self-test: ${#must_flag[@]} flagged, ${#must_pass[@]} passed, as expected"

cd "$(git rev-parse --show-toplevel)"
files=()
while IFS= read -r f; do files+=("$f"); done < <(git ls-files -- '.github/*.yml' '.github/*.yaml')
while IFS= read -r f; do
  if grep -q pipefail -- "$f"; then files+=("$f"); fi
done < <(git ls-files -- '*.sh' '*.bash')
if [ "${#files[@]}" -eq 0 ]; then
  echo "::error::check-no-pipe-into-grep-q.sh found no workflow or script to scan - the file list is wrong"
  exit 1
fi

hits=()
for f in "${files[@]}"; do
  while IFS= read -r h; do hits+=("$h"); done < <(scan "$f" < "$f")
done
if [ "${#hits[@]}" -gt 0 ]; then
  for h in "${hits[@]}"; do
    f="${h%%:*}"
    rest="${h#*:}"
    echo "::error file=$f,line=${rest%%:*}::a pipe into grep -q under pipefail SIGPIPE-flakes (MR-2391): write grep -q -- \"\$pat\" <<<\"\$var\""
    printf '%s\n' "$h"
  done
  exit 1
fi
echo "OK: no pipe into grep -q in ${#files[@]} files (workflows + pipefail scripts)"
