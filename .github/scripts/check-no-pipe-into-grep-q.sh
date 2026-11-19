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
# A command continued onto the next line - a trailing `\`, or a trailing `|` /
# `|&` with only blank or comment lines before the next command - is joined
# first and reported at its first line (MR-2403: a line-by-line scan walked
# past `producer |` + `grep -q pat` on the line below).
# Run: bash .github/scripts/check-no-pipe-into-grep-q.sh   (exit 0 = clean)
# Its test: bash .github/scripts/check-no-pipe-into-grep-q-test.sh
set -euo pipefail

# A `|` or `|&` that is not half of `||`; then any `{` / `(` group openers,
# VAR=value prefixes and wrappers that run their argument as a command
# (command, env, exec, nice, nohup, stdbuf, sudo, time, timeout, xargs - with
# their own options); then grep / egrep / fgrep, also as \grep or by path
# (/usr/bin/grep); then - before a `|`, `;`, `&`, `)` or backtick ends that
# command - an option that turns quiet mode on: a short-option cluster holding
# q after no option that takes an argument (-q, -qE, -Eq, -iqF, -qm1; not the
# pattern `q` of -eq), or --quiet / --silent or a prefix of one (--qui).
assign='[[:alpha:]_][[:alnum:]_]*=[^[:space:]]*'
wrapper='(command|env|exec|nice|nohup|stdbuf|sudo|time|timeout|xargs)([[:space:]]+(-[^[:space:]]*|[0-9][^[:space:]]*|'"$assign"'))*'
re='(^|[^|])[|]&?[[:space:]]*([{(][[:space:]]*|'"$assign"'[[:space:]]+|'"$wrapper"'[[:space:]]+)*'
re+='\\?([^[:space:]|;&()<>`]*/)?(grep|egrep|fgrep)([[:space:]]+[^|;&)`[:space:]]+)*'
re+='[[:space:]]+(-[abcghijklnopqrstuvwxyzEFGHIJKLMNOPQRSTUVWXYZ]*q[^|;&)`[:space:]]*|--(q(u(i(e(t)?)?)?)?|s(i(l(e(n(t)?)?)?)?)?))([[:space:];&|)`]|$)'

# A physical line continues the command when it ends in an odd run of
# backslashes, or in a pipe (then optionally a comment). The `|` of a YAML
# block scalar (`run: |`, `- |-`) is not a pipe: it opens the script.
cont_backslash='(^|[^\\])(\\\\)*\\$'
cont_pipe='(^|[^|])[|]&?[[:space:]]*([[:space:]]#.*)?$'
yaml_block='(:|^[[:space:]]*-)[[:space:]]+[|][-+0-9]*[[:space:]]*([[:space:]]#.*)?$'
blank_or_comment='^[[:space:]]*(#.*)?$'

scan() { # scan <name> < text : print "<name>:<line>: <command>" for each offending command
  local name="$1" n=0 start=0 line cmd="" cont=""
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    line="${line%$'\r'}"
    if [ "$cont" = pipe ] && [[ $line =~ $blank_or_comment ]]; then continue; fi
    if [ -n "$cont" ]; then
      cmd+=" $line"
    elif [[ $line =~ ^[[:space:]]*# ]]; then
      continue
    else
      cmd="$line" start=$n
    fi
    if [[ $line =~ $cont_backslash ]]; then
      cmd="${cmd%\\}" cont=backslash
    elif ! [[ $line =~ $yaml_block ]] && [[ $line =~ $cont_pipe ]]; then
      cmd="${cmd%"${BASH_REMATCH[2]}"}" cont=pipe # drop a trailing comment
    else
      cont=""
      if [[ $cmd =~ $re ]]; then printf '%s:%s: %s\n' "$name" "$start" "$cmd"; fi
    fi
  done
  if [ -n "$cont" ] && [[ $cmd =~ $re ]]; then printf '%s:%s: %s\n' "$name" "$start" "$cmd"; fi
}

# Self-test first: a guard whose pattern quietly stopped matching is a green
# light for exactly the flake it exists to stop. `@P@` stands for the pipe
# character and `@N@` for a newline, so this file does not trip its own scan.
# The full fixture matrix, run end to end, is check-no-pipe-into-grep-q-test.sh.
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
  'x \@N@  @P@ grep -q foo'
  'x @P@ \@N@  grep -q foo'
  'x @P@@N@  grep -q foo'
  'x @P@ # why@N@@N@  # and why not@N@  grep -q foo'
  'x @P@& grep -q foo'
  'x @P@ command grep -q foo'
  'x @P@ \grep -q foo'
  'x @P@ /usr/bin/grep -q foo'
  'x @P@ { grep -q foo; }'
  'x @P@ xargs -r grep -q foo'
  'x @P@ grep --qui foo'
  'x @P@ grep -qm1 foo'
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
  '[ `x @P@ grep -c foo` -eq 0 ]'
  'x @P@ grep -e q foo'
  'grep -q foo < <(x)'
  'x @P@@P@ \@N@  grep -q foo file'
  '# see x @P@@N@grep -q foo file'
  '      - run: @P@@N@          grep -q foo file'
  '  - @P@-@N@    grep -q foo file'
)
selftest_failed=0
for c in "${must_flag[@]}"; do
  c="${c//@P@/|}" c="${c//@N@/$'\n'}"
  if [ -z "$(scan case <<<"$c")" ]; then
    echo "self-test FAIL: not flagged: $c"
    selftest_failed=1
  fi
done
for c in "${must_pass[@]}"; do
  c="${c//@P@/|}" c="${c//@N@/$'\n'}"
  if [ -n "$(scan case <<<"$c")" ]; then
    echo "self-test FAIL: wrongly flagged: $c"
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
