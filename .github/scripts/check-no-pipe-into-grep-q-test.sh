#!/usr/bin/env bash
# Test for check-no-pipe-into-grep-q.sh (MR-2391, MR-2403), end to end: it
# writes each fixture as its own workflow or pipefail script in one of two
# throwaway git repos, runs the guard once in each, and checks the verdict
# per file - every "flag" fixture reported at the line its command starts on,
# no "pass" fixture reported at all, exit 1 and exit 0.
# Run: bash .github/scripts/check-no-pipe-into-grep-q-test.sh   (exit 0 = all passed)
# GUARD=<path> runs the same fixtures against another copy of the guard.
#
# In the fixture bodies `@P@` is a pipe and `@N@` a newline: spelled out, this
# file would trip the guard it tests (it sets pipefail, so the guard scans it).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
guard="${GUARD:-$here/check-no-pipe-into-grep-q.sh}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null

n=0
c_set=() c_file=() c_line=() c_name=()
# add <flag|pass> <name> <kind> <line> <body>
#   kind: sh / bash - a script that sets pipefail (2 header lines); nopf - a
#   script that does not; crlf - an sh script checked out with CRLF; yml - a
#   workflow (6 header lines) whose body is the step's `run: |` script.
#   line: the body line the offending command starts on ("-" for pass).
add() {
  local set="$1" name="$2" kind="$3" line="$4" body="$5" file offset=2 l
  n=$((n + 1))
  body="${body//@P@/|}" body="${body//@N@/$'\n'}"
  case "$kind" in
    yml) file=".github/workflows/f$n.yml" offset=6 ;;
    bash) file="scripts/f$n.bash" ;;
    *) file="scripts/f$n.sh" ;;
  esac
  mkdir -p "$work/$set/$(dirname "$file")"
  {
    case "$kind" in
      yml)
        printf '%s\n' 'on: push' 'jobs:' '  t:' '    runs-on: ubuntu-24.04' '    steps:' '      - run: |'
        while IFS= read -r l; do printf '          %s\n' "$l"; done <<<"$body"
        ;;
      nopf) printf '%s\n' '#!/usr/bin/env bash' "$body" ;;
      *) printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' "$body" ;;
    esac
  } >"$work/$set/$file"
  if [ "$kind" = crlf ]; then
    awk '{ printf "%s\r\n", $0 }' "$work/$set/$file" >"$work/crlf.tmp"
    mv "$work/crlf.tmp" "$work/$set/$file"
  fi
  c_set+=("$set") c_file+=("$file") c_name+=("$name")
  if [ "$line" = - ]; then c_line+=(-); else c_line+=("$((offset + line))"); fi
}

# ── Must flag ─────────────────────────────────────────────────────────────────
add flag "single-line pipe" sh 1 'echo "$out" @P@ grep -q ok'
add flag "single-line pipe in a workflow" yml 1 'echo "$out" @P@ grep -q ok'
add flag "-qE" sh 1 'echo "$out" @P@ grep -qE "ok$"'
add flag "-Eq" sh 1 'echo "$out" @P@ grep -Eq "ok$"'
add flag "-E -q" sh 1 'echo "$out" @P@ grep -E -q "ok$"'
add flag "-iqF cluster" sh 1 'echo "$out" @P@ grep -iqF ok'
add flag "--quiet" sh 1 'echo "$out" @P@ grep --quiet ok'
add flag "--silent" sh 1 'echo "$out" @P@ grep -F --silent ok'
add flag "--qui (a prefix getopt accepts)" sh 1 'echo "$out" @P@ grep --qui ok'
add flag "-qm1 (q, then an option with its argument)" sh 1 'echo "$out" @P@ grep -qm1 ok'
add flag "egrep -q" sh 1 'echo "$out" @P@ egrep -q "ok$"'
add flag "fgrep --quiet" sh 1 'echo "$out" @P@ fgrep --quiet ok'
add flag "backslash continuation, pipe on the next line" sh 1 'echo "$out" \@N@  @P@ grep -q ok'
add flag "backslash continuation after the pipe" sh 1 'echo "$out" @P@ \@N@  grep -q ok'
add flag "trailing pipe" sh 1 'echo "$out" @P@@N@  grep -q ok'
add flag "trailing |&" sh 1 'cargo test @P@&@N@  grep -q ok'
add flag "trailing pipe, then comment and blank lines" sh 1 'cat big.log @P@  # first reason@N@@N@  # second reason@N@  grep -q ok'
add flag "three-line pipeline" sh 1 'cat big.log \@N@  @P@ tr -d x \@N@  @P@ grep -qE ok'
add flag "-q on a continuation line of grep's own options" sh 1 'echo "$out" @P@ grep -E \@N@  -q ok'
add flag "trailing pipe in a run: | block" yml 2 'out=$(cargo test 2>&1)@N@echo "$out" @P@@N@  grep -qE ok'
add flag "continuation in a CRLF checkout" crlf 1 'echo "$out" \@N@  @P@ grep -q ok'
add flag "negated" sh 1 'if ! echo "$out" @P@ grep -q ok; then exit 1; fi'
add flag "negated, continued, in a workflow" yml 1 'if ! echo "$out" @P@@N@    grep -qE ok; then@N@  exit 1@N@fi'
add flag "|& (stderr too)" sh 1 'cargo test @P@& grep -q ok'
add flag "command grep" sh 1 'echo "$out" @P@ command grep -q ok'
add flag "\\grep" sh 1 'echo "$out" @P@ \grep -q ok'
add flag "/usr/bin/grep" sh 1 'echo "$out" @P@ /usr/bin/grep -q ok'
add flag "env VAR=value grep" sh 1 'echo "$out" @P@ env LC_ALL=C grep -q ok'
add flag "VAR=value grep" sh 1 'echo "$out" @P@ LC_ALL=C grep -qF -- "$want"'
add flag "{ grep -q; }" sh 1 'echo "$out" @P@ { grep -q ok; }'
add flag "( grep -q )" sh 1 'echo "$out" @P@ (grep -q ok)'
add flag "xargs grep -q" sh 1 'find . -name "*.log" @P@ xargs grep -q ok'
add flag "xargs with options" sh 1 'find . -name "*.log" -print0 @P@ xargs -0 -r grep -q ok'
add flag "inside a command substitution" sh 1 'seen=$(echo "$out" @P@ grep -q ok && echo yes)'
add flag "a .bash script" bash 1 'echo "$out" @P@ grep -q ok'

# ── Must pass ─────────────────────────────────────────────────────────────────
add pass "here-string" sh - 'grep -q ok <<<"$out"'
add pass "negated here-string" sh - 'if ! grep -qE "ok$" <<<"$out"; then exit 1; fi'
add pass "here-string of a producer" sh - 'grep -qE ok <<<"$(cargo test 2>&1)"'
add pass "here-string in a workflow" yml - 'if ! grep -qE "ok$" <<<"$out"; then@N@  exit 1@N@fi'
add pass "file operand" sh - 'grep -q ok out.log'
add pass "redirected file" sh - 'grep -q ok < out.log'
add pass "negated file operand" sh - '! grep -q ok out.log'
add pass "process substitution" sh - 'grep -q ok < <(cargo test)'
add pass "[[ == ]] match" sh - '[[ $out == *ok* ]]'
add pass "or-list, not a pipe" sh - 'grep -q ok out.log @P@@P@ exit 1'
add pass "continued or-list" sh - 'grep -q ok out.log @P@@P@ \@N@  exit 1'
add pass "pipe into grep -c" sh - 'n=$(echo "$out" @P@ grep -c ok)'
add pass "pipe into grep, then a test with -eq" sh - 'echo "$out" @P@ grep -E ok && [ "$a" -eq 1 ]'
add pass "backtick substitution, then -eq" sh - '[ `echo "$out" @P@ grep -c ok` -eq 0 ]'
add pass "-eq is the pattern q, not quiet" sh - 'echo "$out" @P@ grep -c -eq'
add pass "a command that only ends in grep" sh - 'echo "$out" @P@ mygrep -q ok'
add pass "comment line" sh - '# never: echo "$out" @P@ grep -q ok'
add pass "a comment ending in a pipe does not continue" sh - '# echo "$out" @P@@N@grep -q ok out.log'
add pass "run: | is a block scalar, not a pipe" yml - 'grep -q ok out.log'
add pass "markdown table rows in a heredoc" sh - 'cat <<EOF@N@@P@ a @P@ b @P@@N@@P@---@P@---@P@@N@EOF@N@grep -q ok out.log'
add pass "a script without pipefail is not scanned" nopf - 'echo "$out" @P@ grep -q ok'

fail=0
for set in flag pass; do
  git init -q "$work/$set"
  git -C "$work/$set" add -A
  rc=0
  (cd "$work/$set" && bash "$guard") >"$work/$set.out" 2>&1 || rc=$?
  want=1
  if [ "$set" = pass ]; then want=0; fi
  if [ "$rc" -ne "$want" ]; then
    echo "FAIL: guard exit $rc over the $set fixtures, wanted $want"
    sed 's/^/    /' "$work/$set.out"
    fail=1
  fi
done
flag_hits=$'\n'"$(cat "$work/flag.out")"$'\n'
pass_hits=$'\n'"$(cat "$work/pass.out")"$'\n'

for i in "${!c_set[@]}"; do
  set="${c_set[$i]}" file="${c_file[$i]}" line="${c_line[$i]}" name="${c_name[$i]}"
  if [ "$set" = flag ]; then
    if [[ $flag_hits == *$'\n'"$file:$line: "* ]]; then
      echo "ok:   flags  $name"
    else
      echo "FAIL: flags  $name - $file:$line not reported"
      fail=1
    fi
  else
    if [[ $pass_hits == *$'\n'"$file:"* ]]; then
      echo "FAIL: passes $name - $file wrongly reported"
      fail=1
    else
      echo "ok:   passes $name"
    fi
  fi
done

[ "$fail" -eq 0 ] && echo "all passed (${#c_set[@]} fixtures)"
exit "$fail"
