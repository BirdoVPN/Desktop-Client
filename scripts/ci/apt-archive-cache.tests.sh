#!/usr/bin/env bash
# ============================================================================
# Self-test for scripts/ci/apt-archive-cache.sh (the Linux test jobs' .deb
# archive cache, MR-2347). apt installs a cached archive on its size alone, so
# the stage step's hash check is the whole of the trust; prove it refuses
# what it must, with fake archives in temp directories (no apt, no root):
#
#   stage    an archive matching the plan        -> staged, byte-identical
#            same size, different bytes           -> refused (the case apt's
#                                                    own size check accepts)
#            a symlink to a matching archive      -> refused
#            planned but not in the cache         -> left for apt
#            in the cache but not in the plan     -> ignored
#            no restored directory / no plan      -> stages nothing, exit 0
#   parse    the SHA256 print-uris line           -> plan line
#            MD5Sum / SHA512 / no hash            -> exit 1 (never trusted)
#            a file name with a slash or ..       -> exit 1
#            no lines at all                      -> exit 1
#   collect  every planned archive present        -> complete=true
#            one missing or altered               -> complete=false
#   packages the list read from linux-deps        -> plan refuses a bad name
# ============================================================================
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
cache_sh="$here/apt-archive-cache.sh"
[ -f "$cache_sh" ] || { echo "::error::script missing: $cache_sh"; exit 1; }

work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/apt-cache-selftest.XXXXXX")"
trap 'rm -rf "$work"' EXIT

fail=0
check() { # check <description> <command...>
  local d="$1"
  shift
  if "$@"; then
    echo "ok    $d"
  else
    echo "::error::apt-archive-cache self-test: $d"
    fail=1
  fi
}
sha() { sha256sum "$1" | cut -d' ' -f1; }

restored="$work/restored"
dest="$work/archives"
mkdir -p "$restored" "$dest"
printf 'good archive bytes\n' >"$restored/good_1.0_amd64.deb"
printf 'what the index says\n' >"$work/expected-bad"
printf 'what the cache says\n' >"$restored/bad_2%3a1.0_amd64.deb" # same length, other bytes
printf 'linked archive\n' >"$work/link-target"
ln -s "$work/link-target" "$restored/link_1.0_amd64.deb"
printf 'not planned\n' >"$restored/extra_1.0_amd64.deb"

plan="$work/plan.txt"
{
  echo "good_1.0_amd64.deb 19 $(sha "$restored/good_1.0_amd64.deb")"
  echo "bad_2%3a1.0_amd64.deb 20 $(sha "$work/expected-bad")"
  echo "link_1.0_amd64.deb 15 $(sha "$work/link-target")"
  echo "absent_1.0_amd64.deb 7 $(printf 'absent\n' | sha256sum | cut -d' ' -f1)"
} >"$plan"

run() { APT_PLAN="$plan" APT_ARCHIVES="$dest" RUNNER_TEMP="$work" GITHUB_OUTPUT="$work/output" bash "$cache_sh" "$@"; }

# -- stage ---------------------------------------------------------------------
log=$(run stage "$restored")
echo "$log"
check "the matching archive is staged" test -f "$dest/good_1.0_amd64.deb"
check "the staged archive is byte-identical" cmp -s "$restored/good_1.0_amd64.deb" "$dest/good_1.0_amd64.deb"
check "same size, other bytes: refused" test ! -e "$dest/bad_2%3a1.0_amd64.deb"
check "a symlink: refused" test ! -e "$dest/link_1.0_amd64.deb"
check "an archive the plan does not name: ignored" test ! -e "$dest/extra_1.0_amd64.deb"
check "no verification copy left behind" test -z "$(find "$dest" -name '.birdo-verify.*')"
check "the summary counts 1 staged, 1 rejected, 2 not in the cache" grep -qF "1 verified and staged, 1 rejected, 2 not in the cache" <<<"$log"
check "no restored directory: exit 0, nothing staged" run stage "$work/does-not-exist"
check "no plan: exit 0, nothing staged" env APT_PLAN="$work/no-plan" APT_ARCHIVES="$dest" RUNNER_TEMP="$work" bash "$cache_sh" stage "$restored"

# -- parse ---------------------------------------------------------------------
h=$(printf 'x' | sha256sum | cut -d' ' -f1)
good_line="'http://azure.archive.ubuntu.com/ubuntu/pool/main/p/patchelf/patchelf_0.18.0-1.1build1_amd64.deb' patchelf_0.18.0-1.1build1_amd64.deb 104544 SHA256:$h"
parsed=$(run parse <<<"$good_line")
check "parse: a SHA256 line becomes a plan line" test "$parsed" = "patchelf_0.18.0-1.1build1_amd64.deb 104544 $h"
check "parse: an epoch's %3a is kept" run parse <<<"'http://x/pool/a_1%3a2.0_amd64.deb' a_1%3a2.0_amd64.deb 5 SHA256:$h"
refuse() { ! run parse <<<"$1" >/dev/null 2>&1; }
check "parse: MD5Sum refused" refuse "'http://x/a.deb' a_1_amd64.deb 5 MD5Sum:0123456789abcdef0123456789abcdef"
check "parse: SHA512 refused" refuse "'http://x/a.deb' a_1_amd64.deb 5 SHA512:$h$h"
check "parse: no hash refused" refuse "'http://x/a.deb' a_1_amd64.deb 5 "
check "parse: a path refused" refuse "'http://x/a.deb' ../a_1_amd64.deb 5 SHA256:$h"
check "parse: a leading dot refused" refuse "'http://x/a.deb' .._amd64.deb 5 SHA256:$h"
check "parse: one bad line fails the whole parse" refuse "$good_line"$'\n'"'http://x/b.deb' b_1_amd64.deb 5 MD5Sum:0123456789abcdef0123456789abcdef"
check "parse: no lines refused" refuse ""

# -- collect -------------------------------------------------------------------
cplan="$work/collect-plan.txt"
held="$work/held"
mkdir -p "$held"
printf 'one\n' >"$held/one_1_amd64.deb"
printf 'two\n' >"$held/two_1_amd64.deb"
{
  echo "one_1_amd64.deb 4 $(sha "$held/one_1_amd64.deb")"
  echo "two_1_amd64.deb 4 $(sha "$held/two_1_amd64.deb")"
} >"$cplan"
collect() { APT_PLAN="$cplan" APT_ARCHIVES="$held" RUNNER_TEMP="$work" GITHUB_OUTPUT="$work/collect-output" bash "$cache_sh" collect "$work/out"; }
: >"$work/collect-output"
collect >/dev/null
check "collect: all present -> complete=true" grep -qxF "complete=true" "$work/collect-output"
check "collect: the archives are in the cache directory" cmp -s "$held/two_1_amd64.deb" "$work/out/two_1_amd64.deb"
printf 'TWO\n' >"$held/two_1_amd64.deb"
: >"$work/collect-output"
collect >/dev/null
check "collect: an altered archive -> complete=false" grep -qxF "complete=false" "$work/collect-output"
check "collect: the altered archive is not kept" test ! -e "$work/out/two_1_amd64.deb"
rm -f "$held/two_1_amd64.deb"
: >"$work/collect-output"
collect >/dev/null
check "collect: a missing archive -> complete=false" grep -qxF "complete=false" "$work/collect-output"

# -- plan: the package list --------------------------------------------------------
# plan reads linux-deps' list before it touches apt; a name that is not a
# package name turns the cache off (key empty) instead of reaching apt-get.
fake_deps="$work/linux-deps.yml"
printf '%s\n' '      run: |' '        sudo apt-get -o Acquire::Retries=3 install -y \' '          libgtk-3-dev \' '          "$(evil)"' >"$fake_deps"
: >"$work/plan-output"
APT_PLAN="$work/p.txt" RUNNER_TEMP="$work" GITHUB_OUTPUT="$work/plan-output" LINUX_DEPS="$fake_deps" bash "$cache_sh" plan >/dev/null
check "plan: a bad package name -> key empty, exit 0" grep -qxF "key=" "$work/plan-output"
: >"$work/plan-output"
APT_PLAN="$work/p.txt" RUNNER_TEMP="$work" GITHUB_OUTPUT="$work/plan-output" LINUX_DEPS="$work/missing.yml" bash "$cache_sh" plan >/dev/null 2>&1
check "plan: no linux-deps list -> key empty, exit 0" grep -qxF "key=" "$work/plan-output"
# The real file, through the script's own reader: its list must parse, or
# every test job would silently run uncached.
mapfile -t real < <(LINUX_DEPS="$here/../../.github/actions/linux-deps/action.yml" RUNNER_TEMP="$work" bash "$cache_sh" packages)
bad_names=0
for p in "${real[@]}"; do [[ $p =~ ^[a-z0-9][a-z0-9.+-]*$ ]] || bad_names=1; done
check "the real linux-deps list parses (${#real[@]} packages: ${real[*]})" test "${#real[@]}" -ge 5 -a "$bad_names" -eq 0

if [ "$fail" -ne 0 ]; then
  echo "::error::apt-archive-cache.tests.sh: at least one case failed - see above"
  exit 1
fi
echo "apt-archive-cache self-test: all cases passed"
