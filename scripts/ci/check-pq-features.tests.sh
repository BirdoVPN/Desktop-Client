#!/usr/bin/env bash
# ============================================================================
# Self-test for scripts/ci/check-pq-features.sh (MR-2422), run by tests.yml
# right after the real gate; the one CI entry point for the gate's tests.
#
# First the gate's own `--self-test` (MR-2403): section 5's claim scan
# against its built-in strings, with no cargo. Section 5's claim wordings
# live there, in claim_must_flag / claim_must_pass; add new ones there.
#
# Then the whole gate, against COPIES of this repo's src-tauri inputs
# (Cargo.toml, Cargo.lock, src/) and a stand-in `cargo` that answers the
# gate's one `cargo tree -e features -i ml-kem` call with the real graph,
# captured once from the real tree. Each case changes one input, and each
# must-fail case must fail with its own rule's message. A gate that can be
# edited into a no-op is worse than none:
#
#   pass  the real tree, unmodified
#   pass  the KAT pin file with CRLF line endings (a Windows checkout of it)
#   fail  1  the ml-kem pin in Cargo.toml is no longer exact (= dropped)
#   fail  2  a PQClean/C KEM crate is back in Cargo.lock (pqcrypto, libcrux)
#   fail  2  ml-kem is gone from the graph (cargo tree fails)
#   fail  2  the graph resolves another ml-kem version, or two of them
#   fail  3  feature "zeroize" or "alloc" missing; "hazmat" enabled
#   fail  4  encapsulate_deterministic used outside birdo_pq.rs, or in its
#            production code; the mod tests boundary gone; the symbol gone
#   fail  5  the fail-closed abort is gone; a wrapped downgrade claim in a
#            new .rs file (the scan is wired to every file under src/)
#   fail  6  Cargo.toml claims the same KEM crate as the Android JNI
#   fail  7  the KAT fixture loses or gains a byte, or gets CRLF endings; the
#            pin moves, names another file, has two lines, or is missing
#
# Usage (needs cargo unless the graph is given; GNU or BSD tools):
#   check-pq-features.tests.sh [src-tauri-dir] [cargo-tree-output-file]
# ============================================================================
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
check="$here/check-pq-features.sh"
src_tauri=${1:-$here/../../src-tauri}
graph_in=${2:-}

base=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
if command -v cygpath >/dev/null 2>&1; then base=$(cygpath -u "$base"); fi
work=$(mktemp -d "${base%/}/pq-features-selftest.XXXXXX")
trap 'rm -rf "$work"' EXIT

failures=0
bad() {
  echo "::error::check-pq-features self-test: $*"
  failures=$((failures + 1))
}
die() {
  echo "::error::check-pq-features self-test: $*"
  exit 1
}

kat=src/vpn/fixtures/birdo-pq-ml-kem-1024.kat.json
for f in Cargo.toml Cargo.lock src/vpn/birdo_pq.rs src/commands/vpn.rs "$kat" "$kat.sha256"; do
  [ -f "$src_tauri/$f" ] || die "$src_tauri/$f is missing - the first argument must be a src-tauri directory"
done

# The gate's built-in section-5 self-test, alone. A cargo that fails loudly
# goes first on PATH: `--self-test` must stop before anything calls cargo.
mkdir -p "$work/no-cargo"
printf '%s\n' '#!/usr/bin/env bash' 'echo "--self-test called cargo $*" >&2' 'exit 3' >"$work/no-cargo/cargo"
chmod +x "$work/no-cargo/cargo"
rc=0
out=$(PATH="$work/no-cargo:$PATH" bash "$check" --self-test 2>&1) || rc=$?
if [ "$rc" -eq 0 ] && grep -qF 'section-5 claim scan self-test:' <<<"$out" && ! grep -qF 'ml-kem pinned' <<<"$out"; then
  echo "ok   pass: --self-test (section 5's claim strings, no cargo)"
else
  bad "check-pq-features.sh --self-test should pass on its own, without reaching section 1; exited $rc:"$'\n'"$out"
fi

# The real graph, once: what the gate's own `cargo tree` call answers.
graph="$work/real-cargo-tree.out"
if [ -n "$graph_in" ]; then
  cp "$graph_in" "$graph"
else
  (cd "$src_tauri" && cargo tree -e features -i ml-kem) >"$graph" ||
    die "cargo tree -e features -i ml-kem failed in $src_tauri"
fi
grep -qE '^ml-kem v[0-9]' "$graph" || die "the captured graph has no 'ml-kem v...' root line: not cargo tree -e features -i ml-kem output"
for f in alloc zeroize; do
  grep -qF "ml-kem feature \"$f\"" "$graph" || die "the real graph lacks ml-kem feature \"$f\"; the real gate fails on that first"
done

# The stand-in cargo. The gate runs it from the fixture's src-tauri copy, so
# ../cargo-tree.out is that fixture's graph. Any other call fails loudly: a
# gate that starts calling cargo differently must update this test on purpose.
mkdir -p "$work/bin"
cat >"$work/bin/cargo" <<'STUB'
#!/usr/bin/env bash
if [ "$*" != "tree -e features -i ml-kem" ]; then
  echo "check-pq-features self-test: the gate made a call the stand-in cargo does not answer: cargo $*" >&2
  exit 2
fi
if [ ! -f ../cargo-tree.out ]; then
  echo 'error: package ID specification `ml-kem` did not match any packages' >&2
  exit 101
fi
cat ../cargo-tree.out
STUB
chmod +x "$work/bin/cargo"

# fixture <name>: $work/<name>/src-tauri = a copy of what the gate reads,
# $work/<name>/cargo-tree.out = the real graph.
fixture() {
  local d="$work/$1"
  mkdir -p "$d/src-tauri"
  cp "$src_tauri/Cargo.toml" "$src_tauri/Cargo.lock" "$d/src-tauri/"
  cp -R "$src_tauri/src" "$d/src-tauri/src"
  cp "$graph" "$d/cargo-tree.out"
}

# mutate <file> <sed -E expr> <text that must (or, with !, must not) be there
# afterwards>: a mutation that silently fails to apply would turn a must-fail
# case into a pass. No `sed -i`: GNU and BSD spell it differently.
mutate() {
  sed -E "$2" "$1" >"$1.mut" && mv "$1.mut" "$1"
  case "$3" in
    '!'*) ! grep -qF -- "${3#!}" "$1" || die "mutation '$2' did not apply to $1" ;;
    *) grep -qF -- "$3" "$1" || die "mutation '$2' did not apply to $1" ;;
  esac
}

# insert_before <file> <ERE> <line>: <line> goes in before the first match.
insert_before() {
  awk -v re="$2" -v line="$3" '!done && $0 ~ re { print line; done = 1 } { print }' "$1" >"$1.mut" && mv "$1.mut" "$1"
  grep -qF -- "$3" "$1" || die "nothing in $1 matches /$2/ to insert before"
}

# to_crlf <file>
to_crlf() {
  awk '{ printf "%s\r\n", $0 }' "$1" >"$1.mut" && mv "$1.mut" "$1"
  grep -q $'\r' "$1" || die "could not convert $1 to CRLF"
}

# expect <pass|fail> <name> [error text the failure must carry]
expect() {
  local want=$1 name=$2 needle=${3:-} out rc=0
  out=$(PATH="$work/bin:$PATH" bash "$check" "$work/$name/src-tauri" 2>&1) || rc=$?
  if [ "$want" = pass ]; then
    if [ "$rc" -eq 0 ]; then echo "ok   pass: $name"; else bad "$name should pass, exited $rc:"$'\n'"$out"; fi
  elif [ "$rc" -eq 0 ]; then
    bad "$name should FAIL the gate but passed:"$'\n'"$out"
  elif ! grep -qF -- "$needle" <<<"$out"; then
    bad "$name failed, but not with '$needle':"$'\n'"$out"
  else
    echo "ok   fail: $name ($needle)"
  fi
}

# Literal Rust, TOML and cargo text in the expressions below, not expansions.
# shellcheck disable=SC2016
{
  fixture unmodified
  expect pass unmodified

  fixture pin-file-crlf
  to_crlf "$work/pin-file-crlf/src-tauri/$kat.sha256"
  expect pass pin-file-crlf

  # ── 1. exact pin ────────────────────────────────────────────────────────
  fixture pin-not-exact
  mutate "$work/pin-not-exact/src-tauri/Cargo.toml" \
    's/^(ml-kem = \{ version = ")=/\1/' '!ml-kem = { version = "='
  expect fail pin-not-exact 'no longer pins ml-kem exactly'

  # ── 2. crate identity ───────────────────────────────────────────────────
  fixture pqclean-in-lock
  printf '\n[[package]]\nname = "pqcrypto-mlkem"\nversion = "0.1.1"\n' >>"$work/pqclean-in-lock/src-tauri/Cargo.lock"
  expect fail pqclean-in-lock 'a PQClean/C KEM crate is back in Cargo.lock'

  fixture libcrux-in-lock
  printf '\n[[package]]\nname = "libcrux-ml-kem"\nversion = "0.0.4"\n' >>"$work/libcrux-in-lock/src-tauri/Cargo.lock"
  expect fail libcrux-in-lock 'a PQClean/C KEM crate is back in Cargo.lock'

  fixture ml-kem-gone
  rm "$work/ml-kem-gone/cargo-tree.out"
  expect fail ml-kem-gone 'ml-kem is not in the dependency graph at all'

  fixture other-version
  mutate "$work/other-version/cargo-tree.out" 's/^ml-kem v[0-9][^ ]*/ml-kem v9.9.9/' 'ml-kem v9.9.9'
  expect fail other-version 'expected exactly one ml-kem v'

  fixture two-versions
  printf 'ml-kem v0.0.1\n' >>"$work/two-versions/cargo-tree.out"
  expect fail two-versions 'expected exactly one ml-kem v'

  # ── 3. features ─────────────────────────────────────────────────────────
  fixture no-zeroize
  mutate "$work/no-zeroize/cargo-tree.out" '/ml-kem feature "zeroize"/d' '!ml-kem feature "zeroize"'
  expect fail no-zeroize 'ml-kem feature "zeroize" is NOT enabled'

  fixture no-alloc
  mutate "$work/no-alloc/cargo-tree.out" '/ml-kem feature "alloc"/d' '!ml-kem feature "alloc"'
  expect fail no-alloc 'ml-kem feature "alloc" is NOT enabled'

  fixture hazmat
  printf '%s\n' '├── ml-kem feature "hazmat"' >>"$work/hazmat/cargo-tree.out"
  expect fail hazmat 'ml-kem feature "hazmat" is enabled'

  # ── 4. deterministic encapsulation stays test-only ──────────────────────
  fixture deterministic-elsewhere
  printf '%s\n' 'pub fn leak(ek: &Ek, m: &M) { let _ = ek.encapsulate_deterministic(m); }' \
    >"$work/deterministic-elsewhere/src-tauri/src/vpn/pq_leak.rs"
  expect fail deterministic-elsewhere 'is referenced outside src/vpn/birdo_pq.rs'

  fixture deterministic-in-production
  insert_before "$work/deterministic-in-production/src-tauri/src/vpn/birdo_pq.rs" '^pub fn ' \
    'pub fn leak(ek: &Ek, m: &M) { let _ = ek.encapsulate_deterministic(m); }'
  expect fail deterministic-in-production 'before the #[cfg(test)] mod tests'

  fixture tests-boundary-gone
  mutate "$work/tests-boundary-gone/src-tauri/src/vpn/birdo_pq.rs" 's/mod tests \{/mod unit_tests {/' '!mod tests {'
  expect fail tests-boundary-gone "could not find the '#[cfg(test)] mod tests' boundary"

  fixture symbol-gone
  mutate "$work/symbol-gone/src-tauri/src/vpn/birdo_pq.rs" 's/encapsulate_deterministic/encapsulate_seeded/g' '!encapsulate_deterministic'
  expect fail symbol-gone 'is not referenced anywhere in src/vpn/birdo_pq.rs'

  # ── 5. fail closed, and no comment that says otherwise ──────────────────
  fixture fails-open
  mutate "$work/fails-open/src-tauri/src/commands/vpn.rs" \
    's/Connection aborted to prevent a silent downgrade\./Connecting without it./' '!Connection aborted to prevent a silent downgrade.'
  expect fail fails-open 'no longer fails closed'

  # The claim wordings are --self-test's (above); this case proves the scan
  # reaches every .rs file under src/ and fails the gate with its message.
  fixture downgrade-claim-new-file
  printf '%s\n' '/// An unusable key makes the client fall back' '/// to the classical PSK.' 'pub fn note() {}' \
    >"$work/downgrade-claim-new-file/src-tauri/src/vpn/pq_note.rs"
  expect fail downgrade-claim-new-file 'a comment claims an unusable or undecapsulatable BirdoPQ key demotes'

  # ── 6. no cross-client crate-identity claim ─────────────────────────────
  fixture parity-claim
  insert_before "$work/parity-claim/src-tauri/Cargo.toml" '^ml-kem = ' '# The same crate as the Android JNI (rosenpass-jni).'
  expect fail parity-claim 'asserts the desktop and mobile clients link the same KEM crate'

  # ── 7. the KAT fixture is the bytes both repos pin (MR-2421) ────────────
  fixture kat-value-changed
  mutate "$work/kat-value-changed/src-tauri/$kat" 's/"sharedSecretB64": "/"sharedSecretB64": "A/' '"sharedSecretB64": "A'
  expect fail kat-value-changed 'not to the sha256 pinned beside it'

  fixture kat-trailing-newline
  printf '\n' >>"$work/kat-trailing-newline/src-tauri/$kat"
  expect fail kat-trailing-newline 'not to the sha256 pinned beside it'

  fixture kat-crlf
  to_crlf "$work/kat-crlf/src-tauri/$kat"
  expect fail kat-crlf 'This copy has CRLF line endings'

  fixture kat-gone
  rm "$work/kat-gone/src-tauri/$kat"
  expect fail kat-gone 'the ML-KEM KAT fixture or its pin is missing'

  fixture pin-moved
  mutate "$work/pin-moved/src-tauri/$kat.sha256" 's/^[0-9a-f]{64}/0000000000000000000000000000000000000000000000000000000000000000/' \
    '0000000000000000000000000000000000000000000000000000000000000000  '
  expect fail pin-moved 'not to the sha256 pinned beside it'

  fixture pin-other-file
  mutate "$work/pin-other-file/src-tauri/$kat.sha256" 's/  birdo-pq-ml-kem-1024\.kat\.json$/  birdo-pq-pqclean-stored-key.json/' \
    '  birdo-pq-pqclean-stored-key.json'
  expect fail pin-other-file 'must hold exactly one'

  fixture pin-two-lines
  grep -E '^[0-9a-f]{64} ' "$src_tauri/$kat.sha256" >>"$work/pin-two-lines/src-tauri/$kat.sha256"
  expect fail pin-two-lines 'must hold exactly one'

  fixture pin-gone
  rm "$work/pin-gone/src-tauri/$kat.sha256"
  expect fail pin-gone 'the ML-KEM KAT fixture or its pin is missing'
}

if [ "$failures" -ne 0 ]; then
  echo "::error::check-pq-features self-test: $failures scenario(s) wrong"
  exit 1
fi
echo "OK - check-pq-features.sh passes the tree and fails every regression scenario"
