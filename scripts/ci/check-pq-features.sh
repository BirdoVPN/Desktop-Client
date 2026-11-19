#!/usr/bin/env bash
#
# PQ dependency + feature gate for src-tauri.
#
# WHY THIS EXISTS
# ---------------
# src-tauri/Cargo.toml says the `zeroize` feature is what makes ml-kem's
# `DecapsulationKey` ZeroizeOnDrop, and that is true: ml-kem 0.3.2 gates BOTH
# `impl Drop` and `impl ZeroizeOnDrop` on `#[cfg(feature = "zeroize")]`
# (src/decapsulation_key.rs:142,156). Nothing enforced it. Review of PR #163
# changed the dependency to `features = ["alloc"]` and every crypto test in
# birdo_pq.rs still passed - no test can observe a Drop that did not happen -
# so a Dependabot edit or a refactor could disarm every decapsulation-key wipe
# with a green build. A security control that only lives in a comment is not a
# control.
#
# The same applies to crate identity: the pqcrypto/PQClean C trio must not come
# back (RUSTSEC-2026-0161/-0162/-0163; PQClean upstream archived read-only
# 2026-08-04), and the ml-kem pin must stay exact, because the KAT in
# src/vpn/fixtures/ is the only thing that would notice an encoding change and
# it only runs if someone is looking.
#
# Modelled on Mobile-Client's scripts/check_pq_features.sh - Desktop-Client had
# no equivalent.
#
# Run it from anywhere:  ./scripts/ci/check-pq-features.sh [src-tauri-dir]
# Only the self-test of section 5's claim scan (no cargo needed):
#                        ./scripts/ci/check-pq-features.sh --self-test
# The directory defaults to this repo's src-tauri. The whole gate's self-test,
# check-pq-features.tests.sh (MR-2422), runs --self-test and then points the
# gate at mutated copies of the tree, one per rule.
set -euo pipefail

case "${1:-}" in
  --self-test) ;; # section 5's built-in strings only: no tree, no cargo
  '') cd "$(dirname "$0")/../../src-tauri" ;;
  *) cd "$1" ;;
esac

fail=0
err() { printf '::error::%s\n' "$*" >&2; fail=1; }
ok() { printf '  OK   %s\n' "$*"; }

# Section 5's claim scan. A file is joined into one line with each line's
# comment leader (`//`, `///`, `//!`, a block comment's `*`) dropped first:
# kept, the leader splits a claim wrapped across doc-comment lines ("falls
# back to the /// classical PSK") and the scan walks past it (MR-2403).
# A here-string, not `... | grep -q` (MR-2391): on a file larger than the
# pipe buffer, grep -q's exit at an early match SIGPIPEs the producer,
# pipefail makes the pipeline fail, and the claim is missed.
downgrade_claim_re='fall(s|ing)? back to (the )?(server.provided )?classical|classical[ -]PSK (fallback|on every connect|for the rest)'
claims_downgrade() { # claims_downgrade < file.rs : exit 0 if it makes the claim
  grep -qiE "$downgrade_claim_re" <<<"$(sed -E 's#^[[:space:]]*(//[/!]?|/?[*]+/?)?##' | tr '\r\n' '  ' | tr -s ' ')"
}

# Self-test it first: a claim scan that quietly stopped matching passes
# exactly the comment it exists to catch. `@N@` is a newline, `@R@` a CR.
claim_must_flag=(
  '/// An unusable identity key falls back to the classical PSK.'
  '/// An unusable identity key falls back to the@N@/// classical PSK.'
  '    //! so the client falls@N@    //! back to classical'
  '// keeps a classical-PSK@N@// fallback for the rest of the session'
  '/* the client falls back@N@ * to the server-provided@N@ * classical PSK */'
  '/// falls back to the@R@@N@/// classical PSK@R@'
  '/*@N@ * a key that fails to decapsulate means the classical@N@ * PSK for the rest of the session.@N@ */'
)
claim_must_pass=(
  '/// A failed decapsulation aborts the connect; it never@N@/// takes the classical PSK.'
  '/// The connect is aborted.@N@///@N@/// Classical X25519 still protects the outer leg.'
  '    // 2) Fall back to the server'\''s classical preshared_key when present.'
)
claim_selftest_failed=0
for c in "${claim_must_flag[@]}"; do
  c="${c//@R@/$'\r'}" c="${c//@N@/$'\n'}"
  if ! claims_downgrade <<<"$c"; then
    printf '::error::claim-scan self-test: not caught: %s\n' "$c" >&2
    claim_selftest_failed=1
  fi
done
for c in "${claim_must_pass[@]}"; do
  c="${c//@R@/$'\r'}" c="${c//@N@/$'\n'}"
  if claims_downgrade <<<"$c"; then
    printf '::error::claim-scan self-test: wrongly caught: %s\n' "$c" >&2
    claim_selftest_failed=1
  fi
done
if [ "$claim_selftest_failed" -ne 0 ]; then
  printf '\n::error::PQ gate FAILED: the section-5 claim scan failed its own self-test\n' >&2
  exit 1
fi
ok "section-5 claim scan self-test: ${#claim_must_flag[@]} caught, ${#claim_must_pass[@]} passed"
if [ "${1:-}" = --self-test ]; then exit 0; fi

# ── 1. The pin is exact, and it is the version we reviewed ────────────────────
WANT_VERSION="0.3.4"
if ! grep -qE '^ml-kem = \{ version = "='"${WANT_VERSION}"'"' Cargo.toml; then
  err "Cargo.toml no longer pins ml-kem exactly to =${WANT_VERSION}. Moving the KEM needs the KAT re-run (cargo test --lib birdo_pq) and a read of ml-kem/CHANGELOG.md, then this line updated deliberately."
else
  ok "ml-kem pinned exactly to =${WANT_VERSION} in Cargo.toml"
fi

# ── 2. No PQClean / C or asm KEM crate may come back ──────────────────────────
banned='pqcrypto|pqcrypto-mlkem|pqcrypto-traits|pqcrypto-internals|oqs|oqs-sys|liboqs-sys|libcrux-ml-kem'
# Checked BEFORE the `cargo tree` below, which regenerates a stale Cargo.lock
# as a side effect and would repair a hand-edited one out from under this
# grep.
if hits=$(grep -nE '^name = "('"$banned"')"' Cargo.lock); then
  err "a PQClean/C KEM crate is back in Cargo.lock: ${hits}. These carry RUSTSEC-2026-0161/-0162/-0163 and PQClean is archived read-only, so no security patch will ever land on that C."
else
  ok "no pqcrypto/liboqs/PQClean KEM crate in Cargo.lock"
fi

# `cargo tree -e features -i <crate>` fails outright if the crate is absent, so
# this doubles as "ml-kem is still the KEM".
#
# Deliberately NOT `--locked`: a commit that drops the "zeroize" feature also
# drops ml-kem's `zeroize` edge from Cargo.lock, and under --locked cargo then
# refuses with a lockfile error instead of letting this script say WHICH
# feature went missing - i.e. the exact mutation the gate exists to name would
# produce its least useful message. Lockfile freshness is already enforced by
# `cargo check --all-targets` in the same job.
if ! tree=$(cargo tree -e features -i ml-kem 2>&1); then
  err "ml-kem is not in the dependency graph at all: ${tree}"
  printf '\n::error::PQ gate FAILED\n' >&2
  exit 1
fi

resolved=$(printf '%s\n' "$tree" | sed -n 's/^ml-kem v\([0-9][^ ]*\).*/\1/p' | sort -u)
if [ "$resolved" != "$WANT_VERSION" ]; then
  err "expected exactly one ml-kem v${WANT_VERSION} in the graph, cargo resolved: [${resolved}]"
else
  ok "graph resolves a single ml-kem v${resolved}"
fi

# ── 3. The feature set the security properties rest on ────────────────────────
#   alloc   - the crate's own default; without it nothing builds
#   zeroize - DecapsulationKey Drop + ZeroizeOnDrop
enabled=$(printf '%s\n' "$tree" \
  | grep -oE 'ml-kem feature "[a-z0-9_-]+"' \
  | sed -E 's/.*"(.*)"/\1/' | sort -u | tr '\n' ' ')
ok "ml-kem features enabled in this graph: [${enabled% }]"

for f in alloc zeroize; do
  case " $enabled " in
    *" $f "*) ok "ml-kem feature \"$f\" is enabled" ;;
    *) err "ml-kem feature \"$f\" is NOT enabled. \"zeroize\" is what makes DecapsulationKey ZeroizeOnDrop and \"alloc\" is the crate's own default; dropping either compiles and passes every test while silently changing what happens to key material." ;;
  esac
done

# `hazmat` gates nothing but rustdoc (ml-kem 0.3.2: `hazmat = []`, used only in
# `#[cfg_attr(not(feature = "hazmat"), doc(hidden))]`), so requesting it cannot
# make a release build safer - but its presence in a manifest reads as if it
# could, which is the false claim this gate was added alongside. Keep it out.
# shellcheck disable=SC2016 # literal Rust in backticks, not an expansion
case " $enabled " in
  *" hazmat "*) err 'ml-kem feature "hazmat" is enabled. It gates ONLY rustdoc visibility of `encapsulate_deterministic` (a plain `pub fn`, compiled in every profile), so declaring it buys nothing and misleads the next reader into thinking deterministic encapsulation cannot reach a release binary. Keeping it out of production is a code-review invariant: the only caller may be the #[cfg(test)] KAT helper.' ;;
  *) ok 'ml-kem feature "hazmat" is absent (it would gate rustdoc only)' ;;
esac

# ── 4. Deterministic encapsulation stays test-only ────────────────────────────
# The invariant `hazmat` was wrongly believed to enforce, enforced for real.
if leaks=$(grep -rn 'encapsulate_deterministic' src/ | grep -v '^src/vpn/birdo_pq.rs:'); then
  err "encapsulate_deterministic is referenced outside src/vpn/birdo_pq.rs: ${leaks}. The client never encapsulates in production (the server does, with @noble/post-quantum); a deterministic encapsulation in a shipping path is a real vulnerability, and NOTHING in the build stops one - the function is a plain pub fn."
else
  ok "encapsulate_deterministic appears only in src/vpn/birdo_pq.rs"
fi
# ... and only inside its #[cfg(test)] module. `mod tests` is the last item in
# that file, so any use before it is production code.
mod_line=$(grep -n '^mod tests {' src/vpn/birdo_pq.rs | cut -d: -f1 || true)
if [ -z "${mod_line:-}" ]; then
  mod_line=$(grep -n 'mod tests {' src/vpn/birdo_pq.rs | cut -d: -f1 || true)
fi
# `|| true` on both: under `set -euo pipefail` a renamed symbol or a moved
# `mod tests` makes grep exit 1, pipefail propagates it, and the script dies
# with a BARE exit 1 - no ::error:: line, no "PQ gate FAILED", nothing in the
# CI log to act on. Fail-closed either way, but a gate that cannot say why it
# failed is a gate nobody fixes. The guards below own the diagnosis.
first_use=$(grep -n 'encapsulate_deterministic' src/vpn/birdo_pq.rs | cut -d: -f1 | head -1 || true)
if [ -z "${mod_line:-}" ]; then
  err "could not find the '#[cfg(test)] mod tests' boundary in src/vpn/birdo_pq.rs, so the confinement check below could not run. If the module was renamed, update this script deliberately."
elif [ -z "${first_use:-}" ]; then
  err "encapsulate_deterministic is not referenced anywhere in src/vpn/birdo_pq.rs. Either the KAT helper that reproduces the backend's own ciphertext is gone - which is how a byte-for-byte check quietly stops being one - or the symbol was renamed. Update this gate deliberately instead of letting it pass on an absent name."
elif [ "$first_use" -lt "$mod_line" ]; then
  err "encapsulate_deterministic is used at src/vpn/birdo_pq.rs:${first_use}, before the #[cfg(test)] mod tests at line ${mod_line} - i.e. in code that is compiled into the release binary."
else
  ok "encapsulate_deterministic is confined to the #[cfg(test)] module"
fi

# ── 5. No comment may promise a downgrade path the code refuses ──────────────
# `commands::vpn::derive_quantum_psk` fails CLOSED: with `quantum_enabled` set
# and `try_decapsulate` returning None it returns Err("... Connection aborted to
# prevent a silent downgrade.") and all three callers propagate it. Round 2 of
# PR #163 justified DISCARDING the user's long-lived ML-KEM identity key at
# three comment sites with the opposite claim - a permanent quiet demotion to
# the server's classical PSK - which cannot happen in either direction (with
# quantum off, try_decapsulate returns at its first line and never opens the
# key file). The re-key is right; the reason was not, and a wrong reason next
# to a destructive action is how the action gets "fixed" away later.
if ! grep -qF 'Post-quantum key exchange failed after the server enabled BirdoPQ. Connection aborted to prevent a silent downgrade.' src/commands/vpn.rs; then
  err "src/commands/vpn.rs no longer fails closed on a failed post-quantum decapsulation. If that is deliberate it is a protocol change, and every comment in src/vpn/birdo_pq.rs explaining the re-key path has to be rewritten with it - then this check removed on purpose."
else
  ok "derive_quantum_psk still aborts the connect when BirdoPQ decapsulation fails"
fi
# File-level, not line-level: these claims are written in wrapped doc comments,
# so a line-anchored grep walks straight past them (claims_downgrade, above,
# joins each file with its comment leaders dropped).
downgrade_claims=""
while IFS= read -r f; do
  if claims_downgrade <"$f"; then
    downgrade_claims="${downgrade_claims} ${f}"
  fi
done < <(find src -name '*.rs')
if [ -n "$downgrade_claims" ]; then
  err "a comment claims an unusable or undecapsulatable BirdoPQ key demotes the client to the classical PSK:${downgrade_claims}. It does not - derive_quantum_psk returns Err and the connect is ABORTED (grep 'classical' in those files). Describe the real consequence."
else
  ok "no comment promises a classical-PSK downgrade that derive_quantum_psk forbids"
fi

# ── 6. The manifest may not assert cross-client crate parity ─────────────────
# When this rule was written (2026-09-16) Mobile-Client's native/rosenpass-jni,
# native/birdo-pq-ios and native/birdo-pq-server were still on pqcrypto-mlkem,
# so "same crate as the Android JNI" was false. They have since moved: at
# Mobile-Client origin/main 827dd9b7 (checked 2026-11-18) all three pin
# `ml-kem = "=0.3.4"` with alloc + zeroize (+ getrandom), as this manifest does.
# The rule stays, because nothing in this repo's CI reads Mobile-Client's
# manifests and Dependabot moves each repo's pin on its own: the sentence would
# be an unchecked claim that goes stale unseen, in the first file a contributor
# reads before touching the KEM. Interoperability rests on the KAT fixture
# (section 7 and the KAT test), not on crate identity.
if parity=$(grep -niE 'same (crate|KEM crate) as the (android|ios|mobile)' Cargo.toml); then
  err "Cargo.toml's AUDIT-C1 comment asserts the desktop and mobile clients link the same KEM crate: ${parity}. Nothing in this repo checks BirdoVPN/Mobile-Client native/*/Cargo.toml, so that sentence would go stale unseen the first time one repo's pin moves without the other. The KAT fixture is the interoperability guarantee, not crate identity."
else
  ok "Cargo.toml does not assert cross-client crate identity"
fi

# ── 7. The KAT fixture is still the one birdo-web pins (MR-2421) ──────────────
# src/vpn/fixtures/birdo-pq-ml-kem-1024.kat.json is a byte copy of birdo-web's
# backend/src/vpn/__fixtures__/ fixture, which the server's own library
# (@noble/post-quantum) produced; the KAT test is only an interop proof while
# the two copies are the same bytes. birdo-web is private and this job reads no
# other repo, so both repos pin ONE sha256 in a .sha256 file next to the
# fixture (the same file in both) and each CI hashes its own copy against it
# (birdo-web: scripts/ci/pq-kat-fixture-pin.mjs). A fixture edited here alone
# fails; moving the pin is a deliberate line that must move in both repos.
kat=src/vpn/fixtures/birdo-pq-ml-kem-1024.kat.json
kat_pin=$kat.sha256
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}
if [ ! -f "$kat" ] || [ ! -f "$kat_pin" ]; then
  err "the ML-KEM KAT fixture or its pin is missing (want both ${kat} and ${kat_pin}). The fixture is the only proof that this client decapsulates what the server's library encapsulates; it cannot go."
else
  # sha256sum format: one "<hash>  <name>" line; # comments and blank lines
  # are skipped, as `sha256sum -c` skips them. CRs are dropped so a CRLF
  # checkout of the pin file still reads.
  pin_lines=$(grep -vE '^[[:space:]]*(#|$)' "$kat_pin" | tr -d '\r' || true)
  pin_count=$(printf '%s\n' "$pin_lines" | grep -c . || true)
  pin_re='^([0-9a-f]{64}) [ *]birdo-pq-ml-kem-1024\.kat\.json$'
  if [ "$pin_count" != 1 ] || ! [[ $pin_lines =~ $pin_re ]]; then
    err "${kat_pin} must hold exactly one '<64 lower-case hex>  birdo-pq-ml-kem-1024.kat.json' line besides # comments (sha256sum format); it has ${pin_count}: [${pin_lines}]"
  else
    want=${BASH_REMATCH[1]}
    got=$(sha256_of "$kat")
    if [ "$got" = "$want" ]; then
      ok "the ML-KEM KAT fixture hashes to the sha256 it shares with birdo-web (${want})"
    else
      crlf=""
      if grep -q $'\r' "$kat"; then
        crlf=" This copy has CRLF line endings: the pin is of the LF bytes git stores, which .gitattributes keeps on a fresh checkout."
      fi
      err "${kat} hashes to ${got}, not to the sha256 pinned beside it (${want}), the same pin birdo-web carries. The fixture is a byte copy of birdo-web's backend/src/vpn/__fixtures__/birdo-pq-ml-kem-1024.kat.json: change it there first, copy it here, and move the pin in BOTH repos (two pull requests that link each other).${crlf}"
    fi
  fi
fi

if [ "$fail" -ne 0 ]; then
  printf '\n::error::PQ gate FAILED\n' >&2
  exit 1
fi
printf '\nPQ gate passed.\n'
