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
# Run it from anywhere:  ./scripts/ci/check-pq-features.sh
set -euo pipefail

cd "$(dirname "$0")/../.."
cd src-tauri

fail=0
err() { printf '::error::%s\n' "$*" >&2; fail=1; }
ok() { printf '  OK   %s\n' "$*"; }

# ── 1. The pin is exact, and it is the version we reviewed ────────────────────
WANT_VERSION="0.3.2"
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
  mod_line=$(grep -n 'mod tests {' src/vpn/birdo_pq.rs | cut -d: -f1)
fi
first_use=$(grep -n 'encapsulate_deterministic' src/vpn/birdo_pq.rs | cut -d: -f1 | head -1)
if [ -n "${first_use:-}" ] && [ "$first_use" -lt "$mod_line" ]; then
  err "encapsulate_deterministic is used at src/vpn/birdo_pq.rs:${first_use}, before the #[cfg(test)] mod tests at line ${mod_line} - i.e. in code that is compiled into the release binary."
else
  ok "encapsulate_deterministic is confined to the #[cfg(test)] module"
fi

if [ "$fail" -ne 0 ]; then
  printf '\n::error::PQ gate FAILED\n' >&2
  exit 1
fi
printf '\nPQ gate passed.\n'
