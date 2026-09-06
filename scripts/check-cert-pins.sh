#!/usr/bin/env bash
#
# check-cert-pins.sh — the mechanism behind the "kept in sync" contract.
#
# Certificate pins are duplicated across several source files in this repo, in
# three different languages. Until now the only thing keeping them equal was a
# doc comment asserting that they were. This script is the enforcement.
#
# It runs FIVE independent checks:
#
#   1.  VENDOR   third_party/cert-pins.json equals the SSOT in
#                birdo-shared/cert-pins.json. SKIPPED when birdo-shared is not
#                checked out alongside - which is EVERY CI run, because
#                birdo-shared is private and this repo is public. Pass
#                --require-upstream to turn that skip into a failure. A skip is
#                reported in the final summary line: a check that did not run
#                must never be mistaken for a check that passed.
#   1b. PROVENANCE  third_party/cert-pins.json still hashes to the digest
#                recorded in third_party/cert-pins.provenance.json when it was
#                vendored. This is check 1 for the offline case: it cannot see
#                what upstream says today, but it makes a HAND-EDIT of the
#                vendored copy fail on every PR, with no cross-repo credential.
#                That hand-edit is a real event, not a hypothetical - see below.
#   2.  DIVERGENCE  every pin file in this repo declares EXACTLY the pin set the
#                SSOT lists for the host it pins. Extra pin, missing pin, or
#                typo => failure, naming the file and the offending hash.
#   2b. OVERLAP  the SSOT's own _enforcement_rule and _overlap_rule, enforced
#                instead of merely asserted: every host must keep at least one
#                pin that is actually PRESENT in the live chain, and at least
#                TWO, so that a single CA-side re-issue cannot take the host
#                dark. Hosts that cannot satisfy the second half today are
#                listed in an explicit debt baseline below, which is a ratchet:
#                the debt cannot spread to a new host, and a host that outgrows
#                it fails until it is removed from the list.
#   3.  LIVENESS  for every pinned host, the LIVE certificate chain is fetched
#                and must contain at least one pinned SPKI. This is per-host:
#                a host whose pins have all gone stale fails even if other
#                hosts are fine.
#
# WHY 1b EXISTS. The vendored copy WAS hand-edited: dns.google was trimmed to 4
# pins while birdo-shared carried 10, and every check reported green. Check 2
# compares the Rust pin files to the VENDORED copy, so editing both leaves them
# agreeing with each other; check 1 - the only one that consults the real SSOT -
# was skipped because the run happened in a directory with no ../birdo-shared.
# "4 pins match SSOT" proved only that doh.rs matched the file the same commit
# rewrote. Check 1b removes that circularity from the offline path.
#
# Check 3 is the one the old cert-pin-watchdog.yml got wrong. It read only
# cert_pin.rs, ignored the DoH hosts entirely, and failed only when NONE of the
# pins across the whole file matched — so a DoH provider that had migrated CA
# (as cloudflare-dns.com actually had, silently, for months) passed cleanly.
#
# Exit 0 = all checks pass. Exit 1 = a real divergence or a dead pin set.
#
# Usage:
#   scripts/check-cert-pins.sh                    # all checks
#   scripts/check-cert-pins.sh --offline          # skip check 3 (no network)
#   scripts/check-cert-pins.sh --require-upstream # check 1 must RUN, not skip
#                                                 # (use it from a real checkout
#                                                 #  that has ../birdo-shared)

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SSOT="$REPO_ROOT/third_party/cert-pins.json"
UPSTREAM="$REPO_ROOT/../birdo-shared/cert-pins.json"

PROVENANCE="$REPO_ROOT/third_party/cert-pins.provenance.json"

OFFLINE=0
REQUIRE_UPSTREAM=0
for arg in "$@"; do
  case "$arg" in
    --offline)          OFFLINE=1 ;;
    --require-upstream) REQUIRE_UPSTREAM=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

FAILED=0
SKIPPED=""
fail() { echo "FAIL  $*" >&2; FAILED=1; }
ok()   { echo "ok    $*"; }
info() { echo "      $*"; }
# A check that could not run is NOT a check that passed. Record it so the final
# summary line names it; a green run that quietly covered less than it looks
# like is how the pin drift survived.
skip() {
  echo "SKIP  $*"
  SKIPPED="${SKIPPED}  - $*
"
}

summarise() {
  if [ -n "$SKIPPED" ]; then
    echo "CHECKS SKIPPED (did NOT run — not the same as passed):"
    printf '%s' "$SKIPPED"
  fi
  if [ "$FAILED" -eq 0 ]; then
    if [ -n "$SKIPPED" ]; then
      echo "CERT-PIN CHECKS PASSED — WITH SKIPS (see above)"
    else
      echo "ALL CERT-PIN CHECKS PASSED"
    fi
  else
    echo "CERT-PIN CHECKS FAILED" >&2
  fi
}

command -v python3 >/dev/null 2>&1 && PY=python3 || PY=python

if [ ! -f "$SSOT" ]; then
  echo "FAIL  vendored SSOT missing: $SSOT" >&2
  exit 1
fi

echo "=== 1. vendored SSOT vs birdo-shared ==="
if [ -f "$UPSTREAM" ]; then
  if "$PY" - "$SSOT" "$UPSTREAM" <<'PYEOF'
import json, sys

# Report WHAT drifted, not just THAT something did. A pin-set difference is a
# security divergence - one of the two sides is enforcing a set the other does
# not - and it is the one that must never merge. A metadata-only difference is a
# re-vendoring chore. Both fail (the contract is re-vendor wholesale, so that a
# reviewer only ever has to trust one file), but they are not the same incident
# and the old single-line "DRIFTED" message could not tell them apart.
a = json.load(open(sys.argv[1], encoding="utf-8"))
b = json.load(open(sys.argv[2], encoding="utf-8"))
if a == b:
    sys.exit(0)

pin_drift = False
for host in sorted(set(a.get("hosts", {})) | set(b.get("hosts", {}))):
    pa = [p["hash"] for p in a.get("hosts", {}).get(host, {}).get("pins", [])]
    pb = [p["hash"] for p in b.get("hosts", {}).get(host, {}).get("pins", [])]
    if set(pa) != set(pb):
        pin_drift = True
        print("        PIN SET DRIFT  " + host + ": vendored has " + str(len(pa)) +
              ", upstream has " + str(len(pb)))
        for h in sorted(set(pb) - set(pa)):
            print("          missing here : " + h)
        for h in sorted(set(pa) - set(pb)):
            print("          extra here   : " + h)

if pin_drift:
    print("        ^ THIS IS THE MERGE BLOCKER: the two repos would enforce")
    print("          different pin sets. Converge them before either PR lands.")
else:
    print("        pin sets are IDENTICAL on every host; only descriptive")
    print("        metadata differs. Re-vendor wholesale anyway - the contract is")
    print("        that this file is a copy, so that one file is the thing to")
    print("        review:")
    print("          cp ../birdo-shared/cert-pins.json third_party/cert-pins.json")
    print("          python3 scripts/stamp-cert-pins-provenance.py")
sys.exit(1)
PYEOF
  then ok "third_party/cert-pins.json matches birdo-shared/cert-pins.json"
  else fail "third_party/cert-pins.json has DRIFTED from birdo-shared/cert-pins.json — see above"
  fi
elif [ "$REQUIRE_UPSTREAM" -eq 1 ]; then
  fail "birdo-shared is not checked out at $UPSTREAM and --require-upstream was given"
else
  skip "check 1 (vendored vs birdo-shared SSOT): birdo-shared not checked out at $UPSTREAM"
  info "check 1b below covers the offline case; run this from a checkout that HAS"
  info "../birdo-shared (a real checkout, not a temp worktree) to compare against"
  info "the real SSOT — that is how the last drift got past this script."
fi

echo
echo "=== 1b. vendored SSOT provenance (offline stand-in for check 1) ==="
if [ ! -f "$PROVENANCE" ]; then
  fail "missing $PROVENANCE — run scripts/stamp-cert-pins-provenance.py"
else
  "$PY" - "$SSOT" "$PROVENANCE" <<'PYEOF'
import hashlib, json, sys

ssot_path, prov_path = sys.argv[1], sys.argv[2]

def canonical_sha256(path):
    obj = json.loads(open(path, encoding="utf-8").read())
    canon = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canon).hexdigest()

prov = json.loads(open(prov_path, encoding="utf-8").read())
declared = prov.get("canonical_sha256")
if not declared:
    print("FAIL  cert-pins.provenance.json carries no canonical_sha256 — the stamp "
          "is the check; an empty stamp is not a pass")
    sys.exit(1)

actual = canonical_sha256(ssot_path)
if actual != declared:
    print("FAIL  third_party/cert-pins.json has been EDITED since it was vendored.")
    print("        declared (provenance): " + declared)
    print("        actual   (this file) : " + actual)
    print("      The vendored copy is NOT where pins are edited. Change the pin set in")
    print("      birdo-shared/cert-pins.json, then re-vendor:")
    print("        cp ../birdo-shared/cert-pins.json third_party/cert-pins.json")
    print("        python3 scripts/stamp-cert-pins-provenance.py")
    print("      Hand-editing it here is what let 'doh.rs [dns.google] 4 pins match")
    print("      SSOT' print green while the real SSOT carried 10.")
    sys.exit(1)

print("ok    third_party/cert-pins.json matches its provenance stamp (" +
      declared[:16] + "...)")
print("      vendored from " + str(prov.get("upstream_repo")) + "@" +
      str(prov.get("upstream_commit", ""))[:12] + "  ref: " + str(prov.get("upstream_ref")))
PYEOF
  [ $? -ne 0 ] && FAILED=1
fi

echo
echo "=== 2. pin files vs SSOT (divergence) ==="
"$PY" - "$SSOT" "$REPO_ROOT" <<'PYEOF'
import json, re, sys, os

ssot_path, root = sys.argv[1], sys.argv[2]
ssot = json.load(open(ssot_path))

B64 = r'[A-Za-z0-9+/]{42,44}='

def strip_line_comments(text, markers=('//',)):
    """Drop comment tails so a retired pin left in a comment cannot satisfy
    the check — the exact hole that lets a 'fixed' pin quietly stay dead."""
    out = []
    for line in text.splitlines():
        for m in markers:
            i = line.find(m)
            if i != -1:
                line = line[:i]
        out.append(line)
    return "\n".join(out)

def strip_xml_comments(text):
    return re.sub(r'<!--.*?-->', '', text, flags=re.S)

def section(text, start_re, end_re):
    m = re.search(start_re, text, re.M)
    if not m:
        return None
    rest = text[m.end():]
    e = re.search(end_re, rest, re.M)
    return rest[:e.start()] if e else None

# Each extractor returns {host: set(pins)} from one file, or None if the file's
# structure could not be parsed (which is itself a failure — a parser that has
# silently stopped matching is indistinguishable from a file with no pins).
def rust_api(text):
    s = section(strip_line_comments(text),
                r'PINNED_SPKI_SHA256\s*:\s*&\[&str\]\s*=\s*&\[', r'^\];')
    return None if s is None else {"birdo.app": set(re.findall(B64, s))}

def rust_doh(text):
    s = section(strip_line_comments(text),
                r'DOH_PROVIDERS\s*:\s*&\[DoHProvider\]\s*=\s*&\[', r'^\];')
    if s is None:
        return None
    out = {}
    for host, body in re.findall(r'host:\s*"([^"]+)".*?pins:\s*&\[(.*?)\]', s, re.S):
        out[host] = set(re.findall(B64, body))
    return out or None

def kotlin_api(text):
    # Kotlin writes OkHttp pins as "sha256/<hash>". Match that prefix explicitly:
    # a bare B64 findall would swallow the '/' of 'sha256/' into the hash.
    s = section(strip_line_comments(text), r'val pins\s*=\s*arrayOf\(', r'^\s*\)')
    if s is None:
        return None
    return {"birdo.app": set(re.findall(r'"sha256/(' + B64 + r')"', s))}

def kotlin_doh(text):
    s = section(strip_line_comments(text),
                r'CertificatePinner\.Builder\(\)', r'\.build\(\)')
    if s is None:
        return None
    out = {}
    for host, pin in re.findall(r'\.add\(\s*"([^"]+)"\s*,\s*"sha256/(' + B64 + r')"', s):
        out.setdefault(host, set()).add(pin)
    return out or None

def swift_api(text):
    s = section(strip_line_comments(text),
                r'static let pins\s*:\s*Set<String>\s*=\s*\[', r'^\s*\]')
    return None if s is None else {"birdo.app": set(re.findall(B64, s))}

def android_xml(text):
    t = strip_xml_comments(text)
    out = {}
    for block in re.findall(r'<domain-config>(.*?)</domain-config>', t, re.S):
        hosts = re.findall(r'<domain[^>]*>([^<]+)</domain>', block)
        pins = set(re.findall(r'<pin[^>]*>\s*(' + B64 + r')\s*</pin>', block))
        for h in hosts:
            out.setdefault(h.strip(), set()).update(pins)
    return out or None

EXTRACTORS = [
    ("src-tauri/src/api/cert_pin.rs",                                       rust_api),
    ("src-tauri/src/vpn/doh.rs",                                            rust_doh),
    ("app/src/main/java/app/birdo/vpn/di/NetworkModule.kt",                 kotlin_api),
    ("app/src/main/java/app/birdo/vpn/data/network/DohResolver.kt",         kotlin_doh),
    ("app/src/main/res/xml/network_security_config.xml",                    android_xml),
    ("iosApp/iosApp/Services/APIClient.swift",                              swift_api),
    ("iosApp/PacketTunnel/PacketTunnelProvider.swift",                      swift_api),
]

expected = {h: {p["hash"] for p in v["pins"]} for h, v in ssot["hosts"].items()}
retired  = {r["hash"] for r in ssot.get("_removed", [])}

seen_any = False
failed = False
for rel, fn in EXTRACTORS:
    path = os.path.join(root, rel)
    if not os.path.exists(path):
        continue
    seen_any = True
    got = fn(open(path, encoding="utf-8").read())
    if got is None:
        print(f"FAIL  {rel}: could not parse the pin declaration - "
              f"the extractor in check-cert-pins.sh needs updating "
              f"(a silently-unparsed file must never pass)")
        failed = True
        continue
    for host, pins in got.items():
        want = expected.get(host)
        if want is None:
            print(f"FAIL  {rel}: pins host '{host}' which the SSOT does not declare")
            failed = True
            continue
        missing, extra = want - pins, pins - want
        if not missing and not extra:
            print(f"ok    {rel} [{host}] {len(pins)} pins match SSOT")
            continue
        failed = True
        for p in sorted(missing):
            print(f"FAIL  {rel} [{host}] MISSING pin {p}")
        for p in sorted(extra):
            note = " (retired in SSOT._removed — delete it here)" if p in retired else ""
            print(f"FAIL  {rel} [{host}] UNKNOWN pin {p}{note}")

if not seen_any:
    print("FAIL  no known pin files found in this repo — is the extractor list stale?")
    failed = True

# ---------------------------------------------------------------------------
# SWEEP: find pin files nobody registered above.
#
# The extractor list is hand-maintained, which is the same weakness that
# produced the drift in the first place: a new file carrying pins is simply
# never looked at, and the check reports green. This sweep walks the repo for
# any file containing a hash the SSOT knows about and fails on any that no
# extractor reads. A pin site the checker cannot see is a pin site that rots.
#
# It is how iosApp/PacketTunnel/PacketTunnelProvider.swift was found: a second,
# FAIL-CLOSED pinning delegate carrying its own stale copy of the pin set.
# ---------------------------------------------------------------------------
known_hashes = set()
for _pins in expected.values():
    known_hashes |= _pins
known_hashes |= retired

covered = {os.path.normpath(rel) for rel, _ in EXTRACTORS}
covered.add(os.path.normpath("third_party/cert-pins.json"))
covered.add(os.path.normpath("scripts/check-cert-pins.sh"))

SKIP_DIRS = {".git", "build", "target", "node_modules", "dist", ".gradle",
             "DerivedData", "Pods", ".idea", "vendor", "third_party"}
TEXT_EXT = {".rs", ".kt", ".kts", ".java", ".swift", ".xml", ".json", ".m",
            ".mm", ".h", ".c", ".cpp", ".ts", ".js", ".py", ".sh", ".yml",
            ".yaml", ".toml", ".md", ".plist", ".gradle", ".properties"}

unregistered = []
for dirpath, dirnames, filenames in os.walk(root):
    dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
    for fn in filenames:
        if os.path.splitext(fn)[1].lower() not in TEXT_EXT:
            continue
        full = os.path.join(dirpath, fn)
        rel = os.path.normpath(os.path.relpath(full, root))
        if rel in covered:
            continue
        try:
            body = open(full, encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        hits = sorted(h for h in known_hashes if h in body)
        if hits:
            unregistered.append((rel, hits))

for rel, hits in unregistered:
    print("FAIL  " + rel + ": contains " + str(len(hits)) + " known certificate "
          "pin(s), but no extractor in check-cert-pins.sh reads this file, so "
          "its pins are never checked against the SSOT. Add an extractor.")
    for h in hits[:3]:
        print("        " + h)
    failed = True

if not unregistered:
    print("ok    sweep: no unregistered pin-bearing files (" +
          str(len(covered) - 2) + " pin files known to the checker)")

sys.exit(1 if failed else 0)
PYEOF
[ $? -ne 0 ] && FAILED=1

echo
echo "=== 2b. effective overlap (_enforcement_rule / _overlap_rule) ==="
"$PY" - "$SSOT" <<'PYEOF'
import json, sys

# The SSOT states two rules in prose that nothing has ever checked:
#
#   _enforcement_rule  "every host MUST keep at least one pin that is present
#                       in the live chain"  (a pin the server never sends is
#                       dormant and can never satisfy today's handshake)
#   _overlap_rule      "every host MUST hold at least one pin from a SECOND
#                       hierarchy ... pinning `intermediate + its own root`
#                       buys no migration safety at all"
#
# Prose is not a control. doh.rs asserted the same thing in a doc comment AND in
# a unit test (`pins.len() >= 2`) while dns.google carried exactly one lineage,
# and both stayed green through the outage: counting PINS answers the wrong
# question. The question that matters is how many INDEPENDENTLY-FAILING
# certificates a pin set can actually match on, which is the number of pins the
# server is observed to present -- `in_live_chain: true`.
#
# So this check counts effective pins per host and requires >= 2. Hosts that
# cannot reach 2 today are named below with the reason. That list is a RATCHET,
# not an exemption pool:
#   * a host NOT on the list with < 2 effective pins fails -> the debt cannot
#     spread silently to a new host, or back to dns.google;
#   * a host ON the list that has reached 2 also fails -> the entry cannot rot
#     into a permanent excuse after the underlying problem is fixed.
#
# Closing either entry means adding a pin the provider could actually rotate to
# (a sibling issuing intermediate), which is a change to birdo-shared/cert-pins.json
# first -- this file is vendored and check 1b refuses local edits.
SINGLE_EFFECTIVE_PIN_DEBT = {
    "cloudflare-dns.com":
        "Serves a SHORTENED chain (leaf + SSL.com SSL Intermediate CA ECC R2, no "
        "root; measured 2026-09-06 via 1.1.1.1 and 104.16.248.249), so of its 3 "
        "pins only the intermediate can ever be presented. The SSL.com root and "
        "the legacy DigiCert High Assurance EV root are both dormant. An SSL.com "
        "intermediate re-issue takes this provider dark with no warning -- the "
        "same shape as the dns.google outage. Fix = pin SSL.com's sibling issuing "
        "intermediates in birdo-shared, not here.",
    "dns.quad9.net":
        "Serves a SHORTENED chain (leaf + DigiCert Global G3 TLS ECC SHA384 2020 "
        "CA1, no root; measured 2026-09-06 via 9.9.9.9), so of its 2 pins only the "
        "intermediate can ever be presented and the DigiCert Global Root G3 pin is "
        "dormant. The SSOT's own note already calls this out: 'RISK - VIOLATES "
        "_overlap_rule ... exactly the shape that took dns.google dark.' Fix = pin "
        "DigiCert's sibling G3 intermediates in birdo-shared, not here.",
}

ssot = json.load(open(sys.argv[1], encoding="utf-8"))
failed = False

for host, entry in sorted(ssot["hosts"].items()):
    pins = entry["pins"]
    missing_flag = [p["hash"] for p in pins if "in_live_chain" not in p]
    if missing_flag:
        print("FAIL  " + host + ": " + str(len(missing_flag)) + " pin(s) carry no "
              "in_live_chain field, so this check cannot tell a live pin from a "
              "dormant one. A control that cannot run must not report green.")
        failed = True
        continue

    effective = [p for p in pins if p["in_live_chain"]]
    n = len(effective)
    debt = SINGLE_EFFECTIVE_PIN_DEBT.get(host)

    if n == 0:
        print("FAIL  " + host + ": NO pin is marked in_live_chain -- every pin is "
              "dormant, so no handshake can ever satisfy this host "
              "(SSOT _enforcement_rule).")
        failed = True
    elif n >= 2 and debt is None:
        print("ok    " + host + ": " + str(n) + " of " + str(len(pins)) +
              " pins are presented in a live chain (>= 2, satisfies _overlap_rule)")
    elif n >= 2 and debt is not None:
        print("FAIL  " + host + ": now has " + str(n) + " effective pins, but it is "
              "still listed in SINGLE_EFFECTIVE_PIN_DEBT in this script. Delete the "
              "entry -- a stale exemption reads as coverage.")
        failed = True
    elif debt is not None:
        print("ok    " + host + ": 1 effective pin of " + str(len(pins)) +
              " -- KNOWN DEBT, single point of failure, tracked here:")
        for line in [debt[i:i + 74] for i in range(0, len(debt), 74)]:
            print("        " + line)
    else:
        print("FAIL  " + host + ": only " + str(n) + " of " + str(len(pins)) +
              " pins is ever presented in the live chain. The others are dormant, "
              "so ONE CA-side re-issue takes this host dark in the same handshake "
              "(SSOT _overlap_rule). Pin a sibling issuing intermediate the "
              "provider could rotate to, or -- if this is knowingly accepted -- add "
              "it to SINGLE_EFFECTIVE_PIN_DEBT in scripts/check-cert-pins.sh with "
              "the reason, so it is visible instead of silent.")
        failed = True

for host in sorted(SINGLE_EFFECTIVE_PIN_DEBT):
    if host not in ssot["hosts"]:
        print("FAIL  SINGLE_EFFECTIVE_PIN_DEBT names '" + host + "', which the SSOT "
              "no longer pins. Remove the entry.")
        failed = True

sys.exit(1 if failed else 0)
PYEOF
[ $? -ne 0 ] && FAILED=1

if [ "$OFFLINE" -eq 1 ]; then
  echo
  echo "=== 3. live chain liveness — SKIPPED (--offline) ==="
  skip "check 3 (live chain liveness): --offline"
  echo
  summarise
  exit $FAILED
fi

echo
echo "=== 3. live chain liveness (per host) ==="

# Hosts to dial, and the SNI/connect address to reach them by. The DoH hosts
# are dialled by a pinned IP because a hostile or captive local resolver can
# point the name anywhere — exactly what happened on the machine this script
# was written on, where cloudflare-dns.com resolved to an ISP landing page.
connect_addr() {
  case "$1" in
    birdo.app)          echo "api.birdo.app:443" ;;
    cloudflare-dns.com) echo "1.1.1.1:443" ;;
    dns.google)         echo "8.8.8.8:443" ;;
    dns.quad9.net)      echo "9.9.9.9:443" ;;
    *)                  echo "$1:443" ;;
  esac
}
sni_for() { [ "$1" = "birdo.app" ] && echo "api.birdo.app" || echo "$1"; }

HOSTS=$("$PY" -c "import json,sys;print(' '.join(json.load(open(sys.argv[1]))['hosts']))" "$SSOT")

for host in $HOSTS; do
  addr=$(connect_addr "$host"); sni=$(sni_for "$host")
  chain=$(echo | openssl s_client -connect "$addr" -servername "$sni" -showcerts 2>/dev/null)
  if ! echo "$chain" | grep -q "BEGIN CERTIFICATE"; then
    fail "$host: could not retrieve a certificate chain from $addr"
    continue
  fi

  tmp=$(mktemp -d)
  echo "$chain" | awk -v d="$tmp" '/-----BEGIN CERTIFICATE-----/{n++} n{print > (d "/c" n ".pem")}'
  live=""
  for f in "$tmp"/c*.pem; do
    [ -f "$f" ] || continue
    h=$(openssl x509 -in "$f" -pubkey -noout 2>/dev/null \
          | openssl pkey -pubin -outform DER 2>/dev/null \
          | openssl dgst -sha256 -binary 2>/dev/null | openssl base64)
    [ -n "$h" ] && live="$live$h"$'\n'
  done
  rm -rf "$tmp"

  pinned=$("$PY" -c "
import json,sys
d=json.load(open(sys.argv[1]))
print('\n'.join(p['hash'] for p in d['hosts'][sys.argv[2]]['pins']))" "$SSOT" "$host")

  match=""
  while IFS= read -r h; do
    [ -z "$h" ] && continue
    if printf '%s\n' "$pinned" | grep -qxF "$h"; then match="$h"; break; fi
  done <<< "$live"

  if [ -n "$match" ]; then
    ok "$host: live chain satisfies pin $match"
  else
    fail "$host: NO pinned SPKI is present in the live chain — clients pinning this host CANNOT CONNECT."
    info "  live chain:  $(echo "$live" | tr '\n' ' ')"
    info "  pinned:      $(echo "$pinned" | tr '\n' ' ')"
    info "  Fix by ADDING the new chain pin to birdo-shared/cert-pins.json and every"
    info "  pin file, shipping it, and only then removing the old one."
  fi

  # Leaf expiry is informational: chain-SPKI pins survive a leaf renewal.
  if [ "$host" = "birdo.app" ]; then
    na=$(echo "$chain" | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//')
    if [ -n "$na" ]; then
      days=$(( ( $(date -u -d "$na" +%s) - $(date -u +%s) ) / 86400 ))
      info "  leaf expires $na ($days days) — FYI only, pins are on the CA chain"
      declared=$("$PY" -c "
import json,sys;print(json.load(open(sys.argv[1]))['hosts']['birdo.app'].get('leaf_expires',''))" "$SSOT")
      actual=$(date -u -d "$na" +%Y-%m-%d)
      # A LEAF RENEWAL IS NOT A FAILURE.
      #
      # This used to fail on any mismatch, which made it fail by itself roughly
      # every 90 days: the leaf auto-renews, `actual` moves forward, and the
      # declared field goes stale through nobody's fault. It held the scheduled
      # run RED for 7+ consecutive days across BOTH client repos while every pin
      # was healthy and every live chain satisfied it — training whoever reads
      # this job to ignore a red cert-pin check, which is the one job where that
      # habit is expensive.
      #
      # The pins are on the CA chain and survive a leaf renewal; this block's own
      # comment says so. So the direction of the change is what carries meaning:
      #
      #   forward  -> a normal renewal. Say the field needs refreshing, pass.
      #   backward -> the live leaf expires SOONER than we recorded. That is not
      #               a renewal; it means the certificate was replaced with a
      #               shorter-lived one. Worth a human. FAIL.
      if [ -n "$declared" ]; then
        d_epoch=$(date -u -d "$declared" +%s 2>/dev/null || echo "")
        a_epoch=$(date -u -d "$actual" +%s 2>/dev/null || echo "")
        if [ -z "$d_epoch" ] || [ -z "$a_epoch" ]; then
          # Never silently skip: an unparseable date means this control did not
          # run, and a check that cannot run must not report green.
          fail "birdo.app: cannot compare leaf expiry (declared='$declared' actual='$actual')"
        elif [ "$a_epoch" -lt "$d_epoch" ]; then
          fail "birdo.app: live leaf expires $actual, EARLIER than the declared $declared — the certificate was replaced with a shorter-lived one, not renewed"
        elif [ "$actual" != "$declared" ]; then
          info "  leaf renewed forward: SSOT says $declared, live is $actual — refresh leaf_expires/leaf_expires_measured in birdo-shared (cosmetic, pins unaffected)"
        fi
      fi
      # Renewal-window warning: the pins survive a renewal, but a leaf that is
      # about to lapse with nobody watching is a real outage in waiting.
      if [ "$days" -lt 21 ]; then
        fail "birdo.app: leaf expires in $days days — inside the renewal window, confirm auto-renewal is working"
      fi
    fi
  fi
done

echo
summarise
exit $FAILED
