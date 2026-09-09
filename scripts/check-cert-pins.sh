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
#                birdo-shared/cert-pins.json, AND the provenance stamp tells the
#                truth about upstream history: the commit it names exists,
#                contains exactly the vendored content, and is (or is not) on
#                birdo-shared main as the stamp claims. SKIPPED when birdo-shared
#                is not checked out alongside - which is EVERY CI run, because
#                birdo-shared is private and this repo is public. Pass
#                --require-upstream to turn that skip into a failure. A skip is
#                reported in the final summary line: a check that did not run
#                must never be mistaken for a check that passed.
#   1b. PROVENANCE  the offline stand-in for check 1, with no cross-repo
#                credential. (a) third_party/cert-pins.json still hashes to the
#                digest the stamp recorded when it was vendored, so a HAND-EDIT
#                of the vendored copy fails on every PR. (b) MERGE ORDER: the
#                stamp must say the vendored commit was on birdo-shared main.
#                Vendoring from an unmerged birdo-shared branch is how a
#                coordinated change gets developed, and this check is RED for
#                exactly that long: a consumer PR cannot go green until the SSOT
#                PR has merged and the copy has been re-vendored and re-stamped
#                from main.
#   2.  DIVERGENCE  every pin file in this repo declares EXACTLY the pin set the
#                SSOT lists for the host it pins. Extra pin, missing pin, or
#                typo => failure, naming the file and the offending hash.
#   2b. OVERLAP  the SSOT's own _enforcement_rule and _overlap_rule, enforced
#                instead of merely asserted - and counted in LINEAGES, not pins.
#                An intermediate and the root that signed it are ONE lineage:
#                when the CA serves the host from a different hierarchy both
#                vanish from the same handshake, so "intermediate + its own
#                root" is one failure that looks like two pins. Every host must
#                present >= 2 live lineages, or carry an explicit, dated,
#                accepted `_overlap_risk` waiver in the SSOT. The waiver is a
#                ratchet in both directions: a host below two lineages without
#                one fails, and a waived host that reaches two also fails, so
#                the debt can neither spread silently nor rot into a permanent
#                excuse.
#   2c. RETIRED   a pin the SSOT has retired must not survive anywhere in this
#                repo - not in a comment, a doc block or a test fixture. Check 2
#                strips comments before it compares (so a dead pin in a comment
#                cannot satisfy it), and that blind spot is real: the six Google
#                sibling intermediates were removed from DOH_PROVIDERS on this
#                branch while all six were still written out in a #[cfg(test)]
#                block in the same file, and every check printed green. 2c reads
#                raw text. scripts/cert_pins_retired.py, rules R1 (retired
#                everywhere -> forbidden everywhere) and R2 (retired for a host,
#                still live for another -> forbidden in the files the SSOT's
#                enforced_by names as that host's pin sites).
#   3.  LIVENESS  for every pinned host, the LIVE certificate chain is fetched
#                and must contain at least one pinned SPKI. This is per-host:
#                a host whose pins have all gone stale fails even if other
#                hosts are fine. The chain this vantage observed is then held
#                against the SSOT's own flags: a presented pin the SSOT marks
#                dormant, two declared lineages inside one presented chain, or
#                a root the SSOT says is presented that was not, is a mislabelled
#                SSOT and fails here. It also names the declared live lineages
#                this vantage did NOT see - one green run is evidence about one
#                anycast edge, never about the host.
#
# WHY 1b EXISTS. The vendored copy WAS hand-edited: its dns.google entry was
# trimmed while birdo-shared carried a different set, and every check reported
# green. Check 2 compares the Rust pin files to the VENDORED copy, so editing
# both leaves them agreeing with each other; check 1 - the only one that
# consults the real SSOT - was skipped because the run happened in a directory
# with no ../birdo-shared. "N pins match SSOT" proved only that doh.rs matched
# the file the same commit rewrote. Check 1b removes that circularity from the
# offline path, and the stamper refuses to write a stamp it cannot verify.
#
# WHY 2b COUNTS LINEAGES. An earlier version counted pins marked in_live_chain
# and required >= 2. "Intermediate + its own root, both presented" satisfied it
# - which is precisely the pre-outage dns.google shape (WR2 + GTS Root R1) that
# went dark on every GTS Root R4 edge, and it green-lit birdo.app (WE1 + GTS
# Root R4) the same way. Counting pins answers the wrong question.
#
# WHERE THE LOGIC LIVES, AND WHY NOT HERE. Checks 2b, 2c and 3 call
# scripts/cert_pins_lineages.py, scripts/cert_pins_retired.py and
# scripts/cert_pins_live_chain.py rather than an inline heredoc, so that
# scripts/test_check_cert_pins.py can run them
# against known-bad fixtures (the pre-outage dns.google shape, a stale waiver,
# a chain that matches only a dormant pin, a shortened chain, Google's
# cross-signed roots) and assert they FAIL. The Cert Pins workflow runs that
# self-test on every PR that touches a pin file. A gate nobody has watched fail
# is a comment with a shell script around it.
#
# Check 3 is the one the old cert-pin-watchdog.yml got wrong. It read only
# cert_pin.rs, ignored the DoH hosts entirely, and failed only when NONE of the
# pins across the whole file matched — so a DoH provider that had migrated CA
# (as cloudflare-dns.com actually had, silently, for months) passed cleanly.
#
# Exit 0 = every check that ran passed. Exit 1 = a real divergence, a dead or
# single-lineage pin set with no waiver, an untruthful stamp, or a vendored copy
# taken from a birdo-shared commit that is not on main (the summary names that
# last case separately, as MERGE ORDER BLOCK, because it is the one failure
# that is fixed in the other repo first).
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
MERGE_ORDER_BLOCK=0
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
  if [ "$MERGE_ORDER_BLOCK" -ne 0 ]; then
    echo "MERGE ORDER BLOCK: third_party/cert-pins.json is vendored from a birdo-shared"
    echo "  commit that was NOT on birdo-shared main when it was stamped (check 1b)."
    echo "  Expected while the birdo-shared PR carrying this pin set is still open."
    echo "  Merge that PR first, then re-vendor + re-stamp from main (steps above)."
    if [ "$FAILED" -eq 0 ]; then
      echo "  Every other check that ran PASSED; this is the only failure."
    fi
  fi
  if [ "$FAILED" -eq 0 ] && [ "$MERGE_ORDER_BLOCK" -eq 0 ]; then
    if [ -n "$SKIPPED" ]; then
      echo "CERT-PIN CHECKS PASSED — WITH SKIPS (see above)"
    else
      echo "ALL CERT-PIN CHECKS PASSED"
    fi
  else
    echo "CERT-PIN CHECKS FAILED" >&2
  fi
}

# One exit path. The merge-order block is a failure for the purposes of the
# exit code (a consumer PR must not merge ahead of the SSOT); it is named
# separately above so nobody reads it as a broken pin set.
finish() {
  summarise
  if [ "$FAILED" -ne 0 ] || [ "$MERGE_ORDER_BLOCK" -ne 0 ]; then
    exit 1
  fi
  exit 0
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
  then ok "third_party/cert-pins.json matches birdo-shared/cert-pins.json (upstream working tree)"
  else fail "third_party/cert-pins.json has DRIFTED from birdo-shared/cert-pins.json — see above"
  fi

  # The stamp against upstream HISTORY. Check 1b (below) can only trust what the
  # stamp says; this is the one place that can test whether the stamp is true.
  # A hand-edited stamp - upstream_commit pointed at some other commit, or
  # upstream_commit_on_main flipped to true - is caught here, and re-running the
  # stamper cannot launder it because the stamper measures the same things.
  if [ -f "$PROVENANCE" ]; then
    "$PY" - "$PROVENANCE" "$(dirname "$UPSTREAM")" <<'PYEOF'
import hashlib, json, re, subprocess, sys

prov_path, updir = sys.argv[1], sys.argv[2]
prov = json.load(open(prov_path, encoding="utf-8"))

def git(*args, timeout=60):
    try:
        return subprocess.run(["git", "-C", updir, *args],
                              capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None

def canonical(text):
    obj = json.loads(text)
    canon = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canon).hexdigest()

commit = str(prov.get("upstream_commit", ""))
if not re.fullmatch(r"[0-9a-f]{40}", commit):
    print("FAIL  provenance upstream_commit %r is not a full 40-hex commit sha - "
          "re-stamp with scripts/stamp-cert-pins-provenance.py" % commit)
    sys.exit(1)

r = git("cat-file", "-e", commit + "^{commit}")
if r is None or r.returncode != 0:
    print("FAIL  provenance names upstream_commit %s, which does not exist in %s. "
          "Either `git -C ../birdo-shared fetch --all`, or the stamp was invented."
          % (commit[:12], updir))
    sys.exit(1)

blob = git("show", commit + ":cert-pins.json")
if blob is None or blob.returncode != 0:
    print("FAIL  birdo-shared@%s has no cert-pins.json" % commit[:12])
    sys.exit(1)
if canonical(blob.stdout) != prov.get("canonical_sha256"):
    print("FAIL  the stamp's upstream_commit %s does NOT contain the vendored content." % commit[:12])
    print("        The stamp was hand-edited, or stamped against the wrong commit.")
    print("        Re-vendor and re-stamp: python3 scripts/stamp-cert-pins-provenance.py")
    sys.exit(1)

fetch = git("fetch", "--quiet", "origin", "main", timeout=90)
fetched = fetch is not None and fetch.returncode == 0
head = git("rev-parse", "--short=12", "origin/main")
head = head.stdout.strip() if head is not None and head.returncode == 0 else "?"
anc = git("merge-base", "--is-ancestor", commit, "origin/main")
on_main = anc is not None and anc.returncode == 0
claimed = prov.get("upstream_commit_on_main")
where = "origin/main@%s%s" % (head, "" if fetched else ", NOT fetched - local ref")
if claimed is not on_main:
    print("FAIL  stamp says upstream_commit_on_main=%r, but birdo-shared %s says %r. "
          "Re-stamp: python3 scripts/stamp-cert-pins-provenance.py"
          % (claimed, where, on_main))
    sys.exit(1)
print("ok    stamp is truthful: upstream_commit %s contains the vendored content and %s "
      "birdo-shared main (%s)"
      % (commit[:12], "IS on" if on_main else "is NOT on", where))
PYEOF
    [ $? -ne 0 ] && FAILED=1
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
import hashlib, json, re, sys

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
    print("      Hand-editing it here is what let 'doh.rs [dns.google] N pins match")
    print("      SSOT' print green while the real SSOT carried a different set.")
    sys.exit(1)

print("ok    third_party/cert-pins.json matches its provenance stamp (" +
      declared[:16] + "...)")

# (b) MERGE ORDER. The stamper measured, at stamp time, whether the vendored
# commit was on birdo-shared main; it refuses to write a stamp it could not
# measure. Here that measurement is the gate: a consumer PR vendored from an
# unmerged SSOT branch stays red until the SSOT lands and the copy is
# re-vendored from main. Otherwise the consumer can merge first, and anyone with
# ../birdo-shared then sees check 1 fail while CI - which cannot see upstream -
# stays green.
commit = str(prov.get("upstream_commit", ""))
if not re.fullmatch(r"[0-9a-f]{40}", commit):
    print("FAIL  the stamp carries no full upstream_commit sha. Re-stamp from a checkout")
    print("      that has ../birdo-shared; the stamper refuses to record provenance it")
    print("      cannot verify, so this cannot be filled in by hand.")
    sys.exit(1)
print("      vendored from %s@%s (%s), stamped %s"
      % (prov.get("upstream_repo"), commit[:12], prov.get("upstream_branch", "?"),
         prov.get("vendored_on", "?")))
on_main = prov.get("upstream_commit_on_main")
if on_main is not True:
    print("FAIL  MERGE ORDER: the vendored copy comes from birdo-shared commit %s, which"
          % commit[:12])
    print("      was NOT on birdo-shared main when it was stamped (upstream_commit_on_main=%r)."
          % (on_main,))
    print("      That is the normal state WHILE an SSOT change is in flight, and this check")
    print("      is red for exactly that long. Do NOT merge this PR yet. Sequence:")
    print("        1. merge the birdo-shared PR that carries this pin set")
    print("        2. git -C ../birdo-shared checkout main && git -C ../birdo-shared pull")
    print("        3. cp ../birdo-shared/cert-pins.json third_party/cert-pins.json")
    print("        4. python3 scripts/stamp-cert-pins-provenance.py   # records on_main: true")
    print("        5. commit BOTH files; this check goes green")
    print("      Run that from the real checkout, never from a temp worktree: only a")
    print("      checkout with ../birdo-shared beside it can stamp.")
    sys.exit(3)
print("ok    merge order: the vendored commit was on birdo-shared main when stamped")
PYEOF
  rc=$?
  if [ "$rc" -eq 3 ]; then
    # Exit code 3 is reserved for the MERGE ORDER block so the summary can say
    # so in words. It is still a failure (exit 1 overall); it is just not a
    # failure anybody can fix in this repo.
    MERGE_ORDER_BLOCK=1
  elif [ "$rc" -ne 0 ]; then
    FAILED=1
  fi
fi

echo
echo "=== 2. pin files vs SSOT (divergence) ==="
"$PY" - "$SSOT" "$REPO_ROOT" <<'PYEOF'
import json, re, sys, os

ssot_path, root = sys.argv[1], sys.argv[2]
ssot = json.load(open(ssot_path, encoding="utf-8"))

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
echo "=== 2b. live lineages per host (_enforcement_rule / _overlap_rule) ==="
# The rule lives in scripts/cert_pins_lineages.py - not inline here - so that
# scripts/test_check_cert_pins.py can run it against known-bad fixtures, the
# exact pre-outage dns.google shape first. A checker nobody has watched fail is
# a comment with a shell script around it. That file's header says why this
# counts LINEAGES and not pins.
"$PY" "$REPO_ROOT/scripts/cert_pins_lineages.py" "$SSOT"
[ $? -ne 0 ] && FAILED=1

echo
echo "=== 2c. retired pins must not survive anywhere (SSOT _removed) ==="
# Reads RAW text, comments included - the opposite of check 2, which strips them.
# The pair is deliberate: check 2 must ignore a commented-out pin so it cannot
# be used to satisfy the declaration, and 2c must see it so it cannot be kept.
"$PY" "$REPO_ROOT/scripts/cert_pins_retired.py" "$SSOT" "$REPO_ROOT"
[ $? -ne 0 ] && FAILED=1

if [ "$OFFLINE" -eq 1 ]; then
  echo
  echo "=== 3. live chain liveness — SKIPPED (--offline) ==="
  skip "check 3 (live chain liveness): --offline"
  echo
  finish
fi

echo
echo "=== 3. live chain liveness (per host, from THIS vantage only) ==="

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

HOSTS=$("$PY" -c "import json,sys;print(' '.join(json.load(open(sys.argv[1], encoding='utf-8'))['hosts']))" "$SSOT")

for host in $HOSTS; do
  addr=$(connect_addr "$host"); sni=$(sni_for "$host")
  # Retry a few times. A transient TCP failure to a third-party anycast address
  # is not a pin defect, and a job that goes red for one is a job people learn
  # to ignore — which is expensive on the one check where a red means a
  # population cannot connect.
  chain=""
  for attempt in 1 2 3; do
    chain=$(echo | openssl s_client -connect "$addr" -servername "$sni" -showcerts 2>/dev/null)
    echo "$chain" | grep -q "BEGIN CERTIFICATE" && break
    [ "$attempt" -lt 3 ] && sleep 3
  done
  if ! echo "$chain" | grep -q "BEGIN CERTIFICATE"; then
    fail "$host: could not retrieve a certificate chain from $addr after 3 attempts"
    continue
  fi

  tmp=$(mktemp -d)
  echo "$chain" | awk -v d="$tmp" '/-----BEGIN CERTIFICATE-----/{n++} n{print > (d "/c" n ".pem")}'
  # One line per presented certificate, in presentation order (leaf first):
  #   <spki sha256 b64> TAB <subject> TAB <issuer>
  observed="$tmp/observed.tsv"
  : > "$observed"
  for f in "$tmp"/c*.pem; do
    [ -f "$f" ] || continue
    h=$(openssl x509 -in "$f" -pubkey -noout 2>/dev/null \
          | openssl pkey -pubin -outform DER 2>/dev/null \
          | openssl dgst -sha256 -binary 2>/dev/null | openssl base64)
    subj=$(openssl x509 -in "$f" -noout -subject 2>/dev/null | sed 's/^subject=//')
    iss=$(openssl x509 -in "$f" -noout -issuer 2>/dev/null | sed 's/^issuer=//')
    [ -n "$h" ] && printf '%s\t%s\t%s\n' "$h" "$subj" "$iss" >> "$observed"
  done

  # The analysis lives in scripts/cert_pins_live_chain.py - not inline here -
  # so that scripts/test_check_cert_pins.py can feed it real measured chains
  # offline, including Google's CROSS-SIGNED roots (subject "GTS Root R1",
  # issuer "GlobalSign Root CA"), which an earlier revision of this block
  # misread as "no root presented" and failed from a vantage that had the
  # whole chain. Presence is decided by SPKI, the thing the pin hashes.
  if ! "$PY" "$REPO_ROOT/scripts/cert_pins_live_chain.py" "$SSOT" "$host" "$observed"; then
    FAILED=1
  fi
  rm -rf "$tmp"

  # Leaf expiry is informational: chain-SPKI pins survive a leaf renewal.
  if [ "$host" = "birdo.app" ]; then
    na=$(echo "$chain" | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//')
    if [ -n "$na" ]; then
      days=$(( ( $(date -u -d "$na" +%s) - $(date -u +%s) ) / 86400 ))
      info "  leaf expires $na ($days days) — FYI only, pins are on the CA chain"
      declared=$("$PY" -c "
import json,sys;print(json.load(open(sys.argv[1], encoding='utf-8'))['hosts']['birdo.app'].get('leaf_expires',''))" "$SSOT")
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
finish
