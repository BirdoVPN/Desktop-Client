#!/usr/bin/env python3
"""test_check_cert_pins.py - proves checks 2b and 3 of scripts/check-cert-pins.sh
still fail the shapes they exist to fail.

A checker nobody has watched fail is a comment with a shell script around it.
Every case below mutates a copy of the vendored SSOT (third_party/cert-pins.json)
or feeds a real measured chain to the check, and asserts BOTH the verdict and
the words it is reported in. The first case in each group is the committed
file itself. No hash is written down here: every pin is looked up in the SSOT
by lineage and role, so check 2's sweep for unregistered pin-bearing files has
nothing to find, and a pin change upstream cannot silently un-test a fixture.

The case that matters most is PRE_OUTAGE: dns.google exactly as it shipped
before 2026-09-06 - WR2 + GTS Root R1, both live, ONE lineage. An earlier
revision of check 2b counted pins marked in_live_chain and printed
"2 of 2 ... satisfies _overlap_rule" for that file, while every user reaching a
GTS Root R4 edge could not connect. It must fail, and it must keep failing.

The second most important is CROSS_SIGNED_ROOT: Google serves its roots
cross-signed (subject "GTS Root R1", issuer "GlobalSign Root CA"; measured
2026-09-08 from a UK consumer ISP and the production hub), so no certificate
in that chain is self-signed. An earlier revision of check 3 looked for a
self-signed certificate to decide whether the root was presented, and failed
both dns.google and birdo.app from a vantage that had the whole chain. The
root's public key - the thing the pin hashes - is right there; presence is
decided by SPKI.

Runs on every PR that touches a pin file (cert-pins.yml, job `divergence`,
step `test_check_cert_pins.py`), and locally with

    python3 scripts/test_check_cert_pins.py

Needs only python3; no third-party modules and no network.
"""
import copy
import datetime
import importlib.util
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SSOT = os.path.join(ROOT, "third_party", "cert-pins.json")


def load_module(name):
    path = os.path.join(ROOT, "scripts", name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


lineages = load_module("cert_pins_lineages")
live_chain = load_module("cert_pins_live_chain")

with open(SSOT, encoding="utf-8") as fh:
    BASE = json.load(fh)

# A fixed "today" so a waiver fixture with review_by 2099 never expires and one
# with review_by 2025 is always in the past, whatever the runner's clock says.
TODAY = datetime.date(2026, 9, 8)


# ---------------------------------------------------------------- pin lookup
def pin(host, lineage=None, role=None, live=None):
    """The one pin in `host` matching every given attribute; a fixture that
    cannot find its pin is a fixture describing a different file, so fail loudly."""
    found = []
    for p in BASE["hosts"][host]["pins"]:
        if lineage is not None and p.get("lineage") != lineage:
            continue
        if role is not None and p.get("role") != role:
            continue
        if live is not None and p.get("in_live_chain") is not live:
            continue
        found.append(copy.deepcopy(p))
    if len(found) != 1:
        raise AssertionError("expected exactly one pin in %s with lineage=%r role=%r live=%r, "
                             "found %d" % (host, lineage, role, live, len(found)))
    return found[0]


WR2 = pin("dns.google", lineage="gts-r1", role="active-intermediate")
R1 = pin("dns.google", lineage="gts-r1", role="active-root")
WE2 = pin("dns.google", lineage="gts-r4", role="active-intermediate")
R4 = pin("dns.google", lineage="gts-r4", role="active-root")
CF_ECC_R2 = pin("cloudflare-dns.com", lineage="sslcom-ecc", role="active-intermediate")
CF_ROOT = pin("cloudflare-dns.com", lineage="sslcom-ecc", role="dormant-backup")
Q9_CA1 = pin("dns.quad9.net", lineage="digicert-global-g3", role="active-intermediate")
WE1 = pin("birdo.app", lineage="gts-r4", role="active-intermediate")
BIRDO_R4 = pin("birdo.app", lineage="gts-r4", role="active-root")
ISRG_X1 = pin("birdo.app", lineage="isrg-x1", role="dormant-backup", live=False) \
    if len([p for p in BASE["hosts"]["birdo.app"]["pins"] if p["lineage"] == "isrg-x1"]) == 1 \
    else next(copy.deepcopy(p) for p in BASE["hosts"]["birdo.app"]["pins"]
              if p["lineage"] == "isrg-x1" and "ISRG Root X1" in p["label"])

# Leaf SPKIs as measured (they rotate; they are here only as "a hash the pin
# set must NOT accept"). Not pins, not in the SSOT, so the sweep ignores them.
LEAF_GOOGLE_R1 = "qW3FYuXf0SK210sV5lcUYE1NGTmBA398Ee6LXLqneUY="
LEAF_GOOGLE_R4 = "wyib/Zb8QzNvhqZ9QF7LzXCMzYApj7PsLe/ZjlfJzuI="
LEAF_CLOUDFLARE = "ltQ6aXy3tqpNZKJdnevMD7oR+IsI5rNWbOssFDrl+Ew="
LEAF_QUAD9 = "i2kObfz0qIKCGNWt7MjBUeSrh0Dyjb0/zWINImZES+I="
LEAF_BIRDO = "nyzbCYB1+JcItoSGtxXfjT7t2Cm023p3pk0NmqGnyYo="
UNPINNED = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="


def waiver(review_by="2099-01-01", matchable_pins=2, live_lineages=1, accepted=True):
    return {
        "id": "test-waiver",
        "accepted": accepted,
        "measured": "2026-09-06",
        "matchable_pins": matchable_pins,
        "live_lineages": live_lineages,
        "why": "test fixture",
        "mitigation": "test fixture",
        "review_by": review_by,
    }


# ----------------------------------------------------- check 2b: mutators
def unchanged(doc):
    return doc


def pre_outage(doc):
    """dns.google as shipped before the outage: WR2 + GTS Root R1 live, one
    lineage, plus one dormant pin from a second lineage. No waiver. This is the
    shape the pin-counting revision of check 2b graded 'ok ... 2 of 3'."""
    g = doc["hosts"]["dns.google"]
    g["pins"] = [p for p in g["pins"] if p["lineage"] == "gts-r1"]
    assert len(g["pins"]) == 2 and all(p["in_live_chain"] for p in g["pins"])
    dormant = copy.deepcopy(ISRG_X1)
    dormant.update(role="dormant-backup", in_live_chain=False, lineage_evidence="published")
    g["pins"].append(dormant)
    g.pop("_overlap_risk", None)
    return doc


def pre_outage_bare(doc):
    """The reviewer's reproduction: WR2 + GTS Root R1 and nothing else. The
    pin-counting revision printed 'ok dns.google: 2 of 2 ... satisfies
    _overlap_rule' for exactly this file."""
    g = doc["hosts"]["dns.google"]
    g["pins"] = [p for p in g["pins"] if p["lineage"] == "gts-r1"]
    g.pop("_overlap_risk", None)
    return doc


def pre_outage_waived(doc):
    pre_outage(doc)
    doc["hosts"]["dns.google"]["_overlap_risk"] = waiver()
    return doc


def pre_outage_waiver_expired(doc):
    pre_outage(doc)
    doc["hosts"]["dns.google"]["_overlap_risk"] = waiver(review_by="2025-01-01")
    return doc


def pre_outage_waiver_lies_about_lineages(doc):
    pre_outage(doc)
    doc["hosts"]["dns.google"]["_overlap_risk"] = waiver(live_lineages=2)
    return doc


def pre_outage_waiver_lies_about_pins(doc):
    pre_outage(doc)
    doc["hosts"]["dns.google"]["_overlap_risk"] = waiver(matchable_pins=3)
    return doc


def pre_outage_waiver_not_accepted(doc):
    pre_outage(doc)
    doc["hosts"]["dns.google"]["_overlap_risk"] = waiver(accepted=False)
    return doc


def two_live_pins_two_lineages(doc):
    """The contrast case for PRE_OUTAGE: still exactly two live pins, but from
    two hierarchies (WR2 and WE2; both roots demoted to dormant). Counting pins
    cannot tell this from PRE_OUTAGE; counting lineages must pass this one."""
    for p in doc["hosts"]["dns.google"]["pins"]:
        if p["role"] == "active-root":
            p["role"] = "dormant-backup"
            p["in_live_chain"] = False
    return doc


def stale_waiver(doc):
    """dns.google satisfies the rule today; a waiver on it is a stale exemption
    that reads as coverage the next time the host regresses."""
    doc["hosts"]["dns.google"]["_overlap_risk"] = waiver(matchable_pins=4, live_lineages=2)
    return doc


def no_live_pin(doc):
    for p in doc["hosts"]["dns.google"]["pins"]:
        p["in_live_chain"] = False
    return doc


def pin_without_lineage(doc):
    del doc["hosts"]["dns.google"]["pins"][0]["lineage"]
    return doc


def birdo_app_waiver_dropped(doc):
    """birdo.app presents ONE live lineage today (WE1 + GTS Root R4; the Let's
    Encrypt pins are dormant). The pin-counting revision graded it 'ok 2 of 8'.
    Without its dated waiver it must fail."""
    doc["hosts"]["birdo.app"].pop("_overlap_risk")
    return doc


def new_host_single_lineage(doc):
    """The debt must not spread: a NEW host with intermediate + its own root,
    both live, and no waiver, fails - there is no allow-list to forget."""
    doc["hosts"]["dns.example"] = {
        "pins": [
            dict(WR2, hash=UNPINNED),
            dict(R1),
        ]
    }
    return doc


# (name, mutator, expected failed?, substrings that MUST appear, substrings that must NOT)
LINEAGE_CASES = [
    ("committed file passes: dns.google two live lineages, waived hosts named",
     unchanged, False,
     ["ok    dns.google: 2 live lineages", "gts-r1", "gts-r4",
      "ok    birdo.app: 1 live lineage gts-r4", "KNOWN, ACCEPTED, DATED",
      "ok    cloudflare-dns.com: 1 live lineage sslcom-ecc",
      "ok    dns.quad9.net: 1 live lineage digicert-global-g3"],
     ["FAIL"]),
    ("PRE_OUTAGE: WR2 + R1 live in one lineage + dormant foreign pin, no waiver -> FAIL",
     pre_outage, True,
     ["FAIL  dns.google: 1 live lineage gts-r1", "dormant lineages held: isrg-x1",
      "took dns.google dark"],
     ["ok    dns.google"]),
    ("PRE_OUTAGE_BARE: WR2 + R1 only (the reviewer's reproduction) -> FAIL",
     pre_outage_bare, True,
     ["FAIL  dns.google: 1 live lineage gts-r1", "2 of 2 pins presented"],
     ["satisfies _overlap_rule"]),
    ("pre-outage shape with a dated, accepted waiver passes, and says so",
     pre_outage_waived, False,
     ["ok    dns.google: 1 live lineage gts-r1", "KNOWN, ACCEPTED, DATED", "'test-waiver'"],
     ["FAIL"]),
    ("pre-outage shape, waiver review_by in the past -> FAIL",
     pre_outage_waiver_expired, True, ["FAIL  dns.google", "is in the past"], []),
    ("pre-outage shape, waiver lies about live_lineages -> FAIL",
     pre_outage_waiver_lies_about_lineages, True, ["FAIL  dns.google", "live_lineages says 2"], []),
    ("pre-outage shape, waiver lies about matchable_pins -> FAIL",
     pre_outage_waiver_lies_about_pins, True, ["FAIL  dns.google", "matchable_pins says 3"], []),
    ("pre-outage shape, waiver not accepted -> FAIL",
     pre_outage_waiver_not_accepted, True, ["FAIL  dns.google", "accepted is not true"], []),
    ("two live pins across TWO lineages passes (contrast with PRE_OUTAGE)",
     two_live_pins_two_lineages, False,
     ["ok    dns.google: 2 live lineages", "2 of 4 pins presented"], ["FAIL"]),
    ("stale waiver on a host that satisfies the rule -> FAIL (ratchet, other direction)",
     stale_waiver, True, ["FAIL  dns.google", "stale exemption"], []),
    ("no live pin at all -> FAIL (_enforcement_rule)",
     no_live_pin, True, ["FAIL  dns.google: NO pin is marked in_live_chain"], []),
    ("pin without a lineage label -> FAIL (a control that cannot run must not pass)",
     pin_without_lineage, True, ["FAIL  dns.google", "lineage label"], []),
    ("birdo.app without its waiver -> FAIL (one live lineage, WE1 + its own root)",
     birdo_app_waiver_dropped, True, ["FAIL  birdo.app: 1 live lineage gts-r4"], []),
    ("a NEW host with intermediate + own root and no waiver -> FAIL (no allow-list to forget)",
     new_host_single_lineage, True, ["FAIL  dns.example: 1 live lineage gts-r1"], []),
]


# ----------------------------------------------------- check 3: fixtures
def row(p, subject, issuer):
    return (p["hash"] if isinstance(p, dict) else p, subject, issuer)


def entry(host, mutate=None):
    e = copy.deepcopy(BASE["hosts"][host])
    if mutate:
        mutate(e)
    return e


def mark_gts_r1_dormant(e):
    for p in e["pins"]:
        if p["lineage"] == "gts-r1":
            p["in_live_chain"] = False


GOOGLE_R1_CHAIN = [
    row(LEAF_GOOGLE_R1, "CN=dns.google", "CN=WR2"),
    row(WR2, "CN=WR2", "CN=GTS Root R1"),
    # CROSS_SIGNED_ROOT: subject GTS Root R1, issuer GlobalSign Root CA - as
    # measured 2026-09-08 from a UK consumer ISP over 8.8.8.8 and 8.8.4.4.
    row(R1, "CN=GTS Root R1", "CN=GlobalSign Root CA"),
]
GOOGLE_R4_CHAIN = [
    row(LEAF_GOOGLE_R4, "CN=dns.google", "CN=WE2"),
    row(WE2, "CN=WE2", "CN=GTS Root R4"),
    # As measured 2026-09-08 from the production hub, 6 of 6 samples.
    row(R4, "CN=GTS Root R4", "CN=GlobalSign Root CA"),
]
CLOUDFLARE_CHAIN = [
    row(LEAF_CLOUDFLARE, "CN=cloudflare-dns.com", "CN=SSL.com SSL Intermediate CA ECC R2"),
    row(CF_ECC_R2, "CN=SSL.com SSL Intermediate CA ECC R2",
        "CN=SSL.com Root Certification Authority ECC"),
]
QUAD9_CHAIN = [
    row(LEAF_QUAD9, "CN=dns.quad9.net", "CN=DigiCert Global G3 TLS ECC SHA384 2020 CA1"),
    row(Q9_CA1, "CN=DigiCert Global G3 TLS ECC SHA384 2020 CA1", "CN=DigiCert Global Root G3"),
]
BIRDO_CHAIN = [
    row(LEAF_BIRDO, "CN=birdo.app", "CN=WE1"),
    row(WE1, "CN=WE1", "CN=GTS Root R4"),
    row(BIRDO_R4, "CN=GTS Root R4", "CN=GlobalSign Root CA"),
]

# (name, host, entry, observed chain, expected failed?, MUST appear, must NOT appear)
LIVE_CASES = [
    ("CROSS_SIGNED_ROOT: dns.google R1 chain, root cross-signed by GlobalSign -> ok, R4 not observed",
     "dns.google", entry("dns.google"), GOOGLE_R1_CHAIN, False,
     ["ok    dns.google: live chain satisfies pin", "(lineage gts-r1)",
      "NOT OBSERVED from this vantage point: lineage(s) gts-r4"],
     ["FAIL", "SHORTENED"]),
    ("dns.google R4 chain (the hub's) -> ok, R1 not observed",
     "dns.google", entry("dns.google"), GOOGLE_R4_CHAIN, False,
     ["ok    dns.google: live chain satisfies pin", "(lineage gts-r4)",
      "NOT OBSERVED from this vantage point: lineage(s) gts-r1"],
     ["FAIL"]),
    ("cloudflare-dns.com two-certificate chain, SSOT says no root -> ok, nothing unobserved",
     "cloudflare-dns.com", entry("cloudflare-dns.com"), CLOUDFLARE_CHAIN, False,
     ["ok    cloudflare-dns.com: live chain satisfies pin", "(lineage sslcom-ecc)"],
     ["FAIL", "NOT OBSERVED", "SHORTENED"]),
    ("dns.quad9.net two-certificate chain -> ok",
     "dns.quad9.net", entry("dns.quad9.net"), QUAD9_CHAIN, False,
     ["ok    dns.quad9.net: live chain satisfies pin"], ["FAIL", "NOT OBSERVED"]),
    ("birdo.app WE1 chain, root cross-signed -> ok (the other shape the self-signed test failed)",
     "birdo.app", entry("birdo.app"), BIRDO_CHAIN, False,
     ["ok    birdo.app: live chain satisfies pin", "(lineage gts-r4)"], ["FAIL", "SHORTENED"]),
    ("chain matches only pins the SSOT marks dormant -> FAIL (the flag check 2b trusted is wrong)",
     "dns.google", entry("dns.google", mark_gts_r1_dormant), GOOGLE_R1_CHAIN, True,
     ["FAIL  dns.google: presented pin", "is marked in_live_chain: false"], []),
    ("SHORTENED chain: SSOT says the root is presented, the wire has leaf + WR2 only -> FAIL",
     "dns.google", entry("dns.google"), GOOGLE_R1_CHAIN[:2], True,
     ["FAIL  dns.google", "SHORTENED chain", "no active-root pin"], []),
    ("chain matching no pin at all -> FAIL, clients CANNOT CONNECT",
     "dns.google", entry("dns.google"),
     [row(LEAF_GOOGLE_R1, "CN=dns.google", "CN=Other"), row(UNPINNED, "CN=Other", "CN=Other Root")],
     True, ["FAIL  dns.google: NO pinned SPKI is present", "CANNOT CONNECT"], []),
    ("one chain whose pins the SSOT files under two lineages -> FAIL (labels wrong, 2b over-counts)",
     "dns.google", entry("dns.google"),
     [row(LEAF_GOOGLE_R1, "CN=dns.google", "CN=WR2"), row(WR2, "CN=WR2", "CN=GTS Root R1"),
      row(R4, "CN=GTS Root R4", "CN=GlobalSign Root CA")],
     True, ["FAIL  dns.google", "2 different lineages"], []),
    ("a root the SSOT marks dormant turns up on the wire -> FAIL: the flag (and the waiver's "
     "matchable_pins) are stale, re-measure",
     "cloudflare-dns.com", entry("cloudflare-dns.com"),
     CLOUDFLARE_CHAIN + [row(CF_ROOT, "CN=SSL.com Root Certification Authority ECC",
                             "CN=SSL.com Root Certification Authority ECC")],
     True, ["ok    cloudflare-dns.com: live chain satisfies pin",
            "FAIL  cloudflare-dns.com: presented pin", "is marked in_live_chain: false",
            "presented 3 certificate(s); chain_shape.presented lists 2"], []),
]


def run():
    passed = failed = 0

    def report(name, problems, text):
        nonlocal passed, failed
        if problems:
            failed += 1
            print("FAIL  %s: %s" % (name, "; ".join(problems)))
            for line in text.rstrip().splitlines()[-12:]:
                print("      | " + line)
        else:
            passed += 1
            print("ok    %s" % name)

    print("== check 2b (cert_pins_lineages.py) against %d fixtures ==" % len(LINEAGE_CASES))
    for name, mutate, want_failed, needles, forbidden in LINEAGE_CASES:
        doc = mutate(copy.deepcopy(BASE))
        got_failed, lines = lineages.check(doc, today=TODAY)
        text = "\n".join(lines)
        problems = []
        if got_failed != want_failed:
            problems.append("failed=%r, expected %r" % (got_failed, want_failed))
        problems += ["output lacks %r" % n for n in needles if n not in text]
        problems += ["output unexpectedly contains %r" % n for n in forbidden if n in text]
        report(name, problems, text)

    print()
    print("== check 3 (cert_pins_live_chain.py) against %d measured or mutated chains =="
          % len(LIVE_CASES))
    for name, host, e, observed, want_failed, needles, forbidden in LIVE_CASES:
        got_failed, lines = live_chain.analyse(e, host, observed)
        text = "\n".join(lines)
        problems = []
        if got_failed != want_failed:
            problems.append("failed=%r, expected %r" % (got_failed, want_failed))
        problems += ["output lacks %r" % n for n in needles if n not in text]
        problems += ["output unexpectedly contains %r" % n for n in forbidden if n in text]
        report(name, problems, text)

    print()
    print("test_check_cert_pins: %d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(run())
