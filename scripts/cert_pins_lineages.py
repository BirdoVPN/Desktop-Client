#!/usr/bin/env python3
"""Check 2b of scripts/check-cert-pins.sh: LIVE LINEAGES per host.

    python3 scripts/cert_pins_lineages.py <cert-pins.json>

Exit 0 when every host either presents >= 2 live lineages or carries a valid,
dated, accepted `_overlap_risk` waiver; exit 1 otherwise. Lives in its own
file - rather than inline in the bash checker - so scripts/test_check_cert_pins.py
can run it against known-bad fixtures. A checker nobody has watched fail is a
comment with a shell script around it.

The SSOT states two rules that used to be prose:

  _enforcement_rule  "every host MUST keep at least one pin that is present
                      in the live chain"  (a pin the server never sends is
                      dormant and can never satisfy today's handshake)
  _overlap_rule      an intermediate and the root that signed it are ONE
                      lineage; every host must present a second one, or
                      carry an explicit, dated `_overlap_risk` saying why not

Counting PINS answers the wrong question. doh.rs asserted ">= 2 overlapping
pins" in a doc comment AND in a unit test while dns.google carried exactly one
lineage, and both stayed green through the outage; an earlier revision of this
check counted pins marked in_live_chain and passed "intermediate + its own
root" - the pre-outage dns.google shape, and birdo.app's shape today.

So this check counts LIVE LINEAGES per host: the distinct `lineage` labels
among pins marked in_live_chain. It requires >= 2, or an `_overlap_risk` waiver
in the SSOT that is accepted, dated, unexpired and describes the file it sits
in. The waiver is a RATCHET in both directions, not an exemption pool:
  * a host below two live lineages with no waiver fails -> the debt cannot
    spread silently to a new host, or back to dns.google;
  * a waived host that reaches two live lineages also fails -> the entry
    cannot rot into a permanent excuse after the underlying problem is fixed.

Both the lineage labels and the waivers live in birdo-shared/cert-pins.json;
the vendored copy is not where either is edited (check 1b refuses). What this
check cannot do is verify the labels against the wire. Two things do:
scripts/cert_pins_live_chain.py (check 3) holds the flags against the chain
the running vantage actually received, and `cargo test` in src-tauri/src/vpn/doh.rs
(`test_ssot_live_lineage_flags_match_measured_chains`) holds them against the
chains this repo has measured itself.
"""
import datetime
import json
import sys


def as_date(value):
    try:
        return datetime.date(*[int(x) for x in str(value).split("-")])
    except Exception:  # noqa: BLE001
        return None


def wrap(text, width=74):
    return [text[i:i + width] for i in range(0, len(text), width)]


def check(ssot, today=None):
    """Returns (failed: bool, lines: list[str])."""
    today = today or datetime.date.today()
    out = []
    failed = False

    for host, entry in sorted(ssot["hosts"].items()):
        pins = entry.get("pins") or []
        bad = [p for p in pins
               if not isinstance(p.get("in_live_chain"), bool)
               or not isinstance(p.get("lineage"), str) or not p.get("lineage")]
        if not pins or bad:
            out.append("FAIL  " + host + ": " + str(len(bad)) + " of " + str(len(pins)) +
                       " pin(s) lack a boolean in_live_chain or a lineage label, so this "
                       "check cannot tell a live lineage from a dormant one. A control that "
                       "cannot run must not report green. (SSOT schema 3 fields - fix "
                       "birdo-shared/cert-pins.json.)")
            failed = True
            continue

        live = [p for p in pins if p["in_live_chain"]]
        live_lineages = sorted({p["lineage"] for p in live})
        held_lineages = sorted({p["lineage"] for p in pins})
        dormant_lineages = [lg for lg in held_lineages if lg not in live_lineages]
        waiver = entry.get("_overlap_risk")

        def members(lineage, live=live):
            return " + ".join(p.get("label", "?").split(" - ")[0] for p in live
                              if p["lineage"] == lineage)

        if not live:
            out.append("FAIL  " + host + ": NO pin is marked in_live_chain -- every pin is "
                       "dormant, so no handshake can ever satisfy this host "
                       "(SSOT _enforcement_rule).")
            failed = True
            continue

        if len(live_lineages) >= 2:
            if isinstance(waiver, dict):
                out.append("FAIL  " + host + ": now presents " + str(len(live_lineages)) +
                           " live lineages (" + ", ".join(live_lineages) + ") but still "
                           "carries _overlap_risk " + repr(waiver.get("id")) + " in the "
                           "SSOT. Delete the waiver in birdo-shared -- a stale exemption "
                           "reads as coverage.")
                failed = True
            else:
                out.append("ok    " + host + ": " + str(len(live_lineages)) +
                           " live lineages -- " +
                           "; ".join(lg + " (" + members(lg) + ")" for lg in live_lineages) +
                           " -- " + str(len(live)) + " of " + str(len(pins)) +
                           " pins presented; satisfies _overlap_rule")
            continue

        # Exactly one live lineage: intermediate + its own root, or a lone
        # intermediate.
        detail = ("1 live lineage " + live_lineages[0] + " (" + members(live_lineages[0]) +
                  "); " + str(len(live)) + " of " + str(len(pins)) + " pins presented")
        if dormant_lineages:
            detail += ("; dormant lineages held: " + ", ".join(dormant_lineages) +
                       " (protect a future migration, cannot satisfy today's handshake)")

        if not isinstance(waiver, dict):
            out.append("FAIL  " + host + ": " + detail + ".")
            for line in wrap("An intermediate and the root that signed it vanish from the "
                             "same handshake, so this host is ONE CA-side change away from "
                             "every installed client losing it (SSOT _overlap_rule) -- the "
                             "exact shape that took dns.google dark. Either pin a second "
                             "lineage the host is MEASURED serving, or record an explicit, "
                             "dated, accepted _overlap_risk for it in "
                             "birdo-shared/cert-pins.json. Not here: the vendored copy is "
                             "not where pins are edited (check 1b)."):
                out.append("        " + line)
            failed = True
            continue

        problems = []
        if waiver.get("accepted") is not True:
            problems.append("accepted is not true (an unaccepted risk is an open defect, "
                            "not a waiver)")
        for field in ("why", "mitigation"):
            if not str(waiver.get(field, "")).strip():
                problems.append(field + " is empty")
        rb = as_date(waiver.get("review_by", ""))
        if rb is None:
            problems.append("review_by is not YYYY-MM-DD")
        elif rb < today:
            problems.append("review_by " + rb.isoformat() + " is in the past -- re-measure, "
                            "then fix the overlap or move the date; an accepted risk with "
                            "no expiry is a permanent one nobody re-reads")
        mp = waiver.get("matchable_pins")
        if mp is not None and mp != len(live):
            problems.append("matchable_pins says " + repr(mp) + " but " + str(len(live)) +
                            " pin(s) are marked in_live_chain -- the waiver describes a "
                            "different file")
        ll = waiver.get("live_lineages")
        if ll is not None and ll != len(live_lineages):
            problems.append("live_lineages says " + repr(ll) + " but " +
                            str(len(live_lineages)) + " lineage(s) have a pin marked "
                            "in_live_chain -- the waiver describes a different file")
        if problems:
            out.append("FAIL  " + host + ": " + detail + ", and its _overlap_risk waiver is "
                       "not valid: " + "; ".join(problems) + ". Fix it in "
                       "birdo-shared/cert-pins.json.")
            failed = True
            continue

        out.append("ok    " + host + ": " + detail + " -- KNOWN, ACCEPTED, DATED "
                   "single-lineage risk " + repr(waiver.get("id")) + ", review by " +
                   str(waiver.get("review_by")) + ":")
        for line in wrap(str(waiver.get("why"))):
            out.append("        " + line)

    return failed, out


def main(argv):
    if len(argv) != 2:
        print("usage: cert_pins_lineages.py <cert-pins.json>", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as f:
        ssot = json.load(f)
    failed, lines = check(ssot)
    for line in lines:
        print(line)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
