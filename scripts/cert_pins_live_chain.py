#!/usr/bin/env python3
"""Check 3 of scripts/check-cert-pins.sh, per host: the chain ONE vantage
received, held against the pins and against the SSOT's own flags.

    python3 scripts/cert_pins_live_chain.py <cert-pins.json> <host> <observed.tsv>

<observed.tsv> is one line per presented certificate, leaf first:

    <base64 SHA-256 of the DER SubjectPublicKeyInfo> TAB <subject> TAB <issuer>

Exit 0 when at least one pinned SPKI is present and the SSOT's flags agree with
what was presented; exit 1 otherwise. Lives in its own file so
scripts/test_check_cert_pins.py can feed it real measured chains, including
the one that exposed a bug in an earlier revision (see (c) below).

WHAT THIS PROVES AND WHAT IT DOES NOT. Every pinned host is anycast, so this is
evidence about the one edge that answered, never about the host. It therefore
also prints which declared live lineages it did NOT see: one green run used to
read as "the host is fine", and that reading is how dns.google stayed green
while every GTS Root R4 edge was dark.
"""
import json
import sys


def read_observed(path):
    observed = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if parts and parts[0]:
                observed.append((parts[0],
                                 parts[1] if len(parts) > 1 else "?",
                                 parts[2] if len(parts) > 2 else "?"))
    return observed


def analyse(entry, host, observed):
    """Returns (failed: bool, lines: list[str])."""
    out = []
    by_hash = {p["hash"]: p for p in entry["pins"]}
    matched = [(h, by_hash[h]) for h, _, _ in observed if h in by_hash]

    if not matched:
        out.append("FAIL  %s: NO pinned SPKI is present in the live chain — clients pinning "
                   "this host CANNOT CONNECT." % host)
        out.append("        live chain:  " + " ".join(h for h, _, _ in observed))
        out.append("        pinned:      " + " ".join(by_hash))
        out.append("        Fix by ADDING the new chain pin to birdo-shared/cert-pins.json "
                   "and every")
        out.append("        pin file, shipping it, and only then removing the old one.")
        return True, out

    failed = False
    seen = sorted({p.get("lineage") for _, p in matched if p.get("lineage")})
    out.append("ok    %s: live chain satisfies pin %s%s"
               % (host, matched[0][0],
                  (" (lineage " + ", ".join(seen) + ")") if seen else ""))

    # --- the SSOT's own flags against what this vantage just saw ---------------
    # (a) A presented pin the SSOT marks dormant: check 2b counted this host on
    #     wrong data. The reverse (marked live, never seen) cannot be proven
    #     from one vantage - anycast - so it is only reported, below.
    for h, p in matched:
        if p.get("in_live_chain") is not True:
            out.append("FAIL  %s: presented pin %s (%s) is marked in_live_chain: false in "
                       "the SSOT. The flag is wrong; fix birdo-shared/cert-pins.json."
                       % (host, h, p.get("label")))
            failed = True
    # (b) One presented chain is ONE lineage: its certificates vanish from the
    #     handshake together. If the SSOT assigns them to different lineages,
    #     check 2b counts two independently-failing paths where there is one.
    if len(seen) > 1:
        out.append("FAIL  %s: the single chain presented from this vantage contains pins "
                   "the SSOT assigns to %d different lineages (%s). A chain is one "
                   "lineage; the labels are wrong and check 2b over-counts this host. "
                   "Fix birdo-shared/cert-pins.json." % (host, len(seen), ", ".join(seen)))
        failed = True
    # (c) A root the SSOT says is presented, but was not. The root pin has just
    #     gone dormant from this vantage - the shortened-chain case, which is
    #     the named residual risk for every host pinned as intermediate + root.
    #
    #     "Presented" is decided by SPKI, not by looking for a self-signed
    #     certificate. An earlier revision did the latter and failed both
    #     birdo.app and dns.google from a vantage that had received the full
    #     chain: Google serves its roots CROSS-SIGNED (subject "GTS Root R1",
    #     issuer "GlobalSign Root CA" - measured 2026-09-08), so no certificate
    #     in that chain is self-signed, yet the root's public key - the thing
    #     the pin hashes - is right there. The pin is on the SPKI; so is this.
    shape = entry.get("chain_shape") if isinstance(entry.get("chain_shape"), dict) else None
    if shape is not None and isinstance(shape.get("root_presented"), bool):
        root_pins = {h: p for h, p in by_hash.items() if p.get("role") == "active-root"}
        roots_on_wire = [h for h, _, _ in observed if h in root_pins]
        if shape["root_presented"]:
            if not root_pins:
                out.append("FAIL  %s: the SSOT says the root is presented "
                           "(chain_shape.root_presented) but declares no pin with role "
                           "active-root, so nothing can be checked against the wire. Fix "
                           "birdo-shared/cert-pins.json." % host)
                failed = True
            elif not roots_on_wire:
                out.append("FAIL  %s: the SSOT says the root is presented "
                           "(chain_shape.root_presented) but this vantage received a "
                           "SHORTENED chain: no active-root pin's SPKI is in it (%s). Every "
                           "root pin for this host is dormant here, and only the "
                           "intermediate pin stands between this edge and a hard pin "
                           "failure; re-measure and fix birdo-shared/cert-pins.json."
                           % (host, " ".join(h for h, _, _ in observed)))
                failed = True
        elif roots_on_wire:
            out.append("      note: the SSOT says no root is presented, but this vantage "
                       "received one (%s) - chain_shape in birdo-shared/cert-pins.json needs "
                       "re-measuring (a root appearing is not a client-facing failure)."
                       % ", ".join(roots_on_wire))
        presented = shape.get("presented")
        if isinstance(presented, list) and presented and len(presented) != len(observed):
            out.append("      note: this vantage presented %d certificate(s); "
                       "chain_shape.presented lists %d - re-measure chain_shape in "
                       "birdo-shared/cert-pins.json." % (len(observed), len(presented)))

    # --- what this run did NOT prove ------------------------------------------
    declared_live = sorted({p["lineage"] for p in entry["pins"]
                            if p.get("in_live_chain") is True and p.get("lineage")})
    unseen = [lg for lg in declared_live if lg not in seen]
    if unseen:
        out.append("      NOT OBSERVED from this vantage point: lineage(s) %s. This run says "
                   "nothing about users served those lineages - one anycast edge answered, "
                   "not the host." % ", ".join(unseen))
    for h, subj, _ in observed[1:]:
        if h not in by_hash:
            out.append("      presented but not pinned: %s [%s]. The match came from another "
                       "certificate in the chain; a shortened chain without it would match "
                       "nothing." % (h, subj))

    return failed, out


def main(argv):
    if len(argv) != 4:
        print("usage: cert_pins_live_chain.py <cert-pins.json> <host> <observed.tsv>",
              file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as f:
        ssot = json.load(f)
    host = argv[2]
    entry = ssot["hosts"].get(host)
    if entry is None:
        print("FAIL  %s: not a host in %s" % (host, argv[1]))
        return 1
    failed, lines = analyse(entry, host, read_observed(argv[3]))
    for line in lines:
        print(line)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
