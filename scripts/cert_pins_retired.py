#!/usr/bin/env python3
"""cert_pins_retired.py - check 2c of scripts/check-cert-pins.sh.

A RETIRED PIN MUST NOT SURVIVE ANYWHERE IN THIS REPO.

Why this is a separate check. Check 2 extracts each file's pin DECLARATION -
the array the compiler reads - and compares it to the SSOT. To do that it
strips comment tails, because a retired hash left in a comment must not be able
to satisfy the check. The cost of that is a blind spot with the same shape: a
retired hash sitting in a comment, a doc block or a `#[cfg(test)]` fixture is
invisible to check 2, so a set the owner rejected can go on living in the file
that pins the host, one copy-paste from being restored. That is exactly what
happened on this branch: the six Google sibling intermediates (WR1/WR3/WR4,
WE1/WE3/WE4) were dropped from `DOH_PROVIDERS` and every check printed green
while all six were still written out in a test in the same file.

Two rules, both over the RAW bytes of every text file in the repo:

  R1  GLOBAL RETIREMENT. A hash in the SSOT's `_removed[]` that is not a
      current pin of ANY host must not appear anywhere outside the vendored
      SSOT itself. Nothing in this repo has a reason to name it.

  R2  HOST-SCOPED RETIREMENT. A `_removed[]` entry that names a `host` must not
      appear in any file this repo enforces that host in. This is the case R1
      cannot cover: `WE1` was retired for dns.google and is at the same time a
      live birdo.app pin, so it belongs in api/cert_pin.rs (which pins
      birdo.app) and must never reappear in vpn/doh.rs (which pins dns.google).
      The host -> file mapping is the SSOT's own `enforced_by[]`, resolved
      against the files actually present here, so there is no second extractor
      list to keep in step with check 2's - and a pin site the SSOT does not
      list is caught by check 2's unregistered-file sweep instead.

      LIMIT, stated rather than papered over: R2 sees only the files
      `enforced_by` names. A hash retired for one host while still live for
      another, hidden in some file that enforces neither, is caught by neither
      rule. R1 covers every hash that is retired outright, which is all six of
      the dns.google siblings but one.

The SSOT is where a retired hash is recorded, with its date and reason -
`_removed[]` is the ONE place it is allowed to exist, and check 2 already fails
any file that re-declares it as a pin. This check makes the record the only
copy.

Exit 0 = clean, 1 = a retired hash survives (the offending file, line and the
SSOT's own reason are printed).

    python3 scripts/cert_pins_retired.py third_party/cert-pins.json <repo-root>
"""
import json
import os
import sys

# Same exclusions as check 2's unregistered-pin sweep, so the two agree about
# what "this repo" means. third_party/ is skipped wholesale: the vendored SSOT
# lives there and is the one legitimate home of a retired hash.
SKIP_DIRS = {".git", "build", "target", "node_modules", "dist", ".gradle",
             "DerivedData", "Pods", ".idea", "vendor", "third_party"}
TEXT_EXT = {".rs", ".kt", ".kts", ".java", ".swift", ".xml", ".json", ".m",
            ".mm", ".h", ".c", ".cpp", ".ts", ".js", ".py", ".sh", ".yml",
            ".yaml", ".toml", ".md", ".plist", ".gradle", ".properties"}


def collect(root):
    """{relative path: text} for every text file the rules apply to."""
    files = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() not in TEXT_EXT:
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            try:
                with open(full, encoding="utf-8", errors="ignore") as fh:
                    files[rel] = fh.read()
            except OSError:
                continue
    return files


def _first_line(text, needle):
    for i, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return i
    return 0


def scan(doc, files):
    """Apply R1 and R2. Returns (failed, lines) like the other check modules.

    `doc`   - the parsed SSOT.
    `files` - {relative path: text}. Passing this in (rather than walking here)
              is what lets scripts/test_check_cert_pins.py drive both rules from
              synthetic files with no temp directory and no real hash literals.
    """
    out = []
    failed = False

    current_by_host = {
        host: {p["hash"] for p in entry.get("pins", [])}
        for host, entry in doc.get("hosts", {}).items()
    }
    current_any = set()
    for pins in current_by_host.values():
        current_any |= pins

    # Host -> the files in THIS repo that enforce it, from the SSOT's own
    # enforced_by[]. Entries are "<repo-dir>:<path>"; a path is ours if it
    # exists here, which survives the checkout being renamed and never claims a
    # sibling repo's Kotlin/Swift path.
    sites = {}
    for host, entry in doc.get("hosts", {}).items():
        for ref in entry.get("enforced_by", []):
            path = ref.split(":", 1)[1] if ":" in ref else ref
            if path in files:
                sites.setdefault(host, set()).add(path)

    removed = [r for r in doc.get("_removed", []) if r.get("hash")]
    if not removed:
        out.append("ok    2c: the SSOT records no retired pins - nothing to enforce")
        return failed, out

    for record in removed:
        h = record["hash"]
        host = record.get("host")
        label = record.get("was_labelled", "(unlabelled)")
        reason = (record.get("reason") or "").strip()
        still_current = h in current_any

        if not still_current:
            # R1: retired everywhere, so nothing here has a reason to name it.
            for rel in sorted(files):
                if h not in files[rel]:
                    continue
                failed = True
                out.append("FAIL  2c: %s:%d carries RETIRED pin %s (%s)"
                           % (rel, _first_line(files[rel], h), h, label))
                out.append("        Retired %s in the SSOT%s. Its _removed[] is the only"
                           % (record.get("removed", "?"),
                              " for " + host if host else ""))
                out.append("        place this hash may exist; delete it here. Check 2 cannot")
                out.append("        see it - it strips comments - which is why 2c reads raw text.")
                if reason:
                    out.append("        SSOT reason: " + reason[:200])
        elif host:
            # R2: still live for some other host, so only the files that
            # enforce THIS host are wrong to carry it.
            for rel in sorted(sites.get(host, ())):
                if h not in files[rel]:
                    continue
                failed = True
                out.append("FAIL  2c: %s:%d carries pin %s, retired for %s (%s)"
                           % (rel, _first_line(files[rel], h), h, host, label))
                out.append("        The SSOT's enforced_by names this file as a %s pin site."
                           % host)
                out.append("        The hash is still live for another host, so R1 does not")
                out.append("        cover it - delete it from THIS file.")
                if reason:
                    out.append("        SSOT reason: " + reason[:200])

    if not failed:
        out.append(
            "ok    2c: no retired pin survives outside the SSOT (%d retired hashes "
            "vs %d files; host-scoped sites: %s)"
            % (len(removed), len(files),
               ", ".join("%s -> %s" % (h, "+".join(sorted(v)))
                         for h, v in sorted(sites.items())) or "none"))
    return failed, out


def main(argv):
    if len(argv) != 3:
        print("usage: cert_pins_retired.py <cert-pins.json> <repo-root>", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as fh:
        doc = json.load(fh)
    failed, lines = scan(doc, collect(argv[2]))
    for line in lines:
        print(line)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
