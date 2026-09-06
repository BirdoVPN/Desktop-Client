#!/usr/bin/env python3
"""Re-stamp third_party/cert-pins.provenance.json after re-vendoring the SSOT.

Run this immediately after

    cp ../birdo-shared/cert-pins.json third_party/cert-pins.json

and commit BOTH files. Check 1b of scripts/check-cert-pins.sh fails until you do.

WHY THIS EXISTS. The vendored copy was hand-edited once - dns.google trimmed to
4 pins while the real SSOT carried 10 - and nothing went red. Check 2 compares
the Rust pin files against the VENDORED copy, so editing both keeps them
agreeing with each other; check 1, the only one that looks at the real SSOT, is
skipped whenever ../birdo-shared is absent, which is every CI run. The stamp
makes a hand-edit fail offline, with no cross-repo credential.

The digest is over CANONICAL JSON, not raw bytes: this repo sets
core.autocrlf=true, so the Windows working tree is CRLF while the blob and every
Linux CI checkout are LF, and a raw-byte digest would pass locally and fail on CI.
"""
import hashlib
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
VENDORED = ROOT / "third_party" / "cert-pins.json"
PROVENANCE = ROOT / "third_party" / "cert-pins.provenance.json"
UPSTREAM_DIR = ROOT.parent / "birdo-shared"


def canonical_sha256(path: pathlib.Path) -> str:
    obj = json.loads(path.read_text(encoding="utf-8"))
    canon = json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canon).hexdigest()


def git(*args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(UPSTREAM_DIR), *args],
        capture_output=True, text=True, check=True,
    ).stdout.strip()


def main() -> int:
    if not VENDORED.exists():
        print(f"FAIL  vendored SSOT missing: {VENDORED}", file=sys.stderr)
        return 1

    prov = json.loads(PROVENANCE.read_text(encoding="utf-8")) if PROVENANCE.exists() else {}
    prov["canonical_sha256"] = canonical_sha256(VENDORED)

    # Record where it came from, when birdo-shared is actually checked out
    # alongside. Never invent these fields: an unverifiable provenance record is
    # worse than an absent one.
    if (UPSTREAM_DIR / ".git").exists():
        upstream_file = UPSTREAM_DIR / "cert-pins.json"
        if canonical_sha256(upstream_file) != prov["canonical_sha256"]:
            print(
                "FAIL  third_party/cert-pins.json does not match "
                f"{upstream_file} - re-vendor it before stamping (that is the "
                "whole point of the stamp)",
                file=sys.stderr,
            )
            return 1
        prov["upstream_commit"] = git("rev-parse", "HEAD")
        prov["upstream_subject"] = git("log", "-1", "--format=%s")
    else:
        print(
            "warn  ../birdo-shared is not checked out; upstream_commit/"
            "upstream_subject left as they were - verify them by hand",
            file=sys.stderr,
        )

    with PROVENANCE.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(prov, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"stamped {PROVENANCE.relative_to(ROOT)} -> {prov['canonical_sha256']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
