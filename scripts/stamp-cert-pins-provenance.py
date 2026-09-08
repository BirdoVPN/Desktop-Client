#!/usr/bin/env python3
"""Re-stamp third_party/cert-pins.provenance.json after re-vendoring the SSOT.

Run this immediately after

    cp ../birdo-shared/cert-pins.json third_party/cert-pins.json

and commit BOTH files. Check 1b of scripts/check-cert-pins.sh fails until you do.

    python3 scripts/stamp-cert-pins-provenance.py [--upstream-commit <sha>]

WHY THIS EXISTS. The vendored copy was hand-edited once - its dns.google entry
was trimmed while the real SSOT carried a different set - and nothing went red.
Check 2 compares the Rust pin files against the VENDORED copy, so editing both
keeps them agreeing with each other; check 1, the only one that looks at the
real SSOT, is skipped whenever ../birdo-shared is absent, which is every CI run.
The stamp makes a hand-edit fail offline, with no cross-repo credential.

WHAT THIS SCRIPT REFUSES TO DO, because a stamp that cannot be verified is
worse than no stamp:

  * Stamp without ../birdo-shared checked out. An earlier version warned and
    stamped anyway, leaving upstream_commit as it was - so a hand-edit followed
    by a re-stamp passed check 1b with a provenance record pointing at a commit
    that contains something else. No upstream, no stamp, exit 1.
  * Stamp content that is not (canonically) the content of the upstream COMMIT
    it records. The upstream working tree is not enough: an uncommitted upstream
    edit has no commit to point at, and the commit is what check 1 verifies.
  * Invent upstream_commit_on_main. It is measured with `git merge-base
    --is-ancestor` against origin/main after a fetch. If the fetch fails the
    local origin/main is used and the stamp says so. Check 1b FAILS while this
    is false - vendoring from an unmerged SSOT branch is allowed, merging the
    consumer before the SSOT is not.

The digest is over CANONICAL JSON, not raw bytes: this repo sets
core.autocrlf=true, so the Windows working tree is CRLF while the blob and every
Linux CI checkout are LF, and a raw-byte digest would pass locally and fail on CI.
"""
import datetime
import hashlib
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
VENDORED = ROOT / "third_party" / "cert-pins.json"
PROVENANCE = ROOT / "third_party" / "cert-pins.provenance.json"
UPSTREAM_DIR = ROOT.parent / "birdo-shared"
UPSTREAM_PATH = "cert-pins.json"
UPSTREAM_REPO = "BirdoVPN/birdo-shared"

COMMENT = (
    "Provenance stamp for third_party/cert-pins.json. This file exists because the "
    "vendored copy was HAND-EDITED once (its dns.google entry differed from the SSOT's) "
    "and every check still reported green: check 2 of check-cert-pins.sh compares the "
    "Rust pin files against the VENDORED copy, so an edit to both agrees with itself, "
    "and check 1 - the only one that compares the vendored copy to the real SSOT - is "
    "skipped whenever birdo-shared is not checked out alongside, which is always the "
    "case on CI. This stamp closes that hole WITHOUT needing the upstream repo present: "
    "the recorded digest is of the vendored file's CANONICAL JSON, so any hand-edit to "
    "third_party/cert-pins.json fails check 1b offline, on every PR. Re-vendoring is "
    "therefore a two-file change on purpose."
)
HOW_TO_UPDATE = (
    "cp ../birdo-shared/cert-pins.json third_party/cert-pins.json && "
    "python3 scripts/stamp-cert-pins-provenance.py    # then commit BOTH files"
)
DIGEST_IS_OVER = (
    "json.dumps(json.load(f), sort_keys=True, separators=(',',':'), ensure_ascii=False)"
    ".encode('utf-8') - canonical form, NOT the raw bytes. This repo has "
    "core.autocrlf=true, so the Windows working tree is CRLF while the blob and every "
    "Linux CI checkout are LF; a raw-byte digest would pass on one and fail on the other."
)
MERGE_ORDER = (
    "upstream_commit_on_main is MEASURED by scripts/stamp-cert-pins-provenance.py "
    "(git merge-base --is-ancestor against birdo-shared origin/main) and cannot be "
    "written by hand without check 1 catching it on any checkout that has "
    "../birdo-shared. While it is false, check 1b FAILS on every run, including CI: "
    "the consumer PR that vendors an unmerged SSOT branch stays red until the SSOT PR "
    "merges and this copy is re-vendored and re-stamped from main. That is the merge "
    "order, made mechanical."
)


def canonical_sha256_text(text: str) -> str:
    obj = json.loads(text)
    canon = json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canon).hexdigest()


def git(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(UPSTREAM_DIR), *args],
        capture_output=True, text=True, timeout=timeout,
    )


def main(argv: list[str]) -> int:
    requested = None
    if argv[1:2] == ["--upstream-commit"] and len(argv) == 3:
        requested = argv[2]
    elif argv[1:]:
        print("usage: stamp-cert-pins-provenance.py [--upstream-commit <sha>]",
              file=sys.stderr)
        return 2

    if not VENDORED.exists():
        print(f"FAIL  vendored SSOT missing: {VENDORED}", file=sys.stderr)
        return 1
    if not (UPSTREAM_DIR / ".git").exists():
        print(
            f"FAIL  {UPSTREAM_DIR} is not a git checkout. A stamp records the upstream "
            "commit the vendored copy came from and whether that commit is on "
            "birdo-shared main; neither can be verified without the upstream repo, "
            "and an unverifiable stamp is exactly what check 1b must not trust. "
            "Run this from the real checkout that has ../birdo-shared beside it - "
            "not from a temp worktree.",
            file=sys.stderr,
        )
        return 1

    vendored_digest = canonical_sha256_text(VENDORED.read_text(encoding="utf-8"))

    # Which upstream commit? Default HEAD; --upstream-commit to name one (useful
    # when the upstream checkout is on some other branch).
    r = git("rev-parse", "--verify", (requested or "HEAD") + "^{commit}")
    if r.returncode != 0:
        print(f"FAIL  cannot resolve upstream commit {requested or 'HEAD'}: "
              f"{r.stderr.strip()}", file=sys.stderr)
        return 1
    commit = r.stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        print(f"FAIL  upstream commit resolved to {commit!r}, not a sha", file=sys.stderr)
        return 1

    if requested is None:
        # HEAD only describes the working tree if the file is not modified there.
        dirty = git("status", "--porcelain", "--", UPSTREAM_PATH).stdout.strip()
        if dirty:
            print(
                f"FAIL  {UPSTREAM_DIR / UPSTREAM_PATH} has uncommitted changes "
                f"({dirty}). Commit them upstream first: the stamp records a commit, "
                "and the commit must contain what is vendored.",
                file=sys.stderr,
            )
            return 1

    blob = git("show", f"{commit}:{UPSTREAM_PATH}")
    if blob.returncode != 0:
        print(f"FAIL  birdo-shared@{commit[:12]} has no {UPSTREAM_PATH}", file=sys.stderr)
        return 1
    upstream_digest = canonical_sha256_text(blob.stdout)
    if upstream_digest != vendored_digest:
        print(
            "FAIL  third_party/cert-pins.json does not match "
            f"birdo-shared@{commit[:12]}:{UPSTREAM_PATH} - re-vendor it from that "
            "commit before stamping (that is the whole point of the stamp):\n"
            f"        vendored : {vendored_digest}\n"
            f"        upstream : {upstream_digest}",
            file=sys.stderr,
        )
        return 1

    # Is that commit on birdo-shared main? Fetch first; say so if that failed.
    fetched = False
    try:
        fetched = git("fetch", "--quiet", "origin", "main", timeout=90).returncode == 0
    except subprocess.TimeoutExpired:
        fetched = False
    main_ref = git("rev-parse", "origin/main")
    main_sha = main_ref.stdout.strip() if main_ref.returncode == 0 else ""
    on_main = bool(main_sha) and git(
        "merge-base", "--is-ancestor", commit, "origin/main"
    ).returncode == 0

    if requested is None:
        branch = git("rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
    else:
        names = git("branch", "--contains", commit,
                    "--format=%(refname:short)").stdout.split()
        branch = ", ".join(names) if names else "(no local branch contains it)"
    subject = git("log", "-1", "--format=%s", commit).stdout.strip()

    prov = {
        "_comment": COMMENT,
        "_how_to_update": HOW_TO_UPDATE,
        "_digest_is_over": DIGEST_IS_OVER,
        "_merge_order": MERGE_ORDER,
        "upstream_repo": UPSTREAM_REPO,
        "upstream_path": UPSTREAM_PATH,
        "upstream_commit": commit,
        "upstream_branch": branch,
        "upstream_subject": subject,
        "upstream_commit_on_main": on_main,
        "upstream_main_ref": f"origin/main@{main_sha[:12]}" if main_sha else "(unresolvable)",
        "upstream_main_fetched": fetched,
        "vendored_on": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d"),
        "canonical_sha256": vendored_digest,
    }
    with PROVENANCE.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(prov, f, indent=2, ensure_ascii=False)
        f.write("\n")

    fetch_note = "" if fetched else ", local ref - fetch failed"
    print(f"stamped {PROVENANCE.relative_to(ROOT)} -> {vendored_digest}")
    print(f"        upstream {UPSTREAM_REPO}@{commit[:12]} ({branch}): {subject}")
    if on_main:
        print(f"        on birdo-shared main: YES ({prov['upstream_main_ref']}{fetch_note})")
    else:
        print(f"        on birdo-shared main: NO ({prov['upstream_main_ref']}{fetch_note})")
        print("        check 1b will FAIL - on every run, including CI - until the")
        print("        birdo-shared change merges and this copy is re-vendored and")
        print("        re-stamped from main. That is deliberate: the consumer must not")
        print("        merge before the SSOT does.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
