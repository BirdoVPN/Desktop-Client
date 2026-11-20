#!/usr/bin/env python3
"""Extract the ML-KEM-1024 NIST ACVP vectors that src-tauri's BirdoPQ tests run (MR-1432).

The client links RustCrypto `ml-kem` for ML-KEM-1024 only, so only the
ML-KEM-1024 test groups are kept. They come from NIST's ACVP-Server
`internalProjection.json` files, which hold each test's inputs together with
its expected results, at a pinned commit:

    usnistgov/ACVP-Server@<COMMIT>:gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json
    usnistgov/ACVP-Server@<COMMIT>:gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json

To regenerate (any machine; nothing here runs the downloaded data):

    C=ad33b3d9504491767f1aa76382464f3b3fa2359e
    for p in ML-KEM-keyGen-FIPS203 ML-KEM-encapDecap-FIPS203; do
      curl -fsSL -o "$p.json" \
        "https://raw.githubusercontent.com/usnistgov/ACVP-Server/$C/gen-val/json-files/$p/internalProjection.json"
    done
    python3 -I scripts/extract-acvp-ml-kem-1024.py ML-KEM-keyGen-FIPS203.json \
        ML-KEM-encapDecap-FIPS203.json > src-tauri/src/vpn/fixtures/acvp-ml-kem-1024.json

The script refuses input whose sha256 is not the one pinned below, so a
regenerated fixture is byte-identical to the committed one (the Rust test pins
the fixture's own sha256 as well). Moving to a newer ACVP-Server commit means
changing COMMIT, both UPSTREAM_SHA256 values and the test's pin together.
"""
import hashlib
import json
import sys

COMMIT = "ad33b3d9504491767f1aa76382464f3b3fa2359e"
UPSTREAM_SHA256 = {
    "keyGen": "d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b",
    "encapDecap": "a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f",
}
PARAMETER_SET = "ML-KEM-1024"
# The fields each function's tests keep: inputs and expected results only.
KEEP = {
    ("keyGen", None): ["tcId", "d", "z", "ek", "dk"],
    ("encapDecap", "encapsulation"): ["tcId", "ek", "m", "c", "k"],
    ("encapDecap", "decapsulation"): ["tcId", "dk", "c", "k", "reason"],
    ("encapDecap", "encapsulationKeyCheck"): ["tcId", "ek", "testPassed", "reason"],
    ("encapDecap", "decapsulationKeyCheck"): ["tcId", "dk", "testPassed", "reason"],
}


def load(path, mode):
    raw = open(path, "rb").read()
    got = hashlib.sha256(raw).hexdigest()
    if got != UPSTREAM_SHA256[mode]:
        sys.exit(f"{path}: sha256 {got}, not the pinned {UPSTREAM_SHA256[mode]} ({mode} at {COMMIT})")
    doc = json.loads(raw)
    if doc.get("algorithm") != "ML-KEM" or doc.get("mode") != mode or doc.get("revision") != "FIPS203":
        sys.exit(f"{path}: not the ML-KEM {mode} FIPS203 vector set")
    return doc


def main(keygen_path, encapdecap_path):
    out = {
        "_source": (
            f"NIST ACVP-Server {COMMIT}, gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json "
            f"(sha256 {UPSTREAM_SHA256['keyGen']}) and gen-val/json-files/ML-KEM-encapDecap-FIPS203/"
            f"internalProjection.json (sha256 {UPSTREAM_SHA256['encapDecap']}): the {PARAMETER_SET} test "
            "groups only, inputs and expected results, hex as published. Regenerate with "
            "scripts/extract-acvp-ml-kem-1024.py (MR-1432)."
        ),
        "groups": [],
    }
    for path, mode in ((keygen_path, "keyGen"), (encapdecap_path, "encapDecap")):
        doc = load(path, mode)
        for group in doc["testGroups"]:
            if group.get("parameterSet") != PARAMETER_SET:
                continue
            function = group.get("function")
            keep = KEEP.get((mode, function))
            if keep is None:
                sys.exit(f"{path}: unexpected {PARAMETER_SET} group function {function!r}")
            out["groups"].append({
                "mode": mode,
                "function": function or "keyGen",
                "tgId": group["tgId"],
                "testType": group["testType"],
                "tests": [{k: t[k] for k in keep if k in t} for t in group["tests"]],
            })
    # One group per line, one test per line: diffable, and LF only.
    lines = ["{", f'  "_source": {json.dumps(out["_source"])},', '  "groups": [']
    for gi, group in enumerate(out["groups"]):
        head = {k: v for k, v in group.items() if k != "tests"}
        lines.append("    " + json.dumps(head)[:-1] + ', "tests": [')
        for ti, test in enumerate(group["tests"]):
            comma = "," if ti + 1 < len(group["tests"]) else ""
            lines.append("      " + json.dumps(test) + comma)
        lines.append("    ]}" + ("," if gi + 1 < len(out["groups"]) else ""))
    lines += ["  ]", "}"]
    # Bytes, not text: a text-mode stdout on Windows would write CRLF, and
    # the test pins the LF bytes git stores.
    sys.stdout.buffer.write(("\n".join(lines) + "\n").encode("ascii"))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: extract-acvp-ml-kem-1024.py <keyGen internalProjection.json> <encapDecap internalProjection.json>")
    main(sys.argv[1], sys.argv[2])
