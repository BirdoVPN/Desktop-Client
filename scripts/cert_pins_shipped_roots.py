#!/usr/bin/env python3
"""Check 3s of scripts/check-cert-pins.sh: the live chain against the roots the
app SHIPS (MR-2583, review D473-I1 of Desktop #473).

    python3 scripts/cert_pins_shipped_roots.py bundle <Cargo.lock> <out.pem> [<webpki-roots .crate>]
    python3 scripts/cert_pins_shipped_roots.py verify <roots.pem> <hostname> <leaf.pem> [<presented.pem> ...]

WHY. The app's TLS verifier (src-tauri/src/api/cert_pin.rs, src-tauri/src/vpn/doh.rs)
runs WebPKI against the compiled-in webpki-roots store BEFORE it checks the SPKI
pins, and since MR-2548 (#473) its UnknownIssuer is told to every user as
"Something on this network or computer is intercepting secure connections".
Two SERVER-side changes produce exactly that error while a pin still matches:
the API serving its chain without the intermediate, and a new CA hierarchy that
the shipped root set lacks. Check 3 sees neither: it asks only whether a pinned
SPKI is somewhere in the chain. This asks what the app asks: does the chain, as
presented, validate to a root of the webpki-roots version src-tauri/Cargo.lock
locks, for the name the app dials?

bundle: the webpki-roots crate at the version and checksum src-tauri/Cargo.lock
records (downloaded from static.crates.io unless a .crate is given, and refused
unless its SHA-256 is the lockfile's, as cargo refuses it), turned into a PEM
bundle. Each trust anchor is read from the crate's own source: the subject and
SubjectPublicKeyInfo bytes WebPKI checks against, and the certificate the
generator wrote beside them in a comment. A certificate goes into the bundle
only when its subject and SPKI are byte for byte that anchor's, so the bundle
is the shipped list, not whatever the comments say. An anchor with name
constraints (1.0.11 has one: TUBITAK, .tr only) is left out: openssl would
trust it unconstrained, and the app does not.

verify: `openssl verify` trusting ONLY that bundle (-no-CApath -no-CAstore: the
runner's system store is never consulted), with the rest of the presented chain
as untrusted intermediates, the TLS-server purpose and the hostname the app
dials. Exit 1 when the chain does not validate.

WHAT THIS IS NOT. It is openssl's path validation over the shipped roots, not
WebPKI itself. They agree on what this exists to catch (a missing intermediate,
a root the set lacks, a wrong name); at the edges openssl is the stricter one
that is known (it also checks the root certificate's own dates, which WebPKI
does not read). It checks the version main locks, not every release users run.
The verifier itself is proved by the real-handshake tests in cert_pin.rs.

Needs python3 and openssl; no third-party modules.
"""
import base64
import hashlib
import io
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

CRATE = "webpki-roots"
CRATES_IO_SOURCES = (
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
)
DOWNLOAD = "https://static.crates.io/crates/{name}/{name}-{version}.crate"
TABLE = re.compile(r"TLS_SERVER_ROOTS\s*:\s*&\[TrustAnchor<'static>\]\s*=\s*&\[")
ANCHOR_START = re.compile(r"TrustAnchor\s*\{")
BYTES = r'b"((?:[^"\\]|\\.)*)"'
ANCHOR_BODY = re.compile(
    r"TrustAnchor\s*\{\s*"
    r"subject:\s*Der::from_slice\(" + BYTES + r"\),\s*"
    r"subject_public_key_info:\s*Der::from_slice\(" + BYTES + r"\),\s*"
    r"name_constraints:\s*(None|Some\(Der::from_slice\(" + BYTES + r"\)\))\s*,?\s*\}",
    re.S)
PEM = re.compile(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", re.S)
LABEL = re.compile(r'Label:\s*"([^"]*)"')
BUNDLE_HEADER = "# cert_pins_shipped_roots.py: "


def locked_crate(lock_text):
    """(version, checksum) of the one crates.io webpki-roots in a Cargo.lock,
    or raises ValueError saying why not."""
    found = []
    for block in lock_text.replace("\r\n", "\n").split("[[package]]")[1:]:
        fields = dict(re.findall(r'^(name|version|source|checksum) = "([^"]*)"$', block, re.M))
        if fields.get("name") == CRATE:
            found.append(fields)
    if len(found) != 1:
        raise ValueError("Cargo.lock locks %d %s packages, not exactly one; this check does "
                         "not know which of them the app links" % (len(found), CRATE))
    pkg = found[0]
    if pkg.get("source") not in CRATES_IO_SOURCES:
        raise ValueError("%s %s does not come from crates.io (source %r)"
                         % (CRATE, pkg.get("version"), pkg.get("source")))
    if not re.fullmatch(r"[0-9a-f]{64}", pkg.get("checksum", "")):
        raise ValueError("%s %s has no SHA-256 checksum in Cargo.lock" % (CRATE, pkg.get("version")))
    if not re.fullmatch(r"[0-9A-Za-z.+-]+", pkg.get("version", "")):
        raise ValueError("%s has an unreadable version %r" % (CRATE, pkg.get("version")))
    return pkg["version"], pkg["checksum"]


def download(version):
    url = DOWNLOAD.format(name=CRATE, version=version)
    request = urllib.request.Request(url, headers={"User-Agent": "birdo-desktop-ci (cert pins)"})
    last = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.read()
        except OSError as error:
            last = error
            if attempt < 2:
                time.sleep(3)
    raise ValueError("could not download %s: %s" % (url, last))


def rust_bytes(literal):
    """The bytes a Rust byte-string literal's body (between b" and ") denotes."""
    simple = {"n": 10, "r": 13, "t": 9, "\\": 92, "0": 0, "'": 39, '"': 34}
    out = bytearray()
    i = 0
    while i < len(literal):
        c = literal[i]
        if c == "\\":
            d = literal[i + 1]
            if d == "x":
                out.append(int(literal[i + 2:i + 4], 16))
                i += 4
                continue
            if d in simple:
                out.append(simple[d])
                i += 2
                continue
            raise ValueError("unknown escape \\%s in a byte string" % d)
        if ord(c) > 0x7F:
            raise ValueError("a non-ASCII character in a byte string")
        out.append(ord(c))
        i += 1
    return bytes(out)


def tlv(der, at):
    """(tag, content start, content end) of the DER element at `at`."""
    tag = der[at]
    length = der[at + 1]
    at += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4:
            raise ValueError("an unsupported DER length")
        length = int.from_bytes(der[at:at + n], "big")
        at += n
    if at + length > len(der):
        raise ValueError("a DER element runs past its certificate")
    return tag, at, at + length


def subject_and_spki(der):
    """The subject Name and the SubjectPublicKeyInfo of a certificate, each
    without its outer SEQUENCE header: exactly the bytes a webpki
    `TrustAnchor` carries."""
    _, start, _ = tlv(der, 0)                    # Certificate
    _, start, end = tlv(der, start)              # TBSCertificate
    fields = []
    while start < end:
        tag, content, start = tlv(der, start)
        fields.append((tag, content, start))
    if fields and fields[0][0] == 0xA0:          # [0] version
        fields = fields[1:]
    # serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
    if len(fields) < 6 or fields[4][0] != 0x30 or fields[5][0] != 0x30:
        raise ValueError("not an X.509 certificate this check can read")
    return der[fields[4][1]:fields[4][2]], der[fields[5][1]:fields[5][2]]


def pem_of(der, label):
    body = base64.b64encode(der).decode("ascii")
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return "# %s\n-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n" % (
        label, "\n".join(lines))


def anchors_of(lib_rs):
    """[(label, constrained, der)] for every trust anchor of webpki-roots'
    src/lib.rs, or raises ValueError. `der` is the certificate written beside
    the anchor, after it was checked to BE that anchor."""
    table = TABLE.search(lib_rs)
    if not table:
        raise ValueError("src/lib.rs has no TLS_SERVER_ROOTS table")
    end = lib_rs.find("\n];", table.end())
    if end < 0:
        raise ValueError("the TLS_SERVER_ROOTS table never closes")
    text = lib_rs[table.end():end]
    starts = [m.start() for m in ANCHOR_START.finditer(text)]
    if not starts:
        raise ValueError("the TLS_SERVER_ROOTS table has no trust anchors")
    anchors = []
    previous_end = 0
    for n, start in enumerate(starts, 1):
        body = ANCHOR_BODY.match(text, start)
        if not body or (n < len(starts) and body.end() > starts[n]):
            raise ValueError("trust anchor %d of %d could not be parsed" % (n, len(starts)))
        comment = text[previous_end:start]
        previous_end = body.end()
        pems = PEM.findall(comment)
        label = LABEL.search(comment)
        label = label.group(1) if label else "trust anchor %d" % n
        if len(pems) != 1:
            raise ValueError("%s: %d certificates written beside it, not one" % (label, len(pems)))
        b64 = "".join(line.strip().lstrip("*").strip() for line in pems[0].splitlines())
        try:
            der = base64.b64decode(b64, validate=True)
            subject, spki = subject_and_spki(der)
        except (ValueError, IndexError) as error:
            raise ValueError("%s: the certificate beside it cannot be read (%s)" % (label, error))
        if subject != rust_bytes(body.group(1)) or spki != rust_bytes(body.group(2)):
            raise ValueError("%s: the certificate beside it is NOT this trust anchor (subject or "
                             "key differs), so it cannot stand in for it" % label)
        anchors.append((label, body.group(3) != "None", der))
    return anchors


def build_bundle(lock_text, crate_bytes):
    """(failed, lines, pem_text) for a Cargo.lock and the .crate it locks."""
    try:
        version, checksum = locked_crate(lock_text)
        actual = hashlib.sha256(crate_bytes).hexdigest()
        if actual != checksum:
            raise ValueError("the %s %s crate's SHA-256 is %s, not the %s Cargo.lock records: "
                             "refused, as cargo would refuse it" % (CRATE, version, actual, checksum))
        with tarfile.open(fileobj=io.BytesIO(crate_bytes), mode="r:gz") as crate:
            member = crate.getmember("%s-%s/src/lib.rs" % (CRATE, version))
            if not member.isfile():
                raise ValueError("%s %s: src/lib.rs is not a file" % (CRATE, version))
            lib_rs = crate.extractfile(member).read().decode("utf-8")
        anchors = anchors_of(lib_rs)
    except (ValueError, KeyError, tarfile.TarError, OSError, UnicodeDecodeError) as error:
        return True, ["FAIL  the roots the app ships could not be read: %s" % error], ""
    kept = [(label, der) for label, constrained, der in anchors if not constrained]
    left_out = [label for label, constrained, _ in anchors if constrained]
    header = "%s%s %s (src-tauri/Cargo.lock, sha256 %s...), %d of %d trust anchors\n" % (
        BUNDLE_HEADER, CRATE, version, checksum[:12], len(kept), len(anchors))
    lines = ["ok    the roots the app ships: %s %s (Cargo.lock checksum %s...), %d trust "
             "anchors, every one the certificate written beside it"
             % (CRATE, version, checksum[:12], len(anchors))]
    if left_out:
        lines.append("      left out for their name constraints (openssl would trust them "
                     "unconstrained): %s" % ", ".join(left_out))
    return False, lines, header + "".join(pem_of(der, label) for label, der in kept)


def shipped_version(roots):
    try:
        with open(roots, encoding="utf-8") as f:
            first = f.readline()
    except OSError:
        return "?"
    return first[len(BUNDLE_HEADER):].split(" (")[0] if first.startswith(BUNDLE_HEADER) else "?"


def verify(roots, hostname, leaf, presented, env=None, openssl="openssl"):
    """(failed, lines): whether the chain `leaf` + `presented` validates for
    `hostname` against the bundle `roots` and nothing else."""
    shipped = shipped_version(roots)
    command = [openssl, "verify", "-no-CApath", "-no-CAstore", "-CAfile", roots,
               "-purpose", "sslserver", "-verify_hostname", hostname, "-show_chain"]
    with tempfile.TemporaryDirectory() as tmp:
        if presented:
            untrusted = os.path.join(tmp, "presented.pem")
            with open(untrusted, "w", encoding="utf-8") as out:
                for path in presented:
                    with open(path, encoding="utf-8") as f:
                        out.write(f.read().strip() + "\n")
            command += ["-untrusted", untrusted]
        command.append(leaf)
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=60, env=env)
        except (OSError, subprocess.TimeoutExpired) as error:
            return True, ["FAIL  %s: openssl verify could not run (%s)" % (hostname, error)]
    said = [line.strip() for line in (result.stdout + result.stderr).splitlines() if line.strip()]
    chain = ["        " + line for line in said if line.startswith("depth=")]
    if result.returncode == 0:
        return False, ["ok    %s: the live chain validates against the roots the app ships "
                       "(%s), for that name" % (hostname, shipped)] + chain
    errors = [line for line in said if "error" in line.lower()] or said[-1:]
    return True, [
        "FAIL  %s: the live chain does NOT validate against the roots the app ships (%s): %s"
        % (hostname, shipped, "; ".join(errors)),
        "        The app refuses this chain BEFORE it reads a pin, and tells every user that "
        "their network",
        "        or computer is intercepting secure connections (MR-2548). Likely the server "
        "stopped",
        "        sending its intermediate, or moved to a CA these roots lack: fix the server's "
        "chain, or",
        "        ship a webpki-roots that has its root first.",
    ] + chain


def main(argv):
    if len(argv) >= 4 and argv[1] == "bundle" and len(argv) <= 5:
        with open(argv[2], encoding="utf-8") as f:
            lock_text = f.read()
        try:
            if len(argv) == 5:
                with open(argv[4], "rb") as f:
                    crate_bytes = f.read()
            else:
                crate_bytes = download(locked_crate(lock_text)[0])
        except (ValueError, OSError) as error:
            print("FAIL  the roots the app ships could not be read: %s" % error)
            return 1
        failed, lines, pem = build_bundle(lock_text, crate_bytes)
        for line in lines:
            print(line)
        if failed:
            return 1
        with open(argv[3], "w", encoding="utf-8") as out:
            out.write(pem)
        return 0
    if len(argv) >= 5 and argv[1] == "verify":
        failed, lines = verify(argv[2], argv[3], argv[4], argv[5:])
        for line in lines:
            print(line)
        return 1 if failed else 0
    print(__doc__.split("\n\n")[1], file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
