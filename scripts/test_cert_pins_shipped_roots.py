#!/usr/bin/env python3
"""test_cert_pins_shipped_roots.py - proves check 3s of scripts/check-cert-pins.sh
(scripts/cert_pins_shipped_roots.py, MR-2583) fails the shapes it exists to fail.

A checker nobody has watched fail is a comment with a shell script around it.
The live check runs only on the schedule, against whatever the servers present
that day, so these cases build their own CA hierarchies with openssl and their
own webpki-roots crate (a .tar.gz with a src/lib.rs in the generator's format,
locked by a Cargo.lock carrying its SHA-256), and assert BOTH the verdict and
the words it is reported in:

- the bundle: built only from a crate whose checksum is the lockfile's, only
  from anchors whose written-out certificate IS the anchor (subject and key,
  byte for byte), never from a table it cannot read in full, and without a
  name-constrained anchor. The anchors' bytes come from openssl and from a
  Name built here by hand, never from the checker's own DER reader, so a
  reader that picked the wrong field could not agree with itself;
- the verdict: a full chain to a shipped root passes; the chain without its
  intermediate, a chain to a root the bundle lacks, and the right chain for
  another name fail. So does a chain to a root the runner's own store trusts
  (SSL_CERT_FILE / SSL_CERT_DIR), which a plain `openssl verify` accepts: only
  the shipped roots count.

Runs on every PR that touches a pin file or src-tauri/Cargo.lock (cert-pins.yml,
job `divergence`), and locally with

    python3 scripts/test_cert_pins_shipped_roots.py

Needs python3 and openssl; no third-party modules and no network.
"""
import base64
import hashlib
import importlib.util
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

spec = importlib.util.spec_from_file_location(
    "cert_pins_shipped_roots", os.path.join(ROOT, "scripts", "cert_pins_shipped_roots.py"))
shipped = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shipped)

CONFIG = """\
[req]
distinguished_name = dn
string_mask = utf8only
prompt = no
[dn]
CN = unused
[ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[intermediate]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
[leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:api.example.test
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
"""


class Pki:
    """Throwaway CA hierarchies, made with openssl in `tmp`."""

    def __init__(self, tmp):
        self.tmp = tmp
        self.config = os.path.join(tmp, "openssl.cnf")
        with open(self.config, "w", encoding="utf-8") as f:
            f.write(CONFIG)
        self.serial = 100

    def path(self, name):
        return os.path.join(self.tmp, name)

    def openssl(self, *args):
        subprocess.run(["openssl", *args], check=True, capture_output=True)

    def key(self, name):
        self.openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                     "-out", self.path(name + ".key"))

    def root(self, name, cn):
        self.key(name)
        self.openssl("req", "-x509", "-new", "-config", self.config, "-extensions", "ca",
                     "-key", self.path(name + ".key"), "-subj", "/CN=" + cn, "-days", "2",
                     "-sha256", "-out", self.path(name + ".pem"))
        return self.path(name + ".pem")

    def issue(self, name, cn, issuer, extensions):
        self.key(name)
        self.openssl("req", "-new", "-config", self.config, "-key", self.path(name + ".key"),
                     "-subj", "/CN=" + cn, "-out", self.path(name + ".csr"))
        self.serial += 1
        self.openssl("x509", "-req", "-in", self.path(name + ".csr"),
                     "-CA", self.path(issuer + ".pem"), "-CAkey", self.path(issuer + ".key"),
                     "-set_serial", str(self.serial), "-days", "2", "-sha256",
                     "-extfile", self.config, "-extensions", extensions,
                     "-out", self.path(name + ".pem"))
        return self.path(name + ".pem")

    def der(self, name):
        out = subprocess.run(["openssl", "x509", "-in", self.path(name + ".pem"),
                              "-outform", "DER"], check=True, capture_output=True)
        return out.stdout

    def spki_content(self, name):
        """The certificate's SubjectPublicKeyInfo without its outer header, as
        openssl writes it (not as the checker reads it)."""
        pub = subprocess.run(["openssl", "x509", "-in", self.path(name + ".pem"),
                              "-pubkey", "-noout"], check=True, capture_output=True)
        der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"],
                             input=pub.stdout, check=True, capture_output=True).stdout
        assert der[0] == 0x30
        skip = 2 if der[1] < 0x80 else 2 + (der[1] & 0x7F)
        return der[skip:]


def der_header(tag, content):
    n = len(content)
    if n < 0x80:
        return bytes([tag, n]) + content
    if n <= 0xFF:
        return bytes([tag, 0x81, n]) + content
    return bytes([tag, 0x82, n >> 8, n & 0xFF]) + content


def name_content(cn):
    """A Name of one CN, as `-subj /CN=<cn>` under string_mask utf8only
    encodes it, without its outer SEQUENCE header: built by hand."""
    oid_cn = bytes([0x06, 0x03, 0x55, 0x04, 0x03])
    atv = der_header(0x30, oid_cn + der_header(0x0C, cn.encode("utf-8")))
    return der_header(0x31, atv)


def rust_escape(data):
    """A Rust byte-string body, escaped the way the webpki-roots generator
    writes one."""
    out = []
    for b in data:
        c = chr(b)
        if c == '"':
            out.append('\\"')
        elif c == "\\":
            out.append("\\\\")
        elif c == "\n":
            out.append("\\n")
        elif c == "\t":
            out.append("\\t")
        elif c == "\r":
            out.append("\\r")
        elif c == "\0":
            out.append("\\0")
        elif 0x20 <= b < 0x7F:
            out.append(c)
        else:
            out.append("\\x%02x" % b)
    return "".join(out)


def anchor_block(label, pem_der, subject, spki, constraints=None):
    b64 = base64.b64encode(pem_der).decode("ascii")
    body = "\n".join("   * " + b64[i:i + 64] for i in range(0, len(b64), 64))
    nc = "None" if constraints is None else 'Some(Der::from_slice(b"%s"))' % rust_escape(constraints)
    return (
        "  /*\n"
        "   * Issuer: CN=%s\n"
        "   * Subject: CN=%s\n"
        '   * Label: "%s"\n'
        "   * -----BEGIN CERTIFICATE-----\n"
        "%s\n"
        "   * -----END CERTIFICATE-----\n"
        "   */\n"
        "  TrustAnchor {\n"
        '    subject: Der::from_slice(b"%s"),\n'
        '    subject_public_key_info: Der::from_slice(b"%s"),\n'
        "    name_constraints: %s\n"
        "  },\n\n" % (label, label, label, body, rust_escape(subject), rust_escape(spki), nc))


def lib_rs(blocks):
    return ("//! A compiled-in copy of the root certificates trusted by Mozilla.\n"
            "#![no_std]\n\nuse pki_types::{Der, TrustAnchor};\n\n"
            "pub const TLS_SERVER_ROOTS: &[TrustAnchor<'static>] = &[\n"
            + "".join(blocks) + "];\n")


def crate(version, lib):
    data = lib.encode("utf-8")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo("webpki-roots-%s/src/lib.rs" % version)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def cargo_lock(version, checksum, extra=""):
    return ("# This file is automatically @generated by Cargo.\nversion = 4\n\n"
            "[[package]]\nname = \"rustls-pki-types\"\nversion = \"1.12.0\"\n"
            "source = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
            "checksum = \"%s\"\n\n"
            "[[package]]\nname = \"webpki-roots\"\nversion = \"%s\"\n"
            "source = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
            "checksum = \"%s\"\ndependencies = [\n \"rustls-pki-types\",\n]\n%s"
            % ("0" * 64, version, checksum, extra))


def run():
    passed = failed = 0

    def report(name, problems, text):
        nonlocal passed, failed
        if problems:
            failed += 1
            print("FAIL  %s" % name)
            for p in problems:
                print("        " + p)
            for line in text.splitlines():
                print("        | " + line)
        else:
            passed += 1
            print("ok    %s" % name)

    def judge(name, got_failed, lines, want_failed, needles=(), forbidden=()):
        text = "\n".join(lines)
        problems = []
        if got_failed != want_failed:
            problems.append("failed=%r, expected %r" % (got_failed, want_failed))
        problems += ["output lacks %r" % n for n in needles if n not in text]
        problems += ["output unexpectedly contains %r" % n for n in forbidden if n in text]
        report(name, problems, text)

    tmp = tempfile.mkdtemp(prefix="shipped-roots-test-")
    try:
        pki = Pki(tmp)
        pki.root("rootA", "Test Root A")
        pki.issue("intA", "Test Int A", "rootA", "intermediate")
        pki.issue("leafA", "api.example.test", "intA", "leaf")
        pki.root("rootB", "Test Root B")
        pki.issue("intB", "Test Int B", "rootB", "intermediate")
        pki.issue("leafB", "api.example.test", "intB", "leaf")
        pki.root("rootC", "Test Root C")

        anchor_a = anchor_block("Test Root A", pki.der("rootA"), name_content("Test Root A"),
                                pki.spki_content("rootA"))
        anchor_c = anchor_block("Test Root C", pki.der("rootC"), name_content("Test Root C"),
                                pki.spki_content("rootC"),
                                constraints=bytes([0xA0, 0x07, 0x30, 0x05, 0x82, 0x03]) + b".tr")
        good_lib = lib_rs([anchor_a, anchor_c])
        good = crate("9.9.9", good_lib)
        good_lock = cargo_lock("9.9.9", hashlib.sha256(good).hexdigest())

        print("== check 3s bundle (cert_pins_shipped_roots.build_bundle) ==")
        got_failed, lines, pem = shipped.build_bundle(good_lock, good)
        judge("GOOD_CRATE", got_failed, lines, False,
              ["ok    the roots the app ships: webpki-roots 9.9.9", "2 trust anchors",
               "left out for their name constraints", "Test Root C"])
        bundle = os.path.join(tmp, "shipped.pem")
        with open(bundle, "w", encoding="utf-8") as f:
            f.write(pem)
        problems = []
        if pem.count("-----BEGIN CERTIFICATE-----") != 1 or "# Test Root A" not in pem:
            problems.append("the bundle is not exactly Test Root A")
        if not pem.startswith(shipped.BUNDLE_HEADER + "webpki-roots 9.9.9 "):
            problems.append("the bundle does not name the version it was built from")
        report("GOOD_CRATE_BUNDLE_IS_ROOT_A_ONLY", problems, pem[:200])

        got_failed, lines, _ = shipped.build_bundle(
            cargo_lock("9.9.9", hashlib.sha256(b"another crate").hexdigest()), good)
        judge("CHECKSUM_NOT_THE_LOCKFILES", got_failed, lines, True,
              ["FAIL", "not the", "Cargo.lock records", "refused"])

        swapped = anchor_block("Test Root A", pki.der("rootB"), name_content("Test Root A"),
                               pki.spki_content("rootA"))
        bad = crate("9.9.9", lib_rs([swapped]))
        got_failed, lines, _ = shipped.build_bundle(
            cargo_lock("9.9.9", hashlib.sha256(bad).hexdigest()), bad)
        judge("CERTIFICATE_BESIDE_IT_IS_ANOTHER_ROOT", got_failed, lines, True,
              ["FAIL", "Test Root A", "is NOT this trust anchor"])

        other_key = anchor_block("Test Root A", pki.der("rootA"), name_content("Test Root A"),
                                 pki.spki_content("rootB"))
        bad = crate("9.9.9", lib_rs([other_key]))
        got_failed, lines, _ = shipped.build_bundle(
            cargo_lock("9.9.9", hashlib.sha256(bad).hexdigest()), bad)
        judge("ANCHOR_KEY_IS_ANOTHER_ROOTS", got_failed, lines, True,
              ["FAIL", "is NOT this trust anchor"])

        broken = anchor_a.replace("    name_constraints: None\n", "")
        bad = crate("9.9.9", lib_rs([broken, anchor_c]))
        got_failed, lines, _ = shipped.build_bundle(
            cargo_lock("9.9.9", hashlib.sha256(bad).hexdigest()), bad)
        judge("AN_ANCHOR_THAT_CANNOT_BE_PARSED", got_failed, lines, True,
              ["FAIL", "trust anchor 1 of 2 could not be parsed"])

        bad = crate("9.9.9", lib_rs([]))
        got_failed, lines, _ = shipped.build_bundle(
            cargo_lock("9.9.9", hashlib.sha256(bad).hexdigest()), bad)
        judge("NO_ANCHORS", got_failed, lines, True, ["FAIL", "has no trust anchors"])

        twice = cargo_lock("9.9.9", hashlib.sha256(good).hexdigest(),
                           "\n[[package]]\nname = \"webpki-roots\"\nversion = \"0.26.11\"\n"
                           "source = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
                           "checksum = \"%s\"\n" % ("1" * 64))
        got_failed, lines, _ = shipped.build_bundle(twice, good)
        judge("TWO_WEBPKI_ROOTS_LOCKED", got_failed, lines, True,
              ["FAIL", "locks 2 webpki-roots packages"])

        crlf_lock = good_lock.replace("\n", "\r\n")
        got_failed, lines, _ = shipped.build_bundle(crlf_lock, good)
        judge("CRLF_CHECKOUT_OF_CARGO_LOCK", got_failed, lines, False, ["ok"])

        print()
        print("== check 3s verdict (cert_pins_shipped_roots.verify) ==")
        got_failed, lines = shipped.verify(bundle, "api.example.test", pki.path("leafA.pem"),
                                           [pki.path("intA.pem")])
        judge("FULL_CHAIN_TO_A_SHIPPED_ROOT", got_failed, lines, False,
              ["ok    api.example.test: the live chain validates against the roots the app "
               "ships (webpki-roots 9.9.9)"], ["FAIL"])

        got_failed, lines = shipped.verify(bundle, "api.example.test", pki.path("leafA.pem"), [])
        judge("CHAIN_WITHOUT_ITS_INTERMEDIATE", got_failed, lines, True,
              ["FAIL  api.example.test: the live chain does NOT validate", "webpki-roots 9.9.9",
               "intercepting secure connections"])

        got_failed, lines = shipped.verify(bundle, "api.example.test", pki.path("leafB.pem"),
                                           [pki.path("intB.pem")])
        judge("CHAIN_TO_A_ROOT_THE_APP_DOES_NOT_SHIP", got_failed, lines, True,
              ["FAIL  api.example.test: the live chain does NOT validate"])

        got_failed, lines = shipped.verify(bundle, "other.example.test", pki.path("leafA.pem"),
                                           [pki.path("intA.pem")])
        judge("RIGHT_CHAIN_FOR_ANOTHER_NAME", got_failed, lines, True,
              ["FAIL  other.example.test: the live chain does NOT validate"])

        # The runner's own store trusts root B. A plain openssl verify then
        # accepts B's chain (the control); the check must not.
        store = os.path.join(tmp, "store")
        os.mkdir(store)
        hashed = subprocess.run(["openssl", "x509", "-hash", "-noout", "-in",
                                 pki.path("rootB.pem")], check=True, capture_output=True,
                                text=True).stdout.strip()
        shutil.copy(pki.path("rootB.pem"), os.path.join(store, hashed + ".0"))
        env = dict(os.environ, SSL_CERT_FILE=pki.path("rootB.pem"), SSL_CERT_DIR=store)
        control = subprocess.run(["openssl", "verify", "-untrusted", pki.path("intB.pem"),
                                  pki.path("leafB.pem")], capture_output=True, env=env)
        report("CONTROL_THE_SYSTEM_STORE_TRUSTS_ROOT_B",
               [] if control.returncode == 0 else ["plain openssl verify refused B's chain"],
               (control.stdout + control.stderr).decode("utf-8", "replace"))
        got_failed, lines = shipped.verify(bundle, "api.example.test", pki.path("leafB.pem"),
                                           [pki.path("intB.pem")], env=env)
        judge("SYSTEM_STORE_IS_NEVER_CONSULTED", got_failed, lines, True,
              ["FAIL  api.example.test: the live chain does NOT validate"])

        got_failed, lines = shipped.verify(os.path.join(tmp, "missing.pem"), "api.example.test",
                                           pki.path("leafA.pem"), [pki.path("intA.pem")])
        judge("NO_BUNDLE_IS_NO_PASS", got_failed, lines, True, ["FAIL"])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    print("test_cert_pins_shipped_roots: %d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(run())
