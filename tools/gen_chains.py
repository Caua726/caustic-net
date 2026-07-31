#!/usr/bin/env python3
# =======================================================================
# tools/gen_chains.py
#
# Builds certificate chains for tests/test_verify.cst and writes them to
# tests/vec_chain.cst.
#
#   python3 tools/gen_chains.py > tests/vec_chain.cst
#
# Two kinds of chain.
#
# The REAL one comes out of tests/test_x509.cst's corpus — ietf.org, its Google
# Trust Services intermediate, and GTS Root R4 lifted from the machine's CA
# bundle. It is the proof that this verifier agrees with the internet. It is
# also entirely ECDSA with matched hashes, which is why the rest exist.
#
# The SYNTHETIC ones are built here with openssl, because the algorithms and
# the failures that matter cannot be found lying around:
#
#   * RSA with SHA-256, SHA-384 and SHA-512, and RSASSA-PSS — the real chain
#     has none of these, and a browser meets all of them.
#   * ECDSA where the hash and the curve DISAGREE (a P-256 key signing with
#     SHA-384). The digest then has to be truncated to the group order, and a
#     verifier that skips the truncation still passes every matched-pair chain
#     in existence. This is the one case that silently works until it does not.
#   * Ed25519, which signs the message rather than a digest of it.
#   * An intermediate with CA:FALSE, one whose keyUsage lacks keyCertSign, and
#     a chain one longer than pathLenConstraint allows. Each must come back as
#     its OWN error, not as a generic failure.
#
# Every certificate is generated fresh, so the file changes wholesale when
# regenerated. That is fine: nothing outside it depends on the bytes.
#
# Validity windows are fixed and absolute, and the test passes `now` explicitly
# rather than reading the clock — a corpus pinned to real time is a test that
# fails on a date nobody chose. The one exception is the real chain, whose
# window is whatever GTS issued; ch_now() carries a timestamp inside it.
# =======================================================================

import os
import re
import subprocess
import sys
import tempfile

# openssl dates every certificate from the moment it is generated, and the
# real chain's window is whatever its CA chose, so the instant the test uses
# is COMPUTED from the certificates rather than written here: the latest
# notBefore and the earliest notAfter across everything emitted, halved. A
# hand-picked constant is a test that starts failing on a date nobody chose.
DAYS = 3650


def run(args, **kw):
    r = subprocess.run(args, capture_output=True, **kw)
    if r.returncode != 0:
        sys.exit("%s failed:\n%s" % (" ".join(args), r.stderr.decode()))
    return r.stdout


def genkey(path, kind):
    if kind == "rsa":
        run(["openssl", "genrsa", "-out", path, "2048"])
    elif kind == "p256":
        run(["openssl", "ecparam", "-genkey", "-name", "prime256v1",
             "-noout", "-out", path])
    elif kind == "p384":
        run(["openssl", "ecparam", "-genkey", "-name", "secp384r1",
             "-noout", "-out", path])
    elif kind == "p521":
        run(["openssl", "ecparam", "-genkey", "-name", "secp521r1",
             "-noout", "-out", path])
    elif kind == "ed25519":
        run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", path])
    else:
        sys.exit("unknown key kind %r" % kind)


def sigopts(pss, saltlen="digest"):
    """pss is the MGF1 hash; None means PKCS#1 v1.5. saltlen is openssl's
    rsa_pss_saltlen, where "digest" is the hash length."""
    if not pss:
        return []
    return ["-sigopt", "rsa_padding_mode:pss",
            "-sigopt", "rsa_pss_saltlen:%s" % saltlen,
            "-sigopt", "rsa_mgf1_md:%s" % pss]


def make_root(d, name, kind, md, pss=None, ku=None, bc="critical,CA:TRUE",
              days=DAYS, cn=None):
    key = os.path.join(d, name + ".key")
    crt = os.path.join(d, name + ".der")
    genkey(key, kind)
    ext = os.path.join(d, name + ".ext")
    lines = ["basicConstraints=%s" % bc,
             "subjectKeyIdentifier=hash"]
    if ku:
        lines.append("keyUsage=critical,%s" % ku)
    open(ext, "w").write("\n".join(lines) + "\n")
    args = ["openssl", "req", "-x509", "-new", "-key", key,
            "-subj", "/CN=%s" % (cn or name), "-days", str(days),
            "-outform", "der", "-out", crt, "-extensions", "v3",
            "-config", _minimal_conf(d, ext)]
    if md:
        args += ["-" + md]
    args += sigopts(pss)
    run(args)
    return key, crt


def _minimal_conf(d, extfile):
    """openssl req -x509 wants a config with the extension section in it."""
    conf = extfile + ".cnf"
    open(conf, "w").write(
        "[req]\ndistinguished_name=dn\nprompt=no\n[dn]\n[v3]\n"
        + open(extfile).read())
    return conf


def make_child(d, name, kind, issuer_key, issuer_crt, md, ext_lines,
               pss=None, saltlen="digest"):
    key = os.path.join(d, name + ".key")
    csr = os.path.join(d, name + ".csr")
    crt = os.path.join(d, name + ".der")
    ext = os.path.join(d, name + ".ext")
    genkey(key, kind)
    open(ext, "w").write("\n".join(ext_lines) + "\n")
    args = ["openssl", "req", "-new", "-key", key, "-subj", "/CN=%s" % name,
            "-out", csr]
    if md and kind != "ed25519":
        args += ["-" + md]
    run(args)
    args = ["openssl", "x509", "-req", "-in", csr,
            "-CA", issuer_crt, "-CAform", "der",
            "-CAkey", issuer_key, "-set_serial", str(_serial()),
            "-days", str(DAYS), "-extfile", ext,
            "-outform", "der", "-out", crt]
    if md:
        args += ["-" + md]
    args += sigopts(pss, saltlen)
    run(args)
    return key, crt


_serial_n = [0x1000]


def _serial():
    _serial_n[0] += 1
    return _serial_n[0]


LEAF_EXT = ["basicConstraints=critical,CA:FALSE",
            "keyUsage=critical,digitalSignature",
            "extendedKeyUsage=serverAuth",
            "subjectAltName=DNS:test.example"]


def ca_ext(pathlen=None, ku="digitalSignature,keyCertSign,cRLSign", ca=True):
    bc = "critical,CA:TRUE" if ca else "critical,CA:FALSE"
    if ca and pathlen is not None:
        bc += ",pathlen:%d" % pathlen
    out = ["basicConstraints=" + bc, "subjectKeyIdentifier=hash"]
    if ku:
        out.append("keyUsage=critical," + ku)
    return out


# --- chain construction -------------------------------------------------

CHAINS = []


def add(name, host, want, root_der, chain_ders, note, decoy=None):
    """decoy: a second anchor the test puts in the store BEFORE the real one.
    Used to prove that trust_find_issuer's cheap prefilter cannot decide on its
    own — the decoy's subject DN is built to have the same length and the same
    last two bytes as the real anchor's."""
    CHAINS.append({"name": name, "host": host, "want": want,
                   "root": root_der, "chain": chain_ders, "note": note,
                   "decoy": decoy})


def build(d):
    # --- the plain algorithm sweep: root -> intermediate -> leaf ---------
    for tag, kind, md, pss in (
        ("rsa_sha256", "rsa", "sha256", None),
        ("rsa_sha384", "rsa", "sha384", None),
        ("rsa_sha512", "rsa", "sha512", None),
        ("rsa_pss",    "rsa", "sha256", "sha256"),
        ("rsa_pss384", "rsa", "sha384", "sha384"),
        ("ecdsa_p256", "p256", "sha256", None),
        ("ecdsa_p384", "p384", "sha384", None),
        # A P-256 key signing with SHA-384: the digest is 48 bytes and the
        # group order is 32, so z is the leftmost 32. Skip the truncation and
        # this is the only kind of chain that fails.
        ("ecdsa_trunc", "p256", "sha384", None),
        ("ed25519", "ed25519", None, None),
    ):
        rk, rc = make_root(d, tag + "_root", kind, md, pss=pss,
                           ku="digitalSignature,keyCertSign,cRLSign")
        ik, ic = make_child(d, tag + "_inter", kind, rk, rc, md,
                            ca_ext(pathlen=0), pss=pss)
        _, lc = make_child(d, tag + "_leaf", kind, ik, ic, md,
                           LEAF_EXT, pss=pss)
        add(tag, "test.example", "ok", rc, [lc, ic],
            "%s key, %s" % (kind, pss and (md + "/pss") or (md or "ed25519")))

    # --- the failures, each with its own name ---------------------------
    rk, rc = make_root(d, "neg_root", "p256", "sha256",
                       ku="digitalSignature,keyCertSign,cRLSign")

    # an intermediate that is not a CA
    ik, ic = make_child(d, "notca_inter", "p256", rk, rc, "sha256",
                        ca_ext(ca=False, ku="digitalSignature"))
    _, lc = make_child(d, "notca_leaf", "p256", ik, ic, "sha256", LEAF_EXT)
    add("notca", "test.example", "notca", rc, [lc, ic],
        "intermediate has CA:FALSE")

    # a CA whose keyUsage does not permit signing certificates
    ik, ic = make_child(d, "noks_inter", "p256", rk, rc, "sha256",
                        ca_ext(ku="digitalSignature"))
    _, lc = make_child(d, "noks_leaf", "p256", ik, ic, "sha256", LEAF_EXT)
    add("nokeycertsign", "test.example", "keyuse", rc, [lc, ic],
        "intermediate keyUsage lacks keyCertSign")

    # pathlen:0 with two intermediates below the root
    ak, ac = make_child(d, "plen_a", "p256", rk, rc, "sha256",
                        ca_ext(pathlen=0))
    bk, bc = make_child(d, "plen_b", "p256", ak, ac, "sha256",
                        ca_ext(pathlen=0))
    _, lc = make_child(d, "plen_leaf", "p256", bk, bc, "sha256", LEAF_EXT)
    add("pathlen", "test.example", "pathlen", rc, [lc, bc, ac],
        "two intermediates under a pathlen:0 CA")

    # a leaf whose SAN is for someone else
    ik, ic = make_child(d, "host_inter", "p256", rk, rc, "sha256", ca_ext(pathlen=0))
    other = list(LEAF_EXT)
    other[3] = "subjectAltName=DNS:other.example"
    _, lc = make_child(d, "host_leaf", "p256", ik, ic, "sha256", other)
    add("hostname", "test.example", "hostname", rc, [lc, ic],
        "SAN names other.example")

    # A well-formed chain paired with a store holding a root that signed
    # nothing in it. The leaf has to be a GOOD one — reusing the hostname
    # chain's leaf here would fail on the name first and the vector would
    # prove nothing about anchoring.
    gk, gc = make_child(d, "good_inter", "p256", rk, rc, "sha256",
                        ca_ext(pathlen=0))
    _, glc = make_child(d, "good_leaf", "p256", gk, gc, "sha256", LEAF_EXT)
    _, orphan_root = make_root(d, "orphan_root", "p256", "sha256",
                               ku="digitalSignature,keyCertSign,cRLSign")
    add("untrusted", "test.example", "untrusted", orphan_root,
        [glc, gc], "a sound chain, and a store that does not hold its root")

    # a leaf whose extendedKeyUsage is client-only
    ik, ic = make_child(d, "eku_inter", "p256", rk, rc, "sha256", ca_ext(pathlen=0))
    clientonly = list(LEAF_EXT)
    clientonly[2] = "extendedKeyUsage=clientAuth"
    _, lc = make_child(d, "eku_leaf", "p256", ik, ic, "sha256", clientonly)
    add("eku_client", "test.example", "keyuse", rc, [lc, ic],
        "leaf extendedKeyUsage is clientAuth only")

    # A chain longer than MAX_DEPTH. The root carries no pathLenConstraint, so
    # nothing but the depth ceiling can stop it — otherwise this would come
    # back as PATHLEN and the depth guard would be untested.
    _, deep_root = make_root(d, "deep_root", "p256", "sha256",
                             ku="digitalSignature,keyCertSign,cRLSign")
    deep_key = os.path.join(d, "deep_root.key")
    pk, pc = deep_key, deep_root
    deep = []
    i = 0
    while i < 12:
        pk, pc = make_child(d, "deep_%d" % i, "p256", pk, pc, "sha256", ca_ext())
        deep.append(pc)
        i = i + 1
    _, dlc = make_child(d, "deep_leaf", "p256", pk, pc, "sha256", LEAF_EXT)
    deep.reverse()
    add("depth", "test.example", "depth", deep_root, [dlc] + deep,
        "thirteen links under a root with no pathLenConstraint")

    # An algorithm this library does not implement. P-521 is a real curve with
    # a real OID that tls/x509.cst deliberately does not name, so the chain
    # parses and then has nowhere to go — which must be SIGALG, not BADSIG.
    #
    # With SHA-512 the signature OID is unknown too, so the refusal happens at
    # the hash. With SHA-384 the OID IS known and the refusal has to come from
    # the curve instead — two different guards, one chain each.
    _, p521_root = make_root(d, "p521_root", "p521", "sha512",
                             ku="digitalSignature,keyCertSign,cRLSign")
    p521_key = os.path.join(d, "p521_root.key")
    ik, ic = make_child(d, "p521_inter", "p521", p521_key, p521_root, "sha512",
                        ca_ext(pathlen=0))
    _, lc = make_child(d, "p521_leaf", "p521", ik, ic, "sha512", LEAF_EXT)
    add("sigalg", "test.example", "sigalg", p521_root, [lc, ic],
        "P-521 with SHA-512: neither the OID nor the curve is known")

    _, p521b_root = make_root(d, "p521b_root", "p521", "sha384",
                              ku="digitalSignature,keyCertSign,cRLSign")
    p521b_key = os.path.join(d, "p521b_root.key")
    ik, ic = make_child(d, "p521b_inter", "p521", p521b_key, p521b_root,
                        "sha384", ca_ext(pathlen=0))
    _, lc = make_child(d, "p521b_leaf", "p521", ik, ic, "sha384", LEAF_EXT)
    add("curve_unknown", "test.example", "sigalg", p521b_root, [lc, ic],
        "P-521 with SHA-384: the OID is known, the curve is not")

    # basicConstraints absent entirely, which RFC 5280 reads as "not a CA".
    # The notca chain above says CA:FALSE, which a different guard catches.
    ik, ic = make_child(d, "nobc_inter", "p256", rk, rc, "sha256",
                        ["subjectKeyIdentifier=hash",
                         "keyUsage=critical,digitalSignature,keyCertSign"])
    _, lc = make_child(d, "nobc_leaf", "p256", ik, ic, "sha256", LEAF_EXT)
    add("nobasicconstr", "test.example", "notca", rc, [lc, ic],
        "intermediate has no basicConstraints at all")

    # A sound leaf and an intermediate that did not issue it. Without the
    # issuer-name check this reaches a signature verification and answers
    # BADSIG, which tells the user the wrong thing.
    ok_k, ok_c = make_child(d, "wrong_inter_a", "p256", rk, rc, "sha256",
                            ca_ext(pathlen=0))
    _, wrong_leaf = make_child(d, "wrong_leaf", "p256", ok_k, ok_c, "sha256",
                               LEAF_EXT)
    _, unrelated = make_child(d, "wrong_inter_b", "p256", rk, rc, "sha256",
                              ca_ext(pathlen=0))
    add("wrongchain", "test.example", "untrusted", rc, [wrong_leaf, unrelated],
        "the intermediate the peer sent did not issue the leaf")

    # RSASSA-PSS with a salt that is not the hash length, and one whose MGF1
    # hash disagrees with the message hash. Both are well-formed signatures
    # this library declines to accept, so both are SIGALG.
    prk, prc = make_root(d, "psss_root", "rsa", "sha256", pss="sha256",
                         ku="digitalSignature,keyCertSign,cRLSign")
    pik, pic = make_child(d, "psss_inter", "rsa", prk, prc, "sha256",
                          ca_ext(pathlen=0), pss="sha256")
    _, plc = make_child(d, "psss_leaf", "rsa", pik, pic, "sha256", LEAF_EXT,
                        pss="sha256", saltlen="20")
    add("pss_salt20", "test.example", "sigalg", prc, [plc, pic],
        "PSS leaf with a 20-byte salt under SHA-256")

    _, pmc = make_child(d, "pssm_leaf", "rsa", pik, pic, "sha256", LEAF_EXT,
                        pss="sha1")
    add("pss_mgf1_bad", "test.example", "sigalg", prc, [pmc, pic],
        "PSS leaf whose MGF1 hash is SHA-1 under a SHA-256 signature")

    # A root that expires long before the leaf under it, so a verifier that
    # checks the leaf's window and forgets the anchor's still says yes. The
    # test moves `now` past the root's notAfter, where the leaf is fine.
    srk, src_ = make_root(d, "shortroot_root", "p256", "sha256",
                          ku="digitalSignature,keyCertSign,cRLSign", days=100)
    sik, sic = make_child(d, "shortroot_inter", "p256", srk, src_, "sha256",
                          ca_ext(pathlen=0))
    _, slc = make_child(d, "shortroot_leaf", "p256", sik, sic, "sha256", LEAF_EXT)
    add("shortroot", "test.example", "ok", src_, [slc, sic],
        "the root expires in 100 days, the leaf in 3650")

    # Two roots whose subject DNs have the same length and the same last two
    # bytes. trust_find_issuer compares those before the full DN as a cheap
    # filter; if the full comparison were dropped, the decoy — added first —
    # would be picked and the chain would fail to verify against it.
    _, decoy_root = make_root(d, "collide_decoy", "p256", "sha256",
                              ku="digitalSignature,keyCertSign,cRLSign",
                              cn="collide-decoyXY")
    ck, cc = make_root(d, "collide_real", "p256", "sha256",
                       ku="digitalSignature,keyCertSign,cRLSign",
                       cn="collide-otherXY")
    _ = ck
    cik, cic = make_child(d, "collide_inter", "p256",
                          os.path.join(d, "collide_real.key"), cc, "sha256",
                          ca_ext(pathlen=0))
    _, clc = make_child(d, "collide_leaf", "p256", cik, cic, "sha256", LEAF_EXT)
    add("dn_collision", "test.example", "ok", cc, [clc, cic],
        "a decoy anchor whose DN ends in the same two bytes, same length",
        decoy=decoy_root)


# --- emission -----------------------------------------------------------

WANT = {"ok": 0, "expired": 1, "notyet": 2, "hostname": 3, "untrusted": 4,
        "badsig": 5, "notca": 6, "pathlen": 7, "depth": 8, "sigalg": 9,
        "keyuse": 10}


def cstr(b):
    return '"' + "".join("\\x%02x" % c for c in b) + '"'


def window(der):
    """(notBefore, notAfter) as epoch seconds, via openssl."""
    out = subprocess.run(
        ["openssl", "x509", "-inform", "der", "-noout", "-dates"],
        input=der, capture_output=True).stdout.decode()
    vals = {}
    for line in out.splitlines():
        k, _, v = line.partition("=")
        vals[k] = v.strip()
    return (_parse_openssl_date(vals["notBefore"]),
            _parse_openssl_date(vals["notAfter"]))


def _parse_openssl_date(s):
    import calendar
    import time as _t
    # "Jul 20 21:49:19 2026 GMT"
    return calendar.timegm(_t.strptime(s.replace(" GMT", ""), "%b %d %H:%M:%S %Y"))


def real_chain():
    """LEAF and INTER out of the x509 corpus, and the matching root out of the
    machine's bundle. Returns None if either is unavailable, so the generator
    still runs on a machine without one."""
    src = open("tests/test_x509.cst").read()
    out = {}
    for nm in ("LEAF", "INTER"):
        m = re.search(r'let is \*u8 as ' + nm + r' with imut =\s*"([^"]*)";', src)
        if not m:
            return None
        out[nm] = bytes(int(x, 16)
                        for x in re.findall(r"\\x([0-9a-fA-F]{2})", m.group(1)))

    issuer = subprocess.run(
        ["openssl", "x509", "-inform", "der", "-noout", "-issuer"],
        input=out["INTER"], capture_output=True).stdout.decode()
    want_cn = issuer.split("CN=")[-1].strip()

    for path in ("/etc/ssl/certs/ca-certificates.crt",
                 "/etc/pki/tls/certs/ca-bundle.crt",
                 "/etc/ssl/cert.pem"):
        if not os.path.exists(path):
            continue
        text = open(path, encoding="utf-8", errors="replace").read()
        for m in re.finditer(
                r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                text, re.S):
            subj = subprocess.run(
                ["openssl", "x509", "-noout", "-subject"],
                input=m.group(0), capture_output=True, text=True).stdout
            if want_cn and want_cn in subj:
                der = subprocess.run(
                    ["openssl", "x509", "-outform", "der"],
                    input=m.group(0).encode(), capture_output=True).stdout
                return out["LEAF"], out["INTER"], der, want_cn
    return None


def main():
    with tempfile.TemporaryDirectory() as d:
        build(d)
        for ch in CHAINS:
            ch["root_der"] = open(ch["root"], "rb").read()
            ch["chain_der"] = [open(p, "rb").read() for p in ch["chain"]]
            ch["decoy_der"] = (open(ch["decoy"], "rb").read()
                               if ch["decoy"] else b"")

    real = real_chain()

    # A certificate whose signatureAlgorithm inside the TBS differs from the
    # one outside it. RFC 5280 §4.1.1.2 says they must match, and only the
    # outer one is covered by the signature — so a certificate where they
    # disagree is one built so that a verifier reading one and a policy check
    # reading the other see different algorithms. openssl will not produce it,
    # so the inner OID's last byte is changed here. The TBS comes first in the
    # encoding, so the FIRST occurrence of the algorithm OID is the inner one.
    badalg = b""
    if real:
        base = real[0]
        # sha256WithRSAEncryption / ecdsa-with-SHA256, as they appear in DER.
        for oid in (bytes.fromhex("06092a864886f70d01010b"),
                    bytes.fromhex("06082a8648ce3d040302"),
                    bytes.fromhex("06082a8648ce3d040303")):
            i = base.find(oid)
            if i >= 0 and base.find(oid, i + 1) > i:
                b = bytearray(base)
                b[i + len(oid) - 1] = (b[i + len(oid) - 1] + 1) & 0xFF
                badalg = bytes(b)
                break

    w = sys.stdout.write
    w("// =======================================================\n")
    w("// caustic-net/tests/vec_chain.cst\n")
    w("// Certificate chains, and the one thing wrong with each.\n")
    w("//\n")
    w("// GENERATED by tools/gen_chains.py; see that file for what each chain\n")
    w("// is for and why the real one is not enough on its own.\n")
    w("//\n")
    w("// want: 0 ok · 1 expired · 2 notyet · 3 hostname · 4 untrusted\n")
    w("//       5 badsig · 6 notca · 7 pathlen · 8 depth · 9 sigalg · 10 keyuse\n")
    w("//\n")
    for i, ch in enumerate(CHAINS):
        w("//   %2d  %-14s %-8s %s\n"
          % (i, ch["name"], ch["want"], ch["note"]))
    if real:
        w("//   %2d  %-14s %-8s ietf.org, its GTS intermediate, and %s\n"
          % (len(CHAINS), "real", "ok", real[3]))
    w("// =======================================================\n\n")

    entries = []
    for ch in CHAINS:
        entries.append((ch["name"], "test.example", WANT[ch["want"]],
                        ch["root_der"], ch["chain_der"], ch["decoy_der"]))
    if real:
        leaf, inter, root, _cn = real
        entries.append(("real", "ietf.org", 0, root, [leaf, inter], b""))

    # The instant every chain is checked at: inside every window emitted here.
    lo = None
    hi = None
    for _nm, _hs, _wt, root, chain, _k in entries:
        for der in [root] + list(chain):
            nb, na = window(der)
            lo = nb if lo is None else max(lo, nb)
            hi = na if hi is None else min(hi, na)
    if lo >= hi:
        sys.exit("no instant is inside every certificate's window "
                 "(latest notBefore %d, earliest notAfter %d) — the real "
                 "chain has probably expired; refresh the x509 corpus"
                 % (lo, hi))
    now = lo + (hi - lo) // 2

    w("let is i64 as CH_COUNT with imut = %d;\n" % len(entries))
    w("// The instant every chain below is checked at, computed from the\n")
    w("// certificates themselves: halfway between the latest notBefore and\n")
    w("// the earliest notAfter. The test passes this rather than reading the\n")
    w("// clock, because a corpus pinned to real time is a test that fails on\n")
    w("// a date nobody chose — this one would break the day ietf.org renews.\n")
    w("// Regenerating after that happens is the intended repair.\n")
    w("let is i64 as CH_NOW with imut = %d;\n" % now)
    if real:
        w("let is i64 as CH_REAL with imut = %d;   // the index of the real chain\n"
          % (len(entries) - 1))
    w("\n")

    maxchain = max(len(e[4]) for e in entries)
    for i, (nm, host, want, root, chain, decoy) in enumerate(entries):
        w("let is *u8 as _NM%d with imut = \"%s\";\n" % (i, nm))
        w("let is *u8 as _HS%d with imut = \"%s\";\n" % (i, host))
        w("let is *u8 as _RT%d with imut =\n    %s;\n" % (i, cstr(root)))
        if decoy:
            w("let is *u8 as _DC%d with imut =\n    %s;\n" % (i, cstr(decoy)))
        for j, c in enumerate(chain):
            w("let is *u8 as _C%d_%d with imut =\n    %s;\n" % (i, j, cstr(c)))
    w("\n")

    if badalg:
        w("// A copy of the real leaf whose signatureAlgorithm inside the TBS\n")
        w("// no longer matches the one outside it. cert_parse must refuse it.\n")
        w("let is i64 as BADALG_LEN with imut = %d;\n" % len(badalg))
        w("let is *u8 as BADALG with imut =\n    %s;\n\n" % cstr(badalg))
    else:
        w("let is i64 as BADALG_LEN with imut = 0;\n")
        w("let is *u8 as BADALG with imut = \"\";\n\n")

    # RSASSA-PSS with a trailerField that is not 1. openssl never emits the
    # field at all — 1 is the default and DER omits defaults — so it is made
    # here by retagging the saltLength [2] as a trailerField [3]. That keeps
    # every length identical, which is what makes a one-byte patch possible,
    # and leaves a certificate declaring trailerField 32. RFC 8017 defines
    # only 1, so cert_parse has to refuse it rather than verify under a
    # trailer byte it does not implement.
    badtrail = b""
    for ch in CHAINS:
        if ch["name"] != "rsa_pss":
            continue
        base = ch["chain_der"][0]
        needle = bytes.fromhex("a203020120")          # [2] INTEGER 32
        if base.count(needle) >= 1:
            badtrail = base.replace(needle,
                                    bytes.fromhex("a303020120"))
        break
    if badtrail:
        w("// A PSS certificate whose trailerField is 32 rather than 1.\n")
        w("let is i64 as BADTRAIL_LEN with imut = %d;\n" % len(badtrail))
        w("let is *u8 as BADTRAIL with imut =\n    %s;\n\n" % cstr(badtrail))
    else:
        w("let is i64 as BADTRAIL_LEN with imut = 0;\n")
        w("let is *u8 as BADTRAIL with imut = \"\";\n\n")

    n = len(entries)
    w("let is [%d]*u8 as _nm with mut;\n" % n)
    w("let is [%d]*u8 as _hs with mut;\n" % n)
    w("let is [%d]*u8 as _rt with mut;\n" % n)
    w("let is [%d]i64 as _rtlen with mut;\n" % n)
    w("let is [%d]*u8 as _dc with mut;\n" % n)
    w("let is [%d]i64 as _dclen with mut;\n" % n)
    w("let is [%d]i64 as _want with mut;\n" % n)
    w("let is [%d]i64 as _clen with mut;\n" % n)
    # Flat [chain][slot] tables: no two-dimensional array of pointers is
    # needed, and the stride is a constant the accessor knows.
    w("let is i64 as CH_MAX with imut = %d;\n" % maxchain)
    w("let is [%d]*u8 as _cert with mut;\n" % (n * maxchain))
    w("let is [%d]i64 as _certlen with mut;\n" % (n * maxchain))
    w("let is i64 as _ready with mut = 0;\n\n")

    w("fn _fill() as void {\n")
    for i, (nm, host, want, root, chain, decoy) in enumerate(entries):
        w("    _nm[%d] = _NM%d;  _hs[%d] = _HS%d;  _rt[%d] = _RT%d;"
          "  _rtlen[%d] = %d;\n" % (i, i, i, i, i, i, i, len(root)))
        if decoy:
            w("    _dc[%d] = _DC%d;  _dclen[%d] = %d;\n"
              % (i, i, i, len(decoy)))
        else:
            w("    _dc[%d] = cast(*u8, 0);  _dclen[%d] = 0;\n" % (i, i))
        w("    _want[%d] = %d;  _clen[%d] = %d;\n" % (i, want, i, len(chain)))
        for j, c in enumerate(chain):
            w("    _cert[%d] = _C%d_%d;  _certlen[%d] = %d;\n"
              % (i * maxchain + j, i, j, i * maxchain + j, len(c)))
    w("}\n\n")

    w("fn ch_ensure() as void {\n")
    w("    if (_ready == 0) { _fill(); _ready = 1; }\n")
    w("}\n")
    w("fn ch_name(i as i64) as *u8 { return _nm[i]; }\n")
    w("fn ch_host(i as i64) as *u8 { return _hs[i]; }\n")
    w("fn ch_want(i as i64) as i64 { return _want[i]; }\n")
    w("fn ch_len(i as i64) as i64 { return _clen[i]; }\n")
    w("fn ch_root(i as i64, len as *i64) as *u8 {\n")
    w("    *len = _rtlen[i];\n")
    w("    return _rt[i];\n")
    w("}\n")
    w("// A second anchor to put in the store BEFORE the real one, or null.\n")
    w("// Its subject DN has the same length and the same last two bytes as\n")
    w("// the real anchor's, which is exactly what trust_find_issuer compares\n")
    w("// before it compares the whole name.\n")
    w("fn ch_decoy(i as i64, len as *i64) as *u8 {\n")
    w("    *len = _dclen[i];\n")
    w("    return _dc[i];\n")
    w("}\n")
    w("fn ch_cert(i as i64, j as i64, len as *i64) as *u8 {\n")
    w("    *len = _certlen[i * CH_MAX + j];\n")
    w("    return _cert[i * CH_MAX + j];\n")
    w("}\n")


if __name__ == "__main__":
    main()
