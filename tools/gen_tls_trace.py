#!/usr/bin/env python3
# =======================================================================
# tools/gen_tls_trace.py
#
# Turns RFC 8448 section 3 — "Simple 1-RTT Handshake" — into
# tests/vec_tls.cst.
#
#   curl -LO https://www.rfc-editor.org/rfc/rfc8448.txt
#   python3 tools/gen_tls_trace.py rfc8448.txt > tests/vec_tls.cst
#
# The RFC prints a complete handshake with every intermediate value: the
# client's ephemeral private key, both flights record by record, every
# transcript hash, every derived secret, every traffic key. That is the whole
# reason this file exists. A test that only checks the final Finished says
# "something among thirty byte-exact details is wrong" and nothing more; a
# test that walks the published values says which one, and the difference is
# days.
#
# Two things about the RFC's server certificate decide how the handshake is
# structured, so they are worth stating here rather than being discovered:
#
#   * it is self-signed, CN=rsa, with NO SubjectAltName, and its validity ran
#     out on 2026-07-30. It can never pass chain verification, and it is not
#     supposed to — chain policy is the caller's, and the trace exercises the
#     part that is not: CertificateVerify, the signature over the transcript
#     that proves the peer holds the key.
#   * that signature is rsa_pss_rsae_sha256 over a 1024-bit key, so the trace
#     runs straight through tls/pss.cst.
#
# The blobs are pulled by index from a parse of the whole section, and the
# manifest is printed into the generated file so the indices can be checked
# against the RFC by eye.
# =======================================================================

import json
import re
import sys

# label -> (blob index, what it is). Index into the parsed section-3 blob list.
WANT = [
    ("CLI_PRIV",     0,   "the client's ephemeral x25519 private key"),
    ("CLI_PUB",      1,   "and its public key, as it appears in the ClientHello"),
    ("CH_MSG",       2,   "ClientHello, the handshake message the transcript hashes"),
    ("CH_REC",       4,   "ClientHello, the complete record on the wire"),
    ("SRV_PUB",      8,   "the server's key_share"),
    ("SH_MSG",       9,   "ServerHello, the handshake message"),
    ("SH_REC",      33,   "ServerHello, the complete record"),
    ("ECDHE",       15,   "the x25519 shared secret, IKM for the handshake extract"),
    ("SEC_HS",      16,   "the handshake secret"),
    ("TH_SH",       18,   "transcript hash after ClientHello .. ServerHello"),
    ("C_HS",        20,   "client handshake traffic secret"),
    ("S_HS",        24,   "server handshake traffic secret"),
    ("SEC_MASTER",  31,   "the master secret"),
    ("S_HS_KEY",    36,   "server handshake write key — our read key"),
    ("S_HS_IV",     38,   "server handshake write iv"),
    ("C_HS_KEY",    69,   "client handshake write key — our write key"),
    ("C_HS_IV",     71,   "client handshake write iv"),
    ("EE_MSG",      39,   "EncryptedExtensions"),
    ("CERT_MSG",    40,   "Certificate"),
    ("CV_MSG",      41,   "CertificateVerify — rsa_pss_rsae_sha256 over 1024 bits"),
    ("S_FIN_KEY",   45,   "the server's finished key"),
    ("S_FIN_MSG",   47,   "the server's Finished"),
    ("SRV_FLIGHT",  49,   "EE + Certificate + CertificateVerify + Finished, one record"),
    ("TH_SF",       51,   "transcript hash after the server's Finished"),
    ("C_AP",        53,   "client application traffic secret"),
    ("S_AP",        57,   "server application traffic secret"),
    ("S_AP_KEY",    64,   "server application write key"),
    ("S_AP_IV",     66,   "server application write iv"),
    ("C_FIN_KEY",   79,   "the client's finished key"),
    ("C_FIN_MSG",   81,   "the client's Finished"),
    ("C_FIN_REC",   83,   "the client's Finished, the complete record we must emit"),
    ("C_AP_KEY",    86,   "client application write key"),
    ("C_AP_IV",     88,   "client application write iv"),
    ("TH_CF",       90,   "transcript hash after the client's Finished"),
    ("TICKET_REC",  99,   "NewSessionTicket, after the handshake, under the app key"),
    ("S_DATA_REC", 103,   "the server's application_data record"),
    ("S_ALERT_REC",107,   "the server's close_notify"),
]


def parse_section3(path):
    raw = open(path).read().split("\n")
    skip = re.compile(r"^(Thomson\s+Informational|\x0c|RFC 8448\s+TLS 1\.3 Traces)")
    keep = [ln for ln in raw if not skip.match(ln)]
    a = next(i for i, l in enumerate(keep)
             if l.startswith("3.  Simple 1-RTT Handshake") and i > 60)
    b = next(i for i, l in enumerate(keep)
             if l.startswith("4.  Resumed 0-RTT Handshake") and i > a)
    sec = keep[a:b]

    hexline = re.compile(r"^\s+([0-9a-f]{2}( [0-9a-f]{2})*)\s*$")
    blobs = []
    i = 0
    who = ""
    action = ""
    while i < len(sec):
        m = re.match(r"^   \{(\w+)\}\s+(.*)$", sec[i])
        if m:
            who, action = m.group(1), m.group(2).strip()
        m = re.match(r"^      (.+?) \((\d+) octets\):\s*(.*)$", sec[i])
        if m:
            label, n, rest = m.group(1), int(m.group(2)), m.group(3)
            hexs = re.findall(r"\b[0-9a-f]{2}\b", rest)
            j = i + 1
            while len(hexs) < n and j < len(sec):
                if sec[j].strip() == "":
                    j += 1
                    continue
                if not hexline.match(sec[j]):
                    break
                hexs += re.findall(r"\b[0-9a-f]{2}\b", sec[j])
                j += 1
            if len(hexs) != n:
                sys.exit("blob %r wanted %d octets, read %d" % (label, n, len(hexs)))
            blobs.append({"who": who, "action": action, "label": label,
                          "n": n, "hex": "".join(hexs)})
            i = j
            continue
        i += 1
    return blobs


def cstr(b):
    return '"' + "".join("\\x%02x" % c for c in b) + '"'


def leaf_der(cert_msg):
    """The DER out of a TLS 1.3 Certificate handshake message."""
    if cert_msg[0] != 0x0b:
        sys.exit("not a Certificate message")
    p = 5 + cert_msg[4]              # 4 header, 1 context length, then context
    p += 3                           # certificate_list length
    n = int.from_bytes(cert_msg[p:p + 3], "big")
    p += 3
    return cert_msg[p:p + n]


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: gen_tls_trace.py rfc8448.txt")
    blobs = parse_section3(sys.argv[1])

    vals = {}
    for name, idx, note in WANT:
        if idx >= len(blobs):
            sys.exit("blob %d (%s) is past the end of section 3" % (idx, name))
        vals[name] = (bytes.fromhex(blobs[idx]["hex"]), blobs[idx], note)

    # Sanity: the indices have to still point at what they pointed at. Each of
    # these is a shape the RFC's own text guarantees, so a shift shows up here
    # rather than as a mysterious mismatch inside the handshake.
    checks = [
        ("CH_MSG", lambda b: b[0] == 0x01),
        ("SH_MSG", lambda b: b[0] == 0x02),
        ("EE_MSG", lambda b: b[0] == 0x08),
        ("CERT_MSG", lambda b: b[0] == 0x0b),
        ("CV_MSG", lambda b: b[0] == 0x0f and b[4] == 0x08 and b[5] == 0x04),
        ("S_FIN_MSG", lambda b: b[0] == 0x14),
        ("C_FIN_MSG", lambda b: b[0] == 0x14),
        ("CH_REC", lambda b: b[0] == 0x16),
        ("SH_REC", lambda b: b[0] == 0x16),
        ("SRV_FLIGHT", lambda b: b[0] == 0x17),
        ("C_FIN_REC", lambda b: b[0] == 0x17),
        ("CLI_PRIV", lambda b: len(b) == 32),
        ("ECDHE", lambda b: len(b) == 32),
    ]
    for name, ok in checks:
        if not ok(vals[name][0]):
            sys.exit("blob for %s does not look like what it should — the "
                     "indices in WANT no longer match this RFC text" % name)

    cert = leaf_der(vals["CERT_MSG"][0])

    w = sys.stdout.write
    w("// =======================================================\n")
    w("// caustic-net/tests/vec_tls.cst\n")
    w("// RFC 8448 section 3 — a complete TLS 1.3 handshake, with every\n")
    w("// intermediate value the RFC publishes.\n")
    w("//\n")
    w("// GENERATED by tools/gen_tls_trace.py; see that file for why.\n")
    w("//\n")
    w("// The short version: a handshake that only checks its final Finished\n")
    w("// reports \"one of thirty byte-exact details is wrong\" and nothing\n")
    w("// more. Walking the published values names the step instead.\n")
    w("//\n")
    w("// The server certificate here is self-signed, CN=rsa, has no\n")
    w("// SubjectAltName, and expired on 2026-07-30. It cannot pass chain\n")
    w("// verification and is not meant to: chain policy is the caller's, and\n")
    w("// what this trace exercises is CertificateVerify — the signature over\n")
    w("// the transcript, which is rsa_pss_rsae_sha256 over a 1024-bit key and\n")
    w("// therefore runs through tls/pss.cst.\n")
    w("//\n")
    for name, idx, note in WANT:
        w("//   %-12s %3d octets   %s\n" % (name, len(vals[name][0]), note))
    w("// =======================================================\n\n")

    for name, idx, note in WANT:
        b = vals[name][0]
        w("// %s\n" % note)
        w("let is i64 as %s_N with imut = %d;\n" % (name, len(b)))
        w("let is *u8 as %s with imut =\n    %s;\n" % (name, cstr(b)))
    w("\n")
    w("// The leaf out of the Certificate message, so a test can pin it as an\n")
    w("// anchor without re-parsing the message to find it.\n")
    w("let is i64 as LEAF_N with imut = %d;\n" % len(cert))
    w("let is *u8 as LEAF with imut =\n    %s;\n" % cstr(cert))
    w("\n")
    w("// The cipher suite the trace uses, and the record-layer content types,\n")
    w("// spelled out so the test does not carry magic numbers.\n")
    w("let is i64 as TRACE_SUITE with imut = 0x1301;   // AES_128_GCM_SHA256\n")


if __name__ == "__main__":
    main()
