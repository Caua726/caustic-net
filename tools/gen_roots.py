#!/usr/bin/env python3
# =======================================================================
# tools/gen_roots.py
#
# Turns a PEM bundle of trust anchors into tls/roots.cst, the set caustic-net
# falls back to when the machine has no CA bundle of its own — causticos, a
# scratch container, Windows.
#
#   python3 tools/gen_roots.py /etc/ssl/certs/ca-certificates.crt \
#       > tls/roots.cst
#
# The certificates are emitted as base64 with the line breaks removed, not as
# \xNN escapes. Two reasons, and the size is the smaller one:
#
#   * base64 costs 1.33 bytes of source per byte of DER against 4 for \xNN,
#     so ~129 KB of anchors is 172 KB of source instead of 517 KB;
#   * the embedded set and a bundle read from disk then decode through exactly
#     the same function, so there is one decoder to get right instead of two.
#
# The header records which bundle this came from and its SHA-256, because a
# root set that nobody can date is a root set nobody will refresh.
# =======================================================================

import base64
import hashlib
import os
import re
import sys
import time


def parse_bundle(path):
    """[(name, der)] in file order. The name is the comment line above the
    block if the bundle carries one, which Debian's and Arch's do; it is only
    ever used for diagnostics, so a missing one is not an error."""
    text = open(path, encoding="utf-8", errors="replace").read()
    out = []
    pos = 0
    while True:
        b = text.find("-----BEGIN CERTIFICATE-----", pos)
        if b < 0:
            break
        e = text.find("-----END CERTIFICATE-----", b)
        if e < 0:
            sys.exit("unterminated PEM block at offset %d" % b)
        body = text[b + len("-----BEGIN CERTIFICATE-----"):e]
        try:
            der = base64.b64decode("".join(body.split()), validate=True)
        except Exception as exc:
            sys.exit("bad base64 at offset %d: %s" % (b, exc))

        name = ""
        head = text.rfind("\n", 0, b)
        if head > 0:
            prev = text.rfind("\n", 0, head)
            line = text[prev + 1:head].strip()
            if line.startswith("#"):
                name = line.lstrip("#").strip()
        out.append((name, der))
        pos = e + 1
    return out


def cstr(s):
    """A Caustic string literal. Base64 and the names are plain ASCII, so the
    only characters needing care are the quote and the backslash."""
    esc = s.replace("\\", "\\\\").replace('"', '\\"')
    return '"' + esc + '"'


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: gen_roots.py <bundle.pem>")
    path = sys.argv[1]
    certs = parse_bundle(path)
    if not certs:
        sys.exit("no certificates in %s" % path)

    raw = open(path, "rb").read()
    digest = hashlib.sha256(raw).hexdigest()
    real = os.path.realpath(path)
    stamp = time.strftime("%Y-%m-%d", time.gmtime(os.stat(path).st_mtime))
    total = sum(len(d) for _, d in certs)
    biggest = max(len(d) for _, d in certs)

    w = sys.stdout.write
    w("// =======================================================\n")
    w("// caustic-net/tls/roots.cst\n")
    w("// Trust anchors, embedded.\n")
    w("//\n")
    w("// GENERATED. Do not edit by hand — run\n")
    w("//     python3 tools/gen_roots.py <bundle.pem> > tls/roots.cst\n")
    w("//\n")
    w("// Source:  %s\n" % real)
    w("//          dated %s, sha256 %s\n" % (stamp, digest))
    w("// Content: %d anchors, %d bytes of DER, largest %d.\n"
      % (len(certs), total, biggest))
    w("//\n")
    w("// This is the FALLBACK. tls/trust.cst probes the machine's own bundle\n")
    w("// first and only reaches here when there is none, because a root set\n")
    w("// compiled into a binary cannot be updated and cannot have an anchor\n")
    w("// removed from it — and both of those happen. Anything long-lived that\n")
    w("// runs on a machine with a real bundle should be using that one.\n")
    w("//\n")
    w("// The certificates are base64 with the line breaks stripped, which is\n")
    w("// what caustic-crypto's base64_decode accepts (it returns -1 on the\n")
    w("// first newline), and is the same shape trust.cst produces when it\n")
    w("// reads a PEM file off disk. One decoder, not two.\n")
    w("// =======================================================\n\n")

    w("let is i64 as ROOTS_COUNT with imut = %d;\n" % len(certs))
    w("// Total decoded size, so the store can take one allocation of a known\n")
    w("// size rather than growing while it walks the list.\n")
    w("let is i64 as ROOTS_DER_BYTES with imut = %d;\n" % total)
    w("let is i64 as ROOTS_DER_MAX with imut = %d;\n" % biggest)
    w("let is *u8 as ROOTS_SOURCE with imut = %s;\n\n"
      % cstr("%s dated %s" % (real, stamp)))

    for i, (name, der) in enumerate(certs):
        w("let is *u8 as _R%03d with imut =\n    %s;\n"
          % (i, cstr(base64.b64encode(der).decode())))
    w("\n")
    for i, (name, _) in enumerate(certs):
        w("let is *u8 as _NM%03d with imut = %s;\n" % (i, cstr(name or "?")))
    w("\n")

    n = len(certs)
    w("let is [%d]*u8 as _b64 with mut;\n" % n)
    w("let is [%d]*u8 as _name with mut;\n" % n)
    w("let is [%d]i64 as _b64len with mut;\n" % n)
    w("let is [%d]i64 as _derlen with mut;\n" % n)
    w("let is i64 as _ready with mut = 0;\n\n")

    w("fn _fill() as void {\n")
    for i, (_, der) in enumerate(certs):
        b64 = base64.b64encode(der).decode()
        w("    _b64[%d] = _R%03d;  _b64len[%d] = %d;  _derlen[%d] = %d;"
          "  _name[%d] = _NM%03d;\n"
          % (i, i, i, len(b64), i, len(der), i, i))
    w("}\n\n")

    w("fn roots_ensure() as void {\n")
    w("    if (_ready == 0) { _fill(); _ready = 1; }\n")
    w("}\n\n")
    w("fn roots_count() as i64 { return ROOTS_COUNT; }\n\n")
    w("// The i-th anchor as base64 text, with its length written through\n")
    w("// `len`. Call roots_ensure() first.\n")
    w("fn roots_b64(i as i64, len as *i64) as *u8 {\n")
    w("    *len = _b64len[i];\n")
    w("    return _b64[i];\n")
    w("}\n\n")
    w("// How many bytes the i-th anchor decodes to, so a caller can check its\n")
    w("// buffer before decoding rather than after.\n")
    w("fn roots_der_len(i as i64) as i64 { return _derlen[i]; }\n\n")
    w("// The bundle's own label for the anchor, for diagnostics only. Never\n")
    w("// used for matching: the subject DN in the certificate is the identity.\n")
    w("fn roots_name(i as i64) as *u8 { return _name[i]; }\n")


if __name__ == "__main__":
    main()
