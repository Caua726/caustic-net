#!/usr/bin/env python3
# =======================================================================
# tools/gen_pss_vectors.py
#
# Turns NIST's CAVP file SigVerPSS_186-3.rsp into tests/vec_pss.cst.
#
#   curl -LO https://csrc.nist.gov/csrc/media/projects/\
# cryptographic-algorithm-validation-program/documents/dss/186-3rsatestvectors.zip
#   unzip 186-3rsatestvectors.zip SigVerPSS_186-3.rsp
#   python3 tools/gen_pss_vectors.py SigVerPSS_186-3.rsp > tests/vec_pss.cst
#
# The CAVP file carries 270 vectors: three modulus sizes x five hashes x
# eighteen cases, and each group of eighteen is three P plus three each of
# five distinct failure reasons.
#
# What this takes, and what it drops:
#
#   mod 2048, SHA-256/384/512 .... all 18 each.  Salt length equals the hash
#                                  length here, which is the case TLS 1.3 and
#                                  every real RSASSA-PSS certificate use.
#   mod 1024 and 3072, same three  3 P plus ONE vector per failure reason.
#                                  These groups exist for their salt lengths
#                                  (20 at 1024; 1 and 24 at 3072), which is
#                                  what proves the verifier reads sLen from
#                                  its argument instead of assuming hLen.
#   SHA-1 and SHA-224 ............ dropped entirely. Neither appears in a
#                                  TLS 1.3 signature_algorithms list nor in a
#                                  certificate this decade.
#
# So: 102 of 270, every failure reason represented at every modulus size.
# The salt VALUE is not emitted — EMSA-PSS-VERIFY recovers the salt from the
# padding and only needs its length.
# =======================================================================

import re
import sys
from collections import defaultdict

WANT_SHA = ("SHA256", "SHA384", "SHA512")
FULL_MOD = (2048,)          # groups taken whole
EDGE_MOD = (1024, 3072)     # groups sampled: 3 P + 1 per reason


def parse(path):
    mod = None
    n = None
    cur = {}
    out = []
    for line in open(path):
        line = line.strip()
        m = re.match(r"\[mod = (\d+)\]", line)
        if m:
            mod = int(m.group(1))
            continue
        if not line or line.startswith("#"):
            continue
        if " = " not in line:
            continue
        k, v = line.split(" = ", 1)
        if k == "n":
            n = v
            continue
        if k == "SHAAlg":
            cur = {"mod": mod, "n": n, "sha": v}
        elif k == "Result":
            cur["res"] = v
            out.append(dict(cur))
        else:
            cur[k] = v
    return out


def reason(res):
    """0 for a pass, else the CAVP failure code 1..5."""
    if res.startswith("P"):
        return 0
    m = re.match(r"F \((\d+)", res)
    return int(m.group(1))


def saltlen(rec):
    """CAVP writes a zero-length salt as the single byte 00, not as an empty
    field — 72 of the 270 vectors are like that, and reading them as one byte
    makes every one of them fail at the 0x01 separator."""
    v = rec["SaltVal"]
    if v == "00":
        return 0
    return len(v) // 2


def select(recs):
    groups = defaultdict(list)
    for r in recs:
        if r["sha"] not in WANT_SHA:
            continue
        groups[(r["mod"], r["sha"])].append(r)

    picked = []
    for mod in FULL_MOD + EDGE_MOD:
        for sha in WANT_SHA:
            g = groups.get((mod, sha))
            if not g:
                sys.exit("missing group mod=%d %s" % (mod, sha))
            if mod in FULL_MOD:
                picked.extend(g)
            else:
                seen = set()
                for r in g:
                    code = reason(r["res"])
                    if code == 0:
                        picked.append(r)          # keep every pass
                    elif code not in seen:
                        seen.add(code)
                        picked.append(r)          # one per failure reason
    return picked


def cstr(hexstr):
    """A Caustic string literal of the bytes in `hexstr`."""
    b = bytes.fromhex(hexstr)
    return '"' + "".join("\\x%02x" % c for c in b) + '"'


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: gen_pss_vectors.py SigVerPSS_186-3.rsp")
    recs = select(parse(sys.argv[1]))

    # Each [mod = N] block carries FIFTEEN moduli, not one — a fresh key per
    # (mod, SHAAlg) group. Keying the table by modulus size instead of by the
    # value gives every vector the last group's key, and then nothing verifies
    # for a reason that looks like a bug in the verifier.
    nsym = {}
    for r in recs:
        if r["n"] not in nsym:
            nsym[r["n"]] = "_N%02d" % len(nsym)

    w = sys.stdout.write
    w("// =======================================================\n")
    w("// caustic-net/tests/vec_pss.cst\n")
    w("// NIST CAVP RSASSA-PSS verification vectors.\n")
    w("//\n")
    w("// GENERATED. Do not edit by hand — run\n")
    w("//     python3 tools/gen_pss_vectors.py SigVerPSS_186-3.rsp > tests/vec_pss.cst\n")
    w("// against the file of that name in NIST's 186-3rsatestvectors.zip.\n")
    w("//\n")
    w("// %d of the archive's 270 vectors: all 18 at mod 2048 for each of\n" % len(recs))
    w("// SHA-256/384/512 (salt length == hash length, the case TLS 1.3 and every\n")
    w("// real RSASSA-PSS certificate use), plus, at mod 1024 and 3072, the three\n")
    w("// passes and one vector per failure reason — those groups are here for\n")
    w("// their salt lengths of 20, 1 and 24, which is what proves the verifier\n")
    w("// reads sLen from its argument instead of assuming hLen. SHA-1 and\n")
    w("// SHA-224 are dropped: neither appears in a TLS 1.3 signature_algorithms\n")
    w("// list nor in a certificate this decade.\n")
    w("//\n")
    w("// The salt VALUE is absent on purpose: EMSA-PSS-VERIFY recovers the salt\n")
    w("// from the padding and needs only its length. A salt length of 0 is real:\n")
    w("// CAVP spells it as the byte 00, and reading that as one byte makes the\n")
    w("// vector fail at the separator.\n")
    w("//\n")
    w("// Each [mod = N] block in the source file carries fifteen different\n")
    w("// moduli, one per (mod, SHAAlg) group, so the table below points each\n")
    w("// vector at its own key.\n")
    w("//\n")
    w("// want = 1 pass, 0 fail. reason is CAVP's code:\n")
    w("//   1 message changed · 2 public key e changed · 3 signature changed\n")
    w("//   4 EM malformed, hash moved left · 5 EM malformed, 00 pad byte removed\n")
    w("// =======================================================\n\n")

    w("let is i64 as PV_COUNT with imut = %d;\n\n" % len(recs))

    for hexn, sym in nsym.items():
        w("let is *u8 as %s with imut =\n    %s;\n" % (sym, cstr(hexn)))
    w("\n")

    for i, r in enumerate(recs):
        w("let is *u8 as _M%03d with imut =\n    %s;\n" % (i, cstr(r["Msg"])))
        w("let is *u8 as _S%03d with imut =\n    %s;\n" % (i, cstr(r["S"])))
        e = r["e"].lstrip("0")
        if len(e) % 2:
            e = "0" + e
        w("let is *u8 as _E%03d with imut = %s;\n" % (i, cstr(e)))
    w("\n")

    n = len(recs)
    for name, ty in (("_n", "*u8"), ("_e", "*u8"), ("_m", "*u8"), ("_s", "*u8")):
        w("let is [%d]%s as %s with mut;\n" % (n, ty, name))
    for name in ("_nlen", "_elen", "_mlen", "_siglen", "_sha", "_salt", "_want", "_reason"):
        w("let is [%d]i64 as %s with mut;\n" % (n, name))
    w("let is i64 as _ready with mut = 0;\n\n")

    w("fn _fill() as void {\n")
    for i, r in enumerate(recs):
        e = r["e"].lstrip("0")
        if len(e) % 2:
            e = "0" + e
        w("    _n[%d] = %s;  _nlen[%d] = %d;  _e[%d] = _E%03d;  _elen[%d] = %d;\n"
          % (i, nsym[r["n"]], i, len(r["n"]) // 2, i, i, i, len(e) // 2))
        w("    _m[%d] = _M%03d;  _mlen[%d] = %d;  _s[%d] = _S%03d;  _siglen[%d] = %d;\n"
          % (i, i, i, len(r["Msg"]) // 2, i, i, i, len(r["S"]) // 2))
        w("    _sha[%d] = %s;  _salt[%d] = %d;  _want[%d] = %d;  _reason[%d] = %d;\n"
          % (i, r["sha"][3:], i, saltlen(r), i,
             1 if reason(r["res"]) == 0 else 0, i, reason(r["res"])))
    w("}\n\n")

    w("fn pv_ensure() as void {\n")
    w("    if (_ready == 0) { _fill(); _ready = 1; }\n")
    w("}\n\n")
    for fn, tbl, ty in (
        ("pv_n", "_n", "*u8"), ("pv_nlen", "_nlen", "i64"),
        ("pv_e", "_e", "*u8"), ("pv_elen", "_elen", "i64"),
        ("pv_msg", "_m", "*u8"), ("pv_mlen", "_mlen", "i64"),
        ("pv_sig", "_s", "*u8"), ("pv_siglen", "_siglen", "i64"),
        ("pv_sha", "_sha", "i64"), ("pv_salt", "_salt", "i64"),
        ("pv_want", "_want", "i64"), ("pv_reason", "_reason", "i64"),
    ):
        w("fn %s(i as i64) as %s { return %s[i]; }\n" % (fn, ty, tbl))


if __name__ == "__main__":
    main()
