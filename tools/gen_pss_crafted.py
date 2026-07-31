#!/usr/bin/env python3
# =======================================================================
# tools/gen_pss_crafted.py
#
# The CAVP corpus proves EMSA-PSS-VERIFY accepts what it should and rejects
# five kinds of tampering, but every CAVP modulus is a whole number of bytes
# and every failure is applied to the message, the exponent or the signature —
# never to the encoded message itself in a chosen way. Several guards inside
# tls/pss.cst are therefore unreachable from it:
#
#   * emLen == k-1, which happens only when modBits is 1 mod 8;
#   * a recovered EM that needs more than emBits bits, which big_to_bytes_be
#     would truncate in silence;
#   * the leftmost 8*emLen-emBits bits of EM being non-zero;
#   * a signature with n added to it, which reduces to a valid one;
#   * a valid signature whose salt is past the module's ceiling;
#   * a specific byte of DB being wrong (the 0xbc trailer, a PS byte, the
#     0x01 separator).
#
# Reaching them needs signatures built from a chosen EM, which needs a private
# key. So: generate throwaway keys, encode EM by hand, and raise it to d.
#
#   openssl genrsa -out /tmp/kodd.pem 1025    # modBits == 1 mod 8
#   openssl genrsa -out /tmp/k2048.pem 2048   # the ordinary case
#   openssl genrsa -out /tmp/kbig.pem 4608    # emLen clears hLen + 513 + 2
#   python3 tools/gen_pss_crafted.py /tmp/kodd.pem /tmp/k2048.pem \
#       /tmp/kbig.pem > tests/vec_pss_crafted.cst
#
# Note that `openssl genrsa 2049` yields a 2048-bit modulus on current
# OpenSSL, while 1025 really does give 1025 — hence the odd-looking size.
#
# The keys are thrown away afterwards; nothing here depends on which ones they
# were, so regenerating with fresh keys is fine and expected.
#
# Also emits MGF1 known-answer outputs, computed here from hashlib, for
# lengths that are not multiples of the digest size — the case where a wrong
# truncation or a wrong counter start diverges only in the tail.
# =======================================================================

import hashlib
import os
import subprocess
import sys

HASHES = {256: hashlib.sha256, 384: hashlib.sha384, 512: hashlib.sha512}


def read_key(path):
    """(n, e, d) from a PEM private key, via openssl's text dump."""
    txt = subprocess.run(
        ["openssl", "rsa", "-in", path, "-noout", "-text"],
        capture_output=True, text=True, check=True).stdout

    def grab(label, single_line_int=False):
        lines = txt.splitlines()
        for i, ln in enumerate(lines):
            if ln.startswith(label):
                if single_line_int:
                    return int(ln.split("(")[0].split(":")[1].strip())
                acc = []
                for nxt in lines[i + 1:]:
                    if not nxt.startswith(" "):
                        break
                    acc.append(nxt.strip())
                return int("".join(acc).replace(":", ""), 16)
        sys.exit("no %r in openssl output" % label)

    n = grab("modulus:")
    e = grab("publicExponent:", single_line_int=True)
    d = grab("privateExponent:")
    return n, e, d


def i2osp(x, n):
    return x.to_bytes(n, "big")


def mgf1(seed, length, h):
    out = b""
    c = 0
    while len(out) < length:
        out += h(seed + c.to_bytes(4, "big")).digest()
        c += 1
    return out[:length]


def encode(mhash, sha, embits, salt, *, break_trailer=False, break_ps=False,
           break_sep=False, break_topbits=False, widen=False):
    """EMSA-PSS-ENCODE, with a switch for each way to make it wrong.

    break_topbits sets the leading 8*emLen-emBits bits that the encoder is
    required to clear. It needs a modulus whose bit length is NOT 1 mod 8,
    because that is exactly when those bits exist — a 1025-bit key has none,
    and setting the high bit there produces a perfectly valid signature.

    widen produces an EM one byte wider than emLen, so the recovered integer
    needs more bits than emBits. big_to_bytes_be would truncate it in silence;
    this is the only way to reach the guard that stops it.
    """
    h = HASHES[sha]
    hlen = h().digest_size
    emlen = (embits + 7) // 8
    topbits = 8 * emlen - embits
    if break_topbits and topbits == 0:
        sys.exit("break_topbits needs modBits != 1 mod 8")
    slen = len(salt)
    assert emlen >= hlen + slen + 2

    hp = h(b"\x00" * 8 + mhash + salt).digest()
    ps = b"\x00" * (emlen - slen - hlen - 2)
    db = ps + b"\x01" + salt
    if break_ps:
        db = bytearray(db)
        db[0] = 1                       # a PS byte that is not zero
        db = bytes(db)
    if break_sep:
        db = bytearray(db)
        db[len(ps)] = 0                 # the 0x01 separator removed
        db = bytes(db)

    masked = bytearray(a ^ b for a, b in zip(db, mgf1(hp, emlen - hlen - 1, h)))
    if break_topbits:
        masked[0] |= (0xFF << (8 - topbits)) & 0xFF
    else:
        masked[0] &= 0xFF >> topbits
    em = bytes(masked) + hp + (b"\xbd" if break_trailer else b"\xbc")
    if widen:
        em = b"\x01" + em               # emLen+1 bytes: more than emBits bits
    return em


def sign(em, n, d, k):
    return i2osp(pow(int.from_bytes(em, "big"), d, n), k)


def cstr(b):
    return '"' + "".join("\\x%02x" % c for c in b) + '"'


def main():
    if len(sys.argv) != 4:
        sys.exit("usage: gen_pss_crafted.py kodd.pem k2048.pem kbig.pem")
    nodd, eodd, dodd = read_key(sys.argv[1])
    n48, e48, d48 = read_key(sys.argv[2])
    nbig, ebig, dbig = read_key(sys.argv[3])
    if nodd.bit_length() % 8 != 1:
        sys.exit("first key must have modBits == 1 mod 8, got %d"
                 % nodd.bit_length())
    if n48.bit_length() % 8 != 0:
        sys.exit("second key must have modBits a multiple of 8, got %d"
                 % n48.bit_length())
    # emLen has to clear hLen + 513 + 2 for the salt-ceiling vector to be a
    # valid signature that only the ceiling rejects. Below 4377 bits the
    # emLen check fires first and the ceiling is untestable.
    if nbig.bit_length() < 4377:
        sys.exit("third key must be at least 4377 bits, got %d"
                 % nbig.bit_length())

    msg = bytes(range(64))
    vecs = []

    def add(name, note, n, e, d, sha, slen, want, **broken):
        k = (n.bit_length() + 7) // 8
        embits = n.bit_length() - 1
        h = HASHES[sha]
        mhash = h(msg).digest()
        # The signature is EM^d mod n, so EM has to be below n or the
        # exponentiation loses the high part and the vector stops meaning
        # what it says. Every case here is well under n except the two that
        # deliberately set high bits; those get resampled until they fit.
        for _ in range(2000):
            em = encode(mhash, sha, embits, os.urandom(slen), **broken)
            if int.from_bytes(em, "big") < n:
                break
        else:
            sys.exit("could not build %s below the modulus" % name)
        vecs.append({
            "name": name, "note": note, "n": i2osp(n, k), "e": i2osp(e, 3),
            "sig": sign(em, n, d, k), "sha": sha, "salt": slen, "want": want,
        })
        return len(vecs) - 1

    # The one that fails if emLen is taken as k: modBits is 1 mod 8, so
    # emLen == k-1 and the recovered integer is one byte narrower than the
    # signature. Every CAVP modulus is a multiple of 8, so nothing there hits
    # it, and with emLen == k the H window lands on the wrong bytes.
    i_odd = add("emlen_k_minus_1", "modBits == 1 mod 8, so emLen == k-1",
                nodd, eodd, dodd, 256, 32, 1)
    # EM one byte wider than emLen. big_to_bytes_be truncates rather than
    # failing, so without the bit-length guard the top byte vanishes and the
    # rest is interpreted as if it had always been the whole thing.
    add("over_embits", "recovered EM needs more than emBits bits",
        nodd, eodd, dodd, 256, 32, 0, widen=True)
    # And the same guard from the other side: emBits is a multiple of 8 minus
    # one here, so there IS a leading bit, and the encoder must have cleared it.
    add("topbits_set", "leftmost 8*emLen-emBits bits of EM not zero",
        n48, e48, d48, 256, 32, 0, break_topbits=True)

    i_ok = add("ok_2048_sha256", "plain valid signature, salt == hLen",
               n48, e48, d48, 256, 32, 1)
    add("ok_2048_sha384", "valid, SHA-384, salt == hLen",
        n48, e48, d48, 384, 48, 1)
    add("ok_2048_sha512", "valid, SHA-512, salt == hLen",
        n48, e48, d48, 512, 64, 1)
    add("ok_salt_zero", "valid with an empty salt: PS runs to the separator",
        n48, e48, d48, 256, 0, 1)

    add("bad_trailer", "EM ends 0xbd instead of 0xbc",
        n48, e48, d48, 256, 32, 0, break_trailer=True)
    add("bad_ps", "a PS byte is not zero",
        n48, e48, d48, 256, 32, 0, break_ps=True)
    add("bad_sep", "the 0x01 separator is zero",
        n48, e48, d48, 256, 32, 0, break_sep=True)

    # A valid signature with the integer n added to it. It is still k bytes
    # and s mod n is still the real signature, so a verifier that skips the
    # s < n check reduces it and says yes — a second encoding of the same
    # signature, accepted. RFC 8017 §8.1.2 step 1 exists for this.
    i_plusn = add("sig_plus_n", "valid signature with n added: s >= n",
                  n48, e48, d48, 256, 32, 0)
    k48 = (n48.bit_length() + 7) // 8
    while True:
        s = int.from_bytes(vecs[i_plusn]["sig"], "big") + n48
        if s < (1 << (8 * k48)):
            vecs[i_plusn]["sig"] = i2osp(s, k48)
            break
        vecs.pop(i_plusn)
        i_plusn = add("sig_plus_n", "valid signature with n added: s >= n",
                      n48, e48, d48, 256, 32, 0)

    # A VALID signature whose salt is 513 bytes, on a modulus big enough that
    # emLen still clears hLen + sLen + 2. Nothing but PSS_MAX_SALT rejects it,
    # so deleting that bound turns this into a 1.
    i_bigsalt = add("salt_over_ceiling", "valid, salt 513: only the ceiling refuses",
                    nbig, ebig, dbig, 256, 513, 0)

    w = sys.stdout.write
    w("// =======================================================\n")
    w("// caustic-net/tests/vec_pss_crafted.cst\n")
    w("// PSS signatures built from a chosen encoded message.\n")
    w("//\n")
    w("// GENERATED by tools/gen_pss_crafted.py from throwaway RSA keys; see\n")
    w("// that file for why the CAVP corpus cannot reach these cases and how\n")
    w("// to regenerate. Which keys they were does not matter.\n")
    w("//\n")
    w("// The message is the 64 bytes 0x00..0x3f for every vector.\n")
    w("//\n")
    for i, v in enumerate(vecs):
        w("//   %2d  %-18s %s\n" % (i, v["name"], v["note"]))
    w("// =======================================================\n\n")

    w("let is i64 as PC_COUNT with imut = %d;\n" % len(vecs))
    w("// Indices the test reaches for by name, so reordering the list above\n")
    w("// cannot silently point a check at a different vector.\n")
    w("let is i64 as PC_OK2048  with imut = %d;   // plain valid, SHA-256, salt 32\n" % i_ok)
    w("let is i64 as PC_ODDKEY  with imut = %d;   // the modBits == 1 mod 8 key\n" % i_odd)
    w("let is i64 as PC_SIGPLUSN with imut = %d;  // s >= n\n" % i_plusn)
    w("let is i64 as PC_BIGSALT with imut = %d;   // valid, salt 513\n\n" % i_bigsalt)
    w("let is *u8 as PC_MSG with imut =\n    %s;\n" % cstr(msg))
    w("let is i64 as PC_MSG_LEN with imut = %d;\n\n" % len(msg))

    seen = {}
    for v in vecs:
        key = v["n"]
        if key not in seen:
            seen[key] = "_PCN%d" % len(seen)
            w("let is *u8 as %s with imut =\n    %s;\n" % (seen[key], cstr(key)))
        v["nsym"] = seen[key]
    w("\n")
    for i, v in enumerate(vecs):
        w("let is *u8 as _PCE%d with imut = %s;\n" % (i, cstr(v["e"])))
        w("let is *u8 as _PCS%d with imut =\n    %s;\n" % (i, cstr(v["sig"])))
    w("\n")

    n = len(vecs)
    w("let is [%d]*u8 as _n with mut;\n" % n)
    w("let is [%d]*u8 as _e with mut;\n" % n)
    w("let is [%d]*u8 as _s with mut;\n" % n)
    for name in ("_nlen", "_elen", "_siglen", "_sha", "_salt", "_want"):
        w("let is [%d]i64 as %s with mut;\n" % (n, name))
    w("let is i64 as _ready with mut = 0;\n\n")

    w("fn _fill() as void {\n")
    for i, v in enumerate(vecs):
        w("    // %s\n" % v["note"])
        w("    _n[%d] = %s;  _nlen[%d] = %d;  _e[%d] = _PCE%d;  _elen[%d] = %d;\n"
          % (i, v["nsym"], i, len(v["n"]), i, i, i, len(v["e"])))
        w("    _s[%d] = _PCS%d;  _siglen[%d] = %d;  _sha[%d] = %d;"
          "  _salt[%d] = %d;  _want[%d] = %d;\n"
          % (i, i, i, len(v["sig"]), i, v["sha"], i, v["salt"], i, v["want"]))
    w("}\n\n")
    w("fn pc_ensure() as void {\n")
    w("    if (_ready == 0) { _fill(); _ready = 1; }\n")
    w("}\n")
    for fn, tbl, ty in (
        ("pc_n", "_n", "*u8"), ("pc_nlen", "_nlen", "i64"),
        ("pc_e", "_e", "*u8"), ("pc_elen", "_elen", "i64"),
        ("pc_sig", "_s", "*u8"), ("pc_siglen", "_siglen", "i64"),
        ("pc_sha", "_sha", "i64"), ("pc_salt", "_salt", "i64"),
        ("pc_want", "_want", "i64"),
    ):
        w("fn %s(i as i64) as %s { return %s[i]; }\n" % (fn, ty, tbl))

    # --- MGF1 known answers -------------------------------------------
    w("\n// MGF1 known answers. The seed is \"caustic-net mgf1\"; the lengths\n")
    w("// are deliberately not multiples of the digest size, because a wrong\n")
    w("// truncation or a counter that starts at 1 diverges only in the tail.\n")
    seed = b"caustic-net mgf1"
    w("let is *u8 as MG_SEED with imut = %s;\n" % cstr(seed))
    w("let is i64 as MG_SEED_LEN with imut = %d;\n" % len(seed))
    cases = [(256, 100), (256, 31), (384, 200), (512, 65)]
    w("let is i64 as MG_COUNT with imut = %d;\n" % len(cases))
    for i, (sha, ln) in enumerate(cases):
        out = mgf1(seed, ln, HASHES[sha])
        w("let is *u8 as _MG%d with imut =\n    %s;\n" % (i, cstr(out)))
    w("let is [%d]*u8 as _mg with mut;\n" % len(cases))
    w("let is [%d]i64 as _mgsha with mut;\n" % len(cases))
    w("let is [%d]i64 as _mglen with mut;\n" % len(cases))
    w("let is i64 as _mgready with mut = 0;\n\n")
    w("fn mg_ensure() as void {\n")
    w("    if (_mgready == 1) { return; }\n")
    for i, (sha, ln) in enumerate(cases):
        w("    _mg[%d] = _MG%d;  _mgsha[%d] = %d;  _mglen[%d] = %d;\n"
          % (i, i, i, sha, i, ln))
    w("    _mgready = 1;\n")
    w("}\n")
    w("fn mg_out(i as i64) as *u8 { return _mg[i]; }\n")
    w("fn mg_sha(i as i64) as i64 { return _mgsha[i]; }\n")
    w("fn mg_len(i as i64) as i64 { return _mglen[i]; }\n")


if __name__ == "__main__":
    main()
