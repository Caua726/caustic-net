# caustic-net

**The networking stack for [Caustic](https://github.com/Caua726/Caustic) — from the TCP
socket up to `fetch()`, with no libc and no OpenSSL.**

![version](https://img.shields.io/badge/version-0.1.0-blue)
![status](https://img.shields.io/badge/status-DNS%20%C2%B7%20TLS%201.3%20%C2%B7%20HTTP%2F1.1%20%C2%B7%20fetch-green)
![dependencies](https://img.shields.io/badge/dependencies-caustic--crypto%20%C2%B7%20caustic--compact-blue)
![license](https://img.shields.io/badge/license-MIT-blue)

The scope is everything an application needs to talk to a network: sockets, name
resolution, TLS, the HTTP family, WebSocket, and the protocols above them. The floor is
the standard library's `std/net.cst` (TCP/UDP/poll); everything above it is written here
in Caustic, over Linux syscalls and `ws2_32` on the Windows target.

> **`fetch_get https://example.com/` works.** DNS, TLS 1.3, certificate verification,
> HTTP/1.1, redirects, `Content-Encoding` and a cookie jar are landed and green, and
> `examples/https_get` differs from `examples/http_get` in one expression — which was the
> point of the `Conn` vtable. What is left is connection reuse and parallel fetching, and
> the [status table](#status) is the authority on what exists.

## The keystone: `Conn`

Everything streams through one abstraction — a generic byte stream behind a
function-pointer vtable (`core/conn.cst`):

```cst
struct Conn { ctx as *u8; read as *u8; write as *u8; close as *u8; state as *u8; }
fn conn_read(c as *Conn, buf as *u8, len as i64) as i64;
fn conn_write(c as *Conn, buf as *u8, len as i64) as i64;
fn conn_close(c as *Conn) as i64;
fn conn_state(c as *Conn) as i64;
```

Plain TCP (`transport/tcp_conn.cst`) and TLS both implement the **same** `Conn`, so
HTTP/WS/fetch never know whether bytes are encrypted — a TLS `Conn` simply wraps a lower
`Conn`. The vtable uses `fn_ptr(backend)` stored in `*u8` fields and `call(...)` dispatch
(the verified `std/sort.cst` comparator pattern); the only `call()` sites are the four
typed dispatchers in `core/conn.cst`.

That claim is now settled rather than asserted. `examples/https_get.cst` and
`examples/http_get.cst` differ in one expression:

```cst
tp.dial_host(host, 80)
tls.tls_client(tp.dial_host(host, 443), host, &store)
```

Everything above — `bufread`, `req_for_url`, `resp_read_head`, `body_read_all` — is
identical, because a TLS `Conn` and a TCP `Conn` are the same thing to it.

## The ecosystem

**caustic-net writes protocol logic, not primitives.** Every primitive it needs already
exists in a sibling library, validated there, and arrives as a `depend`. A second
unaudited X25519 inside the same author's own ecosystem would be the worst of both
worlds — and the same argument applies to Brotli, and to punycode.

| Library | What caustic-net takes from it |
|---|---|
| [`caustic-crypto`](https://github.com/Caua726/caustic-crypto) | **TLS:** X25519 · P-256/P-384 · RSA · Ed25519 · AEAD · SHA-2 · HMAC/HKDF · `asn1/x509` + DER · HMAC-DRBG. **WebSocket:** `hash/sha1`. **HTTP auth:** `util/base64`, HMAC. Every primitive vector-validated against NIST CAVP, RFC and Wycheproof. |
| [`caustic-compact`](https://github.com/Caua726/caustic-compact) | **`Content-Encoding`:** gzip · deflate · zlib · **brotli** · **zstd** — wired up in `client/decode.cst`. (Also bzip2, xz/LZMA, LZ4, Snappy, LZW — the HTTP set is a subset of what it ships.) |
| [`caustic-unicode`](https://github.com/Caua726/caustic-unicode) | **`idna`** for internationalized hostnames (punycode), `utf` validation, and `encodings` for charset conversion on response bodies. |
| [`Caustic`](https://github.com/Caua726/Caustic) | The language, compiler, assembler, linker — and `std/net.cst`, the TCP/UDP/poll floor this is built on. |

Written against it:

| Project | Relationship |
|---|---|
| [`caustic-browser`](https://github.com/Caua726/caustic-browser) | A browser from the pixels up, with **no networking yet**. It is the flagship consumer, and what it needs — DNS, TLS, HTTP/1.1 and /2, cookies, cache — is what drives the ordering below. |
| [`causticos`](https://github.com/Caua726/causticos) | An x86_64 OS in Caustic that carries its own ring-3 TCP/IP stack. Related work, and the reason the portability claims here get tested rather than assumed. |

## Layout

```
core/        conn (the vtable) · errno · bytes (Bytes/Slice) · bufread (lines)
             entropy (checked CSPRNG) · chrono (epoch ↔ civil, ASN.1 + HTTP dates)
transport/   tcp_conn (TCP→Conn) · transport (dial/dial_host/listen/accept) · resolver · epoll*
proto/       url · http1 · dns · cookie (RFC 6265 jar) · http2* · websocket* · sse* · mime*
tls/         transcript · keysched · record · x509 · pss · roots · trust · verify
             extensions · handshake · client
client/      fetch (url→dns→connect→tls→http→redirect→decode→cookies) · decode
             connpool (keep-alive reuse, retry-once) · parallel (thread per job)
server/      router* · threaded* · reactor* · static* · middleware*
```
`*` = on the roadmap, not yet landed.

## Conventions

- **Errors:** I/O returns negative `i64` = `-errno` (`core/errno.cst` names them);
  allocating constructors return a pointer and signal failure with null.
  Parsed values use an `ok`/flag field. (Generic `Result`/`Option` are avoided —
  their construction syntax isn't supported by the compiler.)
  New error sentinels sit outside the errno range so one can never be mistaken for an
  `-errno`: `-1000` `WANT_READ`/`WANT_WRITE` (in `errno`, reserved for the non-blocking
  and TLS layers), `-1100` bufread, `-1200` url, `-1300` http1, and reserved ahead —
  `-1400` dns/resolver, `-1500` tls (keysched `-1500`, record `-1510`, handshake `-1520`,
  client `-1530`), `-1600` x509 (parse `-1600`, trust `-1610`, verify `-1620`),
  `-1700` cookie, `-1800` client.
- **Memory:** manual, via the stdlib `bins` allocator per module; `Conn` boxes +
  backend contexts share one heap (`core/conn.cst` `cn_alloc`/`cn_free`), freed by
  `conn_free`. Hot path (`conn_read`/`conn_write`) is zero-alloc raw `*u8+len`.
  `Bytes` is the exception: `bins` refuses any single request above its top bin,
  so a buffer past `SMALL_MAX` (16 KiB) is page-allocated instead. `cap` is
  always the exact size handed to the allocator, which is how a free knows
  which of the two owns the pointer.
- **Imports:** `use "std/mem.cst" only bins, core as mem;` — this exact form. A narrower
  `only` list narrows the module *globally* and breaks `std/string`, which needs `bins`.
  Every path is `./`, `../`, `std/`, or a **library name** — never the short
  `use "hash/sha2.cst"` for a sibling. The short form resolves here, where caustic-crypto
  is a *direct* dependency and gets a `--path` of its own, and stops resolving for a
  consumer, where it arrives transitively under the deps-root `--path` alone. Green here,
  broken for them. `tests/run.cst` enforces it twice: as source, and by compiling every
  case with only the deps root on the search path — the consumer's constraint, not ours.
- **Naming:** `snake_case` fns, `PascalCase` structs, `_prefix` private, vtable
  backends named `_<proto>_<op>`, `SCREAMING` constants `with imut`.
- **Parsers are tested split.** Anything that reads a delimited stream gets a test that
  replays its input one byte per read *and* whole, requiring identical results. A parser
  that only works when a line lands in a single read passes the second and fails the
  first, and a real network produces both.

## Status

| Area | Module | State |
|---|---|---|
| core | `conn` — vtable, loop helpers, deadlines, shared heap | ✅ green (`tests/test_conn`) |
| core | `bytes` — growable buffer, bins ≤16 KiB / pages above | ✅ green (`tests/test_bytes`, growth to 1 MiB) |
| core | `errno` — errno names + sentinels | ✅ |
| core | `bufread` — lines and exact counts over `Conn` | ✅ green (`tests/test_bufread`, incl. one byte per read) |
| core | `entropy` — CSPRNG with the return value checked | ✅ green (`tests/test_ent`) |
| core | `chrono` — epoch ↔ civil, ASN.1 time, HTTP-date | ✅ green (`tests/test_chrono`, exhaustive 1888–2106) |
| transport | `tcp_conn` · `transport` · `Listener` · peer address | ✅ green (`examples/tcp_echo`) |
| transport | epoll/kqueue/IOCP reactor | ⏳ unblocked — stdlib v0.1.6 ships `net.Poller` (epoll on Linux, `poll` elsewhere) |
| transport | Happy Eyeballs (RFC 8305) | ⏳ IPv6 resolves and dials; the two families are tried in series, not raced |
| proto | `url` — RFC 3986 incl. relative resolution (§5.2) | ✅ green (`tests/test_url`) |
| proto | `http1` client — build, head parse, body framing | ✅ green (`tests/test_http1`, `examples/http_get`) |
| proto | `dns` — wire codec, no I/O | ✅ green (`tests/test_dns`, 2 live captures + 15 hostile packets) |
| transport | `resolver` — `hosts` · `resolv.conf` incl. `search`/`ndots` · IPv4+IPv6 · UDP + TCP fallback · TTL cache (SOA-derived on a negative) · `dial_host` | ✅ green (`tests/test_res`, `examples/dns_lookup`) |
| deps | `caustic-crypto` v0.1.0 wired in | ✅ green (`tests/test_dep`) |
| tls | `transcript` — cloneable handshake hash | ✅ green (`tests/test_ks`) |
| tls | `keysched` — HKDF-Expand-Label · Derive-Secret · the full schedule | ✅ green (`tests/test_ks`, RFC 8448 §3) |
| tls | `record` — framing · AEAD · nonce/seq · inline tag · padding | ✅ green (`tests/test_rec`, RFC 8448 captured records, incl. one byte per read) |
| tls | `x509` — DER parse · SAN · basicConstraints · keyUsage · hostname match | ✅ green (`tests/test_x509`); parser validated field-by-field against openssl on 62 real certificates |
| tls | `pss` — EMSA-PSS-VERIFY over any hash, MGF1 generic | ✅ green (`tests/test_pss`, 102 NIST CAVP vectors + 12 chosen encodings) |
| tls | `roots` — 121 trust anchors, embedded | ✅ green (`tests/test_trust`); generated by `tools/gen_roots.py`, byte-identical to the bundle it came from |
| tls | `trust` — PEM · `$SSL_CERT_FILE` · distro paths · embedded fallback · caller-pinned anchors | ✅ green (`tests/test_trust`) |
| tls | `verify` — chain building · signature · validity · hostname · basicConstraints · pathLen · EKU | ✅ green (`tests/test_verify`, 25 chains incl. a live one from ietf.org) |
| tls | `extensions` — SNI · supported_versions · groups · key_share · signature_algorithms · ALPN | ✅ green (`tests/test_tls`, against RFC 8448's own ClientHello) |
| tls | `handshake` — the 1-RTT client, as an explicit state machine | ✅ green (`tests/test_tls`, RFC 8448 §3 value by value + 20 hostile flights) |
| tls | `client` — TLS as a `Conn`, one allocation, KeyUpdate handled | ✅ green (`tests/test_tls`, `examples/https_get` against the real internet) |
| client | `fetch` — url → dns → connect → TLS → HTTP → redirects → decode → cookies | ✅ green (`tests/test_fetch`, a real server in a second process) |
| client | `decode` — gzip · deflate (both framings) · brotli · zstd, with an expansion ceiling | ✅ green (`tests/test_decode`, bodies compressed by Python, 8 MiB bomb refused) |
| proto | `cookie` — RFC 6265 parse · jar · domain/path/Secure rules | ✅ green (`tests/test_cookie`) |
| client | `connpool` — keep-alive reuse by origin, 6 per host, retry-once | ✅ green (`tests/test_pool`, against a server that closes the connection) |
| client | `parallel` — thread per job, waves, WaitGroup | ✅ green at the default level (`tests/test_parallel`, 12 jobs 4 at a time); **not runnable at `-O1`** — see below |
| core | `bufread` deadline (gap 03) | ✅ `br_set_deadline`; bounds the number of fills, pair with `set_recv_timeout` for a single read |
| everything else | see the roadmap | ⏳ |

The three ⛔ rows above were all "the toolchain can't yet"; stdlib v0.1.6 closed each one, so
what is left there is work rather than a blocker.

8 modules, 1 797 lines, 248 checks, green on both compiler backends.

## Roadmap

Ordered so that each tier is independently useful and unblocks the next. Items marked
*(dep)* are wiring an existing sibling library in, not writing an implementation.

**A · Finish the HTTP core.** Small, and it unblocks disproportionately.
HTTP-date (RFC 7231) · cookie jar + public suffix list ·
redirect policy · keep-alive pooling · `Content-Encoding` *(dep: caustic-compact)* ·
IDN hostnames *(dep: caustic-unicode)*

**B · Server and real time.** HTTP/1.1 request parsing · router · middleware ·
static files with ranges and ETag · CORS · rate limiting · graceful shutdown ·
WebSocket client and server *(dep: caustic-crypto sha1 + base64)* · Server-Sent Events

**C · TLS.** records · handshake · key schedule · client implementing `Conn` ·
system trust store · SNI · ALPN · session resumption · then server side and mTLS.
*(dep: caustic-crypto for every primitive, including X.509)*

**D · Names and scale.** DNS over UDP with TCP fallback · cache with TTL ·
`resolv.conf`/`hosts` · SRV/TXT/MX/PTR · DoH and DoT (needs C) ·
IPv6 + Happy Eyeballs · the reactor · io_uring

**E · Modern HTTP.** HTTP/2 — HPACK, streams, flow control (needs ALPN from C) ·
HTTP caching (RFC 9111) · Basic/Digest/Bearer/HMAC auth · SOCKS5 and CONNECT proxies ·
multipart/form-data · range requests · retry with backoff

**F · Their own tracks.** Each of these is a project rather than a module, and probably
belongs in a sibling repository that depends on this one: QUIC + HTTP/3 ·
SMTP/IMAP/POP3 + MIME · SSH + SFTP · MQTT · AMQP · Redis RESP · gRPC ·
STUN/TURN/ICE and WebRTC · ICMP ping and traceroute · NTP · mDNS/DNS-SD

**Not in scope.** JSON is not a networking concern and does not belong here, even though
every API client wants one; it should be its own library. The same reasoning that put
crypto in `caustic-crypto` applies.

### Known gaps in what has landed

01 and 02 are closed: `resp_header_next`/`resp_header_count` walk repeated
headers, and `url_resolve` resolves a relative reference per RFC 3986 §5.2.

| | Gap | Consequence |
|---|---|---|
| 03 | A read deadline bounds fills, not one read | `br_set_deadline` stops a reader between fills; a single blocking read is bounded only by `set_recv_timeout`, which takes whole seconds. Both are needed and `client/fetch` sets both |
| 05 | Response-side parsing only | the server needs the request-shaped equivalent |
| 06 | No chunked *request* encoder | POST works only with `Content-Length` |
| 07 | `br_read_line` always copies | a zero-copy view would suit large headers; `Slice` already exists |
| 08 | Per-module `bins` heaps are never torn down | irrelevant for a long-running server, matters if embedded |
| 09 | `examples/http_get` hard-codes port 18081 | any process on the machine can collide; `transport.listen` cannot report a kernel-assigned port |
| 10 | **ECDSA verification is slow** | see below — it is the number that decides whether a browser on top of this is usable |
| 11 | No revocation of any kind | no CRL, no OCSP, no stapling. A certificate stays trusted until it expires |
| 12 | `nameConstraints` is not implemented | it is *refused*, not ignored: a certificate carrying it critical fails to parse, which is the safe direction but rejects some real CAs |
| 13 | TLS `key_share` is X25519 only | caustic-crypto exports `p256_ecdh_base` but no `p256_ecdh_shared`, so P-256 key exchange needs work upstream. A server that insists on P-256 gets a named `TLS_ERR_HRR` rather than a mystery. Nine of nine sites tried negotiated X25519 |
| 14 | No session resumption | `NewSessionTicket` is read and discarded. Every connection is a full handshake |
| 15 | No client certificates | a `CertificateRequest` is skipped rather than answered |
| 16 | A SHA-384 cipher suite needs the ClientHello to fit 1 KiB | the transcript hash is fixed by the suite, which is not known until the ServerHello, so choosing SHA-384 means rehashing both Hellos. A ClientHello past the buffer declines the suite instead |
| 18 | The public suffix list is a heuristic | `psl_is_public_suffix` refuses a single label and a table of about forty two-part suffixes. It does not know `pvt.k12.ma.us`. A cookie scoped to an unlisted public suffix is accepted. The signature is what the real one would be, so replacing it is one file |
| 19 | Decompression is one-shot | caustic-compact has no incremental API, so a compressed page cannot be rendered while it arrives — and the expansion ceiling is enforced after the decompressor has already produced the bytes, which bounds what the caller sees rather than the peak |
| 20 | `SameSite` is parsed and not enforced | it is stored on the cookie; nothing consults it, because enforcement needs a notion of the initiating site that this layer does not have |
| 21 | `parallel` and `connpool` are not tested TOGETHER | each is tested on its own. Combining them needs a concurrent server, and the one in `tests/test_parallel` is a single thread — a test whose result depends on which of two single-threaded things blocked first measures nothing. The pool's mutex is the argument that it is safe to share; it is not a test |
| 22 | A jar is not safe to share between threads | `client/parallel` gives each job its own `Fetch`, and attaches no jar. A caller that passes one has said it is theirs to synchronise |

### Two bugs below this library

Both were found by the first test here that needed two things running at once,
and both are outside this repository. They are recorded because anything built
on caustic-net will meet them.

**`std/mem/bins.cst`: `bins_new` returns a heap whose lock word is
uninitialised.** It is a local in that function and never written, so the
struct arrives carrying whatever was on the stack. Nothing notices while the
program is single-threaded, because the allocator's lock is a no-op until
`std/thread`'s `spawn` turns it on — and then the first allocation through
such a heap finds a non-zero lock, futex-waits, and never wakes. The process
hangs with no error and no crash.

`core/conn.cst` and `core/bytes.cst` used to do exactly `_bins = bins_new(...)`
and both hung. They now let `bins_alloc` build the heap itself, which is the
one construction that ends up consistent, because its lazy path restores the
lock word it was holding. `transport.init()` forces both heaps up while the
program is still single-threaded.

**The optimizing backend miscompiles a local label inside inline `asm`.**
Eleven lines reproduce it:

```cst
fn pick(x as i64) as i64 with naked {
    asm("test rdi, rdi\njz .Lzero_case\nmov rax, 111\nret\n.Lzero_case:\nmov rax, 222\nret\n");
}
fn main() as i32 { io.printf("%ld %ld\n", pick(1), pick(0)); return 0; }
```

`111 222` at the default level; a segfault at `-O1`. The emitted `.s` is
correct in both — the assembler resolves `.Lzero_case` to the wrong address,
and the `je` ends up with a displacement pointing into another function
entirely. `std/thread.cst`'s `_clone_thread` is exactly this shape, so **every
threaded program crashes at `-O1`**.

Two consequences here. `tests/test_fetch`, `tests/test_pool` and
`tests/test_parallel` run their server halves as a second PROCESS rather than
a thread — which is closer to reality anyway. And `tests/test_parallel` is
built but NOT RUN under `-O1`, with the reason printed on every run rather
than quietly skipped.

### How long a certificate chain takes

Measured by `tests/test_verify` on every run, so the number in the table below
is whatever this machine last saw rather than something written once and left
to rot. On an ordinary desktop, `-O1`, per chain of two links plus an anchor:

| chain | time |
|---|---|
| RSA-2048, SHA-256 | ~1.7 ms |
| ECDSA P-256, SHA-256 | ~31 ms |
| ietf.org (P-256 leaf and intermediate, P-384 root) | ~49 ms |

The surprise is which one is slow. ECDSA is normally the cheap option and here
it costs **twenty times** an RSA verification, because caustic-crypto's
`p256`/`p384` do every field inversion with a full `big_modexp` — one modular
exponentiation per point operation, inside a Montgomery ladder over 28-bit
limbs. RSA gets `big_modexp_public`, which is a single exponentiation and is
already Montgomery.

That is fine for one page and not fine for a browser: ten origins is most of a
second spent on nothing but signatures, before a byte is rendered. The fix is
upstream in caustic-crypto — an affine-coordinate inversion via the extended
Euclidean algorithm instead of Fermat, and a windowed scalar multiplication —
and it is not in this repository's scope. Recorded here so the decision to
carry it is deliberate.

## Build & test

The Caustic toolchain (`caustic`, `caustic-mk`) must be installed; the stdlib
resolves from the install path, so `use "std/net.cst"` just works.

```sh
caustic-mk run test        # compile-check the library, then build and run every case
caustic-mk run test-opt    # the same, through the optimizing backend
caustic-mk build http_get  # the end-to-end example, to run by hand
```

Green is exit 0. The runner is `tests/run.cst`, written in Caustic, so it
behaves the same on both targets — which matters more here than in most
repositories, since portability is the thing the library itself is claiming.

## License

MIT — see [LICENSE](LICENSE).
