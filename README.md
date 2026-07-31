# caustic-net

**The networking stack for [Caustic](https://github.com/Caua726/Caustic) — from the TCP
socket up to `fetch()`, with no libc and no OpenSSL.**

![version](https://img.shields.io/badge/version-0.1.0-blue)
![status](https://img.shields.io/badge/status-early%20%C2%B7%20TCP%20%C2%B7%20URL%20%C2%B7%20HTTP%2F1.1-yellow)
![dependencies](https://img.shields.io/badge/dependencies-caustic--crypto-blue)
![license](https://img.shields.io/badge/license-MIT-blue)

The scope is everything an application needs to talk to a network: sockets, name
resolution, TLS, the HTTP family, WebSocket, and the protocols above them. The floor is
the standard library's `std/net.cst` (TCP/UDP/poll); everything above it is written here
in Caustic, over Linux syscalls and `ws2_32` on the Windows target.

> **Early.** The `Conn` abstraction, TCP, the buffered reader, URL parsing and the
> HTTP/1.1 client are landed and green — `examples/http_get` runs a real request over a
> real socket and reassembles a chunked response. Everything else on the
> [roadmap](#roadmap) is designed and **not yet written**. The [status table](#status) is
> the authority on what exists.

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

The test that this is the right shape will be pointing `examples/http_get` at an `https`
endpoint and changing nothing above the transport.

## The ecosystem

**caustic-net writes protocol logic, not primitives.** Every primitive it needs already
exists in a sibling library, validated there, and arrives as a `depend`. A second
unaudited X25519 inside the same author's own ecosystem would be the worst of both
worlds — and the same argument applies to Brotli, and to punycode.

| Library | What caustic-net takes from it |
|---|---|
| [`caustic-crypto`](https://github.com/Caua726/caustic-crypto) | **TLS:** X25519 · P-256/P-384 · RSA · Ed25519 · AEAD · SHA-2 · HMAC/HKDF · `asn1/x509` + DER · HMAC-DRBG. **WebSocket:** `hash/sha1`. **HTTP auth:** `util/base64`, HMAC. Every primitive vector-validated against NIST CAVP, RFC and Wycheproof. |
| [`caustic-compact`](https://github.com/Caua726/caustic-compact) | **`Content-Encoding`:** gzip · deflate · zlib · **brotli** · **zstd**. (Also bzip2, xz/LZMA, LZ4, Snappy, LZW — the HTTP set is a subset of what it ships.) |
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
proto/       url · http1 · dns · cookie* · http2* · websocket* · sse* · mime*
tls/         transcript · keysched · record · x509 · trust* · verify* · handshake* · client*
server/      router* · threaded* · reactor* · static* · middleware*
client/      fetch* (url→dns→connect→tls→http→redirect→decompress)
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
  `-1400` dns, `-1500` tls, `-1600` x509, `-1700` cookie, `-1800` client.
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
| 03 | `http1` threads no deadline through | `Conn` has `conn_read_exact_by`; http1 ignores it |
| 04 | No connection pool | `conn_reusable()` answers correctly, nothing reuses |
| 05 | Response-side parsing only | the server needs the request-shaped equivalent |
| 06 | No chunked *request* encoder | POST works only with `Content-Length` |
| 07 | `br_read_line` always copies | a zero-copy view would suit large headers; `Slice` already exists |
| 08 | Per-module `bins` heaps are never torn down | irrelevant for a long-running server, matters if embedded |
| 09 | `examples/http_get` hard-codes port 18081 | any process on the machine can collide; `transport.listen` cannot report a kernel-assigned port |

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
