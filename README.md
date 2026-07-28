# caustic-net

**A networking stack in [Caustic](https://github.com/Caua726/Caustic) — sockets up to `fetch()`, with no libc and no OpenSSL.**

![version](https://img.shields.io/badge/version-0.1.0-blue)
![status](https://img.shields.io/badge/status-early%20%C2%B7%20phases%200--1%20landed-yellow)
![dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![license](https://img.shields.io/badge/license-MIT-blue)

> **Early.** The `Conn` abstraction, TCP and the buffered reader are landed and
> green. DNS, URL, HTTP, WebSocket, TLS, the server and `fetch()` are designed
> and **not yet written**. The [status table](#status) is the authority on what
> exists; the layout below marks everything else with `*`.

The plan is a stack built on the Caustic standard library's `std/net.cst`
(TCP/UDP/poll floor), with everything above it written here in Caustic —
**no libc, no OpenSSL, no external libraries** — over Linux syscalls, and
`ws2_32`/`bcrypt` on the Windows target.

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

Plain TCP (`transport/tcp_conn.cst`) and TLS both implement the **same** `Conn`,
so HTTP/WS/fetch never know whether bytes are encrypted — a TLS `Conn` simply
wraps a lower `Conn`. The vtable uses `fn_ptr(backend)` stored in `*u8` fields
and `call(...)` dispatch (the verified `std/sort.cst` comparator pattern); the
only `call()` sites are the four typed dispatchers in `core/conn.cst`.

## Layout

```
core/        conn (the vtable) · errno · bytes (Bytes/Slice) · bufread (lines)
transport/   tcp_conn (TCP→Conn) · transport (dial/listen/accept/tuning) · epoll*
proto/       url* · dns* · headers* · http1* · websocket* · flate* · cookie*
tls/         records · handshake · keyschedule · client (implements Conn)*
server/      router · threaded · reactor*
client/      fetch (url→dns→connect→tls→http→redirect→decompress)*
```
`*` = on the roadmap, not yet landed.

**The primitives are not going to live here.** An earlier plan had `crypto/` and
`asn1/` directories in this repository — SHA-2, HMAC, X25519, RSA, ChaCha20,
DER, X.509. They belong to
[`caustic-crypto`](https://github.com/Caua726/caustic-crypto), which now exists,
is vector-validated against NIST CAVP and Wycheproof, and will be a `depend`
when the TLS track starts. A second, unaudited implementation of X25519 inside
the same author's own ecosystem would be the worst of both worlds. `flate/`
comes from [`caustic-compact`](https://github.com/Caua726/caustic-compact) for
the same reason.

## Conventions

- **Errors:** I/O returns negative `i64` = `-errno` (`core/errno.cst` names them);
  allocating constructors return a pointer and signal failure with null.
  Parsed values use an `ok`/flag field. (Generic `Result`/`Option` are avoided —
  their construction syntax isn't supported by the compiler.)
- **Memory:** manual, via the stdlib `bins` allocator per module; `Conn` boxes +
  backend contexts share one heap (`core/conn.cst` `cn_alloc`/`cn_free`), freed by
  `conn_free`. Hot path (`conn_read`/`conn_write`) is zero-alloc raw `*u8+len`.
  `Bytes` is the exception: `bins` refuses any single request above its top bin,
  so a buffer past `SMALL_MAX` (16 KiB) is page-allocated instead. `cap` is
  always the exact size handed to the allocator, which is how a free knows
  which of the two owns the pointer.
- **Naming:** `snake_case` fns, `PascalCase` structs, `_prefix` private, vtable
  backends named `_<proto>_<op>`, `SCREAMING` constants `with imut`.

## Status

| Phase | Module | State |
|---|---|---|
| 0 | `core/` conn · errno · bytes | ✅ green (`tests/test_conn` mock-Conn dispatch, `tests/test_bytes` growth to 1 MiB) |
| 0 | `core/bufread` — lines + exact counts over `Conn` | ✅ green (`tests/test_bufread`, incl. lines split one byte per read) |
| 1 | `transport/` tcp_conn · transport · `Listener` · peer addr · deadlines | ✅ green (`examples/tcp_echo` round-trip) |
| 1 | epoll reactor + IPv6 addrs | ⏳ next |
| 2 | url · dns | ⏳ |
| 3 | http/1.1 client (+headers, chunked, cookies, redirects) | ⏳ |
| 4 | server (reactor + thread-per-conn) | ⏳ |
| 5 | websocket (sha1 + base64) | ⏳ |
| 6 | flate (gzip/deflate inflate) | ⏳ |
| 7–9 | TLS 1.3, on `caustic-crypto` as a dependency | ⏳ (big track) |
| 10 | fetch orchestrator | ⏳ |

## Build & test

The Caustic toolchain (`caustic`, `caustic-mk`) must be installed; the stdlib
resolves from the install path, so `use "std/net.cst"` just works.

```sh
caustic-mk run test        # compile-check the library, then build and run every case
caustic-mk run test-opt    # the same, through the optimizing backend
caustic-mk build tcp_echo  # the example, to run by hand
```

Green is exit 0. The runner is `tests/run.cst`, written in Caustic, so it
behaves the same on both targets — which matters more here than in most
repositories, since portability is the thing the library itself is claiming.

## License

MIT — see [LICENSE](LICENSE).
