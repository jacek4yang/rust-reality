# Architecture

English | [简体中文](architecture.zh-CN.md)

This document describes how the production data plane is structured: the
connection lifecycle, the raw-relay kernel backends, the descriptor admission
architecture, and what is reported at runtime. Measured evidence for the design
lives in [performance.md](performance.md); the benchmark methodology and
canonical samples live in [benchmarks.md](benchmarks.md).

## Connection lifecycle

1. **Accept.** The listener acquires an FD-budget permit *before* `accept(2)`
   and classifies accept errors; on descriptor pressure an emergency reserve
   descriptor is used to free capacity. One task per connection. Every data
   socket (accepted and outbound) carries a kernel liveness backstop:
   `SO_KEEPALIVE` with 30 s idle / 10 s interval / 3 probes, bounding silent
   peer death without capping healthy transfers.
2. **REALITY.** The ClientHello is read under a bounded deadline and either
   authenticates or falls back. Fallback is byte-exact: the consumed client
   prefix is replayed to the cover target, any inspected target prefix is
   replayed to the client, and the remaining raw pair is handed to the unified
   relay (`TcpRelay::relay_owned`) — splice-capable and FD-accounted, never a
   borrowed userspace copy. The authenticated short ID resolves through a
   cardinality-adaptive immutable index and carries its unique owner UUID into
   the established session.

   In v1.5, the cover response is consumed through a bounded incremental
   reader. Its plan can contain optional CCS, four positional encrypted
   handshake records, and an optional fifth post-Finished record. At most
   66,642 cover bytes are retained; fifth-record discovery first uses buffered
   data and otherwise performs one nonblocking probe. A fifth record causes an
   empty encrypted ApplicationData fake NST to consume server application
   sequence 0. The established server record layer therefore begins at 0 or 1
   according to the authenticated plan; fallback receives every inspected byte.
3. **VLESS + Vision.** The request is decoded from the outer TLS stream;
   the adaptive UUID index finds the header user and requires it to equal the
   short-ID owner before any routing; routing then selects an outbound and the
   session splits into two independent direction tasks (uplink, downlink).
4. **Framed phase.** Both directions run outer-TLS record I/O with Vision
   padding. Hot-path properties (measured, regression-gated):
   - zero steady-state heap allocations per record (instrumented-allocator
     gates in `tls13/allocation_gate.rs`);
   - socket reads refill a connection-owned grow-only buffer once per ≤64
     KiB and complete records are parsed and decrypted in place out of it
     (one syscall per refill, not two per record); every byte buffered past a
     raw boundary is drained to the peer in order before any raw relay
     starts;
   - one timer registration per progress step (`IdleDeadline`), never a fresh
     `time::timeout` per chunk; idle semantics — progress resets the window,
     so long transfers never hit a session cap;
   - the outer downlink reads destination bytes directly into the AEAD
     plaintext region and seals in place (one copy: the socket read);
   - raw-mode Vision records pass through as borrowed slices (no per-record
     16 KiB memcpy);
   - multiple Vision frames are packed per outer TLS record (fewer AEAD seals
     and writes; wire-compatible with Xray's stream decoder).
5. **Direct transition.** When a direction reaches its authenticated Direct
   boundary (uplink: the client's Direct command fully decoded and every
   preceding plaintext byte written; downlink: the first TLS 1.3 application
   record after ServerHello detected and the Direct-carrying Vision frame
   fully sealed and written), the direction decides **exactly once**:
   - peer at its own raw boundary (`RawReady`) or already committed
     (`PairPending`) → this direction deposits its halves; the last depositor
     reunites both complete sockets and runs the **bilateral** raw relay;
   - otherwise → this direction claims its halves (`Relaying`) and starts a
     **directional** raw relay immediately.

   There is no sleep, timer, or watch-channel wait for the peer. The only
   concession to pairing is a bounded window of two scheduler yield points so
   a peer whose boundary flight is already queued can commit first
   (microseconds; reported as `*_handoff_delay_us`). Direction states are
   monotonic (`Framed → DirectPending → RawReady → {PairPending, Relaying} →
   {Closed, Failed}`), which makes split-brain impossible: a peer that
   observed `RawReady`/`PairPending` can no longer go directional, and a peer
   that observed `Relaying` can no longer join the pair.

   Invariants at the boundary (pinned by tests):
   - no unauthenticated or still-framed byte reaches a kernel backend;
   - readers consume exactly one TLS record per socket read on both sides, so
     no post-boundary raw byte sits in a userspace buffer;
   - the downlink raw relay starts only after the final framed write
     completed;
   - once a direction moved any raw byte through a backend it can never be
     replayed through another backend (`TransferLedger`).
6. **Raw phase backends.** Selection is honest and evidence-based:

   | situation | order |
   |---|---|
   | bilateral pair, complete sockets, zero bytes moved | splice → buffered |
   | single raw direction | directional splice → directional buffered |

   - **splice**: one pipe pair per direction (bilateral = two pairs), exactly
     2 FD units per direction, reserved before `pipe2`. Pipes request a 256
     KiB capacity (best effort, below the unprivileged 1 MiB cap) and the
     relay chunk is the pipe's actual capacity; kernel pipe memory is
     accounted worst-case as `maxPooledPipes × 2 × 256 KiB` when the pipe
     pool is enabled (the default; the pool subsumes per-session creation)
     or `maxSpliceRelays × 4 × 256 KiB` without it. Pipes are
     pooled (`PipePool`), so steady-state sessions pay no
     pipe2/fcntl/close churn, and pooled pipes are never reused with unread
     data. Source EOF → graceful write-side shutdown of the destination
     (half-close preserved per direction). Decline (pool/FD budget/pipe2
     failure) only before the first byte.
   - **buffered**: bounded pool, one buffer per direction, zero-fill at
     allocation only.

   Every backend declines only before transferring its first byte and falls
   through the order above. A backend error after transfer starts terminates
   the relay; it is never replayed.
7. **Teardown.** Source EOF shuts down the destination write side in the same
   direction; the peer direction is unaffected. A raw-stage `BrokenPipe` or
   `ConnectionReset` (benign peer-teardown race) closes the direction cleanly
   with its accumulated stats instead of failing the session as a protocol
   rejection.

## Hot-path topology

Per-connection steady cost: 2 tasks, no per-record allocation, one timer
registration per progress step, no hot-path logging.

| stage | owner | allocations | atomics/locks | syscalls | copies |
|---|---|---|---|---|---|
| accept | 1 task/listener | none steady | FD permit CAS + governor CAS | accept4, setsockopt×5 | 0 |
| REALITY auth | conn task | ClientHello + target buffers; one contiguous server-flight wire buffer | handshake/crypto CAS permits, replay cache shard locks | 1–3 reads, flight write | hello/ALPN parse borrowed; transcript tail sealed directly |
| fallback | conn task | prefix vecs (bounded) | fallback CAS, FD CAS ×2, connect | connect, prefix write, then relay | prefix writes only |
| VLESS request | conn task | 533 B initial buffer; grows only for coalesced payload; accepted domain owned once | 0 | TLS records | Addons/domain/prefetch parsed borrowed |
| routing | conn task | 0 no-DNS hit path | one UUID lookup; group policy shared by Arc | optional bounded DNS (spawn_blocking, 1 semaphore slot held till op ends) | 0 |
| outbound connect | conn task | 0 | one tag lookup; FD unit CAS; lock-free rate + concurrency CAS | connect | 0 |
| Vision framed uplink | direction task | socket buffer once (grow-only) | 0 in loop | 1 read/refill (≤64 KiB), 1 write/record | AEAD open in place; borrowed Vision decode (0) |
| Vision framed downlink | direction task | socket buffer once | 0 in loop | 1 read/refill, 1 write per packed record set | AEAD seal in place; Vision frames packed |
| Direct transition | both tasks | 0 | 2 atomics + 1 mutex (once) | 0 | pending-drain write |
| raw relay (splice) | direction task(s) | 0 | pool Mutex per take/give_back (2/session) | splice×2/chunk; pipe syscalls ~0 (pool) | 0 (kernel) |
| raw relay (buffered) | direction task(s) | pooled 32 KiB buffer | pool Mutex + semaphore per session | read+write/chunk | 1 userspace copy/chunk |
| teardown | direction tasks | 0 | state CAS | shutdown/close; abort→SO_LINGER+close | 0 |

## Handoff session transfer

When routing resolves an accepted session to a handoff outbound, the session
changes owner instead of being served locally. The boundary is exact: routing
has resolved, no Vision response was written toward the client, the
server-direction record sequence is either zero or one (depending on the
optional fake NST), and no Vision state exists yet. The ownership rule is
**one session, one protocol owner at any instant**:

```text
LINE_OWNED -> HANDOFF_IN_PROGRESS -> LANDING_OWNED | ABORTED
```

- **LINE_OWNED** — the line node holds the full session: both TLS 1.3 record
  layers, the VLESS request, the client socket.
- **HANDOFF_IN_PROGRESS** — LINE exports the continuation state and seals it
  into one single-flight transfer (a fresh ephemeral X25519 exchange against
  the landing node's static key, mixed with the pair PSK, ChaCha20-Poly1305
  over the full transcript). What crosses the channel, by class: the session
  key material (both directions' application traffic keys and IVs), the
  record sequences and cipher suite, the routing decision (VLESS user id and
  destination), and the in-flight buffers (client random, read-ahead
  ciphertext the reader already consumed, prefetched request payload). After
  the transfer write completes, LINE drops its copy of the continuation state
  and holds no TLS or Vision state for the session again.
- **LANDING_OWNED** — LANDING verifies the transfer (header, timestamp,
  replay cache, key agreement, AEAD, consistency checks — in that order),
  reconstructs the record layers, feeds the transferred pending bytes first,
  dials the destination directly, and runs the standard Vision relay. Its
  first sealed record (the VLESS response header and opening Vision frame)
  doubles as the transfer's success signal.
- **ABORTED** — every LANDING-side failure is a silent close with zero
  response bytes. LINE awaits the first downlink byte with a bounded deadline
  (`firstByteTimeoutMs`); its absence — close, stall, or non-TLS bytes — is
  the rejection signal, and LINE resets the client socket with
  `SO_LINGER{on,0}` (RST, never FIN) instead of serving the session locally
  with consumed state.

After a successful transfer LINE becomes a thin raw relay: it splices client
ciphertext against the handoff socket in both directions without touching a
single TLS record — the session's per-byte cryptographic ownership has moved
to LANDING. A client that resets at teardown (a close with the final
close_notify unread) ends the affected splice direction like an EOF, because
both sockets carry TLS records whose close semantics the endpoints enforce;
every other raw relay keeps the abort-on-reset semantics.

## Descriptor budget

Derived at startup, before any listener is bound:

```text
effective_dynamic_fd_budget = soft_rlimit - fixed_fd_reserve - safety_headroom
```

The fixed reserve is deliberately pessimistic:

| Component | Reserved |
|---|---|
| Listening sockets | one per configured inbound |
| Standard streams and logger sink | 4 |
| Runtime epoll, eventfd and wakers | 16 |
| Uncancellable resolver descriptors | 32 |
| Emergency reserve | 1 |

Resolver descriptors are reserved rather than admitted because a cancelled
`TcpStream::connect` cannot cancel the blocking `getaddrinfo` underneath it;
those descriptors outlive the connection that asked for them. The safety
headroom is `max(soft_limit / 16, 64)` in standard mode; the dedicated
resource mode derives its own larger headroom (see the
[configuration reference](configuration.md#dedicated-resource-mode)).

Policy:

- **Refuse to start** when the soft limit cannot cover the fixed reserve plus
  a minimum viable dynamic budget of 64 units; the error names the measured
  limit and the required value.
- **Clamp downward and warn once** when the configured peak exceeds what the
  limit permits. The startup `descriptor_budget_report` names both numbers
  and the soft limit that would avoid clamping.

Under no policy does the process start with a configuration it cannot honour
and then discover the problem in `accept4`. `maxConnections` remains a
protocol limit; the descriptor budget simply binds first when it is the
tighter constraint.

`FdBudget` is a strict upper-bound permit counter: one relaxed load and one
`compare_exchange_weak` on the fast path, no mutex; permits release in `Drop`
through one path; release uses checked subtraction so a double-release bug is
recorded rather than silently absorbed; waiting under pressure is a bounded
`Notify` wakeup, never a poll loop. Conservative unit costs: 1 per inbound
socket, 1 per outbound socket, 1 per live connector candidate, 4 per
bidirectional splice relay.

Pressure is entered at 15/16 of capacity and left at 13/16; the hysteresis
gap keeps a burst of releases from re-entering pressure on the next accept.
Pressure logging is transition-based. The process never polls
`/proc/self/fd` for admission.

## Listener recovery

Acceptance is three phases with distinct failure semantics:
`accept → configure → admit`. A per-connection socket-option failure closes
that stream, releases its permit, emits one
`connection_rejected{reason:socketConfiguration}`, and continues accepting.

Accept errors are classified from raw `errno`:

| Class | Errnos | Response |
|---|---|---|
| `wouldBlock` | `EAGAIN` | retry, no log |
| `transient` | `EINTR`, `ECONNABORTED`, `EPROTO`, `ECONNRESET`, `ENETDOWN`, `ENETUNREACH`, `EHOSTDOWN`, `EHOSTUNREACH`, `ENONET`, `ETIMEDOUT`, `EPERM` | retry immediately, bounded log |
| `descriptorPressure` | `EMFILE`, `ENFILE` | emergency-FD recovery, backoff, never terminate |
| `memoryPressure` | `ENOBUFS`, `ENOMEM` | bounded exponential backoff |
| `fatal` | `EBADF`, `ENOTSOCK`, `EOPNOTSUPP`, `EINVAL`, `EFAULT` | terminate this listener only, with errno attached |
| `unknown` | anything else | backoff and retry |

Backoff starts at 5 ms, doubles, and is capped at 500 ms; it resets on the
first successful accept.

One descriptor is held open on `/dev/null` for the process lifetime as an
emergency reserve. Admission bounds only what this process accounts for; a
library, resolver thread, or another process can still consume a descriptor
against the shared `ENFILE` limit. On an unexpected `EMFILE` the reserve is
released, one accept is attempted with a 1 ms bound, the accepted socket is
closed immediately, and the reserve is reacquired. The peer observes a close
rather than a hang. This is a last-resort path, not a substitute for correct
admission.

## Splice descriptors

A bidirectional splice relay creates two pipe pairs; four FD units are
acquired *before* `pipe2`, and the permit is owned by the same object as the
pipes. When units are unavailable the backend declines — safe because it
happens before any byte is transferred, so the caller falls through to the
buffered backend without replaying the connection. If the second pipe pair
fails, the first is closed and all four units are released.

## Removed kernel relay backends

- **sockhash**: removed. It never armed in any production benchmark matrix,
  a privileged A/B showed parity with splice, and the unprivileged production
  deployment model could never arm it. Stale `sockhash`,
  `maxSockhashRelays`, or `maxPinnedMemoryBytes` configuration keys fail
  strict decoding as unknown fields.
- **io_uring**: removed, not implemented. Rationale:
  [decisions/0002-io-uring-removed.md](decisions/0002-io-uring-removed.md).
  Stale `ioUring` or `maxIoUringRelays` configuration keys fail strict
  decoding as unknown fields.

The automatic backend order is splice → buffered; the portable buffered
relay and Linux `splice` require no additional privilege.

## Resource governance

Static per-kind admission semaphores (connection, handshake, crypto,
fallback) plus the lock-free FD budget with pressure hysteresis exist in
every mode. `runtime.resourceMode: "dedicated"` adds machine-aware budgeting
and a two-dimensional (FD + memory) pressure model; see the
[configuration reference](configuration.md#dedicated-resource-mode).

## Observability

| Event | When |
|---|---|
| `relay_backend_report` | once at startup: one line per backend (configured / supported / runtime-ready / decline reason) |
| `descriptor_budget_report` | once at startup; prints the recommended soft limit |
| `machine_report` | once at startup, dedicated resource mode only |
| `descriptor_pressure_changed` | on a descriptor-pressure transition, never per accept |
| `resource_pressure_changed` | on a combined-state transition, never per sample |
| `accept_error_recovered` | on a recoverable accept error, with raw errno |
| `connection_rejected` | per refused connection, with a closed-vocabulary reason |
| `admission_limited` | per category refused by a limit or by the pressure state |
| `connection_completed` (debug) | per connection: byte counts, per-direction Direct flags, selected backends, handoff delays |

No event carries a target, an SNI value, a UUID, a key, or any payload.
