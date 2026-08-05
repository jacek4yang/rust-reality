# Performance: the proxy data path

This document describes how the production data plane moves bytes, which kernel
backends exist, when each is selected, and what is reported at runtime. It is
the design companion to `PERFORMANCE-REPORT.md`, which carries the measured
evidence.

## Connection lifecycle

1. **Accept.** The listener acquires an FD-budget permit *before* `accept(2)`
   and classifies accept errors; on descriptor pressure an emergency reserve
   descriptor is used to free capacity. One task per connection.
2. **REALITY.** The ClientHello is read under a bounded deadline and either
   authenticates or falls back. Fallback is byte-exact: the consumed client
   prefix is replayed to the cover target, any inspected target prefix is
   replayed to the client, and the remaining raw pair is handed to the unified
   relay (`TcpRelay::relay_owned`) — splice-capable and FD-accounted, never a
   borrowed userspace copy.
3. **VLESS + Vision.** The request is decoded from the outer TLS stream;
   routing selects an outbound; the session splits into two independent
   direction tasks (uplink, downlink).
4. **Framed phase.** Both directions run outer-TLS record I/O with Vision
   padding. Hot-path properties (measured, regression-gated):
   - zero steady-state heap allocations per record (instrumented-allocator
     gates in `tls13/allocation_gate.rs`);
   - record storage is grow-only and zero-initialized at most once per size
     class — no per-record 16 KiB zero fill;
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
     no post-boundary raw byte sits in a userspace buffer (the Xray
     `rawInput` problem cannot occur);
   - the downlink raw relay starts only after the final framed write
     completed — the ordering Xray commit `f926ee4a` protects;
   - once a direction moved any raw byte through a backend it can never be
     replayed through another backend (`TransferLedger`).

6. **Raw phase backends.** Selection is honest and evidence-based:

   | situation | order |
   |---|---|
   | bilateral pair, complete sockets, zero bytes moved | sockhash → splice → buffered |
   | single raw direction | directional splice → directional buffered |

   - **sockhash** (Linux, `policy.relay.sockHash`, needs CAP_BPF/privilege):
     both sockets are armed into a SOCKHASH with a stream-verdict SK_SKB
     program; the kernel redirects payload socket→socket with no userspace
     involvement. Arming is transactional (both directions or neither,
     idempotent rollback), requires complete socket ownership, a zero-byte
     ledger, and empty userspace input queues (FIONREAD guard). FIN is not
     propagated by the redirect: each half-close is detected and synthesized
     on the peer after a drain barrier proves the redirect backlog converged.
     Accounting is kernel-reported (TCP_INFO deltas against arm baselines).
   - **splice**: one pipe pair per direction (bilateral = two pairs), exactly
     2 FD units per direction, reserved before `pipe2`. Source EOF → graceful
     write-side shutdown of the destination (half-close preserved
     per direction). Decline (pool/FD budget/pipe2 failure) only before the
     first byte.
   - **buffered**: bounded pool, one buffer per direction, zero-fill at
     allocation only.
   - **io_uring**: **removed, not implemented**; stale `ioUring` config keys
     fail decoding. Rationale: `decisions/adaptive-relay-implementation-plan.md`.

   Every backend declines only before transferring its first byte and falls
   through the order above. A backend error after transfer starts terminates
   the relay; it is never replayed.

7. **Teardown.** Source EOF shuts down the destination write side in the same
   direction; the peer direction is unaffected. A raw-stage `BrokenPipe` or
   `ConnectionReset` (benign peer-teardown race) closes the direction cleanly
   with its accumulated stats instead of failing the session as a protocol
   rejection.

## Observability

- Startup: `relay_backend_report` (one line per backend: configured /
  supported / runtime-ready / decline reason), `descriptor_budget_report`,
  `machine_report` (dedicated mode).
- Per connection (debug): `connection_completed` with
  `uplink_bytes`/`downlink_bytes`, `uplink_direct`/`downlink_direct`,
  `relay_backend` (pair), `uplink_backend`/`downlink_backend` (directional),
  `uplink_direct_at_bytes`/`downlink_direct_at_bytes`,
  `uplink_handoff_delay_us`/`downlink_handoff_delay_us`.
- Pressure: `descriptor_pressure_changed`, `resource_pressure_changed`
  (transitions only).

## Resource governance

Static per-kind admission semaphores (connection, handshake, crypto, fallback)
plus the lock-free FD budget with pressure hysteresis exist in every mode.
`runtime.resourceMode: "dedicated"` adds machine-aware budgeting and a
two-dimensional (FD + memory) pressure model; see
[dedicated-resource-mode.md](dedicated-resource-mode.md).

## Methodology note (benchmarks)

The workspace proxy environment sets `NO_PROXY` with `127.0.0.1`, which makes
curl bypass even an explicit `--socks5-hostname` for loopback URLs. Every
benchmark harness in `scripts/` strips proxy variables from the curl
environment and the Vision-Direct/matrix harnesses verify tunnel usage via
server-side connection logs. Numbers produced without this guard measure
direct loopback connections, not the proxy.
