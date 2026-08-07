# Architecture refactor plan (1.0)

Status: living document. Branch: perf/1.0-pipe-pool. Written after the
correctness-closure battery and the D8 decision surface.

## A. Current hot-path topology (verified against source, this branch)

| stage | owner | allocations | atomics/locks | syscalls | copies |
|---|---|---|---|---|---|
| accept | 1 task/listener | none steady | FD permit CAS + governor CAS | accept4, setsockopt×4 | 0 |
| REALITY auth | conn task | ClientHello buffer (≤16KiB, once) | handshake/crypto CAS permits, replay cache shard locks | 1-3 reads, flight write | hello parse borrow-based |
| fallback | conn task | prefix vecs (bounded) | fallback CAS, FD CAS ×2, connect | connect, prefix write, then relay | prefix writes only |
| VLESS request | conn task | request buffer ≤533+16KiB once | 0 | TLS records | 0 (borrowed prefetch) |
| routing | conn task | 0 hit path | shared rules (Arc) | optional bounded DNS (spawn_blocking, 1 semaphore slot held till op ends) | 0 |
| outbound connect | conn task | 0 | FD unit CAS, direct barrier CAS | connect | 0 |
| Vision framed uplink | direction task | socket buffer once (grow-only) | 0 in loop | 1 read/refill (≤64KiB), 1 write/record | AEAD open in place; borrowed Vision decode (0) |
| Vision framed downlink | direction task | socket buffer once | 0 in loop | 1 read/refill, 1 write per packed record set | AEAD seal in place; Vision frames packed |
| Direct transition | both tasks | 0 | 2 atomics + 1 mutex (once) | 0 | pending-drain write |
| raw relay (splice) | direction task(s) | 0 | pool Mutex per take/give_back (2/session) | splice×2/chunk; pipe syscalls ~0 (pool) | 0 (kernel) |
| raw relay (buffered) | direction task(s) | pooled 32KiB buffer | pool Mutex + semaphore per session | read+write/chunk | 1 userspace copy/chunk |
| raw relay (sockhash, opt-in) | — | 0 | arm transaction | map_update×2, teardown probes | 0 (kernel redirect) |
| teardown | direction tasks | 0 | state CAS | shutdown/close; abort→SO_LINGER+close | 0 |

Per-connection steady cost: 2 tasks, no per-record allocation, one timer
registration per progress step, no hot-path logging.

## B. Target architecture (evidence-justified)

Keep: one Tokio multi-thread runtime (no contention evidence), direction-
specialized relay, process-lifetime authorities (closure stage), PipePool
(provisional). The only open structural questions are:

1. **Backend decision surface (D8).** Raw-relay surface measured: splice beats
   buffered-32KiB on throughput AND CPU/GiB at every concurrency (2.2-2.8 vs
   1.7-2.1 GiB/s; 420-480 vs 560-640 ms/GiB). But Xray's fallback (readv/
   writev 64KiB userspace, no splice) measures 2.4-4.2 GiB/s against our
   splice fallback 1.9-2.5. Hypothesis D8a: buffered with 64KiB buffers
   matches Xray's readv path and beats splice at availability-limited
   concurrency. The 64KiB surface decides the fallback backend policy.
2. **Framed path.** ~46% AEAD on a c1 framed profile; after the copy/timer/
   zero-fill cleanup the framed path is crypto-bound. Framed work beyond
   parity is a research question requiring an AEAD fraction decomposition
   (per-record seal/open cost vs GHASH vs copies) — no crypto provider change
   without that evidence.
3. **Connection setup.** Not yet profiled independently (accept→first-byte);
   needs a setup-rate harness before any claim.

## C. Keep / Replace / Delete matrix

| subsystem | verdict | reason |
|---|---|---|
| Tokio multi-thread runtime | KEEP | no migration/contention evidence |
| TcpRelay backend selector + TransferLedger | KEEP | honest decline-before-byte semantics |
| splice backend | KEEP | wins the raw surface outright |
| buffered backend | KEEP (resize research) | needed as fallback + possibly 64KiB |
| PipePool | KEEP-PROVISIONAL | zero-cost mechanism; delete if splice use shrinks |
| sockhash backend | EXPERIMENTAL→decide | reachability/benefit unproven; opt-in only |
| DirectHandoff coordinator | KEEP | linearizable decision, mutex once/session |
| framed TLS record layer | KEEP | zero-alloc, grow-only, buffered reads |
| ResourceGovernor/DirectBarrier (process-lifetime) | KEEP | closure stage |
| admission pressure model | KEEP | verified under saturation |
| per-connection 2-task split | KEEP | half-close independence proven |
| legacy relay_bidirectional + handler.rs | DELETE | dead production code (used only by its own tests) |

## D. Performance hypotheses (falsification-first)

- **D8a**: buffered-64KiB ≈ Xray's fallback readv throughput at c32/c64 and
  beats splice there. Falsifier: 64KiB surface shows buffered ≤ splice
  throughput/CPU at c32/c64 → splice stays; fallback gap re-attributed to
  session setup or origin interplay.
- **D8b**: if 64KiB confirms, the fallback path should prefer buffered-64K for
  high-churn sessions with a measured criterion — NOT an adaptive classifier
  (explicitly deferred by directive).
- **D9 (framed)**: AEAD fraction ≥ 40% of framed CPU; improvable headroom is
  the non-AEAD remainder only (~1.1-1.2x max framed speedup unless AEAD itself
  improves). Falsifier: decomposition shows AEAD < 25% → wider headroom.
- **D10 (setup)**: per-connection setup cost is unmeasured; hypothesis: REALITY
  auth dominates setup CPU. To be measured with a setup-rate harness.

## Experiment register (active)

| exp | hypothesis | measurement | status |
|---|---|---|---|
| E-D8-surface | splice vs buffered raw surface | relay-surface.jsonl (270 samples) | DONE: splice wins everywhere |
| E-D8-64k | D8a | relay-surface-64k.jsonl | RUNNING |
| E-D8-fallback-e2e | D8a end-to-end | matrix fallback cells, splice on/off | PENDING |
| E-D9-amadhl | framed AEAD fraction | perf decomposition | PENDING |

## Reverted/rejected so far

- PipePool-as-fallback-fix: falsified (kept as zero-cost mechanism, provisional).
- io_uring: removed (prior stage).
- Short-flow classifier: forbidden without new evidence; not built.
