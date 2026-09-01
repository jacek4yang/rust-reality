# ADR 0017: Relay atomic bookkeeping, pipe-cleanliness typestate, and pool contention are rejected on measurement

## Status

Rejected on measurement (negative result). Three performance hypotheses reached
terminal outcomes without any production source change. This ADR exists so they
are not retried without new evidence.

## Context

Issue #198 opened a cache-locality, allocation and syscall-efficiency milestone
with three named candidates in the relay data path:

- **H1** — `TransferLedger` performs a shared atomic read-modify-write per
  transferred chunk. Direction-local byte counts plus a cheaper one-way
  irreversible-transfer proof might remove it.
- **H2** — pooled splice pipes are checked with `ioctl(FIONREAD)` before reuse.
  The splice pump's success path structurally drains each chunk, so cleanliness
  might be provable from control flow instead of from the kernel.
- **H3** — `BufferPool`, `PipePool`, `FdBudget` and semaphore state are shared
  across connections and might be contended.

The governing rule was that none of "fewer syscalls is faster", "pooling
improves locality" or "lock-free beats `Mutex`" may serve as a justification.
Each had to be shown as a mechanism first.

Baseline: protected main `ae1c7b0935779a7ebdc32673d4bf4a371898ea2c`, frozen as
SHA-256 `da50fa39b8eab7211518e506637cc4cf25d9629dee387ad6dc6ebc50a6cbc823`,
Build ID `604978b388b012431ecaf84ebb09982eb5318957`, manifest verified before
use. Host: Intel Core i3-8100, 4 cores, no SMT, single socket, with
`perf_event_paranoid` left at 3 and measurement running under the existing
benchmark root authority.

## Decision

**Reject all three. Change no production code.**

### The measurement that settles H1 and H3

`perf c2c`, system-wide, during benchmark-owned runs:

| workload | records | load ops | Load Local HITM | Load Remote HITM | shared lines |
| --- | --- | --- | --- | --- | --- |
| Vision Direct relay, 1.25 GiB moved, c4 | 88,960 | 36,068 | **106** | 0 | 88 |
| Setup rate, 10,368 sessions, c32 | 260,980 | 103,614 | **160** | 0 | 141 |

106 cross-core HITM events across an entire 1.25 GiB relay, and the busiest
shared line accounts for six of them. The shared-line tables are dominated by
kernel addresses, not application data. Any application structure being
ping-ponged between cores at data-path frequency would dominate these tables.
None does.

### H1 — `REJECTED_BELOW_MEASUREMENT_FLOOR`

Three steps, each measured.

**Frequency.** The expectation that `record()` runs about 4,000 times per GiB —
one per 512 KiB pipe-capacity chunk — is wrong by an order of magnitude.
Counting the tracepoint system-wide during a Vision Direct run gave 58,883
`splice` entries for 1.250 GiB, i.e. **47,106 splice syscalls per GiB** and
about **23,553 `record()` calls per GiB**. splice is availability-limited, so at
~1.2 GiB/s on loopback it moves roughly 22 KiB per call.

**Cost per call**, measured on this host with the exact CAS loop from
`TransferLedger::add`: **8.37 ns** uncontended, **47.47 ns** with two threads
hammering the adjacent counters back to back. The two counters do share one
cache line — offsets 48 and 56 of the same 64-byte line — so false sharing is
structurally possible.

**Whether it occurs**: it does not, per the c2c table above. So the operative
figure is the uncontended one.

| | µs/GiB | of 80.4 ms/GiB | of 114 ms/GiB |
| --- | --- | --- | --- |
| realistic (uncontended) | 197 | 0.245% | 0.173% |
| worst case (fully contended) | 1,118 | 1.391% | 0.981% |

The relay CPU/GiB **A/A floor measured on this exact suite is 0.54%**: during
#192 an identical binary compared against itself produced a three-block
bootstrap interval excluding 1.0 by that margin. H1's entire theoretical
benefit, with the ledger cost driven to zero, is two to three times below the
floor of the instrument that would have to measure it.

This equally rejects the cheaper variant considered instead of the redesign —
padding the counters onto separate cache lines. Same ceiling, and c2c says
there is no false sharing to remove.

### H2 — `REJECTED_CORRECTNESS_RISK`

`PipePool::give_back` calls `pending_input` once per pooled pipe return — once
per relay direction, not per chunk. That is roughly **30 calls per GiB** on the
relay workload. On the setup workload, system-wide `ioctl` was 2.45 per session
*including the client harness and every other ioctl on the host*, and `pipe2`
was 0.062 per session, confirming the pool is hitting. The ceiling is about two
ioctls per session against ~555 µs CPU/connection — **~0.36%**, and only for
sessions that reach a Direct transition.

Being below the floor is not the whole reason. A structural simplification at
neutral CPU would be acceptable, and this is not one. Proving cleanliness from
control flow means tracking drained-ness through every splice-pump exit —
success, splice error, destination error, timeout, cancellation, partial
pending, unwind — and the failure mode of getting it wrong is session A's bytes
becoming session B's input. It trades a cheap kernel-authoritative check for a
hand-proven invariant, *adding* invariant surface, to recover something that
cannot be measured.

### H3 — `REJECTED_NO_MECHANISM` at ≤4 cores, `NOT_MEASURABLE_ON_CURRENT_HOST` beyond

There is no contention to shard. See the c2c table.

This host bounds how much contention can ever appear and makes remote HITM
structurally unobservable. The rejection is therefore scoped: it holds on the
measurable configuration and licenses no claim about a many-core deployment.

## Consequences

- No production source changed. No paired ABBA run was performed for any
  hypothesis: an expensive paired run is not justified when the mechanism has
  not changed, and a candidate below the demonstrated A/A floor is
  performance-neutral by construction.
- No PMU tooling was built. The existing harness collects `task-clock`,
  `instructions` and `context-switches`; the cache and TLB counters it does not
  collect turned out to be unnecessary, because tracepoint frequency and `c2c`
  answered every question. Building a general PMU framework to measure
  hypotheses that mechanism evidence already settles would have been the
  speculative tooling this milestone forbids.
- One durable fact is worth more than the three rejections: **splice moves
  ~22 KiB per call at ~1.2 GiB/s on loopback, not the 512 KiB pipe capacity.**
  Future reasoning about relay syscall rates should start from the measured
  47,106 splice syscalls/GiB rather than from the pipe size. The pipe capacity
  governs how much *can* be in flight, not how much each call moves.
- The `TransferLedger` counters remain on one cache line. That is recorded as a
  known structural property rather than a defect, because it is measurably not
  contended at this call rate.

## Rejected alternatives

- **Pad `TransferLedger`'s counters onto separate cache lines.** Cheaper and
  semantically free compared with the H1 redesign, and rejected for the same
  reason: the ceiling is below the measurement floor and c2c shows no false
  sharing to remove.
- **Run the paired A/B anyway to "see".** Rejected as an experiment known in
  advance to be unable to resolve its effect — the definition of manufacturing
  a number.
- **Extend the benchmark harness with a richer PMU event set first.** Rejected:
  no hypothesis needed it once frequency and `c2c` were measured.
- **Shard the pools because concurrency is high.** Rejected: c32 was measured
  and produced 160 local HITM events.

## Revisit conditions

- **H1** — if `record()` frequency rises by roughly 50×, which would mean a much
  smaller splice chunk or a path that records per TLS record rather than per
  splice; or if `c2c` on a many-core host shows the ledger line in the HITM
  table.
- **H2** — if a workload appears where pooled-pipe returns dominate the syscall
  profile, meaning very short Direct sessions at high rate. Even then, the
  isolation guarantee is not negotiable: only a proven-drained pipe may skip
  verification, and every other terminal state must drop it.
- **H3** — on a many-core, multi-socket host. Re-measure with `c2c` before
  either implementing or re-rejecting; this ADR does not settle that
  configuration.
- Do not revisit any of these to reduce a syscall count or raise a cache hit
  rate in isolation. Those are mechanisms, not results.

## Evidence

- Issue #198, Phase A comment: PMU capability table, both `c2c` captures, the
  splice frequency measurement, and the CAS cost measurement.
- Baseline freeze `ae1c7b0935779a7ebdc32673d4bf4a371898ea2c`; setup ABBA run
  over 12 slots and 10,368 sessions with zero failures.
- [ADR 0012](0012-relay-buffer-hypothesis-rejected.md) for the earlier relay
  hypothesis rejected on mechanism, and `docs/en/performance.md` D6, where
  PipePool was already shown to remove syscall churn without moving throughput.
