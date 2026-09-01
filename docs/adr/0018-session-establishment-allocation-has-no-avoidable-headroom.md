# ADR 0018: Session-establishment allocation has no avoidable headroom

## Status

Accepted (negative result). Complete session establishment was characterized
against the real setup-rate harness. No production source changed, and none is
justified. This ADR exists so the obvious follow-on — pooling the per-connection
TLS buffers — is not proposed again without new evidence.

## Context

Issue #198 left allocation characterization outstanding after
[ADR 0017](0017-relay-atomic-and-contention-hypotheses-rejected.md) closed the
three relay hypotheses. The question was narrow: does complete production
session establishment contain a *material, avoidable* allocation mechanism worth
optimizing? "No" was an explicitly valid answer.

The steady-state payload path was not the subject. It is kernel `splice`, and
the framed record loop already has zero-allocation-per-record gates in
`src/protocol/reality/tls13/allocation_gate.rs`. The interesting unit is the
session.

Baseline: protected main `2d2e73587931c54eb6aa7363003ffcd1b41f4461`, frozen as
SHA-256 `2f72d71257099147c67c172313627237882cb876cf5db8512549ceab305be3e8`,
Build ID `24921a0f6764374c910c58aa3f394d96cadb64e5`, manifest verified.

## Method

Two evidence classes, kept strictly separate.

**Allocation counts** came from a diagnostic build: a counting `GlobalAlloc`
wrapping `System` with relaxed atomics and bounded size buckets — non-allocating,
so no recursion — plus a per-admitted-connection counter, emitting one bounded
stderr line every 250 ms. Because each benchmark slot runs a fresh server
process, per-session figures are deltas between the first and last snapshot of
each process, which excludes startup entirely and never depends on aligning with
the harness.

**CPU attribution** came from production and symbolized builds under the
benchmark-owned profiler, never from the counting build. Instrumented CPU was
never compared against uninstrumented CPU.

The diagnostic sources were reverted; nothing from them is committed.

## What was measured

Real setup-rate harness, 12 server processes, concurrency 1/8/32, 31,140
sessions, **zero failures**:

| | per session |
| --- | --- |
| allocations | **80.64** |
| deallocations | 80.70 |
| reallocations | 5.23 |
| bytes allocated | **241,257** |
| realloc bytes | 18,148 |

Agreement across the 12 independent processes was 80.50–80.71 allocations per
session, a spread of 0.26%. Allocations minus deallocations was −1,836 over
31,140 sessions, so nothing accumulates.

Size distribution, and this shape is the load-bearing part:

| class | per session | share |
| --- | --- | --- |
| ≤16 B | 14.03 | 17.4% |
| 17–32 B | 8.40 | 10.4% |
| 33–64 B | 12.03 | 14.9% |
| 65–128 B | 12.02 | 14.9% |
| 129–256 B | 8.03 | 10.0% |
| 257–512 B | 2.01 | 2.5% |
| 513 B–1 KiB | 5.17 | 6.4% |
| 1–4 KiB | 12.92 | 16.0% |
| 4–16 KiB | 1.02 | 1.3% |
| 16–64 KiB | 3.01 | 3.7% |
| 64–256 KiB | 2.00 | 2.5% |

**Allocator CPU.** Two independent profiles agree: `malloc` 0.86–0.98%, `free`
0.56–1.03%, `calloc` 0.22%, `realloc` 0.15%, plus the unnamed `malloc.c`
internals between `__default_morecore` and `malloc`. Total **≈2.4% of userspace
cycles**. Userspace is about 60% of setup CPU, so the allocator is
**≈1.4% of total CPU per session**.

One correction worth recording: the hottest unnamed libc region in these
profiles (≈1.6% at `0x163613` and a cluster around `0x162xxx`) is *not* the
allocator. Disassembly shows size-dispatched byte copies — the string/memory
routines. Attributing it to `malloc` would have overstated allocator cost by
roughly two thirds.

**No memory-syscall or fault churn.** Attributing system-wide events by command
over a 100 s window covering ~13,000 sessions, the server issued ~717 `mmap` and
~311 `munmap` — **0.055 mmap per session** — and took ~2,566 page faults, or
**0.20 per session**. The client harness, not the server, is the mmap-heavy
process. glibc's adaptive threshold keeps the large buffers on a warm, recycled
heap; they are not remapped per session.

## Decision

**No production change. There is no single avoidable allocation family with
headroom above the measurement floor.**

The setup CPU/session A/A floor is ±0.5%, measured during #192 (bootstrap95
[0.9959, 1.0067]). Against an allocator costing ≈1.4% of session CPU, a
candidate must remove **≥35% of allocator cost — about 28 of the 80.64
allocations per session** — merely to be distinguishable from noise.

The largest identifiable family is the fixed per-connection protocol buffers:
two of `SOCKET_BUFFER_CAPACITY` (`4 × MAX_TLS_RECORD_WIRE_LEN`, ≈66.6 KiB) and
three record-slot buffers (≈16.6 KiB), plus one 4–16 KiB buffer. Six
allocations, **7.4% of the count but ~90% of the bytes**. That asymmetry is what
makes 241 KB per session look alarming and be irrelevant.

Weighting those six by size against the small allocations:

| weight | recovered CPU/session | vs 0.5% floor |
| --- | --- | --- |
| 1× | 0.11% | below |
| 2× | 0.20% | below |
| 3× | 0.28% | below |
| 5× | 0.41% | below |

Even at 5× they do not clear the floor — and 5× is generous for heap-recycled
chunks that cost no `mmap` and no page fault.

No other family can qualify either, and this follows from the histogram rather
than from inspection: reaching 28 allocations per session means being ~35% of
all allocations, while the largest single size class is 14.03 (17.4%). The
distribution is flat across seven classes in the 8–14 per session range — the
signature of many small distinct families, not one dominant mechanism.

### Classification

| family | per session | classification |
| --- | --- | --- |
| 2 × ≈66.6 KiB TLS socket buffers | 2 | `REQUIRED_BY_OWNERSHIP_LIFETIME` — per-connection, holds TLS ciphertext and plaintext |
| 3 × ≈16.6 KiB record-slot buffers | 3 | `REQUIRED_BY_OWNERSHIP_LIFETIME` |
| X25519 / ML-KEM / key-schedule state | several | `REQUIRED_BY_CRYPTO` |
| Tokio task, future and timer state | several | `REQUIRED_BY_RUNTIME` |
| small temporaries across seven size classes | ~74 total | `CURRENTLY_UNAVOIDABLE` / `REQUIRED_BY_EXTERNAL_API`; no dominant member |

## Consequences

- Session establishment is not allocation-bound. The dominant userspace cost in
  these profiles is X25519 field arithmetic reached through
  `build_server_flight_inner` at 21.6% — the handshake itself, which is the
  work the session exists to do.
- 241 KB allocated per session is not a defect. It is six warm, recycled,
  correctly sized protocol buffers, and the bytes figure carries almost none of
  the CPU.
- No pool was introduced. The system allocator already provides size classes,
  thread caches and reuse; a second mechanism would add pointer chasing, locks,
  retained RSS and cache pollution to recover something unmeasurable.

## Rejected alternatives

- **Pool the per-connection TLS buffers.** The obvious proposal from the bytes
  figure, and the reason this ADR exists. Rejected twice over: the gain is below
  the measurement floor even at a 5× size weighting, and those buffers hold TLS
  plaintext and ciphertext, so reuse would require lifetime, zeroization and
  cross-session isolation analysis under the secret-hygiene rule. Paying a
  security-review cost for a sub-floor gain is the wrong trade.
- **A session arena or custom global allocator.** No measured allocation
  hotspot exists to justify either, and both were out of scope for exactly that
  reason.
- **Chase the 241 KB/session figure.** Bytes are not the cost; `mmap` per
  session is 0.055 and page faults are 0.20.
- **Attribute allocator callsites by sampling.** Attempted and rejected as
  unsound at this sample density: `malloc` draws ~17 samples in a 2K-sample
  profile, and glibc has no frame pointers, so `fp` unwinding cannot cross it.
  The exact size histogram plus source reading is the trustworthy instrument.

## Revisit conditions

- If session CPU falls far enough that 1.4% becomes a materially larger share —
  for example if the handshake crypto were substantially cheaper — re-derive the
  ceiling before proposing anything.
- If a future change introduces a *single* allocation family exceeding roughly
  30 allocations per session, it becomes a candidate on its own terms.
- If a workload appears whose sessions are much shorter than this harness's, so
  that fixed per-connection buffers amortize over less work, re-measure
  allocations per session first.
- Do not revisit to reduce allocated *bytes* per session. That number is not the
  cost, and this ADR records the measurement showing why.

## Evidence

- Issue #198, allocation characterization comment: counts, size distribution,
  allocator symbol attribution, `mmap` and page-fault attribution by command.
- Baseline freeze `2d2e73587931c54eb6aa7363003ffcd1b41f4461`; setup runs of 12
  slots and 31,140 sessions with zero failures.
- [ADR 0017](0017-relay-atomic-and-contention-hypotheses-rejected.md) for the
  relay hypotheses and the A/A floor discipline this reuses.
