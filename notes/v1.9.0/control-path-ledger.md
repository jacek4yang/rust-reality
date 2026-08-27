# Per-connection control-path ledger

Scope: one normal, successful, authenticated Vision Direct session on the current
`main`, from `accept` to the point where the kernel `splice` loop owns the transfer.
Established by reading the code, not by hardware counters — the benchmark host has
`perf_event_paranoid = 3`, so no cycle or cache figures appear here and none are
estimated.

This is the control path only. Payload copies are accounted separately.

## Conclusion first

A normal connection performs on the order of **15 relaxed atomic operations, one
1–2 entry map lookup, two to three `Arc` increments, one task spawn, and zero
locks, zero futex waits, zero heap allocations for admission** before reaching the
same `splice` dataplane v1.4 used.

That cost is **per connection**, not per record or per relay chunk. Amortised over a
multi-gigabyte bulk transfer it is arithmetically incapable of explaining a 15–20 %
sustained throughput difference. It could matter for a connection-rate-bound
workload; it cannot matter for single-stream bulk download.

So the control-plane growth between v1.4 and current — the ~3,600 new lines in
`src/runtime` — is **not** a plausible cause of the historical bulk-throughput
observation. That is a narrowing of the search space, not a claim that the
observation was wrong.

## Stage-by-stage

| stage | atomics | Arc clone | alloc | lock | syscall | lookup |
| --- | --- | --- | --- | --- | --- | --- |
| accept | — | — | — | — | `accept4` | — |
| fd budget permit | 1 CAS | — | — | none | — | — |
| generation load (`ArcSwap`) | 1 acquire | guard | — | none | — | — |
| listener → `ConnectionRuntime` | — | 1 | — | none | — | `HashMap`, 1–2 entries |
| logger clone | 1 | 1 | — | none | — | — |
| socket configuration | — | — | — | — | `setsockopt` ×n | — |
| connection admission | 1 acquire + 1 CAS | — | — | none | — | `match` on kind |
| task spawn | tokio internal | — | task box | none | — | — |
| pre-auth idle admission | 1 acquire + 1 CAS | — | — | none | — | — |
| handshake admission | 1 acquire + 1 CAS | — | — | none | — | — |
| REALITY crypto admission | 1 acquire + 1 CAS | — | — | none | — | — |
| replay admission | 1 acquire + 1 CAS | — | — | none | — | — |
| user lookup | — | — | — | none | — | sorted, ≤64 UUIDs |
| routing select | — | — | none | none | — | compiled matcher |
| outbound select | — | — | — | none | — | sorted, ≤4 tags |
| Vision transition | — | — | — | none | — | — |
| raw-relay rendezvous | — | — | — | none | — | — |
| splice setup | pipe-pool CAS | — | pooled | none | `pipe2` if cold | — |
| cleanup | permit release CAS ×n | drops | — | none | `close` | — |

## Primitives, verified

**Admission is a relaxed compare-exchange on one counter.** Not a Tokio
`Semaphore`, so no waker registration, no futex, no task parking:

```rust
// src/runtime/ceiling.rs
pub(crate) fn try_acquire(&self) -> Option<CeilingPermit> {
    let ceiling = self.ceiling();
    let mut observed = self.in_flight.load(Ordering::Relaxed);
    loop {
        if observed >= ceiling { return None; }
        match self.in_flight.compare_exchange_weak(
            observed, observed + 1, Ordering::Relaxed, Ordering::Relaxed,
        ) { Ok(_) => break, Err(actual) => observed = actual }
    }
    …
}
```

**The pressure gauge is one `Acquire` load plus a decode**, and it is optional —
`if let Some(gauge) = &self.inner.pressure` means a configuration without pressure
tracking pays a single branch:

```rust
pub fn state(&self) -> ResourcePressure { decode(self.inner.state.load(Ordering::Acquire)) }
```

**The permit is a stack value.** `AdmissionPermit { kind, _permit }` — RAII release,
no box, no registry insertion.

**`admission.rs`, `ceiling.rs` and `fd_budget.rs` contain no `Mutex` or `RwLock`.**
The whole admission subsystem is lock-free on both the success and the rejection
path.

**Soft ceilings are free when unused.** The adaptive knob only moves a ceiling when
a controller calls it; until then `try_acquire` compares against a constant and
behaves exactly as a fixed-size pool. This satisfies the requirement that adaptive
behaviour stay off the per-record path: the controller writes a ceiling
occasionally, and the datapath never runs controller logic.

## A suspicion raised and rejected

While tracing, `AdmissionKind::CryptoOperation`, `ReplayEntry` and `Handshake`
appeared to have pools, pressure classification and `runtime explain` reporting but
no production acquisition site — which would have made
`resourceGovernor.maxHandshakes` a *misleading* control surface: an operator tunes a
number that nothing enforces.

**Rejected.** The initial greps were truncated. Every kind is enforced:

```text
Connection       src/server/production.rs
PreAuthIdle      src/server/pre_auth.rs
Handshake        src/server/pre_auth.rs
CryptoOperation  src/server/reality.rs, src/server/cover_profile.rs
ReplayEntry      src/protocol/reality/replay.rs
Fallback         src/server/fallback.rs
DnsLookup        src/server/dns.rs
```

No dead admission kind, no misleading reported limit. Recorded because a rejected
suspicion is part of the model, and because the failure mode — believing a truncated
search — is worth naming.

## What is genuinely absent from the success path

- no `String` allocation, no `format!`, no `to_string`
- no `HashMap<String, _>` — the one map is keyed by `SocketAddr` on 1–2 entries
- no serde structure and no `Config` (see the CompiledRuntimePlan audit)
- no lock, no `Semaphore`, no futex
- no per-record or per-chunk controller computation

## Open, and honestly open

- **Task allocation.** `tokio::spawn` boxes the connection future. Its size is the
  subject of the rejected future-factory experiment, still unexplained: shrinking
  21,224 B → 10,768 B *lost* framed-download throughput. Mechanism unknown; static
  codegen analysis is the available route without PMU.
- **Per-accept map.** 1–2 entries, one lookup per accept. Below evaluator resolution;
  deliberately untouched.
- **Cycle-level cost.** Not measurable here. Recorded as PMU-pending rather than
  guessed.

## Epistemic status

```text
measured    admission is a relaxed CAS on one counter, no semaphore, no futex
measured    admission subsystem contains no Mutex or RwLock
measured    pressure read is one Acquire load, and is optional
measured    every AdmissionKind is enforced at a real production site
measured    success path allocates no String and touches no Config
established control-path cost is per-connection and cannot explain bulk-throughput loss
rejected    "some admission kinds are reported but unenforced"
open        connection-future size mechanism
pending     cycle-level cost, blocked on PMU availability
```
