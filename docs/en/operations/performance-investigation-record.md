# Performance investigation record

This page preserves the durable conclusions of the closed performance
investigations: the per-connection control-path accounting, the historical
throughput question, and the mechanisms that were measured and rejected. The
[performance reference](../performance.md) holds the measured data-plane
properties and the release evidence; this page holds the *investigation*
record so the same hypotheses are not re-litigated from scratch.

## Per-connection control path (ledger)

Scope: one normal, successful, authenticated Vision Direct session on `main`,
from `accept` to the point where the kernel `splice` loop owns the transfer.
Established by reading the code — no cycle or cache figures are claimed.

**Conclusion first.** A normal connection performs on the order of **15 relaxed
atomic operations, one 1–2 entry map lookup, two to three `Arc` increments, one
task spawn, and zero locks, zero futex waits, zero heap allocations for
admission** before reaching the same `splice` dataplane earlier releases used.
That cost is per connection, not per record or per relay chunk. Amortised over
a multi-gigabyte bulk transfer it is arithmetically incapable of explaining a
15–20% sustained throughput difference. It could matter for a
connection-rate-bound workload; it cannot matter for single-stream bulk
download.

Verified primitives:

- **Admission is a relaxed compare-exchange on one counter** — not a Tokio
  `Semaphore`, so no waker registration, no futex, no task parking.
- **The pressure gauge is one `Acquire` load plus a decode**, and it is
  optional — a configuration without pressure tracking pays a single branch.
- **The permit is a stack value.** RAII release, no box, no registry insertion.
- The admission subsystem contains no `Mutex` or `RwLock` on either the success
  or the rejection path.
- **Soft ceilings are free when unused**: the adaptive knob only moves a
  ceiling when a controller calls it; until then `try_acquire` compares against
  a constant and behaves exactly as a fixed-size pool. Adaptive behaviour never
  runs controller logic on the per-record path.
- Every admission kind that is reported to operators
  (`maxHandshakes` etc.) has a real production acquisition site; the suspicion
  of an unenforced control surface was checked and rejected (the initial greps
  were truncated).

Control-plane growth between releases (the ~3,600 new lines in the runtime
resource/admission/derivation layer) is therefore **not** a plausible cause of
any historical bulk-throughput observation. That is a narrowing of the search
space, not a claim that the observation was wrong.

## Historical throughput question (≈671 vs ≈808 Mbps)

A real-WAN download difference (≈671 Mbps on the current deployment vs ≈808 on
an earlier setup) was investigated; see [ADR 0012](../../adr/0012-relay-buffer-hypothesis-rejected.md)
for the relay-buffer hypothesis rejection. The surviving durable facts:

- **The absolute numbers cannot be reproduced from the build host** — its own
  link caps near 70 Mbps, and the unproxied reference is *slower* than the
  proxied path. The decisive confirmation must be measured from the reporting
  client's vantage point.
- **v1.4.0 baseline identity** (downloaded and verified against the release
  `SHA256SUMS`): tag `v1.4.0`, commit `ed8fea0a5efae480a559691c738e6927ed85fa5c`,
  binary SHA-256 `38ba5cd5e02edbb039b13751220b91b60cb005a22d2241e6c3026d84ce643c57`,
  GNU Build ID `d1de46ed1deddb0dfe66434a09896589c0794e32`.
- **Mechanism triage**: the splice datapath barely moved between v1.4.0 and the
  investigation point (`relay.rs` byte-identical; `tcp_relay.rs` changed only a
  policy-type rename plus one constant); the runtime resource/admission layer
  grew ~3,600 lines — which the control-path ledger above rules out as a bulk
  throughput cause.
- **Rejected mechanism: splice pipe-page exhaustion.** The 256 KiB → 512 KiB
  splice pipe capacity change halved the calculated concurrent splice headroom
  under `fs.pipe-user-pages-soft` (~64 vs ~128 concurrent relays). Measured
  against the live node with 80 concurrent 4 MiB HTTPS streams: **zero
  `pipe_capacity_downgraded` events**, 80/80 sessions reached Direct, splice in
  both directions. The bounded pools and ramp/retire behaviour keep live pipe
  count under budget. Revisit condition: a workload holding more than roughly
  64 simultaneous splice relays, or a node with a lower
  `fs.pipe-user-pages-soft`.
- **Rejected mechanism: `relay.bufferBytes`** — see ADR 0012.
- **What is ruled out**: a CPU-side or per-record regression at 32 MiB loopback
  (32/32 protected metrics neutral against the published v1.8.0 baseline); a
  missing splice backend; measurement from the build host.

**Decision rule for settling the question** (stated in advance so the result
cannot be rationalised afterwards): run the four-way comparison — pinned stock
Xray, official v1.4.0, official v1.8.0, current candidate — from the original
high-bandwidth client, same VPS, same target, one short window, ABBA ordering.
If Xray and v1.4.0 both reproduce ~800 while the others sit near ~670, that is
strong evidence of a rust-reality regression and the version interval is then
bisected. If all four perform similarly in that controlled window, the
historical difference was environmental or WAN variance and **no rust-reality
regression should be invented**.

## Compiled-control-plane audit

The question "does the runtime need a `CompiledRuntimePlan` construct" was
answered negatively by audit; see [ADR 0013](../../adr/0013-no-compiled-runtime-plan.md).
