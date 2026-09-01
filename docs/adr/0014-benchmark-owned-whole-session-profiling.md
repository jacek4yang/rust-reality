# ADR 0014: Whole-session profiling is owned by the benchmark transaction

## Status

Accepted. This decision changes tooling ownership only. It does not authorize a
production optimization or change benchmark verdict computation.

## Context

The setup-rate and Vision-Direct harnesses own more than a workload loop. A run
holds the exclusive benchmark host lock while it establishes topology, starts an
identity-registered server, performs warmup, measures the workload, restores host
state, and publishes its result. A useful whole-session profile must observe the
exact server in that transaction, after warmup and during the measured workload.

The standalone `cargo dev perf hotspot --mode attach-server` command cannot be
composed around that run. It correctly attempts to acquire the same exclusive
host lock, so starting it while the benchmark is active is rejected. Weakening
or bypassing the lock would create two authorities over the same host and make
both the benchmark and capture untrustworthy. Attaching later also cannot recover
the already-completed workload. Earlier diagnostic captures therefore used a
surrogate attachment and were useful only as qualitative evidence.

## Decision

**An optional whole-session hotspot capture is a child resource of the benchmark
transaction that owns the server.**

1. `setup-rate` and `vision-direct` accept `--profile`. No other benchmark suite
   accepts the option until it has an equivalent ownership and identity boundary.
2. The benchmark keeps its single exclusive host lock. The capture receives a
   borrow of that lock as authority evidence; it neither reacquires nor bypasses
   the lock.
3. The capture receives the benchmark's already-registered candidate binary,
   verified Build ID, and exact live server PID. It records PID start time,
   executable SHA-256, and Build ID before sampling, verifies the same process
   again before stopping, and archives the exact ELF read-only.
4. `perf record` is a scoped child of the capture. The child is interrupted and
   reaped when the workload finishes, or killed and reaped within a bounded
   cleanup interval if it does not cooperate. Target exit, early perf failure,
   timeout, or identity drift fails the capture.
5. A capture is complete only after non-empty `perf.data`, the exact Build ID in
   `perf buildid-list`, a usable `perf report`, immutable ELF identity, and
   checksums all verify. Its contract records benchmark capture authority and is
   otherwise admitted by the existing hotspot-bundle pipeline.
6. The enclosing benchmark cannot publish success until profile finalization and
   process cleanup have succeeded. A workload or profile failure leaves no
   completion marker for either result.

## Consequences

The captured interval begins after benchmark warmup and spans the measured
workload rather than process startup. This is the useful whole-session boundary
for the two supported harnesses, not a claim that every instruction from process
birth to exit is sampled.

The capture lives at `hotspot/` below the benchmark output directory and remains
a normal identity-bound hotspot artifact. Investigators can therefore use the
same `cargo dev perf hotspot-bundle` workflow against the archived exact ELF;
they do not need a symbol-rich surrogate binary.

The benchmark is the sole transaction authority, but the existing capture
machinery remains the sole authority for perf lifecycle, evidence validation,
and hotspot publication. This deliberately avoids a second profiler framework.

## Alternatives rejected

**Run the standalone attach command concurrently.** Rejected because its lock
failure is correct. Allowing concurrent lock owners would make host mutation and
cleanup ambiguous.

**Add a lock-bypass flag to hotspot capture.** Rejected because a user-provided
assertion cannot prove that the caller owns the topology, server, or cleanup
transaction.

**Profile a separately launched surrogate server.** Rejected as formal evidence:
it does not bind samples to the server that produced the benchmark result.

**Move perf orchestration into each benchmark harness.** Rejected because the
existing hotspot implementation already owns PID identity, Build-ID validation,
archival, reporting, checksums, and bundle admission. The benchmark needs a
scoped entry point, not a parallel implementation.

## Revisit conditions

- Add another suite only when it can pass an already-registered exact binary and
  PID from inside the same exclusive benchmark transaction.
- Change the sampled interval only when a named investigation requires a
  different phase boundary and the evidence contract records that boundary.
- Do not use this decision as justification for kernel, deployment, or production
  tuning; those require separate measured questions and review.
