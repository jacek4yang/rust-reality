# ADR 0010: Rejected connection-future factory (per-connection task memory)

## Status

Rejected on measurement; recorded so the finding is not lost and the
experiment is not repeated blindly.

## Context

`ConnectionTasks::spawn` took the connection future by value and awaited it
inside a spawned async block. rustc keeps the captured upvar slot alive for the
whole coroutine alongside the separate awaitee slot, so each connection task's
state machine was sized for two copies of the same future. Measured with
`rustc -Zprint-type-sizes` on the release build:

```text
{async block@src/runtime/connection.rs}: 21224 bytes
    variant `Suspend0`: 21216 bytes
        upvar  `.future`:    10592 bytes
        local  `.__awaitee`: 10592 bytes   <-- the same future, second slot
```

Hypothesis: passing a factory (`M: FnOnce() -> F`) instead of a future would
leave it existing only as the awaitee, halving per-connection task state with no
heap allocation and no extra spawned task. On a 1 GiB / 1 vCPU node at
`maxConnections` 4096 that is roughly 42 MiB of task state.

The memory hypothesis was confirmed exactly: the connection task future dropped
from 21 224 B to 10 768 B (−49.3%), the largest async future in the crate from
21 376 B to 11 008 B, and async futures ≥ 16 KiB from 11 to 0. Cost: `.text`
grew 1 408 B (6 089 319 → 6 090 727) from the extra generic monomorphisation;
`.rodata` and `.data.rel.ro` unchanged.

## Decision

**Rejected.** Two independent formal rounds against the pinned v1.7.0 release
asset, judged by the typed evaluator, both failed on the same protected cell —
`framed-download` at 32 MiB, concurrency 1:

| round | ABBA start | throughput ratio | p99 ratio |
| --- | --- | --- | --- |
| r01 | baseline-first | 0.9791 [0.9632, 0.9952] | **1.0244 [1.0116, 1.0428] REGRESSION** (Holm p = 0.0234) |
| r02 | candidate-first | **0.9850 [0.9790, 0.9934] REGRESSION** (Holm p = 0.0312) | 1.0104 [0.9984, 1.0237] |

The delta satisfies every criterion for a real signal rather than noise: it
persists, it has the same sign in both rounds, it survives ABBA order reversal,
and in both rounds the throughput confidence interval lies entirely below 1.0.
Which of the two metrics crosses the significance threshold alternates between
rounds, which is what a genuine effect near the margin looks like — not what an
order artefact looks like.

Candidate mechanism, unproven: the change alters only the per-connection spawn
path, which cannot plausibly slow a single-connection 32 MiB framed download by
1.5–2% on its own. The 1 408 B of added `.text` shifting code layout — and with
it instruction-cache behaviour on the framed record path — is the more likely
cause. That was not confirmed: unprivileged hardware PMU access is denied by
kernel policy on the measurement host, so no i-cache measurement was taken and
none is claimed.

Trading measured framed-download throughput for per-connection memory is not a
trade this project accepts by default: retained optimisations must not harm a
protected path, and the memory pressure being relieved was not a demonstrated
production problem.

## Revisit conditions

Revisit when **any** of the following holds:

1. A per-connection memory ceiling becomes a demonstrated production constraint
   on the 1–2 vCPU / ~1 GiB profile — for example a measured RSS-driven
   admission failure — so the trade has a real benefit to weigh against the
   regression.
2. The same task-size reduction can be achieved without adding code — for
   example removing the wrapper coroutine entirely by making
   `ConnectionTasks::spawn` accept a future whose `Output` is already
   `ConnectionTaskResult`. That moves the peer-address association to the
   caller and weakens a type guarantee, so it needs its own review.
3. PMU access becomes available on a benchmark host, making the i-cache-layout
   hypothesis testable instead of speculative. If layout is confirmed as the
   mechanism, the regression may be removable by other means, or shown to be an
   artefact of that specific binary layout rather than of the change.

## Evidence

- `artifacts/v18-prf-gate/gates/evaluation-r01.json`, `evaluation-r02.json`
- `artifacts/v18-prf-gate/gates/matrix-formal-r01`, `matrix-formal-r02`,
  `setup-abba-r01`, `fallback-abba-r01`
- Candidate binary SHA-256
  `112021132274ea09fc4f891dc40aa0f49dfb54176cd5bd0e10830706b5fdc8e0` at commit
  `c4f0e636db2ab489c61fd302fe92297e205c5c7d`
- Baseline: published v1.7.0 `linux-x86_64-generic` asset, SHA-256
  `7765a65fe0368fec614ce3da44c6700e645fd172e8d19affc3af1f99c2e23c03`

The setup and fallback legs were neutral in both rounds
(`setup:server-cpu` 1.0002 [0.9938, 1.0075]), so the regression is specific to
the framed download cell rather than a general slowdown. The memory-audit
document (`docs/en/operations/memory-audit-v1.8.md`) records the duplication
that remains present in v1.8 as a result of this rejection.
