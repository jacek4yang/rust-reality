# ADR 0072: Return freed glibc heap to the kernel after a connection burst

## Status

Accepted (owner approval, 2026-11-23). This is a recorded exception to the
`rr-linux` boundary set by
[ADR 0015](0015-rr-linux-is-a-no-std-linux-abi-boundary.md), which refines the
`rr-linux` layer of
[ADR 0008](0008-session-engine-runtime-and-transport-boundaries.md): one C
library call, on glibc only. No threshold, contract or evaluator is changed,
and no existing test is weakened.

## Context

The Frozen handoff/constrained cell measures LANDING recovered RSS growth
against an absolute 32,768 KiB limit (ADR 0051 keeps the constrained bar
tight). On main the metric is bimodal: about 23.7 MiB on some runs and about
33.3 MiB on others, with the same code and workload.

- Frozen 44863967961 (#507): 33,256 KiB, FAIL.
- Frozen 44906123680 (main e6389d2): 33,292 KiB, FAIL.
- Frozen runs in the low mode: 23,668 KiB (main ed6bfc4), 23,764 KiB (#509).

A local lab, recorded on #325, reproduced the cell's LANDING shape: the
e6389d2 glibc binary, a 1 GiB cgroup, 1 CPU, 8192 descriptors, 2 Handoff LINEs
with stock Xray clients, and the cell's transfer and checkpoint schedule.

- After recovery, glibc held about 48 MB of arena memory with under 0.5 MB in
  use. Calling `malloc_trim(0)` released 44–47 MiB of RSS.
- Pinning the mmap/trim thresholds or forcing one arena changed nothing. The
  retained memory is small freed chunks pinned below a few live allocations.
  glibc can shrink an arena only from its top.
- The cell's bimodality is consistent with that top-trim sometimes succeeding.
  This explanation is an inference; the lab is always in the high mode.

The retention is allocator placement, not a leak and not live state. Neither
`rustix` nor `linux-raw-sys` can return it, because `malloc_trim` is C library
policy, not a kernel mechanism.

## Decision

1. **`rr-linux` gains one C library call: `heap::release_free_heap()`.**
   - On `target_env = "gnu"` it calls `libc::malloc_trim(0)` in one documented
     `unsafe` block (`clippy::undocumented_unsafe_blocks` stays denied).
   - On every other target, including musl, it does nothing and returns
     `false`. musl builds are byte-for-byte unaffected in behavior.
   - This is the crate's only libc function call and its second `unsafe`
     block, after `socket::AbortMark::apply`. The protocol crate keeps
     `#![deny(unsafe_code)]` unchanged.
2. **Trigger rule.** The existing resource monitor (1 s maintenance cadence)
   reads the governor's admitted-connection count. It trims when the count has
   fallen to at most half of the highest count seen since the last trim **and**
   by at least 16 connections. The peak then restarts from the current count,
   so a slow drain trims at most once per halving, never once per tick. Idle
   warm connections and small fluctuations never trim.
3. **Nothing else changes.** No relay path, buffer size, allocator choice,
   tunable, threshold, contract or evaluator is touched.

## Cost

Measured in the same local lab, cell workload, 4 cycles (8/32/8/32), base
e6389d2 against the candidate with a lab-only timing log around the call:

| Run | Recovered growth (KiB) | LANDING CPU (utime+stime) | 1 MiB GET p50 / p99 / max | Trims, wall time each |
| --- | --- | --- | --- | --- |
| base A | 46,620 | 2.83 s | 23 / 398 / 429 ms | none |
| base B | 48,364 | 1.70 s | 12 / 78 / 113 ms | none |
| candidate A | 1,260 | 1.70 s | 33 / 101 / 117 ms | 4: 2.4, 3.2, 2.8, 3.6 ms |
| candidate B | 1,152 | 1.73 s | 13 / 47 / 54 ms | 4: 2.4, 4.0, 2.7, 2.6 ms |

Each run made 640 GETs and 160 paced 4 MiB PUTs across both LINEs, with 0
failures.

- One trim fired per cycle, 1.1–1.9 s after the last transfer finished. No
  transfer was in flight during any of the 8 trims.
- Each trim took 2.4–4.0 ms of wall time on the monitor task, about 12 ms per
  12-minute run. CPU time is measured at 10 ms resolution and varies by more
  than 1 s between identical base runs, so the trim's CPU cost is below what
  this lab can resolve. The latency differences are also within run-to-run
  noise.
- Not measured: a trim that fires while other connections are still relaying
  (for example, a drop from 72 to 30 connections). LANDING runs one worker
  thread, so such a trim could delay those connections by a few milliseconds
  once per halving.

## Consequences

- LANDING recovered RSS growth in the lab falls from about 47–49 MiB to about
  1.3 MiB, well inside the 32,768 KiB constrained bar, without changing the bar.
- `rr-linux`'s libc edge, previously compile-time constants only (`SOMAXCONN`),
  now also carries one runtime call on glibc. The `Cargo.toml` and crate docs
  state this.
- The fix must still pass Frozen on its exact head. If the cell stays
  bimodal or above the limit, this ADR does not authorize any further change.

## Alternatives considered

- **Swap the global allocator (jemalloc or mimalloc).** Rejected for now: a new
  large dependency and a process-wide behavior change across every path and
  benchmark, to fix one post-burst retention effect.
- **Raise or rescale the constrained RSS limit, or change the contract.**
  Rejected: it weakens a qualification bar to pass a test (#325 rules,
  ADR 0051 §4).
- **glibc tunables (`arena_max`, `mmap_threshold`, `trim_threshold`).**
  Rejected: measured in the lab with no effect.
- **Trim on every monitor tick or on a timer.** Rejected: pays the cost while
  load is ongoing and on idle servers for no benefit.
- **Call `malloc_trim` from the main crate.** Rejected: it would need `unsafe`
  in the protocol crate.

## Revisit conditions

- Remove the call if glibc gains automatic trimming of non-top free pages, or
  if the project adopts a different global allocator.
- Revisit the trigger if a Frozen or Native run shows the trim on a hot path or
  a measurable latency regression.

## Evidence

- #325 comment 7064250318: stop-rule finding and metric distribution.
- #325 comment 7064537877: Frozen 44906123680 (e6389d2) FAIL, 33,292 KiB.
- #325 comment 7065574846: local allocator-retention lab, with and without
  `malloc_trim(0)`.
- #325 comment 7066492462: correction (the existing `AbortMark` `unsafe` block).
- Frozen 44863967961 (#507, 33,256 KiB) and 44906123680 (main e6389d2).
- The implementing change: `cargo dev check --all` 19/19 PASS locally before
  the pull request; exact-head CI, Security, Candidate packages, Native and
  Frozen are required before merge.
