# ADR 0051: Scale VM RSS envelopes by role GiB

Status: Accepted

## Context

Frozen run `38057641054` on `4282d68` completed all four QEMU cells, then
failed offline merge evaluation with eleven
`absolute memory/thread envelope exceeded` findings on **handoff/ordinary**
only. Payloads were present (ADR payload copy already fixed). Cells-summary
still reported pass because `--cell` jobs do not run the full offline Pass
evaluate until merge ([ADR 0042](0042-four-cell-qemu-matrix-parallelism.md)).

Retained evidence (landing role):

| Cell | memory_limit | baseline RSS | recovered cycle RSS | growth | `recovered_rss_growth_kib` |
| --- | --- | --- | --- | --- | --- |
| handoff/ordinary | 2 GiB / 2 vCPU | 6796 KiB | ~44–45 MiB | ~37–38 MiB | 32768 (fail) |
| handoff/constrained | 1 GiB / 1 vCPU | 6952 KiB | ~36–37 MiB | ~29–30 MiB | 32768 (pass) |
| nxr/ordinary | 2 GiB / 2 vCPU | 6764 KiB | ~14 MiB | ~7 MiB | 32768 (pass) |

Growth plateaus after cycle 1 (not monotonic leak). Ordinary LANDING is
intentionally larger ([campaign assemble](../../tools/rr-dev/src/bench/stability/campaign.rs)
and evaluator identity checks). The contract stores one recovered/peak KiB
budget calibrated on the 1 GiB unit; applying it unchanged to the 2 GiB ordinary
LANDING fails a steady footprint that constrained handoff already sits just
under. Class B harness/contract asymmetry, not Class A product leak.

Historical `4282d68` / `38057641054` verdict remains immutable.

## Decision

1. Keep `recovered_rss_growth_kib` / `peak_rss_growth_kib` as the **1 GiB unit**.
2. Offline evaluate scales both RSS growth ceilings by
   `role.memory_limit_bytes.max(1 GiB) / 1 GiB` (ordinary LANDING → ×2).
3. Thread growth limits stay absolute (thread counts do not track GiB).
4. Do not raise the unit budget globally; constrained cells keep the tight bar.
5. Unbounded growth still fails: ordinary LANDING recovered growth must stay
   ≤ 64 MiB over cold-start baseline.

## Consequences and limits

First complete four-cell merge evaluate after payload retention can Pass on
handoff/ordinary without manufacturing a weaker constrained bar. This does not
rebase baselines after `landing-restart`, does not idle-sleep for RSS reclaim,
and does not claim allocator-byte accounting. Native envelopes are unchanged.
