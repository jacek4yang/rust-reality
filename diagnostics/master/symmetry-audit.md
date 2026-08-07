# Benchmark symmetry audit (R1 precondition)

Every harness's symmetry parameters, verified against the scripts at HEAD
2b6fca0+/d28c5f0 (perf/1.0-pipe-pool). The D8 lesson: an asymmetric log level
fabricated a 25% fallback deficit.

## scripts/benchmark-matrix.sh (main A/B/C matrix)

| parameter | rust servers | xray server | notes |
|---|---|---|---|
| log level | debug (needed for per-connection backend stats) | warning | ASYMMETRIC but now KNOWN: rust debug logs serialize per connection on the stderr lock; D8 proved this dominates short-session cells |
| stdout/stderr | redirected to files | redirected to files | symmetric |
| telemetry | none | none | — |
| CPU affinity | none (all 4 cores) | none | symmetric |
| CPU governor | scaling 100%, i3-8100 (no turbo variability issues observed; variance handled by interleaving) | same | — |
| build profile | release LTO (repo profile) | go build default | both production profiles |
| frame pointers/debug | production binary (stripped) | — | diagnostic builds are never used for A/B numbers |
| origin | shared compiled Go origin (plain + TLS1.3) | same | symmetric, saturation-guarded |
| payload | deterministic 0..255 files | same | — |
| concurrency | per cell | same | — |
| connection reuse | none (curl per request) | same | — |
| warmup | one pass per implementation per path before samples | same | — |
| order | seeded random interleave per cell | same | — |
| proxy env | stripped from curl (NO_PROXY bypass guard + accepted-connection counting) | same | bypass guard active |

KNOWN ASYMMETRY (by design, disclosed per report): rust servers log at debug
so backendStats exist; Xray logs at warning. Cells sensitive to per-connection
logging cost (short-session churn: fallback c32, small-payload high-c) are
re-measured with the clean harness before any claim.

## scripts/benchmark-fallback-ab.sh (clean fallback A/B)

| parameter | rust | xray |
|---|---|---|
| log level | warn | warning | SYMMETRIC |
| stderr | file | file | ✓ |
| origin | one shared compiled Go origin | same | ✓ |
| connection | direct curl to listener (fallback) | same | ✓ |
| proxy env | stripped | stripped | ✓ |
| CPU/ctx switches | perf stat on each server process | same | ✓ |

## scripts/benchmark-vision-direct.sh / benchmark-xray.sh

rust at debug (per-direction stats needed) vs xray warning — SAME known
asymmetry as the matrix; c1/c4 long-transfer cells are insensitive to it
(per-connection logging is amortized over 64MiB), short-session cells are not
claimed from these harnesses.

## benches/relay_backends.rs (raw relay surface)

Single-process A/B (buffered/splice/automatic in one binary): perfectly
symmetric by construction; 2 workers by default (parameterizable via
RR_BENCH_WORKERS); production runtime uses available_parallelism (4 on this
host) — the bench is a relative surface, not a production-throughput proxy.

## Sock retained-but-not-reused results

All pre-fix results whose symmetry cannot be established are already marked
non-discriminating or discarded in PERFORMANCE-REPORT.md (bypassed runs,
Python-origin c32 cells, bimodal fallback:32:1, single-stream origin-bound
cells).
