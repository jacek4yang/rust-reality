# CONNECTION-SETUP-PERFORMANCE — connection setup-rate model

Base commit: `d28c5f0` (perf/1.0-pipe-pool). Harness:
`scripts/benchmark-setup-rate.sh`; data: `benchmarks/final/setup-rate3/`.
MEASURED-LOCAL on the loopback host (i3-8100 4C/4T, kernel 6.12).

## Scope

This model covers **setup only** — accept → REALITY handshake → VLESS
parse → routing → outbound connect → first Vision transition — and is
deliberately separated from steady-state framed throughput
(FRAMED-AMDAHL-REPORT.md). No steady-state numbers are inferred from
this harness.

## Method notes (symmetry)

- Client: raw Python SOCKS5 (no curl — curl subprocesses are
  spawn-bound and cap the cell below either implementation).
- Cover/origin: **local** TLS origin (a remote cover adds ~75 ms RTT and
  swamps the measurement).
- Proxy env (`ALL_PROXY`/`NO_PROXY`/…) stripped from client and origin
  environments; loopback traffic provably traverses the proxy.
- Both servers at warn-level logging (per
  `diagnostics/master/symmetry-audit.md`: debug per-connection logging
  fabricated the historical "fallback gap"; it is not repeated here).
- Xray: current master binary from the adjacent read-only clone, same
  host/affinity/concurrency.

## Results (3 samples per cell, medians)

| cell | rust-reality | Xray | ratio |
|---|---|---|---|
| c1 conn/s | 269 | 198 | **1.36×** |
| c8 conn/s | 775 | 782 | 0.99× |
| c32 conn/s | 874 | 857 | 1.02× |
| c32 p99 setup latency | 70.8 ms | 84.1 ms | rust −16% |

Per-connection server cost at c32 (perf stat, one representative run):

| metric | rust-reality | Xray | ratio |
|---|---|---|---|
| CPU/connection | 0.64 ms | 1.16 ms | **rust −45%** |
| instructions/connection | 3.97 M | 5.70 M | rust −30% |
| context switches/connection | 5.5 | 22.4 | rust −75% |

## Interpretation

- Setup throughput is at parity at concurrency (c8/c32) and materially
  ahead single-threaded (c1 1.36×). The host's 4 CPUs bound both
  servers at c32; the per-connection cost columns are the cleaner
  signal: rust-reality does the same setup work at roughly half the
  CPU, a third fewer instructions, and a quarter of the context
  switches.
- The setup rate target from the performance objectives (≥1.50× Xray)
  is **not** met on throughput at c32 — but the cell is host-CPU-bound
  for both sides, so throughput parity at −45% CPU/connection is the
  honest local statement. A bigger host is required to test whether the
  CPU advantage converts into a rate advantage (UNVERIFIED-EXTERNAL).
- No setup-path optimization is proposed from this stage: setup is not
  the framed bottleneck, and the per-connection cost already favors
  rust-reality.

## Reproduce

```bash
source ../proxy-env.sh   # only if the Xray build needs fetching
scripts/benchmark-setup-rate.sh   # writes benchmarks/final/setup-rate*/
```
