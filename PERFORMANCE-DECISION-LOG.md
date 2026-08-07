# Performance decision log (1.0)

Format per candidate: ID, parent/candidate SHA, hypothesis, mechanism, changed
files, gates, focused bench, end-to-end result, profile movement, resource
result, security review, keep/revert, confidence.

## Register

| ID | status | hypothesis | verdict |
|---|---|---|---|
| D1 | accepted | Reload/asset-refresh multiplies process ceilings (MB1) | KEPT: authorities hoisted to ProcessAuthorities (f8cd340+5b3f778); reload x10 tests |
| D2 | accepted | Abort indistinguishable from clean FIN (MB2) | KEPT: SO_LINGER{on,0} on abort paths + DirectionAbortGuard (9bbd534); RST-vs-EOF tests |
| D3 | accepted | DNS work insufficiently bounded/accounted (12.3) | KEPT: DnsLookup pool, permit held in blocking op, fail-fast, no queue (510cd61) |
| D4 | accepted | No coherent kernel liveness backstop (12.4) | KEPT: SO_KEEPALIVE 30/10/3 on all data sockets; netns experiment validated formula (1cac77e); TCP_USER_TIMEOUT rejected with reason |
| D5 | accepted | Diagnostics can mislabel source; pipe cliff invisible (12.5) | KEPT: MemorySampleSource + MemorySamplerChanged; pipe downgrade in ledger->outcome->connection log; orphan constant deleted (24068cc) |
| D6 | falsified-as-cause, kept-with-tradeoff | PipePool: per-session pipe create/resize/destroy costs fallback c32 (Opus hypothesis, CREDIBLE) | Mechanism CONFIRMED (Go/Xray pool 1MiB pipes, ~0/session; rust-reality paid 2 pipe2+2 fcntl+4 close/session). Implemented PipePool (90eb08c). strace A/B on identical fallback workload (96 sessions): pipe2 192→64, close/fcntl ~eliminated; splice(2) itself is 97% of syscall time (~101k calls, 15.5KiB/call avg) so end-to-end did not move: fallback c32 C/X=0.767, c64 0.76, 512:32 0.675 (gate target >=1.00 FAILED); C/P≈1.0 everywhere, no regression, integrity matched. Verdict: the hypothesis is FALSIFIED as the fallback gap's cause — the gap is splice-call cost vs Xray's 64KiB readv/writev (Xray fallback does not splice at all). KEPT with explicitly documented tradeoff: proven syscall/FD-churn reduction at zero measured cost, bounded retention, exact accounting; it makes NO fallback-throughput claim. |
| D7 | pending | Sockhash pair-path unreachable after c1ec2cf → delete privileged code | — |
| D8 | falsified | fallback c32 gap = splice call cost vs Xray readv/writev | FALSIFIED: clean-harness fallback splice = 1.04–1.05× Xray at −26/−35% CPU; gap was harness debug logging (see entry below) |
| D9 | supported-not-integrated | Framed path is AEAD-bound; OpenSSL EVP ≈2× RustCrypto at production record sizes | SUPPORTED (isolated): decomposition download AEAD 51%/kernel 47%, upload 39%/57% (perf, d28c5f0, benchmarks/final/framed-prof/); crypto-bench AES-128-GCM 16KiB OpenSSL 4.12 vs RustCrypto 2.02 GiB/s (2.04×; conservative — EVP ctx recreated per call). Amdahl ceiling 1.35× download / 1.25× upload. Copy-elimination REJECTED (0 avoidable copies, COPY-MAP.md); Vision/record-parse <1%; scheduler ≈1%. Integration requires product decision on an OpenSSL link dependency before any production change — flagged to user. |

## Reverted / rejected

(none yet)

## New hypotheses registered

- D8: fallback c32 gap = splice(2) call cost at availability-limited chunk sizes
  vs Xray's readv/writev fallback. VERDICT: FALSIFIED (2026-08-07).
  Evidence chain (all retained in benchmarks/final/):
  1. relay-surface.jsonl (270 samples): splice beats buffered on throughput
     AND CPU/GiB at EVERY concurrency (2.2-2.8 vs 1.7-2.1 GiB/s; 420-480 vs
     560-640 ms/GiB at c32/c64) — splice is not the per-byte problem.
  2. relay-surface-64k.jsonl: buffered-64KiB is +2-12% over 32KiB but still
     below splice everywhere — D8a falsified on the raw surface.
  3. fallback-ab (clean harness, warn-level logging, direct-to-listener):
     splice 3278 vs Xray 3134 MiB/s at c32/32MiB (1.05x), 4197 vs 4036 at
     c32/512MiB (1.04x), task-clock 865ms vs 1173ms (-26%) and 10.0s vs 15.3s
     (-35%) — fallback is AT PARITY OR AHEAD of Xray with materially lower
     CPU. The earlier 'gap' was dominated by the matrix harness's debug-level
     per-connection logging (JSON events serialize on the stderr lock per
     connection; Xray logged at warning).
  4. PipePool A/B at the same workload: pool 3290 vs no-pool 3273 MiB/s
     (+0.5%, noise; CPU -3.8%) — pool is end-to-end neutral at these rates,
     mechanism proven; retention stays PROVISIONAL per its cheap price.
  Residual note: per-connection debug logging is a real cost at high churn
  (stderr lock) — acceptable because it is debug-only and off in production.
  No backend change made; splice remains preferred everywhere; buffered stays
  the decline fallback at 32 KiB (64 KiB showed no e2e benefit).

  FALSIFICATION PLAN (per override, 2026-08-07):
  - Causal model: at high concurrency, per-call availability limits splice
    chunks; splice pays 2 syscalls + 2 kernel copies per chunk vs buffered
    2 syscalls + 2 userspace copies per 32KiB buffer; if splice chunk sizes
    stay small under contention, splice CPU/GiB exceeds buffered, which
    explains the fallback c32 gap (Xray uses NO splice there).
  - Falsifying observations: (a) splice CPU/GiB <= buffered at c32/c64 raw
    relay (gap is NOT syscall-driven); (b) splice and buffered CPU/GiB equal
    while fallback still trails Xray (gap lives elsewhere, e.g. scheduling);
    (c) splice throughput >= buffered at c32/c64 on the raw surface.
  - Experiment: benches/relay_backends.rs decision surface — directions x
    {1,32,512}MiB x c{1,4,32,64} x {buffered, splice, automatic}, 3+ samples,
    randomized order, per-sample throughput + cpuUser/System + context
    switches + peak RSS. Then fallback end-to-end A/B (splice on/off) and
    perf attribution if the surface shows a crossover.
  - Revert criterion: if splice loses BOTH throughput and CPU at c32/c64,
    the fallback path stops preferring splice for such sessions ONLY with a
    measured criterion (size/concurrency threshold from the surface), or
    splice chunk policy changes with evidence.
