# Unverified and partially verified gates

This file is the honest record of every required gate that could not be run,
could not be run at full fidelity on this host, or produced a result weaker
than its specification. Nothing here is claimed as passed.

Last updated: see git log for the branch head.

## Real-world path gates

1. **"Final downlink median at least 95% (target 105%) of Xray on the observed
   real-world path."** — NOT VERIFIED AT THE OBSERVED BANDWIDTH. The host's NIC
   (`enp2s0`) negotiates 100 Mb/s, so the 651/311 Mbps reference observation
   cannot be reproduced from this machine; every real-path measurement here is
   capped at ~94 Mbps for both implementations equally. What IS verified:
   loopback tunneled Direct-path downlink (the same code path and the same
   Xray client), where the baseline deficit (0.79x Xray) was eliminated
   (>=0.97x, typically ~1.0x) with `downlink_backend=splice` on every sampled
   connection. Real-path A/B runs (alternating servers, real Internet
   destination) were executed for crash/protocol-error evidence; they cannot
   discriminate above ~94 Mbps.

2. **"20 repeated real-path runs produce no crash or protocol error."** —
   RUN AND PASSED: 20 alternating real-Internet runs (5 MiB each,
   Cloudflare speed endpoint, `diagnostics/final/real-path.json`), 0
   failures, no crash or protocol error. Direct egress from this host was
   slow (0.2–1.3 MiB/s per run) and symmetric across implementations, so the
   runs carry no bandwidth signal — only correctness.

3. **Speedtest screenshots.** — NOT TAKEN. Loopback + scripted real-path
   runs are retained as machine-readable logs instead; no interactive
   Speedtest client exists on this host.

## Performance gates

4. **"p99 no worse than Xray by more than 5%."** — measured on loopback only
   (matrix `summary.json` per-request seconds). Loopback p99 is dominated by
   process startup of curl and the Python origins; interpret with care.

5. **"CPU time per GiB no worse than Xray for raw Direct."** — measured via
   `perf stat` on the server processes during sustained Direct downloads;
   see `diagnostics/final/`. Loopback includes the shared Xray client and
   Python origin in the path (disclosed in every harness's limitations).

6. **Saturation-level concurrency.** — the matrix runs concurrency 32; a
   "host-appropriate saturation level" beyond 32 parallel curls was not
   swept automatically. FD/counter-return gates are covered by unit and
   privileged tests instead.

## Tooling gates

7. **Miri / sanitizers.** — NOT RUN. Miri does not support the raw
   `bpf(2)`/`getsockopt` syscalls in `crates/rr-linux` (the only unsafe code
   in the workspace), so it cannot exercise the changed unsafe surface.
   Instead: offset/layout ABI tests in rr-linux, the full privileged suites
   under sudo, and the instrumented-allocator gates.

8. **cargo audit.** — RUN AND PASSED: libgit2 could not use the SOCKS
   proxy, so the advisory DB was cloned with system git (proxy-honoring)
   and audit ran with `--db --no-fetch`: 1189 advisories loaded, 200 crate
   dependencies scanned, zero vulnerabilities (`diagnostics/final/gates/audit.log`).

## Coverage notes (verified, but read the scope)

9. **One-way Direct.** — one-way Direct is a transient state with the
   reference Xray client (uplink and downlink Direct commands are both
   emitted once inner TLS 1.3 application data flows). The mechanism is
   pinned by integration tests (`one_way_direct_*` in `src/server/vision.rs`)
   and the directional relay conformance tests; the sustained one-way
   scenario is exercised at the relay level (`benches/relay_backends.rs`
   directional cells), not end-to-end.

10. **NXR landing/outbound.** — covered by unit/integration tests and the
    unified relay conformance suite (NXR landing calls `relay_owned`
    directly). Not separately benchmarked end-to-end: Xray has no NXR
    equivalent, so there is no A/B baseline.

## Follow-up additions (PR #17 completion pass)

11. **Fallback at concurrency 32+ (32 MiB):** final measures 0.76-0.81x Xray
    with a trustworthy compiled origin. Profiled: splice-syscall-bound;
    256 KiB pipes cut splice calls ~8x but did not close the throughput gap
    (calls are availability-limited at c32). Not a regression vs baseline
    (final >= 1.14x baseline); explicitly UNRESOLVED — future work only with a
    new measured hypothesis.

12. **Single-stream TLS origin cells (payload 512 MiB x c1):** origin-bound
    (~400-500 MiB/s per Go TLS connection); ratios across implementations
    swing 0.8-1.1 between runs. Not reported as proxy performance.

13. **SOCKHASH throughput benefit:** measured on the production fallback path
    (parity with splice, slightly higher CPU on short sessions). A long-lived
    bilateral-flow benefit remains plausible but is UNVERIFIED — no
    long-lived eligible workload was measurable on this host. Default remains
    off.
