# RESOLVED REPOSITORY STATE

- Repo: jacek4yang/rust-reality @ /home/jacek/work/kimi-rust-reality-performance/rust-reality
- Branch: fix/pr17-correctness-closure, HEAD 70442b365de90903edb4959f8835667b9f8d6eaf (clean, == origin)
- main: 717e69bfd1e83dd114ff652b74167ad3046e7692
- PR #17 (perf/complete-proxy-datapath-and-dedicated-runtime): OPEN Draft, head 274cca9d728d2f96d073ccc0d1ed84158740d7bf — do not modify
- PR #18 (fix/pr17-correctness-closure → PR #17 branch): OPEN Draft, head 70442b3, checks GREEN (quality/dependency/fuzz pass; sanitizers skip on PR events)
- Dispatched Security run 31080903908 on 70442b3: ASan/LSan PASS, TSan PASS, fuzz PASS, dependency PASS
- rr-parent worktree: 274cca9 (immutable comparison point)

# RESOLVED TOOLCHAIN STATE

- Host: Debian 13, kernel 6.12.94+deb13-amd64, i3-8100 4C/4T, 16 GiB, RLIMIT_NOFILE 524288/524288, perf_event_paranoid=3, passwordless sudo (normal-user builds only)
- rustc/cargo 1.96.0; perf 6.12.100; LLVM 19.1.7 (llvm-mca, llvm-objdump present); Go 1.24.4; Python 3.14.6
- IDA Pro 9.3 @ /home/jacek/Applications/ida-pro; IDAlib venv .venv-ida — headless smoke PASS (5727 functions on the diagnostic binary)
- gh authenticated as jacek4yang; proxy env for GitHub/package ops: proxy-env.sh (recorded; sanitized from benchmarks/logs)

# TRUSTED EXISTING EVIDENCE

- Diagnostic binary artifacts/assembly-profile/target/release/rust-reality sha256 afa29e3610…, git 70442b3 (DWARF, frame pointers, unstripped) — valid
- artifacts/perf-benchmark/perf.data sha256 98b20b58b0… — buildid-list matches the diagnostic binary ✓ pairing valid
- Hotspot bundle for VisionDecoder::decode (0x349a50–0x349fbf) with full mapping pipeline (2334/2334 samples mapped) — pipeline proven, but it profiles the equal-wall-time built-in benchmark, NOT production traffic
- benchmarks/final/*: multi-run A/B matrices (baseline/final/Xray, compiled Go origin, ~2.5k retained samples) — valid loopback evidence at their commits
- closure correctness fixes c61162e/fe8cee6/c1ec2cf/f23b1ae — preserved
- Sockhash privileged suites pass locally under sudo; sockhash is opt-in and off by default

# STALE OR UNTRUSTED EVIDENCE

- Opus 5 second-pass audit archive (sha 9e592272…): NOT PRESENT on disk (no verify.sh found) — its conclusions are treated as CREDIBLE-HYPOTHESIS only; each must be re-derived or measured
- fallback:32:1 cells: bimodal on this host (~700 vs ~1300 MiB/s in all implementations) — non-discriminating
- single-stream TLS origin cells (~400–500 MiB/s): origin-bound — non-discriminating
- Any perf numbers from root-run processes: not representative of production User= deployment
- 100 Mb/s NIC: no WAN/NIC-fidelity measurement possible on this host

# CURRENT HARD BLOCKERS

- MB1: reload/asset-refresh recreates ResourceGovernor + direct authorities per generation → ceiling multiplication across reloads (old sessions hold old permits)
- MB2: cancellation can truncate a transfer while the peer sees a clean FIN — abort must be distinguishable (SO_LINGER {on,0} on true abort paths)
- Closure gate items: DNS ownership bounding/accounting, kernel liveness policy, diagnostic truthfulness (cgroup/RSS labels, pipe-capacity downgrade visibility)
- PipePool stop/go experiment pending (fallback c32 ~0.78–0.81x Xray)
- Sockhash pair-path reachability after c1ec2cf unmeasured (kept/deleted decision owed)

# FIRST EXECUTABLE EXPERIMENT

1. Merge blockers MB1 + MB2 on fix/pr17-correctness-closure with focused tests (reload x10 ceiling invariance; abort→RST observable per backend).
2. Then closure items 12.3–12.5, gates, and PR #18 update.
3. New branch perf/1.0-pipe-pool: process-lifetime pipe pool behind an internal switch, with the preregistered stop/go: fallback c32/c64 ≥ 1.00x Xray, no >3% regression on raw Direct/framed, no descriptor/pipe-page safety regression, root vs unprivileged reported separately.

# FILES/BRANCHES THAT WILL BE MODIFIED

- Branch fix/pr17-correctness-closure: src/server/production.rs, src/runtime/*, src/server/outbound.rs, src/server/vision.rs, src/transport/*, src/config/* (authorities hoisting, abort semantics, DNS, liveness, diagnostics)
- Branch perf/1.0-pipe-pool (new, stacked on the closure branch): src/transport/tcp_relay.rs, crates/rr-linux (pipe sizing/accounting), src/config/model.rs + validate.rs, docs
- Root: IMPLEMENTATION-STATE.md, PERFORMANCE-DECISION-LOG.md, UNVERIFIED-GATES.md
- diagnostics/master/**, artifacts/**, reports/**, machine-readable/**
