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


# STAGE: correctness closure (2026-08-07)

- head: see `git rev-parse HEAD` on fix/pr17-correctness-closure (this section written at 24068cc)
- hypotheses tested: MB1 (accepted), MB2 (accepted), DNS ownership (accepted),
  kernel liveness (accepted, netns-validated), diagnostic truthfulness (accepted)
- accepted commits: f8cd340, 5b3f778 (MB1), 9bbd534 (MB2), 510cd61 (DNS),
  1cac77e (keepalive), 24068cc (diagnostics)
- reverted: none in this stage
- gates so far: fmt, clippy -D warnings, cargo test --workspace/--all-features (427)
- tool failures/workarounds: netns-deletion gracefully closes peer sockets
  (invalid death model) -> silent death model uses `ip link set down` instead;
  host fully restored (notes/HOST-CHANGES.md)
- remaining uncertainty: none for the closure gate items; closure battery
  (CI, sanitizers, soak) runs next
- next permitted stage: closure battery, then PipePool stop/go on a new branch


# STAGE: closure battery outcome (2026-08-07)

- head at battery: a59581d (rustdoc fix) on cf5cfcb (all correctness code)
- local battery: ALL PASS (fmt/clippy/427+427/doc/nextest-427/deny/audit-0/
  rustdoc/benches/fuzz-compile/check.sh/interop/low-RLIMIT/privileged-8+9/
  soak-30min-clean)
- GitHub: blocked externally — 3x queue-starvation cancellations, zero steps,
  uniform 15m01s (see UNVERIFIED-GATES.md #14). Dispatched sanitizers on
  cf5cfcb: ASan/LSan PASS, fuzz PASS, dependency PASS; TSan cancelled (queue).
- closure gate declared COMPLETE on all locally verifiable items; PipePool
  stop/go experiment is UNBLOCKED on branch perf/1.0-pipe-pool.
- analysis reports landed: reports/NGINX-TRANSFERABLE-PATTERNS.md,
  reports/XRAY-SPLICE-PIPE-POOLING.md (hypothesis CONFIRMED: Go pools 1MiB
  pipes ~0 per-session syscalls; rust-reality pays 2 pipe2 + 2 fcntl + 4 close
  per session; correction: Xray fallback does NOT splice — it readv/writevs,
  so the fallback gap is not explained by pooling).


# STAGE: PipePool stop/go experiment (2026-08-07, branch perf/1.0-pipe-pool)

- head: 90eb08c
- hypothesis: per-session pipe churn explains the fallback gap (Opus, CREDIBLE)
- mechanism audit first (reports/XRAY-SPLICE-PIPE-POOLING.md): Go pools 1MiB
  pipes ~0/session; rust-reality created+resized+destroyed pipes per relay.
- implemented: PipePool (lazy growth + idle shrink, units travel with pipe,
  dirty pipes discarded, counters exposed, default pipePool=true).
- stop/go gate (matrix-pipepool, 258 samples, 0 invalid, integrity matched):
  fallback c32 0.767x, c64 0.76x, 512:32 0.675x Xray — TARGET >=1.00 FAILED.
  regression cells: all C/P within volatile bands, no >3% regression.
- mechanism evidence (strace A/B, 96 sessions): pipe2 192→64, close/fcntl
  ~eliminated; splice(2) is 97% of syscall time (~101k calls both builds).
- verdict: falsified as the fallback cause; KEPT with documented tradeoff
  (zero-cost syscall/FD-churn reduction; NO fallback claim). Fallback gap
  re-diagnosed as D8: splice call cost vs readv/writev at c32.
- tool failures: none. CI still blocked by GitHub queue starvation (retried 3x).
- next permitted stage: B1 hygiene (fd-budget release waiter guard), then
  reports/archive/stacked PR.


# STAGE: D8 falsification (2026-08-07, branch perf/1.0-pipe-pool)

- surface bench extended (2b6fca0): sizes {1,32,512}MiB x c{1,4,32,64} x
  {buffered,splice,auto} with cpuUser/System + ctx switches per sample;
  workers/buffer-size parameterized.
- D8 verdict: FALSIFIED. splice wins the raw surface outright; buffered-64K
  does not beat splice; the fallback gap was a debug-logging artifact of the
  matrix harness — clean-harness fallback splice = 1.04-1.05x Xray with
  26-35% lower task-clock (benchmarks/final/fallback-ab*, relay-surface*).
- PipePool: neutral end-to-end (+0.5% throughput, -3.8% CPU at c32 fallback);
  retention remains provisional-but-justified (zero-cost, proven mechanism).
- artifacts: benchmarks/final/relay-surface.jsonl, relay-surface-64k.jsonl,
  fallback-ab/, fallback-ab512/, fallback-pool-ab/.
- next: R1+ (framed AEAD decomposition, setup-rate harness) or close out with
  reports/archive/PR updates.

# STAGE: R1/R5-R6 Amdahl investigation (2026-08-07, branch perf/1.0-pipe-pool)

- symmetry audit: diagnostics/master/symmetry-audit.md — all future A/B cells
  must record log level/affinity/build/origin; the historical fallback gap was
  a debug-logging artifact and no asymmetric harness result is reused.
- setup-rate model (scripts/benchmark-setup-rate.sh,
  benchmarks/final/setup-rate3/): c1 269 vs 198 conn/s (1.36x), c8 775 vs 782,
  c32 874 vs 857; server cost at c32: 0.64 vs 1.16 ms CPU/conn (-45%),
  3.97M vs 5.70M instr/conn, 5.5 vs 22 ctx/conn. Report:
  CONNECTION-SETUP-PERFORMANCE.md.
- steady-state framed decomposition (perf on diagnostic binary b95f0844…,
  git d28c5f0; text in benchmarks/final/framed-prof/, raw perf.data in
  ../artifacts/framed-prof-d28c5f0/): download AEAD ~51% / kernel ~47%;
  upload AEAD ~39% / kernel ~57%; Vision+record-parse+scheduler+memcpy <2%
  combined. Reports: FRAMED-AMDAHL-REPORT.md, FRAMED-HOT-PATH-MAP.md,
  COPY-MAP.md (zero avoidable userspace copies on the framed path).
- isolated crypto bench (../artifacts/crypto-bench/, AES-128-GCM):
  OpenSSL EVP 4.12 vs RustCrypto 2.02 GiB/s at 16KiB records (2.04x,
  conservative). D9 registered as SUPPORTED-not-integrated; Amdahl ceiling
  1.35x download / 1.25x upload. Production integration requires a product
  decision on the OpenSSL link dependency — flagged to user, not started.
- next: user decision on the OpenSSL dependency; otherwise framed work
  concludes at parity-is-target and the branch moves to remaining R-phases
  (D7 sockhash reachability, memory density, final evidence).
