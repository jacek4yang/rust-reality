# Performance

English | [简体中文](performance.zh-CN.md)

This document records the measured performance properties of the v1.0.0 data
plane and the evidence behind each design decision. Unless stated otherwise,
numbers were measured on the validation host: Intel Core i3-8100 (4C/4T @
3.60 GHz), 16 GiB RAM, Debian 13, **Linux 6.12.94+deb13-amd64**, rustc
1.96.0, loopback against a compiled Go origin with an unmodified Xray 26.7.28
client. Loopback shares the host CPUs between server, client, and origin;
these numbers describe implementation cost, never Internet throughput. The
frozen v1.0.0 release comparison matrix is published in
[benchmarks.md](benchmarks.md).

## Framed-path cost decomposition

A steady-state framed profile (established connections only; setup excluded)
of the pre-ring build decomposes server CPU as:

| category | download share | upload share |
|---|---:|---:|
| AEAD (AES-128-GCM seal/open, RustCrypto baseline) | ≈51% | ≈39% |
| kernel boundary (read/write/copy_user, page clearing, TCP stack) | ≈47% | ≈57% |
| tokio scheduler/timers, Vision framing, record parsing, libc memcpy | <2% combined | <2% combined |

The kernel-boundary figures — including the `clear_page` first-touch
zeroing share (≈3.9% of download CPU) — are specific to the validated host
and kernel above (Linux 6.12 with `init_on_alloc` enabled, so freed-page
zeroing appears inline). They describe that kernel's behavior for this
workload and must not be generalized to other kernels, hosts, or
`init_on_alloc` configurations.

Two consequences, both pinned by measurement:

- **Copy elimination is not a framed opportunity.** The copy-topology audit
  (source + profile) shows zero avoidable userspace copies per payload byte
  in every steady-state path; only the two irreducible syscall-boundary
  copies remain on the framed paths, and the splice paths touch no userspace
  bytes at all. libc memcpy measures ≈0.15% of framed CPU.
- **AEAD is the only large userspace lever.** Amdahl ceilings on the
  measured fractions: a 2.5× faster AEAD caps end-to-end framed gain at
  ≈1.44× download / ≈1.31× upload (server-CPU-bound model); infinite AEAD
  speed caps at 2.04×/1.63×. The kernel boundary is the floor that caps any
  AEAD win.

## Record AEAD provider: ring by default

TLS 1.3 `TLS_AES_128_GCM_SHA256` record protection is provided by **ring**
(BoringSSL-derived C/assembly, statically linked) in the default build.
Building with `--no-default-features` selects the pure-Rust RustCrypto
aes-gcm provider with no other behavioral change; byte-exact cross-provider
equivalence and the RFC 8448 vectors are enforced by tests under both
configurations. The security tradeoff (expanded-key-schedule zeroization) is
documented in [SECURITY.md](../SECURITY.md).

Measured evidence (validation host above):

- Isolated AES-128-GCM at production 16 KiB records: ring seals at 5.16
  GiB/s vs RustCrypto 2.03 GiB/s — **≈2.5×**, winning at every record size
  from 64 B to 32 KiB.
- End-to-end framed loopback (219 valid samples, 0 invalid, integrity
  matched): ring ≥ RustCrypto in all 16 cells; **1.05–1.16×** on the
  512 MiB cells. Below the Amdahl ceiling because loopback throughput is
  host-CPU-shared; the per-GiB server cost below is the transferable
  measurement.
- Server cost per GiB of framed download: task-clock **−33%** (631 vs 940
  ms/GiB), instructions −30%, context switches −39%; RSS +3% (noise).
- Against Xray 26.7.28 on the same matrix, ring moves framed 512 MiB cells
  to 1.04–1.12× (RustCrypto was mixed at 0.95–1.12×): Xray's record AEAD is
  Go's stitched AES-NI+PCLMULQDQ assembly at ≈4.8 GiB/s @16 KiB, so the
  provider swap closes an implementation-quality gap, not a
  feature-detection miss.
- Supply chain: zero new dependency crates (ring already ships in the
  release graph via ureq/rustls), fully static link, slightly smaller
  binary.

## Raw relay and fallback

- On the raw relay surface (directions × payload × concurrency), splice
  beats the buffered backend on throughput **and** CPU/GiB at every measured
  concurrency; 64 KiB buffered buffers gained 2–12% over 32 KiB but stayed
  below splice everywhere. splice is therefore preferred everywhere;
  buffered remains the decline fallback.
- A mechanism audit of Xray 26.7.28/Go explains the comparison shape:
  Xray's REALITY **fallback** path uses readv/writev 64 KiB userspace
  copies — no splice at all — while its Vision downlink splices through the
  Go runtime's `sync.Pool` of 1 MiB pipes (≈0 pipe syscalls per session
  once warm). rust-reality's `PipePool` removes the equivalent per-session
  pipe2/fcntl/close churn for its 256 KiB pipes.
- Clean same-origin fallback A/B (warn-level logging both sides):
  splice fallback 1.04–1.05× Xray at concurrency 32 with 26–35% lower
  task-clock. An earlier apparent fallback deficit was traced to the matrix
  harness's debug-level per-connection logging, not to the relay path (see
  the methodology section of [benchmarks.md](benchmarks.md)).

## Connection setup

Setup-rate model (accept → REALITY handshake → VLESS parse → routing →
outbound connect → first Vision transition; steady state excluded;
validation host above, local TLS origin, raw-socket client):

| cell | rust-reality | Xray | ratio |
|---|---:|---:|---:|
| c1 conn/s | 269 | 198 | 1.36× |
| c8 conn/s | 775 | 782 | 0.99× |
| c32 conn/s | 874 | 857 | 1.02× |
| c32 p99 setup latency | 70.8 ms | 84.1 ms | −16% |

Per-connection server cost at c32: CPU 0.64 vs 1.16 ms (**−45%**),
instructions −30%, context switches −75%. Throughput is at parity at
concurrency because the 4-CPU host bounds both servers; the per-connection
cost columns are the cleaner signal. Whether the CPU advantage converts into
a rate advantage on a larger host is unverified.

## Decision register (D1–D9)

One-line verdicts for the performance decisions that shaped v1.0.0:

- **D1 — kept.** Reload/asset-refresh multiplied process ceilings; shared
  authorities hoisted to process-lifetime ownership.
- **D2 — kept.** Abort made indistinguishable from clean FIN
  (`SO_LINGER{on,0}` on abort paths plus an abort guard).
- **D3 — kept.** DNS work bounded: lookup pool, permit held for the blocking
  operation, fail-fast, no queue.
- **D4 — kept.** Kernel liveness backstop: `SO_KEEPALIVE` 30/10/3 on all
  data sockets; `TCP_USER_TIMEOUT` evaluated and rejected with reason.
- **D5 — kept.** Memory-sample source made explicit; pipe-capacity downgrade
  surfaced in relay outcome and connection logs.
- **D6 — falsified as cause, kept with tradeoff.** PipePool eliminated
  per-session pipe syscall/FD churn (mechanism confirmed by strace A/B) but
  did not move end-to-end fallback throughput — splice call cost was not
  the gap. Kept as a zero-cost mechanism with no throughput claim.
- **D7 — resolved by deletion.** The sockhash backend never armed in
  production matrices, showed privileged parity with splice, and required
  privilege the deployment model never has; removed (~5,400 lines).
- **D8 — falsified.** The apparent fallback c32 gap was harness debug
  logging, not splice call cost; clean A/B shows fallback splice at
  1.04–1.05× Xray with materially lower CPU.
- **D9 — proven, shipped as default.** The framed path is AEAD-bound and
  ring is ≈2.5× RustCrypto at production record sizes; shipped as the
  default record AEAD provider with the RustCrypto fallback retained and
  continuously tested.

## Rejected directions (evidence-based)

- io_uring: removed after a lifecycle audit — not zero-copy as designed, no
  cancellation, no session layer; completing it would have been a rewrite
  for dubious gain over splice. See
  [decisions/0002-io-uring-removed.md](decisions/0002-io-uring-removed.md).
- Scheduler/runtime redesign: the Tokio multi-thread runtime measures ≈1%
  of framed CPU; no contention evidence.
- Vision framing / record parsing work: <1% combined.
- Short-flow adaptive classifiers: forbidden without new evidence; none was
  found.
