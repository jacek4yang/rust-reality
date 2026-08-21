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
[benchmarks.md](benchmarks.md). v1.6.0, v1.5.1, and v1.5.0 evidence is in the
sections immediately below and keeps the v1.0.0 tables unchanged as
historical release measurements.

## v1.6.0 release evidence

The v1.6.0 release was measured against the published v1.5.1 binary with the
formal evaluator passing all 40 protected metrics and zero regressions. The
retained changes were 512 KiB splice pipes (fallback CPU/GiB ratio 0.953,
bootstrap95 [0.925, 0.974]) and framed-uplink batching (+5.5% at c32 with
3.5× fewer origin writes). The public comparator remains Xray-core 26.7.28
(`5ca6f4b`, go1.26.0, binary SHA-256 `23d228d7…04c5268`). Full setup,
throughput, DNS, routing, RSS, limitations, identities, and evidence paths are
in [benchmarks.md](benchmarks.md#v160-release-comparison-evidence).

## v1.5.1 release evidence

v1.5.1 contains no data-plane redesign; it is a targeted cost-removal and
correctness release measured against the published v1.5.0 release binary
(`eda773b`) on the same host, with every run serialized under the
host-exclusive lock. The formal evaluator passed all 40 protected metrics
with zero regressions (`artifacts/v1.5.1/gates/evaluator-report.json`).

- **Incremental handshake-transcript hashing.** The REALITY server flight
  now hashes the TLS 1.3 handshake transcript incrementally instead of
  re-hashing the whole growing transcript four times; transcript values
  and wire output are unchanged. Measured on the release gate host:
  SHA-256 compress self-time fell from 22.0% to 13.8% of setup CPU, and
  server CPU per setup connection fell 6.7% (setup ABBA median ratio
  0.933, bootstrap95 [0.930, 0.934]; 602 µs vs 646 µs aggregate
  task-clock; classified as a statistically significant improvement by the
  release evaluator).
- **Lazy per-connection debug events and `log.output: "none"`.**
  Per-connection debug events (`connection_accepted`,
  `connection_completed`, `connection_closed`) are constructed only when
  debug output can actually reach the configured sink; at `info` or
  higher, or with `log.output: "none"`, the per-connection log path does
  no work at all. Warn-level rejection and admission events stay eager as
  operator signal. This is why the v1.5.1 Xray comparison runs both
  servers at warn level with no logging asymmetry.
- **DNS cache identity includes the query class.** A static configured
  peer and a dynamic per-session destination with the same name previously
  shared one cache slot, so a static lookup could be served by a dynamic
  entry (or vice versa) and the static TTL could extend a dynamic answer.
  Static and dynamic entries for one name now have independent lifetimes,
  both counting against `dns.cache.maxEntries`; static negative results
  remain uncached.
- **DNS cache sharding rejected on evidence.** The single bounded cache
  mutex was re-measured with 1–1024 concurrent same-name and distinct-name
  lookups: same-name ≈ distinct-name wall time, and CPU scales with cores
  rather than with spinning. The lock is not the bottleneck, so it is
  deliberately kept unsharded.
- **Xray comparison.** The v1.5.1 vs Xray 26.7.28 setup-rate, throughput,
  DNS, routing-scale, and RSS measurements are collected in
  [benchmarks.md](benchmarks.md#v151-release-comparison-evidence).

## v1.5 cover-flight and release evidence

The v1.5 candidate was compared with the immutable v1.4 release binary on the
same four-core validation host. The setup harness used symmetric warn logging,
three warmed balanced ABBA blocks, exact binary hashes, and independent cells
at c1/c8/c32. Candidate/baseline setup-rate medians and 95% block-bootstrap
intervals were:

| concurrency | median change | 95% interval |
|---:|---:|---:|
| 1 | -0.38% | -0.465% to +0.170% |
| 8 | +0.26% | -3.368% to +2.497% |
| 32 | +0.53% | -1.257% to +1.557% |

All three intervals cross no difference. Normalized counters changed by
-0.768% task-clock, -0.190% instructions, and +1.042% context switches; the
last is approximately +0.058 context switches per setup connection. A
separate current `strace` round found 4.0013 fewer `recvfrom` calls per
candidate connection. The trace is mechanism evidence only: its timings are
not compared with the uninstrumented ABBA.

Two full balanced matrix rounds covered bidirectional, Direct download/upload,
fallback, and framed download/upload. Each retained 219 samples with zero
invalid samples; payload hashes passed, and every workload's candidate/baseline
throughput and latency 95% block-bootstrap interval crossed no difference.
Direct upload's median ratio reversed from 0.9511 in the first round to 1.1390
in the second, confirming order/host noise. Thus the evidence detects neither
a statistically significant protected-path regression nor a throughput win.
The same source is released as portable and x86-64-v3 artifacts, but CPU-tier
identity alone is not treated as performance evidence.

The formal x86-64-v3-versus-portable run
`20260812T130000Z-matrix-v3-04285e63-r01` used the same source commit and
features, immutable tier-specific binaries, six balanced ABBA blocks, and warn
logging. It retained 219 samples with zero invalid samples; portable, v3, and
the Xray guard each passed a separate exact 64 MiB SHA-256 transfer. Ratios
below are **v3 / portable** (higher throughput is better; lower worst-request
latency is better):

| path | throughput median (95% bootstrap) | worst latency median (95% bootstrap) |
|---|---:|---:|
| bidirectional | 1.0306 (0.9240–1.1118) | 0.9935 (0.8477–1.0862) |
| Direct download | 1.0145 (0.9820–1.0498) | 0.9906 (0.9417–1.0372) |
| Direct upload | 0.9682 (0.8462–1.1066) | 0.9970 (0.8829–1.1871) |
| fallback | 0.9981 (0.9280–1.0613) | 0.9795 (0.8752–1.0169) |
| framed download | 1.0091 (0.9826–1.0278) | 1.0150 (0.9996–1.0162) |
| framed upload | 1.0058 (0.9865–1.0229) | 0.9751 (0.9556–1.0074) |

Every throughput and worst-request-latency interval contains 1. The run
therefore establishes no statistically reliable v3 advantage on this host.
The opt-in tier remains a separately identified build for capable CPUs; it is
not a reason to relax any portable regression gate, and a future v3 result can
never mask a portable regression.

Interoperability gates passed against Xray 26.7.28 with Microsoft, Google, and
Fastly public covers and against a local OpenSSL 3.5.6 cover without CCS. Each
case verified an exact 1 MiB SHA-256 transfer and ML-DSA-65 key compatibility.
These gates establish wire correctness, not throughput.

## v1.5.0 DNS, routing, and IPv6 evidence

Same validation host and methodology caveats as above (Intel i3-8100, Linux
6.12, loopback/same-host; implementation cost, never Internet throughput).

- **Shared DNS resolver.** With an upstream server list, 128 concurrent
  identical lookups coalesced into 2 upstream queries instead of 315, and the
  warm-path p50 fell from 12.9 ms to sub-microsecond; the cold path cost
  +2.1%. System mode (`dns.servers: ["system"]`) applies the same
  singleflight coalescing and `DnsLookup` admission governance but caches no
  dynamic answers, because getaddrinfo exposes no TTLs.
- **Routing candidate indices.** Rule lists of 64 or more entries compile an
  adaptive index (measured footprint ≈53 bytes per rule) with exact
  first-match semantics. Measured P95 decision latency fell 31–57% at 1,000
  rules and 31–55% at 10,000 rules; small rule sets are unchanged on the
  linear path.
- **Real IPv6 validation.** `scripts/validate-ipv6-e2e.sh` ran end to end
  over real global IPv6 with real IPv6 Internet egress: 29 pass, 0 fail,
  1 skip. The skip is the external-ingress case — no outside IPv6 source was
  available on the validation host, so inbound IPv6 from the public Internet
  is asserted only by the listener-bind and same-host evidence, not by an
  external client. Coverage includes all listener modes, Xray client
  sessions over every address-family combination (mixed A/AAAA,
  DNS-selected family, IPv6 literals, bracketed covers), byte-exact 64 MiB
  upload, download, and full-duplex transfers, 100 ms/1% netem impairment,
  route loss and recovery, and fast family-refusal fallback (0.086 s).
- **v3 versus generic.** The formal tier A/B above (all twelve intervals
  contain 1) is the complete v3 evidence: the opt-in tier has no measured
  advantage, because ring performs its own AES runtime dispatch in every
  tier. It exists so operators who already require x86-64-v3 get an
  explicitly identified build, not a faster one.

## v1.3 control-plane and setup-path structures

The v1.3 audit separated hashes by purpose instead of globally replacing
`HashMap`:

- attacker-influenced mutable replay state and large Geo asset sets retain the
  randomized standard hasher for collision resistance;
- validation/reload maps are startup-only and do not justify a custom hasher;
- immutable UUID and outbound-tag indexes select a contiguous sorted layout
  only below measured cardinality boundaries, then use the standard hash map.

Criterion on the release host selected 64 as the UUID boundary: with 64
entries, sorted hit/miss were 19.95/16.32 ns versus 20.26/20.76 ns for a
same-value SipHash map; at 128, sorted hit had risen to 23.59 ns and switching
to the hashed representation measured 22.01 ns. Outbound tags select sorted
storage through four entries (11.58 ns hit versus 20.40 ns hash at four) and
hash above it (at sixteen: 27.02 ns sorted versus 25.85 ns hash).

The strengthened short-ID/UUID pairing is also the lookup structure: one
decoded short ID resolves directly to its owner UUID, so the later VLESS check
is one equality rather than a second short-ID search. The owner index stays
sorted through 256 IDs (17.41/16.87 ns hit/miss versus 19.60/18.17 ns hash) and
switches to SipHash above that measured boundary; at 512, hash wins
19.59/18.18 ns versus 20.23/19.84 ns. A normal two-ID sorted hit is 3.50 ns,
10.0× below the replaced owner-selecting constant-time scan's 35.04 ns. This
does not weaken the externally visible failure policy: every pre-Finished
authentication failure still follows the same bounded byte-exact fallback.

REALITY no longer constructs a second per-listener UUID registry after the
short-ID owner index has already authenticated the same identities. The owner
UUID is carried into the established session and the VLESS UUID check is one
equality. Routing likewise performs one UUID lookup per decision and shares
one `Arc<CompiledUserPolicy>` among every UUID in a group; the empty-DNS
result has an allocation-counter gate proving zero heap allocation. The
outbound tag is resolved once for both Handoff and ordinary connects rather
than once in each layer.

VLESS parsing now has two explicit specializations. The public API constructs
its owned header directly, while the production Vision path borrows Addons,
domain and prefetched payload from the bounded request buffer and owns the
accepted domain exactly once. An allocation-counter test measured zero
allocations across 1,024 borrowed domain parses. A repeated full Criterion run
measured the owned API at 27.23 ns IPv4, 53.67 ns domain, 27.46 ns IPv6 and
425.01 ns for the maximum header; every case remained inside Criterion's noise
threshold against its immediate baseline. The request buffer now starts at
the protocol maximum header size (533 B) and grows only when a TLS record also
contains prefetched payload, instead of reserving a full record up front.

Replay caches combine a hash table for exact duplicate detection with a
deadline min-heap for expiry. REALITY purges the selected shard; NXR/Handoff
also do so on the normal reserve path and scan all sixteen shards only after
real global capacity pressure. With 4,096 live nonces, reserving a batch of 64
fell from 593.18 µs for the legacy full-retain path to 17.43 µs (**34.0×**);
purging a no-expiry live set is cardinality-independent at about 282 ns rather
than 10.54 µs. REALITY keys are already server-computed SHA-256 digests, so its
table uses an independent 64-bit digest word directly instead of running
SipHash over all 32 bytes: at 4,096 entries, hit/miss fell from 25.25/24.99 ns
to 2.18/1.11 ns (**11.6×/22.4×**). Handoff and NXR keep randomized hashing
because their nonce keys remain peer-controlled.

The direct-dial rate gate is now an atomic GCRA with a conservative integral
nanosecond interval and the same one-second burst allowance as the former
`Mutex<f64 token bucket>`. It never queues and cannot exceed the configured
rate. Including the unchanged Tokio concurrency semaphore, Criterion measured
68.34 vs 84.90 ns single-threaded and 145.60 vs 181.75 ns with four contending
threads (about **19.5%/19.9% less time**).

The common X25519 handshake keeps its fixed 32-byte server share on the stack.
The server flight is built once as one contiguous wire buffer and sealed from
the existing transcript tail; the former outer record vector, duplicate
flight-plaintext vector, and send-time assembly allocation/copy are gone.

Dependency features were tightened to the used surfaces, direct `base64`
versions were unified, and Criterion's plotting/parallel default graph was
removed. The lockfile lost ten packages. After all source changes the stripped
release binary is 6,309,616 bytes, 22,920 bytes (0.36%) below the pre-audit
6,332,536-byte build. Canonical values are retained in
`benchmarks/final/v1.3-hot-structures/summary.json`.

The complete setup path (accept through first Vision payload) was then run
against Xray 26.7.28 with three 96-connection samples per cell and zero
failures. rust-reality medians were 190/793/892 conn/s at c1/c8/c32 versus
177/721/833 for Xray. Server perf cost normalized over the 864 measured
connections was 0.757 ms and 4.00 M instructions per connection versus
1.239 ms and 5.69 M for Xray. This same-host result validates the composed
path; it is not a WAN capacity claim. Raw and summarized evidence lives in
`benchmarks/final/v1.3-setup-refactor/`.

For VLESS Encryption, the exact nested REALITY + Vision A/B and the decision
not to ship it in this profile are documented in
[ADR 0003](decisions/0003-do-not-stack-vless-encryption-on-reality.md): p50
throughput was 0.696×, server CPU/GiB 5.50×, and Vision splice was disabled.

## Robustness gates

Every bounded parser has a libFuzzer target. The v1.3 gate runs 20,000 ASan
instrumented cases each for `wire_parsers` (including the production borrowed
VLESS decoder), Vision framing, Handoff headers, Handoff blobs, and complete
Handoff opening. The restricted validation shell cannot initialize
LeakSanitizer under ptrace, so those local fuzz smoke runs set
`ASAN_OPTIONS=detect_leaks=0`; the scheduled CI workflow runs the full ASan +
LSan suite on a normal runner.

The parser property gate compares owned and borrowed VLESS decoding for every
prefix of a 533-byte maximum header and for zero/one/255 replacements at every
byte. Replay, admission, FD, and relay tests cover cancellation, poison
recovery, capacity reclamation, and contention. Scheduled CI additionally runs
the complete test suite under AddressSanitizer/LeakSanitizer and the concurrent
REALITY replay race under ThreadSanitizer. Monotonic deadlines and counters
use checked arithmetic; exhausted domains return an explicit unavailable error
instead of saturating into an unsafe success state.

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
  pipe2/fcntl/close churn for its 512 KiB pipes.
- Final v1.0.0 clean same-origin fallback A/B (warn-level logging both
  sides; `benchmarks/final/v1-fallback-ab/`): splice fallback 1.00–1.03×
  Xray at c1–c32 with equal-or-lower task-clock. An earlier apparent
  fallback deficit was traced to the matrix harness's debug-level
  per-connection logging, not to the relay path (see the methodology
  section of [benchmarks.md](benchmarks.md)). Historical D8-era mechanism
  runs measured 1.04–1.05× on the same host; they are superseded as
  headline values by the final release comparison.

## Connection setup

Final v1.0.0 figures (accept → REALITY handshake → VLESS parse → routing →
outbound connect → first Vision transition; steady state excluded;
validation host above, local TLS origin, raw-socket client; evidence:
`benchmarks/final/v1-setup-rate/`):

| cell | rust-reality | Xray | ratio |
|---|---:|---:|---:|
| c1 conn/s | 270 | 123 | 2.20× |
| c8 conn/s | 806 | 688 | 1.17× |
| c32 conn/s | 895 | 812 | 1.10× |
| c32 p99 setup latency | 59.3 ms | 59.3 ms | parity |

Per-connection server cost across the measured window (864 connections):
CPU 0.65 vs 1.53 ms (**−58%**), instructions −29%, context switches −77%.
Throughput converges at c32 because the 4-CPU host bounds both servers; the
per-connection cost columns are the cleaner signal. Whether the CPU
advantage converts into a rate advantage on a larger host is unverified.

## Decision register (D1–D11)

One-line verdicts for the performance decisions that shaped v1.0.0:

- **D1 — kept.** Reload/asset-refresh multiplied process ceilings; shared
  authorities hoisted to process-lifetime ownership.
- **D2 — kept.** Aborted transfers made distinguishable from graceful
  completion: the abort path arms `SO_LINGER{on,0}` so the peer observes a
  reset (RST/`ECONNRESET`), never a clean short EOF, while graceful
  teardown keeps FIN semantics (`DirectionAbortGuard`).
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
  logging, not splice call cost; clean A/B at the time measured fallback splice at
  1.04–1.05× Xray with materially lower CPU; the final v1.0.0 comparison
  (1.00–1.03×) supersedes it as the headline.
- **D9 — proven, shipped as default.** The framed path is AEAD-bound and
  ring is ≈2.5× RustCrypto at production record sizes; shipped as the
  default record AEAD provider with the RustCrypto fallback retained and
  continuously tested.
- **D10 — classified, no action.** The framed steady-state `clear_page`
  share is kernel TCP send-path page zeroing (`init_on_alloc` on the
  validated kernel), scaling per byte transferred — not per-connection
  userspace buffer cost (churn measured 28 minor faults/connection ≈ 2%
  of churn CPU). No buffer pool or lazy-growth was built.
- **D11 — proven, shipped.** Framed downlink record batching (one
  `readv` into four record slots + one write per ≤64 KiB) cut send
  syscalls 4×, server CPU/GiB −18.5%, and lifted framed download +7.6%
  at 512 MiB c32 in the gated A/B.

## Final release matrix (v1.0.0)

Frozen from the exact release-candidate production binary (built from git
`d2fbb0c`; the sample files' `commit` field records the harness checkout
SHA, and the post-matrix documentation commits changed no executable byte —
the rebuilt binary differs only in the embedded commit string and build-id,
both SHA-256s preserved in the release evidence archive),
binary SHA-256 `a77fe34a…`, ring default), comparator Xray-core 26.7.28
(`5ca6f4b`, go1.26.0, binary SHA-256 `23d228d7…`). 543 valid samples, 0
invalid, SHA-256 integrity matched for every implementation. Matrix cells
run rust-reality at debug log level (tunnel-bypass guard) against Xray at
warning — a handicap for rust-reality; fallback and setup rows use
symmetric warn-level harnesses. Full table: the README performance
section carries the representative rows; raw samples are in the release
evidence archive. Notes: `direct-upload:32MiB:c1` was bimodal for both
implementations (78–237 MiB/s spread) and is excluded as
non-discriminating; matrix fallback cells under-report rust-reality due
to the log-level asymmetry — the clean fallback A/B (1.00–1.03×) is the
honest figure.

## Deployment characterization (v1.0.0)

- **Routing correctness: PASS** — 26/26 (uuid, destination) cases across
  2 user groups, direct/blackhole/SOCKS5 outbounds, and
  domain/GeoSite/IP/GeoIP/port/late-match/default rules; every UUID
  reached only its intended outbound, byte-verified.
- **Routing decision tax: none measurable** — simple (1 user),
  medium (100 UUIDs/16 rules), and complex (1000 UUIDs/72 rules)
  configurations all measured 896 conn/s at 0.60 ms CPU/connection;
  DNS-in-path variants cost +0.12 ms/connection through the local
  resolver.
- **NXR two-hop tax vs direct:** ≈3–5% throughput, +0.15 ms CPU/conn.
- **NXR vs SOCKS5 (same endpoints):** +18% setup rate (880 vs 748
  conn/s), +11–13% throughput at 32/512 MiB c32; at 100 ms netem RTT,
  36 vs 19 conn/s (p50 218 ms vs 413 ms) — one fewer round trip per
  connection.
- **rust+NXR vs Xray+SOCKS5** (system-level, not protocol-isolated):
  880 vs 696 conn/s, 0.77 vs 1.02 ms CPU/connection.
- **Integrity:** every cell byte-verified; no transfer errors.

## Handoff line-node offload (measured, single host)

The Handoff topology moves a session's per-byte TLS/Vision work from the line
node to the landing node: after the one-time transfer, the line node is a raw
ciphertext splice relay. The measured A/B below compares that topology against
the NXR two-hop chain, same workload (512 MiB transfers through an unmodified
Xray client), same host.

**Evidence label:** single-host loopback on the validation host (Intel Core
i3-8100, 4C/4T), no cgroup isolation; loopback shares the host CPUs between
client, both server nodes, and origin. Figures are milliseconds of task-clock
CPU per GiB over 1.5 GiB stat windows — implementation cost, never Internet
throughput, and not cross-host transferable.

| metric (ms CPU/GiB) | NXR chain | Handoff chain | Δ |
|---|---:|---:|---:|
| LINE download | 549 | **98.1** | **−82.1%** (5.6×) |
| LINE upload | 1 043 | **415.0** | **−60.2%** (2.5×) |
| LANDING download | 103 | 517.3 | 5.0× (absorbed the TLS work, as designed) |
| **System download total** | 652 | **615.4** | **−5.6%** |

Profiles confirm the mechanism: the line node's steady state contains no AEAD,
record-layer, or Vision symbols at any percent limit (userspace is the splice
pump and scheduler glue; the transfer path — one X25519 exchange and one
bounded seal per session — measures ≈0.25% cumulative), while the landing
node's profile is the transplanted TLS workload. Upload stays dearer than
download on the line node because client records arrive in ≤16 KiB chunks,
so the residual is syscall-rate-bound, not cryptographic.

Reading this as an operator: Handoff is edge-compute migration, not a free
lunch — the line node sheds per-byte TLS, the landing node absorbs it, and
total system CPU is roughly flat (slightly better here). Choose **Handoff**
when the public line node is CPU-constrained and a stronger private landing
node is available; choose **NXR** when session keys must never leave the
public node — NXR transfers no key material at all, at the price of the
payload crossing the private hop in plaintext after its one-time
authentication.

## Hot-path forensic audit (v1.0.0)

Profiles of six workloads on an attribution build (same source, DWARF,
frame pointers) with IDA/disassembly spot checks: every material
userspace region is a third-party crypto primitive (ring's stitched
AES-GCM in steady state; sha2/X25519/ML-KEM in handshakes) or none
exists — the raw-relay userspace path peaks at 1.5% (`splice_pump`),
and no routing symbol reaches 1% under the complex-churn profile. No
finding crossed the keep gate (≥2% userspace with ≥5% realistic
end-to-end headroom); no production change was made. Known kernel costs
(copy_user, page zeroing) are classified per D10.

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
