# FRAMED-AMDAHL-REPORT — quantitative cost decomposition of the framed path

Base commit: `d28c5f0` (perf/1.0-pipe-pool).
Diagnostic binary: `artifacts/assembly-profile-10d/rust-reality`,
sha256 `b95f08447919da6df1e8efc3b44ff54bbc8ea7b5a8cc7a67e5b5161cf1bf5b58`
(release opt + DWARF + frame pointers, unstripped).
Profile: `sudo perf record` against the normal-user server under a clean
steady-state framed loopback workload; raw perf.data retained at
`../artifacts/framed-prof-d28c5f0/`; text reports committed at
`benchmarks/final/framed-prof/perf-{download,upload}.txt`.
Harness symmetry per `diagnostics/master/symmetry-audit.md` (warn-level
logging both sides, proxy env stripped, local origin).

Labels: MEASURED-LOCAL = measured on this host; MODELED = arithmetic on
measured inputs; CREDIBLE-HYPOTHESIS = not yet falsified/confirmed.

## 1. Steady-state framed decomposition (MEASURED-LOCAL)

Setup cost is excluded — the profile captures established connections
only (see CONNECTION-SETUP-PERFORMANCE.md for the separate setup model).

### Download (server seals → client opens), share of server CPU

| category | share | principal symbols |
|---|---|---|
| AEAD (AES-128-GCM seal/open, RustCrypto aes-gcm 0.11) | **≈51%** | `aes::backends::x86_aes::encrypt` 22.10%, `polyval proc_par_blocks` 17.09%, `universal_hash::update_padded` 11.20%, `compute_tag`/`apply_keystream`/small ≈0.6% |
| kernel boundary (read/write/copy_user, page clearing, TCP stack) | **≈47%** | copy_user rep_movs 13.27%, clear_page 3.90%, rest TCP/syscall/epoll |
| tokio scheduler/timers | ≈1% | `Sleep::reset` 0.24%, `poll_ready` 0.16% |
| Vision framing + TLS record parsing | <1% | `relay_outer_downlink` closure 0.40% |
| libc memcpy (userspace) | ≈0.15% | — |

### Upload (server opens → seals), share of server CPU

| category | share |
|---|---|
| AEAD | **≈38.7%** (aes 14.92 + polyval 13.33 + update_padded 9.44 + small ≈1.0) |
| kernel boundary | **≈57%** (copy_user 9.46%, clear_page 2.66%, …) |
| scheduler/Vision/record-parse/memcpy | <2% combined |

Confidence: high for the top two categories (stable across both
directions and multiple runs); inclusive-attribution overlap is small
because AEAD leaf symbols dominate self time.

Scaling behavior: AEAD cost scales **per byte**; kernel-boundary cost
scales per byte (copy) plus per syscall (record/chunk); everything else
is per record or per connection and already negligible.

## 2. Amdahl ceilings (MODELED on the measured fractions)

Download, F_aead = 0.51:

| AEAD speedup | end-to-end ceiling |
|---|---|
| 1.25× | 1.11× |
| 1.5× | 1.20× |
| 2.0× | 1.34× |
| ∞ | 2.04× |

Upload, F_aead = 0.387:

| AEAD speedup | end-to-end ceiling |
|---|---|
| 1.5× | 1.15× |
| 2.0× | 1.28× |
| ∞ | 1.63× |

Kernel-boundary fraction is not independently attackable without a
backend change (splice is inapplicable to framed traffic by definition);
treat it as a floor.

## 3. Isolated crypto-provider experiment (MEASURED-LOCAL)

Scratch bench: `../artifacts/crypto-bench/` (not a production change).
AES-128-GCM seal (production cipher suite), reused cipher state,
256 MiB per cell, i3-8100. OpenSSL leg additionally pays per-call EVP
context creation + key schedule, so its numbers are **conservative**.

| record size | RustCrypto aes-gcm 0.11 (in-place) | OpenSSL 3.5.6 EVP (out-of-place) | ratio |
|---|---|---|---|
| 1 KiB | 1.81 GiB/s (1.85 c/B) | 1.03 GiB/s (3.26 c/B) | 0.57× |
| 4 KiB | 1.88 GiB/s (1.79 c/B) | 2.54 GiB/s (1.32 c/B) | 1.35× |
| 8 KiB | 2.01 GiB/s (1.67 c/B) | 3.40 GiB/s (0.99 c/B) | 1.69× |
| 16 KiB | 2.02 GiB/s (1.66 c/B) | 4.12 GiB/s (0.81 c/B) | **2.04×** |
| 32 KiB | 2.03 GiB/s (1.65 c/B) | 4.58 GiB/s (0.73 c/B) | 2.26× |

Both legs run on AES-NI + PCLMULQDQ hardware; the delta is OpenSSL's
stitched/interleaved AES-GCM code, not a feature-detection miss.
Production records are large (Vision packs frames up to 16 KiB), so the
8–32 KiB rows are the relevant ones. First AES-256-GCM run showed the
same shape (2.9× at 16 KiB), so the gap is not cipher-specific.

VERDICT: **SUPPORTED** — a provider change has a real ceiling:
AEAD ≈2.0× at 16 KiB → end-to-end framed ceiling ≈1.35× download /
1.25× upload (MODELED). The micro delta must still be proven to
transfer end-to-end; FFI/record-boundary overheads can shrink it.

## 4. What this rules out

- Copy elimination: REJECTED as a framed opportunity — COPY-MAP.md shows
  zero avoidable userspace copies; profile agrees (memcpy ≈0.15%).
- Vision framing / record parsing work: REJECTED — <1% combined.
- Scheduler/runtime redesign: REJECTED by evidence — ≈1%; runtime
  topology stays untouched per directive.
- AEAD micro-tuning of the current RustCrypto path (unrolling, block
  batching within the crate's API): the crate already dispatches to
  AES-NI intrinsics; the 2× delta is implementation-level, not a flag.

## 5. Decision inputs

MEASURED BOTTLENECK #1: AEAD — ≈51% download / ≈39% upload of framed CPU.
Theoretical max gain: 1.35×/1.25× end-to-end via a ≈2× provider (OpenSSL
EVP); 2.04×/1.63× at infinite AEAD speed.

MEASURED BOTTLENECK #2: kernel boundary — ≈47% download / ≈57% upload.
Not attackable for framed traffic without changing the security
architecture; it is the floor that caps any AEAD win.

MEASURED BOTTLENECK #3: none — every remaining category is <2%.

FIRST REFACTOR (proposed, needs product-level go-ahead): an integration
experiment wiring OpenSSL EVP AES-128-GCM behind an internal switch into
the hand-written TLS 1.3 record layer, keeping RustCrypto as the default.

FALSIFICATION CONDITION: end-to-end framed loopback (clean symmetric
harness) shows <1.10× download or <1.05× upload, or any
correctness/constant-time/interoperability gate fails.

EXPECTED END-TO-END GAIN: 1.15–1.35× framed throughput depending on
direction, bounded by the ceilings above.

OPEN PRODUCT QUESTION: adding an OpenSSL link dependency changes the
supply chain (currently pure RustCrypto; SECURITY.md documents this).
That decision is flagged for the user before any production integration;
the isolated evidence stands regardless.
