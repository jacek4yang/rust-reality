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
256 MiB per cell, i3-8100. The OpenSSL leg additionally pays per-call EVP
context creation + key schedule, so its numbers are **conservative**.
The production build provably uses the AES-NI/PCLMULQDQ backends of the
`aes`/`polyval` crates (profile symbols `aes::backends::x86_aes`,
`polyval::backend::intrinsics`), so the RustCrypto leg is representative.

| record size | RustCrypto aes-gcm 0.11 (in-place) | OpenSSL 3.5.6 EVP (out-of-place) | ring 0.17 (in-place) | best ratio |
|---|---|---|---|---|
| 1 KiB | 1.81 GiB/s (1.85 c/B) | 1.03 GiB/s (3.25 c/B) | 3.56 GiB/s (0.94 c/B) | ring 1.97× |
| 4 KiB | 1.98 GiB/s (1.69 c/B) | 2.60 GiB/s (1.29 c/B) | 4.73 GiB/s (0.71 c/B) | ring 2.39× |
| 8 KiB | 2.01 GiB/s (1.67 c/B) | 3.37 GiB/s (1.00 c/B) | 4.99 GiB/s (0.67 c/B) | ring 2.48× |
| 16 KiB | 2.03 GiB/s (1.65 c/B) | 4.08 GiB/s (0.82 c/B) | 5.16 GiB/s (0.65 c/B) | **ring 2.54×** |
| 32 KiB | 2.03 GiB/s (1.65 c/B) | 4.57 GiB/s (0.73 c/B) | 5.22 GiB/s (0.64 c/B) | ring 2.57× |

All three legs run on AES-NI + PCLMULQDQ hardware; the delta is
implementation quality (BoringSSL-derived stitched assembly in ring,
OpenSSL's interleaved AVX code), not a feature-detection miss.
Production records are large (Vision packs frames up to 16 KiB), so the
8–32 KiB rows are the relevant ones. ring wins at every record size,
does in-place sealing (the exact shape the record layer needs), and is
a crates.io dependency with no system library link — unlike OpenSSL.

VERDICT: **SUPPORTED** — a provider change has a real ceiling:
AEAD ≈2.5× at 16 KiB via ring → end-to-end framed ceiling ≈1.45×
download / 1.31× upload (MODELED: 1/(0.49+0.51/2.54), 1/(0.611+0.387/2.54)).
The micro delta must still be proven to transfer end-to-end; record
boundaries and nonce handling can shrink it.

## 4. What this rules out

- Copy elimination: REJECTED as a framed opportunity — COPY-MAP.md shows
  zero avoidable userspace copies; profile agrees (memcpy ≈0.15%).
- Vision framing / record parsing work: REJECTED — <1% combined.
- Scheduler/runtime redesign: REJECTED by evidence — ≈1%; runtime
  topology stays untouched per directive.
- AEAD micro-tuning of the current RustCrypto path (unrolling, block
  batching within the crate's API): the crate already dispatches to
  AES-NI intrinsics; the 2×+ delta is implementation-level, not a flag.

## 5. Decision inputs

MEASURED BOTTLENECK #1: AEAD — ≈51% download / ≈39% upload of framed CPU.
Theoretical max gain: 1.45×/1.31× end-to-end via ring (≈2.5× AEAD);
2.04×/1.63× at infinite AEAD speed.

MEASURED BOTTLENECK #2: kernel boundary — ≈47% download / ≈57% upload.
Not attackable for framed traffic without changing the security
architecture; it is the floor that caps any AEAD win.

MEASURED BOTTLENECK #3: none — every remaining category is <2%.

FIRST REFACTOR (proposed, needs product-level go-ahead): an integration
experiment swapping the record layer's AES-128-GCM from RustCrypto
aes-gcm to ring behind an internal switch, keeping RustCrypto as the
default. ring also covers ChaCha20-Poly1305 if the same swap proves out.

FALSIFICATION CONDITION: end-to-end framed loopback (clean symmetric
harness) shows <1.10× download or <1.05× upload, or any
correctness/constant-time/interoperability gate fails.

EXPECTED END-TO-END GAIN: 1.15–1.45× framed throughput depending on
direction, bounded by the ceilings above.

OPEN PRODUCT QUESTION: swapping RustCrypto for ring changes the crypto
supply chain (ring embeds BoringSSL-derived C/asm; SECURITY.md currently
documents a pure-RustCrypto stack; deny/audit policy and the hand-written
TLS boundary must be reviewed). That decision is flagged for the user
before any production integration; the isolated evidence stands
regardless.
