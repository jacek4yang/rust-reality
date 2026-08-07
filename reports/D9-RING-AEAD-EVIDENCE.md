# D9 — ring AEAD experiment: final evidence report

Branch: `perf/d9-ring-aead` (ca2ba28 + 859115e on top of main 45d90d8).
Feature: `ring-aead` (opt-in; RustCrypto remains the default in this PR).

## RUSTCRYPTO BASELINE

- Isolated AES-128-GCM @16 KiB records (i3-8100, reused state):
  seal 2.03 GiB/s (1.65 cycles/B), open 1.88 GiB/s (1.78 cycles/B).
- E2E framed (matrix, benchmarks/final/d9-framed-ab): 512 MiB c32
  download 1277 MiB/s, upload 1331 MiB/s; c1 682 / 636 MiB/s.
- Server cost per 2 GiB framed download (perf stat, 3 reps):
  task-clock 1870–1928 ms (≈940 ms/GiB), 8.82 G instructions
  (≈4.41 G/GiB), ~9.9k context switches.
- Framed steady-state profile (diagnostic build, d28c5f0): AEAD symbols
  (aes::x86_aes + polyval + update_padded) ≈51% of download CPU, ≈39%
  of upload CPU — the AEAD fraction the swap attacks.

## RING ISOLATED SEAL RESULT

| size | ring | RustCrypto | ratio |
|---|---|---|---|
| 64 B | 0.75 GiB/s | 0.67 GiB/s | 1.12× |
| 1 KiB | 3.55 | 1.79 | 1.98× |
| 4 KiB | 4.75 | 1.97 | 2.41× |
| 16 KiB | 5.16 | 2.03 | **2.54×** |
| 32 KiB | 5.23 | 2.03 | 2.57× |

## RING ISOLATED OPEN RESULT

| size | ring | RustCrypto | ratio |
|---|---|---|---|
| 64 B | 0.63 GiB/s | 0.52 GiB/s | 1.21× |
| 1 KiB | 3.22 | 1.69 | 1.91× |
| 4 KiB | 4.45 | 1.85 | 2.41× |
| 16 KiB | 4.64 | 1.88 | **2.47×** |
| 32 KiB | 4.54 | 1.92 | 2.36× |

(Open legs include one symmetric buffer clone per iteration; ratios are
the conservative read.)

## PREDICTED AMDAHL E2E SPEEDUP

Server-CPU model with measured AEAD fractions and 2.5× provider:
download 1/(0.49+0.51/2.5) ≈ **1.44×**; upload 1/(0.611+0.387/2.5) ≈
**1.31×**. These are ceilings for server-CPU-bound conditions.

## OBSERVED E2E SPEEDUP (matrix, 219 valid samples, 0 invalid)

Framed cells, ring vs rustcrypto medians (n=5 for ≤32 MiB, n=3 for 512 MiB):

| cell | ratio | cell | ratio |
|---|---|---|---|
| download 512M c1 | 1.079 | upload 512M c1 | 1.055 |
| download 512M c32 | 1.160 | upload 512M c32 | 1.074 |
| download 32M c32 | 1.105 | upload 32M c32 | 1.073 |
| download 32M c1/c4 | 1.00–1.01 | upload 32M c1/c4 | 1.04–1.06 |
| download 1M c32 | 1.117 | upload 1M c32 | 1.183 |

All 16 framed cells ≥ 1.00. The observed steady-state gain (1.05–1.16×)
is below the Amdahl ceiling because loopback shares the 4 host CPUs
between server, Xray client, and origin: the profiled AEAD fraction is
of *server* CPU, while E2E throughput is host-CPU-bound. The server-side
CPU/GiB result below is the transferable measurement.

## CPU/GiB DELTA (server, perf stat, 2 GiB framed download, 3 reps each)

- task-clock: 631 ms/GiB (ring) vs 940 ms/GiB (rustcrypto) → **−33%**
- instructions: 3.11 G/GiB vs 4.41 G/GiB → **−30%**
- context switches: ~6.0k vs ~9.9k per 2 GiB → −39%
- RSS (VmHWM after 512 MiB transfer): 6 704 kB vs 6 488 kB — +3%, noise.
- Single-stream wall time ≈ equal (latency-bound); the win is efficiency
  and multi-connection throughput.

## XRAY RELATIVE RESULT (same matrix)

ring vs Xray at 512 MiB: download 1.124× (c1), 1.065× (c32); upload
1.097× (c1), 1.040× (c32). rustcrypto was mixed (0.95–1.12). Mechanism
check (source + Go micro-bench): Xray's record AEAD is Go's stitched
AES-NI+PCLMULQDQ assembly at ≈4.8 GiB/s @16 KiB — RustCrypto ran 2.4×
slower than Xray's AEAD; ring (5.16 GiB/s) moves rust-reality to parity
or slightly ahead, with no per-record scratch copy (Xray pays one).
Caveat: rust servers logged at debug (harness guard requirement), Xray
at warning, so Xray-relative numbers are conservative for rust.

## PERF/IDA ATTRIBUTION

- Before (symbolized diagnostic build, d28c5f0): aes::x86_aes 22.1% +
  polyval 17.1% + update_padded 11.2% ≈ 50.4% of framed download CPU.
- After (ring release binary, sudo perf record on the production path):
  RustCrypto AEAD symbols gone; hot userspace region 0x571500–0x571700
  disassembles to ring's AVX2 GCM (`vpclmulqdq`/`ymm` interleaved AES
  rounds) at a few % total; userspace-binary share of server CPU fell
  from 49.2% to 37.0%, kernel share 50.5% → 61.8% (absolute kernel time
  unchanged — the freed time is userspace AEAD).
- Raw perf.data retained: ../artifacts/d9-e2e/perf-{ring,rustcrypto}-download.data.

## PROVIDER-EQUIVALENCE RESULT

- Byte-identity fixtures: identical ciphertext+tag for identical
  key/nonce/AAD/plaintext at lengths {0,1,64,1K,4K,16K} × sequences
  {0,1,255,65536,2^24−1}, including the record layer's iv⊕seq nonce
  derivation; cross-open both directions; corrupted tag/ciphertext/AAD
  and wrong nonce rejected by both providers.
- RFC 8448 byte-exact seal/open tests pass under BOTH feature
  configurations; full workspace suite green under default and
  ring-aead.
- Adversarial review (independent agent): no BLOCKER/MAJOR findings.
  Documented gaps: (1) ring's LessSafeKey does not zeroize its expanded
  key schedule on drop (RustCrypto build does) — accepted for the
  experiment, flagged for the default decision; (2) after a failed open
  the ring build's buffer contents are unspecified (callers never read
  it; contract pinned in code); (3) undersized-body error mapping aligned
  by an explicit guard (859115e).

## FULL GATE RESULT

- cargo fmt --all --check: PASS (both configurations)
- cargo clippy --workspace --all-targets [-D warnings]: PASS default and
  --features ring-aead
- cargo test --workspace: PASS default and --features ring-aead
- Xray interoperability: matrix used an unmodified Xray SOCKS/Vision
  client; all 219 samples valid, bytesVerified=true, 2 GiB sha256
  integrity matched for ring, rustcrypto, and Xray cells.
- CI on the PR: pending at report time (runs with --all-features, which
  exercises the ring path automatically).

## SUPPLY-CHAIN DELTA

- New crates: ZERO. ring 0.17.14 is already in the release graph via
  ureq→rustls; Cargo.lock gains exactly one line (the root dependency
  edge). Licenses (Apache-2.0 AND ISC) pass `cargo deny`; `cargo audit`
  clean (local DB).
- Linking: fully static; `ldd` identical to the RustCrypto build; binary
  13 KiB SMALLER (6 066 304 vs 6 079 472 B).
- Build: ring's C/asm already compiles on every build (via rustls);
  incremental cost of the feature ≈ zero; cold ring build ~11 s.
- Targets: x86_64/aarch64 Linux both first-class ring targets — no
  portability delta vs the current tree. Non-ring targets (wasm, exotic)
  unaffected while the feature stays opt-in.
- Maintenance: ring is pre-1.0 with slow cadence; rustls team co-maintains;
  aws-lc-rs registered as the fallback comparator (not benchmarked).
- SECURITY.md: needs the drafted "ring may provide AES-128-GCM records"
  paragraph only if the default flips; not required for opt-in.

## D9 VERDICT: PROVEN

Provider equivalence byte-exact; security invariants intact (nonce
derivation/sequence/AAD/framing shared and unchanged); Xray interop
green; framed E2E +5–16% on steady cells with zero regressing cells;
server CPU/GiB −33%; attribution confirmed at the instruction level.

## PRODUCTION DEFAULT RECOMMENDATION

Flip the default to ring for AES-128-GCM records in a follow-up, after
two actions: (1) decide the zeroization tradeoff (ring cannot zeroize
its expanded schedule; options: accept + document, or evaluate
aws-lc-rs which also lacks zeroize-on-drop — likely accept+document);
(2) update SECURITY.md with the drafted paragraph. Until then the
feature remains opt-in (`--features ring-aead`), CI covers both
configurations via --all-features.
