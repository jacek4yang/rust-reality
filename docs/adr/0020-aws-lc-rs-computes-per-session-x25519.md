# ADR 0020: `aws-lc-rs` computes the per-session X25519 agreements

## Status

Accepted on measurement. Scoped to the two per-session X25519 call sites. It
authorizes no protocol, wire-format, or configuration change, and it does not
decide anything about the other cryptographic primitives.

## Context

Whole-session profiling had attributed roughly 29.5% of server session CPU to
Curve25519 work. That bucket was never a decision on its own: `x25519-dalek` and
`ed25519-dalek` share inlined field arithmetic, so "curve25519" could have been
X25519 basepoint multiplication, X25519 variable-base agreement, Ed25519
signing, or any mixture. PMU counters are unavailable on the measurement host —
`cargo dev doctor` reports `perf` restricted by `perf_event_paranoid=3` with an
explicit instruction not to lower it — so symbol sampling could not split it
either, and would have struggled regardless because the two libraries land in
the same inlined symbols.

The split was instead derived mechanistically: audited per-session operation
counts multiplied by measured per-operation cost.

A REALITY session performs **four** Curve25519 scalar multiplications:

| operation | site | ns (dalek) | share of bucket |
| --- | --- | ---: | ---: |
| X25519 variable-base — REALITY authentication | `protocol/reality/auth.rs` | 56,590 | 37.8% |
| X25519 variable-base — TLS ECDHE | `tls13/handshake.rs` | 56,405 | 37.7% |
| X25519 basepoint — TLS server share | `tls13/handshake.rs` | 17,127 | 11.4% |
| Ed25519 signature — CertificateVerify | `tls13/messages.rs` | 19,256 | 12.9% |

So the bucket is ~87% X25519 and ~13% Ed25519. The brief's warning that it must
not be assumed to be all X25519 was correct, and X25519 still dominates it.

## Decision

Compute the two per-session X25519 agreements with `aws-lc-rs` 1.18.1 (non-FIPS,
high-level safe API), behind `src/crypto/x25519.rs`.

Two types, because the server performs X25519 in two shapes with different
ownership rules:

- `StaticX25519Key` — the configured REALITY private key, imported **once** when
  authentication state is compiled. Importing an AWS-LC private key costs
  ~7.7 µs against a ~23 µs agreement, so a per-connection import would return a
  quarter of the improvement. The type makes the one-time import the natural
  use.
- `EphemeralX25519Key` — one TLS key exchange. `agree` takes `self`, so single
  use is a type-system property. Nothing caches, reuses, or precomputes an
  ephemeral secret, and the private key never exists as raw bytes on our side.

`RealityAuthenticator` loses its `Clone` derive. `aws_lc_rs::agreement::PrivateKey`
is not `Clone`, which looked like it would force an `Arc` or a copy of secret
material; the derive turned out to be unused, so the constraint is resolved by
deletion.

### What was deliberately not built

No trait, no dynamic dispatch, no provider registry, no feature-selected
backend, no configuration surface, and no per-session branching. Which
implementation computes X25519 is a build decision, not operator policy. The
boundary exists to hold the ownership rules above and to give the equivalence
tests something to address — not to abstract cryptography in general.

## The `no_std` boundary is untouched, and is now guarded

[ADR 0016](0016-protocol-core-is-no-std-ready-but-stays-in-place.md) records a
`no_std + alloc` protocol core inside `src/protocol`, enforced by
`tests/protocol_core_boundary.rs`. `aws-lc-rs` requires `std`, so this deserved
an explicit answer rather than an assumption.

The two call sites are `reality/auth.rs` and `tls13/handshake.rs`. Neither is in
the enforced core list, and neither is there by oversight: ADR 0016 classifies
`handshake` as inherently runtime-bound, and the boundary test's own
documentation says `reality/auth.rs` "deliberately compiles from
configuration". They are the two modules the audit had already placed outside
the layer.

`crates/rr-session` — the workspace's actual `#![no_std]` crate — has zero
dependencies and contains no cryptography, so nothing there is affected either.

The boundary test compares source text, so it would **not** have caught a
`std`-only crate entering the core; a crypto import reads like any other. It now
forbids `aws_lc_rs` by name in the twelve core modules. That matters for what
comes next rather than for this change: `tls13/record.rs` (AEAD) and
`tls13/messages.rs` (Ed25519, HMAC) **are** in the core list, so migrating
either to `aws-lc-rs` is an architecture decision requiring its own ADR, not an
import. ADR 0016's audit specifically established that `ring` resolves without
`std`, so today's AEAD provider does not have this problem.

## Evidence

Correctness first, because a faster wrong answer is worthless. `x25519-dalek`
remains a production dependency (key generation, destination probe, handoff), so
the equivalence tests compare two real implementations rather than one against
itself:

- RFC 7748 §6.1 vectors as a non-circular anchor.
- 2000 random public-key derivations and 2000 random agreements: byte-identical.
- 500 Ed25519 signatures: byte-identical (a T8 input, recorded here because it
  was measured).
- **Accept/reject parity on every low-order point and non-canonical field
  encoding.** This is the load-bearing check: dalek rejects by computing the
  agreement and testing `was_contributory()`, `aws-lc-rs` by returning an error.
  Different mechanisms, so their agreement had to be demonstrated. Divergence
  would change which client authenticates.
- Every 32-byte value dalek accepts as a configured key is still accepted, so no
  working configuration can start failing.
- 5528 checks total, 0 failures, on both GNU and musl.

Interoperability, against unmodified Xray 26.7.28, 1 MiB SHA-256-verified
payload, once per key-exchange group:

| cover | negotiated group | result |
| --- | --- | --- |
| `dl.google.com:443` | X25519MLKEM768 | PASS |
| local X25519-pinned TLS server | X25519 | PASS |

The group each run used was established rather than assumed: the pinned Xray
ClientHello was captured and decoded (it offers a 1216-byte X25519MLKEM768 key
share alongside X25519), and the cover's selection was probed directly. Hybrid
`X25519MLKEM768` keeps its `ML-KEM || X25519` concatenation order byte for byte;
only the code computing the X25519 component changed.

Setup-rate A/B, frozen identity-bound artifacts, both arms unprofiled:

| run | median candidate/baseline | bootstrap95 |
| --- | ---: | --- |
| A/B | **0.8833** | [0.8742, 0.8834] |
| A/B, ABBA order reversed | **0.8832** | [0.8779, 0.8833] |
| A/A floor | 1.0029 | [0.9906, 1.0036] |

**571 → 503 µs of server CPU per connection: −11.7%**, reproduced with the
ordering reversed, against an A/A floor whose widest excursion is 0.94%. Zero
failures across all three runs.

The mechanism is confirmed, not merely correlated. The primitive measurements
predicted a saving of 68.8 µs per session before the candidate existed; the A/B
measured 68 µs. Agreement to about 1% is what distinguishes this from a
coincidence, and it lets the attribution be stated as a measurement: X25519 was
~22.9% of server session CPU, Ed25519 a further ~3.4%.

## Cost accepted

| cost | value |
| --- | --- |
| stripped ELF | +2,599,896 B (+35.6%) |
| `.text` | +2,028,672 B (+38.7%) |
| dynamic dependencies | unchanged |
| musl static tier | static-pie, 0 `NEEDED`, 0 `INTERP` — preserved |
| warm process start | +66 µs (+5.2%), once per process |
| build requirements | a C compiler; no CMake, bindgen, Go or Perl |
| supply chain | no `cargo deny` policy change; no OpenSSL licence |

Binary growth is real and structural: `aws-lc-sys` builds a whole libcrypto and
offers no X25519-only build. It is accepted because 2.6 MB of read-only text
buys 11.7% of session CPU permanently, with no new dynamic dependency and
without weakening the fully-static musl guarantee.

## Consequences and revisit conditions

- `x25519-dalek` stays a production dependency for key generation, the
  destination probe and the handoff control channel. Consolidating those is a
  separate transaction; keeping it also preserves an independent oracle for the
  equivalence tests.
- The binary cost argues for continuing the sequence rather than stopping here:
  the remaining provider comparisons would amortise it by *removing* providers.
  Nothing in this ADR presumes their outcome.
- Revisit if `x25519-dalek` gains an assembly or ADX backend that closes the
  2.4x gap, if binary size becomes a release constraint, or if a supported
  target loses a usable C toolchain.
