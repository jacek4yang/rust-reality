# ADR 0021: SHA, HKDF, HMAC and Ed25519 stay on RustCrypto

## Status

Rejected on measurement (two candidate provider migrations declined). This ADR
changes no production code. It exists because both rejections are durable
architectural decisions with non-obvious revisit conditions, and because one of
them reverses a recommendation this repository had already written down.

## Context

[ADR 0020](0020-aws-lc-rs-computes-per-session-x25519.md) moved the two
per-session X25519 agreements to `aws-lc-rs` for a measured −11.7% of server
session CPU, and issue #213 continued through the remaining per-session
primitives. Two were left open, both deliberately:

- **SHA / HKDF / HMAC.** Measured on the i3-8100 and recorded as *measured, not
  decided*, because that CPU has no SHA-NI. `sha2 0.11` dispatches to SHA-NI for
  SHA-256 at runtime and has no accelerated non-SHA-NI x86-64 SHA-256 path, so
  on that host it ran portable code against ring's and AWS-LC's assembly. The
  recorded recommendation was that the provider "should be ring", pending a
  SHA-NI host.
- **Ed25519.** `aws-lc-rs` measured 2.04x, but `tls13/messages.rs` is inside the
  `no_std + alloc` protocol core that [ADR 0016](0016-protocol-core-is-no-std-ready-but-stays-in-place.md)
  established and `tests/protocol_core_boundary.rs` enforces — and which ADR
  0020 extended to forbid `aws_lc_rs` there by name. The open question was
  architectural, not numerical.

A second measurement host resolved both: a ThinkPad E15 Gen 4 with a 12th-gen
Core i5-1240P — Alder Lake-P, 4 Golden Cove P-cores plus 8 Gracemont E-cores,
**with SHA-NI**. It contributes a hardware tier, not better instrumentation:
`perf` is not installed on it and installing it was out of scope, so every
PMU-dependent question remains answerable only on the i3.

The earlier comparison had been run from an ad-hoc script that was never
committed, which meant "re-run it on SHA-NI hardware" was not actually a
runnable instruction. It is now `benches/crypto_providers.rs`: the same gated
binary, from one commit, on both hosts, at the shapes the server performs —
including the incremental transcript (six updates and four clone snapshots, as
`build_server_flight_inner` drives it) rather than a one-shot digest of a round
number. All three providers are asserted byte-identical before any of them is
timed.

## Decision

**Keep `sha2`, `hkdf`, `hmac` and `ed25519-dalek`. Adopt neither `ring` nor
`aws-lc-rs` for these primitives.**

### SHA / HKDF / HMAC — the prior recommendation is reversed

The i3 recommendation rested on a prediction, and the prediction was half wrong:

> On a SHA-NI server, `sha2` would take the SHA-NI path and most of the digest
> advantage should disappear. The HMAC and HKDF advantages are a different thing
> and travel better: they are largely per-call construction overhead in
> `hkdf`/`hmac` rather than hash-core throughput.

The digest half is right. The HMAC/HKDF half is not — those advantages were
hash-core throughput too, and on SHA-NI hardware they invert. SHA-NI dispatch is
confirmed engaging, with a control that separates clock from mechanism: going
from the i3 to a pinned P-core, `sha2` SHA-256 over 1400 B improves 9.39x and
HMAC-SHA256 7.62x, while SHA-384 improves 1.61x and HMAC-SHA512 1.70x. Only
1.22x of any of that is clock.

Ratios against RustCrypto, 25 repetitions, bootstrap intervals, each reproduced
in an independent second run (`<1.000` means the contender is faster):

| operation | ring, i3 | ring, P-core | ring, E-core |
| --- | ---: | ---: | ---: |
| transcript SHA-256, X25519 flight | 0.564 | **1.097** | 1.075 |
| HKDF-Expand-Label SHA-256 | 0.618 | **1.156** | 1.242 |
| HMAC-SHA256 Finished | 0.604 | **1.306** | 1.407 |
| HKDF-SHA256 REALITY auth | 0.610 | **1.227** | 1.211 |
| HKDF-Extract SHA-256 | 0.404 | 0.907 | 0.985 |
| transcript SHA-384 | 0.726 | 0.878 | **5.717** |
| HMAC-SHA512 certificate binding | 0.720 | 0.908 | **5.885** |
| HKDF-Extract SHA-384 | 0.491 | 0.619 | **4.008** |

Two independent reasons to decline, either of which is sufficient.

**It is slower on the representative tier.** Against audited per-session
operation counts — 3 HKDF-Extract, 16 HKDF-Expand-Label, 2 Finished HMAC, one
incremental transcript, one REALITY HKDF, one HMAC-SHA512, under the default
`TLS_AES_128_GCM_SHA256` suite — the complete per-session SHA/HKDF/HMAC cost is:

| tier | RustCrypto | ring | ring delta |
| --- | ---: | ---: | ---: |
| i3-8100, no SHA-NI | 38,024 ns | 22,071 ns | −15,953 ns (−42.0%) |
| i5-1240P P-core | **5,901 ns** | 6,478 ns | **+577 ns (+9.8%)** |
| i5-1240P E-core | **7,195 ns** | 14,973 ns | **+7,778 ns (+108.1%)** |

On the i3 that saving is 3.2% of a 501 µs session. On SHA-NI hardware the whole
bucket has collapsed to 5.9 µs, so no SHA provider — not even a free one — can
reach 3% of a session there.

**It is catastrophic on one core class.** Every SHA-512-family operation costs
ring and `aws-lc-rs` roughly 4–6x on Gracemont while RustCrypto is unaffected.
This is the most reproducible result in the campaign: bootstrap intervals such
as `[5.678, 5.695]`, reproduced across independent runs to 0.01–0.7%, and
measured as a ratio against another provider on the *same* core, so core
frequency cancels. Adopting ring for SHA would trade a ~15% P-core gain on the
SHA-384/512 family for a ~490% E-core loss on it, on a CPU whose scheduler moves
work between those core classes routinely.

The migration target would have been `keys.rs`: 875 lines, 53 references to the
crypto types, validated by RFC 8448 vectors, the most protocol-critical file in
the repository. That risk was worth taking for a measured gain and is not worth
taking for a measured loss.

### Ed25519 — the boundary-preserving option is slower than the incumbent

`aws-lc-rs` is genuinely ~1.9–2.0x faster on every tier measured, and T1 already
proved 500/500 byte-identical signatures, so neither speed nor correctness is
the obstacle. The new information is the third column:

| tier | `ed25519-dalek` | `ring` | `aws-lc-rs` |
| --- | ---: | ---: | ---: |
| i3-8100 | 19,322 ns | 26,946 ns (1.40x slower) | 9,545 ns (0.494x) |
| i5-1240P P-core | 13,486 ns | 17,706 ns (1.31x slower) | 7,111 ns (0.527x) |
| i5-1240P E-core | 33,023 ns | 40,628 ns (1.23x slower) | 24,012 ns (0.727x) |

T4, T5 and T7 could each have chosen `ring` and left ADR 0016 intact, because
ring resolves without `std`. **Ed25519 has no such option: ring is 23–40%
slower than the incumbent on every core class measured.** The only faster
provider is the one the boundary forbids.

Ed25519 is ~3.4–3.8% of the 501 µs i3 session; removing 50.6% of it bounds the
whole-session gain at **1.95%**. The new tier cannot be measured end to end, but
the ceiling can be bounded rather than guessed: Ed25519 shrinks 0.70x onto the
P-core while the SHA bucket collapses 6.4x, so the session shrinks at least as
fast as Ed25519 does and its share rises slightly. Across any plausible session
cost between 250 and 400 µs the ceiling stays between 1.6% and 2.6%.

That is below the ≥3% bar for architectural complexity, and below the new host's
own P-core A/A floor (p90 3.13%) — the ceiling cannot be distinguished from
noise on the host with the modern CPU. ADR 0016's boundary is worth more than
2%.

## What was deliberately not built

No provider trait, no `Box<dyn CryptoProvider>`, no feature-selected SHA
backend, no per-core-class dispatch, and no operator configuration. The E-core
finding in particular invites a "use ring on P-cores" reflex; production ships
one provider decision, and a runtime provider switch keyed on core class would
add a branch and two code paths to the key schedule to chase a sub-microsecond
term. Provider count is not a performance metric, and three providers
(`aws-lc-rs` for X25519, `ring` for AEAD, RustCrypto for hashes and signatures)
remain intentional: each holds the primitive it measurably wins.

## Consequences

- `sha2`, `hkdf`, `hmac` and `ed25519-dalek` stay production dependencies, and
  `tls13/keys.rs` and `tls13/messages.rs` stay inside ADR 0016's enforced
  `no_std + alloc` core with no new exception.
- No binary growth, no dependency change, no supply-chain change, no interop
  surface touched. `--no-default-features` behaviour is unchanged.
- The comparison is now a committed benchmark rather than a lost script, so
  re-deciding this on new hardware is one command
  (`cargo bench --bench crypto_providers`) rather than a re-derivation.
- Issue #213's crypto sequence is terminal. Its accepted outcome remains the
  X25519 migration: **571 → 501 µs of server CPU per connection, −12.3%**.

## Revisit conditions

For SHA / HKDF / HMAC — a *provider* change, not a hardware change:

- `sha2` loses its SHA-NI backend, or ships a materially slower one;
- ring or `aws-lc-rs` gains a SHA-NI SHA-256 path **and** fixes its Gracemont
  SHA-512 behaviour — both are required, because either alone leaves one of the
  two reasons above standing;
- a supported deployment tier is established that lacks SHA-NI, in which case
  the i3 column becomes the representative one and the decision flips on the
  measurement rather than on preference.

For Ed25519:

- Ed25519's share of session CPU reaches ~6%, at which point the same 2x becomes
  a ≥3% whole-session win;
- the `ed25519-dalek` gap widens past ~3x;
- `tls13/messages.rs` leaves the enforced core for its own reasons, or ADR
  0016's extraction conditions fire, removing the boundary objection;
- a `no_std`-clean Ed25519 provider becomes faster than `ed25519-dalek`.

Do not revisit either from the i3-8100 table alone. That host has no SHA-NI and
is now the least representative of the two.

## Evidence

- `benchmarks/evidence/crypto-provider-primitive-hardware-tiers.json` — median
  ns/op for every operation, provider and tier; per-session totals; host,
  toolchain, binary SHA-256 and Build ID; A/A floors.
- `benches/crypto_providers.rs` — the harness, including the 36 byte-equality
  checks that gate the timing and the two shape decisions the result depends on:
  the Ed25519 signing key is built once outside the timed closure because
  `CertificateIdentity` holds it for the process lifetime, while HMAC and HKDF
  keys are built per call because production builds them per call.
- Issue #213 — the host capability dossier (including `perf` as `NOT_AVAILABLE`
  on the new host and what that does and does not block), the full ratio tables
  with bootstrap intervals and reproduction deltas, and the T7 and T8 verdicts.
