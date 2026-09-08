# ADR 0028: Finalize the v2 cryptographic provider set

## Status

Accepted. Supersedes ADR 0020's provider selection, completes ADR 0023's
X25519 boundary, and retains ADR 0021's SHA/HMAC/HKDF and Ed25519 decisions.

## Context

The release needs a mature, bounded dependency surface. Owning every primitive
is not a requirement. Issue #225's C3c and PR #239 remove the remaining
rust-reality X25519 call sites outside `rr-crypto`, including the client, cover
probe, hybrid TLS exchange, and Handoff control channel.

The C2 fastcrypto SHA/HMAC/HKDF benchmark was discarded because concurrent
work contaminated it. It supplies no performance evidence. Both production
hosts support SHA-NI, which `sha2` uses for SHA-256. ADR 0021 supplies the
existing hardware-tier comparison; its Intel results are not Zen performance
measurements. No accepted whole-product result justifies another provider
migration during release finalization.

## Decision

- Use `rr-crypto` for rust-reality's own X25519 operations. It imports mature
  s2n-bignum routines at the revision and hashes recorded in
  [crypto provenance](../en/development/crypto-provenance.md), with safe Rust
  ownership and CPU dispatch. This is architectural consolidation at arithmetic
  parity, not a new whole-product speed claim.
- Keep RustCrypto `sha2`, `hmac`, and `hkdf`. C2 is complete by retention;
  another benchmark is not a v2 release prerequisite.
- Keep ring for all default TLS record AEAD suites. Keep RustCrypto AES-GCM
  for REALITY authentication, ChaCha20-Poly1305 for Handoff, and both for the
  `--no-default-features` TLS record path.
- Keep `ed25519-dalek` and `ml-kem`. No custom signature, AEAD, or post-quantum
  implementation enters this release.
- Keep `aws-lc-rs` and `x25519-dalek` only as development oracles and benchmark
  comparators. Neither they nor `aws-lc-sys` may occur in the normal production
  graph. Research repositories are never build dependencies.

The full provider mapping and reproduction commands belong to
[the production crypto reference](../en/development/crypto-providers.md).
Third-party HTTPS asset fetching through `ureq`/rustls retains ring's own TLS
internals; the single X25519 boundary claim concerns rust-reality's protocols.
Removing AWS-LC removes its production CMake/libcrypto build, not ring's C
compiler requirement or the development oracle's build requirements.

## Correctness and ownership

Entropy enters the owned boundary. Ephemeral secrets draw into owned storage,
agreement consumes them, and zeroization follows the last owner. LANDING's
static key is immutable and shared through `Arc`; concurrent agreements cannot
mutate the scalar, and its final owner performs destruction. The non-contributory
input check remains mandatory. Handoff's bytes, authentication barrier, retry
rules, and replay semantics do not change with the provider.

`crypto_boundary` checks exact source ownership and runs the locked normal
dependency graph with all features. A failed graph command or a forbidden
provider fails the test. Differential tests use both independent oracles;
RFC vectors, assembly reproduction, provenance digests, fuzzing, and AArch64
QEMU execution cover distinct failure modes. Upstream proofs do not certify
this Rust build, and emulation establishes correctness, not ARM performance.

## Consequences

No new operator setting, connection parameter, or wire extension is required.
The binary can be rolled back independently of persistent production identity.
Provider consolidation has a bounded review surface; the accepted provenance
and oracle requirements remain release obligations.

## Revisit conditions

Reopen a provider decision only for a security defect, a supported target the
provider cannot serve, or a reproducible whole-product benefit on the deployment
envelope that justifies the compatibility and maintenance risk. Research
availability alone is insufficient.

## Evidence

- [Issue #225](https://github.com/jacek4yang/rust-reality/issues/225): accepted
  X25519 evidence, discarded C2 experiment, and final retention decision.
- [PR #239](https://github.com/jacek4yang/rust-reality/pull/239): source ownership,
  consumed probe keys, immutable LANDING sharing, fail-closed dependency tests,
  differential and exact-head CI/security validation.
- ADRs 0021 and 0023, `tests/crypto_boundary.rs`,
  `tests/x25519_differential.rs`, and `crates/rr-crypto` reproduction tests.
