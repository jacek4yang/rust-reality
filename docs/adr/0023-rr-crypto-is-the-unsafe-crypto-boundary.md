# ADR 0023: `rr-crypto` is the crate where cryptographic `unsafe` lives

## Status

Accepted.

## Context

Issue #225 moves rust-reality's cryptography from a set of external providers to
a subsystem this repository owns. The first implementation to migrate is X25519,
and it forced a structural question the earlier steps did not.

The main crate is `#![deny(unsafe_code)]`, stated in `[lints.rust]` and load-bearing:
[ADR 0008](0008-session-engine-runtime-and-transport-boundaries.md) puts raw
kernel mechanisms in `rr-linux` precisely so the protocol crate can keep that
property. An X25519 implementation this repository owns is assembly reached
through `global_asm!` and `unsafe extern "C"` declarations. It cannot live in
the main crate without deleting the rule that keeps the main crate honest, and
that trade is not worth making for one primitive — or for any number of them.

There is a second constraint that decides the shape rather than the location.
`tests/protocol_core_boundary.rs` forbids `aws_lc_rs` inside the `no_std`
protocol core by name, because it requires `std`. That single fact is why the
binary currently links **two** X25519 implementations: `aws-lc-rs` for the two
per-session agreements, and `x25519-dalek` everywhere the caller sits inside the
`no_std` core or does not justify a `std`-only provider. The duplication is a
symptom, and it only resolves if the replacement is `no_std`.

## Decision

Create `crates/rr-crypto`: a `no_std`, `core`-only crate holding the
cryptographic implementations rust-reality owns, with a safety policy narrower
than a blanket allowance and stricter than the main crate's silence.

1. **`unsafe` is permitted here and nowhere else in the production graph.** It
   is bounded by rules the build enforces, not by review:
   - `clippy::undocumented_unsafe_blocks = deny`, so every block states the
     invariant that makes it sound, in tests as well as in the library;
   - an unsafe call that depends on a CPU feature is reachable only through a
     runtime probe of that feature, so no binary can execute an instruction its
     CPU lacks;
   - the public API is safe. A caller outside the crate cannot construct an
     input that violates an invariant an `unsafe` block relies on.
2. **`no_std`, `core` only.** No `alloc`, no allocation on any path. A boundary
   that reintroduced the `std` requirement would have missed the reason it
   exists.
3. **Narrow surface.** Architecture backends are `pub(crate)`. The crate exports
   the secret types, the agreement operations, and one reporting function
   (`backend_name`) so a portability claim can be stated as an observation.
   Per-variant entry points are `#[cfg(test)]`, because in this crate that is
   what they are.
4. **Provenance is a precondition, not a follow-up.** Imported implementations
   are recorded in
   [crypto provenance](../en/development/crypto-provenance.md) before use, with
   the upstream revision, the exact transformation, and an explicit statement of
   which upstream verification does *not* carry over.

The crate is not a cryptography library and is not to become one. It holds the
primitives rust-reality performs, in the shapes it performs them.

## Consequences

- The main crate keeps `#![deny(unsafe_code)]`, unchanged and unqualified.
- `#[deny(missing_docs)]` and the clippy set are stricter here than in the main
  crate, which is the correct direction for code that cannot be checked by the
  type system alone.
- One `sha2` **dev-dependency**, used only to verify vendored upstream digests
  against the pinned provenance. It does not enter the production graph, and
  `cargo tree -e normal` is what proves that rather than the manifest's
  intention.
- Verifying that the committed assembly is upstream's mechanical expansion needs
  a C preprocessor. That is a **test-time** requirement and it skips with a
  message when `cpp` is absent, so the claim "the build needs no C toolchain"
  stays true without qualification and CI still checks the expansion on every
  change.
- Roughly 3 MB of vendored assembly enters the tree: four expanded `.s` files
  and their upstream `.S` originals per architecture, plus the licence. Every
  file is inside the 512 KiB per-object limit, so no exception is needed. It
  replaces a ~2.6 MB vendored C libcrypto reached through a build script, and
  unlike that one it is readable, diffable, and pinned by digest here.

## Rejected alternatives

- **Relax `unsafe_code` in the main crate.** It would delete a property that
  currently costs nothing and buys a great deal, in exchange for not creating a
  directory. ADR 0015 already rejected the same trade for syscalls.
- **Put the assembly in `rr-linux`.** That crate is the *Linux ABI* boundary.
  Field arithmetic is not a kernel mechanism, and merging them would make the
  name of each a lie.
- **One crate per architecture**, as the staging repository has. That structure
  exists there to serve hypothetical external consumers. rust-reality has one
  binary, and per-architecture crates would be micro-crates created for
  directory symmetry, which §11 forbids.
- **Keep a portable Rust fallback for targets without a backend.** A portable
  X25519 measured 1.85x the incumbent; shipping it as a "fallback" would be a
  regression wearing a safety label. Absence of the module is a compile error at
  the call site, which is the honest outcome.
- **Write the arithmetic ourselves.** The incumbent already executes this exact
  upstream assembly, reached through megabytes of unrelated C. The question was
  never whether we could match s2n-bignum; it was whether the arithmetic needed
  to arrive with a CMake build attached.

## Revisit conditions

- A second consumer appears for these primitives, making a published API worth
  its cost.
- A primitive arrives that needs `alloc`, which would break the `core`-only rule
  and should be argued explicitly rather than by adding an import.
- A target enters the release matrix with no assembly backend, which would make
  the no-portable-fallback decision load-bearing in a way it is not today.

## Evidence

- Issue #225 for the migration ledger and the measured X25519 position:
  parity on the arithmetic, the value being −24.65% binary, −2 production
  crates, and removal of the only C toolchain requirement.
- `crates/rr-crypto` tests: RFC 7748 §5.2/§6.1 vectors including the
  1,000-iteration case, both compiled variants agreeing, the committed assembly
  reproducing from upstream, and the vendored inputs pinned by SHA-256.
- `tests/x25519_differential.rs`: agreement with `aws-lc-rs` and `x25519-dalek`
  over 640 deterministic rounds, and identical refusal of the non-contributory
  set.
