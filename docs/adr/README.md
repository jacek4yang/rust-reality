# Architecture decision records (ADRs)

An ADR records one durable engineering decision: an architecture boundary, a
security invariant, an ownership change, an important rejected strategy, or an
external-reference boundary — together with the reasoning and evidence that made
the decision correct at the time it was accepted. ADRs are the second source of
normative force for this repository after [AGENTS.md](../../AGENTS.md): where
[AGENTS.md](../../AGENTS.md) states the law, an ADR records why a specific part
of the law is what it is.

## What belongs in an ADR

- a durable architecture boundary (layering, crate extraction, runtime independence);
- a security invariant with reasoning (authentication stacking, handshake shape);
- an ownership or responsibility change between subsystems;
- an important rejected strategy with measured evidence and a revisit condition;
- a durable performance-strategy acceptance or rejection;
- an external reference or mechanism boundary (what is deliberately NOT implemented here).

## What does not belong in an ADR

- temporary PR progress or current-task narrative (belongs in the PR/issue);
- today's CI failure or a debugging diary (belongs in the PR/issue, then Git history);
- migration checklists (belongs in the release notes of the breaking release);
- anything whose truth depends on the current date rather than the current tree.

## Conventions

- Files are numbered `NNNN-kebab-case-title.md`; the next number is
  (highest existing number) + 1. Numbers are never reused, and accepted ADRs are
  never edited to change their decision — superseding decisions cite their
  predecessor and state the delta.
- Each ADR carries a `Status` line: `Accepted`, `Superseded by ADR NNNN`, or
  `Rejected`. The canonical language is English; ADRs are not translated.
- Evidence referenced by an ADR lives in `benchmarks/evidence/` when it is a
  compact durable object; larger historical runs live in Git history or release
  artifacts, cited by identity (SHA-256, tag, or commit), never by local path.
- The [documentation index](../en/index.md) and this README must stay consistent
  about the ADR set. `cargo dev docs check` validates links across the tree.

## Index

| ADR | Decision | Status |
| --- | --- | --- |
| [0001](0001-start-with-a-single-cargo-package.md) | Start with a single Cargo package | Accepted; partially superseded (Linux ABI extracted into `crates/rr-linux`) |
| [0002](0002-io-uring-removed.md) | io_uring relay backend removed | Accepted |
| [0003](0003-do-not-stack-vless-encryption-on-reality.md) | Do not stack VLESS Encryption on REALITY | Accepted |
| [0004](0004-cover-derived-tls-handshake-shape.md) | Derive the TLS handshake shape from the cover | Accepted |
| [0005](0005-handoff-server-record-sequences.md) | Restore Handoff at server record sequence 0 or 1 | Accepted |
| [0006](0006-prebuilt-reality-cover-profiles.md) | Prebuilt REALITY cover profiles | Accepted |
| [0007](0007-adaptive-line-to-landing-warm-connections.md) | Adaptive LINE-to-LANDING warm connections | Accepted |
| [0008](0008-session-engine-runtime-and-transport-boundaries.md) | Session Engine, Runtime Adapter, and Transport boundaries | Accepted for incremental implementation |
| [0009](0009-durable-evidence-identity.md) | Durable evidence identity for replayable benchmark runs | Accepted |
| [0010](0010-rejected-connection-future-factory.md) | Rejected connection-future factory (per-connection task memory) | Rejected on measurement |
| [0011](0011-framed-loop-copy-allocation-complete.md) | The framed record loop is copy- and allocation-complete | Accepted (negative result) |
| [0012](0012-relay-buffer-hypothesis-rejected.md) | The relay-buffer throughput hypothesis is rejected on mechanism | Rejected on mechanism |
| [0013](0013-no-compiled-runtime-plan.md) | No compiled-runtime-plan construct | Accepted (negative result) |
| [0014](0014-benchmark-owned-whole-session-profiling.md) | Whole-session profiling is owned by the benchmark transaction | Accepted |
| [0015](0015-rr-linux-is-a-no-std-linux-abi-boundary.md) | `rr-linux` is a `no_std` Linux ABI boundary | Accepted |
| [0016](0016-protocol-core-is-no-std-ready-but-stays-in-place.md) | The protocol core is `no_std`-ready and stays in the main crate | Accepted (deferred action) |
| [0017](0017-relay-atomic-and-contention-hypotheses-rejected.md) | Relay atomic bookkeeping, pipe-cleanliness typestate, and pool contention | Rejected on measurement |
| [0018](0018-session-establishment-allocation-has-no-avoidable-headroom.md) | Session-establishment allocation has no avoidable headroom | Accepted (negative result) |
| [0019](0019-one-current-configuration-schema.md) | One current configuration schema | Accepted |
| [0020](0020-aws-lc-rs-computes-per-session-x25519.md) | `aws-lc-rs` computes the per-session X25519 agreements | Accepted on measurement |
