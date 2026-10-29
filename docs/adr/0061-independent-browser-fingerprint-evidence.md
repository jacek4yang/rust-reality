# ADR 0061: Independent browser fingerprint evidence

Status: Accepted

## Context

Browser-shaped ClientHellos cannot be validated solely by the serializer's own
parser, or by comparison with another emulation library. Browser executables
run on native Windows while the production crate and rr-dev have Linux-specific
platform dependencies. Importing production into a collector both defeats this
platform boundary and risks circular verification.

## Decision

`tools/rr-fingerprint` is an independent, cross-platform tooling workspace
member. It owns bounded raw TLS capture decoding and browser evidence tooling.
It has no dependency on the production crate, rr-session, or the production
ClientHello implementation. This crate represents a real platform and reference
boundary, not a separate production client. It is never packaged for operators.

Genuine, officially distributed, version-pinned browsers are the primary
ClientHello oracle. Pinned unmodified Xray is a secondary comparator. Preserve
raw TLS record boundaries, capability order, extension bodies, and relationships
between ephemeral shares. Any normalization must be explicit and separately
reviewed. Unknown extensions remain observable. JA3/JA4 cannot establish parity
by themselves.

Reference evidence binds browser and driver versions and hashes, OS and runner
image, launch conditions, and a successful HTTPS transaction. Immutable fixtures
qualify releases; live browser collection only detects drift and proposes an
explicit update. Browser updates never change production aliases automatically.
Missing or unexplained differences cannot produce a passing fidelity verdict.
The first tooling slice provides a lossless decoder; it does not itself certify
any browser profile or implement production fingerprint selection.

## Consequences

The tooling workspace's existing format, clippy and test gates cover this new
member. Its decoder ships with fuzz coverage. Native-platform execution tests
remain necessary; compiling on Linux is not proof of Windows browser capture.
Machine-readable evidence belongs under benchmarks, documentation under docs,
and current work belongs in PRs and Issue #325.

REALITY authentication and VLESS session behavior are separate protocol
contracts. ClientHello fidelity does not imply full browser traffic equivalence.

## Revisit conditions

Revisit this boundary only if the native platforms or independence requirement
changes. More browser names alone do not justify additional production paths.
