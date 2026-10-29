# ADR 0062: P-256 for browser TLS key shares

Status: Accepted

## Context

Browser ClientHello profiles can carry a secp256r1 key share alongside X25519
and X25519MLKEM768. Omitting that share changes the observable fingerprint;
advertising an unusable share violates the TLS negotiation contract. The
existing X25519 implementation does not implement P-256 arithmetic.

## Decision

Extend ADR 0028's provider set narrowly with RustCrypto `p256` 0.14.0, with
default features disabled and ECDH enabled. `crypto::p256_ecdh` is the only
production module permitted to name the provider. Retain ADR 0023's unsafe
boundary unchanged: no new unsafe code, handwritten arithmetic or provider
framework is introduced. The existing X25519 and hybrid implementations remain
the authorities for their groups.

Generate a fresh scalar from `crypto::entropy` by bounded rejection sampling.
Temporary scalar bytes and agreed secrets use zeroizing storage. The provider
owns scalar validation and zeroization of its secret key. Each non-clonable
ephemeral owner is consumed by agreement. Only TLS 1.3 uncompressed 65-byte
SEC1 public points are accepted; infinity, off-curve coordinates, compressed
representations and wrong lengths fail closed.

P-256 is TLS key agreement only. REALITY's X25519-based authentication,
session-ID sealing, transcript, certificate authentication and Finished checks
are unchanged. A profile may advertise P-256 only after its production
negotiation path retains and uses the corresponding private state. A standalone
primitive test is not a browser fidelity or authenticated-session verdict.

## Validation and consequences

Keep exact provider ownership enforced by `crypto_boundary`. Test valid
agreements against the existing dev-only AWS-LC oracle and reject malformed
encodings at the boundary. Fuzz peer-share parsing. Locked production and
tooling dependency policies and supported architecture qualification remain
required. Upstream implementation tests are not a proof of this integration.

P-256 adds handshake work for profiles that actually offer it; it must not add
work to TLS record processing. Measure its intrinsic profile cost separately
from implementation regressions against the pinned pre-fingerprint binary.
No performance result is implied by selecting this provider.

## Revisit conditions

Revisit for a provider security defect, an unsupported release target, or
measured whole-product evidence justifying another provider. Adding another
browser name alone does not justify another cryptographic implementation.
