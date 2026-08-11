# ADR 0004: Derive the TLS handshake shape from the cover

- Status: accepted for v1.4
- Date: 2026-08-11

## Context

REALITY must preserve the configured cover's ServerHello. The v1.3 server did
so, but put all post-ServerHello handshake plaintext in one compact encrypted
record. A controlled four-way comparison reused the same stock Xray/uTLS
ClientHello and REALITY identity against v1.3, the v1.4 candidate, Xray, and a
pinned OpenSSL reference. The encrypted post-ServerHello record lengths were:

| TLS 1.3 case | v1.3 | OpenSSL reference and Xray | v1.4 |
| --- | --- | --- | --- |
| AES-128-GCM/SHA-256, hybrid group | `331` | `32, 833, 281, 53` | `32, 833, 281, 53` |
| AES-128-GCM/SHA-256, X25519 | `331` | `32, 833, 281, 53` | `32, 833, 281, 53` |
| AES-256-GCM/SHA-384, hybrid group | `347` | `32, 833, 281, 69` | `32, 833, 281, 69` |
| ChaCha20-Poly1305/SHA-256, hybrid group | `331` | `32, 833, 281, 53` | `32, 833, 281, 53` |

The reference was official OpenSSL tag `openssl-3.5.6`, commit
`286ddeaac037533bbdce65b3c689e3f7ffebf0f6`, built static with
`no-shared`, `no-module`, and `no-legacy`. Its identities were:

- `libssl.a` SHA-256
  `9f4418b3c0f87917661e3b678870cefe315ad821a804e5f424f137c94c6797dd`;
- `libcrypto.a` SHA-256
  `e12443fa2f114bc673b8565699ceb0b6d9f1c1f76b62f3271c86e683a296a16d`;
- reference binary SHA-256
  `c2baaadd2568df8b8e272df10cd88310d119c59d916e0a3c77604c690e0fee3b`;
- reference binary GNU Build ID
  `9b151403598d429664aa3da45d4af8f376a15522`.

The harness also verified the reference's compile-time and run-time identity as
OpenSSL 3.5.6, compiler 14.2.0, the default provider only, and configuration
loading disabled. The binary had no dynamic libssl or libcrypto dependency.

A three-sample cover corpus showed why a fixed OpenSSL record profile is not
valid. The local pinned reference consistently used four encrypted records;
`www.microsoft.com` also used four (`36, 8268, 281, 69`), while
`dl.google.com` consistently coalesced the flight into one `3842`-byte record.
Certificate and deployment choices therefore dominate some record lengths.
The lengths quoted in this ADR are TLS record body lengths; on the wire each
record adds its five-byte header.

## Decision

Keep the cover-derived ServerHello authoritative and derive the encrypted
handshake record plan from the cover's post-ServerHello flight:

- preserve the exact compatibility CCS (`14 03 03 00 01 01`) and its position;
- when the cover's first encrypted record is at most 512 wire bytes, retain the
  four positional cover record lengths;
- when it is greater than 512 wire bytes, retain the cover's coalesced wire
  length;
- authenticate only bounded zero padding needed to realize those lengths; and
- retain a hard 66,125-byte bound on the captured cover prefix.

The 512-wire-byte threshold distinguishes the two stable corpus classes; it is
not an OpenSSL constant or a claim about every cover. The plan is internal and
bounded. It adds no configuration surface and no dependency.

Record shaping occurs only after the handshake messages and transcript have
been constructed. Tests prove that concatenated authenticated handshake bytes
are unchanged, every shaped record consumes exactly one handshake record
sequence number, Client Finished still verifies, and the application traffic
sequence begins unchanged. Handoff and Vision Direct therefore retain their
existing application-record ownership and transition boundaries.

The complete ServerHello, CCS, and encrypted handshake flight remains one
contiguous process write. On the pinned local reference, shaping added 883 wire
bytes but no write call. The process syscall names still differ (`sendto` in
rust-reality and `write` in the reference), so only write count and size—not
syscall identity—are aligned there.

## Consequences

The v1.4 server is OpenSSL-reference-aligned on the measured local TLS record
count, record lengths, first-flight byte count, and process write size. It is
also cover-aligned for the measured Microsoft four-record and Google coalesced
classes. This is not a claim that its traffic is indistinguishable from
OpenSSL, Xray, or any cover.

The adaptive read adds about 3.4 additional cover `recvfrom` calls per setup
connection in the controlled 768-connection c1 syscall trace. Repeated setup
profiling measured a 0.26% setup-rate decrease,
a 1.86% task-clock/connection increase, and a 2.11% cycles/connection increase,
all within the setup budget. The controlled Direct workload measured +0.26%
throughput, -1.87% task clock/GiB, and +1.03% cycles/GiB; no steady-state cost or
new material userspace hotspot was established.

TCP segmentation and PSH placement remain `NETWORK_DEPENDENT`; equal raw
packet sequences on loopback do not generalize across kernels, offload, MSS,
or networks. Instrumented timing samples are `NOT_COMPARABLE` with untraced
production timing, and the small public corpus does not establish universal
cover behavior. Application-data recordization is unchanged.

The policy makes the cover flight an admission contract for authenticated
clients. A cover must emit the middlebox-compatibility CCS immediately after
its ServerHello; TLS 1.3 covers that legitimately omit CCS (for example when
the mirrored ClientHello carries an empty legacy session ID) fall back. In the
positional class the cover must present four encrypted records whose lengths
each fit the generated message; covers that coalesce a small flight into fewer
records, or whose per-position lengths are smaller than the generated
EncryptedExtensions/Certificate/CertificateVerify/Finished messages, fall
back. In the coalesced class a first encrypted record between 513 wire bytes
and the generated flight size falls back, and a cover whose flight continues
past a large first record is matched with a single coalesced record rather
than its true multi-record shape. Every one of these mismatches fails closed:
the already authenticated client is spliced to the cover byte-exactly, exactly
as an unauthenticated probe is. Stock Xray fingerprints send a session ID and
negotiate the measured classes, so mainstream clients are unaffected, but
these combinations are deterministic per (client fingerprint, cover) pair and
are documented here as the known incompatibility classes of v1.4.

Fixed padding and random padding profiles were rejected because they discard
cover evidence or add unjustified variability and overhead. Full libssl
termination was not attempted: it lacks a justified, supported route for
preserving cover-derived ServerHello semantics, REALITY state, Handoff record
state, and Vision Direct. OpenSSL EVP experiments for AES-128-GCM,
AES-256-GCM, ChaCha20-Poly1305, hashes/HKDF, and X25519 were all rejected by
the end-to-end keep gates. The shipped provider choices and dependency model
remain unchanged.

## Revisit criteria

Revisit only if a broader reproducible cover corpus invalidates the two-class
policy, stock Xray interoperability changes, or a provider/library experiment
passes both the protocol-state requirements and the end-to-end performance
gate. Do not tune the policy to TCP packetization or one site's transient
certificate flight.
