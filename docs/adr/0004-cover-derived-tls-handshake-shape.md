# ADR 0004: Derive the TLS handshake shape from the cover

- Status: accepted for v1.4; amended for v1.5
- Date: 2026-08-11
- Last amended: 2026-08-12

## Context

REALITY must preserve the configured cover's ServerHello. Before v1.4,
rust-reality put all post-ServerHello handshake plaintext in one compact
encrypted record. A controlled four-way comparison reused the same stock
Xray/uTLS ClientHello and REALITY identity against v1.3, the v1.4 candidate,
Xray, and a pinned OpenSSL reference. The encrypted post-ServerHello record
body lengths were:

| TLS 1.3 case | v1.3 | OpenSSL reference and Xray | v1.4 |
| --- | --- | --- | --- |
| AES-128-GCM/SHA-256, hybrid group | `331` | `32, 833, 281, 53` | `32, 833, 281, 53` |
| AES-128-GCM/SHA-256, X25519 | `331` | `32, 833, 281, 53` | `32, 833, 281, 53` |
| AES-256-GCM/SHA-384, hybrid group | `347` | `32, 833, 281, 69` | `32, 833, 281, 69` |
| ChaCha20-Poly1305/SHA-256, hybrid group | `331` | `32, 833, 281, 53` | `32, 833, 281, 53` |

The reference was official OpenSSL tag `openssl-3.5.6`, commit
`286ddeaac037533bbdce65b3c689e3f7ffebf0f6`, built static with `no-shared`,
`no-module`, and `no-legacy`. Its identities were:

- `libssl.a` SHA-256
  `9f4418b3c0f87917661e3b678870cefe315ad821a804e5f424f137c94c6797dd`;
- `libcrypto.a` SHA-256
  `e12443fa2f114bc673b8565699ceb0b6d9f1c1f76b62f3271c86e683a296a16d`;
- reference binary SHA-256
  `c2baaadd2568df8b8e272df10cd88310d119c59d916e0a3c77604c690e0fee3b`;
- reference binary GNU Build ID
  `9b151403598d429664aa3da45d4af8f376a15522`.

A small cover corpus showed why a fixed OpenSSL profile is invalid. The local
reference and Microsoft used four encrypted records while Google coalesced its
flight. Certificate and deployment choices dominate some outer lengths. The
lengths above are record body lengths; each record adds a five-byte wire header.

The original v1.4 reader treated compatibility CCS as mandatory, retained at
most 66,125 cover-prefix bytes, and always handed application record sequence
0 to the established session. That was a deliberately narrow first release of
cover-derived shaping, not a permanent statement about valid TLS 1.3 servers.
Further evidence found legitimate covers without CCS and flights with a fifth
encrypted post-Finished record. v1.5 therefore needs a broader, still-bounded
model without weakening byte-exact fallback.

## Decision

Keep the cover-derived ServerHello authoritative. Build an internal
`CoverHandshakePlan` from the bounded observed cover flight; do not expose a
runtime shape or performance switch.

For v1.5:

- compatibility CCS is optional, and its presence and position are reproduced;
- the encrypted handshake is represented by the observed coalesced shape or by
  four positional records for EncryptedExtensions, Certificate,
  CertificateVerify, and Finished;
- an optional fifth encrypted record after Finished is represented by one
  empty TLS 1.3 ApplicationData record. This is a *fake NST shape record*: it
  contains no NewSessionTicket message, ticket, PSK, or resumption state;
- refills read no more than 4 KiB at a time. Fifth-record discovery consumes
  already-buffered bytes first and otherwise makes at most one nonblocking
  probe of no more than 512 bytes;
- every inspected cover byte is retained for fallback, with a hard 66,642-byte
  maximum retained prefix; truncation, length overflow, an oversized prefix,
  or an unrealizable positional length fails closed before the REALITY flight;
- handshake messages and transcript are constructed exactly once. Only record
  boundaries and authenticated zero padding are shaped, and the complete
  server flight remains one contiguous process write.

The fake NST shape record is sealed with the server application traffic key at
sequence 0 after Finished. Consequently, the established server application
record layer starts at sequence 1 when it is emitted and sequence 0 otherwise.
The client application sequence still starts at 0. Handoff transfers and
restores the actual sequence; ADR 0005 records its mixed-version consequences.

The old 512-wire-byte classifier remains an observed policy boundary, not an
OpenSSL constant or a universal TLS claim. Fixed and random padding profiles
remain rejected because they discard cover evidence or add unjustified
variability and cost.

## Consequences

The current policy accepts the measured four-record and coalesced classes,
optional compatibility CCS, and an optional fifth post-Finished shape. It is
not a claim that rust-reality traffic is indistinguishable from OpenSSL, Xray,
or any cover. TCP segmentation and PSH placement remain network-dependent.

Xray 26.7.28 end-to-end gates passed with Microsoft, Google, and Fastly public
covers. A local OpenSSL 3.5.6 cover that omits CCS also passed. Each case
verified an exact 1 MiB SHA-256 transfer and ML-DSA-65 key compatibility. The
public corpus is still small, and these are correctness results rather than
performance samples.

Three warmed balanced setup ABBA blocks against immutable v1.4 measured
candidate/baseline medians of -0.38% at c1 (95% interval -0.465% to +0.170%),
+0.26% at c8 (-3.368% to +2.497%), and +0.53% at c32 (-1.257% to +1.557%).
All intervals cross no difference. Normalized task-clock and instructions
changed by -0.768% and -0.190%; context switches changed by +1.042%, about
+0.058 per connection. A separate current trace measured 4.0013 fewer
`recvfrom` calls per candidate connection. Its instrumented elapsed time is
not compared with the uninstrumented ABBA.

Two balanced six-path matrix rounds (bidirectional, Direct download/upload,
fallback, and framed download/upload) each retained 219 samples with zero
invalid samples and exact payload integrity. Every throughput and latency 95%
block-bootstrap interval crossed no difference. Direct upload's median ratio
reversed from 0.9511 to 1.1390 between rounds, confirming order/host noise.
The result establishes no statistically significant protected-path regression
or performance win.

Unsupported, malformed, truncated, oversized, or internally inconsistent
cover flights still fail closed. The authenticated client rejoins the cover
with every already consumed byte replayed exactly once. The wider model does
not convert uncertain input into an accepted REALITY handshake.

Full libssl termination remains rejected: it offers no justified supported
route for preserving cover-derived ServerHello semantics, explicit record
state, Handoff, and Vision Direct. Earlier OpenSSL EVP provider experiments
also failed the end-to-end keep gates; the provider and dependency model are
unchanged.

## Revisit criteria

Revisit if a broader reproducible cover corpus invalidates the bounded shape
model, stock Xray interoperability changes, the fake NST shape becomes
observable as a compatibility problem, or a provider experiment passes both
the protocol-state requirements and end-to-end performance gates. Do not tune
the policy to TCP packetization or one site's transient certificate flight.
