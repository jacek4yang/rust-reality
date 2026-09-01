# Threat model

English | [简体中文](../zh-CN/threat-model.md)

## Protected data path

```text
Xray-compatible client
  -> VLESS + REALITY + xtls-rprx-vision public listener
  -> UUID policy on the line node
  -> direct | SOCKS5 | blackhole | NXR | Handoff
  -> optional firewall-restricted NXR or Handoff landing node
  -> destination
```

The public listener always requires TCP, REALITY, VLESS decryption `none`, and
the Vision flow. A configuration that attempts plain VLESS is rejected before
listeners are bound.
Configured server names may be concrete DNS names or a leftmost one-label
pattern such as `*.lmu.edu`; the ClientHello SNI must remain concrete.
Every configured UUID owns a non-empty set of globally unique short IDs. The
REALITY phase resolves the presented short ID directly to its unique owner;
after the encrypted VLESS header is decoded, authorization requires its UUID to
equal that owner. This two-stage binding prevents cross-account UUID/short-ID
mixing.

## Security objectives

The public entry is designed to resist unauthenticated protocol identification,
active probing, captured-ClientHello replay, malformed or fragmented record
input, and local resource exhaustion. Authentication becomes committed only
after the expected TLS 1.3 ClientFinished is verified. Any earlier cancellation,
timeout, or failure rolls back the pending replay reservation.

Authentication failures do not receive a synthetic proxy response. Every byte
already consumed from the peer is forwarded to the configured REALITY target,
in order, before live relay begins. Fallback concurrency and lifetime are
bounded independently from authenticated connections.

Cover warm pooling does not change that boundary. An idle pooled socket grants
no authority and contains no TLS state. Only a successfully authenticated,
replay-reserved handshake may check one out; every failure category opens its
own real-cover connection exactly as before. Ready and connecting sockets are
strictly bounded, FD-accounted, generation-isolated, and discarded under
resource pressure before speculative warming can compete with active traffic.

Prebuilt profiles preserve the same unauthenticated boundary. Profile lookup
is unreachable until authentication and replay reservation succeed. A bounded
collector, not arbitrary user observations, is authoritative; it publishes
only after four controlled responses agree. Profiles erase cover random,
session ID, ephemeral key exchange, and traffic secrets, expire with jitter,
and never cross configuration generations. Unknown GREASE/ECH shapes,
unsupported PSK, unexpected EncryptedExtensions, profile disagreement, stale
state, or local-flight sizing failure selects live cover instead of guessing.
An authorized client can at most consume one of 16 bounded nomination slots;
it cannot publish cover semantics or influence an existing validated profile.

This does not claim universal TLS indistinguishability. The narrower objective
is no clear deterministic semantic difference for a validated class: selected
version, cipher, group, ServerHello extension order, ALPN, compatibility CCS,
and outer record plan follow controlled cover evidence, while random and secret
fields must vary. Active unauthenticated probes and captured replays continue
to receive only real-cover behavior.

Fixed-peer transport warming preserves the Handoff, NXR, and SOCKS5 protocol
boundaries. A checked-out socket is single-use; it is never returned to READY
and carries no authenticated user, key agreement, replay reservation,
destination, or SOCKS authorization. Firewall source restriction remains an
additional deployment boundary for Handoff and NXR, never a replacement for
fresh per-flow authentication.

**A warm TCP connection is only prepaid transport state. Before the first
protocol byte it is unauthenticated, bounded, idle state; after the first
protocol byte it enters the existing short authentication deadline. No
Handoff or NXR authority, replay state, destination side effect, or session
ownership is granted merely because the TCP connection was established in
advance.** LANDING admits that idle state under its own finite ceiling and
reclaims it on pressure or generation replacement. The first byte immediately
starts the short deadline, so a slowloris cannot inherit the long warm-idle
lifetime.

Configuration, routing assets, users, REALITY state, and outbounds are published
as one immutable generation. A failed refresh keeps the last complete snapshot.
Private keys, UUIDs, NXR PSKs, Handoff PSKs and static keys, credentials, and
full configurations are excluded from structured logs.

VLESS Encryption is not an additional objective for the mandatory REALITY
profile. The outer TLS 1.3 record layer already supplies confidentiality,
integrity, and forward-secret traffic keys; stacking another data AEAD would
disable the supported Vision raw/splice path. The security/performance decision
and its revisit gates are recorded in
[ADR 0003](../adr/0003-do-not-stack-vless-encryption-on-reality.md).

## NXR boundary

NXR is an internal replacement for unauthenticated SOCKS-style line-to-landing
access, not for the public protocol. Each user TCP flow owns one NXR TCP
connection and sends exactly one bounded request containing a version, target,
timestamp, random nonce, and HMAC under an independent 32-byte PSK.

The landing node checks structure, time, HMAC, and a bounded nonce replay cache
before DNS resolution or a destination connection. Failure is a silent close.
Success switches permanently to raw bidirectional bytes with half-close. There
is no TLS, REALITY, AEAD, certificate, multiplexing, persistent framing,
or post-authentication encryption in NXR. Its listener should be reachable only
from the line node's source IP at the firewall.

Because post-authentication NXR traffic is plaintext, anyone who can observe or
modify the private hop can observe or modify payload not protected by an
end-to-end protocol such as HTTPS. Use a private network or a different secured
transport when that threat exists.

## Handoff boundary

Handoff transfers an accepted session's full TLS ownership from the line node
to a landing node over one single-flight channel. The transfer message carries
the session's traffic keys, so the channel is sealed: a fresh ephemeral X25519
exchange against the landing node's static key, mixed with the pair PSK in one
HKDF-SHA256 chain, one ChaCha20-Poly1305 seal with the entire header as
associated data. AEAD open success is the mutual key confirmation: the landing
node proves its static key, the line node proves the PSK. Replay protection is
a timestamp window plus a bounded nonce cache, checked before any key-agreement
work.

Forward secrecy is bounded by the landing node's static key: compromising that
key retroactively exposes every recorded transfer it answered, and with them
the transferred sessions. Rotate the static key to bound that window. During a
zero-downtime rotation the landing may still accept retired keys from its
`previousPreSharedKeys`/`previousPrivateKeys` lists, and the forward-secrecy
bound holds only after those previous static keys are dropped. After the
transfer, the hop carries only the session's TLS ciphertext, which the
endpoints' record AEAD still protects; an observer of the link sees record
sizes and timing, not payload.

Every transfer failure — structure, timestamp, replay, authentication, state —
closes silently with zero response bytes, and the line node resets the client
socket rather than serving the session locally. An attacker on the link who
lacks both secrets cannot decrypt, forge, or redirect a transfer, and cannot
inject into a transferred session without breaking its record AEAD; they can
still close connections (the client observes a reset) and burn bounded replay
entries with structurally valid forgeries, the same exposure the NXR cache
already accepts — the firewall, not the cache, is the rate limit. The listener
must be reachable only from the line nodes' addresses.

Two trust statements to accept explicitly: the landing node applies no routing
policy to the transferred destination — trust in the line node is absolute, so
a compromised line node turns the landing node into an internal dialer; and the
landing node holds live session keys for every transferred session, so its
memory is part of the session's secrecy boundary.

Handoff and NXR retries stop at the complete authenticated write. Before that
boundary at most one alternate transport is permitted and it uses a fresh
timestamp, nonce, Handoff ephemeral key/AEAD transfer, or NXR HMAC request.
After a complete write, LANDING may already have reserved replay state,
resolved or connected a destination, or resumed a session, so the logical flow
is never repeated because of a late close or response failure.

## Resource and kernel boundaries

All pre-authentication work, connections, fallbacks, cryptographic work, replay
entries, destination dials, relay buffers, and splice pipes have explicit
ceilings. The data path has no unbounded queue or cache. Protocol code denies
unsafe Rust.

The admission and replay clocks are bounded integer domains. A deadline that
cannot be represented, a replay-generation counter that is exhausted, or a
rate finer than one nanosecond per token is rejected as unavailable; arithmetic
must never turn saturation into successful admission. Every temporary replay
reservation owns an RAII permit and rolls back on parse failure, timeout,
cancellation, duplicate detection, allocation failure, and counter exhaustion.

Robustness is continuously checked by bounded parser fuzz targets, truncation
and field-mutation equivalence properties, and scheduled ASan/LSan plus TSan
gates. These tests do not claim mathematical absence of all defects, but they
make unhandled input, resource, arithmetic, and race states explicit release
criteria.

`fuzz/Cargo.toml` is the authoritative attack-surface inventory. Its current
targets cover raw VLESS/wire parsers, structured REALITY authentication and
replay state, Vision decoding and state transitions,
Handoff headers/blobs/opening and structured round trips, NXR round trips,
cover-flight parsing, TLS 1.3 record round trips, transcript hashing, strict
normalized ClientHello classification, controlled profile compatibility,
profile EncryptedExtensions parsing, ServerHello reconstruction,
configuration decoding, diagnostic rendering, and runtime-independent session
ownership and retry semantics. CI rejects undeclared
target source files and runs every declared target; whole-crate line coverage
is not treated as a substitute for these reachable boundaries.

The testing model is layered and no layer replaces another: byte-level wire
fuzzing and parser fuzzing remain authoritative for wire behaviour, semantic
event-sequence fuzzing covers ownership rules that only a sequence of events can
violate, and integration tests cover the assembled runtime.

The semantic layer is the `session_semantics` target. It drives the `rr-session`
Session Engine with arbitrary event sequences and no socket, clock, or runtime,
and asserts that a transport grant is issued at most once per direction, that the
two Vision directions never split a bilateral pair across arbitrary
interleavings, that per-direction state growth stays bounded by an independently
defined progress ladder, that a terminal direction stays terminal for the rest of
a sequence, and that an authenticated transfer never authorizes an attempt after
its irreversible `CommittedWrite` boundary. The single-step relations it relies
on — the legal transition table, the strict progress ordering, the
pair/directional rule, and where a grant may be planned — are proven
*exhaustively* against a hand-written reference model by the unit tests in
`crates/rr-session/src/vision.rs`, so neither layer is a restatement of the code
it checks. Replay double-commit and pre-authentication authority remain covered
by the structured REALITY authentication and Handoff/NXR round-trip targets,
because that state has not been extracted into the Session Engine.

Linux `splice` is permitted only after both sides are plaintext TCP sockets. It
cannot cross the REALITY/TLS application boundary. If bounded splice resources
are unavailable before transfer starts, relay falls back to bounded userspace
buffers.

## Non-goals

- The application cannot stop upstream volumetric DDoS from saturating the VPS
  link; provider filtering and firewall policy are required.
- REALITY does not make a compromised endpoint trustworthy.
- NXR does not provide payload confidentiality or integrity after its one-time
  authentication request.
- Microbenchmark results are not Internet throughput or latency guarantees.
- GeoIP and GeoSite lists are policy inputs, not security authorities.

## Kernel relay backends

Adding a kernel data path changes what an attacker can reach, so the boundary is
stated explicitly.

**A kernel backend never sees pre-authentication or framed traffic.** Each
direction has its own exact authenticated raw boundary, and a backend receives a
direction only after that direction has crossed it: after REALITY authentication
has failed and the connection has become a cover relay, after NXR authentication
has completed, or after a Vision direction has reached its exact authenticated
Direct boundary. A one-way Vision Direct direction is relayed on its own
(directional splice) while the opposite direction remains framed in userspace;
the bilateral, socket-reuniting splice is used only when both directions have
independently crossed their boundaries and pairing is safe.

**A backend cannot silently swallow bytes.** Fallback to another backend is only
possible while the shared transfer ledger reads zero in both directions; the
decline type cannot be constructed otherwise. After any transfer, an error ends
the connection.

**Unsafe code is contained.** `crates/rr-linux` is where Linux ABI `unsafe`
may live and denies `unsafe_op_in_unsafe_fn`; the protocol crate keeps
`unsafe_code = "deny"`. The crate reaches the kernel through reviewed `rustix`
APIs rather than hand-written ABI, and since abort authority became
ownership-bound no production `unsafe` block remains in it at all. Descriptor
lifetimes, socket options, abort semantics and the `/proc` parser have direct
tests. No eBPF is loaded: the privileged sockhash backend was removed (D7), so
the server needs no kernel-injection capability.

**Logs stay secret-free.** Decline reasons, phases and backend names come from
closed vocabularies. No UUID, key, PSK, SNI value, target address, configuration
body or payload byte reaches a log line from any of this work.
