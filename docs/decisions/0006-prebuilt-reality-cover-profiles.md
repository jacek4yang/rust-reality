# ADR 0006: Prebuilt REALITY cover profiles

Status: Accepted

Date: 2026-08-24

## Context

An authenticated REALITY handshake currently opens a TCP connection to the
configured cover, forwards the exact ClientHello, and waits for the cover's
TLS 1.3 flight before constructing the local REALITY flight. This deliberately
makes the cover authoritative for ServerHello semantics and record shape, and
it also preserves an exact fallback path for every rejected or incompatible
handshake. On a remote cover, however, the authenticated critical path pays a
TCP handshake RTT and a ClientHello-to-server-flight RTT.

Caching only the cover certificate is incorrect. The cover selects the cipher
suite, key-share group, ServerHello extension structure and order, ALPN
behavior, compatibility CCS behavior, and encrypted-flight record shape. The
REALITY certificate and all ephemeral handshake state must still be generated
fresh for each authenticated connection.

## Decision

The optimization has three strictly ordered tiers.

1. Before successful REALITY authentication and replay reservation, traffic
   always uses the live cover path. Malformed input, unsupported ClientHello,
   wrong SNI, invalid short ID, invalid authentication, and replay never
   consult a profile and never receive a locally synthesized TLS response.
2. After authentication, a profile miss uses a single-use TCP connection from
   a bounded adaptive warm pool. The socket is only TCP-established: no TLS
   byte is sent before checkout. The exact current ClientHello is forwarded and
   the existing strict cover-flight reader remains authoritative. A stale warm
   socket is discarded without a checkout probe RTT; bounded retry then falls
   back to the existing cold connect.
3. After authentication, a validated profile hit may reconstruct the observed
   cover class locally. The profile contains stable presentation and shape
   metadata only. Server random, echoed session ID, ephemeral key exchange,
   handshake/application traffic secrets, REALITY certificate binding,
   CertificateVerify, Finished, and record sequence state are regenerated for
   every connection. Any uncertainty is a profile miss and returns to tier 2.

Tier 1 is implemented and measured before tier 2 is enabled.

## Warm TCP ownership

Each immutable runtime generation owns one pool per enabled REALITY cover.
Ready sockets are bound to that generation, target, network policy, and the
resolved endpoint selected by the existing connector. Their lifecycle is:

```text
CONNECTING -> READY -> CHECKED_OUT -> COVER TRANSACTION -> CLOSED
                  \-> STALE/CANCELLED -> CLOSED
```

A checked-out socket never returns to the pool. The descriptor permit follows
the socket through checkout and fallback relay. Publication deactivates the
old generation synchronously: it stops refill and closes idle sockets, while
already checked-out sessions retain ownership and finish normally. The new
generation warms asynchronously and never blocks listener startup.

One controller task owns a bounded `FuturesUnordered` set of connect futures;
there is no task spawned per dial and its cardinality never exceeds
`maxConnecting`. Checkout only takes a short control-plane lock, transfers
socket ownership, and leaves no pool synchronization in the TLS or relay data
path. Crossing the low watermark wakes the controller. Misses perform a normal
cold connect rather than waiting for refill.

## Adaptive controller

The controller tracks ready and connecting counts, checkout hits and misses,
an EWMA of arrival rate, an EWMA of connect latency, a decaying recent burst,
idle age, and connection failures. It estimates the ready target from arrival
rate times establishment latency plus conservative burst headroom. Misses
accelerate bounded growth. Shrink starts only after a cooldown and removes
idle excess gradually. Low/high watermark hysteresis and a bounded refill
batch prevent oscillation and dial storms.

Arrival adaptation is demand-driven at a 100 ms minimum interval from checkout
and dial-completion events. A resettable 500 ms quiet-pool deadline handles
expiry, backoff recovery, and shrink; real demand resets it because those same
events already perform due maintenance. This avoids a periodic wakeup during
continuous traffic and does not impose the original 10 Hz timer on every idle
pool. The split was retained only after `perf stat` showed that the unconditional
timer materially increased context switches and CPU per setup connection.

Background failures use capped exponential backoff with endpoint-derived
jitter. User-flow cold connects do not wait behind that backoff. Idle health is
checked with local socket error/readiness state plus idle and absolute lifetime
bounds; checkout never sends a ping or waits for a response.

## Resource accounting

Every connecting and ready socket holds the existing strict `FdBudget` permit.
A process-lifetime warm-pool authority also caps speculative connecting and
ready ownership across immutable generations, while each endpoint retains its
own smaller bounds for fairness. Descriptor or process pressure stops refill
and drains speculative idle sockets before normal active traffic is denied.
All permits are RAII-owned and cancellation-safe.

The configured theoretical descriptor peak includes ready sockets and bounded
parallel dial candidates. Pools, tasks, retained sockets, observations, and
metrics all have fixed upper bounds.

## Cover profiles

The later immutable `CoverProfile` cache is keyed by a conservative normalized
ClientHello class and cover identity. Random, session ID, ephemeral key-share
bytes, REALITY authentication ciphertext, and proven non-reflected GREASE may
be excluded only after deterministic differential tests. ALPN, cipher offers,
supported versions, key-share groups, signature algorithms, extension
structure/order, and hybrid capability remain class inputs where they can
change cover behavior. False misses are preferred to false hits.

Profiles are produced only by bounded controlled probes using the production
parsers. User traffic may report disagreement but cannot publish profile
semantics. Several identical observations are required before an immutable
generation becomes `Validated`; `Unavailable`, `Collecting`, `Stale`,
`Unstable`, and `Disabled` states always select the live cover. Profiles are
ephemeral initially, expire, refresh with bounded jitter, and are never reused
across configuration generations unless a later decision proves that safe.

The implementation does not support cover-selected TLS 1.3 PSK/resumption or
early data. Such observations are profile misses.

## Security consequences

The authenticated optimization path remains unreachable without successful
REALITY authentication and replay reservation. A captured ClientHello replay
therefore follows the real-cover fallback path. If target parsing, profile
classification, flight sizing, fresh cryptography, or resource admission is
uncertain, the implementation uses the real cover instead of guessing.

The project does not claim universal TLS indistinguishability. It reproduces
validated cover semantics for narrowly classified ClientHello profiles and
falls back to the live cover whenever confidence is insufficient. TCP segment
boundaries, PSH flags, and one host's offload behavior are not treated as
authoritative TLS fingerprints; protocol-visible record and negotiation
semantics are.

## Validation

Release evidence must retain cold-live, warm-live, and prebuilt raw samples at
controlled cover RTTs. It reports profile and pool misses rather than dropping
them. A differential corpus compares semantic ServerHello fields, CCS
position, ALPN, encrypted record counts and outer lengths, and optional
post-Finished shape while requiring random and secret values to differ.

Long wall-clock checks are not required to validate logical lifetime bounds:
deterministic state-machine tests and accelerated short-duration concurrency
soaks cover expiry, backoff, shrink, reload, cancellation, and pressure. A
longer soak remains release evidence only when it measures a property that
cannot be accelerated honestly.

## Revisit criteria

Multi-modal profile sampling, persistent profile storage, application-level
cover keepalive, or broader ClientHello normalization require a separate ADR
and new differential evidence. They are not part of this decision.
