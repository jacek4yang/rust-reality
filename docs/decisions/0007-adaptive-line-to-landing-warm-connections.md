# ADR 0007: Adaptive LINE-to-LANDING warm connections

Status: Accepted

Date: 2026-08-25

## Context

Handoff, NXR, and SOCKS5 previously opened a fresh TCP connection to their
fixed upstream for every user flow. That made the LINE-to-LANDING or upstream
TCP three-way handshake part of the user-visible setup path. ADR 0006 already
introduced a bounded, generation-owned `AdaptiveTcpPool` for protocol-neutral
TCP establishment. A second pool implementation would duplicate its adaptive
controller, descriptor authority, pressure behavior, and reload rules.

Handoff and NXR LANDING listeners previously started their short
authentication timeout as soon as TCP was accepted. Such a listener closes a
legitimate warm socket before a later user can check it out. Merely extending
that deadline would instead let a peer send one byte and retain parser state
for the full idle lifetime.

## Decision

The existing adaptive pool is reused for fixed Handoff, NXR, and SOCKS5
outbounds. It owns TCP establishment only. Each READY socket is checked out at
most once, becomes permanently session-owned, and is never returned to the
pool. A checkout miss immediately uses the existing cold dial while waking
background refill. No checkout ping, application heartbeat, multiplexing, or
protocol pre-authentication is introduced.

Handoff and NXR LANDING listeners use two pre-authentication phases:

```text
ACCEPTED -> PRE_AUTH_IDLE -> AUTHENTICATING -> AUTHENTICATED -> RELAY
```

`PRE_AUTH_IDLE` reads only the first protocol byte under
`preAuthIdleTimeoutMs`. It holds a distinct, finite admission permit and does
not allocate the complete request, perform protocol cryptography, reserve
replay state, resolve DNS, connect a destination, or send a response. Receipt
of the first byte releases that idle permit and begins the existing short
`authenticationTimeoutMs` deadline for the remaining request and validation.
The authentication permit is released before destination establishment.

**A warm TCP connection is only prepaid transport state. Before the first
protocol byte it is unauthenticated, bounded, idle state; after the first
protocol byte it enters the existing short authentication deadline. No
Handoff or NXR authority, replay state, destination side effect, or session
ownership is granted merely because the TCP connection was established in
advance.**

The default pre-auth idle lifetime is 60 seconds. For an obvious colocated
LINE/LANDING pair, configuration validation requires it to cover the smaller
of the LINE pool's idle and absolute lifetimes plus the short authentication
deadline, preventing predictable stale churn without coupling a LANDING-only
configuration to an unused LINE policy. Separate-node deployment preflight
must enforce the same relationship. `maxPreAuthIdleConnections` is a separate
LANDING ceiling, defaults to 1024, and cannot exceed `maxConnections`.

## Pool ownership and adaptation

Each compiled fixed-peer outbound in an immutable runtime generation owns one
optional pool. This identity naturally includes the protocol, peer address,
network generation, and the generation's Handoff/NXR key or SOCKS credential
material without deriving or logging a secret-bearing key. Reload creates new
pools; old pools stop refill, cancel speculative connects, close READY
sockets, and allow already checked-out sessions to finish.

The shared controller retains its bounded ready and connecting ceilings,
refill batch, EWMA arrival rate and connect latency, recent-burst headroom,
failure backoff, proactive low-watermark refill, and shrink hysteresis. One
controller owns a bounded `FuturesUnordered`; checkout does not spawn a dial
task. Maintenance wakes on work, dial completion, pressure transitions, and
the next real expiry/backoff/shrink deadline rather than polling every socket.

Every speculative socket holds the existing `FdBudget` and
`WarmPoolAuthority` permits. Descriptor or process pressure stops refill and
drains READY sockets. LANDING pressure also wakes and reclaims
`PRE_AUTH_IDLE` sockets. Active authenticated sessions keep their permits and
remain higher priority than actively authenticating sessions, which in turn
remain higher priority than unauthenticated idle transport state.

## Handoff semantics

A checkout constructs a completely fresh sealed Handoff transfer using a new
timestamp, nonce, ephemeral X25519 keypair, HKDF result, and AEAD ciphertext.
LANDING still performs the existing structure, timestamp, replay, static-key,
PSK, continuation, record-sequence, and first-downlink validation. A READY
socket is not an authenticated Handoff session.

Write progress defines the only bounded transport retry boundary:

- `NoBytesWritten`: discard the socket and make at most one cold fallback
  attempt with a newly sealed transfer.
- `PartialWrite`: discard permanently and, at most once, use a newly generated
  transfer on the cold fallback socket.
- `CompleteWrite`: never retry the logical session. LANDING may already have
  authenticated, connected the destination, or resumed TLS/Vision.

Late first downlink, first-downlink validation failure, destination failure,
or relay failure after a complete transfer remains a session failure. The
continuation and authenticated bytes are never replayed on another socket.

## NXR semantics

Every checkout creates a fresh timestamp, random nonce, encoded destination,
and HMAC. LANDING still validates structure, bounds, time, HMAC, and replay
before DNS resolution or destination connection. The same byte-counted retry
rules apply: at most one alternate before complete write, always with a newly
encoded authenticated request, and no retry after complete write.

## SOCKS5 semantics

Only TCP is prepared. Method negotiation, optional username/password
authentication, destination CONNECT, and relay begin after checkout. Protocol
or authentication rejection is final; a safely classified transport failure
before CONNECT may use the bounded alternate/cold path. `warmTcp: false`
disables preparation for upstreams with short idle timeouts or strict
connection quotas. Credential identity is isolated by immutable outbound
generation. Prepared/authenticated SOCKS state is deliberately excluded.

## Stale sockets, failure, and fallback

READY sockets use passive local error readiness plus idle and maximum lifetime
bounds. They do not perform a checkout round trip. A stale checkout is
discarded, records a fixed-cardinality transport metric, accelerates refill,
and follows the bounded retry rules above. Background connect failures use
capped exponential backoff with jitter; user-triggered cold dials never wait
behind it. Correctness never depends on warm availability.

## Security consequences

Firewall restriction to LINE source addresses remains mandatory for Handoff
and NXR, but source address is not authentication. Fresh protocol
authentication and replay protection remain mandatory on every checked-out
connection. No Handoff state, NXR request, SOCKS credential, user identity,
destination, or endpoint-derived pool key is logged. Metrics expose only the
fixed transport classes `handoff`, `nxr`, and `socks5`.

The finite LANDING idle ceiling adds intentional unauthenticated TCP state but
does not grant protocol authority or destination side effects. Pressure and
reload reclaim that state before active sessions. A peer that sends one byte
cannot inherit the long idle lifetime because the short authentication
deadline starts immediately.

## Performance evidence

Release evidence must compare cold and warm Handoff, NXR, and SOCKS5 at 1, 10,
50, 100, and 200 ms controlled one-leg RTT, retain raw startup-aware hit/miss
and stale counters, cover concurrency 1/8/32/128/512 where the host permits,
and include burst and idle-age matrices. The claim is deliberately narrow:
on a valid warm hit the user does not wait for a new LINE-to-LANDING/upstream
TCP handshake. Protocol responses, destination setup, and propagation remain.

An instrumented build may attribute phases, but headline numbers must come
from the exact optimized release candidate. Real-WAN evidence supplements
netem when suitable hosts exist and is not substituted for deterministic
mechanism tests. ADR 0006's authenticated prebuilt-cover and active-probe
evidence must remain non-regressed.

## Limitations and revisit criteria

Instantaneous unbounded demand can miss. Middleboxes may silently expire idle
sockets, and arbitrary SOCKS5 servers can have incompatible connection-limit
policies. Operators can disable warming per outbound, while bounded stale
fallback preserves correctness.

SOCKS pre-authentication, application heartbeat, multiplexing, QUIC, TLS 1.3
0-RTT, REALITY EarlyData, application early data, and Handoff wire redesign
require separate protocol and threat-model decisions. They are not part of
this ADR.
