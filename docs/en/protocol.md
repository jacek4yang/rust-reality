# Protocol overview

English | [简体中文](../zh-CN/protocol.md)

`rust-reality` exposes exactly one public protocol stack and two internal
hop protocols. This page summarizes what each is; the security properties and
trust boundaries are normative in [threat-model.md](threat-model.md).

## Public stack: VLESS + REALITY + Vision

```text
Xray-compatible client
  -> VLESS + REALITY + xtls-rprx-vision public listener
  -> UUID policy and routing on the server
  -> direct | block | SOCKS5 | NXR | Handoff outbound
  -> destination
```

- **REALITY** provides the camouflage and authentication outer layer. The
  server impersonates a configured TLS 1.3 cover target; a client proves
  possession of the per-user key material inside what looks like an ordinary
  TLS 1.3 handshake. Configured server names may be concrete DNS names or a
  leftmost one-label pattern such as `*.lmu.edu`; the ClientHello SNI must
  remain concrete. Authentication is committed only after the expected TLS
  1.3 ClientFinished is verified. Each VLESS UUID owns one or more REALITY
  short IDs. The ClientHello short ID resolves through an immutable,
  cardinality-adaptive owner index; after VLESS decode, the header UUID must
  equal that resolved owner. A UUID and a short ID copied from different client
  entries therefore cannot be combined into an authorized session.
  Authenticated setup has three fail-safe cover tiers: a validated exact-class
  profile builds a fresh local flight; otherwise a TCP-established warm socket
  obtains the current real cover flight; otherwise the ordinary cold cover
  path is used. Prebuilt mode never replays a ServerHello or key material and
  is unreachable before authentication and replay reservation.
- **Fallback** is the failure mode: an unauthenticated connection is
  forwarded byte-for-byte, in order, to the cover target. No synthetic
  response identifies the service as a proxy, and fallback concurrency is
  bounded independently of authenticated traffic.
- **VLESS** is the authenticated request protocol inside the TLS stream:
  UUID, command, and destination. Decryption is `none` — the outer REALITY
  TLS 1.3 record layer provides confidentiality and integrity. v1.3 does not
  stack VLESS Encryption inside REALITY because it disables Vision splice and
  duplicates per-byte encryption; see the measured
  [decision record](../adr/0003-do-not-stack-vless-encryption-on-reality.md).
- **`xtls-rprx-vision`** is the only accepted flow. It adds padding and
  length obfuscation in the framed phase and supports **Direct** transitions:
  once a direction is authenticated and its inner TLS 1.3 application data
  is identified, that direction switches to a raw relay (Linux `splice`
  preferred) with the boundary invariants described in
  [architecture.md](architecture.md). Plain VLESS, TLS-only VLESS,
  WebSocket, QUIC, UDP proxying, and non-Vision flows are not supported on
  the public inbound.

The public stack is wire-compatible with Xray-core clients; the compatibility
gate is described in [benchmarks.md](benchmarks.md).

## Outbounds

- **direct**: bounded connect with optional domain strategy (DNS resolution
  under a bounded, fail-fast pool) and a direct-barrier that rate-limits
  unauthenticated dials.
- **SOCKS5**: outbound to an upstream SOCKS5 server with optional
  username/password authentication. Its optional warm state is TCP-only;
  method negotiation, authentication, and CONNECT remain per-flow.
- **block**: refuse the connection. Built in, and never declared.
- **NXR**: forwards the flow to a landing node (below).
- **Handoff**: transfers the whole session to a landing node (below).

## NXR: the internal line-to-landing hop

NXR is an internal replacement for unauthenticated SOCKS-style
line-to-landing access, not a public protocol. Each authenticated user TCP
flow on the line node owns one NXR TCP connection to the landing node and
sends exactly one bounded request: version, target, timestamp, random nonce,
and an HMAC under an independent 32-byte pre-shared key. The landing node
checks structure, time window, HMAC, and a bounded nonce replay cache before
any DNS resolution or destination connection; failure is a silent close.

After that one-time authenticated request, NXR switches permanently to raw
bidirectional bytes with half-close: there is no TLS, REALITY, AEAD,
certificate, multiplexing, persistent framing, or
post-authentication encryption. The NXR listener must be firewall-restricted
to the line node's fixed source IP, and the hop must be treated as plaintext:
anyone who can observe it can observe payload that is not protected
end-to-end (for example by HTTPS).

TCP may be established before a flow exists, but it remains protocol-
unprivileged. LANDING waits for byte one under a bounded pre-auth idle policy,
then applies the existing short deadline to the rest of the request. No replay
state, DNS, or destination side effect occurs in the idle phase. A checked-out
socket is single-use and each attempt constructs a fresh timestamp, nonce, and
HMAC; no logical flow is retried after the complete request write.

## Handoff: the internal session-transfer hop

Handoff is an internal session transfer, not a public protocol. After REALITY
authentication, VLESS decode, and routing, the line node transfers the whole
session — TLS record state, sequence numbers, Vision context, and pending
bytes — to a landing node in one sealed, replay-protected message; the line
node then relays the session's TLS ciphertext.

The transfer is sealed with a fresh ephemeral X25519 exchange against the
landing node's static key, mixed with an independent pair PSK in one
HKDF-SHA256 chain under one ChaCha20-Poly1305 seal; a timestamp window and a
bounded nonce cache are checked before any key-agreement work, and every
failure closes silently with zero response bytes. On success the landing node
reconstructs the session's TLS record layers and dials the transferred
destination — directly by default, or through the outbound named by the
listener's `egress` setting (`direct`, `block`, or a declared outbound;
Handoff never chains) — and resumes the session. During a key-rotation window the landing also accepts
up to two retired pre-shared keys and static key pairs
(`previousPreSharedKeys`/`previousPrivateKeys`), so peers can rotate without
downtime; retired keys are dropped promptly after the window. The landing
node applies no
routing policy to the transferred destination and holds live session keys, so
its memory is part of the session's secrecy boundary. The Handoff listener
must be reachable only from the line nodes' addresses.

The TCP connection may likewise be established in advance without changing
Handoff wire bytes or authority. The first transfer byte ends a bounded
zero-byte idle phase and starts the short transfer-authentication deadline.
Each checkout seals fresh timestamp/nonce/ephemeral-key/AEAD state. A bounded
alternate is permitted only before complete transfer write; after that cutoff
LANDING may already have resumed the session or connected the destination, so
late failure is final.

## Trust boundaries in one paragraph

The public listener resists unauthenticated protocol identification, active
probing, ClientHello replay, malformed record input, and local resource
exhaustion. Everything pre-authentication is bounded and secret-free in logs.
The server operator still owns the cover-target choice, the firewall policy
(especially for NXR and Handoff), the VPS link (no application can absorb upstream
volumetric DDoS), and endpoint compromise (REALITY does not make a
compromised endpoint trustworthy). See [threat-model.md](threat-model.md)
for the full model and the non-goals.
