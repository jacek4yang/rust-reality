# Threat model

## Protected data path

```text
Xray-compatible client
  -> VLESS + REALITY + xtls-rprx-vision public listener
  -> UUID policy on the line node
  -> direct | SOCKS5 | blackhole | NXR
  -> optional firewall-restricted NXR landing node
  -> destination
```

The public listener always requires TCP, REALITY, VLESS decryption `none`, and
the Vision flow. A configuration that attempts plain VLESS is rejected before
listeners are bound.

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

Configuration, routing assets, users, REALITY state, and outbounds are published
as one immutable generation. A failed refresh keeps the last complete snapshot.
Private keys, UUIDs, NXR PSKs, credentials, and full configurations are excluded
from structured logs.

## NXR boundary

NXR is an internal replacement for unauthenticated SOCKS-style line-to-landing
access, not for the public protocol. Each user TCP flow creates one NXR TCP
connection and sends exactly one bounded request containing a version, target,
timestamp, random nonce, and HMAC under an independent 32-byte PSK.

The landing node checks structure, time, HMAC, and a bounded nonce replay cache
before DNS resolution or a destination connection. Failure is a silent close.
Success switches permanently to raw bidirectional bytes with half-close. There
is no TLS, REALITY, AEAD, certificate, multiplexing, pool, persistent framing,
or post-authentication encryption in NXR. Its listener should be reachable only
from the line node's source IP at the firewall.

Because post-authentication NXR traffic is plaintext, anyone who can observe or
modify the private hop can observe or modify payload not protected by an
end-to-end protocol such as HTTPS. Use a private network or a different secured
transport when that threat exists.

## Resource and kernel boundaries

All pre-authentication work, connections, fallbacks, cryptographic work, replay
entries, destination dials, relay buffers, and splice pipes have explicit
ceilings. The data path has no unbounded queue or cache. Protocol code denies
unsafe Rust.

Linux `splice` is permitted only after both sides are plaintext TCP sockets. It
cannot cross the REALITY/TLS application boundary. If bounded splice resources
are unavailable before transfer starts, relay falls back to bounded userspace
buffers. `io_uring` and sockhash configuration switches remain disabled until
their implementations and capability probes are independently accepted.

## Non-goals

- The application cannot stop upstream volumetric DDoS from saturating the VPS
  link; provider filtering and firewall policy are required.
- REALITY does not make a compromised endpoint trustworthy.
- NXR does not provide payload confidentiality or integrity after its one-time
  authentication request.
- Microbenchmark results are not Internet throughput or latency guarantees.
- GeoIP and GeoSite lists are policy inputs, not security authorities.
