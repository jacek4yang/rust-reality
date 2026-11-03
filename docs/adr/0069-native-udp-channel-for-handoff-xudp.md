# ADR 0069: Native UDP channel for Handoff XUDP

Status: Accepted (supersedes the Handoff part of [ADR 0060](0060-xudp-over-nxr-and-handoff.md))

## Context

[ADR 0060](0060-xudp-over-nxr-and-handoff.md) §3 carried XUDP through Handoff
by transferring the client's TLS session to LANDING, exactly like TCP. LANDING
then owned the XUDP framing, and LINE sealed a policy snapshot into the
transfer so LANDING could authorize later destination rewrites.

That design fails in normal deployments:

- The snapshot cannot express asset matchers. As soon as any rule uses
  `geoip:` / `geosite:` (the common `block-private` → `geoip:private` rule is
  enough), the snapshot collapses to "initial destination only", so every
  second destination on one association (STUN, QUIC to a different CDN
  address, multiple resolvers) tears the association down.
- LANDING has no routing DNS, so domain destinations repeated on stock Xray
  Keep frames cannot be re-resolved there.
- Routing authority is split across two machines, and LANDING needs a
  growing subset of LINE's routing semantics to stay correct.

The owner requirement for this change: LINE keeps decrypting
REALITY/Vision/XUDP and owns every DNS, GeoIP/GeoSite, routing, and
authorization decision. LINE→LANDING carries only authorized datagrams, over
a new native UDP transport (not TCP, not the NXR carrier, not a Handoff TLS
continuation). LANDING only forwards. TCP Handoff (TLS state transfer and
zero-copy ciphertext relay) is unchanged. Public wire protocols and stock
Xray / v2rayN compatibility are unchanged. The path MTU must be discovered
automatically with no client configuration.

## Decision

### 1. Scope

- XUDP associations whose route class is Handoff no longer transfer TLS.
  LINE runs the XUDP association itself (as for Direct and NXR) and opens one
  native UDP channel session per association toward the LANDING named by the
  outbound.
- TCP Handoff is byte-identical: same `HND1` blob, same continuation-state
  version, same splice relay. The blob codec keeps its `SessionKind` and
  policy-snapshot fields unchanged so no TCP Handoff byte changes; LANDING now
  rejects an `Xudp` continuation as a protocol error (silent close).
- The old LANDING-side XUDP resume path, the policy-snapshot sealing on LINE,
  and the Handoff-XUDP relay are deleted (one canonical model).

### 2. Wire format: `handoff-udp` version 1

Every packet starts with an 18-byte cleartext header, which is also the AEAD
associated data:

| bytes | field |
| --- | --- |
| 1 | version = 1 |
| 1 | type: OPEN=1, OPEN_ACK=2, DATA=3, FRAG=4, PROBE=5, PROBE_ACK=6, CLOSE=7 |
| 8 | session id (random, chosen by LINE) |
| 8 | counter (big endian; 0 only for OPEN) |

OPEN (122 bytes) = header ‖ u64 unix time ‖ 16-byte nonce ‖ 32-byte
ephemeral X25519 public key ‖ AEAD(user id) ‖ 16-byte tag ‖ 16-byte
admission tag.

All other packets = header ‖ ChaCha20-Poly1305(plaintext) ‖ tag, with nonce
= 4 zero bytes ‖ counter. Counters start at 1 per direction and never repeat.

- DATA plaintext: address family (4 or 6) ‖ address ‖ port ‖ payload. Uplink
  names the destination LINE authorized; downlink names the real source.
  Domains are not representable: LINE always resolves first.
- FRAG plaintext: u32 fragment id ‖ u8 index ‖ u8 count ‖ chunk of one DATA
  plaintext.
- PROBE plaintext: u32 probe id, zero-padded so the whole packet has the
  probed size. PROBE_ACK: u32 id ‖ u16 received size.
- OPEN_ACK and CLOSE have empty plaintext.

The largest datagram is the XUDP payload cap (7526 bytes), because every
datagram enters or leaves through one XUDP frame on LINE.

### 3. Keys and authentication

The channel reuses the Handoff pair secrets with domain separation:

- `shared = X25519(E_priv, S_pub)` against the landing static key.
- `PRK = HKDF-Extract(salt = "rust-reality/handoff-udp/v1" ‖ E_pub ‖ S_pub,
  ikm = shared ‖ PSK)`; `HKDF-Expand(PRK, info = OPEN cleartext ‖ S_pub, 96)`
  yields `k_open`, `k_line→landing`, and `k_landing→line`. The label differs
  from the TCP transfer label, so the two schedules never collide.
- The user id is sealed under `k_open` with counter 0.
- Admission tag = HMAC-SHA256(`K_adm`, first 106 OPEN bytes), truncated to
  16 bytes, where `K_adm = HKDF(salt = "rust-reality/handoff-udp/v1/open-filter",
  ikm = PSK)`.

LANDING validates an OPEN in this order: exact length and header, timestamp
window (`maximumTimeDifference`, as for TCP), admission tag against each
rotation PSK in constant time, then one replay-cache reserve of the nonce,
then the bounded DH/HKDF/AEAD candidate trials of the TCP transfer (retired
PSKs and keys accepted during rotation). The admission tag sits before the
replay reserve and DH on purpose: UDP sources are spoofable and need no
handshake, so a flood without the PSK can neither burn replay capacity nor
force X25519 work.

Per-session replay protection is a 1024-packet sliding window, checked before
and committed only after AEAD success. Forged, replayed, reflected
(direction-key), and foreign-session packets are dropped silently and never
move the window.

### 4. Sessions

- LINE: one connected UDP socket per XUDP association. OPEN is retransmitted
  with backoff (250 ms doubling to 2 s) until LANDING acknowledges it or any
  authenticated packet arrives. The open deadline is the outbound's
  `connectTimeoutMs`; past it the association fails with an explicit error.
  It never falls back to Direct or to TCP. CLOSE is sent best effort when the
  association ends.
- LANDING: one task per Handoff landing address. Sessions are keyed by
  session id, at most 4096 per address, and expire after 120 s without
  authenticated traffic, which is longer than LINE's XUDP idle bound, so LINE
  normally closes first. A byte-identical retransmitted OPEN is
  re-acknowledged to the bound peer only. An authenticated packet with a
  fresh counter from a new source address moves the session there (NAT
  rebinding). Nothing is ever sent to an unauthenticated source.
- LANDING egress: one UDP socket per address family per session, bound to the
  listener address when the family matches and charged to the descriptor
  budget. Replies from any source are returned with their real source
  (full-cone, the same semantics as Direct XUDP egress on LINE).
- LANDING forwards only datagrams sealed with a live session's keys. It
  evaluates no routing rule and loads no assets.
- Key material is read from the current generation for each new OPEN, so a
  reload or rotation affects new sessions only.
- The channel requires direct LANDING egress. A LANDING whose egress is a
  configured SOCKS5/NXR outbound refuses OPENs, and LINE reports the open
  timeout.

### 5. Routing semantics on LINE

Every New and Keep destination goes through the same LINE path as Direct and
NXR: `select_with_dns`, then late resolution for domains, IPv4-preferred
address selection for landward egress, capability check, then
`authorize_xudp_egress`. Block, unknown outbounds, and a capability change
inside one association fail the association before anything is sent. A
blocked destination therefore never reaches LANDING. LINE semantics are the
existing ones, unchanged.

### 6. Path MTU (RFC 8899 style DPLPMTUD)

Each direction of each session runs its own prober on channel packet sizes
(UDP payload bytes):

- Base 1200 (QUIC's minimum datagram), floor 512, maximum 8972 (9000-byte
  IPv4 jumbo). The local ceiling is the kernel route MTU on LINE's connected
  socket (`IP_MTU`), or the protocol maximum on LANDING's shared socket.
- Sockets set DF (`IP_PMTUDISC_DO` / `IPV6_PMTUDISC_DO`). Nothing is ever
  IP-fragmented.
- The first probe confirms the base. Then a binary search uses padded,
  authenticated PROBEs (1 s timeout, 3 tries per size, 16-byte granularity).
  Only an acknowledged probe raises the limit. Ordinary data loss never
  changes it.
- Kernel feedback: an ICMP Packet Too Big / Fragmentation Needed lowers the
  kernel route MTU, and the next oversized send fails with `EMSGSIZE`. The
  prober lowers to the kernel's value (or to the base or floor when the socket
  cannot report it) and the datagram is re-packetized at once (up to four
  attempts). It is not dropped.
- Black holes (ICMP filtered): a confirmation probe at the current size runs
  every 15 s. When all retries are lost, the limit falls back to the base (or
  the floor if the base failed) and the search restarts. A search also
  re-confirms its starting size first, so a path below the base is found
  within one probe budget.
- A raise timer (600 s) restores the original ceiling and searches upward
  again, so a path that grew mid-session is used again.
- IPv4 and IPv6 overheads are accounted separately.

A datagram larger than the current limit is split into FRAG packets (at most
16 per datagram, 7526-byte datagrams fit down to the 512-byte floor) and
reassembled on the other side under strict limits: at most 8 incomplete groups
and 4 maximum datagrams of buffered bytes per session, a 3 s reassembly
timeout, oldest-group eviction, and discard of inconsistent groups. There is
no silent drop for size: a datagram either fits in one packet or is
fragmented.

`udpMtu` (on the Handoff outbound and on the landing) fixes the IP MTU
assumption and disables probing for that end. It is absent (automatic) by
default and needs no client configuration.

### 7. Configuration

- Handoff outbound (LINE): optional `udpPort` (default: `port`) and optional
  `udpMtu` (576–9000, default: automatic).
- Handoff landing: optional `udpPort` (default: the listener's port) and
  optional `udpMtu`.
- With defaults, LANDING binds UDP on the same address and port number as each
  TCP listener (for example `10.0.0.2:7443/udp` next to `10.0.0.2:7443/tcp`),
  and logs it as listener `<tag>/udp`. Changing `udpPort` takes effect on
  restart.
- Every existing configuration stays valid. No public client setting changes.

### 8. Firewall and migration

- LANDING must accept UDP on `udpPort` from LINE's addresses only, and must
  allow its own outbound UDP egress. LINE must allow outbound UDP to it.
  Restricting the source is still recommended even though unauthenticated
  packets are dropped without a reply.
- Mixed versions: a new LINE talking to an old LANDING gets no OPEN_ACK, and
  Handoff XUDP fails closed with the open timeout. An old LINE talking to a
  new LANDING transfers an XUDP continuation, which LANDING rejects. TCP
  Handoff works across both. Upgrade both ends of every LINE→LANDING pair
  together, as for any contract change.

## Threat model

- The LINE↔LANDING UDP hop sees only authenticated, encrypted packets. An
  observer learns packet sizes, timing, the session id, counters, and the OPEN
  timestamp. Destinations and payloads are encrypted.
- Forward secrecy: each session's keys come from a fresh ephemeral X25519
  share against the landing static key, combined with the PSK. Compromising
  the static key after the fact still requires the PSK. Compromising both
  exposes recorded sessions (the same boundary as the TCP transfer).
- An attacker without the PSK cannot open sessions, burn replay capacity,
  force DH work, inject or replay datagrams, or make LANDING send anything
  (no reflection or amplification: LANDING never answers an unauthenticated
  packet, and an OPEN_ACK is smaller than the OPEN).
- A holder of the PSK and landing public key (a LINE) can use LANDING as a
  UDP egress for any destination. That is the intended trust: LANDING trusts
  LINE's authorization, as with TCP Handoff and NXR.
- Resource bounds: the session cap, idle expiry, per-session reassembly memory
  caps, the descriptor budget for egress sockets, and the bounded OPEN replay
  cache.
- LANDING still sees plaintext datagrams it forwards, as it does for NXR UDP
  and TCP Handoff.

## Alternatives considered

- Keep TLS transfer for XUDP and extend the policy snapshot with assets or
  expanded CIDR sets. This puts routing on LANDING, needs asset distribution
  or very large blobs, and still cannot handle LINE's DNS. Rejected by the
  owner requirement.
- Reuse the NXR framed TCP carrier. It has head-of-line blocking and
  TCP-in-UDP semantics problems for QUIC. Rejected.
- QUIC or DTLS between the nodes. These are larger dependencies with handshake
  round trips. The channel needs only datagram AEAD with a one-message open.
  Rejected.
- Parsing ICMP via `IP_RECVERR`. Kernel PMTU caching with DF plus `EMSGSIZE`
  delivers the same signal without a new error-queue parser. Deferred.

## Consequences

- Handoff XUDP gives up TLS offload on LINE. LINE runs Vision/XUDP for UDP
  associations, as it already does for Direct and NXR. TCP keeps the offload.
- LANDING operators must open one UDP port (default: the same number as
  TCP).
- New code: `src/protocol/handoff/udp/` (codec, key schedule, replay window,
  fragmentation, PMTU state machine) and `src/server/handoff/udp/` (LINE
  association, LANDING service). The parsers have fuzz target
  `handoff_udp_packets`.
- Tests: unit tests for every packet type and tamper, rotation, replay,
  fragments, and PMTU states; loopback LINE↔LANDING integration including
  forged and replayed traffic, NAT rebinding, OPEN loss, open timeout, refused
  egress, black-hole and shrinking/growing paths; a root network-namespace
  test for interface MTU change mid-session; and stock Xray end to end with
  `geoip:private` / GeoSite rules, multiple destinations, DNS, STUN, large
  datagrams, and genuine HTTP/3 (also on a 1280-byte MTU loopback).

## References

- [ADR 0031](0031-handoff-transfers-keyupdate-capable-state.md) — Handoff TLS state transfer (TCP, unchanged)
- [ADR 0059](0059-asymmetric-stock-xray-interop.md) — stock Xray interop
- [ADR 0060](0060-xudp-over-nxr-and-handoff.md) — XUDP over NXR (still current) and the superseded Handoff design
- RFC 8899 — Packetization Layer Path MTU Discovery for Datagram Transports
