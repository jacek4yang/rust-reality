# Client role

English | [简体中文](../../zh-CN/configuration/client.md)

A **client** node listens on loopback only. It accepts local SOCKS5 and/or
HTTP CONNECT, authenticates outbound to an **entry** with VLESS + REALITY +
Vision, and relays application bytes. It holds no public REALITY identity and
must not be exposed on a non-loopback address.

See also [ADR 0032](../../adr/0032-client-candidates-stop-before-destination-open.md):
selection races authentication only; a committed session is never migrated;
destination requests are never replayed.

## Minimal single-LINE example

```json
{
  "role": "client",
  "listeners": [
    {
      "port": 10808,
      "ipv4": "127.0.0.1"
    }
  ],
  "lines": [
    {
      "address": "entry.example.com",
      "port": 443,
      "id": "11111111-1111-4111-8111-111111111111",
      "publicKey": "UWesja3AOowUwLohp5LcPtmE0gZmBSsn8I6623QczzY",
      "shortId": "0102030405060708",
      "serverName": "www.example.com",
      "fingerprint": "chrome"
    }
  ]
}
```

Default inbound protocol is SOCKS5 (no-auth CONNECT). Point curl or an
application at `socks5h://127.0.0.1:10808`.

## Browser ClientHello

Each LINE accepts `"fingerprint": "chrome"` (default) or
`"fingerprint": "firefox"`. These select pinned native Windows profiles:

| Name | Browser version | TLS key shares |
| --- | --- | --- |
| `chrome` | Google Chrome Stable 156.0.8078.74 | GREASE, X25519MLKEM768, X25519 |
| `firefox` | Mozilla Firefox 159.0 | X25519MLKEM768, X25519, P-256 |

Unknown names, historical versions, Safari/iOS and randomized profile names are
rejected during configuration loading. Selection and hedging retain each LINE's
profile. The field is serialized by configuration formatting and appears in the
generated current schema (`cargo dev config schema`). Browser/driver/capture
software is tooling only and is not bundled in the production executable.

The profile reproduces a fresh TCP ClientHello without resumption or real ECH.
It preserves per-handshake entropy, Chrome extension shuffling, GREASE, and ECH
GREASE. Firefox reuses its X25519 public share inside the hybrid share; Chrome
uses independent keys. Every offered real key share has retained private state.
The TLS implementation supports TLS 1.3 only and rejects HelloRetryRequest;
advertised TLS 1.2 cover capabilities do not enable a TLS 1.2 session.
REALITY's authenticated session ID and certificate identity remain protocol
specific. In particular, REALITY authenticates its HMAC-bound Ed25519 identity
and verifies Ed25519 CertificateVerify and Finished, even though the native
browser signature lists do not advertise Ed25519. This existing REALITY
certificate policy is not the browser's PKI or signature-negotiation policy;
the measured equivalence claim covers the ClientHello, not a generic browser
TLS state machine. ClientHello equivalence does not reproduce browser HTTP, QUIC, OS,
packet timing or complete traffic behavior.

See [testing](../development/testing.md) for native capture provenance and the
independent structural comparison procedure.

## SOCKS5 UDP ASSOCIATE (XUDP)

The same SOCKS5 listener accepts **UDP ASSOCIATE**. Datagrams are carried as
**XUDP** (VLESS Mux `0x03` / Vision) on one committed LINE — not a second
carrier and not native QUIC. Multi-address sessions use XUDP `New`/`Keep`
framing; the association never migrates mid-session.

UDP/443 is refused unless the LINE sets `allowUdp443: true` (stock
`xtls-rprx-vision-udp443` policy). Wire Addons still advertise
`xtls-rprx-vision`. Server egress for XUDP is **Direct**, **NXR**, or
**Handoff** ([ADR 0060](../../adr/0060-xudp-over-nxr-and-handoff.md)); Block and
unsupported outbounds fail closed with no silent Direct fallback. See
[XUDP and Vision UDP/443](../development/xudp.md).

```json
{
  "role": "client",
  "listeners": [{ "port": 10808, "ipv4": "127.0.0.1" }],
  "lines": [{
    "address": "entry.example.com",
    "port": 443,
    "id": "11111111-1111-4111-8111-111111111111",
    "publicKey": "UWesja3AOowUwLohp5LcPtmE0gZmBSsn8I6623QczzY",
    "shortId": "0102030405060708",
    "serverName": "www.example.com",
    "fingerprint": "chrome",
    "allowUdp443": true
  }]
}
```

## HTTP CONNECT inbound

Set `protocol` to `http` on a listener. Only HTTP/1.x `CONNECT` is accepted
(`HTTPS_PROXY=http://127.0.0.1:…`). Absolute-form forward proxying is not
supported.

```json
{
  "role": "client",
  "listeners": [
    {
      "port": 18080,
      "ipv4": "127.0.0.1",
      "protocol": "http"
    }
  ],
  "lines": [
    {
      "address": "entry.example.com",
      "port": 443,
      "id": "11111111-1111-4111-8111-111111111111",
      "publicKey": "UWesja3AOowUwLohp5LcPtmE0gZmBSsn8I6623QczzY",
      "shortId": "0102030405060708",
      "serverName": "www.example.com",
      "fingerprint": "chrome"
    }
  ]
}
```

UDP replies preserve their source independently of the current uplink target.
A delayed reply cannot authorize or replace the target of a later Keep frame.
NXR LANDING includes the actual UDP source in each authenticated downlink
frame; LINE rejects a downlink datagram without that address. Oversized replies
fail closed instead of becoming truncated datagrams.

## Multi-LINE groups and selection

Tag each LINE, declare `lineGroups`, and optionally pin a listener to a group.
Absent `lineGroups`, all lines form one implicit `default` group. Selection
uses a sticky primary with a hedge after `selection.hedgeMs` (default 275)
inside `selection.timeoutMs` (default 15000). Health trips after repeated
authentication faults and affects **new** sessions only.
Groups that reference the same LINE share its immutable compiled configuration;
each group keeps its own health and sticky-primary state.

```json
{
  "role": "client",
  "listeners": [
    {
      "port": 10808,
      "ipv4": "127.0.0.1",
      "lineGroup": "edge"
    }
  ],
  "lines": [
    {
      "tag": "a",
      "address": "10.0.0.1",
      "port": 443,
      "id": "11111111-1111-4111-8111-111111111111",
      "publicKey": "UWesja3AOowUwLohp5LcPtmE0gZmBSsn8I6623QczzY",
      "shortId": "0102030405060708",
      "serverName": "www.example.com",
      "fingerprint": "chrome"
    },
    {
      "tag": "b",
      "address": "10.0.0.2",
      "port": 443,
      "id": "11111111-1111-4111-8111-111111111111",
      "publicKey": "UWesja3AOowUwLohp5LcPtmE0gZmBSsn8I6623QczzY",
      "shortId": "0102030405060708",
      "serverName": "www.example.com",
      "fingerprint": "chrome"
    }
  ],
  "lineGroups": [
    {
      "name": "edge",
      "lines": [
        "a",
        "b"
      ]
    }
  ],
  "selection": {
    "hedgeMs": 275,
    "timeoutMs": 15000
  }
}
```

## Operator bounds

- SOCKS5 method negotiation plus its command, or an HTTP CONNECT head, must
  complete within 15 seconds. LINE authentication then uses one overall
  `selection.timeoutMs` budget, including single-LINE groups and hedged attempts.
  Expiry closes pending candidate sockets before any destination request.
- Local and LINE TCP sockets use the shared NODELAY and kernel keepalive policy.
  Cancelling the client listener cancels its owned connections; completed
  connection tasks are reaped while the listener remains active.
- Listeners must bind loopback (`127.0.0.1` / `::1`). Non-loopback binds are
  rejected.
- A group lists one to eight LINE tags; tags must exist and be unique in the
  group.
- `shortId` is even-length hex, 2–16 characters, left-aligned as on the entry.
- `entry` and `landing` reject `protocol` and `lineGroup` on listeners.

## Related

- [How configuration works](index.md)
- [Users and credentials](users-and-credentials.md) (UUID, short ID, public key)
- [Architecture — shared client wire boundary](../architecture.md#shared-client-wire-boundary)
