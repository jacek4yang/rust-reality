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
      "serverName": "www.example.com"
    }
  ]
}
```

Default inbound protocol is SOCKS5 (no-auth CONNECT). Point curl or an
application at `socks5h://127.0.0.1:10808`.

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
      "serverName": "www.example.com"
    }
  ]
}
```

## Multi-LINE groups and selection

Tag each LINE, declare `lineGroups`, and optionally pin a listener to a group.
Absent `lineGroups`, all lines form one implicit `default` group. Selection
uses a sticky primary with a hedge after `selection.hedgeMs` (default 275)
inside `selection.timeoutMs` (default 15000). Health trips after repeated
authentication faults and affects **new** sessions only.

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
      "serverName": "www.example.com"
    },
    {
      "tag": "b",
      "address": "10.0.0.2",
      "port": 443,
      "id": "11111111-1111-4111-8111-111111111111",
      "publicKey": "UWesja3AOowUwLohp5LcPtmE0gZmBSsn8I6623QczzY",
      "shortId": "0102030405060708",
      "serverName": "www.example.com"
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
