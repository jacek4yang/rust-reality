# Configuration reference

English | [简体中文](../../zh-CN/configuration/reference.md)

Every object, every field, what it means, whether it is required, and what an
omitted value becomes. The guides explain *how and why*; this page states
*what*.

Conventions used throughout:

- **derived** — omitting the field means the value is computed from this
  machine at startup, not that a fixed constant is used.
- **hot / cold** — whether a change applies on `SIGHUP` or needs a restart.
- Key material is URL-safe unpadded base64 decoding to exactly 32 bytes.

## Top level

The `role` field selects the shape of the whole document. Two shapes exist and
they share no required fields beyond `role` and `listeners`.

### `role: "entry"`

| field | type | required | meaning |
| --- | --- | --- | --- |
| `role` | `"entry"` | yes | Selects this shape. |
| `listeners` | array of [Listener](#listener) | yes | Public listening endpoints. All share one REALITY identity. |
| `reality` | [Reality](#reality) | yes | REALITY identity and cover target. |
| `users` | array of [User](#user) | yes | Authorized client identities. |
| `outbounds` | object of [Outbound](#outbound) | no | Declared transports, keyed by name. Absent means only `direct` and `block`. |
| `routing` | [Routing](#routing) | yes | Where traffic goes. |
| `assets` | [Assets](#assets) | no | Geo data. Needed only by `geoip:`/`geosite:` conditions. |
| `dns` | [Dns](#dns) | no | Name resolution. |
| `network` | [Network](#network) | no | Outbound address-family policy. |
| `log` | [Log](#log) | no | Logging destination and retention. |
| `runtime` | [Runtime](#runtime) | no | Resource posture and expert limits. |

### `role: "landing"`

| field | type | required | meaning |
| --- | --- | --- | --- |
| `role` | `"landing"` | yes | Selects this shape. |
| `listeners` | array of [Listener](#listener) | yes | Firewall-restricted listening endpoints. |
| `landing` | [Landing](#landing) | yes | The internal protocol terminated here, and its credentials. |
| `egress` | string | no | How transferred destinations are reached. A built-in outbound or a key of `outbounds`. Absent means `direct`. |
| `outbounds` | object of [Outbound](#outbound) | no | Declared transports, keyed by name. |
| `dns` | [Dns](#dns) | no | Name resolution. |
| `network` | [Network](#network) | no | Outbound address-family policy. |
| `log` | [Log](#log) | no | Logging destination and retention. |
| `runtime` | [Runtime](#runtime) | no | Resource posture and expert limits. |

A landing has no `reality`, no `users`, and no `routing`. Stating one is an
error naming the field.

## Listener

Cold. Several listeners may share a family but not a socket.

| field | type | required | absent means |
| --- | --- | --- | --- |
| `port` | integer 1–65535 | yes | — |
| `ip` | `"auto"` \| `"dualStack"` \| `"ipv4Only"` \| `"ipv6Only"` | no | `"auto"` |
| `ipv4` | string | no | the IPv4 wildcard `0.0.0.0` |
| `ipv6` | string | no | the IPv6 wildcard `::` |

`auto` binds both families and starts if at least one succeeds. `dualStack`
requires both. `ipv4` and `ipv6` name a concrete address to bind instead of
the wildcard, and are used only for a family that is being bound at all.

## Reality

Hot. Entry nodes only.

| field | type | required | absent means |
| --- | --- | --- | --- |
| `cover` | `host:port` | yes | — |
| `privateKey` | key material | yes | — |
| `serverNames` | array of string | no | the host part of `cover` |
| `maxTimeDiffMs` | integer | no | `60000`; zero disables the check |
| `coverOptimization` | [CoverOptimization](#coveroptimization) | no | every optimization enabled |

`cover` is required because only an operator can choose a host that is
plausible for this server to be fronting. `privateKey` is secret; the matching
public key goes to clients.

`serverNames` entries are exact names or a leftmost single-label wildcard such
as `*.example.com`. A cover named by IP address has no host part to default
to, so `serverNames` becomes required there.

### CoverOptimization

Expert surface. These change what this server does toward the cover host, so
they are operator policy rather than derived values.

| field | type | absent means |
| --- | --- | --- |
| `enabled` | boolean | enabled |
| `warmTcp` | boolean | enabled |
| `prebuiltProfiles` | boolean | enabled |

`warmTcp` keeps TCP-established cover sockets ready; no TLS bytes are sent
before checkout. `prebuiltProfiles` builds cover-derived TLS profiles in the
background and uses them only after successful authentication and replay
reservation.

## User

Hot. Entry nodes only. Identities and short IDs are unique across the node.

| field | type | required | absent means |
| --- | --- | --- | --- |
| `id` | UUID | yes | — |
| `shortIds` | array of string | yes | — |
| `label` | string | no | the identity is reported by its UUID |
| `policy` | string | no | the top-level `routing` default and rules apply |

A short ID is 2–16 hexadecimal characters, an even count. A client picks one
per connection; listing several lets one identity's devices carry different
short IDs.

`label` is non-secret and has no protocol effect. `policy` names a key of
`routing.policies`.

## Outbound

Hot. Keyed by name; the key is the name, so there is no `tag` field. `direct`
and `block` are built in and may not be declared.

### `type: "socks5"`

| field | type | required | absent means |
| --- | --- | --- | --- |
| `type` | `"socks5"` | yes | — |
| `address` | string | yes | — |
| `port` | integer | yes | — |
| `username` | string | no | no authentication |
| `password` | string | no | no authentication |
| `warmTcp` | boolean | no | enabled |

`username` and `password` are required if and only if the other is present.

### `type: "nxr"`

| field | type | required | absent means |
| --- | --- | --- | --- |
| `type` | `"nxr"` | yes | — |
| `address` | string | yes | — |
| `port` | integer | yes | — |
| `psk` | key material | yes | — |
| `warmTcp` | boolean | no | enabled |

`psk` must match the landing node's `psk` and must be independent of every
other key in the file.

### `type: "handoff"`

| field | type | required | absent means |
| --- | --- | --- | --- |
| `type` | `"handoff"` | yes | — |
| `address` | string | yes | — |
| `port` | integer | yes | — |
| `psk` | key material | yes | — |
| `landingPublicKey` | key material | yes | — |
| `connectTimeoutMs` | integer | no | `10000` |
| `firstByteTimeoutMs` | integer | no | `15000` |
| `warmTcp` | boolean | no | enabled |

`landingPublicKey` is public material, not a secret: it is the public half of
the landing's `privateKey`. `firstByteTimeoutMs` is how this node detects a
silent rejection.

## Routing

Hot. Entry nodes only.

| field | type | required | absent means |
| --- | --- | --- | --- |
| `default` | string | yes | — |
| `rules` | array of [Rule](#rule) | no | no rules; everything takes `default` |
| `policies` | object of [Policy](#policy) | no | no policies |
| `strategy` | `"asIs"` \| `"resolveIfNoMatch"` \| `"resolveOnDemand"` | no | `"resolveIfNoMatch"` |

`default` is required because where traffic goes by default is the single most
consequential line in the file, and it is never inferred.

| `strategy` | behaviour |
| --- | --- |
| `asIs` | never resolve for routing; `ip` rules match only literal addresses |
| `resolveIfNoMatch` | resolve only when no domain rule matched and an `ip` rule exists |
| `resolveOnDemand` | resolve whenever an `ip` rule could apply |

### Policy

| field | type | required | absent means |
| --- | --- | --- | --- |
| `default` | string | yes | — |
| `rules` | array of [Rule](#rule) | no | no rules; everything takes this policy's `default` |

A policy replaces both the global default and the global rules for the users
that select it — except that `routing.rules` are evaluated first and are not
overridable.

### Rule

Ordered, first match wins. At least one condition is required; a rule with
none is refused.

| field | type | required | absent means |
| --- | --- | --- | --- |
| `outbound` | string | yes | — |
| `name` | string | no | the rule is reported by its position |
| `domain` | array of string | no | no domain condition |
| `ip` | array of string | no | no IP condition |
| `port` | array of string | no | no port condition |

Entries within one condition are alternatives; conditions present together
must all match.

**Domain matchers**

| form | matches |
| --- | --- |
| `example.com` | that exact name |
| `full:example.com` | that exact name |
| `domain:example.com` | that name and any subdomain |
| `keyword:example` | any name containing the substring |
| `regexp:…` | any name the expression matches |
| `geosite:cn` | any name in that geo list |
| `ext:file.dat:tag` | a tag from an external data file |

**IP matchers** — a literal address, a CIDR block, or `geoip:label`.
`geoip:private` is built in and needs no data file.

**Port matchers** — a single port, or an inclusive `from-to` range.

## Landing

Hot, including key rotation. Landing nodes only. Tagged by `protocol`.

### `protocol: "nxr"`

| field | type | required | absent means |
| --- | --- | --- | --- |
| `protocol` | `"nxr"` | yes | — |
| `psk` | key material | yes | — |
| `authenticationTimeoutMs` | integer | no | `3000` |
| `connectTimeoutMs` | integer | no | `10000` |
| `preAuthIdleTimeoutMs` | integer | no | `60000` |
| `maxTimeDifferenceSeconds` | integer | no | `30` |

### `protocol: "handoff"`

| field | type | required | absent means |
| --- | --- | --- | --- |
| `protocol` | `"handoff"` | yes | — |
| `psk` | key material | yes | — |
| `privateKey` | key material | yes | — |
| `previousPsks` | array of key material | no | no rotation window |
| `previousPrivateKeys` | array of key material | no | no rotation window |
| `authenticationTimeoutMs` | integer | no | `3000` |
| `connectTimeoutMs` | integer | no | `10000` |
| `preAuthIdleTimeoutMs` | integer | no | `60000` |
| `maxTimeDifferenceSeconds` | integer | no | `30` |

At most two retired keys per list, each distinct from the active one. Senders
always seal with the active key; the retired ones exist so a rotation can be
performed one node at a time. Drop them promptly — see
[Handoff](handoff.md#rotating-without-dropping-traffic).

## Assets

Hot. Entry nodes only. Consulted only when a routing rule names a `geoip:` or
`geosite:` condition other than the built-in `geoip:private`.

| field | type | required | absent means |
| --- | --- | --- | --- |
| `geoip` | HTTPS URL | no | no GeoIP data |
| `geosite` | HTTPS URL | no | no GeoSite data |
| `cacheDirectory` | path | no | `/var/lib/rust-reality/assets` |
| `reloadIntervalSeconds` | integer | no | one day |

Sources must be `https://`, and a URL carrying embedded credentials is
refused. A failed poll keeps the last good snapshot serving.

## Dns

Cold. The resolver is installed once for the process.

| field | type | required | absent means |
| --- | --- | --- | --- |
| `servers` | array of string | no | `["system"]` |
| `timeoutMs` | integer | no | `5000` |
| `cache` | [DnsCache](#dnscache) | no | every bound derived |

Exactly `["system"]` uses the operating system resolver through
`getaddrinfo`, honouring `/etc/resolv.conf`. `"system"` may not be mixed with
other entries.

### DnsCache

Expert surface. Every field derives a safe value and an ordinary deployment
has no reason to state any of them.

| field | type | absent means |
| --- | --- | --- |
| `maxEntries` | integer | `1024` |
| `minTtlSeconds` | integer | `5` |
| `maxTtlSeconds` | integer | `3600` |
| `negativeTtlSeconds` | integer | `60` |
| `staticTtlSeconds` | integer | `300` |
| `systemReuseMs` | integer | derived |

`maxTtlSeconds` may not be below `minTtlSeconds`. Answers without an SOA TTL
are never cached negatively.

## Network

Cold. Outbound address-family policy, independent of `listeners[].ip`.

| field | type | absent means |
| --- | --- | --- |
| `ip` | `"auto"` \| `"preferIpv4"` \| `"preferIpv6"` \| `"ipv4Only"` \| `"ipv6Only"` | `"auto"` |

## Log

Hot.

| field | type | absent means |
| --- | --- | --- |
| `level` | `"error"` \| `"warn"` \| `"info"` \| `"debug"` | `"info"` |
| `output` | `"stderr"` \| `"journald"` \| `"file"` \| `"none"` | `"stderr"` |
| `file` | [FileLog](#filelog) | — |

`stderr` is what systemd captures into the journal without further
configuration; `journald` is the same stream formatted for journald's own
parsing. `none` drops every event before any encoding or I/O, which silences
warn-level rejection and admission signal too — prefer a `level` filter unless
logging itself is unacceptable.

`file` is required by, and only meaningful for, `output: "file"`, and the two
imply each other.

### FileLog

| field | type | required | absent means |
| --- | --- | --- | --- |
| `path` | path | yes | — |
| `maxBytes` | integer | no | 64 MiB |
| `maxFiles` | integer | no | `8` |
| `maxTotalBytes` | integer | no | `maxBytes` × `maxFiles` |

## Runtime

Cold, every field.

| field | type | absent means |
| --- | --- | --- |
| `profile` | `"auto"` \| `"shared"` \| `"dedicated"` | `"auto"` |
| `tuning` | `"startup"` \| `"adaptive"` | `"startup"` |
| `objective` | `"balanced"` \| `"latency"` \| `"throughput"` | `"balanced"` |
| `statusFile` | path | no snapshot is published |
| `limits` | [Limits](#limits) | every value derived |

`statusFile` is consulted only with `tuning: "adaptive"`, and stating it under
`startup` is refused rather than ignored.

### Limits

Expert overrides. **Every field is optional, and a present field is pinned to
its stated value** — including a value equal to what would have been derived.
Absent fields derive from the detected machine.

| field | type | unpinned means |
| --- | --- | --- |
| `maxConnections` | integer | derived |
| `maxHandshakes` | integer | derived |
| `clientHelloTimeoutMs` | integer | documented default |
| `handshakeTimeoutMs` | integer | documented default |
| `connectTimeoutMs` | integer | documented default |
| `fallbackTimeoutMs` | integer | documented default |
| `splice` | boolean | the detected platform capability |
| `pipePool` | boolean | the detected platform capability |

The four timeouts are protocol security parameters rather than machine
budgets, so they are never derived. `splice` and `pipePool` exist to work
around a kernel that reports a capability and then misbehaves.

Relay buffer sizes, pool bounds, warm connection sizing, the direct-dial
barrier, replay cache capacity, and DNS cache internals have no fields: they
are implementation detail derived from the machine. See
[runtime and resources](runtime-and-resources.md).

## Reload summary

| section | hot | cold |
| --- | --- | --- |
| `role` | | ✓ |
| `listeners` | | ✓ |
| `reality` | ✓ | |
| `users` | ✓ | |
| `outbounds` | ✓ | |
| `routing` | ✓ | |
| `landing` | ✓ | |
| `egress` | ✓ | |
| `assets` | ✓ | |
| `log` | ✓ | |
| `dns` | | ✓ |
| `network` | | ✓ |
| `runtime` | | ✓ |

A reload that changes a cold setting is refused by name, and the running
configuration keeps serving. Established connections always finish on the
generation that admitted them.
