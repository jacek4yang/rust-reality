# Configuration reference

English | [简体中文](configuration.zh-CN.md)

This document covers every accepted JSON field in `rust-reality` 1.x. The
executable remains authoritative:

```shell
rust-reality schema > rust-reality.schema.json
rust-reality check --config config.json
rust-reality config format --config config.json > config.formatted.json
```

## Format and validation model

- The file is UTF-8 JSON and is limited to 4 MiB.
- Field names are case-sensitive camelCase. Enum strings are case-sensitive as
  shown below.
- Unknown fields are rejected at every typed object level.
- Structural defaults are applied only where this reference says “default”.
- `check` validates references and cross-field security/resource invariants that
  JSON Schema alone cannot express.
- A generated configuration is the safest starting point; do not copy example
  keys or UUIDs from documentation.

Top-level shape:

```json
{
  "log": {},
  "assets": {},
  "dns": {},
  "network": {},
  "inbounds": [],
  "outbounds": [],
  "routing": {},
  "advanced": {},
  "runtime": {}
}
```

| Field | Required | Default | Meaning |
| --- | --- | --- | --- |
| `log` | no | stderr/info | Logging sink, severity, and bounded file retention. |
| `assets` | no | community GeoIP/GeoSite URLs and bounded cache defaults | Routing asset sources and refresh policy. |
| `dns` | no | system resolver, 5000 ms | Shared resolver, cache, and timeout policy for every connector-side lookup. |
| `network` | no | autonomous dual stack | Outbound family selection, health memory, and fallback timing. Listener families are per-inbound `listen`. |
| `inbounds` | yes | — | At least one strictly typed `vless` or internal `nxr` or `handoff` listener. |
| `outbounds` | yes | — | At least one `direct`, `blackhole`, `socks5`, `nxr`, or `handoff` transport. |
| `routing` | yes | — | Global rules and explicit per-UUID policy groups. |
| `advanced` | no | bounded production defaults | Expert escape hatch: `advanced.limits` holds the numeric admission, direct-dial, buffer, and Linux relay policy. |
| `runtime` | no | `standard` posture, `auto` profile | Process resource posture, machine tenancy profile, and policy tuning mode. |

Upgrading a 1.4 configuration requires migration: the scalar
`"listen": "<ip>"` form and `network.addressFamily` are rejected. The complete
old-to-new mapping table is in the
[CHANGELOG 1.5.0 migration notes](../CHANGELOG.md).

## `log`

| Field | Required | Default / allowed | Meaning and constraints |
| --- | --- | --- | --- |
| `log.level` | no | `info`; `error`, `warn`, `info`, `debug` | Minimum emitted severity. Debug logging still excludes configuration and keys. |
| `log.output` | no | `stderr`; `stderr`, `journald`, `file`, `none` | `journald` writes stderr for systemd capture; `file` enables built-in rotation; `none` drops every event before any encoding or I/O. |
| `log.file` | only for `output: "file"` | absent | Forbidden for stderr/journald/none. Contains all fields below. |
| `log.file.path` | yes | — | Non-empty active file path. Parent directory must be writable by the service account. |
| `log.file.maxBytes` | yes | — | Rotate before one file exceeds `65536..=1073741824` bytes. |
| `log.file.maxFiles` | yes | — | Maximum active plus rotated files, `1..=64`. |
| `log.file.maxTotalBytes` | yes | — | Must be at least `maxBytes` and at most `maxBytes * maxFiles`. |

Secrets, full configurations, UUID values, credentials, and key material are
not emitted as structured log fields. File limits bound retained application
logs; they do not replace filesystem quotas.

## `assets`

| Field | Required | Default | Meaning and constraints |
| --- | --- | --- | --- |
| `assets.geoip` | no | jsDelivr `Loyalsoldier/v2ray-rules-dat` `geoip.dat` | HTTPS URL with a host and no embedded credentials. |
| `assets.geosite` | no | jsDelivr `Loyalsoldier/v2ray-rules-dat` `geosite.dat` | HTTPS URL with a host and no embedded credentials. |
| `assets.cacheDirectory` | no | `/var/lib/rust-reality/assets` | Non-empty persistent cache for files, validators, and external assets. |
| `assets.reloadIntervalSeconds` | no | `86400` | Asset conditional-revalidation interval; must be greater than zero. |
| `assets.requestTimeoutSeconds` | no | `120` | Absolute timeout for one request including body, `1..=300`. |
| `assets.maxBytes` | no | `134217728` | Maximum accepted bytes per GeoIP, GeoSite, or external file, `1024..=536870912`. |

Redirects are limited, HTTP validators are reused, and a candidate is parsed
before atomic publication. Failure keeps the last validated memory snapshot and
disk cache. Only GeoIP/GeoSite labels referenced by routing rules are indexed.

`ext:file:tag` reads an Xray-compatible DAT file named by a relative path below
`cacheDirectory`. The file component must contain only normal relative path
components: absolute paths, `.`/`..`, and traversal are rejected. External files
are operator-provided; only the two primary Geo URLs are downloaded directly.

## `dns`

Every connector-side name resolution — direct outbound dials, REALITY cover
targets, and SOCKS5/NXR/Handoff server names — goes through one shared
process-wide resolver. Each resolution holds a `DnsLookup` admission permit
(`advanced.limits.resourceGovernor.maxDnsLookups`), and identical concurrent lookups
coalesce into one upstream flight. Routing-strategy lookups
(`domainStrategy: IPIfNonMatch`/`IPOnDemand`) deliberately use the system
resolver instead, so the addresses checked by IP rules are exactly the
addresses dialed.

| Field | Required | Default | Meaning and constraints |
| --- | --- | --- | --- |
| `dns.servers` | no | `["system"]` | Exactly `["system"]` selects the operating-system resolver (getaddrinfo). Any other list selects the built-in DNS protocol resolver (UDP with TCP fallback): entries are an IP literal, `ip:port`, `[v6]:port`, or a hostname bootstrapped once through the system resolver at startup; the default port is 53. Mixing `system` with upstream servers is rejected. |
| `dns.timeoutMs` | no | `5000` | Absolute deadline for one resolution attempt, `1..=600000`. |
| `dns.cache.maxEntries` | no | `1024` | Ceiling on cached names, counting positive, negative, and in-flight entries, `1..=65536`. |
| `dns.cache.minTtlSeconds` | no | `5` | Floor clamp applied to upstream positive TTLs; must not exceed `maxTtlSeconds`. |
| `dns.cache.maxTtlSeconds` | no | `3600` | Ceiling clamp applied to upstream positive TTLs, `1..=86400`. |
| `dns.cache.negativeTtlSeconds` | no | `60` | Ceiling clamp applied to upstream negative (SOA) TTLs, `0..=86400`. NXDOMAIN/NODATA answers without an SOA TTL are never cached. |
| `dns.cache.staticTtlSeconds` | no | `300` | Cache duration for configured static peers (REALITY cover target, fixed SOCKS5/NXR/Handoff endpoints) in every resolver mode, `1..=86400`. |
| `dns.cache.systemReuseMs` | no | `0` | Optional recent-completion reuse window in milliseconds, applied only with `dns.servers = ["system"]`: positive getaddrinfo answers (which carry no TTL) are reused for at most this long, `0..=60000`. This is NOT authoritative TTL caching — an upstream change becomes visible only when the window expires; negative answers are never cached and there is no stale-while-revalidate. `0` disables it. Ignored with real DNS servers, where upstream TTLs govern. |

Cache identity is the (query class, name) pair: a static peer entry and a
dynamic per-session entry for the same name are independent slots with
independent lifetimes, both counting against `maxEntries`. The static TTL
can never extend a dynamic answer, and a dynamic answer can never satisfy a
static lookup.

System mode does not cache dynamic answers: getaddrinfo exposes no TTLs, so
only singleflight coalescing and admission governance apply, unless the
optional `systemReuseMs` recent-completion window is configured. With real DNS
servers, every cached positive or negative answer carries the upstream TTL
clamped to the bounds above. Configured static peers are the explicit
exception: they are cached in every resolver mode, the operator owns their
staleness through `staticTtlSeconds`, and static negative results are never
cached.

At most 64 unique addresses are retained for one routed domain. A direct
outbound reuses the exact resolved snapshot used by GeoIP/IP rules, avoiding a
second inconsistent lookup.

The resolver is installed once at startup and is process-lifetime: a reload
that changes `dns.servers`, `dns.timeoutMs`, or `dns.cache` is rejected
(`DnsPolicyChanged`), because no reload generation can swap the installed
resolver.

Upstream DNS uses plain UDP/TCP without DNSSEC validation, so point
`dns.servers` at a resolver you trust; a spoofed answer is bounded by the
clamped TTL bounds above.

## `network`

```json
{
  "dial": {
    "mode": "auto",
    "fallbackDelayMs": 250,
    "routeRefreshSeconds": 30,
    "hardFailurePenaltySeconds": 30,
    "latencyMemorySeconds": 300
  }
}
```

| Field | Required | Default / allowed | Meaning and constraints |
| --- | --- | --- | --- |
| `network.dial.mode` | no | `auto`; `auto`, `preferIpv4`, `preferIpv6`, `ipv4Only`, `ipv6Only` | Families enabled for endpoints resolved and dialed locally. It never controls inbound listeners. |
| `network.dial.fallbackDelayMs` | no | `250` | Delay before the first alternate-family attempt, `0..=5000`. Zero starts both immediately. An immediate preferred-family error launches the alternate without waiting. |
| `network.dial.routeRefreshSeconds` | no | `30` | Interval for local kernel route/source-address refresh, `1..=3600`. |
| `network.dial.hardFailurePenaltySeconds` | no | `30` | Deprioritization and bounded recovery-probe interval after repeated strong family failures, `1..=3600`. |
| `network.dial.latencyMemorySeconds` | no | `300` | Lifetime of the bounded per-family successful-setup latency EWMA, `1..=86400`. |

At startup `auto` performs one local kernel route/source-selection check and
caches a process-wide snapshot. One usable family becomes primary. When both
are usable, the system resolver/address-selection order establishes the stable
initial preference; neither family is hard-coded. The check sends no packet
and is not a public-connectivity probe. `preferIpv4` and `preferIpv6` enable
both families but choose the named family when it is usable. `ipv4Only` and
`ipv6Only` are strict: other-family results are filtered, including numeric
literals.

Periodic route refresh and real connection results update two fixed atomic
family records. Two consecutive `EAFNOSUPPORT`, `EPROTONOSUPPORT`,
`ENETUNREACH`, `EHOSTUNREACH`, `EADDRNOTAVAIL`, or `ENODEV` failures trigger
a temporary family penalty. `ECONNREFUSED` and `ECONNRESET` prove the family
path was reachable and clear pending hard-failure evidence. A generic timeout
or one unreachable destination does not poison global family health. An
alternate win while the first attempt remains pending is weak evidence only;
three consecutive observations are required to change primary. Route return
or penalty expiry permits bounded recovery trials, and two successes restore
the configured/startup preference.

Mixed A/AAAA results are de-duplicated and interleaved. At most two connects
are live, all attempts share one absolute deadline, the first success wins,
and losing tasks/sockets are cancelled and drained before return. Every live
candidate owns an FD-budget unit; if a second unit is unavailable, fallback is
serialized instead of exceeding the budget. SOCKS5/NXR/Handoff server names
are resolved through this policy, while the original destination carried to a
remote proxy remains unchanged.

## `inbounds`

`inbounds` must be non-empty. Every listener has a unique `tag`, and no two
entries may expand to the same `(listen, port)`. A tag is 1–64 ASCII letters, digits,
dots, dashes, or underscores. `port` is `1..=65535`.

Every `listen` is an object with `mode`, `ipv4`, and `ipv6`. `auto` attempts
both independent sockets and starts if at least one binds; only family/protocol
unavailability (`EAFNOSUPPORT`, `EPROTONOSUPPORT`, or `EADDRNOTAVAIL` on an
unspecified wildcard) is degradable. `EADDRINUSE`, `EACCES`, invalid concrete
addresses, and every other bind error are fatal. `dualStack` requires both
sockets. `ipv4Only` and `ipv6Only` bind exactly the named address. Every IPv6
socket has `IPV6_V6ONLY=1` applied before bind, so behavior never depends on
`net.ipv6.bindv6only`. Startup logs the exact active and unavailable families;
the topology stays fixed until restart. Any listener or outbound dial-policy
change requires restart.

### Public VLESS + REALITY + Vision inbound

```json
{
  "protocol": "vless",
  "tag": "public-reality",
  "listen": { "mode": "auto", "ipv4": "0.0.0.0", "ipv6": "::" },
  "port": 443,
  "settings": {
    "clients": [
      {
        "id": "GENERATED-UUID",
        "shortIds": ["0123456789abcdef", "1023456789abcdef"],
        "email": "operator-label",
        "flow": "xtls-rprx-vision"
      }
    ],
    "decryption": "none"
  },
  "streamSettings": {
    "network": "tcp",
    "security": "reality",
    "realitySettings": {
      "target": "www.example.com:443",
      "serverNames": ["www.example.com"],
      "privateKey": "GENERATED-X25519-PRIVATE-KEY",
      "maxTimeDiffMs": 60000,
      "coverOptimization": {
        "enabled": true,
        "warmTcp": true,
        "prebuiltProfiles": true
      }
    }
  }
}
```

The placeholder values above are intentionally not usable. Generate real state
with `config generate standalone`, `config generate line`, or `config generate
handoff`.

| Field | Required | Default / fixed value | Meaning and constraints |
| --- | --- | --- | --- |
| `protocol` | yes | fixed `vless` | Selects the only public protocol. |
| `tag` | yes | — | Unique listener/routing tag. |
| `listen` | yes | — | Object containing `mode` (`auto`, `dualStack`, `ipv4Only`, or `ipv6Only`) and the configured `ipv4`/`ipv6` addresses. |
| `port` | yes | — | TCP bind port, non-zero. |
| `settings.clients` | yes | — | Non-empty authorized-client array. UUIDs are globally unique across public inbounds. |
| `settings.clients[].id` | yes | — | Canonical hyphenated UUID; hex is case-insensitive for identity. |
| `settings.clients[].shortIds` | yes | — | Non-empty IDs owned exclusively by this UUID. Each is 2–16 even hexadecimal characters and is unique case-insensitively across the inbound. Multiple values support rotation. |
| `settings.clients[].email` | no | absent | Non-secret operator label; not used for authentication or routing. |
| `settings.clients[].flow` | yes | fixed `xtls-rprx-vision` | Any other flow is rejected. |
| `settings.decryption` | no | fixed/default `none` | Retained for Xray-shaped configuration; any other value is rejected. |
| `streamSettings.network` | yes | fixed `tcp` | Public UDP is not implemented. |
| `streamSettings.security` | yes | fixed `reality` | Plain or TLS-only VLESS is rejected. |
| `streamSettings.realitySettings.target` | yes | — | Cover endpoint `host:port`; bracket IPv6. Probe it from the server first. |
| `streamSettings.realitySettings.serverNames` | yes | — | Non-empty, case-insensitively unique array of concrete ASCII DNS names or leftmost one-label patterns such as `*.lmu.edu`. |
| `streamSettings.realitySettings.privateKey` | yes | — | URL-safe unpadded base64 decoding to exactly 32 X25519 bytes. Secret. |
| `streamSettings.realitySettings.maxTimeDiffMs` | no | `60000` | Accepted client clock difference, `0..=600000`; zero disables this check. |
| `streamSettings.realitySettings.coverOptimization.enabled` | no | `true` | Master switch for authenticated-only cover latency optimizations. It never changes rejection/fallback behavior. |
| `streamSettings.realitySettings.coverOptimization.warmTcp` | no | `true` | Maintain bounded TCP-established cover sockets. No TLS byte is sent before authenticated checkout. |
| `streamSettings.realitySettings.coverOptimization.prebuiltProfiles` | no | `true` | Collect bounded, ephemeral cover profiles with controlled probes and locally build fresh authenticated flights only for exact, validated ClientHello classes. A miss always uses the live cover. |

Every public UUID must appear exactly once in `routing.users[].userIds`.

Wildcard server names follow certificate-style one-label semantics:

- `*.lmu.edu` accepts the concrete SNI `www.lmu.edu` or `vpn.lmu.edu`;
- it does not accept `lmu.edu`, `a.b.lmu.edu`, or a literal `*.lmu.edu` SNI;
- the wildcard must be the entire leftmost label, and at least two suffix labels
  are required, so `www.*.edu`, `*.*.edu`, and `*.edu` are rejected;
- clients must send a concrete SNI. For `self-test`, a wildcard can be probed
  only when `target` contains a matching concrete hostname, for example target
  `www.lmu.edu:443` with pattern `*.lmu.edu`.

Use a concrete `--server-name` during initial generation when possible, then
add an audited wildcard only when multiple real certificate names are required.

### Internal NXR inbound

```json
{
  "protocol": "nxr",
  "tag": "internal-nxr",
  "listen": { "mode": "auto", "ipv4": "0.0.0.0", "ipv6": "::" },
  "port": 7443,
  "settings": {
    "preSharedKey": "GENERATED-NXR-KEY",
    "maxTimeDifferenceSeconds": 30,
    "maxNonceEntries": 65536,
    "nonceRetentionSeconds": 120,
    "preAuthIdleTimeoutMs": 60000,
    "authenticationTimeoutMs": 3000,
    "connectTimeoutMs": 10000
  }
}
```

| Field | Required | Default | Meaning and constraints |
| --- | --- | --- | --- |
| `protocol` | yes | fixed `nxr` | Selects the internal landing protocol. |
| `tag` | yes | — | Unique listener/operational tag. |
| `listen` | yes | — | Independent inbound listener topology; restrict internal addresses at the host/provider firewall. |
| `port` | yes | — | Raw NXR TCP port, non-zero. |
| `settings.preSharedKey` | yes | — | Independent URL-safe unpadded base64 value decoding to exactly 32 bytes. |
| `settings.maxTimeDifferenceSeconds` | no | `30` | Accepted absolute wall-clock skew, `1..=300`. |
| `settings.maxNonceEntries` | no | `65536` | Maximum verified nonce entries, `1..=1000000`. |
| `settings.nonceRetentionSeconds` | no | `120` | Replay retention; from `2 * maxTimeDifferenceSeconds + 1` through `86400`. |
| `settings.preAuthIdleTimeoutMs` | no | `60000` | Maximum accepted lifetime with zero protocol bytes, `1..=600000`; no authentication or destination work occurs in this phase. |
| `settings.authenticationTimeoutMs` | no | `3000` | Deadline to finish the bounded authentication request after its first byte, `1..=600000`. |
| `settings.connectTimeoutMs` | no | `10000` | Deadline to connect only after authentication succeeds, `1..=600000`. |

NXR authentication failure closes silently before DNS or destination connect.
After success, the connection becomes raw bidirectional bytes. NXR has no
post-authentication encryption and must not be exposed to the Internet.
The first request byte switches from the long bounded idle phase to the short
authentication deadline; sending one byte cannot retain the idle lifetime.

### Internal Handoff inbound

```json
{
  "protocol": "handoff",
  "tag": "internal-handoff",
  "listen": { "mode": "auto", "ipv4": "0.0.0.0", "ipv6": "::" },
  "port": 7443,
  "settings": {
    "preSharedKey": "GENERATED-HANDOFF-KEY",
    "privateKey": "GENERATED-X25519-PRIVATE-KEY",
    "maxTimeDifferenceSeconds": 30,
    "maxNonceEntries": 65536,
    "nonceRetentionSeconds": 120,
    "preAuthIdleTimeoutMs": 60000,
    "authenticationTimeoutMs": 3000,
    "connectTimeoutMs": 10000
  }
}
```

| Field | Required | Default | Meaning and constraints |
| --- | --- | --- | --- |
| `protocol` | yes | fixed `handoff` | Selects the internal session-transfer protocol. |
| `tag` | yes | — | Unique listener/operational tag. |
| `listen` | yes | — | Independent inbound listener topology; restrict internal addresses at the host/provider firewall. |
| `port` | yes | — | Raw Handoff TCP port, non-zero. |
| `settings.preSharedKey` | yes | — | Independent URL-safe unpadded base64 value decoding to exactly 32 bytes; the pair PSK shared with the line node's handoff outbound. |
| `settings.privateKey` | yes | — | Independent static X25519 private key, URL-safe unpadded base64 decoding to exactly 32 bytes; its public half is the line outbound's `landingPublicKey`. |
| `settings.maxTimeDifferenceSeconds` | no | `30` | Accepted absolute wall-clock skew, `1..=300`. |
| `settings.maxNonceEntries` | no | `65536` | Maximum reserved transfer nonces, `1..=1000000`. |
| `settings.nonceRetentionSeconds` | no | `120` | Replay retention; from `2 * maxTimeDifferenceSeconds + 1` through `86400`. |
| `settings.preAuthIdleTimeoutMs` | no | `60000` | Maximum accepted lifetime with zero transfer bytes, `1..=600000`; no continuation allocation, crypto, replay reservation, or destination work occurs. |
| `settings.authenticationTimeoutMs` | no | `3000` | Deadline to finish the bounded sealed transfer after its first byte, `1..=600000`. |
| `settings.connectTimeoutMs` | no | `10000` | Deadline to dial the transferred destination after authentication succeeds, `1..=600000`. |
| `settings.egress` | no | direct dial | Outbound tag selecting how the landing reaches transferred destinations. The tag must reference a `direct`, `socks5`, `nxr`, or `blackhole` outbound; a `handoff` outbound is rejected — landings cannot be chained. |
| `settings.previousPreSharedKeys` | no | `[]` | Retired pair PSKs still accepted during a bounded key-rotation window: at most two independent URL-safe unpadded base64 values decoding to exactly 32 bytes each; duplicates within the list and any value equal to `preSharedKey` are rejected. |
| `settings.previousPrivateKeys` | no | `[]` | Retired static X25519 private keys still accepted during a bounded key-rotation window; same shape, two-entry bound, and equality rules as `previousPreSharedKeys`. |

The listener verifies exactly one single-flight transfer per connection — a
fresh ephemeral X25519 Diffie-Hellman against `privateKey`, mixed with the
pair PSK and sealed with ChaCha20-Poly1305 over the full transcript — in this
order: header structure, timestamp window, nonce reserve against the bounded
replay cache, key agreement, AEAD open, then internal consistency checks.
Every failure closes silently with zero response bytes, before DNS or
destination connect. On success the listener reconstructs the session's TLS
record layers, dials the transferred destination — directly by default, or
through the outbound selected by `settings.egress` — and resumes the
session; afterwards the connection carries the session's raw TLS ciphertext.

Key independence is enforced within one configuration file: a Handoff
`preSharedKey` equal to any NXR `preSharedKey` or to any REALITY
`privateKey`, or a Handoff `privateKey` equal to any REALITY `privateKey`,
fails validation — and so does any previous-key entry equal to that
material. Independence across nodes remains the operator's obligation. The Handoff listener carries live
session keys and must not be exposed to the Internet: allow it only from the
line nodes' source addresses at the firewall.

For every Handoff or NXR inbound, validation requires
`preAuthIdleTimeoutMs >= min(warmConnections.idleTimeoutMs,
warmConnections.maxLifetimeMs) + authenticationTimeoutMs`. This prevents the
normal LINE ready lifetime from systematically outliving LANDING. Idle sockets
remain unauthenticated and are also bounded by
`advanced.limits.resourceGovernor.maxPreAuthIdleConnections`.

#### Key rotation

`preSharedKey` and `privateKey` rotate without downtime in three steps.
Previous keys never appear on the wire — senders always seal with the active
pair only — so a line node that never sets these fields interoperates with a
landing that does, in either upgrade order.

1. Reload the landing with the new pair active and the retired values listed
   in `previousPreSharedKeys`/`previousPrivateKeys`. The landing now opens
   transfers sealed under the retired material as well, and emits one
   `handoff_rotation_window_open` warning per listener per generation while
   any retired key remains configured.
2. Move every line node's handoff outbound to the new pair (`preSharedKey`
   and the new `landingPublicKey`).
3. Reload the landing with the previous-key lists empty again.

Drop previous keys promptly: while a retired key stays accepted, the
forward-secrecy bound the rotation exists to restore has not yet taken hold
(see the [threat model](threat-model.md)). The open path tries the active
pair first, bounds all candidate trials at nine, and never reveals which
candidate matched — failures keep the closed error vocabulary and the silent
close.

## `outbounds`

`outbounds` must be non-empty. Outbound tags use the same 1–64-character syntax
and must be unique among outbounds.

### Direct

```json
{ "protocol": "direct", "tag": "direct" }
```

Connects directly to the selected destination subject to
`advanced.limits.directBarrier` and connection timeout. No `settings` field is accepted.

### Blackhole

```json
{
  "protocol": "blackhole",
  "tag": "block",
  "settings": { "responseDelayMs": 0 }
}
```

| Field | Required | Default | Meaning and constraints |
| --- | --- | --- | --- |
| `settings` | no | empty/default | Close behavior. |
| `settings.responseDelayMs` | no | `0` | Delay before close, `0..=30000`. |

No destination connection is opened.

### SOCKS5

```json
{
  "protocol": "socks5",
  "tag": "socks-egress",
  "settings": {
    "address": "127.0.0.1",
    "port": 1080,
    "username": "user",
    "password": "secret",
    "warmTcp": true
  }
}
```

| Field | Required | Default | Meaning and constraints |
| --- | --- | --- | --- |
| `settings.address` | yes | — | Valid ASCII hostname or IP address. |
| `settings.port` | yes | — | SOCKS5 TCP port, non-zero. |
| `settings.username` | no | absent | Must appear with `password`, be non-empty, and be at most 255 bytes. Secret-protected in debug output. |
| `settings.password` | no | absent | Must appear with `username`, be non-empty, and be at most 255 bytes. Secret. |
| `settings.warmTcp` | no | `true` | Pre-establish TCP only. Disable for upstreams with aggressive idle/connection limits. SOCKS method/authentication/CONNECT never occurs before checkout. |

Without credentials the client negotiates no-authentication. With both fields it
uses username/password authentication.

### NXR outbound

```json
{
  "protocol": "nxr",
  "tag": "landing",
  "settings": {
    "address": "10.0.0.2",
    "port": 7443,
    "preSharedKey": "GENERATED-NXR-KEY",
    "warmTcp": true
  }
}
```

| Field | Required | Default | Meaning and constraints |
| --- | --- | --- | --- |
| `settings.address` | yes | — | Valid landing-node ASCII hostname or IP address. |
| `settings.port` | yes | — | Firewall-restricted NXR TCP port, non-zero. |
| `settings.preSharedKey` | yes | — | Same independent URL-safe unpadded 32-byte key as the landing inbound. |
| `settings.warmTcp` | no | `true` | Pre-establish protocol-unprivileged single-use TCP sockets; each checkout creates a fresh timestamp, nonce, and HMAC. |

Each user TCP flow owns one NXR TCP connection and sends one authenticated,
strictly bounded request. A warm socket is single-use; there is no multiplexing
and a miss immediately opens the normal cold connection.

### Handoff outbound

```json
{
  "protocol": "handoff",
  "tag": "landing",
  "settings": {
    "address": "10.0.0.2",
    "port": 7443,
    "preSharedKey": "GENERATED-HANDOFF-KEY",
    "landingPublicKey": "GENERATED-X25519-PUBLIC-KEY",
    "connectTimeoutMs": 10000,
    "firstByteTimeoutMs": 15000,
    "warmTcp": true
  }
}
```

| Field | Required | Default | Meaning and constraints |
| --- | --- | --- | --- |
| `settings.address` | yes | — | Valid landing-node ASCII hostname or IP address. |
| `settings.port` | yes | — | Firewall-restricted Handoff TCP port, non-zero. |
| `settings.preSharedKey` | yes | — | Same independent URL-safe unpadded 32-byte pair PSK as the landing inbound. |
| `settings.landingPublicKey` | yes | — | The landing node's static X25519 public key, URL-safe unpadded base64 decoding to exactly 32 bytes; public material, not a secret. |
| `settings.connectTimeoutMs` | no | `10000` | Deadline to dial the landing node and write the one sealed transfer, `1..=600000`. |
| `settings.firstByteTimeoutMs` | no | `15000` | Deadline for the landing node's first downlink byte after the transfer, `1000..=600000`; see below. |
| `settings.warmTcp` | no | `true` | Pre-establish protocol-unprivileged single-use TCP sockets. Every checkout still seals a fresh authenticated transfer. |

Routing a user to a handoff outbound transfers the whole accepted session to
the landing node at the session boundary: one TCP connection per session
carries one sealed transfer and then the session's raw TLS ciphertext — no
multiplexing or socket reuse. The transfer protocol answers every failure
with a silent close, so the line node treats a missing first downlink byte
within `firstByteTimeoutMs` as the rejection signal and resets the client
socket; the session is never served locally after a failed transfer.

`firstByteTimeoutMs` must exceed the landing node's
`authenticationTimeoutMs + connectTimeoutMs` with headroom: the first sealed
record is produced only after the transfer is read, authenticated, and the
destination dialed, so a shorter deadline resets viable sessions whose
landing node is slow or congested. The default 15000 ms covers the default
landing budgets (3000 + 10000 ms).

## `routing`

```json
{
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "globalRules": [],
    "users": [
      {
        "name": "default-users",
        "userIds": ["GENERATED-UUID"],
        "defaultOutbound": "direct",
        "rules": []
      }
    ]
  }
}
```

| Field | Required | Default | Meaning and constraints |
| --- | --- | --- | --- |
| `routing.domainStrategy` | no | `IPIfNonMatch` | `AsIs`, `IPIfNonMatch`, or `IPOnDemand`; behavior below. |
| `routing.globalRules` | no | `[]` | Ordered prelude evaluated for every public user. Keep small and auditable. |
| `routing.users` | yes | — | User policy groups. May be empty only when no public VLESS UUID exists, such as an NXR-only landing node. |
| `routing.users[].name` | yes | — | Non-empty unique operator-facing group name. |
| `routing.users[].userIds` | yes | — | Non-empty canonical UUID array; each configured public UUID is assigned exactly once. |
| `routing.users[].defaultOutbound` | yes | — | Existing outbound tag selected if no rule matches. |
| `routing.users[].rules` | no | `[]` | Ordered rules using the same shape as global rules. |

Evaluation is deterministic first-match: all global rules, then the authenticated
UUID group's rules, then its default. Groups are a readability/ownership
boundary; they are not matched by source IP or email.

### Rule fields

| Field | Required | Default | Meaning and constraints |
| --- | --- | --- | --- |
| `name` | yes | — | Non-empty operator-facing rule name. |
| `outbound` | yes | — | Existing outbound tag. |
| `domain` | no | `[]` | Domain/GeoSite matchers. |
| `ip` | no | `[]` | IP/CIDR/GeoIP matchers. |
| `port` | no | `[]` | Strings such as `"443"` or inclusive `"1000-2000"`; ports are `1..=65535`. |
| `network` | no | `[]` | `"tcp"` or `"udp"`; the current public data path carries TCP, so `udp` does not match it. |
| `inboundTag` | no | `[]` | Existing public VLESS inbound tags. Internal NXR tags are not public routing identities. |

A rule must contain at least one condition. Categories are ANDed: if both
`domain` and `port` are present, both must match. Values inside one category are
ORed: any listed domain and any listed port can satisfy their category.

### Domain matchers

| Syntax | Behavior |
| --- | --- |
| `full:api.example.com` | Case-insensitive exact hostname. |
| `domain:example.com` | DNS-label-aware suffix; matches `example.com` and `a.example.com`, not `badexample.com`. |
| `example.com` | Same suffix behavior as `domain:`. |
| `keyword:example` | Case-insensitive ASCII substring. |
| `regexp:<expression>` | Case-insensitive Rust regular expression, compiled when routing is built. |
| `geosite:cn` | Label from configured community `geosite.dat`. |
| `ext:custom.dat:label` | Domain label from an Xray-compatible DAT file below `cacheDirectory`. |

### IP matchers

| Syntax | Behavior |
| --- | --- |
| `192.0.2.1` / `2001:db8::1` | One exact address. |
| `10.0.0.0/8` / `2001:db8::/32` | IPv4/IPv6 CIDR with valid prefix. |
| `geoip:private` | Label from configured community `geoip.dat`. |
| `ext:custom.dat:label` | IP label from an Xray-compatible DAT file below `cacheDirectory`. |

### `domainStrategy`

| Value | Behavior for a domain destination |
| --- | --- |
| `AsIs` | Router never resolves for IP rules. Domain rules can match; selected outbound resolves if needed. |
| `IPIfNonMatch` | Evaluate without DNS first. Resolve only if evaluation reaches the user default and an applicable global/user IP rule exists, then evaluate again. |
| `IPOnDemand` | If an applicable global/user IP rule exists, resolve before rule evaluation. |

An unknown user fails before DNS. DNS results are bounded and attached to the
route decision so direct dialing uses the same addresses.

### Routing example

```json
{
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "globalRules": [
      {
        "name": "reject-private",
        "outbound": "block",
        "ip": ["geoip:private"]
      },
      {
        "name": "reject-ads",
        "outbound": "block",
        "domain": ["geosite:category-ads-all"]
      }
    ],
    "users": [
      {
        "name": "landing-users",
        "userIds": ["GENERATED-UUID-A"],
        "defaultOutbound": "landing",
        "rules": [
          {
            "name": "local-direct",
            "outbound": "direct",
            "domain": ["geosite:cn"]
          }
        ]
      },
      {
        "name": "direct-users",
        "userIds": ["GENERATED-UUID-B"],
        "defaultOutbound": "direct",
        "rules": []
      }
    ]
  }
}
```

Replace placeholders with UUIDs present in public inbound clients.

## `advanced`

Expert escape hatch. `advanced.limits` holds the complete numeric resource
and relay policy; every field carries the bounded production default, so the
whole object, `limits`, or any of its four child objects may be absent. If
`resourceGovernor`, `directBarrier`, `warmConnections`, or `relay` is explicitly present, fields
marked “required when object present” must be supplied; do not assume a
partial object inherits every default. `config format` makes applied defaults
visible.

How these numbers become the effective policy depends on
`runtime.tuning.mode`: under `fixed` they are used verbatim; under the
derived modes (`startup`, `adaptive`) a field whose value differs from the
built-in default is operator-pinned and always wins, while every other field
is derived from the detected machine at startup. See
[Startup policy derivation](#startup-policy-derivation).

### `advanced.limits.resourceGovernor`

| Field | Required when object present | Whole-object default | Constraints / meaning |
| --- | --- | --- | --- |
| `maxConnections` | yes | `16384` | Greater than zero; parent ceiling for accepted connections. |
| `maxHandshakes` | yes | `1024` | Greater than zero and no more than `maxConnections`; sessions actively authenticating after their first protocol byte. |
| `maxPreAuthIdleConnections` | no | `1024` | Greater than zero and no more than `maxConnections`; accepted Handoff/NXR sockets that have sent zero protocol bytes. Reclaimed under pressure before active sessions. |
| `maxFallbacks` | yes | `512` | Greater than zero and no more than `maxConnections`; concurrent cover relays. |
| `maxCryptoOperations` | yes | `128` | Greater than zero and no more than `maxHandshakes`; expensive crypto admission. |
| `maxReplayEntries` | yes | `65536` | Greater than zero; pending plus committed REALITY replay entries. |
| `replayRetentionMs` | no | `120000` | Retention after verified ClientFinished, `1..=600000`. |
| `maxDnsLookups` | no | `64` | Concurrent resolutions admitted to the shared DNS resolver, across both the system getaddrinfo pool and upstream server flights. |
| `clientHelloTimeoutMs` | yes | `3000` | ClientHello read deadline, `1..=600000`, no more than handshake timeout. |
| `handshakeTimeoutMs` | yes | `10000` | Authenticated handshake deadline, `1..=600000`. |
| `connectTimeoutMs` | yes | `10000` | Cover/outbound connect deadline, `1..=600000`, no more than fallback timeout. |
| `fallbackTimeoutMs` | yes | `120000` | Maximum fallback lifetime, `1..=600000`. |

### `advanced.limits.directBarrier`

| Field | Required when object present | Whole-object default | Constraints / meaning |
| --- | --- | --- | --- |
| `maxConcurrent` | yes | `2048` | Concurrent direct dials, greater than zero and no more than `maxConnections`. |
| `maxPerSecond` | yes | `4096` | New direct dials per second, from 1 through 1,000,000,000. |

This isolates direct destination pressure from authenticated connection count.

### `advanced.limits.warmConnections`

| Field | Required when object present | Whole-object default | Constraints / meaning |
| --- | --- | --- | --- |
| `minReady` | yes | `4` | Low-demand ready floor; may be zero and never exceeds `maxReady`. |
| `maxReady` | yes | `256` | Per-endpoint ready ceiling, `1..=4096`. |
| `maxConnecting` | yes | `64` | Per-endpoint simultaneous speculative dials, `1..=min(maxReady, 1024)`. |
| `refillBatch` | yes | `16` | Dials submitted per controller reconciliation, `1..=maxConnecting`. |
| `idleTimeoutMs` | yes | `30000` | Maximum unused idle age, `100..=3600000`. |
| `maxLifetimeMs` | yes | `300000` | Absolute unused-socket lifetime, at least `idleTimeoutMs` and no more than one hour. |
| `shrinkDelayMs` | yes | `30000` | Demand-free hysteresis before gradual shrink, `100..=3600000`. |

These limits apply to enabled REALITY cover, Handoff, NXR, and SOCKS5 pools per
endpoint; a strict process-lifetime authority additionally
bounds all generations, and the FD budget remains final. A checkout never waits
for refill. Under pressure speculative ready sockets are dropped before the
normal cold path is attempted.

### `advanced.limits.relay`

| Field | Required when object present | Whole-object default | Constraints / meaning |
| --- | --- | --- | --- |
| `bufferBytes` | yes | `32768` | Bytes per pooled userspace buffer, `4096..=1048576`. |
| `maxPooledBuffers` | yes | `4096` | Global pooled-buffer ceiling, `2..=65536`. |
| `maxSpliceRelays` | no | `256` | With splice enabled, greater than zero and no more than `maxConnections`. Each relay consumes two pipe pairs. |
| `maxRelayMemoryBytes` | no | `536870912` | Ceiling on pooled plus registered relay buffer memory. |
| `pipePool` | no | `true` | Reuse splice pipes process-wide instead of creating/resizing/destroying them per session. |
| `maxPooledPipes` | no | `256` | Pooled-pipe ceiling; the pool accounts `maxPooledPipes × 2` pipe capacities of memory. |
| `splice` | yes | `true` | Permit bounded nonblocking Linux splice only across plaintext TCP boundaries. |

### Backend selection

The automatic preference order is `splice`, then `buffered`.

A backend may hand the connection to the next one **only before it has
transferred a byte**. After any byte moves, a backend error terminates the relay;
the connection is never replayed through another backend. This is enforced
structurally: the only way to construct a decline is through the shared transfer
ledger, which refuses once either counter is nonzero.

No kernel backend ever sees a byte that still carries TLS records or Vision
frames. Each Vision direction has its own exact authenticated Direct boundary:
a direction that has crossed it may be relayed by directional splice while the
opposite direction is still framed; the bilateral whole-socket splice is used
only when both directions have independently become raw and pairing is safe.

### Resource accounting

Validation rejects an impossible budget before any listener binds, using checked
arithmetic:

```text
buffered_memory = maxPooledBuffers * bufferBytes
pipe_memory     = 0 when splice is disabled
                | maxPooledPipes * 2 * 512 KiB when pipePool is on
                | maxSpliceRelays * 4 * 512 KiB when pipePool is off

buffered_memory + pipe_memory <= maxRelayMemoryBytes
```

`maxPooledBuffers` is a **buffer count**, never a byte budget.

### Capability reporting

One `relay_backend_report` event is emitted at startup with one line per
backend. An unavailable backend names a fixed reason from a closed vocabulary —
`disabled`, `unsupportedOperatingSystem`, `unsupportedKernel`, `missingOperation`,
`missingCapability`, `blockedBySeccomp`, `blockedByLsm`, `resourceLimit`,
`queueUnavailable`, `unsafeToArm`, `existingQueuedBytes`,
`initializationFailure` — and the decline is never repeated per connection.

Splice never crosses the REALITY/TLS security boundary. If splice resources are
unavailable before transfer starts, relay falls back to bounded userspace
buffers.

## `runtime`

Process-level resource posture. The whole object is optional.

| Field | Required when object present | Default / allowed | Constraints / meaning |
| --- | --- | --- | --- |
| `runtime.profile` | no | `auto`; `auto`, `shared`, `dedicated` | Who owns this machine. `shared` selects the standard resource posture and `dedicated` the dedicated posture (raise the soft `RLIMIT_NOFILE` to the hard limit, derive the descriptor budget with the dedicated headroom, and run the bounded memory-pressure monitor; see [Dedicated resource mode](#dedicated-resource-mode)). `auto` resolves to `dedicated` only when the cgroup v2 tenancy boundary is fully observable (a finite `cpu.max` quota and a finite `memory.max`); it never guesses dedicated on bare metal. Cold setting; changing it requires a restart. |
| `runtime.tuning.mode` | no | `startup`; `fixed`, `startup`, `adaptive` | How the numeric policy is produced. `fixed` takes the numbers from `advanced.limits` (or the built-in defaults) and never moves them — v1.5 behavior. `startup` derives every unpinned field once at startup from the detected machine. `adaptive` derives exactly like `startup` and additionally runs the adaptive controller, which adjusts the soft admission ceilings and the direct-dial rate within the startup-derived bounds. See [Startup policy derivation](#startup-policy-derivation) and [Adaptive ceilings](#adaptive-ceilings). |
| `runtime.tuning.objective` | no | `balanced`; `latency`, `balanced`, `throughput` | Shape of the derived numbers; consulted only by the derived tuning modes (`startup`, `adaptive`). |
| `runtime.statusFile` | no | unset; a file path | Consulted only in `adaptive` tuning mode: the controller atomically rewrites this JSON snapshot at startup and on every ceiling or pressure transition, and `rust-reality runtime report` reads it. Cold setting; changing it requires a restart. |

### Startup policy derivation

With `runtime.tuning.mode: startup` (the default) the serve path derives the
numeric policy once at startup from the detected machine — the same formulas
`config autotune` uses, but fully passive: no benchmark, storage, or loopback
probe runs at startup, so readiness is never delayed. The inputs `autotune`
measures fall back to their conservative tiers (the 32 KiB buffer tier, no
measured setup capacity), so a derived plan never invents numbers the
autotuner would not produce without measurements.

Derivation is field-by-field. A field whose `advanced.limits` value differs
from the built-in default is operator-pinned and always wins; every other
field is derived. (Writing a value equal to the default is indistinguishable
from not writing it.) All timeouts and `replayRetentionMs` are never
derived — they are protocol security parameters carried from the
configuration — and the unpinned `relay.splice`/`relay.pipePool` booleans
follow the derived platform capability.

The objective scales selected derived outputs after the balanced derivation,
before the hard caps; the safety floors apply last, so `latency` can never
under-provision and `throughput` never exceeds the machine-derived ceilings:

| Field | `latency` | `balanced` | `throughput` |
| --- | --- | --- | --- |
| `resourceGovernor.maxConnections` | ×0.5 | ×1 | ×1.5 |
| `resourceGovernor.maxHandshakes` | ×1 | ×1 | ×1 |
| `resourceGovernor.maxPreAuthIdleConnections` | ×1 | ×1 | ×1 |
| `resourceGovernor.maxFallbacks` | ×0.5 | ×1 | ×1 |
| `resourceGovernor.maxCryptoOperations` | ×1 | ×1 | ×1 |
| `resourceGovernor.maxReplayEntries` | follows `maxConnections` (×4) | | |
| `resourceGovernor.maxDnsLookups` | ×1 | ×1 | ×1 |
| `directBarrier.maxConcurrent` | ×0.5 | ×1 | ×1.5 |
| `directBarrier.maxPerSecond` | ×0.5 | ×1 | ×2 |
| `relay.bufferBytes` | one tier down | 32 KiB default tier | one tier up (max 64 KiB) |
| `relay.maxPooledBuffers` | ×0.5 | ×1 | ×2 |
| `relay.maxSpliceRelays` / `relay.maxPooledPipes` | ×1 | ×1 | ×2 |
| `relay.maxRelayMemoryBytes` | ×0.75 | ×1 | ×1.5 (≤ memory/4) |

Fields not listed — every timeout and `replayRetentionMs` — are carried from
the configuration unchanged.

The derived policy is validated exactly like `config autotune` output before
any listener binds. One `runtime_plan_report` log event at startup records
the resolved resource mode, the tuning mode and objective, and the effective
runtime pool sizes. `rust-reality runtime explain --config …` prints the same
plan offline: the detected machine, the resolved profile, the effective value
of every field with its source (`derived`, `override`, or `default`), and the
applied bounds.

The effective policy is cold. A reload re-derives the candidate against the
current machine view and rejects when the derived numbers would differ —
including drift caused only by a changed cgroup boundary since startup —
because the admission pools were sized at process start and cannot move.

### Adaptive ceilings

With `runtime.tuning.mode: adaptive` the startup derivation runs exactly as
in `startup` mode, and a controller then adjusts the *soft* ceilings at
runtime. A soft ceiling can only tighten admission below the constructed
pool size; permits already held are never revoked, so established sessions
are unaffected.

- **Knobs**: the six `resourceGovernor` admission ceilings, plus
  `directBarrier.maxConcurrent` and `directBarrier.maxPerSecond` (the GCRA
  dial rate, driven by the same dial-demand signal as the concurrency
  ceiling). Nothing else moves: all timeouts, `replayRetentionMs`, relay
  buffer and pool sizes, the descriptor budget, listener topology, and DNS
  policy are startup-only.
- **Bounds**: each knob is bounded above by its startup-derived value (the
  effective policy the pools were constructed with) and below by the v1.5
  built-in default for the field, lowered to the startup value when an
  operator pin sits below the default — a pinned ceiling is respected
  exactly and the server always keeps a responsive minimum.
- **Decisions**: the controller ticks every 5 seconds and measures held
  permits against the soft ceiling in effect. A knob scales up after 3
  consecutive ticks at or above 85% utilization and down after 6 consecutive
  ticks at or below 40% — fast to protect, slow to relax — with a minimum of
  30 seconds between successive changes to the same knob. Each step is 25%
  of the startup value, quantized (counts in 64s, the dial rate in 16s).
- **Critical pressure**: one tick at critical resource pressure clamps every
  knob to its floor in a single step, bypassing hysteresis and dwell.
  Recovery walks back up through the normal hysteresis.
- **Observability**: every knob change emits exactly one
  `adaptive_ceiling_changed` log event; nothing is logged per tick. When
  `runtime.statusFile` is set, the controller additionally rewrites that
  JSON file atomically at startup and on every ceiling or pressure
  transition; `rust-reality runtime report --status-file <PATH> [--json]`
  prints the last published snapshot.

### Bootstrap runtime topology

`serve` detects the machine and resolves the profile *before* building the
Tokio runtime, so the runtime pools are sized from the same machine view the
policy derivation uses. Under the `dedicated` posture the pools are sized
explicitly: `worker_threads = effective_cpus().clamp(1, 64)` — cgroup-quota
aware, and the multi-thread runtime is kept even at 1 vCPU — and
`max_blocking_threads = (32 + 8 × effective_cpus).clamp(64, 512)`, the pool
DNS and probe work sit on. The shared/standard posture keeps the tokio
defaults (one worker per visible CPU, 512 blocking threads), exactly as v1.5
built the runtime. Both sizes are cold: tokio cannot resize a live runtime,
so they are fixed for the process lifetime. CLI-only commands keep a small
single-thread runtime.


### Dedicated resource mode

`{ "runtime": { "profile": "dedicated" } }` declares that the process
owns the machine — or, under a container runtime, its cgroup — and budgets
against measured machine resources instead of assuming nothing about
co-tenants. The mode is a **cold setting**: it shapes the process-lifetime
descriptor budget, the soft-limit raise, and the memory monitor, so a SIGHUP
reload that changes it is rejected and the last good generation keeps
running.

**Startup detection.** Once, before any listener is bound, the process
detects soft/hard `RLIMIT_NOFILE`, soft/hard `RLIMIT_MEMLOCK` (reported
only), and the cgroup v2 of the current process (`cpu.max`,
`cpuset.cpus.effective`, `memory.current`, `memory.high`, `memory.max`; the
literal `max` is treated as unbounded, and absent or unreadable files degrade
to "not reported" rather than a fabricated value), falling back to
`MemTotal` and the visible CPU count when cgroup files are absent. Everything
is reported in one structured `machine_report` event.

**Soft-limit raise.** When the hard `RLIMIT_NOFILE` exceeds the soft limit,
the dedicated mode raises the process's own soft limit to the hard limit via
`setrlimit(2)` — no privilege required, nothing outside the process touched.
A failed raise is not fatal; the derivation continues with the effective soft
limit. Keep `LimitNOFILE=` in the systemd unit: the raise can only reach the
*inherited* hard limit.

**Descriptor budget.** Same formula as standard mode
(`effective_soft_limit - fixed_reserve - headroom`), with a larger headroom
of `max(limit / 10, 64)` instead of `max(limit / 16, 64)` — the process plans
against the raised limit and keeps a tenth of it for descriptor consumers it
cannot account for. The invariant `budget + reserve + headroom <=
effective_soft_limit` holds under both policies.

**Memory budget.** The effective memory total is the finite cgroup
`memory.max` (capped by `MemTotal`), otherwise `MemTotal`; when neither is
readable the memory dimension is disabled rather than invented. Watermarks,
each with separate enter/exit thresholds so oscillation produces no
transitions:

| Boundary | Fraction of total |
|---|---|
| usable budget | 80% |
| pressure enter / exit | 60% / 50% |
| critical enter / exit | 90% / 80% |

**Pressure model.** Two dimensions feed one effective state: the FD-budget
watermarks (high at 15/16 of capacity, low at 13/16) and a monitor task
sampling cgroup `memory.current` (fallback: resident set from
`/proc/self/statm`) once per second. The monitor is the only writer; the
read path is one atomic load, never in a data loop. An unreadable sample
keeps the previous state.

| State | New fallback | New handshake | New accept | New direct dial | Established traffic |
|---|---|---|---|---|---|
| `Normal` | admitted | admitted | admitted | admitted | flows |
| `Pressure` | refused | refused | admitted | admitted | flows |
| `Critical` | refused | refused | paused / failed fast | failed fast | flows |

Permits already held are never revoked, so established relays continue
through both tiers; the listener parks on a `Notify` wakeup and resumes
automatically on hysteresis exit.

**What the mode never does.** It never touches a sysctl, a cgroup file,
another process, or the hard limits (the only mutation is raising its own
soft `RLIMIT_NOFILE`); never admits beyond the derived budgets; never
pre-allocates or burns CPU to "use" the machine (the only periodic task is
the one-second memory sample); never polls `/proc/self/fd`.

**Operational guidance.** Use `dedicated` when the process is the single
tenant of a machine, VM, or cgroup; keep `standard` when unpredictable
workloads share the descriptor limit or memory cgroup. If `memory_total` is
`0` in `machine_report`, no memory watermark exists — treat that as a
monitoring gap, not as headroom.

## Reload boundaries

`serve`/`run` receives SIGHUP and builds one complete candidate. Publication is
atomic; failure keeps the old generation, and established connections keep the
generation they acquired.

Hot-updateable with compatible topology:

- logging;
- asset URLs/cache contents/refresh settings;
- VLESS users and REALITY authentication/cover state;
- outbound definitions, routing groups, and rules;
- NXR key, clock window, and I/O timeouts when replay capacity/retention stay
  unchanged;
- Handoff key material, clock window, timeouts, and the egress outbound
  selection when replay capacity/retention stay unchanged.

Restart required:

- adding/removing a listener, changing `listen.mode`, either bind address,
  port, or protocol;
- any `network.dial` change, because the startup snapshot and shared health
  state are process-lifetime;
- any `dns` change (`servers`, `timeoutMs`, or `cache`), because the shared
  resolver — including its timeout and cache bounds — is installed once at
  startup and remains process-lifetime;
- any `runtime` change (`profile`, `tuning`, or `statusFile`), because the
  resource posture shapes the process-lifetime descriptor budget and memory
  monitor and the adaptive controller is process-lifetime; the tuning mode
  compares strictly, so `fixed` ↔ `startup` ↔
  `adaptive` drift always requires a restart;
- under a derived tuning mode (`startup`/`adaptive`), anything that would
  change the derived numbers — an edited `advanced.limits` pin or a changed
  machine boundary since startup — because the admission pools were sized at
  process start;
- any `advanced.limits.resourceGovernor` change, because REALITY replay
  admission/state is process-lifetime;
- any `advanced.limits.directBarrier` change, because the direct-dial authority
  is process-lifetime;
- any `advanced.limits.warmConnections` change, because the cross-generation
  speculative-connection authority is process-lifetime;
- any `advanced.limits.relay` change, because buffer/splice pools are
  process-lifetime;
- NXR `maxNonceEntries` or `nonceRetentionSeconds` changes;
- Handoff `maxNonceEntries` or `nonceRetentionSeconds` changes.

Run `check` and preferably `self-test` before SIGHUP. A valid file can still be
reload-incompatible and require a controlled restart.

## Secret and file handling

- Keep configuration `0640 root:rust-reality` or stricter.
- Never commit generated UUIDs, REALITY private keys, short IDs intended to be
  private, NXR PSKs, Handoff PSKs, Handoff static private keys, SOCKS
  credentials, or real endpoints.
- Generate keys on a trusted host with OS entropy and transfer them over an
  authenticated channel.
- Use a dedicated writable asset directory. External DAT files must remain
  inside it.
- `config format` prints the full configuration, including secrets, to stdout;
  redirect carefully and do not pipe it into logs.
