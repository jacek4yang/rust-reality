# Configuration reference

English | [简体中文](configuration.zh-CN.md)

This document covers every accepted JSON field in `rust-reality` 0.1.x. The
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
  "inbounds": [],
  "outbounds": [],
  "routing": {},
  "policy": {}
}
```

| Field | Required | Default | Meaning |
| --- | --- | --- | --- |
| `log` | no | stderr/info | Logging sink, severity, and bounded file retention. |
| `assets` | no | community GeoIP/GeoSite URLs and bounded cache defaults | Routing asset sources and refresh policy. |
| `dns` | no | system resolver, 5000 ms | DNS behavior used by IP-assisted routing. |
| `inbounds` | yes | — | At least one strictly typed `vless` or internal `nxr` listener. |
| `outbounds` | yes | — | At least one `direct`, `blackhole`, `socks5`, or `nxr` transport. |
| `routing` | yes | — | Global rules and explicit per-UUID policy groups. |
| `policy` | no | bounded production defaults | Admission, direct-dial, buffer, and Linux relay policy. |

## `log`

| Field | Required | Default / allowed | Meaning and constraints |
| --- | --- | --- | --- |
| `log.level` | no | `info`; `error`, `warn`, `info`, `debug` | Minimum emitted severity. Debug logging still excludes configuration and keys. |
| `log.output` | no | `stderr`; `stderr`, `journald`, `file` | `journald` writes stderr for systemd capture; `file` enables built-in rotation. |
| `log.file` | only for `output: "file"` | absent | Forbidden for stderr/journald. Contains all fields below. |
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

| Field | Required | Default | Meaning and constraints |
| --- | --- | --- | --- |
| `dns.servers` | no | `["system"]` | Currently must be exactly `["system"]`; custom UDP/TCP/DoH resolvers are rejected instead of ignored. |
| `dns.timeoutMs` | no | `5000` | Absolute routing lookup deadline, `1..=600000`. |

At most 64 unique addresses are retained for one routed domain. A direct
outbound reuses the exact resolved snapshot used by GeoIP/IP rules, avoiding a
second inconsistent lookup.

## `inbounds`

`inbounds` must be non-empty. Every listener has a unique `tag`, and no two
entries may bind the same `(listen, port)`. A tag is 1–64 ASCII letters, digits,
dots, dashes, or underscores. `port` is `1..=65535`.

### Public VLESS + REALITY + Vision inbound

```json
{
  "protocol": "vless",
  "tag": "public-reality",
  "listen": "0.0.0.0",
  "port": 443,
  "settings": {
    "clients": [
      {
        "id": "GENERATED-UUID",
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
      "shortIds": ["0123456789abcdef"],
      "maxTimeDiffMs": 60000
    }
  }
}
```

The placeholder values above are intentionally not usable. Generate real state
with `config generate standalone` or `config generate line`.

| Field | Required | Default / fixed value | Meaning and constraints |
| --- | --- | --- | --- |
| `protocol` | yes | fixed `vless` | Selects the only public protocol. |
| `tag` | yes | — | Unique listener/routing tag. |
| `listen` | yes | — | IPv4 or IPv6 bind address. |
| `port` | yes | — | TCP bind port, non-zero. |
| `settings.clients` | yes | — | Non-empty authorized-client array. UUIDs are globally unique across public inbounds. |
| `settings.clients[].id` | yes | — | Canonical hyphenated UUID; hex is case-insensitive for identity. |
| `settings.clients[].email` | no | absent | Non-secret operator label; not used for authentication or routing. |
| `settings.clients[].flow` | yes | fixed `xtls-rprx-vision` | Any other flow is rejected. |
| `settings.decryption` | no | fixed/default `none` | Retained for Xray-shaped configuration; any other value is rejected. |
| `streamSettings.network` | yes | fixed `tcp` | Public UDP is not implemented. |
| `streamSettings.security` | yes | fixed `reality` | Plain or TLS-only VLESS is rejected. |
| `streamSettings.realitySettings.target` | yes | — | Cover endpoint `host:port`; bracket IPv6. Probe it from the server first. |
| `streamSettings.realitySettings.serverNames` | yes | — | Non-empty, case-insensitively unique array of concrete ASCII DNS names or leftmost one-label patterns such as `*.lmu.edu`. |
| `streamSettings.realitySettings.privateKey` | yes | — | URL-safe unpadded base64 decoding to exactly 32 X25519 bytes. Secret. |
| `streamSettings.realitySettings.shortIds` | yes | — | Non-empty, unique case-insensitive hex IDs; each is 2–16 even characters. |
| `streamSettings.realitySettings.maxTimeDiffMs` | no | `60000` | Accepted client clock difference, `0..=600000`; zero disables this check. |

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
  "listen": "0.0.0.0",
  "port": 7443,
  "settings": {
    "preSharedKey": "GENERATED-NXR-KEY",
    "maxTimeDifferenceSeconds": 30,
    "maxNonceEntries": 65536,
    "nonceRetentionSeconds": 120,
    "authenticationTimeoutMs": 3000,
    "connectTimeoutMs": 10000
  }
}
```

| Field | Required | Default | Meaning and constraints |
| --- | --- | --- | --- |
| `protocol` | yes | fixed `nxr` | Selects the internal landing protocol. |
| `tag` | yes | — | Unique listener/operational tag. |
| `listen` | yes | — | Internal bind address; restrict at the host/provider firewall. |
| `port` | yes | — | Raw NXR TCP port, non-zero. |
| `settings.preSharedKey` | yes | — | Independent URL-safe unpadded base64 value decoding to exactly 32 bytes. |
| `settings.maxTimeDifferenceSeconds` | no | `30` | Accepted absolute wall-clock skew, `1..=300`. |
| `settings.maxNonceEntries` | no | `65536` | Maximum verified nonce entries, `1..=1000000`. |
| `settings.nonceRetentionSeconds` | no | `120` | Replay retention; from `2 * maxTimeDifferenceSeconds + 1` through `86400`. |
| `settings.authenticationTimeoutMs` | no | `3000` | Deadline to read the one bounded authentication request, `1..=600000`. |
| `settings.connectTimeoutMs` | no | `10000` | Deadline to connect only after authentication succeeds, `1..=600000`. |

NXR authentication failure closes silently before DNS or destination connect.
After success, the connection becomes raw bidirectional bytes. NXR has no
post-authentication encryption and must not be exposed to the Internet.

## `outbounds`

`outbounds` must be non-empty. Outbound tags use the same 1–64-character syntax
and must be unique among outbounds.

### Direct

```json
{ "protocol": "direct", "tag": "direct" }
```

Connects directly to the selected destination subject to
`policy.directBarrier` and connection timeout. No `settings` field is accepted.

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
    "password": "secret"
  }
}
```

| Field | Required | Default | Meaning and constraints |
| --- | --- | --- | --- |
| `settings.address` | yes | — | Valid ASCII hostname or IP address. |
| `settings.port` | yes | — | SOCKS5 TCP port, non-zero. |
| `settings.username` | no | absent | Must appear with `password`, be non-empty, and be at most 255 bytes. Secret-protected in debug output. |
| `settings.password` | no | absent | Must appear with `username`, be non-empty, and be at most 255 bytes. Secret. |

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
    "preSharedKey": "GENERATED-NXR-KEY"
  }
}
```

| Field | Required | Meaning and constraints |
| --- | --- | --- |
| `settings.address` | yes | Valid landing-node ASCII hostname or IP address. |
| `settings.port` | yes | Firewall-restricted NXR TCP port, non-zero. |
| `settings.preSharedKey` | yes | Same independent URL-safe unpadded 32-byte key as the landing inbound. |

Each user TCP flow opens one NXR TCP connection and sends one authenticated,
strictly bounded request. There is no multiplexing or persistent pool.

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

## `policy`

If `policy` or one of its three child objects is absent, the complete child
default is used. If `resourceGovernor`, `directBarrier`, or `relay` is explicitly
present, fields marked “required when object present” must be supplied; do not
assume a partial object inherits every default. `config format` makes applied
defaults visible.

### `policy.resourceGovernor`

| Field | Required when object present | Whole-object default | Constraints / meaning |
| --- | --- | --- | --- |
| `maxConnections` | yes | `16384` | Greater than zero; parent ceiling for accepted connections. |
| `maxHandshakes` | yes | `1024` | Greater than zero and no more than `maxConnections`; concurrent pre-auth work. |
| `maxFallbacks` | yes | `512` | Greater than zero and no more than `maxConnections`; concurrent cover relays. |
| `maxCryptoOperations` | yes | `128` | Greater than zero and no more than `maxHandshakes`; expensive crypto admission. |
| `maxReplayEntries` | yes | `65536` | Greater than zero; pending plus committed REALITY replay entries. |
| `replayRetentionMs` | no | `120000` | Retention after verified ClientFinished, `1..=600000`. |
| `clientHelloTimeoutMs` | yes | `3000` | ClientHello read deadline, `1..=600000`, no more than handshake timeout. |
| `handshakeTimeoutMs` | yes | `10000` | Authenticated handshake deadline, `1..=600000`. |
| `connectTimeoutMs` | yes | `10000` | Cover/outbound connect deadline, `1..=600000`, no more than fallback timeout. |
| `fallbackTimeoutMs` | yes | `120000` | Maximum fallback lifetime, `1..=600000`. |

### `policy.directBarrier`

| Field | Required when object present | Whole-object default | Constraints / meaning |
| --- | --- | --- | --- |
| `maxConcurrent` | yes | `2048` | Concurrent direct dials, greater than zero and no more than `maxConnections`. |
| `maxPerSecond` | yes | `4096` | New direct dials per second, greater than zero. |

This isolates direct destination pressure from authenticated connection count.

### `policy.relay`

| Field | Required when object present | Whole-object default | Constraints / meaning |
| --- | --- | --- | --- |
| `bufferBytes` | yes | `32768` | Bytes per pooled userspace buffer, `4096..=1048576`. |
| `maxPooledBuffers` | yes | `4096` | Global pooled-buffer ceiling, `2..=65536`. |
| `maxSpliceRelays` | no | `1024` | With splice enabled, greater than zero and no more than `maxConnections`. Each relay consumes two pipe pairs. |
| `splice` | yes | `true` | Permit bounded nonblocking Linux splice only across plaintext TCP boundaries. |
| `ioUring` | yes | `false` | Reserved; `true` is rejected until a bounded runtime capability probe is implemented. |
| `sockhash` | yes | `false` | Reserved; `true` is rejected until the eBPF capability probe is implemented. |

Splice never crosses the REALITY/TLS security boundary. If splice resources are
unavailable before transfer starts, relay falls back to bounded userspace
buffers.

## Reload boundaries

`serve`/`run` receives SIGHUP and builds one complete candidate. Publication is
atomic; failure keeps the old generation, and established connections keep the
generation they acquired.

Hot-updateable with compatible topology:

- logging;
- asset URLs/cache contents/refresh settings;
- DNS timeout;
- VLESS users and REALITY authentication/cover state;
- outbound definitions, routing groups, and rules;
- direct-barrier settings;
- NXR key, clock window, and I/O timeouts when replay capacity/retention stay
  unchanged.

Restart required:

- adding/removing a listener, changing bind address/port, or changing protocol
  at an address;
- any `policy.resourceGovernor` change, because REALITY replay admission/state
  is process-lifetime;
- any `policy.relay` change, because buffer/splice pools are process-lifetime;
- NXR `maxNonceEntries` or `nonceRetentionSeconds` changes.

Run `check` and preferably `self-test` before SIGHUP. A valid file can still be
reload-incompatible and require a controlled restart.

## Secret and file handling

- Keep configuration `0640 root:rust-reality` or stricter.
- Never commit generated UUIDs, REALITY private keys, short IDs intended to be
  private, NXR PSKs, SOCKS credentials, or real endpoints.
- Generate keys on a trusted host with OS entropy and transfer them over an
  authenticated channel.
- Use a dedicated writable asset directory. External DAT files must remain
  inside it.
- `config format` prints the full configuration, including secrets, to stdout;
  redirect carefully and do not pipe it into logs.
