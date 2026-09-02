# DNS and network

English | [简体中文](../../zh-CN/configuration/dns-and-network.md)

How this node resolves names and which address family it dials with. Both have
working defaults; this page is for when they are not right.

## The defaults

Omit both sections and the node uses the system resolver and dials whichever
address family works, preferring what the host's routing table suggests. On a
normal dual-stack VPS that is the correct behaviour and there is nothing to
configure.

## `network.ip`

```json
{ "network": { "ip": "preferIpv4" } }
```

This is the outbound policy — how this node dials destinations. It is separate
from `listeners[].ip`, which is about accepting connections, and the two do
not have to agree: a node can accept IPv6 clients and dial IPv4-only.

| value | behaviour |
| --- | --- |
| `auto` (default) | detect what the host can do and prefer accordingly |
| `preferIpv4` | try IPv4 first, fall back to IPv6 |
| `preferIpv6` | try IPv6 first, fall back to IPv4 |
| `ipv4Only` | IPv4 only; an IPv6-only destination is unreachable |
| `ipv6Only` | IPv6 only |

`auto` re-checks periodically, so a host that gains or loses IPv6 connectivity
is followed without a restart.

Pin it when the host's IPv6 is present but broken — configured, advertised,
and blackholed — which `auto` cannot always distinguish from working. Symptoms
are connections that hang for seconds before succeeding.

`network` is cold. Changing it needs a restart, because the dial policy is
fixed when the connector is built.

## `dns`

```json
{
  "role": "entry",
  "listeners": [
    {
      "port": 443
    }
  ],
  "reality": {
    "cover": "www.microsoft.com:443",
    "privateKey": "ERERERERERERERERERERERERERERERERERERERERERE"
  },
  "users": [
    {
      "id": "11111111-1111-4111-8111-111111111111",
      "shortIds": [
        "0123456789abcdef"
      ]
    }
  ],
  "routing": {
    "default": "direct"
  },
  "dns": {
    "servers": [
      "1.1.1.1",
      "9.9.9.9"
    ],
    "timeoutMs": 4000,
    "cache": {
      "maxEntries": 8192,
      "minTtlSeconds": 60
    }
  },
  "network": {
    "ip": "preferIpv4"
  }
}
```

| field | default | meaning |
| --- | --- | --- |
| `servers` | the system resolver | resolvers to query |
| `timeoutMs` | 5000 | per-query deadline |
| `cache` | derived | cache bounds, below |

`servers` accepts IP addresses, or the single entry `"system"` to use the
host's configured resolver explicitly. `"system"` may not be mixed with
others: either the host decides or this file does, and a list that is half one
and half the other has no clear meaning.

### When to set servers

**Leave it alone** when the host already has a fast local resolver. That is
the best case, and a local caching stub such as `systemd-resolved` or `unbound`
pointed at by `/etc/resolv.conf` beats anything configured here, because it
serves the whole machine.

**Set it** when the host resolver is slow, is on a network path you do not
trust, or returns answers shaped by the same filtering you are working around.
DNS is where a proxy leaks the most: the destination name is visible to
whoever answers.

### The cache

```json
{ "dns": { "cache": { "maxEntries": 8192, "minTtlSeconds": 60 } } }
```

| field | meaning |
| --- | --- |
| `maxEntries` | how many answers to keep |
| `minTtlSeconds` | floor on how long an answer is reused |
| `maxTtlSeconds` | ceiling on the same |
| `negativeTtlSeconds` | how long to remember a failure |
| `staticTtlSeconds` | lifetime for a literal address |
| `systemReuseMs` | how long a system-resolver answer is reused |

All of them derive from the machine when omitted, and on most nodes they
should stay omitted. Raise `minTtlSeconds` when an upstream returns very short
TTLs and the lookup rate is a problem; lower `maxTtlSeconds` when destinations
move and stale answers cause failures.

`maxTtlSeconds` must not be below `minTtlSeconds`, and the validator says so
rather than silently reordering them.

`dns` is cold: the resolver is installed once for the process, so changing it
needs a restart.

## Routing and DNS

`routing.strategy` decides whether a destination name is resolved *for routing
purposes*, which is a different question from whether it is resolved to
connect. A node whose rules are all domain-based never resolves for routing at
all. See [routing](routing.md#strategy).

That interaction matters for cost: `resolveOnDemand` with a large `ip` rule set
means a lookup on connections that domain rules would otherwise have decided
for free.

## Diagnosing it

`check` never resolves anything — it is offline, so a file naming an
unreachable resolver still validates.

`doctor` does:

```shell
rust-reality doctor -c /etc/rust-reality/config.json
```

It queries the configured servers and reports whether they answer. A node that
starts but resolves nothing is usually this.
