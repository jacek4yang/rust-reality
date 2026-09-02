# Troubleshooting

English | [简体中文](../../zh-CN/operations/troubleshooting.md)

Organised by symptom. Start with what you observed, not with what you suspect.

## First, three commands

Before anything else, in this order:

```shell
rust-reality check   -c /etc/rust-reality/config.json   # is the file valid?
rust-reality explain -c /etc/rust-reality/config.json   # what does it resolve to?
rust-reality doctor  -c /etc/rust-reality/config.json   # does the environment agree?
```

`check` is offline and safe anywhere. `explain` shows the derived values and
the routing summary. `doctor` contacts what the file names. Between them they
answer most questions before you read a log.

## The server will not start

### `check` fails

The diagnostic names the field and points at the line:

```
error: invalid value for `reality.privateKey`
 --> /etc/rust-reality/config.json:6:19
  |
6 |     "privateKey": "[REDACTED]"
  |                   ^^^^^^^^^^^^ must be URL-safe unpadded base64 decoding to exactly 32 bytes
```

Common causes:

| message mentions | cause |
| --- | --- |
| `unknown field` | a typo, or a field from a previous release |
| `unknown outbound` | a name in `routing` that `outbounds` does not declare |
| `must be URL-safe unpadded base64` | a key copied with padding, whitespace, or truncation |
| `carries the same key material as` | one generated value reused for two purposes |
| `field \`advanced\` was removed in v1.9` | a configuration written for an earlier release |

A file written for a previous release fails immediately and by name. There is
no migration path and no compatibility mode: write the new file. It is
shorter, and [standalone](../configuration/standalone.md) walks through it.

### `check` passes but the process exits

Read the first lines of the journal:

```shell
sudo journalctl -u rust-reality -n 50 --no-pager
```

| event | meaning |
| --- | --- |
| bind failure on `:443` | something else holds the port, or the process lacks the capability to bind it |
| `descriptor_budget_report` with `fd_clamped: true` | the descriptor limit cannot support the configured ceilings |
| no `listener_started` at all | it failed before binding; the error precedes it |

For port 443 as a non-root user, grant the capability in the unit rather than
running as root — see [deployment](deployment.md).

## Clients cannot connect

This is almost always one of two things. Check both before looking further.

### 1. The key halves are swapped

`rust-reality generate x25519` prints two values. The **private** half goes in
`reality.privateKey` on the server. The **public** half goes in the client.

If the value in your server file is also the value in your client, they are
swapped. Regenerate or re-copy, and note that you cannot recover the public
half from the server file — record it when you generate the pair.

The symptom is unhelpful by design: from the server's point of view the client
simply failed to authenticate, so it is proxied to the cover and receives the
cover's real response. The client sees a TLS connection that works and a proxy
that never carries traffic.

### 2. The client's SNI does not match

The client's server name must match an entry in `reality.serverNames`. When
that field is omitted, the only accepted name is the host part of
`reality.cover`.

```shell
rust-reality explain -c /etc/rust-reality/config.json
```

Set the client's SNI to that host. Note that changing `cover` while
`serverNames` is implicit also changes the accepted SNI.

### Then check the rest

| check | how |
| --- | --- |
| the port is reachable | `nc -vz <server> 443` from the client's network |
| the UUID matches | it is `users[].id`, exactly |
| the short ID belongs to that user | it must be one of *that user's* `shortIds` |
| the flow is `xtls-rprx-vision` | this server speaks no other |
| the cover still works | `rust-reality doctor` |

### Connections work, then stop after some time

Look for `admission_limited` in the journal. The node is at a derived ceiling:

```shell
sudo journalctl -u rust-reality | grep admission_limited
```

```json
{"event":"admission_limited","resource":"connections"}
```

`rust-reality explain --json` shows the ceiling, its floor, and its cap. If it
is genuinely too low for this workload, pin it — see
[runtime and resources](../configuration/runtime-and-resources.md). If it is
not, something is holding connections open that should not be.

## Traffic goes to the wrong place

Ask rather than read:

```shell
rust-reality explain -c /etc/rust-reality/config.json --route example.com
```

```
example.com for alice -> direct (routing, default outbound)
```

The answer names the outbound, the list that decided, and how. Then:

- **`default outbound` when you expected a rule** — the rule did not match.
  Check the matcher form: `domain:example.com` matches subdomains,
  `example.com` alone does not.
- **A global rule fired when you expected a policy rule** — `routing.rules`
  are evaluated before any policy and are not overridable. That is what makes
  them the right place for rules that must hold for everyone, and the wrong
  place for anything else.
- **The wrong user** — a user with no `policy` follows `routing.default`, not
  any policy. `explain` lists each policy with how many users select it; a
  policy with zero users is a mistake.

### Geo rules never match

`explain` is offline, so it cannot evaluate them, and it says so:

```
note: geo conditions were not evaluated: `explain` is offline, so a rule
naming geoip: or geosite: was treated as not matching. Use `doctor` to load
the data.
```

For the running server, the question is whether the data loaded:

```shell
rust-reality doctor -c /etc/rust-reality/config.json
```

```json
{ "assets": { "domainLabels": 0, "domainSources": 0, "ipLabels": 0, "ipSources": 0 } }
```

Zero labels means nothing loaded. Either `assets` is absent, or the download
failed — check the journal for an asset event, confirm the URL is `https://`
and reachable from the server, and confirm the service account owns
`cacheDirectory`.

`geoip:private` is built in and works with no data files at all.

## Line and landing problems

### Connections fail at the first transfer

The two files are individually valid — `check` reads one file and cannot see
the other. Verify the three values that span them:

| line node | landing node |
| --- | --- |
| `outbounds.<name>.port` | `listeners[].port` |
| `outbounds.<name>.psk` | `landing.psk` |
| `outbounds.<name>.address` | must be reachable from the line node |

From the line node:

```shell
nc -vz 10.0.0.2 7443
```

If that fails, it is the firewall or the address, not the configuration.

### Handoff specifically

Additionally, `landingPublicKey` on the line node must be the public half of
`privateKey` on the landing. A mismatched pair produces a transfer the landing
cannot open — authentication succeeds and the connection then fails, which
looks different from a wrong `psk`.

If you cannot confirm the pair, regenerate: `rust-reality generate x25519` on
the landing, private half into `landing.privateKey`, public half into the line
node's `landingPublicKey`.

### After a key rotation

Check whether the window is still open:

```shell
sudo journalctl -u rust-reality | grep handoff_rotation_window_open
```

It is logged once per generation while retired keys remain listed. If you see
it and the rotation is finished, remove `previousPsks` and
`previousPrivateKeys` and reload — until you do, the retired key still opens a
transfer.

## Reloads

### A reload is rejected

```shell
sudo journalctl -u rust-reality -n 20 --no-pager
```

```
configuration configuration reload rejected:
runtime profile, tuning, or resource-mode changes require a process restart
```

The old configuration is still serving; nothing was lost. Either revert the
cold change or restart:

| message | change it names |
| --- | --- |
| `listener addresses require a process restart` | `listeners` |
| `network dial policy requires a process restart` | `network` |
| `DNS resolver policy requires a process restart` | `dns` |
| `runtime profile, tuning, or resource-mode changes require a process restart` | any `runtime` field |

Always `check` before reloading. A reload that fails validation is refused the
same way, and the journal is a worse place to learn about a typo than your
terminal is.

### A reload succeeded but nothing changed

Established connections keep the generation that admitted them, by design — a
reload never re-routes a live session. New connections use the new
configuration. Confirm the generation advanced:

```shell
sudo journalctl -u rust-reality | grep configuration_published
```

```json
{"event":"configuration_published","generation":3}
```

## Performance

Before tuning anything, find out where the time goes.

### Setup is slow

The cover's latency is inside the setup of every connection:

```shell
rust-reality check-cover --cover www.microsoft.com:443
```

A `totalMillis` in the hundreds is a cover that makes every connection slow.
Choose a closer one — see [cover targets](../configuration/cover-targets.md).

### Throughput is low

```shell
rust-reality explain -c /etc/rust-reality/config.json
```

Check the advisories at the end. Host `net.ipv4.tcp_rmem` / `tcp_wmem` maxima
below the relay buffer tier throttle large transfers, and this process will
not change a sysctl on your behalf.

Then check `profile`. On a machine this process owns, `dedicated` raises the
descriptor limit, sizes the thread pools from the real CPU view, and enables
the memory pressure monitor. `auto` cannot tell that a VPS is dedicated when
there is no cgroup boundary to observe.

## Reading the logs

Events are JSON, one per line, so `jq` works:

```shell
sudo journalctl -u rust-reality -o cat | jq -c 'select(.level != "info")'
```

Useful ones:

| event | meaning |
| --- | --- |
| `server_starting` | the process began startup |
| `machine_report` | what was detected, under `dedicated` |
| `descriptor_budget_report` | the descriptor plan; `fd_clamped` matters |
| `listener_started` | a socket is accepting |
| `configuration_published` | a generation went live |
| `configuration_rejected` | a reload was refused; the full diagnostic is on stderr |
| `connection_rejected` | one connection failed; `reason` classifies it |
| `admission_limited` | a ceiling was reached; `resource` names it |
| `handoff_rotation_window_open` | retired landing keys are still accepted |

`connection_rejected` reasons: `authentication`, `resource_limit`, `timeout`,
`outbound`, `protocol`, `socket_configuration`. `authentication` on a public
node is ordinary background noise — it is what a scanner produces.

Set `log.level` to `debug` for per-connection events. It is verbose, and it is
the level at which a single connection's life can be followed end to end.

## Still stuck

Gather this before asking:

```shell
rust-reality --version
rust-reality explain -c /etc/rust-reality/config.json --json
sudo journalctl -u rust-reality -n 200 --no-pager
```

`explain --json` contains no key material, so it is safe to share. The
configuration file is not — it contains private keys.
