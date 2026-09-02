# CLI reference

English | [简体中文](../zh-CN/cli.md)

Seven commands. Each one is a job an operator intentionally does.

```
rust-reality run         -c <config.json>
rust-reality check       -c <config.json>
rust-reality doctor      -c <config.json>
rust-reality explain     -c <config.json> [--json] [--route <HOST>]
rust-reality format      -c <config.json> [--write]
rust-reality check-cover --cover <HOST:PORT> [--server-name <NAME>] [--timeout-ms <N>]
rust-reality generate    uuid | x25519 | short-id | psk
```

Plus `--help` and `--version`. Every command that reads a configuration takes
`-c` / `--config`.

| command | answers |
| --- | --- |
| `run` | serve traffic until SIGINT or SIGTERM |
| `check` | is this configuration internally valid? |
| `doctor` | will this configuration actually work on this machine and network? |
| `explain` | what does this exact configuration resolve to here? |
| `format` | rewrite my configuration in the canonical, validated form |
| `check-cover` | is this candidate host usable as a REALITY cover target? |
| `generate` | produce material I must not invent by hand |

There is deliberately no benchmark, no schema dump, no profiling, and no
repository tooling here. A command exists because an operator wants to do it,
not because a subsystem can expose one — engineering capabilities live in
`cargo dev`, and the deployed daemon is not the project's toolbox.

## `run`

```shell
rust-reality run -c /etc/rust-reality/config.json
```

Binds every configured listener, then serves until SIGINT or SIGTERM. It stays
in the foreground, which is what systemd and every other supervisor wants.

**Signals**

| signal | effect |
| --- | --- |
| `SIGHUP` | reload the configuration file atomically |
| `SIGINT`, `SIGTERM` | stop, draining live connections |

A reload compiles the new file completely before publishing it. If anything
fails, the running configuration keeps serving and the failure is logged as
`configuration_rejected` with the full diagnostic on stderr. A reload that
changes a cold setting is refused by name — see
[the reload summary](configuration/reference.md#reload-summary).

Shutdown waits up to 30 seconds for live relays to finish, then aborts what
remains.

**Exit status** is non-zero on a bind failure, a signal-installation failure,
or a listener that stops unexpectedly.

## `check`

```shell
rust-reality check -c /etc/rust-reality/config.json
```

```
/etc/rust-reality/config.json is a valid entry node
```

Parses, validates every value, and validates every cross-reference. Then it
stops.

**`check` is strictly offline.** It resolves no names, opens no sockets,
downloads nothing, and binds nothing. That is a guarantee, not a tendency: it
is asserted by test. So it runs anywhere — in CI on a laptop, in a container
with no network, against a file for a machine you are not sitting at.

Failures go to stderr with the offending line, and stdout stays empty:

```
error: invalid value for `runtime.profile`
 --> /etc/rust-reality/config.json:3:27
  |
3 |   "runtime": { "profile": "server" },
  |                           ^^^^^^^^ expected "auto", "shared", or "dedicated"
  |
  = actual value: "server"
  = help: use "dedicated" only when this process owns the bounded host or cgroup
```

Secrets are never echoed; a diagnostic about key material shows `[REDACTED]`.

**Exit status** 0 if valid, non-zero otherwise. Run it before every reload.

## `doctor`

```shell
rust-reality doctor -c /etc/rust-reality/config.json
```

Everything `check` does, and then it contacts what the file names: resolves
DNS, dials the cover target and confirms it still negotiates TLS 1.3, loads
and parses geo data, and checks filesystem permissions and directories.

It never binds the production listener and never mutates the system.

```json
{
  "assets": { "domainLabels": 0, "domainSources": 0, "generation": 0, "ipLabels": 0, "ipSources": 0 },
  "configuration": "ok",
  "cover": [
    {
      "target": "www.microsoft.com:443",
      "serverName": "www.microsoft.com",
      "compatible": true,
      "cipherSuite": "TLS_AES_256_GCM_SHA384",
      "keyExchangeGroup": "X25519",
      "connectMillis": 322,
      "serverHelloMillis": 319,
      "totalMillis": 642
    }
  ],
  "role": "entry",
  "routing": "ok"
}
```

Run it before a restart, after changing the cover, and when something that
used to work has stopped.

## `explain`

```shell
rust-reality explain -c /etc/rust-reality/config.json
```

Reports what this exact file resolves to on this machine — the decisions, not
a dump of internal state:

```
role: entry
listeners:
  0.0.0.0:443, [::]:443 (auto, at least one)
routing:
  default: landing-1 (1 rule, strategy resolveIfNoMatch)
  policy split: default landing-1 (1 rule, 1 user)
  outbounds: direct, block, landing-1
  geo data: required by at least one rule
machine: 4 effective cpus (4 logical), 524288 descriptors, 16194637824 bytes memory (cgroup_v2)
posture: profile auto -> standard, tuning startup, objective balanced
runtime: 4 worker threads, 512 blocking threads (tokio-default)
limits: 25 values, all derived from the machine (--json for the table)
```

Pinned limits are listed; derived ones are counted. When the host's own
settings will constrain the process, advisories follow — and they are advisory
in the strict sense, because this process never writes a sysctl, another
process's rlimit, or a cgroup file.

Like `check`, it is offline.

### `--json`

The complete report, for automation:

```shell
rust-reality explain -c config.json --json | jq '.fields[] | select(.source == "operator-pinned")'
```

Every field carries its value, provenance (`operator-pinned`,
`startup-derived`, or `default`), the objective multiplier where one applies,
and the floor and cap. `schemaVersion` identifies the report shape. The report
contains no key material, so it is safe to attach to a bug report.

### `--route HOST`

Answers where one destination would go, instead of reporting the whole file:

```shell
rust-reality explain -c config.json --route example.com
rust-reality explain -c config.json --route 10.1.2.3:443
rust-reality explain -c config.json --route '[2001:db8::1]:443'
```

```
example.com for alice -> landing-1 (routing.policies.split, default outbound)
```

The answer names the outbound, the list that decided, and how: `global rule`,
`policy rule`, or `default outbound`. Accepts `host` or `host:port`, including
bracketed and bare IPv6 literals, and defaults to port 443.

Being offline bounds what it can say, and it says so rather than reporting a
route the running server would not choose:

```
note: geo conditions were not evaluated: `explain` is offline, so a rule
naming geoip: or geosite: was treated as not matching. Use `doctor` to load
the data.
```

A landing node is refused: it does not route, it sends every transfer to one
egress.

## `format`

```shell
rust-reality format -c config.json           # print it
rust-reality format -c config.json --write   # rewrite in place
```

Rewrites a configuration in the canonical form. It is not `jq`, and the
difference is the point:

1. **It validates.** Its output is always a file this binary accepts. `jq .`
   will happily pretty-print something the server rejects.
2. **It orders keys the way the reference documents them** — outbounds before
   the routing that refers to them, required fields before optional ones.
   `jq` preserves arbitrary input order and `jq -S` sorts alphabetically,
   which scatters related fields apart.
3. **It is round-trip safe by construction**, going through the typed model,
   so it cannot emit a shape the model cannot read.

The contract, all of it pinned by test:

- deterministic, and **idempotent** — `format(format(x))` is byte-identical
- **semantics-preserving** — `parse(format(x))` equals `parse(x)`
- a field you wrote survives even when it equals its default
- a field you omitted is never expanded into the file
- invalid input is rejected, not pretty-printed

`--write` goes through a crash-safe atomic write, so a failure leaves no
partial file. It never transforms an old configuration and is not migration
tooling: a file from a previous release fails exactly as it fails under
`check`.

## `check-cover`

```shell
rust-reality check-cover --cover www.microsoft.com:443
rust-reality check-cover --cover www.example.org:443 --server-name www.example.org
```

Checks whether a host is usable as a REALITY cover target, before any
configuration exists.

| option | default | meaning |
| --- | --- | --- |
| `--cover HOST:PORT` | required | the candidate, with its port |
| `--server-name DNS_NAME` | the cover host | name to send in the ephemeral ClientHello |
| `--timeout-ms N` | 5000 | absolute DNS, connect, write, and ServerHello deadline |

```json
{
  "target": "www.microsoft.com:443",
  "serverName": "www.microsoft.com",
  "compatible": true,
  "cipherSuite": "TLS_AES_256_GCM_SHA384",
  "keyExchangeGroup": "X25519",
  "connectMillis": 304,
  "serverHelloMillis": 1892,
  "totalMillis": 2197
}
```

`compatible: true` is the requirement; the timings are the other half of the
answer, because the cover's latency lands inside the setup of every connection
this node will serve.

Run it **on the deployment host** — the answer depends on the network path,
and a cover that works from a laptop may fail from the VPS. `doctor` runs the
same check against the cover already in a configuration.

## `generate`

Produces material an operator should not invent by hand, and nothing else.
There is no command that assembles a configuration, a client profile, or a
subscription link.

```shell
rust-reality generate uuid [COUNT] [--json]
rust-reality generate x25519 [--json]
rust-reality generate short-id [COUNT] [--bytes N] [--json]
rust-reality generate psk [--json]
```

| subcommand | for | notes |
| --- | --- | --- |
| `uuid` | `users[].id` | RFC 4122 version 4; `COUNT` up to 1024 |
| `x25519` | `reality.privateKey`, or a Handoff landing's `landing.privateKey` | one pair per purpose |
| `short-id` | `users[].shortIds` | `--bytes` 1–8, default 8 |
| `psk` | an NXR or Handoff `psk` | one per landing |

Human output is labelled:

```
private key (keep secret): bkuHF6dZ2Elt_dkFKZoXkSUZ6gnLITrUZbRmDggVfuQ
public key  (give to peers): CyrxYetA0RSs9IxcGpb7vNfQ3GoKm6xTUL5qWdbjUAY
```

`--json` is the stable machine-readable form, for installers:

```json
{
  "privateKey": "005oawzDIFyUCdSjXtgGaP7UgGF7zFEzay4kL_nq9ww",
  "publicKey": "UWesja3AOowUwLohp5LcPtmE0gZmBSsn8I6623QczzY"
}
```

## Exit status

`0` on success. Non-zero on any failure, with the reason on stderr.

Every command writes its result to stdout and its diagnostics to stderr, so
`rust-reality explain --json -c config.json > report.json` yields a clean
file even when a warning is printed.

## Development commands

Benchmark suites, profiling, schema generation, repository checks, fuzz
inventory, and documentation verification are `cargo dev` subcommands in the
tooling workspace, not part of the shipped binary. See
[development workflow](development/development-workflow.md).

```shell
cargo dev check --all          # the full validation gate
cargo dev config schema        # generate the JSON Schema
cargo dev docs check           # documentation policy, including every example
```
