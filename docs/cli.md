# Command-line reference

English | [简体中文](cli.zh-CN.md)

## General behavior

```text
rust-reality [--help] [--version] <COMMAND>
```

The program writes primary machine-readable or generated output to stdout and
diagnostics to stderr. Generation commands that create a public REALITY server
write the private server JSON to stdout and the client-facing REALITY public
key to stderr. Redirect them separately.

`--help` is available at every command level. Successful commands return exit
status 0. Configuration, I/O, network, runtime, and benchmark failures return
non-zero without printing secret values. Clap reports invalid syntax or ranges
and prints the relevant usage.

## Server and validation commands

### `serve`

```text
rust-reality serve --config <PATH>
```

Loads, validates, compiles, and binds the production server in the foreground.
It installs SIGINT/SIGTERM graceful shutdown and SIGHUP atomic reload handling.
Use this command in the provided systemd unit.

| Option | Required | Meaning |
| --- | --- | --- |
| `-c, --config <PATH>` | yes | Strict JSON configuration file. |

### `run`

```text
rust-reality run --config <PATH>
```

Exact alias for `serve`; provided for service-manager command-line conventions.

### `check`

```text
rust-reality check --config <PATH>
```

Reads at most 4 MiB, decodes strict JSON, rejects unknown fields, and validates
all fields and references. It performs no asset download, destination probe, or
listener bind. Success prints `configuration PATH is valid`.

### `self-test`

```text
rust-reality self-test --config <PATH>
```

Runs `check`, downloads or conditionally revalidates all required Geo assets,
parses them, compiles routing, and performs a real TLS 1.3 compatibility probe
for every configured REALITY target/SNI pair. It does not bind listeners. The
JSON report contains configuration, asset, routing, and destination results.

Configured wildcard patterns are never sent as SNI. `self-test` derives a
concrete SNI from the target hostname only when it matches the wildcard; for
example, target `www.lmu.edu:443` can probe `*.lmu.edu`.

Run `self-test` on the deployment host before enabling or restarting service;
network path and cover-target behavior can differ from a development machine.

### `probe-dest`

```text
rust-reality probe-dest \
  --target <HOST:PORT> \
  --server-name <DNS_NAME> \
  [--timeout-ms <MILLISECONDS>]
```

Sends an ephemeral TLS ClientHello and verifies that a real cover target has a
bounded, strictly parseable TLS 1.3 ServerHello suitable for REALITY.

| Option | Required | Default/range | Meaning |
| --- | --- | --- | --- |
| `--target <HOST:PORT>` | yes | — | Cover endpoint, including port; bracket IPv6 literals. |
| `--server-name <DNS_NAME>` | yes | — | ASCII DNS SNI sent in ClientHello. |
| `--timeout-ms <N>` | no | `5000`, `1..=60000` | Separate absolute bound used by DNS/connect/write/ServerHello work. |

The JSON result is compatibility evidence for that target at that moment, not
a guarantee that the destination will never change behavior.
`probe-dest` requires a concrete DNS name; a wildcard is a server-side matching
pattern and is never a valid ClientHello SNI.

## Configuration commands

### `config generate standalone`

```text
rust-reality config generate standalone \
  [--listen <IP>] [--port <PORT>] \
  --target <HOST:PORT> --server-name <DNS_NAME>
```

Generates one public VLESS + REALITY + Vision inbound, one UUID, one REALITY
X25519 key pair, two short IDs owned by that UUID, and a direct outbound/user
policy.

| Option | Required | Default | Meaning |
| --- | --- | --- | --- |
| `--listen <IP>` | no | `0.0.0.0` | Public bind address. |
| `--port <PORT>` | no | `443` | Public TCP port, `1..=65535`. |
| `--target <HOST:PORT>` | yes | — | REALITY cover target. |
| `--server-name <DNS_NAME>` | yes | — | Client SNI and allowed server name. |

Canonical JSON is written to stdout; `REALITY public key for the client: ...`
is written to stderr.

### `config generate line`

```text
rust-reality config generate line \
  [--listen <IP>] [--port <PORT>] \
  --target <HOST:PORT> --server-name <DNS_NAME> \
  --nxr-address <HOST> [--nxr-port <PORT>] --nxr-key <BASE64>
```

Generates the same protected public inbound, plus NXR, direct, and blackhole
outbounds. The generated UUID defaults to the NXR landing outbound.

| Additional option | Required | Default | Meaning |
| --- | --- | --- | --- |
| `--nxr-address <HOST>` | yes | — | Landing-node address reachable by the line node. |
| `--nxr-port <PORT>` | no | `7443` | Firewall-restricted NXR TCP port. |
| `--nxr-key <BASE64>` | yes | — | URL-safe unpadded 32-byte PSK from `node-keygen`. |

### `config generate landing`

```text
rust-reality config generate landing \
  [--listen <IP>] [--port <PORT>] --nxr-key <BASE64>
```

Generates an internal NXR listener and direct outbound. It contains no public
VLESS, REALITY, Vision, or TLS state.

| Option | Required | Default | Meaning |
| --- | --- | --- | --- |
| `--listen <IP>` | no | `0.0.0.0` | Internal bind address. |
| `--port <PORT>` | no | `7443` | Internal NXR TCP port. |
| `--nxr-key <BASE64>` | yes | — | Same PSK used by the line node's NXR outbound. |

### `config generate handoff`

```text
rust-reality config generate handoff \
  [--listen <IP>] [--port <PORT>] \
  --server-address <HOST> --target <HOST:PORT> --server-name <DNS_NAME> \
  --landing-address <HOST> [--landing-port <PORT>] --output-dir <DIR>
```

Generates a complete Handoff deployment in one step: `line.json` (public
VLESS + REALITY + Vision line node whose user routes to the handoff
outbound), `landing.json` (firewall-restricted internal handoff listener),
and `xray-client.json` (SOCKS-inbound Xray client for the line node). All
key material is generated independently: the UUID, the REALITY X25519 key
pair, two short IDs owned by that UUID, the Handoff pre-shared key, and the landing node's
static X25519 pair. Both server configurations are validated before they
are written.

| Additional option | Required | Default | Meaning |
| --- | --- | --- | --- |
| `--server-address <HOST>` | yes | — | Public line-node address clients dial. |
| `--landing-address <HOST>` | yes | — | Landing-node address reachable by the line node. Repeat for a multi-landing deployment. |
| `--landing-port <PORT>` | no | `7443` | Firewall-restricted Handoff TCP port. With repeated `--landing-address`, pass one port for all landings or repeat once per address. |
| `--output-dir <DIR>` | yes | — | Directory the three files are written to. |

The three file paths are written to stdout; `REALITY public key for the
client: ...` and `UUID for the client: ...` are written to stderr. The
Handoff PSK and the private keys exist only in the two server files.

With repeated `--landing-address` the generator writes a multi-landing
deployment:

```shell
rust-reality config generate handoff \
  --server-address line.example.com \
  --target cover.example.com:443 \
  --server-name cover.example.com \
  --landing-address 10.0.0.2 --landing-port 7443 \
  --landing-address 10.0.0.3 --landing-port 7443 \
  --output-dir handoff/
```

This writes `line.json`, `landing-1.json`, `landing-2.json`, and
`xray-client.json` (a single landing keeps the unnumbered `landing.json`).
The line node carries one UUID per landing and routes each UUID's group to
that landing's handoff outbound (`landing-1`, `landing-2`, ...); each
landing pair has independent key material, and every emitted server file is
validated before it is written. `xray-client.json` keeps its single-UUID
shape and uses the first landing's UUID — assigning further UUIDs to
clients is an operator choice.

### `config autotune`

```text
rust-reality config autotune \
  --config <INPUT.json> --output <TUNED.json> \
  [--report <REPORT.json>] [--scratch-directory <DIR>] \
  [--duration-ms <N>] [--warmup-ms <N>] \
  [--storage-mib <N>] [--network-mib <N>] [--dedicated]
```

Runs bounded host-local protocol, machine/cgroup, storage, and TCP-loopback
probes, then writes a validated tuned copy and its complete measurement report.
It never edits the input. Output files are owner-only (`0600`) and published by
same-directory atomic rename; the report is published first and the validated
configuration last.

| Option | Required | Default/range | Meaning |
| --- | --- | --- | --- |
| `-c, --config <PATH>` | yes | — | Existing valid configuration; credentials, listeners, routing, timeouts, and logging are preserved. |
| `-o, --output <PATH>` | yes | — | Tuned configuration path; must differ from input and report. |
| `--report <PATH>` | no | `<OUTPUT>.report.json` | Auditable measurements and the exact selected policy. |
| `--duration-ms <N>` | no | `900`, `90..=30000` | Measured time per protocol case. |
| `--warmup-ms <N>` | no | `100`, `1..=10000` | Warm-up per protocol case. |
| `--storage-mib <N>` | no | `32`, `1..=256` | Bytes written, synced, and read in the scratch directory. |
| `--network-mib <N>` | no | `32`, `1..=256` | Bytes transferred in each TCP-loopback direction. |
| `--scratch-directory <DIR>` | no | OS temporary directory | Filesystem measured by the bounded storage probe. |
| `--dedicated` | no | off | Also switch the copy to `runtime.resourceMode: "dedicated"`; use only when rust-reality owns the host or cgroup. |

Autotune changes only resource-governor, direct-dial, and relay policy. It does
not choose security protocol, UUID/short-ID ownership, cover target, routing,
or timeout policy. Inspect the diff and report, run `check`, then deploy through
the normal restart procedure. See the
[tuning guide](tuning.md#automatic-measured-starting-policy).

### `config format`

```text
rust-reality config format --config <PATH>
```

Validates the complete file and writes deterministic, canonical pretty JSON to
stdout. It never edits the input file in place. Redirect to a new file, inspect
it, then replace atomically if desired.

### `schema`

```text
rust-reality schema > rust-reality.schema.json
```

Prints the complete JSON Schema. The schema describes structure and enum types;
use `check` for cross-reference and security invariants.

## Identity and key commands

### `uuid`

```text
rust-reality uuid [COUNT]
```

Prints one RFC 4122 version 4 UUID per line using OS entropy. `COUNT` defaults
to 1 and must be `1..=1024`.

### `x25519`

```text
rust-reality x25519
```

Prints JSON containing `privateKey` and `publicKey`, both URL-safe unpadded
base64. Use the private key only in server configuration and the public key in
the Xray client.

### `mldsa65`

```text
rust-reality mldsa65 [--seed <BASE64>]
```

Generates an Xray-compatible ML-DSA-65 seed and verification key. Without
`--seed`, OS entropy creates a new 32-byte seed. With `--seed`, the value must
decode from URL-safe unpadded base64 to exactly 32 bytes. JSON output contains
`seed` and `verify`. This command is compatibility/key tooling; the current
server configuration has no ML-DSA field.

### `node-keygen`

```text
rust-reality node-keygen
```

Prints JSON containing an independent 32-byte URL-safe unpadded
`preSharedKey` for one NXR trust relationship. Do not reuse a REALITY key,
password, or one NXR key across unrelated line/landing pairs.

## Performance command

### `benchmark`

```text
rust-reality benchmark \
  [--duration-ms <MILLISECONDS>] \
  [--warmup-ms <MILLISECONDS>]
```

Runs bounded in-process hot-path measurements and writes a JSON report suitable
for archiving and same-host comparisons.

| Option | Default/range | Meaning |
| --- | --- | --- |
| `--duration-ms <N>` | `1000`, `90..=30000` | Measured time requested for each case. |
| `--warmup-ms <N>` | `250`, `1..=10000` | Warm-up before each case. |

The report includes the embedded commit, build/target information, timings,
operation counts, means, and sample percentiles. It is not an Internet
throughput test; see the [benchmark policy](benchmarks.md).

## Signals and atomic reload

| Signal | Behavior |
| --- | --- |
| SIGINT / SIGTERM | Stop accepting new work and perform bounded graceful shutdown. |
| SIGHUP | Load the same path, validate and compile a full candidate, then atomically publish it. |

A failed SIGHUP keeps the current generation. Existing connections retain the
generation they started with. Listener topology, `runtime` settings,
resource-governor policy, direct-barrier policy, relay policy, and NXR
replay-cache capacity/retention require a restart; see the
[configuration reference](configuration.md#reload-boundaries).
