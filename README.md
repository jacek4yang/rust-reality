# rust-reality

[![CI](https://github.com/jacek4yang/rust-reality/actions/workflows/ci.yml/badge.svg)](https://github.com/jacek4yang/rust-reality/actions/workflows/ci.yml)
[![Security](https://github.com/jacek4yang/rust-reality/actions/workflows/security.yml/badge.svg)](https://github.com/jacek4yang/rust-reality/actions/workflows/security.yml)
[![Release](https://img.shields.io/github/v/release/jacek4yang/rust-reality?display_name=tag&sort=semver)](https://github.com/jacek4yang/rust-reality/releases)

English | [简体中文](README.zh-CN.md)

`rust-reality` is a Linux-focused, single-binary proxy server. Its only public
client entry is **VLESS + REALITY + `xtls-rprx-vision`**. An optional, separate
NXR protocol carries authenticated per-flow traffic from a public line node to
a firewall-restricted landing node.

```text
Xray-compatible client
  -> VLESS + REALITY + Vision
  -> rust-reality line or standalone node
  -> direct | SOCKS5 | blackhole | NXR
  -> optional NXR landing node
  -> destination
```

## Why rust-reality

- Xray 26.7.28-compatible public VLESS + REALITY + Vision data path.
- Exact and certificate-style one-label REALITY server-name patterns such as
  `*.lmu.edu`; clients still send a concrete SNI.
- Authentication is committed only after a valid TLS 1.3 ClientFinished.
- Authentication failures are forwarded byte-for-byte to the configured cover
  target; no synthetic proxy response identifies the service.
- Explicit per-UUID routing groups with ordered, first-match rules.
- Xray-compatible GeoIP, GeoSite, and `ext:file:tag` assets with bounded HTTPS
  download, validation, caching, and atomic last-known-good updates.
- Direct, authenticated SOCKS5, blackhole, and low-overhead NXR outbounds.
- Bounded connections, handshakes, fallbacks, crypto work, replay state,
  buffers, DNS results, and Linux splice resources.
- Strict JSON configuration, atomic SIGHUP reload, bounded logging, built-in
  key generation, destination probing, self-test, schema, and benchmarks.
- Stable Rust, no `unsafe` in the crate, no panic/unwrap in the production data
  path, and reproducible tagged release archives.

## Release status and scope

The `0.1.x` series is a pre-1.0 production preview. The public protocol has an
end-to-end interoperability gate using an unmodified Xray-core 26.7.28 client,
but operators must review the threat model, firewall policy, cover target, and
resource limits for their own VPS.

Supported release target: Linux x86_64 with a modern kernel. The public inbound
does not support plain VLESS, TLS-only VLESS, WebSocket, QUIC, UDP proxying, or
non-Vision flow. NXR is not a public protocol and does not encrypt payload after
its one-time authenticated request.

## Quick start

Download the archive, manifest, and checksums from the
[latest release](https://github.com/jacek4yang/rust-reality/releases/latest),
then verify all assets before installation:

```shell
sha256sum --check SHA256SUMS
tar -xzf rust-reality-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
sudo install -m 0755 rust-reality /usr/local/bin/rust-reality
```

Probe a proposed REALITY cover endpoint and generate a standalone server:

```shell
rust-reality probe-dest \
  --target www.microsoft.com:443 \
  --server-name www.microsoft.com

rust-reality config generate standalone \
  --target www.microsoft.com:443 \
  --server-name www.microsoft.com \
  > config.json 2> client-values.txt

rust-reality check --config config.json
rust-reality self-test --config config.json
rust-reality serve --config config.json
```

The generated JSON contains a UUID, private REALITY key, short ID, and a
direct-routing policy. The client-facing REALITY public key is written to
standard error so the private server configuration can be captured separately.
Protect both outputs and replace the example target with a destination that
passes `probe-dest` from the deployment host.

For a line/landing deployment, generate one independent NXR key and use it on
both nodes:

```shell
rust-reality node-keygen
rust-reality config generate line --help
rust-reality config generate landing --help
```

The NXR port must be allowed only from the line node's fixed source IP at the
landing firewall.

## Configuration and routing

Configuration is strict camelCase JSON. Unknown fields, missing required
references, duplicate UUIDs/tags, unsafe URLs, unbounded limits, plain VLESS,
and unsupported acceleration switches are rejected before listeners are bound.

Routing evaluates:

1. `routing.globalRules` in order;
2. the authenticated UUID's `routing.users[].rules` in order;
3. that user group's `defaultOutbound`.

Conditions inside one rule are conjunctive across categories and alternative
values inside a category are ORed. Domain, GeoSite, IP, GeoIP, port, network,
and public inbound-tag conditions are supported. See the complete
[configuration reference](docs/configuration.md) for every field, default,
constraint, matcher syntax, and reload behavior.

## Operations

- `serve` and `run` stay in the foreground for systemd or another supervisor.
- SIGINT/SIGTERM performs graceful shutdown.
- SIGHUP validates and atomically publishes a compatible configuration; active
  connections retain their prior immutable generation.
- Geo assets are conditionally revalidated on their configured interval. A
  failed download or parse keeps the last good snapshot.
- Logs can go to stderr, journald, or a size/count/total-byte-bounded file set.
  Secrets and full configuration values are excluded from structured logs.

Install and review [`deploy/rust-reality.service`](deploy/rust-reality.service)
for a hardened systemd baseline.

## Command line

The single binary provides:

```text
serve, run, check, self-test, probe-dest
config generate, config format, schema
uuid, x25519, mldsa65, node-keygen
benchmark
```

See the [CLI reference](docs/cli.md) for all arguments, ranges, defaults,
outputs, signals, and examples.

## Documentation

| Guide | English | 简体中文 |
| --- | --- | --- |
| Documentation index | [English](docs/index.md) | [简体中文](docs/index.zh-CN.md) |
| CLI reference | [English](docs/cli.md) | [简体中文](docs/cli.zh-CN.md) |
| Configuration reference | [English](docs/configuration.md) | [简体中文](docs/configuration.zh-CN.md) |
| Deployment | [English](docs/deployment.md) | [简体中文](docs/deployment.zh-CN.md) |
| Threat model | [English](docs/threat-model.md) | [简体中文](docs/threat-model.zh-CN.md) |
| Benchmarks | [English](docs/benchmarks.md) | [简体中文](docs/benchmarks.zh-CN.md) |
| Security policy | [English](SECURITY.md) | [简体中文](SECURITY.zh-CN.md) |

Protocol audit, architecture decisions, and Xray interoperability evidence are
also linked from the documentation index.

## Performance

The built-in `benchmark` command emits machine-readable, bounded protocol
measurements. Criterion suites cover VLESS decoding, Vision framing, and
routing. A controlled same-host Xray comparison is recorded in
[`docs/benchmarks.md`](docs/benchmarks.md).

These measurements are not Internet-speed promises. Latency, loss, congestion,
CPU, kernel, NIC, destination, and client behavior must be controlled before
drawing deployment conclusions.

## Build and test

The pinned toolchain is declared in `rust-toolchain.toml`:

```shell
cargo install cargo-nextest --version 0.9.140 --locked
cargo install cargo-deny --version 0.19.4 --locked
cargo install cargo-audit --version 0.22.2 --locked
./scripts/check.sh
./scripts/build-release.sh
```

The quality gate includes formatting, strict Clippy, dependency policy,
RustSec audit, documentation, nextest, release-mode tests, doc tests, and
benchmark harness execution. Security CI additionally runs parser fuzz smoke
tests and scheduled sanitizer jobs.

## Security

Read the [threat model](docs/threat-model.md) before exposing a listener. The
program cannot stop upstream volumetric DDoS from saturating a VPS link. NXR
must be firewall-restricted, and its post-authentication bytes are plaintext.

Report sensitive findings through GitHub private vulnerability reporting as
described in [`SECURITY.md`](SECURITY.md). Never publish real private keys,
UUIDs, NXR PSKs, credentials, packet captures, access tokens, or deployment
configuration in an issue or log.
