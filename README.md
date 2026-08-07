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

## Highlights

- Xray-core 26.7.28-compatible public VLESS + REALITY + Vision data path,
  gated end to end with an unmodified Xray client.
- Directional Vision Direct: each direction switches to a raw kernel relay
  (`splice` preferred) the moment it is authenticated, with split-brain made
  structurally impossible.
- Framed record batching, zero steady-state per-record allocations, and zero
  avoidable userspace copies on every data path.
- ring (BoringSSL-derived) AES-128-GCM record AEAD by default; a pure-Rust
  RustCrypto fallback build is one flag away and continuously tested.
- Bounded everything: connections, handshakes, fallbacks, crypto work, replay
  state, buffers, DNS results, descriptors, and splice resources — with
  pressure hysteresis instead of collapse.
- Exact and one-label wildcard REALITY server names, per-UUID routing groups,
  Xray-compatible GeoIP/GeoSite assets with atomic last-known-good updates.
- Strict JSON configuration, atomic SIGHUP reload, secret-free bounded
  logging, key generation, destination probing, self-test, and schema from
  one binary.
- Stable Rust, no `unsafe` in the crate, no panic/unwrap in the production
  data path, reproducible tagged release archives.

## Performance vs Xray-core

The v1.0.0 comparison against Xray-core 26.7.28 is frozen from the
release-candidate matrix. **TBD-final-matrix** — numbers frozen from the
v1.0.0 release-candidate matrix; do not quote this section until the
coordinator publishes the final table.

| cell | rust-reality | Xray-core | ratio |
|---|---:|---:|---:|
| TBD-final-matrix | TBD | TBD | TBD |

Until then, the canonical development samples and the measured evidence
behind the design (framed AEAD decomposition, ring provider A/B, setup-rate
model, fallback A/B) are documented in [docs/performance.md](docs/performance.md)
and [docs/benchmarks.md](docs/benchmarks.md). All numbers are same-host
loopback measurements on a disclosed host; none of them is an
Internet-throughput promise.

## Architecture

One Tokio multi-thread runtime; one task per connection, splitting into two
independent direction tasks after authentication. The framed phase runs
outer-TLS record I/O with Vision padding; at an authenticated Direct boundary
each direction independently transitions to a raw relay — bilateral
socket-reuniting `splice` when both directions arrive, directional `splice`
otherwise, bounded buffered userspace as the decline fallback. Fallback
(camouflage) traffic to the cover target uses the same unified,
FD-accounted relay. See [docs/architecture.md](docs/architecture.md) for the
lifecycle, the hot-path topology, the descriptor-budget model, and the
observability events, and [docs/protocol.md](docs/protocol.md) for the
protocol stack itself.

## Supported scope

Supported release target: Linux x86_64 with a modern kernel. The public
inbound does not support plain VLESS, TLS-only VLESS, WebSocket, QUIC, UDP
proxying, or non-Vision flow. NXR is not a public protocol and does not
encrypt payload after its one-time authenticated request. The public protocol
carries an end-to-end interoperability gate using an unmodified Xray-core
26.7.28 client; operators must still review the threat model, firewall
policy, cover target, and resource limits for their own VPS.

## Quick start

Download the archive, manifest, and checksums from the
[latest release](https://github.com/jacek4yang/rust-reality/releases/latest),
then verify all assets before installation:

```shell
sha256sum --check SHA256SUMS
tar -xzf rust-reality-v1.0.0-x86_64-unknown-linux-gnu.tar.gz
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
passes `probe-dest` from the deployment host. The full walkthrough, including
the line/landing NXR topology, is in
[docs/getting-started.md](docs/getting-started.md).

## Configuration

Configuration is strict camelCase JSON. Unknown fields, missing required
references, duplicate UUIDs/tags, unsafe URLs, unbounded limits, plain VLESS,
and removed acceleration switches are rejected before listeners are bound.

Routing evaluates `routing.globalRules` in order, then the authenticated
UUID's `routing.users[].rules` in order, then that user group's
`defaultOutbound`. Conditions inside one rule are conjunctive across
categories and alternative values inside a category are ORed. See the
complete [configuration reference](docs/configuration.md) for every field,
default, constraint, matcher syntax, reload behavior, and the dedicated
resource mode.

## Deployment

`serve`/`run` stay in the foreground for systemd; SIGINT/SIGTERM shut down
gracefully; SIGHUP validates and atomically publishes a compatible
configuration while established connections keep their generation. Install
and review [`deploy/rust-reality.service`](deploy/rust-reality.service) for a
hardened systemd baseline, and follow
[docs/deployment.md](docs/deployment.md) for verification, service accounts,
firewall rules, upgrades, and rollback.

## Security

Read the [threat model](docs/threat-model.md) before exposing a listener, and
the [security policy](SECURITY.md) for supported versions, private
vulnerability reporting, and the cryptographic boundary — including the ring
AEAD provider's documented zeroization tradeoff and the
`--no-default-features` RustCrypto fallback build. The program cannot stop
upstream volumetric DDoS from saturating a VPS link. NXR must be
firewall-restricted, and its post-authentication bytes are plaintext. Never
publish real private keys, UUIDs, NXR PSKs, credentials, packet captures,
access tokens, or deployment configuration in an issue or log.

## Documentation

| Guide | English | 简体中文 |
| --- | --- | --- |
| Documentation index | [English](docs/index.md) | [简体中文](docs/index.zh-CN.md) |
| Getting started | [English](docs/getting-started.md) | [简体中文](docs/getting-started.zh-CN.md) |
| CLI reference | [English](docs/cli.md) | [简体中文](docs/cli.zh-CN.md) |
| Configuration reference | [English](docs/configuration.md) | [简体中文](docs/configuration.zh-CN.md) |
| Deployment | [English](docs/deployment.md) | [简体中文](docs/deployment.zh-CN.md) |
| Protocol overview | [English](docs/protocol.md) | [简体中文](docs/protocol.zh-CN.md) |
| Architecture | [English](docs/architecture.md) | [简体中文](docs/architecture.zh-CN.md) |
| Performance | [English](docs/performance.md) | [简体中文](docs/performance.zh-CN.md) |
| Benchmarks | [English](docs/benchmarks.md) | [简体中文](docs/benchmarks.zh-CN.md) |
| Threat model | [English](docs/threat-model.md) | [简体中文](docs/threat-model.zh-CN.md) |
| Security policy | [English](SECURITY.md) | [简体中文](SECURITY.zh-CN.md) |

## Build and development

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
tests and scheduled sanitizer jobs. The default build uses ring for the
TLS 1.3 AES-128-GCM record AEAD; `cargo build --release
--no-default-features` selects the pure-Rust RustCrypto provider with no
other behavioral change.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option. Third-party dependencies retain their own licenses;
`deny.toml` constrains them to a permissive allow-list.
