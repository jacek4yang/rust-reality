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
  -> direct | SOCKS5 | blackhole | NXR | Handoff
  -> optional NXR or Handoff landing node
  -> destination
```

## Highlights

- Xray-core 26.7.28-compatible public VLESS + REALITY + Vision data path,
  gated end to end with an unmodified Xray client.
- Directional Vision Direct: each direction switches to a raw kernel relay
  (`splice` preferred) the moment it is authenticated, with split-brain made
  structurally impossible.
- Optional Handoff topology: a line node can transfer an accepted session's
  TLS ownership to a firewall-restricted landing node over one authenticated,
  sealed channel, shedding its per-byte TLS CPU to the landing node
  (measured loopback: −82% line download CPU/GiB).
- Framed record batching, zero steady-state per-record allocations, and zero
  avoidable userspace copies on every data path.
- ring (BoringSSL-derived) AES-128-GCM record AEAD by default; a pure-Rust
  RustCrypto fallback build is one flag away and continuously tested.
- The authenticated server flight preserves the cover-derived ServerHello and
  follows optional CCS, the measured four-position/coalesced handshake shape,
  and an optional fifth post-Finished shape. The latter is represented by an
  empty ApplicationData fake NST with no resumption state. Inspection is
  bounded to 66,642 retained bytes and remains byte-exact on fallback.
- Bounded everything: connections, handshakes, fallbacks, crypto work, replay
  state, buffers, DNS results, descriptors, and splice resources — with
  pressure hysteresis instead of collapse.
- Exact and one-label wildcard REALITY server names, per-UUID routing groups,
  UUID-owned multi-short-ID authentication, Xray-compatible GeoIP/GeoSite
  assets with atomic last-known-good updates.
- Measured host-local `config autotune` with auditable atomic output, plus
  cardinality-adaptive UUID/routing/outbound indexes and deadline-driven replay
  expiry instead of unconditional live-table scans.
- Strict JSON configuration, atomic SIGHUP reload, secret-free bounded
  logging, key generation, destination probing, self-test, and schema from
  one binary.
- Stable Rust: the main protocol crate denies `unsafe` (Linux ABI unsafe is
  isolated in `crates/rr-linux` under explicit SAFETY invariants), no
  panic/unwrap in the production data path, reproducible tagged release
  archives.

## Performance vs Xray-core

Comparator: Xray-core 26.7.28 (commit `5ca6f4b`, go1.26.0), the same
binary that gates interoperability. Host: Intel i3-8100 (4C/4T), Linux
6.12.94, loopback, Go origin, 5 samples per cell; every cell
byte-verified, plus 2 GiB SHA-256 integrity runs per implementation.
Matrix cells run rust-reality at debug log level (required by the
harness's tunnel-bypass guard) against Xray at warning — a handicap for
rust-reality; the fallback and setup rows come from symmetric warn-level
harnesses. These are controlled same-host results, not Internet speed
guarantees.

| Workload | rust-reality 1.0.0 | Xray-core | Ratio |
|---|---:|---:|---:|
| Direct download, 512 MiB ×32 | 1386 MiB/s | 516 MiB/s | **2.69×** |
| Direct upload, 512 MiB ×32 | 1155 MiB/s | 1031 MiB/s | 1.12× |
| Framed download, 512 MiB ×32 | 1580 MiB/s | 1388 MiB/s | 1.14× |
| Framed upload, 512 MiB ×32 | 1442 MiB/s | 1383 MiB/s | 1.04× |
| Bidirectional, 512 MiB ×32 | 1017 MiB/s | 633 MiB/s | 1.61× |
| Fallback, 32 MiB ×32 (clean harness) | 3279 MiB/s | 3194 MiB/s | 1.03× |
| Connection setup, c32 | 895 conn/s | 812 conn/s | 1.10× |

Setup cost per connection is well under half of Xray's (0.65 ms vs 1.53 ms
server CPU over the measured 864-connection window). Single-stream loopback cells are latency-bound and
sit at parity (0.94–1.04×). The full 36-cell matrix, the deployment
characterization (routing, NXR vs SOCKS5, RTT sensitivity), the hot-path
forensic report, and everything needed to reproduce them are in
[docs/performance.md](docs/performance.md) and
[docs/benchmarks.md](docs/benchmarks.md).

For v1.5, a balanced same-host ABBA comparison against v1.4 found no
statistically significant setup or protected-path throughput/latency change:
all reported 95% intervals in two complete matrix rounds crossed no difference.
The candidate did remove
4.0013 cover `recvfrom` calls per setup connection in a separate syscall
trace. These are bounded implementation-cost observations, not a claimed
throughput win; the exact intervals are in
[docs/performance.md](docs/performance.md#v15-cover-flight-and-release-evidence).

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

Supported release target: Linux x86_64 with a modern kernel. Releases retain
the portable `x86_64-unknown-linux-gnu` archive and also provide an opt-in
`x86_64-v3` archive. The latter requires an x86-64-v3 CPU and has no runtime
fallback; use the portable archive when CPU support is unknown.

The public
inbound does not support plain VLESS, TLS-only VLESS, WebSocket, QUIC, UDP
proxying, or non-Vision flow. NXR is not a public protocol and does not
encrypt payload after its one-time authenticated request. The public protocol
carries an end-to-end interoperability gate using an unmodified Xray-core
26.7.28 client; operators must still review the threat model, firewall
policy, cover target, and resource limits for their own VPS.

## Quick start

Download the two archives, manifest, and checksums from the
[latest release](https://github.com/jacek4yang/rust-reality/releases/latest),
then verify all assets before installation:

```shell
sha256sum --check SHA256SUMS
# Portable package (recommended when CPU support is unknown):
tar -xzf rust-reality-v<version>-x86_64-unknown-linux-gnu.tar.gz
# Or, on an x86-64-v3 CPU:
# tar -xzf rust-reality-v<version>-x86_64-v3-unknown-linux-gnu.tar.gz
sudo install -m 0755 rust-reality /usr/local/bin/rust-reality
```

`release-manifest.json` schema v2 records both CPU tiers and their requirements.

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
rust-reality config autotune \
  --config config.json --output config.tuned.json
rust-reality check --config config.tuned.json
rust-reality self-test --config config.tuned.json
rust-reality serve --config config.tuned.json
```

The generated JSON contains a UUID, private REALITY key, two UUID-owned short
IDs, and a
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
resource mode. v1.2 configurations must move the former shared
`realitySettings.shortIds` list under its owning `clients[]` entry before a
v1.3 restart.

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
