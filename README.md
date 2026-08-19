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

Comparator: Xray-core 26.7.28 (commit `5ca6f4b`, go1.26.0, binary SHA-256
`23d228d7…04c5268`) — the same binary that gates interoperability. Every
v1.5.1 number below was measured on the release host (Intel i3-8100 4C/4T,
Linux 6.12) with both servers at warn-level logging (rust-reality performs
no per-connection log work at warn), the same unmodified Xray SOCKS5
client in front of both servers, the same TLS 1.3 REALITY cover, loopback
origins, byte-verified transfers, and balanced ABBA interleaving. These
are controlled same-host results, not Internet speed guarantees. The full
methodology and per-run artifact pointers are in
[docs/benchmarks.md](docs/benchmarks.md); earlier per-release headline
tables are kept there as historical evidence.

Connection setup (accept → first Vision transition; 288-sample ABBA):

| concurrency | rust-reality conn/s | Xray conn/s | ratio | p99 rust | p99 Xray |
|---:|---:|---:|---:|---:|---:|
| 1 | 266.6 | 262.5 | 1.02× | 4.4 ms | 16.0 ms |
| 8 | 756.3 | 710.0 | 1.07× | 18.6 ms | 32.5 ms |
| 32 | 850.8 | 806.4 | 1.05× | 59.4 ms | 64.5 ms |

Bulk throughput, v1.5.1 vs Xray p50 ratio (512 MiB × concurrency 32, two
rounds):

| path | ratio |
|---|---:|
| bidirectional | 1.29–1.33× |
| Direct download | 1.48–1.59× |
| framed download | 1.13–1.15× |
| Direct upload | 1.07–1.11× |
| framed upload | 1.02–1.03× |
| fallback (camouflage relay) | 0.94–1.02× |

Server-side DNS (loopback resolver; 8 rounds × 32 connections per phase):
cold p50 11.0 ms vs 11.2 ms, warm p50 9.2 ms vs 10.2 ms with zero upstream
queries on both sides, and a burst of 64 concurrent identical names
finished in 73.8 ms vs 107.2 ms wall time.

Routing decision cost by rule count (worst-case last-rule match, balanced
ABBA per scale point):

| rules | rust-reality conn/s | Xray conn/s | ratio | p50 rust | p50 Xray |
|---:|---:|---:|---:|---:|---:|
| 10 | 699 | 646 | 1.08× | 10.0 ms | 10.0 ms |
| 100 | 703 | 659 | 1.07× | 9.8 ms | 10.8 ms |
| 1,000 | 683 | 598 | 1.14× | 9.8 ms | 11.3 ms |
| 10,000 | 690 | 321 | 2.15× | 9.7 ms | 22.3 ms |

Memory: after a 10-minute mixed-workload soak the standalone server's
resident set was 7.7 MiB (7.9 MiB peak) versus Xray's 38.0 MiB under the
equivalent load shape.

Versus v1.5.0: the incremental handshake-transcript hashing in v1.5.1
lowered server CPU per setup connection by 6.7% (setup ABBA median ratio
0.933, bootstrap95 [0.930, 0.934]; 602 µs vs 646 µs aggregate task-clock),
and the formal release evaluator passed all 40 protected metrics with no
regressions.

### Where rust-reality is faster

- Bulk Direct download (1.48–1.59×) and bidirectional load (1.29–1.33×) at
  concurrency 32 — the Vision Direct splice fast path.
- Setup tail latency: p99 is up to 3.6× lower at c1 (4.4 ms vs 16.0 ms)
  and stays lower through c32.
- Routing at scale: the decision cost is flat from 10 to 10,000 rules
  while Xray's degrades (2.15× connection-rate advantage at 10,000 rules).
- Same-name DNS bursts (1.45× wall time) and resident memory (about 5×
  lower RSS under the 10-minute soak).

### Where performance is equivalent

- The fallback (camouflage) relay: 0.94–1.02× across all measured cells.
- Framed upload (1.02–1.03×) and single-stream or small-payload cells
  (≈0.99–1.05×, latency-dominated on loopback).
- Setup throughput at c1 (1.02×) and cold/warm DNS resolution latency
  (within ~1 ms p50).

### Operational differences

- Starting Xray with 10,000 explicit domain rules takes ~50 seconds on
  this host (matcher construction); rust-reality starts in ~1 second
  because its routing indices are compiled at config load.
- In the cold-DNS measurement rust-reality issued A and AAAA upstream
  queries (512 upstream queries for 256 names) while the Xray
  configuration issued A-only (256) — a configuration difference, not an
  efficiency claim; the warm phases needed zero upstream queries on both
  sides.

### Limitations of the measurements

- One host (4-core i3-8100), one kernel (Linux 6.12), loopback only;
  concurrency-32 cells on four cores measure scheduler contention as much
  as proxy cost. Numbers describe implementation cost, not Internet
  throughput.
- The concurrency-32 matrix rounds used exploratory sample sizes; only the
  concurrency-1 matrix is a formal release gate.
- Small-payload c1 cells are latency-dominated, and some are bimodal on
  this host.
- In the 32 MiB × c1 Direct upload cell Xray is faster (223 MiB/s vs
  197 MiB/s in the formal matrix; the same ordering appeared in both
  exploratory rounds).
- Xray's server CPU per setup connection was not measured — the perf
  attribution needed privileges the Xray leg did not have.
- The DNS phases used a loopback upstream (~0 ms RTT), so cold/warm
  numbers isolate resolver and cache plumbing, not network latency.

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

Supported release targets: Linux x86_64 and Linux aarch64 with a modern
kernel. Releases ship three archives: `linux-x86_64-generic` (baseline
x86-64, the recommended asset), `linux-x86_64-v3` (opt-in; requires the
x86-64-v3 microarchitecture level, no runtime fallback, and no measured
advantage on the validation host — the record AEAD dispatches to AES hardware
at runtime in every tier), and `linux-aarch64-generic` (ARMv8.0 with neon,
built and smoke-tested natively on ARM runners). Use the generic archive when
CPU support is unknown.

The public
inbound does not support plain VLESS, TLS-only VLESS, WebSocket, QUIC, UDP
proxying, or non-Vision flow. NXR is not a public protocol and does not
encrypt payload after its one-time authenticated request. The public protocol
carries an end-to-end interoperability gate using an unmodified Xray-core
26.7.28 client; operators must still review the threat model, firewall
policy, cover target, and resource limits for their own VPS.

## Quick start

Download the archive for your platform, the manifest, and checksums from the
[latest release](https://github.com/jacek4yang/rust-reality/releases/latest),
then verify all assets before installation:

```shell
sha256sum --check SHA256SUMS
# Generic x86-64 package (recommended when CPU support is unknown):
tar -xzf rust-reality-v<version>-linux-x86_64-generic.tar.gz
# Or, on an x86-64-v3 CPU:
# tar -xzf rust-reality-v<version>-linux-x86_64-v3.tar.gz
# On ARM64 (ARMv8.0 with neon or later):
# tar -xzf rust-reality-v<version>-linux-aarch64-generic.tar.gz
sudo install -m 0755 rust-reality /usr/local/bin/rust-reality
```

`release-manifest.json` schema v3 records every tier's compiler, cargo
features, target CPU/features, native-measurement status, and minimum CPU
requirements.

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
IDs, an inbound `listen.mode: auto`, an outbound `network.dial.mode: auto`, and
a direct-routing policy. The listener creates independent IPv4 and IPv6
sockets while outbound family selection uses one adaptive process-wide state.
The client-facing REALITY public key is written to
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
