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
- Authenticated REALITY setup uses a validated prebuilt cover profile when an
  exact conservative ClientHello class is ready, otherwise a warm live-cover
  TCP socket and then the ordinary cold live-cover path. Unauthenticated,
  malformed, unsupported, and replayed traffic always sees the real cover.
- Directional Vision Direct: each direction switches to a raw kernel relay
  (`splice` preferred) the moment it is authenticated, with split-brain made
  structurally impossible.
- Optional Handoff topology: a line node can transfer an accepted session's
  TLS ownership to a firewall-restricted landing node over one authenticated,
  sealed channel, shedding its per-byte TLS CPU to the landing node
  (measured loopback: −82% line download CPU/GiB).
- Adaptive single-use warm TCP pools pre-pay fixed-peer establishment for
  Handoff, NXR, and SOCKS5. On a valid hit the LINE-to-LANDING/upstream TCP
  handshake leaves the per-flow critical path; every protocol still performs
  its normal per-session authentication and a miss cold-connects immediately.
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
v1.8.0 protected Xray-comparison number below retains the v1.6.1 measurement
foundation from the release host (Intel i3-8100 4C/4T, Linux 6.12). Both
servers used warn-level logging (rust-reality performs
no per-connection log work at warn), the same unmodified Xray SOCKS5
client in front of both servers, the same TLS 1.3 REALITY cover, loopback
origins, byte-verified transfers, and balanced ABBA interleaving. These
are controlled same-host results, not Internet speed guarantees. The full
methodology and per-run artifact pointers are in
[docs/benchmarks.md](docs/benchmarks.md); earlier per-release headline
tables are kept there as historical evidence.

Connection setup (accept → first Vision transition; 144-sample ABBA):

| concurrency | rust-reality conn/s | Xray conn/s | ratio | p99 rust | p99 Xray |
|---:|---:|---:|---:|---:|---:|
| 1 | 268.5 | 251.4 | 1.07× | 4.5 ms | 17.7 ms |
| 8 | 767.5 | 716.9 | 1.07× | 18.8 ms | 30.8 ms |
| 32 | 853.2 | 784.5 | 1.09× | 59.3 ms | 73.3 ms |

Bulk throughput, v1.8.0 vs Xray p50 ratio (32 MiB × concurrency 32, two
rounds):

| path | ratio |
|---|---:|
| bidirectional | 1.28× |
| Direct download | 1.61× |
| framed download | 1.13× |
| Direct upload | 1.06× |
| framed upload | 1.10× |
| fallback (camouflage relay) | 0.98× |

Server-side DNS (loopback resolver; 8 rounds × 32 connections per phase):
cold p50 29.2 ms vs 30.4 ms, warm p50 23.1 ms vs 25.0 ms with zero upstream
queries on both sides, and a burst of 64 concurrent identical names
finished in 80.2 ms vs 100.2 ms wall time.

Routing decision cost by rule count (balanced ABBA per scale point):

| rules | rust-reality conn/s | Xray conn/s | ratio | p50 rust | p50 Xray |
|---:|---:|---:|---:|---:|---:|
| 10 | 795 | 787 | 1.01× | 29.3 ms | 32.3 ms |
| 100 | 803 | 753 | 1.07× | 28.1 ms | 32.1 ms |
| 1,000 | 813 | 685 | 1.19× | 29.9 ms | 34.9 ms |
| 10,000 | 794 | 324 | 2.45× | 29.8 ms | 81.1 ms |

Memory: after a 10-minute mixed-workload soak the standalone server's
resident set was 8.3 MiB versus Xray's 39.5 MiB under the equivalent load
shape.

Versus v1.5.1: the fallback relay now runs with 512 KiB splice pipes —
server CPU per GiB ratio 0.953 (bootstrap95 [0.925, 0.974], all six ABBA
blocks below 1.0) with splice syscalls halved — and the Vision framed
uplink batches decoded records into one destination write (+5.5%
throughput at concurrency 32, 3.5× fewer origin write syscalls; sparse
flows pay no added latency). The formal release evaluator passed all 40
protected metrics with no regressions against the v1.5.1 release binary.

Versus Xray: server CPU per setup connection was 571 µs vs 925 µs in the
same perf-attributed setup benchmark — rust-reality completes a VLESS +
REALITY + Vision setup with about 0.62× the server CPU.

### Where rust-reality is faster

- Bulk Direct download (1.61×) and bidirectional load (1.28×) at
  concurrency 32 — the Vision Direct splice fast path.
- Setup tail latency: p99 is up to 3.9× lower at c1 (4.5 ms vs 17.7 ms)
  and stays lower through c32.
- Routing at scale: the decision cost is flat from 10 to 10,000 rules
  while Xray's degrades (2.45× connection-rate advantage at 10,000 rules).
- Same-name DNS bursts (1.25× wall time) and resident memory (about 4.8×
  lower RSS under the 10-minute soak).
- Setup CPU cost: 0.62× the server CPU per connection (571 µs vs 925 µs
  task-clock, perf-attributed).

### Where performance is equivalent

- The fallback (camouflage) relay: 0.98× bulk (1.00× on the formal
  byte-exact ABBA gate) — with server CPU per GiB down to 0.953× of the
  v1.5.1 implementation.
- Framed upload (1.10×) and single-stream or small-payload cells
  (≈1.0×, latency-dominated on loopback).
- Setup throughput at c1 (1.07×) and cold/warm DNS resolution latency
  (within ~2 ms p50).

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
kernel. Releases ship four archives: `linux-x86_64-generic` (baseline
x86-64 GNU/glibc, recommended for conventional distributions),
`linux-x86_64-musl` (baseline x86-64, fully static, recommended for Alpine,
other musl systems, and minimal containers), `linux-x86_64-v3` (opt-in;
requires the x86-64-v3 microarchitecture level, no runtime fallback, and no
measured advantage on the validation host — the record AEAD dispatches to AES
hardware at runtime in every tier), and `linux-aarch64-generic` (ARMv8.0 with
neon, built and smoke-tested natively on ARM runners). Use a baseline archive
when CPU support is unknown and select GNU versus musl for the deployment
userspace.

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
# Generic GNU/glibc x86-64 package:
tar -xzf rust-reality-v<version>-linux-x86_64-generic.tar.gz
# On Alpine/musl or in a minimal container, use the static package:
# tar -xzf rust-reality-v<version>-linux-x86_64-musl.tar.gz
# Or, on an x86-64-v3 GNU/glibc CPU:
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
| Security policy | [English](SECURITY.md) | [简体中文](docs/zh-CN/security.md) |

## Build and development

The pinned toolchain is declared in `rust-toolchain.toml`:

```shell
cargo install cargo-nextest --version 0.9.140 --locked
cargo install cargo-deny --version 0.19.4 --locked
cargo install cargo-audit --version 0.22.2 --locked
cargo dev check --all
cargo dev release build linux-x86_64-generic
```

The quality gate includes formatting, strict Clippy, dependency policy,
RustSec audit, documentation, nextest, release-mode tests, doc tests, and
benchmark harness execution. Security CI additionally runs every target from
`fuzz/Cargo.toml` in bounded shards, with a deeper scheduled fuzz budget, plus
ASan/LSan and TSan jobs. The default build uses ring for the
TLS 1.3 AES-128-GCM record AEAD; `cargo build --release
--no-default-features` selects the pure-Rust RustCrypto provider with no
other behavioral change.

## Acknowledgements

`rust-reality` is an independent, from-scratch Rust implementation, but it
stands on the work of a wider open-source community. In particular, thank you
to:

- [Xray-core](https://github.com/XTLS/Xray-core) for the VLESS, REALITY, and
  Vision ecosystem, reference behavior, and the unmodified client used by the
  interoperability and comparison gates.
- [Rust](https://www.rust-lang.org/) and [Tokio](https://tokio.rs/) for the
  language, tooling, and asynchronous networking runtime.
- [ring](https://github.com/briansmith/ring) and the
  [RustCrypto](https://github.com/RustCrypto) projects for the cryptographic
  implementations used by the protocol stack.
- [Hickory DNS](https://github.com/hickory-dns/hickory-dns) for the asynchronous
  DNS resolver used by configured upstream resolution.

Thanks also to every maintainer and contributor behind the dependencies
recorded in `Cargo.lock`. Each third-party project remains subject to its own
license.

## Friends

- [LINUX DO](https://linux.do/) — a friendly developer and technology
  community.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option. Third-party dependencies retain their own licenses;
`deny.toml` constrains them to a permissive allow-list.
