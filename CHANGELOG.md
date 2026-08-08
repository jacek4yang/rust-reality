# Changelog

All notable user-facing changes to this project are documented in this file.

## [1.2.0] - 2026-08-08

### Added

- **Multi-landing Handoff**: one line node can route different UUID groups to
  different landing nodes using the existing routing language — one tagged
  handoff outbound per landing, and per-group rules can still reach local
  direct egress. `config generate handoff` accepts repeated
  `--landing-address`/`--landing-port` and writes `landing-1.json` …
  `landing-N.json` (independent key material per landing), a merged
  `line.json` with one UUID group per landing, and a matching
  `xray-client.json`. Every emitted file is validated before it is written.
- **Landing egress** (`egress` on the handoff inbound): a landing node can
  reach transferred destinations through a configured `direct`, `socks5`,
  `nxr`, or `blackhole` outbound instead of only dialing directly. A
  `handoff` egress is rejected — Handoff never chains.
- **Zero-downtime Handoff key rotation**: a landing accepts up to two
  `previousPreSharedKeys` and `previousPrivateKeys` during a rotation window,
  so rotating the Handoff PSK or static key no longer requires a
  synchronized two-node swap. An open rotation window is announced once per
  listener with a warning event; previous keys must be dropped promptly
  after rotation (the forward-secrecy bound in the threat model holds only
  once they are gone).

### Fixed

- A relay abort guard could fire on an already-closed descriptor after the
  raw relay had consumed the sockets; under descriptor recycling that could
  reset an unrelated connection. The guard now disarms exactly where the
  relay takes ownership.
- A cancelled descriptor-budget wait no longer leaks its waiter
  registration, which had silently disabled the release path's notify
  optimization.
- The Handoff transfer's descriptor permit is now released strictly after
  its socket closes on every error path.
- The Handoff key-independence validator also rejects a `preSharedKey`
  equal to a REALITY `privateKey` — the most plausible same-file copy-paste
  collision.

### Removed

- The test-only borrowed-socket relay entry points (`TcpRelay::relay`,
  `relay_borrowed`, `RelayContext::borrowed`) and the write-only
  `owns_complete_sockets` state; the single-variant `RouteError` was folded
  into `RouteResolutionError`.

### Compatibility

- No wire or configuration breakage: v1.1.0 configurations load unchanged,
  and mixed v1.1.0/v1.2.0 LINE↔LANDING pairs interoperate byte-exactly in
  both directions over Handoff and NXR. Upgrade either node first.

### Notes

- Validated on Linux x86_64. Real multi-host LAN, real WAN, ≥8-core, and
  NUMA behavior are explicitly unverified in this release; the WAN-emulation
  characterization lives in docs/benchmarks.md.

## [1.1.0] - 2026-08-08

### Added

- **Handoff session transfer** (`handoff` inbound/outbound): after REALITY
  authentication, VLESS request decode, and routing, a line node transfers
  the entire session — TLS 1.3 record-layer state, sequence numbers, Vision
  context, pending bytes — to a landing node over one sealed, bounded,
  replay-protected message (per-transfer ephemeral X25519 against the
  landing's static key, PSK mixed in one HKDF-SHA256 chain,
  ChaCha20-Poly1305, versioned binary format). The landing becomes the sole
  TLS/Vision owner; the line degrades to a thin kernel splice relay.
  Unmodified Xray clients are unaffected. Measured on the validation host
  (single-host loopback): line-node CPU per GiB −82% downlink / −60% uplink
  versus the NXR topology; two-node total roughly flat. See
  docs/performance.md for the labeled evidence and docs/threat-model.md for
  the security boundary (the line↔landing link must be private/firewalled).
- `config generate handoff` produces `line.json`, `landing.json`, and
  `xray-client.json` with all key material generated and both server
  configurations pre-validated.
- Numeric IP literals carried as VLESS domains (destinations, REALITY cover
  targets, NXR/SOCKS5 upstreams) now dial directly without entering the
  blocking system resolver or consuming bounded DNS-pool permits.
- New outbound setting `firstByteTimeoutMs` bounds how long a handoff line
  waits for the landing's first sealed record before declaring rejection.
- Fuzz targets for the Handoff header, continuation blob decoder, and
  transfer open path.

### Fixed

- Two `Notify` lost-wakeup races in the resource-pressure gauge and the FD
  budget: a state transition or capacity release landing between the waiter's
  re-check and its first poll could strand the waiter forever.
- The replay reservation and the handshake deadline are now anchored to one
  instant; a ClientFinished admitted by the deadline can no longer be
  rejected by an already-expired reservation.
- A liveness timeout that truncates an in-flight transfer is now classified
  as an abort (RST semantics) instead of a clean timeout, and reports as
  `timeout`, not `protocol`, in rejection accounting.
- Descriptor accounting: a soft RLIMIT of 0 is refused instead of planned as
  unlimited; the theoretical FD peak includes pipe-pool retention; the
  emergency reserve scales with the listener count.
- Teardown resets at the handoff line relay (both sockets carry TLS records)
  count as clean EOF, ending spurious `connection_rejected` events on clean
  session completion.

### Removed

- The test-only plain-VLESS server path and the orphaned config snapshot
  store, plus dead APIs found by the final audit (about −950 LOC total).
  Coverage of the deleted paths exists against the production relay.

### Notes

- No configuration migration is required; v1.0 configurations load
  unchanged.

## [1.0.0] - 2026-08-07

First stable release.

### Public protocol

- VLESS + REALITY + `xtls-rprx-vision` is the only public client entry,
  wire-compatible with Xray-core clients. Exact and leftmost one-label
  wildcard REALITY server names are supported; authentication is committed
  only after a valid TLS 1.3 ClientFinished.
- Authentication failures fall back byte-for-byte to the configured cover
  target; no synthetic response identifies the service.
- End-to-end interoperability is gated with an unmodified Xray-core 26.7.28
  client (`scripts/test-xray-interop.sh`), including an ML-DSA-65
  verification-key differential.

### Data plane

- Directional Vision Direct: each direction transitions independently to a
  raw relay at its authenticated boundary — bilateral socket-reuniting
  `splice` when both directions arrive, directional `splice` otherwise,
  bounded buffered userspace as the decline fallback. Split-brain is made
  structurally impossible by monotonic direction states.
- REALITY fallback (camouflage) traffic uses the same unified, FD-accounted
  relay, with pooled pipes (`PipePool`) removing per-session pipe churn.
- Framed record batching packs multiple Vision frames per outer TLS record;
  the framed path performs zero steady-state per-record allocations and zero
  avoidable userspace copies.
- The default TLS 1.3 AES-128-GCM record AEAD provider is ring
  (BoringSSL-derived, statically linked): ≈2.5× faster record seal/open at
  production sizes, −33% server CPU per GiB, zero new dependency crates.
  Building with `--no-default-features` selects the pure-Rust RustCrypto
  provider with identical protocol behavior; both configurations are tested
  in CI. The provider's zeroization tradeoff is disclosed in `SECURITY.md`.

### Resource architecture and correctness

- Bounded everything: connections, handshakes, fallbacks, cryptographic
  work, replay state, buffers, DNS results, descriptors, and splice
  resources, with descriptor-pressure hysteresis and a classified accept
  error-recovery model (including an emergency-reserve descriptor) instead
  of listener collapse.
- Optional `runtime.resourceMode: "dedicated"` for single-tenant machines:
  soft `RLIMIT_NOFILE` raise, machine-derived budgets, and a two-dimensional
  (FD + memory) pressure model with priority shedding that never revokes
  established relays.
- DNS work runs in a bounded, fail-fast pool; all data sockets carry a
  `SO_KEEPALIVE` liveness backstop; aborted transfers reset the peer
  (`SO_LINGER{on,0}`) instead of resembling a clean FIN.
- The io_uring and sockhash kernel backends were removed before release;
  stale configuration keys for them are rejected as unknown fields.

### NXR

- The internal line-to-landing NXR protocol ships with one-time HMAC
  authentication under an independent pre-shared key, a bounded nonce replay
  cache, and silent-close failure; it is firewall-restricted by design and
  carries no post-authentication encryption.

### Operations

- Strict camelCase JSON configuration with full validation before listeners
  bind; atomic SIGHUP reload with last-good retention, where cold settings
  are rejected rather than silently deferred.
- Secret-free bounded logging to stderr, journald, or a size/count/total-
  byte-bounded file set; GeoIP/GeoSite assets update atomically with
  last-known-good retention.
- One binary provides key generation, destination probing, configuration
  generation/formatting, schema export, self-test, serving, and bounded
  built-in benchmarks. Reproducible tagged release archives for Linux
  x86_64.

### Performance

- Final release matrix against Xray-core 26.7.28 (same-host loopback,
  i3-8100): Direct download 2.69× at 512 MiB c32, framed download 1.14×,
  framed upload 1.04×, bidirectional 1.61×, fallback 1.03× (clean
  harness), setup rate 1.10× with 0.65 ms vs 1.53 ms server CPU per connection.
  Representative rows in README.md; full methodology and the
  deployment/forensic gates in `docs/performance.md`.

[1.0.0]: https://github.com/jacek4yang/rust-reality/releases/tag/v1.0.0
