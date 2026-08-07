# Changelog

All notable user-facing changes to this project are documented in this file.

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
  `SO_KEEPALIVE` liveness backstop; abort paths are indistinguishable from
  clean FIN.
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

- The comparator summary against Xray-core 26.7.28 is **TBD**: numbers are
  frozen from the v1.0.0 release-candidate matrix at release time. The
  canonical development samples (framed AEAD provider A/B, fallback A/B,
  setup-rate model) are documented in `docs/performance.md` and
  `docs/benchmarks.md`.

[1.0.0]: https://github.com/jacek4yang/rust-reality/releases/tag/v1.0.0
