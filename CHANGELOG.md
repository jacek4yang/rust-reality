# Changelog

All notable user-facing changes to this project are documented in this file.

## [Unreleased]

### Added

- Per-inbound `listen` topology with `auto`, `dualStack`, `ipv4Only`, and
  `ipv6Only`; IPv4 and IPv6 use independent sockets and IPv6 is explicitly
  `IPV6_V6ONLY` before bind.
- A bounded process-wide outbound startup snapshot and two-family runtime
  health state with route refresh, classified failure evidence, hysteresis,
  expiry, and recovery trials.
- Bounded Happy-Eyeballs-style dialing for locally resolved peers: one DNS
  snapshot, one absolute deadline, at most two live candidates, one FD permit
  per live socket, and drained losing tasks.

### Changed

- Replaced the combined `network.addressFamily` model with independent
  `inbounds[].listen` and `network.dial` configuration. This is intentionally
  not backward compatible; obsolete fields and scalar listeners are rejected.
- `listen.mode: auto` degrades only genuine family/protocol unavailability and
  logs exact active/unavailable families. Address conflicts, permission
  failures, and invalid concrete addresses remain fatal; `dualStack` requires
  both families.
- Outbound `auto` derives its stable initial ordering from local route/source
  capability and system address-selection behavior. Refusal, reset, generic
  timeout, one destination failure, and cancelled race losers no longer create
  global hard-family penalties.
- Same-host release validation against `main` found Direct relay throughput
  changes between -1.46% and +0.56% across upload, download, and full-duplex at
  concurrency 1 and 32. Setup CPU/connection was +0.55%; numeric IPv4 setup was
  unchanged, numeric IPv6 was +1.12%, and immediate IPv6-refusal fallback was
  30.9% faster than the original pull-request head.

## [1.4.0] - 2026-08-11

### Added

- A bounded, cover-derived TLS 1.3 server-flight policy now reproduces either
  one coalesced post-ServerHello encrypted record or four positional records.
  The choice and outer lengths come from the authenticated connection's actual
  cover flight; the cover ServerHello remains authoritative.
- `scripts/benchmark-tls-shape.sh` and its small libssl reference/helper tools
  provide a reproducible four-way comparison of a byte-identical stock-Xray
  ClientHello against a pinned OpenSSL reference, v1.3.0, the candidate, and
  Xray. Reports separate TLS records, process writes, loopback packets, and
  timings, and require exact binary hashes before opening listeners.

### Changed

- The REALITY cover reader now validates middlebox-compatibility CCS and a
  bounded portion of the encrypted cover flight under the existing absolute
  handshake deadline. Every consumed byte is retained so incompatibility,
  timeout, admission failure, or pre-write shape failure still rejoins the same
  cover socket byte-exactly.
- EncryptedExtensions, Certificate, CertificateVerify, and Finished are built
  and transcripted exactly once, then only their TLS record boundaries and
  authenticated zero padding are shaped. The flight remains one contiguous
  socket write; application record layers still begin at sequence zero, so
  Vision Direct and Handoff state ownership are unchanged.
- Benchmark/deployment harnesses now pin and report binary, source, lockfile,
  compiler, feature, logging, kernel, and CPU identities. Routing/scale
  generators preserve UUID-owned short IDs, and large integrity outputs are
  deleted after each cell instead of accumulating across implementations.

### Wire-shape evidence

- The reference is official OpenSSL 3.5.6 tag `openssl-3.5.6` at commit
  `286ddeaac037533bbdce65b3c689e3f7ffebf0f6`, built statically with its built-in
  default provider and ambient configuration disabled. Exact executable and
  static-library hashes are recorded in ADR 0004.
- With identical authenticated ClientHellos, v1.3.0 emitted one encrypted
  handshake record (`[331]` bytes for AES-128-GCM/ChaCha20-Poly1305 and `[347]`
  for AES-256-GCM). The candidate, pinned OpenSSL reference, and Xray all
  emitted `[32, 833, 281, 53]` or `[32, 833, 281, 69]` in the controlled local
  certificate cases. ServerHello length, CCS placement, legacy record version,
  record count, per-position lengths, first-flight bytes, and write count/size
  align on those measured dimensions.
- This is not a universal cover fingerprint. A three-sample cover corpus was
  stable per target but varied materially: the pinned local reference and
  Microsoft used four records, while Google used one coalesced record. The
  adaptive policy follows that measured outer shape; fixed/random padding was
  rejected. Loopback TCP packetization remains network-dependent, the Rust and
  reference syscall primitives differ, and straced single-sample timings are
  not comparable.

### Performance and provider decisions

- Controlled setup profiling measured −0.26% median setup rate, +1.86%
  CPU/connection, +0.67% instructions/connection, and about 3.4 additional
  cover `recvfrom` calls per setup connection. Vision Direct throughput was
  +0.26% with −1.87% CPU/GiB and −0.21% instructions/GiB. These same-host
  effects are within the v1.4 keep budget; noisy loopback throughput cells are
  retained as samples rather than headline wins or regressions.
- OpenSSL EVP was independently tested but not retained. AES-128-GCM lost to
  the current ring provider on the real record path; AES-256-GCM,
  ChaCha20-Poly1305, bulk hashes, and X25519 showed isolated wins in some cells
  but lacked an end-to-end gain sufficient to justify provider lifecycle,
  deployment, ABI, and dependency cost. Full libssl termination was not
  attempted because supported APIs cannot preserve the project's explicit
  record state, Handoff, cover-derived ServerHello, and Vision Direct model.

### Compatibility and security

- Stock Xray 26.7.28 interoperability passes with both four-record Microsoft
  and coalesced Google covers, including exact 1 MiB payload integrity and the
  hybrid ML-DSA profile. No public configuration, application-data record
  policy, dependency, or wire-semantic migration is introduced.
- Transcript partition-invariance, exact ClientFinished verification,
  application sequence ownership, cover fallback rejoin, malformed/truncated
  flights, bounded allocation, replay ordering, and provider equivalence have
  dedicated tests. The maximum retained positional cover prefix is 66,125
  bytes per already authenticated/admitted connection.

### Known limitations

- The cover flight is now an admission contract for authenticated clients:
  the cover must emit the middlebox-compatibility CCS after its ServerHello
  and present either a four-record flight whose positional lengths fit the
  generated messages or a coalesced first record larger than the generated
  flight. Covers outside these measured classes (including TLS 1.3 covers
  that legitimately omit CCS when the mirrored ClientHello has an empty
  legacy session ID) fail closed: the authenticated client rejoins the cover
  byte-exactly instead of completing the REALITY handshake. Stock Xray
  fingerprints negotiate the supported classes. See ADR 0004.

## [1.3.0] - 2026-08-10

### Added

- **Measured host-local autotuning:** `config autotune` runs bounded protocol,
  cgroup/machine, scratch-storage, and bidirectional TCP-loopback probes and
  writes a validated tuned copy plus a complete JSON decision report. The
  input, identity/security state, routing, logging, cover targets, and timeout
  policy are preserved. Outputs are owner-only (`0600`) same-directory atomic
  replacements. Its connection ceiling is independently bounded by FD and a
  conservative 64 KiB-per-session memory plan; `--dedicated` is explicit.
- Reproducible Criterion gates for short-ID ownership, UUID lookup,
  outbound-tag lookup, REALITY digest hashing, direct-admission contention,
  and replay expiry/reservation, plus executable Xray v26.7.28 A/B harnesses
  for setup and VLESS Encryption nested inside the mandatory REALITY + Vision
  stack.

### Changed

- **UUID-owned REALITY short IDs:** `shortIds` now lives inside every
  `settings.clients[]` object. One UUID owns one or more IDs, each ID is unique
  within the inbound, and authorization is two-stage: REALITY resolves the
  short ID directly to its unique owner UUID, then the decoded VLESS UUID must
  equal that owner. Generators emit two independent IDs per UUID for staged
  rotation and never share them across multi-landing identities.
- The immutable short-ID owner index uses a compact sorted array through 256
  IDs and the randomized standard hash map above it, at the measured 256/512
  crossover. Normal two-ID ownership lookup is 3.50 ns versus 35.04 ns for the
  replaced owner-selecting linear constant-time scan on the release host.
- UUID authentication and UUID-group routing share a cardinality-adaptive
  immutable index: up to 64 UUIDs use a compact sorted array; larger tables
  use the randomized standard hash map. Outbound tags use the same measured
  idea with a four-entry sorted boundary. This avoids SipHash/bucket overhead
  for normal small configurations without sacrificing large-table lookup or
  hash-flood resistance.
- REALITY, NXR, and Handoff replay caches now maintain deadline heaps instead
  of retaining/scanning every live hash entry. NXR/Handoff normally lock and
  purge only the nonce's shard; a sixteen-shard sweep happens only under real
  capacity pressure. With 4,096 live entries, reserving a 64-nonce batch fell
  from 593.18 µs to 17.43 µs on the release host (34.0×).
- The production REALITY path no longer builds a duplicate UUID registry or
  performs a second UUID lookup after the short ID has authenticated its
  owner. Routing shares one compiled policy among UUIDs in the same group and
  does one user lookup per decision; outbound selection resolves its tag once
  across both Handoff and ordinary connects.
- VLESS request parsing has separate owned-public and borrowed-production
  specializations. The Vision parser allocates nothing while inspecting
  Addons/domain/prefetch, and its request buffer starts at 533 bytes instead
  of a full TLS record. The common X25519 handshake uses a fixed server-share
  array and writes one preassembled contiguous server flight, eliminating the
  duplicate plaintext and send-time assembly allocations.
- The direct-dial mutex/floating-point token bucket is now a lock-free atomic
  GCRA with the same one-second burst allowance. Full-barrier Criterion time
  fell about 19.5% single-threaded and 19.9% with four contending threads.
- REALITY replay lookup uses an independent word of its server-computed
  SHA-256 key directly as the table hash (11.6× hit and 22.4× miss speedup at
  4,096 entries). Peer-controlled NXR and Handoff nonce tables deliberately
  retain randomized hashing for collision resistance.
- Dependency features now match the used surfaces, the duplicate direct
  `base64` version is unified, and Criterion no longer pulls its unused
  plotting/parallel defaults. Cargo.lock lost ten packages; the final stripped
  release binary is 6,309,616 bytes, 22,920 bytes (0.36%) smaller than the
  6,332,536-byte pre-audit build.

### Fixed

- Monotonic-time exhaustion now fails closed in both the lock-free direct-dial
  GCRA and REALITY replay-generation counter. Saturation can no longer turn a
  spent `u64` domain into an endlessly admitted or duplicate-prone state; the
  replay admission permit is released on every rejected generation.
- Expiry-heap cleanup no longer relies on runtime `expect` assertions after a
  peek, and the direct rate configuration rejects sub-nanosecond refill rates
  that its integral clock model cannot represent exactly.
- The production borrowed VLESS decoder is now exercised by the wire fuzz
  target and a deterministic property test covering every truncation and
  byte-field mutation of a maximum-sized request. Owned and borrowed paths
  must return identical errors or decoded fields.

### Security decision

- VLESS Encryption is **not** stacked inside REALITY in v1.3. The exact Xray
  v26.7.28 A/B measured 30.4% lower p50 throughput, 5.5× server CPU/GiB, and
  loss of the Vision splice path for a 3.7% setup-rate reduction. REALITY TLS
  1.3 already supplies confidentiality and integrity for this mandatory
  profile. The benefits for raw/CDN/untrusted-relay profiles, threat analysis,
  and explicit revisit gates are retained in ADR 0003.

### Compatibility and migration

- **Configuration migration is required for every public VLESS inbound.** Move
  `streamSettings.realitySettings.shortIds` into the owning
  `settings.clients[].shortIds` and delete the old field. A single client can
  keep the array unchanged; multiple clients must receive disjoint non-empty
  arrays. v1.3 rejects the ambiguous shared form instead of guessing credential
  ownership. Run `check` before restart; the configuration guide contains the
  complete migration rule.
- The public and internal wire formats are unchanged. Existing Xray clients
  continue to use one short ID belonging to their UUID. NXR/Handoff rolling
  interoperability is unchanged; only the rust-reality server JSON shape is
  intentionally incompatible with v1.2.

### Notes

- Validated on Linux x86_64. Autotune results are starting policies, not WAN or
  production load tests; retain the report, inspect the diff, and canary the
  result on the real traffic mix.

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
[1.2.0]: https://github.com/jacek4yang/rust-reality/releases/tag/v1.2.0
[1.3.0]: https://github.com/jacek4yang/rust-reality/releases/tag/v1.3.0
