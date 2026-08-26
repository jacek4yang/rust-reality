# Changelog

All notable user-facing changes to this project are documented in this file.

## [1.8.0] - 2026-08-26

No configuration migration is required from v1.7.0, and no wire-format,
client-visible, or deployment-identity change is included. Existing stock Xray
client links continue to work unchanged. This release is an internal architecture
release: it establishes compiler- and CI-enforced layer boundaries so that future
performance, fuzzing, and transport work has something solid to stand on.

### Added

- Added the internal, dependency-free `no_std` Session Engine crate
  `rr-session`, which owns synchronous data-only session decisions: byte-exact
  authenticated-write progress and its irreversible retry boundary, the Vision
  direction lifecycle and its permitted transition table, one-shot raw-relay
  ownership grants, and the bounded raw-relay rendezvous policy.
- Added semantic event-sequence fuzzing (`session_semantics`) alongside the
  existing byte-level wire and parser fuzzing, which is unchanged. It drives the
  Session Engine with arbitrary event sequences and no socket, clock, or runtime,
  and asserts that a transport grant is issued at most once per direction, that
  the two Vision directions never split a bilateral pair, that per-direction
  state growth stays bounded, that a terminal direction stays terminal, and that
  an authenticated transfer never authorises an attempt after its irreversible
  boundary.
- Added CI-enforced layering gates. `tests/session_engine_boundary.rs` fails the
  build if the Session Engine names a runtime, socket, descriptor, clock,
  allocator, synchronisation primitive, randomness source, or logger, if it gains
  a dependency, or if it stops being `no_std`; it also fails if the transport
  layer can name the Session Engine at all, which is the cheapest strong form of
  the rule that the raw relay imposes no per-chunk semantic work.
  `tests/transport_capability_boundary.rs` fails the build if protocol semantics
  can name or select a transport backend.
- Added `docs/memory-audit-v1.8.md`: an ownership map for eleven tracked items, a
  copy ledger with every hot-path copy classified, an allocation ledger, and an
  async future-size table, together with an explicit statement of what is not
  measured.

### Changed

- The irreversible authenticated-write boundary is now expressed by type rather
  than by convention. A completed write yields a one-shot, non-`Clone`
  `CommittedWrite` witness and a failed write yields `RetryableProgress`, which
  cannot describe a committed message. Four runtime `unreachable!` guards were
  deleted from the Handoff and NXR transfer paths because the states they
  excluded are no longer representable.
- The raw-relay rendezvous policy — how many cooperative scheduling points a
  Vision direction may spend waiting for its peer, and when to stop observing —
  moved into the Session Engine as `PairRendezvous`. The Tokio adapter keeps only
  the scheduling operation it is asked to perform. Behaviour is unchanged: at most
  three peer observations and at most two scheduling points, then the same
  mutex-serialised commit.
- Each raw transport capability now takes the policy type it can honour. The
  directional relay takes `DirectionalRelayContext`, which has no reset-as-EOF
  field because its backends do not implement one, so that option is no longer
  accepted and silently ignored.

### Fixed

- `WriteProgress::from_written` classified a fully delivered zero-length message
  as retryable, disagreeing with the counted writer, which reports completion for
  an empty message without issuing a write. Completion is now tested first.
  Production authenticated messages always carry a mandatory header and are never
  empty, so no reachable outcome changes; this removes a latent hazard that
  pointed toward retrying an already-delivered message.

### Performance

- Performance is neutral against the immutable v1.7.0 release asset. Four
  independent formal gates, each judged by `evaluate-release-performance.py` with
  exact paired sign-flip permutation tests and global Holm correction, reported
  `PASS` with zero regressions: the Session Engine extraction (32 metrics at
  concurrency 1 plus 24 metrics covering concurrency 1, 8 and 32), the write
  boundary change (32), the runtime adapter (32), and the transport capability
  boundary (32).
- One measured memory finding is documented rather than fixed. Each spawned
  connection task carries the connection future twice — 21 224 bytes instead of
  10 768 — because rustc keeps a captured upvar slot alive alongside the awaitee
  slot. The obvious fix was implemented, removed the duplication exactly, and was
  then rejected because two independent formal rounds both failed the protected
  framed-download cell. See `notes/v1.8.0/rejected-connection-future-factory.md`
  for the evidence and the revisit conditions.

## [1.7.0] - 2026-08-26

No configuration migration is required from v1.6.1. Handoff, NXR, and SOCKS5
TCP warming is enabled by default; set `warmTcp: false` on an individual
outbound whose peer enforces an incompatible idle or connection policy.

### Added

- Authenticated REALITY handshakes can consume a generation-isolated adaptive
  pool of TCP-established cover sockets, removing the cover TCP handshake RTT
  on a warm hit. No TLS bytes are sent before checkout; failures and replayed
  or malformed ClientHellos retain the original real-cover byte-exact path.
- Added bounded `realitySettings.coverOptimization` switches and the shared
  `advanced.limits.warmConnections` policy, with strict FD accounting,
  pressure-first reclamation, refill backoff, and reload isolation.
- Added bounded ephemeral REALITY cover profiles. Four controlled observations
  must agree before an exact normalized ClientHello class can locally generate
  a fresh authenticated flight. Unknown, stale, unstable, or unrepresentable
  classes use live cover; unauthenticated and replayed traffic never consults
  profiles.
- Handoff, NXR, and SOCKS5 fixed-peer outbounds now reuse the existing
  generation-isolated adaptive TCP pool. A checked-out socket is single-use,
  carries no protocol authority, and a miss immediately follows the cold path.
- Handoff and NXR LANDING listeners now separate bounded zero-byte pre-auth
  idle from the existing short authentication deadline. The first protocol
  byte switches phases; a distinct `maxPreAuthIdleConnections` admission cap,
  pressure reclamation, and reload isolation protect intentional idle state.
- Added byte-counted Handoff/NXR write boundaries. A bounded pre-complete retry
  always constructs fresh authentication state; a complete transfer/request
  is never retried because LANDING may already have external side effects.
- Normal zero-byte Handoff/NXR warm-socket and old-generation retirement is
  silent at ordinary log levels instead of being mislabeled as authentication
  rejection/resource pressure. Any connection that sent byte one still uses
  the short authentication deadline and ordinary rejection reporting; actual
  pressure reclamation remains visible.
- A stalled stale Handoff, NXR, or SOCKS5 warm socket can no longer consume the
  absolute deadline of its bounded cold fallback. Each permitted transport
  attempt receives the normal per-attempt timeout; retry counts and
  irreversible authenticated-write boundaries are unchanged.

### Security

- Warm sockets are prepaid transport state only. Handoff and NXR retain fresh
  per-session authentication and replay protection, SOCKS5 still negotiates
  and authenticates after checkout, and unauthenticated REALITY traffic stays
  on the real-cover path.
- LANDING pre-auth idle sockets are finite, perform no destination DNS/connect
  or protocol crypto, yield before authenticated sessions under pressure, and
  cannot cross immutable configuration generations.

### Performance

- On a controlled 50 ms cover RTT, authenticated warm-cover setup measured
  1.93× the pre-feature c1 rate and 1.84× at c8 while remaining inside the
  protected CPU-per-connection margin. Unauthenticated and replayed traffic
  continues to use the real cover path.
- On a warm transport checkout, the LINE-to-LANDING/upstream TCP handshake is
  removed from the per-flow critical path. The optimized feature-head build
  passed all nine controlled 50/100/200 ms Handoff/NXR/SOCKS5 mechanism cells:
  median cold-minus-warm setup was 0.999–1.002 measured RTT. Exact-final
  publication evidence remains a release gate and is not inferred from unit
  tests.

### Testing

- Added deterministic Handoff/NXR pre-auth, slowloris, replay, idle-age,
  pressure, reload, retry-boundary, FD-lifetime, stale-checkout, and cold
  fallback coverage, plus SOCKS5 authentication/CONNECT and credential
  isolation coverage.
- The deployment evaluator retains paired production-build cold/warm samples,
  measured netem RTT, fixed-cardinality pool counters, and a fail-closed
  one-handshake-removal verdict for Handoff, NXR, and SOCKS5.
- Optional long-horizon soak evidence records aggregate PSS and per-process
  RSS, avoiding repeated accounting of shared file-backed mappings while
  retaining process-local growth detection. Publication instead requires the
  exact-candidate high-density dual-VPS canary; long-horizon soak remains
  scheduled, non-blocking stability monitoring.

## [1.6.1] - 2026-08-23

No configuration migration is required from v1.6.0.

### Added

- Official `linux-x86_64-musl` release archive: baseline x86-64,
  fully static, built and executed on native x86_64 hardware, and intended
  for Alpine, other musl distributions, and minimal containers. Release
  aggregation remains all-or-nothing, so a missing musl tier blocks publish.

### Security

- CI now discovers and runs every target declared by `fuzz/Cargo.toml` in
  bounded shards, with scheduled deeper coverage and failure artifacts.
- Structured synthetic REALITY authentication fuzzing now covers successful
  authentication, owner/short-ID mismatch, timestamp and session-ID bounds,
  transcript mutations, replay duplicates, and rollback on failed exits.

### Testing

- A deterministic 17-case active-probe regression gate now protects valid and
  rejected authentication, ClientHello fragmentation/replay, TLS shape,
  fallback prefix ownership, cover failures, close behavior, and pressure
  rejection without making network-dependent packetization claims.
- The Linux x86_64 performance contract now records protected workload cells,
  immutable binary and host identity, allocation baselines, hot-structure size
  guardrails, and identity-bound `perf stat`/`perf c2c` evidence.

### Documentation

- English and Chinese current-release performance tables are validated against
  one machine-readable source, preventing version, comparator, row, heading,
  and headline-value drift.

## [1.6.0] - 2026-08-20

rust-reality is forward-only: there is no backward compatibility between
releases. v1.5 configurations are rejected with strict unknown-field errors;
apply the mapping below by hand, then run
`rust-reality check --config config.json`. The complete operator migration
procedure ships in the v1.6.0 release notes.

### Breaking changes

- The v1.5 top-level `policy` object is removed. It no longer parses; move
  every value to the identically named `advanced.limits.*` fields. The
  `configuration_deprecation` log event is removed with it.
- `runtime.resourceMode` is removed. Use `runtime.profile`:
  `standard` → `shared`, `dedicated` → `dedicated`; an unset field maps to
  the `auto` profile, which resolves to `dedicated` only inside a fully
  bounded cgroup v2 — pin `runtime.profile: "shared"` to keep the
  unconditional v1.5 `standard` posture.
- `config migrate` is removed. Migration is a manual edit against the table
  below plus `check`; the binary carries no migration engine.
- `config autotune --dedicated` now writes `runtime.profile: "dedicated"`
  instead of `runtime.resourceMode: "dedicated"`. The measurement-report
  schema is bumped to `schemaVersion: 2` and its `resourceMode` field is
  renamed to `profile`.
- Library API: `config::load_config_with_report` and
  `config::ConfigLoadReport` are replaced by the single
  `config::load_config`; `Config::normalize`, the `Config.policy` field,
  `RuntimeConfig::resource_mode`, and the whole `config::migrate` module
  are removed.
- The splice relay pipe capacity rises from 256 KiB to 512 KiB (measured:
  halves the splice syscall rate and ~5% server CPU per GiB on sustained
  streams). The worst-case relay-memory accounting doubles per pipe, so the
  built-in `advanced.limits.relay.maxPooledPipes` default drops from 512 to
  256, keeping the default accounted pool total at 256 MiB. Configurations
  that pin `maxPooledPipes` or set `pipePool: false` may need a higher
  `maxRelayMemoryBytes` under the doubled per-pipe accounting; run
  `rust-reality check --config config.json`.

### v1.5 → v1.6 configuration mapping

| v1.5 | v1.6 |
| --- | --- |
| `policy.resourceGovernor.*` | `advanced.limits.resourceGovernor.*` (field names identical) |
| `policy.directBarrier.*` | `advanced.limits.directBarrier.*` |
| `policy.relay.*` | `advanced.limits.relay.*` |
| `runtime.resourceMode: "standard"` | `runtime.profile: "shared"` |
| `runtime.resourceMode: "dedicated"` | `runtime.profile: "dedicated"` |
| no `runtime.resourceMode` | nothing; the `auto` profile applies (pin `"shared"` to keep the unconditional standard posture) |
| any pinned limit | add `runtime.tuning.mode: "fixed"` to keep the exact v1.5 numbers; the `startup` default derives unpinned fields from the machine |

Then run `rust-reality check --config config.json`.

### Added

- Startup policy derivation (`runtime.tuning.mode: startup`, the default):
  the serve path derives every numeric policy field that `advanced.limits`
  does not pin once at startup from the detected machine, using the same
  formulas as `config autotune`. Derivation is fully passive — no benchmark,
  storage, or loopback probe runs at startup, so readiness is never delayed —
  and validated exactly like autotune output before any listener binds. A
  field whose `advanced.limits` value differs from the built-in default is
  operator-pinned and always wins; all timeouts and `replayRetentionMs` are
  never derived. `runtime.tuning.objective` (`latency`/`balanced`/
  `throughput`) scales selected derived outputs after the balanced
  derivation, with the hard caps and safety floors documented in
  `docs/configuration.md#startup-policy-derivation`. `fixed` mode keeps
  v1.5 behavior byte-for-byte.
- Adaptive tuning mode (`runtime.tuning.mode: adaptive`): a controller
  adjusts the soft admission ceilings (the six `resourceGovernor` pools and
  `directBarrier.maxConcurrent`) and the GCRA dial rate
  (`directBarrier.maxPerSecond`) at runtime, within startup-derived hard
  bounds above and the v1.5 built-in defaults below. Decisions are
  deterministic and explainable: a 5-second tick, scale-up after 3
  consecutive ticks at ≥85% utilization, scale-down after 6 consecutive
  ticks at ≤40%, a 30-second dwell between successive changes to the same
  knob, ±25% steps quantized to 64 (counts) or 16 (rate), and a one-tick
  clamp to the floor under critical resource pressure. Held permits are
  never revoked; timeouts, replay retention, relay pools, the descriptor
  budget, and listener topology are never touched. `fixed` and `startup`
  behavior is byte-identical to before — no controller exists outside
  `adaptive` mode.
- `runtime.statusFile`: in `adaptive` mode the controller atomically
  rewrites this JSON snapshot at startup and on every ceiling or pressure
  transition (pressure state, every knob's value/floor/ceiling/held permits,
  and the last transition with reason and timestamp). Cold setting.
- `rust-reality runtime report --status-file <PATH> [--json]`: prints the
  last adaptive-controller snapshot a running instance published; reads the
  file only, never contacts the process.
- New log events: `adaptive_ceiling_changed` (info, exactly one per knob
  transition — nothing is logged per tick) and
  `adaptive_status_write_failed` (warn, bounded per failed publish).
- Dedicated bootstrap topology: `serve` now detects the machine and resolves
  the profile before building the Tokio runtime. In the `dedicated` posture
  the pools are sized from the cgroup-aware CPU view
  (`worker_threads = effective_cpus().clamp(1, 64)`,
  `max_blocking_threads = (32 + 8 × cpus).clamp(64, 512)`); the
  shared/standard posture keeps the tokio defaults. A `runtime_plan_report`
  log event records the resolved mode, tuning, and pool sizes at startup.
- `rust-reality runtime explain --config <PATH> [--json]`: offline report of
  the detected machine, resolved profile, bootstrap topology, and the
  effective value, source (`derived`/`override`/`default`), multiplier, and
  bounds of every policy field, plus advisory kernel-tuning suggestions.
- v1.6 configuration model: `runtime.profile` (`auto`/`shared`/`dedicated`),
  `runtime.tuning.mode` (`fixed`/`startup`/`adaptive`),
  `runtime.tuning.objective` (`latency`/`balanced`/`throughput`), and the
  `advanced.limits` expert escape hatch holding the numeric resource/relay
  policy previously living under `policy`.
- Compiler-grade configuration diagnostics: every load failure (`check`,
  `serve` startup, and hot reload) renders a rustc-style block —
  `file:line:column`, the offending source line with a caret span, the
  logical configuration path, expected versus actual, and a remediation hint
  — instead of a bare serde message. Strong typos suggest the intended field
  (`profiel` → did you mean `profile`?); the removed `policy` and
  `runtime.resourceMode` fields get targeted errors naming their v1.6
  replacements; secret values (private keys, PSKs, UUIDs, short IDs,
  passwords) are redacted from excerpts. Reload rejections keep the closed
  `configuration_rejected` log event and additionally write the full
  diagnostic to stderr for journal capture. Rendering is plain text with no
  ANSI color and stays off the network hot path.

### Changed

- Hot reload now compares the tuning mode strictly: `fixed`, `startup`, and
  `adaptive` produce different effective policies, so any drift between them
  is rejected and requires a restart. Reloads under a derived mode
  re-derive the candidate against the current machine view and reject when
  the derived numbers would differ, because the admission pools were sized
  at process start.
- `config autotune` now writes the derived policy to `advanced.limits`
  instead of the v1.5 `policy` object.
- Validation errors for numeric policy fields now report paths under
  `advanced.limits.*` (previously `policy.*`).

## [1.5.1] - 2026-08-19

### Added

- Optional `dns.cache.systemReuseMs` recent-completion reuse window for the
  system resolver (`["system"]` mode): positive getaddrinfo answers, which
  carry no TTL, may be reused for a short bounded window (`0..=60000` ms,
  default `0` = off). This is not authoritative TTL caching: an upstream
  change becomes visible only when the window expires, negative answers are
  never cached, and there is no stale-while-revalidate. Ignored with real
  DNS servers, where upstream TTLs govern.
- `log.output: "none"` disables logging entirely: no file is created, nothing
  is written to stderr or journald, and every event is dropped before
  timestamping, JSON encoding, or any sink I/O. `log.file` remains forbidden
  unless `log.output` is `file`.

### Changed

- Per-connection debug events (`connection_accepted`, `connection_completed`,
  `connection_closed`) are now constructed only when debug output can actually
  reach the configured sink. With `log.level` at `info` or higher, or with
  `log.output: "none"`, the per-connection log path does no work at all;
  warn-level rejection and admission events stay eager as operator signal.
- The REALITY server flight now hashes the TLS 1.3 handshake transcript
  incrementally instead of re-hashing the whole growing transcript four
  times. Transcript values and wire output are unchanged; measured on the
  release gate host this removes the standalone transcript-digest cost from
  the handshake profile (SHA-256 compress self-time 22.0% → 13.8% of setup
  CPU) and reduces server CPU per connection by ≈6.7% (formal setup ABBA
  median ratio 0.933, bootstrap95 [0.930, 0.934]).
- The DNS cache contention design was re-measured before changing it: with
  1–1024 concurrent same-name and distinct-name lookups the single bounded
  mutex is not the bottleneck (same-name ≈ distinct-name wall time; CPU
  scales with cores, not with spinning), so the lock is deliberately kept
  and sharding was rejected on evidence.

### Fixed

- The shared DNS cache identity now includes the query class. Previously a
  static configured peer and a dynamic per-session destination with the same
  name shared one cache slot, so a static lookup could be served by a
  dynamic entry (or vice versa) and the static TTL could extend a dynamic
  answer. Static and dynamic entries for one name now have independent
  lifetimes, both counting against `dns.cache.maxEntries`; static negative
  results remain uncached.

### Release-gate evidence

- Candidate `a6d6363` vs the published v1.5.0 release binary (`eda773b`),
  same-host i3-8100, all runs serialized under the host-exclusive lock:
  the formal evaluator passed all 40 protected metrics with zero
  regressions; formal setup ABBA (576 samples) registered statistically
  significant improvements in setup:c1:throughput and setup:server-cpu
  (the transcript-hash change); the formal concurrency-1 throughput matrix
  (867 samples, 0 invalid) reported no significant protected-path change;
  10-minute soaks showed flat descriptors, threads, and RSS with zero
  transfer failures. Exploratory concurrency-32 matrix and CPU/GiB legs
  showed no meaningful regression. Xray reference pin: v26.7.28
  (go1.26.0), unchanged from v1.5.0.

### Known limitations

- External IPv6 ingress from a second host was not tested (no external
  source was available); host-global and real Internet egress were
  validated instead (v1.5.0 evidence, unchanged behavior).
- Upstream DNS (`dns.servers`) is plain UDP/TCP without DNSSEC validation;
  point it at a trusted resolver. Spoofed answers are bounded by clamped
  TTLs.
- Routing-strategy resolution (IpIfNonMatch/IpOnDemand) intentionally uses
  the system resolver so rule-checked addresses are exactly the dialed
  addresses; the configured upstream applies to the connector paths.
- The x86_64-v3 asset shows no measured advantage over the generic asset on
  the validation host (crypto is runtime-dispatched regardless); it is an
  opt-in tier, and aarch64 performance was not natively measurable.

## [1.5.0] - 2026-08-19

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
- The authenticated REALITY cover-flight plan now models optional
  middlebox-compatibility CCS, four positional encrypted handshake records,
  and an optional fifth post-Finished record. When that fifth record is
  present, rust-reality emits an empty TLS 1.3 ApplicationData record as a
  bounded cover-shaped fake NST; it carries no ticket or resumption state.
- A shared process-wide DNS resolver fronts every connector-side lookup
  (routing `domainStrategy`, direct dials, REALITY cover targets, and
  SOCKS5/NXR/Handoff server names). `dns.servers` selects exactly `["system"]`
  (getaddrinfo; singleflight coalescing and admission governance only — no
  dynamic caching, because the system resolver exposes no TTLs) or a list of
  upstream DNS servers (IP literal, `ip:port`, `[v6]:port`, or a hostname
  bootstrapped through the system resolver; real TTLs over UDP with TCP
  fallback). The new `dns.cache` bounds the shared cache
  (`maxEntries`/`minTtlSeconds`/`maxTtlSeconds`/`negativeTtlSeconds`/
  `staticTtlSeconds`); configured static peers are cached in every mode. All
  upstream flights hold `DnsLookup` admission permits. The resolver is
  installed once at startup; changing `dns.servers`, `dns.timeoutMs`, or
  `dns.cache` requires a restart.
- Official Linux releases now ship three per-tier archives:
  `rust-reality-v1.5.0-linux-x86_64-generic.tar.gz` (baseline x86-64, the
  recommended asset), `rust-reality-v1.5.0-linux-x86_64-v3.tar.gz` (opt-in;
  requires the x86-64-v3 microarchitecture level), and
  `rust-reality-v1.5.0-linux-aarch64-generic.tar.gz` (ARMv8.0 baseline with
  neon, built and smoke-tested natively on ARM runners). An aarch64-crypto
  tier was evaluated and deliberately dropped: ring already dispatches AES/SHA
  hardware support via HWCAP at runtime, so the tier's advantage was
  unverifiable. `release-manifest.json` schema v3 records per-tier compiler,
  cargo features, target CPU/features, native-measurement status, and minimum
  CPU requirements; `SHA256SUMS` covers all archives and the manifest. The
  pipeline builds, smokes, and aggregates every tier before publishing — a
  failed tier fails the release instead of publishing a partial matrix.
- The benchmark and forensic scripts accept explicit run IDs, immutable binary
  paths and hashes, unique output/temp directories, and isolated perf/IDA
  inputs. Authoritative comparisons use balanced ABBA blocks and fail closed
  on missing samples or integrity failures.

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
- If an asset server begins an HTTP 200 response but its body later times out
  or fails in transport, rust-reality now falls back to the existing bounded,
  parse-validated cache. Oversized responses remain a fail-closed error.
- Cover flight inspection is bounded to a 66,642-byte retained prefix. Reads
  are incremental and deadline-bound; optional fifth-record detection uses
  buffered bytes first and then at most one nonblocking probe. Every inspected
  byte remains available to the byte-exact fallback path.
- A fake NST consumes server application record sequence 0, so the established
  server record layer starts at sequence 1 for that shape and at sequence 0
  otherwise. Client application sequence ownership remains unchanged.
- Handoff keeps `HND1`, protocol version 1, continuation-state version 1, and
  the existing wire encoding. A v1.5 LANDING accepts server sequence 0 or 1
  and rejects sequence 2 or greater before record-layer restoration, avoiding
  AEAD nonce reuse.
- Rule lists of 64 or more entries now build adaptive matcher indices
  (about 53 bytes per rule) instead of evaluating every matcher linearly.
  First-match semantics are unchanged and small rule sets keep the linear
  path; measured P95 decision latency fell 31–57% at 1,000 rules and 31–55%
  at 10,000 rules. See docs/performance.md.

### Fixed

- Sessions against a cover that negotiates no ALPN now establish correctly:
  the generated EncryptedExtensions ALPN is shaped to the cover's observed
  record slot. Previously such sessions silently fell back to the cover.
  `probe-dest` remains bounded to the ServerHello. Covers that do offer ALPN
  should still negotiate it; ALPN-less covers are legitimately supported.

### Migration from 1.4

v1.5.0 intentionally rejects the v1.4 listener shape; run `check` before
restart. The mapping is mechanical:

| v1.4 | v1.5.0 |
| --- | --- |
| `"listen": "0.0.0.0"` (or any concrete IPv4) | `"listen": { "mode": "ipv4Only", "ipv4": "<address>" }` for identical single-family behavior, or `{ "mode": "auto" }` to serve both families |
| `"listen": "::"` (or any concrete IPv6) | `"listen": { "mode": "ipv6Only", "ipv6": "<address>" }`, or `{ "mode": "auto" }` |
| `network.addressFamily` (unreleased v1.5 development snapshots only) | `network.dial.mode` (`auto`, `preferIpv4`, `preferIpv6`, `ipv4Only`, `ipv6Only`) |

Unspecified fields in the `listen` object default to the wildcard addresses
(`0.0.0.0` / `::`), so only the address a mode uses needs to be named.
`network.dial` is optional and defaults to `auto`; it controls only locally
resolved outbound dials and never the listeners. There is no
backward-compatible fallback: obsolete fields and scalar listeners fail
strict decoding as unknown or invalid values.

### Compatibility and operations

- Xray 26.7.28 end-to-end gates passed with the Microsoft, Google, and Fastly
  public covers. A local OpenSSL 3.5.6 cover that omits compatibility CCS also
  passed. Each gate verified an exact 1 MiB SHA-256 payload and ML-DSA-65 key
  compatibility; these are interoperability results, not throughput claims.
- Real global IPv6 and real IPv6 Internet egress were validated end to end
  (`scripts/validate-ipv6-e2e.sh`): 29 pass, 0 fail, 1 skip — the skip is the
  external-ingress case, for which no outside IPv6 source was available on the
  validation host. Coverage includes all listener modes, Xray client sessions
  over every address-family combination (mixed A/AAAA, DNS-selected family,
  IPv6 literals, bracketed covers), byte-exact 64 MiB upload, download, and
  full-duplex transfers, 100 ms/1% netem impairment, route loss and recovery,
  and fast family-refusal fallback (0.086 s).
- Rolling Handoff upgrades are LANDING-first, then LINE: a v1.4 LINE can use a
  v1.5 LANDING. Rollback is LINE-first, followed by admission stop and active
  session drain before LANDING downgrade. A v1.5 LINE that exports sequence 1
  is not compatible with a v1.4 LANDING.

### Performance evidence

- Same-host release validation of the dual-stack change found Direct relay
  throughput changes between -1.46% and +0.56% across upload, download, and
  full-duplex at concurrency 1 and 32. Setup CPU/connection was +0.55%;
  numeric IPv4 setup was unchanged, numeric IPv6 was +1.12%, and immediate
  IPv6-refusal fallback was 30.9% faster than the original pull-request head.
- Same-host warn-level setup ABBA against v1.4 measured candidate/baseline
  medians of -0.38% at c1 (95% bootstrap CI -0.465% to +0.170%), +0.26% at c8
  (-3.368% to +2.497%), and +0.53% at c32 (-1.257% to +1.557%). Every interval
  crosses no difference; no setup-throughput win or regression is claimed.
- Normalized setup counters changed by -0.768% task-clock, -0.190%
  instructions, and +1.042% context switches (about +0.058 per connection).
  A separate current trace measured 4.0013 fewer `recvfrom` calls per
  connection in the candidate. Instrumented and uninstrumented timing are not
  compared.
- Two balanced six-path matrix rounds covering bidirectional, Direct
  download/upload, fallback, and framed download/upload each retained 219
  samples with zero invalid samples. Every throughput and latency 95%
  block-bootstrap interval crossed no difference. Direct-upload's median ratio
  reversed from 0.9511 to 1.1390 between rounds, confirming order/host noise;
  the evidence establishes no statistically significant protected-path
  change, not a performance victory.

- Final release-gate comparison (candidate `47a7151` vs the post-integration
  baseline `572c077`, same-host i3-8100, all runs serialized): formal setup
  ABBA across concurrency 1/8/32/128 (576 samples) showed connection-rate
  ratios 0.991-1.005 with all Holm-adjusted p=1.0; the formal concurrency-1
  throughput matrix (867 samples) reported no significant change in any cell
  (ratios 0.967-1.026), and concurrency-32 exploratory ABBA bulk ratios were
  0.973-1.048; CPU/GiB ratios were 0.992-1.065 with every interval crossing
  1.0; 10-minute soaks showed flat descriptors, threads, and RSS. The
  evaluator passed all 40 protected metrics. The two commits added after the
  gated candidate (reload-time DNS drift rejection; CI aggregate allowlist)
  do not touch the measured paths.

### Known limitations

- External IPv6 ingress from a second host was not tested (no external source
  was available); host-global and real Internet egress were validated instead.
- Static and dynamic DNS answers share one cache namespace, so a static-peer
  entry can briefly extend the effective staleness of a same-named dynamic
  answer and vice versa; negative answers are never cached for static peers.
- If a DNS flight leader were to die without publishing (no such path exists
  today), its name would wait out the absolute timeout before recovering.
- Upstream DNS (`dns.servers`) is plain UDP/TCP without DNSSEC validation;
  point it at a trusted resolver. Spoofed answers are bounded by clamped TTLs.
- Routing-strategy resolution (IpIfNonMatch/IpOnDemand) intentionally uses
  the system resolver so rule-checked addresses are exactly the dialed
  addresses; the configured upstream applies to the connector paths.
- The x86_64-v3 asset shows no measured advantage over the generic asset on
  the validation host (crypto is runtime-dispatched by ring regardless); it
  is an opt-in tier, and aarch64 performance was not natively measurable.

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
