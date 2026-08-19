# v1.6.0 Fuzz Attack-Surface Map

Maps every externally reachable parser and state machine to its fuzz
coverage. "Existing" targets predate v1.6.0; "new" targets were added in this
effort. Fuzz coverage is an attack-surface requirement: a reachable parser
without a target is a gap that needs either a target or a justification.

## Covered

| Attack surface | Entry point(s) | Fuzz target |
| --- | --- | --- |
| VLESS request decode (owned + zero-copy ref) | `vless::decode_request`, `fuzz_decode_request_ref` | `wire_parsers` (existing) |
| REALITY ClientHello record + message parse | `ClientHello::parse_record`, `ClientHello::parse_message` | `wire_parsers` (existing) |
| ClientHello extension walk (SNI, ALPN, key share, supported versions) | inside `ClientHello::parse_message` | `wire_parsers` (existing) |
| Short-ID selection / owner index | inside REALITY auth, driven by parsed ClientHello | `wire_parsers` (partial: parse only; auth needs valid signatures) |
| NXR header length pre-parse | `nxr::request_len_from_header` | `wire_parsers` (existing) |
| NXR authenticated request decode | `nxr::decode_authenticated_request` | `wire_parsers` (existing, raw) + `nxr_round_trip` (new: structured encode→decode + bitflip-must-fail) |
| Vision decoder, single-shot | `VisionDecoder::decode` | `vision_decoder` (existing) |
| Vision decoder transitions (fragmented headers/UUID/padding, End/Direct mode switches) | `VisionDecoder::decode` + `VisionEncoder` round trip | `vision_transitions` (new: structured encode→fragmented-decode equality + terminal-mode oracle) |
| Handoff message header pre-parse | `handoff::message_len_from_header` | `handoff_header` (existing) |
| Handoff continuation blob decode | `handoff::fuzz_decode_blob` | `handoff_blob` (existing) |
| Handoff authenticated transfer open | `handoff::open_transfer` | `handoff_open_transfer` (existing, raw) |
| Handoff continuation reconstruction | `seal_transfer`→`open_transfer` field equality + corruption rejection | `handoff_round_trip` (new) |
| Cover ServerHello flight parsing (nested TLS detector path) | `tls13::fuzz_cover_flight` (read_target_server_flight driver) | `cover_flight` (existing) |
| TLS 1.3 record open/seal | `Tls13RecordLayer::seal_into` / `open_in_place` | `tls13_record` (new: per-suite round trip + truncation/coalescing/bitflip rejection) |
| Handshake transcript hash | `TranscriptHasher` vs `HashAlgorithm::digest` | `transcript_diff` (new differential: incremental == one-shot for all chunkings) |
| Config JSON deserialization + normalization + validation | `config::fuzz_decode_config` (exact `load_config` decode path) | `config_json` (new: structured generator via `arbitrary`, all values synthetic) |

## Gaps (with justification)

| Attack surface | Why not fuzzed here |
| --- | --- |
| REALITY authentication (X25519 + HMAC of ClientHello random/session id) | Requires valid cryptographic transcripts; the fuzzer cannot forge them, so coverage would be the reject path only. Reject-path structure is already exercised via `wire_parsers` + unit tests. Candidate for a structured harness that drives `auth` with test keys — deferred, needs a `fuzzing`-gated test-key constructor. |
| TLS 1.3 handshake state machine (`build_server_flight`, `EstablishedTls`) | Async I/O state machine over streams, not a byte parser; covered by deterministic unit/integration tests. A fuzz harness would need a scripted-async shim — high cost, low marginal signal. |
| ClientFinished read (`read_client_finished`) | Same async-I/O constraint; the underlying record open is covered by `tls13_record`. |
| Alerts / close_notify handling (`TlsApplicationIo`) | Alert bytes arrive inside opened records (covered); the async dispatch layer is unit-tested. |
| Cover-target read paths beyond ServerHello (`read_target_server_flight` full flight) | `cover_flight` drives the ServerHello-first flight reader; deeper flights need a scripted multi-flight harness — candidate for later. |
| DNS results (`hickory-resolver` answers) | Third-party parser (hickory) owns wire decode; our code consumes its typed output. Fuzzing hickory is out of scope for this repo. |
| GeoIP/GeoSite asset parsing (`assets.rs` protobuf-ish lists) | Asset bytes come from operator-configured URLs, not from unauthenticated network peers; attack surface is supply-chain, mitigated by size caps + validation, covered by unit tests. Documented as accepted residual gap — a `assets_dat` target is a cheap future add if threat model changes. |
| Endpoint/CIDR + routing rule compilation (`server/routing.rs`) | Inputs are operator config strings, reached through `config_json` (routing section is generated); the compile functions themselves are deterministic and unit-tested. A dedicated `routing_compile` target is cheap but low value — recorded as residual. |
| Fallback inspection (`server/fallback.rs`, fallback prefix bytes) | Fallback decision consumes the already-fuzzed ClientHello parse; the async proxying layer is integration-tested. |
| Reload path | Reload re-enters `load_config` (covered by `config_json`) and asset reload (see GeoIP/GeoSite above); no distinct byte parser. |
| VLESS response header encode | Encode-only (no untrusted input); round-trip covered by unit tests. |

## Residual risk notes

- `handoff_open_transfer` and `handoff_blob` use fixed synthetic keys; the
  new `handoff_round_trip` adds key-varying structured coverage.
- The `config_json` generator is deliberately a *small custom generator*,
  not a full `arbitrary` derivation of `Config`: the model is large and most
  depth comes from grammar-shaped JSON plus a byte-level tail mutation, not
  from replicating every field.

## Baseline (2026-08-19, e3251aa + this branch)

Environment: cargo-fuzz 0.13.2, nightly-x86_64, ASan+UBSan libFuzzer builds.
The LLVM source-coverage workflow works in this environment:
`cargo +nightly fuzz coverage <target>` produces
`fuzz/coverage/<target>/coverage.profdata`; the instrumented binary lands in
`target/<triple>/coverage/<triple>/release/<target>` and
`llvm-cov report <binary> -instr-profile=<profdata> --sources src` renders
per-file numbers. All fuzz invocations ran under
`flock -x /tmp/v151-bench.lock`.

### Smoke runs (15 s per target, `scripts/fuzz-smoke.sh`)

| Target | Executions | exec/s | Peak RSS | cov/ft | Crash |
| --- | --- | --- | --- | --- | --- |
| wire_parsers | 3,742,251 | 233,890 | 508 MB | 589/705 | none |
| vision_decoder | 5,647,387 | 352,961 | 531 MB | 81/224 | none |
| vision_transitions | 495,305 | 30,956 | 469 MB | 423/1290 | none |
| handoff_header | 11,762,357 | 735,147 | 484 MB | 33/34 | none |
| handoff_blob | 3,812,910 | 238,306 | 499 MB | 303/480 | none |
| handoff_open_transfer | 2,230,607 | 139,412 | 400 MB | 186/187 | none |
| handoff_round_trip | 10,220 | 638 | 112 MB | 1722/2836 | none |
| cover_flight | 339,511 | 21,219 | 416 MB | 669/1066 | none |
| tls13_record | 234,558 | 14,659 | 476 MB | 1141/4595 | none |
| transcript_diff | 473,122 | 29,570 | 488 MB | 304/1008 | none |
| config_json | 88,998 | 5,562 | 469 MB | 2456/6553 | none |
| nxr_round_trip | 812,762 | 50,797 | 423 MB | 379/501 | none |

`handoff_round_trip` is deliberately slow: every input performs a real
X25519 ephemeral DH, ChaCha20-Poly1305 seal+open, and replay-cache setup.

### LLVM line coverage (corpora grown 30 s per target)

Whole-crate `src/` line coverage plus the key attacked files:

| Target | Crate lines | Key file coverage (lines) |
| --- | --- | --- |
| wire_parsers | 2.13% | vless/decode.rs 75.1%, client_hello.rs 40.7%, nxr.rs 32.6% |
| vision_decoder | 0.71% | vless/vision.rs 39.1% |
| vision_transitions | 1.49% | vless/vision.rs 71.9% |
| handoff_header | 0.21% | handoff.rs 5.9% |
| handoff_blob | 0.81% | handoff.rs 18.7% |
| handoff_open_transfer | 0.43% | handoff.rs 12.3% |
| handoff_round_trip | 3.02% | handoff.rs 79.6% |
| cover_flight | 4.07% | tls13/target_read.rs 84.6% |
| tls13_record | 1.41% | tls13/record.rs 51.8% |
| transcript_diff | 0.23% | tls13/keys.rs 11.5% (hash paths only) |
| config_json | 2.81% | config/validate.rs 26.6%, config/model.rs 47.0% |
| nxr_round_trip | 0.86% | nxr.rs 84.0% |

Crate-wide percentages are low by construction: most of `src/` is async
server/runtime code no parser target can reach. The key-file column is the
metric that matters per target.

### New targets added (6)

- `config_json` — config deserialization + normalization + validation via
  the exact `load_config` decode path (`config::fuzz_decode_config`), driven
  by a small custom `arbitrary` generator; all values synthetic.
- `vision_transitions` — encoder→decoder round trip under fuzz-driven
  fragmentation with payload and terminal-mode oracles, plus raw chunked
  decode.
- `tls13_record` — seal→open round trip per cipher suite; truncation,
  coalescing, and single-bit corruption must always be rejected.
- `handoff_round_trip` — structured `ContinuationState` seal→open field
  equality; single-bit corruption must always be rejected.
- `nxr_round_trip` — structured authenticated encode→decode equality;
  single-bit corruption must always be rejected.
- `transcript_diff` — differential: incremental transcript hash equals
  one-shot digest for arbitrary chunkings.

### Seed corpora and dictionaries

Checked-in seeds live in `fuzz/seeds/<target>/` (synthetic only — no real
keys, UUIDs, or captures). `fuzz/corpus/` stays gitignored for locally grown
corpora. Dictionaries: `fuzz/dictionaries/config_json.dict` (config grammar
tokens) and `fuzz/dictionaries/wire.dict` (TLS/VLESS wire tokens).
`scripts/fuzz-smoke.sh` runs every target for a bounded budget
(≤30 s, default 20 s) against seeds plus a scratch corpus and is safe to
wire into CI later.
