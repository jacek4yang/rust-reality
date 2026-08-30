# Fuzz attack-surface map

Maps every externally reachable parser and state machine to its fuzz coverage.
Fuzz coverage is an attack-surface requirement: a reachable parser without a
target is a gap that needs either a target or a recorded justification. The
[threat model](../threat-model.md) explains the trust boundaries; the commands
live in [development/fuzzing.md](../development/fuzzing.md).

## Covered

| Attack surface | Entry point(s) | Fuzz target |
| --- | --- | --- |
| VLESS request decode (owned + zero-copy ref) | `vless::decode_request`, `fuzz_decode_request_ref` | `wire_parsers` |
| REALITY ClientHello record + message parse | `ClientHello::parse_record`, `ClientHello::parse_message` | `wire_parsers` |
| ClientHello extension walk (SNI, ALPN, key share, supported versions) | inside `ClientHello::parse_message` | `wire_parsers` |
| Short-ID selection / owner index | inside REALITY auth, driven by parsed ClientHello | `wire_parsers` (partial: parse only; auth needs valid signatures) |
| NXR header length pre-parse | `nxr::request_len_from_header` | `wire_parsers` |
| NXR authenticated request decode | `nxr::decode_authenticated_request` | `wire_parsers` (raw) + `nxr_round_trip` (structured encode→decode + bitflip-must-fail) |
| Vision decoder, single-shot | `VisionDecoder::decode` | `vision_decoder` |
| Vision decoder transitions (fragmented headers/UUID/padding, End/Direct mode switches) | `VisionDecoder::decode` + `VisionEncoder` round trip | `vision_transitions` (structured encode→fragmented-decode equality + terminal-mode oracle) |
| Handoff message header pre-parse | `handoff::message_len_from_header` | `handoff_header` |
| Handoff continuation blob decode | `handoff::fuzz_decode_blob` | `handoff_blob` |
| Handoff authenticated transfer open | `handoff::open_transfer` | `handoff_open_transfer` |
| Handoff continuation reconstruction | `seal_transfer`→`open_transfer` field equality + corruption rejection | `handoff_round_trip` |
| Cover ServerHello flight parsing (nested TLS detector path) | `tls13::fuzz_cover_flight` (read_target_server_flight driver) | `cover_flight` |
| TLS 1.3 record open/seal | `Tls13RecordLayer::seal_into` / `open_in_place` | `tls13_record` (per-suite round trip + truncation/coalescing/bitflip rejection) |
| Handshake transcript hash | `TranscriptHasher` vs `HashAlgorithm::digest` | `transcript_diff` (differential: incremental == one-shot for all chunkings) |
| Config JSON deserialization + normalization + validation | `config::fuzz_decode_config` (exact `load_config` decode path) | `config_json` (structured generator via `arbitrary`, all values synthetic) |
| REALITY authentication round trip | REALITY auth handshake | `reality_auth_round_trip` |
| Session-engine semantics | `rr-session` state machines | `session_semantics` |
| Configuration diagnostics | diagnostic rendering on malformed config | `config_diagnostic` |

## Gaps (with justification)

| Attack surface | Why not fuzzed here |
| --- | --- |
| TLS 1.3 handshake state machine (`build_server_flight`, `EstablishedTls`) | Async I/O state machine over streams, not a byte parser; covered by deterministic unit/integration tests. A fuzz harness would need a scripted-async shim — high cost, low marginal signal. |
| ClientFinished read (`read_client_finished`) | Same async-I/O constraint; the underlying record open is covered by `tls13_record`. |
| Alerts / close_notify handling (`TlsApplicationIo`) | Alert bytes arrive inside opened records (covered); the async dispatch layer is unit-tested. |
| Cover-target read paths beyond ServerHello (`read_target_server_flight` full flight) | `cover_flight` drives the ServerHello-first flight reader; deeper flights need a scripted multi-flight harness — candidate for later. |
| DNS results (`hickory-resolver` answers) | Third-party parser (hickory) owns wire decode; our code consumes its typed output. Fuzzing hickory is out of scope for this repo. |
| GeoIP/GeoSite asset parsing (`assets.rs` protobuf-ish lists) | Asset bytes come from operator-configured URLs, not from unauthenticated network peers; attack surface is supply-chain, mitigated by size caps + validation, covered by unit tests. Documented as accepted residual gap — an `assets_dat` target is a cheap future add if the threat model changes. |
| Endpoint/CIDR + routing rule compilation (`server/routing.rs`) | Inputs are operator config strings, reached through `config_json` (routing section is generated); the compile functions themselves are deterministic and unit-tested. A dedicated `routing_compile` target is cheap but low value — recorded as residual. |
| Fallback inspection (`server/fallback.rs`, fallback prefix bytes) | Fallback decision consumes the already-fuzzed ClientHello parse; the async proxying layer is integration-tested. |
| Reload path | Reload re-enters `load_config` (covered by `config_json`) and asset reload (see GeoIP/GeoSite above); no distinct byte parser. |
| VLESS response header encode | Encode-only (no untrusted input); round-trip covered by unit tests. |

## Residual risk notes

- `handoff_open_transfer` and `handoff_blob` use fixed synthetic keys;
  `handoff_round_trip` adds key-varying structured coverage.
- The `config_json` generator is deliberately a *small custom generator*, not
  a full `arbitrary` derivation of `Config`: the model is large and most depth
  comes from grammar-shaped JSON plus a byte-level tail mutation.
- Checked-in seeds live in `fuzz/seeds/<target>/` (synthetic only — no real
  keys, UUIDs, or captures). `fuzz/corpus/` stays gitignored for locally grown
  corpora. Dictionaries: `fuzz/dictionaries/config_json.dict` (config grammar
  tokens) and `fuzz/dictionaries/wire.dict` (TLS/VLESS wire tokens).
