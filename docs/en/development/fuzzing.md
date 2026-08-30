# Fuzzing

Fuzz coverage is an attack-surface requirement, not decoration: every externally
reachable parser, decoder, or reconstruction path must have a fuzz target or a
recorded justification for the gap. See the threat model
([English](../threat-model.md) | [简体中文](../../zh-CN/threat-model.md)) for the
trust boundaries that make this a security discipline, and the
[attack-surface map](../operations/fuzz-attack-surface.md) for the complete
surface-to-target inventory with recorded gaps.

## Targets

Targets live in `fuzz/fuzz_targets/`, one `fuzz_target!` binary each. The
manifest is validated by `cargo dev fuzz targets`; CI's Security workflow runs
sharded smoke passes over all targets on every PR. The current set covers:

- VLESS request decode, REALITY ClientHello record/message parse and extension
  walk, NXR header/decode round trips (`wire_parsers`, `nxr_round_trip`);
- Vision decoder single-shot and fragmented transitions
  (`vision_decoder`, `vision_transitions`);
- Handoff header, blob, authenticated transfer open, and round trip
  (`handoff_header`, `handoff_blob`, `handoff_open_transfer`, `handoff_round_trip`);
- cover ServerHello flight parsing (`cover_flight`);
- TLS 1.3 record open/seal and transcript-hash differential
  (`tls13_record`, `transcript_diff`);
- configuration JSON deserialization on the exact `load_config` decode path
  (`config_json`, `config_diagnostic`);
- REALITY authentication round trip and session-engine semantics
  (`reality_auth_round_trip`, `session_semantics`).

## Commands

```shell
cargo dev fuzz targets              # validate the manifest; print targets (optionally sharded)
cargo dev fuzz smoke                # deterministic short smoke pass over the targets
```

CI runs the smoke shards on every PR; longer local campaigns use cargo-fuzz
directly (`cargo fuzz run <target>`) against `fuzz/`.

## Rules

- A new parser, decoder, or reconstruction path MUST ship with a fuzz target in
  the same change (see [AGENTS.md](../../../AGENTS.md), fuzz engineering law).
- Fuzz-only hooks must stay outside production behavior: production code must
  not branch on fuzzing, and fuzz harnesses must not relax production invariants.
- Structured round-trip targets (encode → decode equality, bitflip-must-fail)
  are preferred where a legitimate producer exists; raw-input targets where the
  bytes come from the network.
