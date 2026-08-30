# Testing

What to run, in what order, and what each layer proves. The escalation ladder
lives in [development-workflow.md](development-workflow.md); this page explains
the validation layers themselves.

## Production test layers

- **Unit/module tests** live beside the code they validate
  (`src/**`, `crates/**`). They encode the protocol, state-machine, and
  allocation invariants — including the allocation gates in
  `src/protocol/reality/tls13/allocation_gate.rs` that assert zero steady-state
  allocations per record, and the state-transition tables in `crates/rr-session`.
- **Integration tests** live in `tests/` (production) and validate cross-module
  behavior: configuration loading, server lifecycle, layout baselines
  (`tests/layout_baseline.rs` pins hot-state struct sizes).
- **No-default-features tests** (`cargo test --workspace --no-default-features
  --locked`) validate the RustCrypto fallback build: identical wire behavior
  with a different AEAD provider.
- **Benchmarks** (`benches/`) compile under `cargo dev check --all` and prove
  hot-path properties; see [benchmarks.md](../benchmarks.md).
- **Fuzz targets** (`fuzz/fuzz_targets/`) cover every externally reachable
  parser/decoder/reconstruction path; see [fuzzing.md](fuzzing.md).
- **Sanitizers** run in CI (Security workflow): Address/LeakSanitizer and
  replay/warm-transport race sanitizer profiles.

## Focused runs

```shell
cargo test -p rust-reality <test_name_substring> --locked
cargo nextest run -p rust-reality --locked          # faster, CI-equivalent profile
cargo test --workspace --locked                     # full default suite
```

## Tooling tests

The `rr-dev` tooling workspace has its own suite and gate:

```shell
cargo test  --manifest-path tools/rr-dev/Cargo.toml -p rr-dev --locked
cargo clippy --manifest-path tools/rr-dev/Cargo.toml --all-targets --all-features --locked -- -D warnings
```

## What must never be weakened

Do not weaken or delete an existing gate, assertion, or sanitizer profile to
make a change easier. If a gate is genuinely wrong, fix the gate in a reviewed
change with a documented reason; silent gate-weakening is treated as a process
violation (see [AGENTS.md](../../../AGENTS.md)).
