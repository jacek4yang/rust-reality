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
- **Architecture boundary tests** assert the layering itself over the source
  tree rather than over behavior: `tests/transport_capability_boundary.rs`
  keeps protocol and session semantics from reaching down into a transport
  backend, and `tests/protocol_core_boundary.rs` keeps the `no_std`-ready
  protocol core free of the runtime, the clock, and configuration
  ([ADR 0016](../../adr/0016-protocol-core-is-no-std-ready-but-stays-in-place.md)).
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

The `rr-dev` tooling workspace has its own suite, and `cargo dev check` runs it:
formatting and strict clippy in every scope, the test suite in `--all`. These
are the commands for running it directly:

```shell
cargo test   --manifest-path tools/Cargo.toml --workspace --locked
cargo clippy --manifest-path tools/Cargo.toml --workspace --all-targets --all-features --locked -- -D warnings
```

This coverage is load-bearing rather than tidy. `cargo dev` is the repository's
benchmark, profiling and interoperability authority, so a measurement the gate
cannot vouch for is not evidence. While the tooling workspace sat outside the
gate, `cargo dev bench` drifted out of sync with the CLI it drives, Xray
interoperability rendering broke, and the workspace accumulated hundreds of
rustfmt diffs — all while the production gate stayed green.

## What must never be weakened

Do not weaken or delete an existing gate, assertion, or sanitizer profile to
make a change easier. If a gate is genuinely wrong, fix the gate in a reviewed
change with a documented reason; silent gate-weakening is treated as a process
violation (see [AGENTS.md](../../../AGENTS.md)).

## Offline stability evidence

`cargo dev bench stability-evaluate --evidence /path/to/evidence.json` verifies
all bound objects and evaluates the frozen ownership contract. Execute the
exact evaluator binary named by the bundle. Relative object paths cannot escape
the bundle or traverse symlinks. PASS requires every required check and case;
FAIL records demonstrated violations, NOT_RUN identifies absent cases, and
INVALID identifies malformed or incomplete evidence. The report retains each
finding even when INVALID takes precedence in the aggregate verdict.

The schema and pure evaluator are fuzzed together. Adversarial tests cover
leaked sockets, dirty/excessive pipes, missing permits, transient retention,
retired generations, memory envelopes, payload corruption, stale upload
receipts, missing samples, process replacement, changed binaries and invalid
numbers. Synthetic evaluator fixtures are unit tests, never campaign evidence.

For qualification, debug logs include one-second `resource_ownership` and
`connection_task_ownership` observations and `generation_retired` events. The
pipe observation inspects retained pipe bytes and reports a missing value if
inspection fails; it never substitutes zero for failure. These observations are
not an allocator census. Replay expiry reclamation runs on the maintenance
cadence in both resource modes; authentication deadlines remain unchanged.

`cargo dev bench stability-observe --pid PID --log PATH` collects raw Linux
status, proportional memory, descriptor targets, limits and the complete debug
log inside the owned fixture. It never signals the process. Read failures and
closed-during-read descriptors remain explicit, and both final process and
executable identity reads are attempted after intermediate failures. Each
normalized sample references its raw observation; offline verification checks
fresh ownership records, the full listener task set (including completed or
cancelled work), replay occupancy, generation retirement, permit counts and the
startup descriptor census. Accepted zero-byte sockets count against pre-auth
permits and the startup ceiling. Admission counters also expose outstanding
handshake, fallback, cryptographic and DNS work at recovery. Declared capacities
and deadlines must match the actual running authorities. These observations do
not claim an allocator-byte census.

`cargo dev bench stability-fixture --fixture PATH --output FRESH_DIRECTORY`
boots the preserved, owned three-guest KVM fixture, checks guest CPU/swap and
process identities, retains launch/serial/terminal receipts, and stops only the
children it owns. `--constrained` selects 1 vCPU / 1 GiB for LANDING. Temporary
QEMU disk snapshots preserve the existing guest disks; QMP/monitor endpoints are
disabled and SSH uses pinned host keys on loopback. This is fixture preflight,
not candidate qualification; its output explicitly reports qualification NOT RUN.
