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

`/path/to/bundle/rr-dev bench stability-evaluate --evidence /path/to/bundle/evidence.json` verifies
all bound objects and evaluates the frozen ownership contract. Execute the
exact evaluator binary named by the bundle. Relative object paths cannot escape
the bundle or traverse symlinks. PASS requires every required check and case;
FAIL records demonstrated violations, NOT_RUN identifies absent cases, and
INVALID identifies malformed or incomplete evidence. The report retains each
finding even when INVALID takes precedence in the aggregate verdict.
Build the harness with `RUST_REALITY_GIT_COMMIT` set to the candidate's exact
source commit. Both campaign execution and offline evaluation reject a harness
whose embedded source differs, even if its contract bytes match.
Required-check receipts must have a supported semantic verifier; an exit code
and an opaque file cannot establish PASS. CI/Security receipts are the exact
`gh run view RUN_ID --json headSha,workflowName,status,conclusion,databaseId,url,event`
response. The local full gate uses `check --all --output json` and retains every
stage's stdout/stderr objects; its stage list must match the frozen harness.
Lifecycle checks bind the complete stdout from
`cargo test --lib --locked -- --color never`. The contract names each required
test; ignored, missing, duplicated or filtered cases cannot satisfy it, and the
terminal totals must reproduce the observed case results.

The schema and pure evaluator are fuzzed together. Adversarial tests cover
leaked sockets, dirty/excessive pipes, missing permits, transient retention,
retired generations, memory envelopes, payload corruption, stale upload
receipts, missing samples, process replacement, changed binaries and invalid
numbers. Synthetic evaluator fixtures are unit tests, never campaign evidence.

Each transfer retains its source payload and received download or prefix. The
offline verifier compares their bytes and reconstructs PUT receipts from hashed
origin access-log snapshots captured before and after the batch. It rejects
rewritten prefixes, claimed boundaries that differ from the retained snapshot,
old or duplicate request paths, truncated records and changed payload files.
Generation publication histories must be contiguous from startup; omitted
publications or retirements of unknown generations invalidate the observation.

The contract fixes load starts, fault order and observation windows before
execution. Transfer intervals must demonstrate the requested concurrency.
Partition progress and RTT/loss coverage require transfers during the fault;
post-fault checkpoints must recover ownership, including after process restart.
Reused raw observations, excess unopened permits and memory high-water marks
above the peak envelope fail verification.

The required `native-resources` check references `native-resources.json` from
the native soak. Offline verification reopens every bound raw observation and
checks startup policy, all six process identities, round coverage, fixed recovery
windows, and per-process/aggregate envelopes. A short integration PASS cannot
stand in for the required 30-minute workload. Source, harness and contract
substitution, missing final identities or changed observation files are rejected.

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

Fixed runtime Unix sockets are distinguished from TCP using kernel inode rows
for the selected process; their count cannot grow beyond startup. The collector
retains no unrelated namespace socket paths. Executable hashing uses the same
`sha256sum` primitive as release tooling so debug-build hashing does not consume
the sampling window; missing or malformed hash receipts still fail closed.

`cargo dev bench stability-fixture --fixture PATH --output FRESH_DIRECTORY`
boots the preserved, owned three-guest KVM fixture, checks guest CPU/swap and
process identities, retains launch/serial/terminal receipts, and stops only the
children it owns. `--constrained` selects 1 vCPU / 1 GiB for LANDING. Temporary
QEMU disk snapshots preserve the existing guest disks; QMP/monitor endpoints are
disabled and SSH uses pinned host keys on loopback. This is fixture preflight,
not candidate qualification; its output explicitly reports qualification NOT RUN.

The internal guest helper owns the server, stock-Xray client and origin children.
It verifies the controller's guest boot identity and frozen executable digests,
then follows the contract's absolute schedule. Evidence collection never moves
a missed deadline. Reload, warm/cold changes, stale-pool eviction, abrupt LANDING
restart and data-interface netem actions retain action receipts and netem command
output. Restart
requires the owned process identity and confirms termination by SIGKILL. Startup
and execution failures retain the primary error and attempted final observations.
Private configuration remains under the owned fixture, outside the evidence bundle.

RTT/loss windows last 60 seconds for the concurrency-4 matrix (two transfers
per LINE); other faults and recovery use four per LINE. Each exercised LINE
must complete at least 100 transfers. Other fault
intervals last 10 seconds. The directional integrity window lasts 60 seconds,
followed by 180 seconds of recovery. These schedules are fixed in the executable
contract before qualification, including on constrained LANDING guests.
Offline evaluation requires every integrity checkpoint, including recovered owner,
memory and process identity checks after the final transfer. Raw `/proc` fields
must have their exact kernel units and shape; numeric prefixes alone are invalid.
VM startup and terminal receipts are checked against the frozen identities.
Before/after kernel observations bind CPU, memory, swap, boot and OOM counters;
complete product logs bind both LANDING process lifetimes and expose protocol
rejections or panics. Missing outcomes and substituted logs are INVALID.
Each fault requires begin/end action receipts from all three guests. Verification
checks command order and exit status, exact data interfaces, installed netem
delay/loss and restoration, an actual stale-socket eviction, the owned SIGKILL
receipt, stable warm/cold configuration hashes and timely reload publications.

`cargo dev bench stability-run --fixture PATH --output FRESH_DIRECTORY
--candidate FROZEN_BINARY --xray XRAY_BINARY --openssl OPENSSL_BINARY` drives
the four local VM cells. It requires a clean checkout at the candidate's embedded
commit and preserves source, contract, harness and executable copies. Each stress
cycle starts with a concurrency-sized wave of 4-MiB uploads paced at 256 KiB/s,
then completes at least 100 transfers per LINE. Echo probes retain exact received
prefixes across fault boundaries; directional probes include concurrent upload
and download legs. Curl ignores user configuration and proxy environment values.
Completed guest observations also stream into bounded host files, so a failed
final retrieval retains previously collected data without an unbounded memory
copy. A failed attempt keeps its partial cell, raw files and terminal status.
The VM runner does not supply the separate required native, CI, security or
package-check receipts: absent receipts keep aggregate qualification NOT RUN.
The native interoperability receipt retains the exact source and downloaded
payloads and the OpenSSL handshake trace. Offline verification checks their
bytes, the absence of server CCS, the pinned external executables and the
prescribed stock-Xray command; a summary claiming success alone cannot pass.
