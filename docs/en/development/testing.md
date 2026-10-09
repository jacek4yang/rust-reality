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
  The colocated `server::production::reload_io` regression additionally drives
  a real production NXR listener: unread bidirectional bytes survive key
  publication, the established stream remains byte-exact, and a new connection
  authenticates with the new key. This is loopback reload coverage, not a claim
  of Handoff, network-partition or independent-kernel coverage.
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
- **Sanitizers** run in CI (Security workflow): Address/LeakSanitizer.
  Concurrent replay and transport regression tests remain in the ordinary suite.
  See [ADR 0035](../../adr/0035-remove-thread-sanitizer-gate.md) for the explicit
  decision to remove ThreadSanitizer and its coverage trade-off.

## Actions execution lanes

CI and Security provide ordinary regression feedback. Native qualification
executes real-process/network-namespace interoperability, pressure/recovery and
connection lifetime checks. Candidate packages verify the actual distribution
assets. QEMU specialist qualification separately exercises independent guest
kernels and constrained CPU/RAM; it is not a precise performance benchmark.

Native qualification also supports explicit `workflow_dispatch` on the selected
branch's exact SHA, including the final merged `main` commit. Both the full
qualification job and the 600-second connection matrix check out that same SHA.
PR-head evidence does not qualify a later merge commit; retain a new exact-main
run before release. Dispatch becomes available once the workflow is present on
the default branch.

QEMU starts on `ready_for_review` or explicit `workflow_dispatch`, rather than
every draft push. Dispatch uses the selected branch's exact SHA. Existing
campaigns are not cancelled by newer requests. A result never qualifies a
different SHA; after another commit on a ready PR, explicitly request the new
campaign. Missing or skipped qualification is not a pass. The existing Tier B
contract remains required until a reviewed replacement covers its obligations.
See [ADR 0036](../../adr/0036-separate-native-and-qemu-qualification.md).

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

RTT/loss windows last 90 seconds for the concurrency-8 matrix (four transfers
per LINE), with a fixed 12-second admission drain before restore so in-flight
1 MiB transfers can finish inside the fault interval; other faults and recovery
use four per LINE. Each exercised LINE must complete at least 100 transfers.
Other fault intervals last 10 seconds. The directional integrity window lasts 60 seconds,
followed by 180 seconds of recovery. These schedules are fixed in the executable
contract before qualification, including on constrained LANDING guests.
Offline evaluation requires every integrity checkpoint, including recovered owner,
memory and process identity checks after the final transfer. Raw `/proc` fields
must have their exact kernel units and shape; numeric prefixes alone are invalid.
VM startup and terminal receipts are checked against the frozen identities.
Before product startup, the controller synchronizes only the owned snapshot
guests and disables their NTP service. Before/after clock receipts bind each
guest boot to host request intervals: offset at most 250 ms, round trip at most
500 ms, and local wall/monotonic drift at most 50 ms. Sampling reserves 350 ms
inside the existing two-second deadline. Missing or skewed clocks invalidate
the shared workload schedule; clocks are never corrected during a run. The
controller establishes a private, owned SSH control connection before measuring
each clock exchange, then closes it on success or failure. Authentication time
does not become clock uncertainty, and an operator's SSH connection is never reused.
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
campaign should use the frozen release-built harness:
`RUST_REALITY_GIT_COMMIT=$(git rev-parse HEAD) cargo build --release --manifest-path tools/Cargo.toml -p rr-dev`,
then invoke `tools/target/release/rr-dev bench stability-run` with the same inputs.
Keep the guests' pinned physical cores, including SMT siblings, free of other
compilation and test work throughout execution. Each stress
cycle starts with a concurrency-sized wave of 4-MiB uploads paced at 256 KiB/s,
then completes at least 100 transfers per LINE. Echo probes retain exact received
prefixes across fault boundaries; directional probes include concurrent upload
and download legs. Curl ignores user configuration and proxy environment values.
Completed guest observations also stream into bounded host files, so a failed
final retrieval retains previously collected data without an unbounded memory
copy. A failed attempt keeps its partial cell, raw files and terminal status.
The VM runner does not supply the separate required native, CI, security or
package-check receipts: absent receipts keep aggregate qualification NOT RUN.
After the VM runner exits, `cargo dev bench stability-check --evidence BUNDLE/evidence.json
--case local-full-gate` collects the authoritative local gate. The `lifecycle`
case runs unfiltered library tests and binds all eight required lifecycle checks.
`--case long-lived-connections` runs the ignored 600-second authenticated matrix
(SSE, WebSocket, quiet directions, delayed response, half-close and write stall).
The unfiltered lifecycle run lists that test as ignored and cannot satisfy it.
Use `--case exact-head-ci --run-id ID` and `--case exact-head-security --run-id ID`
to retain the corresponding GitHub workflow receipts. Run from the clean frozen
checkout with its exact frozen harness. Each attempt retains its command, owned
child identity, raw stdout/stderr, terminal result and final source/executable
checks, including on failure. Collection serializes aggregate updates and refuses
to replace any previous check attempt. Evaluate the completed bundle separately;
collection alone does not establish readiness.
The same collector runs `native-interop`, `native-mechanism`,
`native-descriptor-pressure` and `native-resources` with the frozen candidate,
Xray and OpenSSL copies. It fixes the existing suite arguments, retains nested
raw observations and rejects shortened native duration or recovery coverage.
Run these host-exclusive workloads after the VM campaign has released its lock.
The native interoperability receipt retains the exact source and downloaded
payloads and the OpenSSL handshake trace. Offline verification checks their
bytes, the absence of server CCS, the pinned external executables and the
prescribed stock-Xray command; a summary claiming success alone cannot pass.
Descriptor-pressure receipts require the fixed 192-descriptor limit, 96-stream
fill bound and 12-connection storm. Offline verification reconstructs the startup
budget and high-to-normal transition, verifies the 4-KiB control and 64-KiB
recovery echoes, and rejects missing raw logs or bytes. Interrupted echoes retain
their actual received prefix, preserving the original failure.
Native mechanism receipts must reproduce the reviewed 50/100/200-ms, zero-loss,
concurrency-1 matrix from bound raw files using the existing netem evaluator.
The verifier checks the source, harness and executable identities, complete
publication chain and final identity checks. Relocation resolves original paths
only through retained artifact bindings; missing rows, substituted files or a
recorded PASS that disagrees with recomputation cannot qualify. WAN evaluation
continues to use its separate existing workflow and acceptance rules.
All four package checks require the native execution bundles described in the
[release process](../release-process.md). Offline verification rejects missing
commands, changed images, wrong tiers, emulation and archive/binary substitution.

## Release feedback loop

A release gate passing means every declared check passed for the exact candidate;
it is not a guarantee that no defect exists in every deployment. GitHub Actions
can host the required native and QEMU environments. A hosted check must retain
its source/binary identities and verifiable receipts; moving execution to Actions
does not waive a required case or change the acceptance contract.

Keep deterministic state-machine and ownership tests, short real-protocol
integration tests, sanitizer checks, and full multi-node qualification distinct.
Reproduce collector failures in short tests before spending another full campaign
on them. A race between a live descriptor census and separately sampled counters
is incomplete evidence, not proof of a product leak and not a successful check.
Do not retry until green or silently discard failed observations.

Report released-binary regressions using the repository's release regression
issue form. Include the version/asset, environment, sanitized topology, minimal
reproduction and timestamped symptoms. Maintainers classify product defects,
measurement defects and environment failures, preserve the original evidence,
and add a focused regression test with the fix before rerunning affected gates.
Keep large traces in bounded external artifacts rather than Git; never publish
credentials or private traffic. Security reports follow `SECURITY.md`.

## Candidate package execution

The `Candidate packages` PR workflow checks out the exact PR head, derives the
four-tier matrix from `cargo dev release matrix`, and uses the maintained build,
package, smoke and aggregate commands. Each tier executes its tests and packaged
binary on a matching native runner (the x86_64 musl binary runs on x86_64 Linux).
Artifacts are named with the candidate SHA and retained for seven days. The
package version comes from Cargo metadata; this workflow creates no Git tag and
has no release publication permission. Passing it establishes package execution,
not the remaining protocol/resource qualification or authorization to publish.

Injected stale-socket authentication rejections are classified only from verified
fault-action receipts: exact evicted peer, LANDING boot/role, successful prescribed
`ss -K` command and its observed start/end interval. Each evicted connection can
explain at most one matching authentication event across the retained process
logs. Other peers, reasons, timestamps, duplicate events, admission limits and
configuration rejections remain unexpected. Raw logs and historical verdicts are
never rewritten by this classification.

For deliberate LANDING restart, LINE-A also records the single established
loopback ingress connection at the fault boundary. A Handoff relay EPIPE can be
classified as injected only once, for that exact peer, after the verified kill
and ingress census, and before the intact affected prefix's recorded failure
plus the existing clock guard. Missing/ambiguous census, a different peer,
stage, cause or errno, repeated errors, and errors outside that interval remain
blocking. This adds observation to the test fixture, not a product-log filter
or a production behavior change.

Fault batches soft-stop admission at the contracted boundary (restore for
ordinary faults; restore minus the RTT drain for RTT/loss). Reaching that
boundary is scheduled termination, not a transfer failure. Submitted attempts
and partial results remain retained; missing coverage or an in-flight transfer
finishing outside the required interval still fails. Requests started after
restoration are never silently labelled as fault-period work.
