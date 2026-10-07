# Engineering and release program

English | [简体中文](../zh-CN/release-process.md)

This is the executable release program from v1.7 through v2.0. Repository
state, required GitHub checks, and retained exact-candidate evidence override a
roadmap estimate. A release never trades protocol correctness, security, or a
protected performance path for schedule.

For the v2 binary upgrade, production configuration bytes, identity, routing,
systemd semantics, SSH aliases, firewall and cloud network policy are immutable.
Use the existing generation layout. Preserve the original rollback binary even
when the official artifact replaces a validated candidate. A configuration
rejection is a software compatibility defect; it does not authorize rewriting
the operator's file. The bounded v1.8 Handoff/direct input and `serve --config`
invocation are specified by [ADR 0027](../adr/0027-preserve-the-existing-v18-handoff-landing.md).

## Evidence tiers and invalidation

Release validation is intentionally time-bounded:

| Tier | Blocking | Budget | Question |
| --- | --- | --- | --- |
| A — focused formal gate | yes | about 10–20 minutes | Does the exact production binary implement the claimed mechanism, preserve integrity, and avoid protected-path regression? |
| B — stress and isolated multi-node qualification | yes | bounded work and explicit fault cases | Does the exact candidate preserve integrity and recover bounded resources under repeated load, reload, partition and restart? QEMU system VMs qualify. |
| C — extended soak | no | hours or overnight | Does long-horizon operation reveal retention or rare network behavior? |

Tier B may run entirely in isolated QEMU system VMs; real dual-VPS access is
not a publication prerequisite. A real-WAN canary remains separately labelled
deployment evidence. Tier C remains useful nightly, post-release, or during a
focused investigation, but an additional hours-long or multi-day soak is not
required for publication. Existing required native checks are not skipped or
made optional by calling them a soak.

Stress compresses operation counts, not elapsed time. It cannot establish a
month of uptime, exercise an untriggered timer, or reproduce a real WAN merely
by increasing concurrency. Time-dependent boundaries need deterministic tests;
untested calendar, kernel and network behavior remains explicit.
The rationale is [ADR 0033](../adr/0033-stress-and-virtual-machines-qualify-releases.md).

Every retained artifact records the commit, binary SHA-256, ELF Build ID,
version, rustc, target, features, host, kernel, workload, raw samples, and
integrity result. Source changes invalidate evidence by dependency, not by
ritual: a transport change reruns transport gates and multi-node qualification; a docs-only
change does not invalidate an immutable transport binary; release packaging
changes rerun package and official-artifact smoke tests.

### Tier B — stress and isolated multi-node qualification

The following is the publication acceptance contract, not a claim that starting
VMs or completing a throughput benchmark is sufficient:

1. **Provenance and isolation.** Use the immutable release candidate and pinned
   stock Xray. Record executable hashes, build identities, fixture/controller/
   evaluator source hashes, commands, guest images, acceleration mode, kernels,
   distinct boot IDs, CPU/RAM/swap limits and network topology. Use two LINE
   guests and one LANDING guest with separate kernels; user-mode QEMU or three
   processes in one guest is not this test. Host forwards are loopback-only;
   faults affect only owned guest links, never the host or production network.
2. **Interoperability and pressure.** Run the existing exact-candidate native
   interoperability, mechanism and descriptor-pressure gates with their
   unchanged contracts. Exercise Handoff and NXR through stock Xray on both
   LINEs. Include a 1-vCPU/1-GiB LANDING resource/recovery case as well as the
   ordinary multi-worker case. No OOM, panic, unexpected process exit,
   authentication/protocol regression or corrupted bytes is acceptable.
3. **Repeated finite stress.** For each topology, complete at least eight
   load/drain/recovery cycles without restarting the daemons. Each cycle must
   complete at least 100 authenticated transfers through each LINE; include
   concurrency 8 and 32, steady load and bursts. Record attempts, successful
   operations, bytes, errors and quiescent checkpoints, not just elapsed time.
   All non-fault transfers must succeed. Bounded retained capacity is allowed;
   unexplained growth in live resources across recovered cycles is not.
4. **Lifecycle and fault matrix.** Preserve a bidirectional stream across LINE
   reload and prove old-generation retirement and new admissions. Exercise warm
   reuse, stale retirement and cold fallback. Kill/restart LANDING, isolate
   LINE-A's data link for 10 seconds while LINE-B continues, and exercise
   50/100/200-ms RTT plus a 100-ms/1%-loss case. After each restored fault,
   require the first new admission within the declared recovery bound and then
   100 consecutive successful new transfers, each within its deadline. A killed
   process need not preserve its old TCP streams; their received prefixes must
   remain exact. Count every induced failure and bind it to the fault window;
   do not accept protocol/authentication rejection or hide a restart loop.
5. **Integrity and resources.** Verify exact bytes/SHA-256 for 1-MiB and larger
   downloads, uploads and simultaneous bidirectional traffic. Upload receipts
   must be newly appended for unique run-specific paths. Retain at least 12
   identity-bound resource samples per role spanning baseline, load, peak and
   recovery; sample each stress cycle's recovered state without PID replacement.
   Use the frozen [ownership contract](../../benchmarks/contracts/stability.json)
   and [ADR 0034](../adr/0034-qualify-resource-ownership-and-lifetime.md) for
   recovered LANDING descriptors and memory lifetime evidence. Preserve LINE FD
   768/2,048, LANDING peak FD 1,024, threads baseline +8/+16 and RSS baseline
   +32/+96 MiB. Retain PSS,
   anonymous memory and process start times for attribution. Do not require
   RSS to return byte-for-byte, infer a leak from residency alone, or extrapolate
   a short run into a monthly memory prediction.
6. **Temporal boundaries.** Record deterministic tests for the affected replay/
   TTL, generation/credential retirement, shared inactivity, write-stall,
   half-close and cancellation contracts. Use explicit time inputs or controlled
   test-runtime time where supported. Do not shorten production deadlines,
   change real clocks or replace these tests with a larger connection count.
7. **Reviewable verdict.** Retain every case and failure, raw samples, integrity
   receipts and a fail-closed audit against the criteria above. Fixture and
   evaluator code must be reviewable and validated; a hand-written success
   Boolean is not evidence. Missing cases remain not-run. Label the scope
   `LOCAL_QEMU` or `LOCAL_KVM`, never `dual-vps-active-release-canary`. A release
   PR must identify the exact evidence and record the reviewer's acceptance.

Use `cargo dev perf freeze`, `cargo dev check --all`, existing
`cargo dev bench run --suite no-ccs-interop`, `--suite deployment` with
`--deployment-plan mechanism`, and `--suite descriptor-pressure` for the
repository-owned portions; supply the same frozen `--rust-bin` and pinned
reference binaries. The VM fixture adds guest isolation and the fault/stress
cases; it does not replace these commands. The existing
`cargo dev deploy canary` evaluator remains WAN-specific and must not be fed
fabricated SSH/firewall assertions to make a local run look like a VPS run.

## Phase 0 — verify current state

Before repository mutation inspect local Git, `origin/main`, open PRs and
checks, releases and worktrees:

```shell
git fetch origin --prune
git status --short --branch
git worktree list
gh repo view
gh pr list
gh pr checks PR
gh release list
```

Before separately authorized live deployment, inspect both logical SSH roles
and record service names, executable/configuration paths and hashes, listeners,
users, limits and firewall shape without exporting secrets. An unknown or
unhealthy live service stops deployment; it does not block independent local
qualification or authorize blind repair. Publication alone requires no
production SSH connection.

## Phase 1 — finish and merge a feature PR

Use a focused branch and reviewable commits. Run unit/property, replay,
resource, reload, fuzz, sanitizer, active-probe, stock-Xray, and package gates
relevant to the change. The v1.7 claim uses a production-build balanced ABBA
Handoff/NXR/SOCKS5 cold/warm gate at 50/100/200 ms, with 1/10 ms retained as
diagnostics. It must demonstrate approximately one measured TCP RTT of
improvement and exact integrity. A large exploratory Cartesian matrix is
non-blocking.

Retain distinct startup-aware, steady-state, burst, idle-age, and combined
cover-plus-LANDING evidence. Review that checked-out sockets never return,
complete authenticated writes never retry, retry state is fresh, permits
outlive sockets, generations and credentials do not cross, speculative
backoff never delays cold fallback, and no destination side effect precedes
authentication. Then update and merge through `gh`:

```shell
gh pr edit PR --body-file PR-BODY
gh pr ready PR
gh pr checks PR --watch
gh pr merge PR --squash --delete-branch
```

Use the repository's observed merge policy. Never merge a failed required
check, security gate, unexplained resource growth, interoperability failure,
or meaningful protected-path regression.

## Phase 2 — release metadata and exact candidate

Create `release/vX.Y.Z` from fresh `origin/main`. Update Cargo metadata and
locks, changelog, bilingual documentation, evidence pointers, and release
headlines. Open `release: rust-reality vX.Y.Z`, wait for exact CI, and merge
through `gh`.

Create an immutable worktree from merged main and build with the official
release scripts. The candidate must report the intended version. Run affected
fast final gates, then Tier A and Tier B. Never overwrite a binary while it is
being evaluated.

The deployment steps below apply only to a separately authorized live rollout.
They are not additional publication prerequisites when Tier B was qualified in
QEMU. Repository review/merge and tag/publication authorization remain distinct
from permission to touch a live host.

## Phase 3 — permanent LINE deployment

`rust-reality-vps` is a daily-use node. Port 22 is immutable administrative
infrastructure and port 443 is its only public proxy listener. Releases live
under `/opt/rust-reality/releases/`; root-owned compatible configurations live
under `/etc/rust-reality/releases/`. `current` selects the running generation;
`previous` selects the one verified rollback generation.

REALITY/VLESS identity is persistent deployment state. Normal upgrades preserve
the private/public-key relationship, VLESS UUIDs, short IDs, SNI/target policy,
flow, endpoint, routing, and outbound semantics. Secret-bearing configuration
is never printed or stored in public artifacts. Compare migrations using
`cargo dev config fingerprint`, which emits hashes rather than values.

The first migration copies the known-good binary and compatible config into a
minimal rollback bundle before replacing the old active layout. Thereafter:

```shell
cargo dev deploy inspect --target line --output line-before.json
cargo dev deploy plan stage --target line --snapshot line-before.json \
  --release-id RELEASE --binary /absolute/path/to/rust-reality \
  --config /absolute/path/to/config.json --expected-sha256 SHA256 \
  --expected-version VERSION --source-commit COMMIT --output stage-plan.json
cargo dev deploy apply stage --target line --release-id RELEASE \
  --binary /absolute/path/to/rust-reality \
  --config /absolute/path/to/config.json --expected-sha256 SHA256 \
  --expected-version VERSION --source-commit COMMIT --mutate-remote \
  --output stage-evidence.json
cargo dev deploy apply cutover --target line --release-id RELEASE \
  --binary /absolute/path/to/rust-reality \
  --config /absolute/path/to/config.json --expected-sha256 SHA256 \
  --expected-version VERSION --source-commit COMMIT --mutate-remote \
  --output cutover-evidence.json
# application canary
cargo dev deploy apply promote --target line --release-id RELEASE \
  --mutate-remote --output promote-evidence.json
```

`inspect` and `plan` are read-only. `apply` refuses to run without the explicit
`--mutate-remote` acknowledgement. `stage` verifies version, SHA-256, `check`,
and `doctor` without changing CURRENT. `cutover` prepares PREVIOUS, performs
the shortest stop/symlink/start
window, verifies the executable and 443, and rejects any unexpected wildcard
TCP listener introduced during the cutover. Pre-existing unrelated listeners
remain the host operator's responsibility and are not silently disabled by the
deployment tool. Any startup or listener-policy failure automatically restores
the old generation. A later interoperability or canary failure runs `rollback`.
Promotion records acceptance. Optional pruning is separate and must not remove
the retained pre-upgrade rollback release; persistent identity is never pruned
with release directories.

## Phase 4 — dual-VPS active canary

This is real-WAN deployment validation, not a mandatory publication environment.
Keep its reports and gate identity separate from local VM qualification.

LANDING port 443 is allowed only from the LINE public IPv4 `/32`; port 22 is
never changed. Origins are loopback-only. Handoff is the primary topology:

```text
stock Xray client -> LINE:443 -> warm Handoff -> LANDING:443 -> loopback origin
```

The approximate ten-minute schedule is baseline, steady traffic, connection
churn, bounded burst/recovery, warm idle/stale rotation, LINE reload,
controlled LANDING restart/recovery, 1 MiB and larger download/upload/
bidirectional integrity, and final recovery. Resource sampling uses SSH, not a
public metrics listener.

`cargo dev deploy canary-plan` validates and records the complete canary input
without contacting either host. The same inputs go to `cargo dev deploy
canary-run --mutate-remote`; its report is re-admitted by the fail-closed `cargo
dev deploy canary` evaluator. The acceptance requires exact identity, both
SSH connections, constrained listeners/firewall, stock Xray, integrity, warm
Handoff, deliberately observed cold fallback, generation retirement, LANDING
recovery, at least 500 bounded connection attempts, bounded pool targets and
connects, no systematic LANDING rejection churn, and recovering FD/thread/RSS
envelopes. RSS need not return byte-for-byte because allocator retention is
real; FD recovery also uses reviewed absolute ceilings that account for the
bounded reusable splice-pipe pool rather than comparing a warmed process to
its pre-traffic descriptor count. The controlled restart may cause a small,
bounded number of outbound failures, but authentication/protocol rejection is
never accepted. The short canary does not extrapolate a MiB/hour slope. Test
additional protocol modes locally when selecting them would change production
configuration.

The inventory determines which topology the existing public listener actually
serves. If it uses SOCKS5 rather than Handoff, report that difference explicitly;
do not change users, credentials or routing to manufacture the diagram above.
Validate the unchanged public path and use an authorized, separately labelled
supplemental Handoff run with a loopback-only LINE entry and the existing
restricted LANDING:443. This demonstrates the real WAN leg, not Handoff routing
on the public LINE listener. No temporary wildcard/public listener is permitted.
Historical v1.8 supplemental evidence in `benchmarks/evidence/releases/`
records a different, previously authorized procedure; it does not authorize
configuration changes during the v2 binary upgrade.

Pass native inventory snapshots captured **before cutover** as `--line-baseline`
and `--landing-baseline`. The canary compares wildcard address/port pairs before
and after traffic against those snapshots: an unrelated existing listener is
preserved, while a new listener or address family fails the gate. The LANDING
TCP/443 firewall restriction is checked again after recovery.

For supplemental Handoff, stage a dedicated `rust-reality-canary-<name>.service`
on the canonical LINE alias, with the candidate binary and one loopback listener.
Supply `--supplemental-line-service` and `--supplemental-line-port` together with
`--public-socks-port`, `--public-url` and `--public-payload`. The stock-Xray config
must contain two explicitly loopback SOCKS inbounds, routed separately to the
supplemental entry (through an SSH loopback forward) and the unchanged public
LINE endpoint. No host alias, public service unit or routing configuration is
replaced. The runner verifies the supplemental process owns only its declared
loopback listener, reloads both LINE processes, and checks public download bytes
at startup, every phase and final recovery. The report labels the topology and
evaluates separate public-LINE and supplemental-LINE resource samples using the
same reviewed LINE bounds. Rollback still acts on the production generations;
the operator removes the temporary supplemental unit and SSH forward afterward.

Run the loopback origin with `cargo dev bench origin --access-log PATH`
and pass that remote path as `--origin-access-log`. The one-MiB payload must be
exactly one MiB and the large payload must be larger. Download, upload and
concurrent download/upload checks require exact bytes/SHA-256. Upload receipts
must be newly appended and match each run-specific PUT path, length and digest;
an old receipt or a matching length alone cannot establish integrity.

## Phase 5 — tag, publish, and deploy official artifacts

After exact-main Tier A/B gates pass, create and push an annotated tag, then
monitor the existing all-or-nothing workflow:

```shell
git tag -a vX.Y.Z EXACT_MAIN_SHA -m "rust-reality vX.Y.Z"
git push origin vX.Y.Z
gh run list --limit 20
gh run watch RUN_ID
```

Do not create a duplicate release. Verify the tag commit, full asset matrix,
`SHA256SUMS`, `release-manifest.json`, generic/musl smoke, and aarch64 policy.
Download and verify the official artifacts, then repeat compatibility/integrity
smoke in the qualified isolated environment. Publication does not require a
production deployment. For an independently authorized live rollout, deploy
the official artifact over the candidate, repeat the deployment canary, and
retain PREVIOUS. A rollout failure restores PREVIOUS and is fixed forward with
the appropriate patch release.

## Phase 6 — v1.8 Session Engine

Use a separate worktree while v1.7 monitoring continues. First freeze v1.7
dependency/coupling, buffer ownership, copy, allocation, async-future size,
syscall, PMU, assembly, and structure-size baselines. Extract in small PRs:
pure codecs/state; retry and irreversible-write ownership; REALITY/VLESS/Vision
orchestration; Tokio Runtime Adapter; deletion of duplicate logic.

The Session Engine accepts time, randomness, DNS/connect results, write
progress, and timer expiry as events. It knows no Tokio, `TcpStream`, fd,
epoll, io_uring, thread, or scheduler type. A one-time `RawRelayGrant`
transfers authenticated sockets to the transport relay, keeping semantic
abstraction out of every relay chunk. State-machine fuzzing enforces no
authority before auth, no replay double commit, no retry after complete write,
one owner, terminal-state monotonicity, bounded state, and generation
isolation. Every PR is performance-neutral-or-better against frozen v1.7.

## Phase 7 — v1.9 client and EarlyPrepare

Build a narrow loopback SOCKS5 client for VLESS + REALITY + Vision while stock
Xray remains mandatory. EarlyPrepare requires a separate ADR and explicit wire
decision. Its first form contains only bounded encrypted request metadata bound
to the authenticated ClientHello and later canonical VLESS request. Validated
ClientFinished remains the side-effect barrier; arbitrary early application
data is excluded.

## Phase 8 — v1.10, experiments, and v2.0

After architecture stabilization, use measured ABBA work to reduce copies,
allocations, repeated hashing, future sizes, metrics contention, cache misses,
and syscalls. PMU and syscall ledgers are evidence, not source-level guesses.
Arena/slab allocation, worker topology, io_uring, send-zc, and AF_XDP remain
isolated experiments with hard acceptance criteria. A losing experiment is
documented and removed; baseline deployment never gains new privileges.

v2.0 means a runtime-independent Session Engine, explicit Runtime Adapter and
Transport ownership, substantial core/alloc-compatible pure logic, a supported
client, safe optional EarlyPrepare if proven, mature semantic fuzzing, bounded
resources, stock-Xray interoperability, and a per-path allocation/copy/syscall/
cache/CPU/latency audit. Version count alone is not a reason to tag v2.0.
