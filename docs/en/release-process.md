# Engineering and release program

English | [简体中文](../zh-CN/release-process.md)

This is the executable release program from v1.7 through v2.0. Repository
state, required GitHub checks, and retained exact-candidate evidence override a
roadmap estimate. A release never trades protocol correctness, security, or a
protected performance path for schedule.

## Evidence tiers and invalidation

Release validation is intentionally time-bounded:

| Tier | Blocking | Budget | Question |
| --- | --- | --- | --- |
| A — focused formal gate | yes | about 10–20 minutes | Does the exact production binary implement the claimed mechanism, preserve integrity, and avoid protected-path regression? |
| B — dual-VPS active canary | yes | about 10 minutes | Does the exact candidate deploy, operate over a real WAN, survive churn/reload/LANDING restart, and recover bounded resources? |
| C — extended soak | no | hours or overnight | Does long-horizon operation reveal retention or rare network behavior? |

Tier C remains useful nightly, post-release, or during a focused leak
investigation. It is not a publication prerequisite and must not stall the
next worktree. A ten-minute canary is described only as high-density lifecycle
evidence, never as proof that no long-term leak exists.

Every retained artifact records the commit, binary SHA-256, ELF Build ID,
version, rustc, target, features, host, kernel, workload, raw samples, and
integrity result. Source changes invalidate evidence by dependency, not by
ritual: a transport change reruns transport gates and the canary; a docs-only
change does not invalidate an immutable transport binary; release packaging
changes rerun package and official-artifact smoke tests.

## Phase 0 — verify current state

Before mutation inspect local Git, `origin/main`, open PRs and checks, releases,
worktrees, and both SSH hosts:

```shell
git fetch origin --prune
git status --short --branch
git worktree list
gh repo view
gh pr list
gh pr checks PR
gh release list
ssh rust-reality-vps true
ssh rust-reality-landing-vps true
```

Record service names, executable/configuration paths and hashes, listeners,
users, limits, and firewall shape without exporting secret values. An unknown
or unhealthy live service stops deployment; it does not justify blind repair.

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
  --prune-old-releases --mutate-remote --output promote-evidence.json
```

`inspect` and `plan` are read-only. `apply` refuses to run without the explicit
`--mutate-remote` acknowledgement. `stage` verifies version, SHA-256, `check`,
and `self-test` without changing CURRENT. `cutover` prepares PREVIOUS, performs
the shortest stop/symlink/start
window, verifies the executable and 443, and rejects any unexpected wildcard
TCP listener introduced during the cutover. Pre-existing unrelated listeners
remain the host operator's responsibility and are not silently disabled by the
deployment tool. Any startup or listener-policy failure automatically restores
the old generation. A later interoperability or canary failure runs `rollback`.
Promotion keeps CURRENT and PREVIOUS and prunes older replaceable software;
persistent identity is never pruned with release directories.

## Phase 4 — dual-VPS active canary

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
never accepted. The short canary does not extrapolate a MiB/hour slope. NXR
receives a separate compact run on the same LANDING 443, after which the
intended daily configuration is restored.

When a canary leg cannot exercise a specific topology gap (for example the
v1.8.0 release where neither the formal loopback legs nor the canary reached
the LINE-to-LANDING Handoff/NXR path), the established alternative is a
**supplemental real-WAN run** that extends the live daily configuration
instead of replacing it: identities, users, and routing are copied verbatim
(hash-verified), one canary-only user is appended, and the daily generation is
restored afterwards with the live configuration hash verified byte-identical.
A compact durable record of such a run lives in
`benchmarks/evidence/releases/` (`v1.8-supplemental-dual-vps-evidence.md`).

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
Download the official artifact, verify it, deploy it over the candidate,
repeat compatibility/integrity smoke, and leave it running. Failure restores
PREVIOUS and is fixed forward with the appropriate patch release.

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
