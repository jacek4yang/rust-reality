# Engineering handoff — issue #147 scripts-zero transaction

PR #154 is the scripts-zero transaction. It was based on `main` after PR #153;
the PR body is the mutable continuation ledger. Verify the exact PR head,
checks, merge state, and resulting `origin/main` rather than inferring them from
this file.

## Repository

```text
PR #154 base        641a3f3   (main after PR #153)
transaction         PR #154   branch dev/scripts-deployment
latest release      v1.8.0    (tag on 6618e9d)
tracking issue      #147      (durable scripts-elimination execution state)
```

## scripts/ elimination milestone — scripts-zero candidate

```text
scripts/ recursively tracked         0 (verify after commit)
top-level scripts/ directory          absent (verify after commit)
active repository Bash policy        0
active repository Python policy      0
workflow repository .sh/.py calls    0
current docs active scripts commands 0
PR #154 start                       12
deleted in PR #154                  aggregate-hotspot-samples.py,
                                    bench-origin/{go.mod,main.go},
                                    benchmark-contract.sh,
                                    benchmark-deployment.sh,
                                    deployment_driver.py,
                                    export-hotspot-bundle.sh,
                                    host-exclusive-lock-keeper.py,
                                    idalib-export-address.py,
                                    run-target-host-validation.sh
final waiver deletion               deploy-release-vps.sh,
                                    run-dual-vps-canary.sh
```

### Completed families (do not redo)

```text
evaluator / checks / release / fuzz / config id / perf env / historical gates
bench core     cargo dev bench {list,environment}
deploy control cargo dev deploy {inspect,plan,apply}
               typed bootstrap/stage/cutover/rollback/promote, exact identity,
               CURRENT/PREVIOUS, listener checks and secret-free evidence
deploy canary  cargo dev deploy {canary-plan,canary-run,canary}
               typed exact-candidate schedule, integrity, churn, recovery,
               resource evidence, fail-closed verdict and failure rollback
bench suites   cargo dev bench run --suite {real-path,xray,vision-direct}
               live WAN + loopback HTTP + loopback HTTPS smokes passed
pipe budget    checks::pipe_budget (native; Python extract removed)
deploy netem   cargo dev deploy netem  (data-quality + ABBA mechanism)
               validate-deployment-netem.py DELETED
check policy   cargo dev check --all runs zero repository-owned .py validators
               deployment summary + lock/publication contracts are native
core A/B       cargo dev bench run --suite {setup-rate-xray,setup-rate,
               fallback,matrix}  (PRs #149, #150)
               wall/perf/strace/netem mechanisms accepted locally; host
               networking and fs.pipe-user-pages-soft verified restored
pressure       cargo dev bench pressure (native descriptor/cgroup policy)
soak           cargo dev bench soak (native topology, reload, resource and
               integrity evidence; real bounded acceptance passed)
profiles       cargo dev bench profiles (native cgroup/workload/evidence/report
               policy; real 1c1g acceptance passed with clean teardown)
hotspot core   cargo dev perf hotspot (identity-bound perf capture, reports,
               build IDs, checksums and publication; real acceptance passed)
hotspot bundle cargo dev perf hotspot-bundle (completed-capture identity,
               private IDALib bridge, instruction mapping gate, checksums and
               publication; real IDALib acceptance passed 520/520 mapped,
               0.000000% unmapped, 19/19 checksums)
```

### Final deployment deletion acceptance

| Deleted legacy authority | Unique semantics now owned by Rust | Accepted evidence | Result |
| --- | --- | --- | --- |
| `deploy-release-vps.sh` | Fixed LINE/LANDING aliases; snapshots; artifact/config identity; bootstrap, stage, atomic cutover, listener/service verification, promotion/pruning; constructed rollback | `deploy::{host,snapshot,plan,executor}` unit/fake-transport tests, including injected cutover failure, redaction, typed SSH argv and repeat rollback | Deleted in PR #154 |
| `run-dual-vps-canary.sh` | Exact candidate/comparator identity; direct LINE→LANDING topology; churn; LINE reload; LANDING restart/recovery; byte integrity; bounded pools; resource envelope; fail-closed evidence; cleanup and rollback | `deploy::{canary_run,canary}` schedule, firewall, journal, report-admission and evaluator tests; non-mutating `canary-plan` | Deleted in PR #154 |

The operator explicitly supplied `APPROVED: DEPLOYMENT DELETION WAIVER` for issue
#147 and accepted the completed fake-executor, dry-run parity, recorded mechanism
parity, failure-injection/rollback, native canary, and read-only inspection
evidence. This is the accepted deletion path. No live VPS mutation was performed
or authorized by this waiver.

Final local scripts-zero checkpoint:

```text
rr-dev tests                         PASS (542/542)
strict rr-dev clippy                PASS
documentation check                 PASS (40 Markdown files)
cargo dev check --all               PASS (14/14)
inventory JSON/invariants           PASS
active Bash/Python policy census    PASS (0/0)
workflow .sh/.py caller census      PASS (0)
current-doc active command census   PASS (0; historical citations retained)
compatibility wrappers              PASS (0)
```

Exact-head GitHub CI/Security must also pass before PR #154 is merged and issue
#147 is closed; that external state belongs in the PR/issue ledger rather than a
repository file that would itself change the checked commit.

### Verified reusable artifacts

```text
artifacts/xray-reference-v26.7.28
  sha256 23d228d78d699306c4782d6b400e2afa97c9bc9f291ae623448b5504904c5268
```

## Closed questions — do not reopen

```text
CompiledRuntimePlan / control-plane bulk / relay.bufferBytes /
pipe-page exhaustion / framed AVOIDABLE=0 / 4*MAX_TLS_RECORD_WIRE_LEN KEEP
```
