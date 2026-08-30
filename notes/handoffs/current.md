# Engineering handoff — merged main and active PR #154

`main` contains PR #153. Deployment/hotspot migration work remains on draft
PR #154; this file does not claim it is merged. The PR body is the mutable
continuation ledger, so verify its exact head and checks before acting.

## Repository

```text
merged main         641a3f3   (merge of PR #153)
active candidate    PR #154   branch dev/scripts-deployment
latest release      v1.8.0    (tag on 6618e9d)
tracking issue      #147      (durable scripts-elimination execution state)
```

## scripts/ elimination milestone — in progress

```text
scripts/ recursively tracked         2 (verify: git ls-files 'scripts/**' | wc -l)
active repository Bash policy        2 (the two live-gated authorities below)
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
tracked pending gate                deploy-release-vps.sh,
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

### Final deployment deletion matrix

| Legacy authority | Unique semantics now owned by Rust | Non-live proof | Remaining acceptance |
| --- | --- | --- | --- |
| `deploy-release-vps.sh` | Fixed LINE/LANDING aliases; snapshots; artifact/config identity; bootstrap, stage, atomic cutover, listener/service verification, promotion/pruning; constructed rollback | `deploy::{host,snapshot,plan,executor}` unit/fake-transport tests, including injected cutover failure, redaction, typed SSH argv and repeat rollback | One issue #147 deployment mutation path |
| `run-dual-vps-canary.sh` | Exact candidate/comparator identity; direct LINE→LANDING topology; churn; LINE reload; LANDING restart/recovery; byte integrity; bounded pools; resource envelope; fail-closed evidence; cleanup and rollback | `deploy::{canary_run,canary}` schedule, firewall, journal, report-admission and evaluator tests; non-mutating `canary-plan` | One issue #147 deployment mutation path |

The gate accepts exactly one of: mutation acceptance on an identified disposable
staging pair; separately authorized LINE/LANDING acceptance using
`APPROVED: LIVE VPS MUTATION`; or an explicit operator waiver accepting fake execution, dry-run
parity, recorded parity and read-only inspection. None is currently recorded.
Until one exists, both files remain tracked and #147 remains open.

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
