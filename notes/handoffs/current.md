# Engineering handoff — expected post-merge state for PR #152

This file describes the repository tree expected after PR #150 merges. While the
PR is open, `main` remains the authoritative merged state and the PR body is the
authoritative continuation ledger. Verify every mutable GitHub, Git, disk, and
environment fact before relying on it.

## Repository

```text
base main           d818ded   (verify: git rev-parse origin/main)
candidate           PR #152   (verify its head/state with GitHub)
latest release      v1.8.0    (tag on 6618e9d)
tracking issue      #147      (durable scripts-elimination execution state)
```

## scripts/ elimination milestone — in progress

```text
scripts/ recursively tracked        21 (verify: git ls-files scripts/ | wc -l)
workflow scripts/ references        0
session start                       46
deleted this session                benchmark-real-path.sh, benchmark-xray.sh,
                                    benchmark-vision-direct.sh,
                                    validate-deployment-netem.py,
                                    test-performance-gates.py,
                                    benchmark-setup-rate-xray.sh,
                                    benchmark-setup-rate.sh,
                                    benchmark-fallback-ab.sh,
                                    benchmark-matrix.sh
```

### Completed families (do not redo)

```text
evaluator / checks / release / fuzz / config id / perf env / historical gates
bench core     cargo dev bench {list,environment}
deploy canary  cargo dev deploy canary
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
```

### Remaining — exact next actions

```text
1. Continue the approved sequence from issue #147:
   DNS/routing/VLESS (37 -> 33)         DONE (PR #151)
   TLS-shape/interop/IPv6 (33 -> 21)    DONE (PR #152)
   soak/profiles/resource-pressure/
     shared helpers (21 -> 12)          DONE (PR #153)
   deployment control plane (12 -> 7)   NEXT
   hotspot/final cleanup (7 -> 0)
   - do not rebuild process/workspace/lock/identity/report lifecycle
   - scripts/bench-origin remains only for benchmark-deployment.sh and is
     deleted with that final caller in the deployment family

2. The deployment family has a gate: issue #147 requires staging-VPS
   acceptance, separately authorized LINE/LANDING acceptance, or an
   explicit user waiver. An implementation agent may not choose the waiver.

3. Outer workspace: ~17 GiB free; the merged PR #149 worktree was retired
   (Class A: clean, merged, reproducible).
   Gate each expensive operation on its measured peak plus a safety reserve.
   Preserve artifacts/ (pinned evidence), proxy-env.sh, private/.
```

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
