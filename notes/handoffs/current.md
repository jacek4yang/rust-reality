# Engineering handoff — current state

Verify every mutable fact below before relying on it.

## Repository

```text
main                df3e214   (verify: git rev-parse origin/main)
latest release      v1.8.0    (tag on 6618e9d)
open PRs            none at time of writing
```

## scripts/ elimination milestone — in progress

```text
scripts/ recursively tracked        43 (verify: git ls-files scripts/ | wc -l)
workflow scripts/ references        0
session start                       46
deleted this session                benchmark-real-path.sh
                                    benchmark-xray.sh
                                    benchmark-vision-direct.sh
```

### Completed families (do not redo)

```text
evaluator / checks / release / fuzz / config id / perf env / historical gates
bench core     cargo dev bench {list,environment}
deploy canary  cargo dev deploy canary
bench suites   cargo dev bench run --suite {real-path,xray,vision-direct}
               live WAN + loopback HTTP + loopback HTTPS smokes passed
pipe budget    checks::pipe_budget (native; Python extract removed)
deploy netem   cargo dev deploy netem  (DATA-QUALITY only so far)
               pass + missing-record fixtures green
               --evaluate-performance still NOT_EVALUATED (mechanism next)
```

### Remaining — exact next actions

```text
1. NEXT: finish deploy::netem mechanism ABBA evaluation
   - port mechanism_evaluation + bootstrap_interval from
     scripts/validate-deployment-netem.py
   - attach rawResults during validate so mechanism can read p50 rows
   - native fixtures for mechanism pass/fail (test_netem cases 3-4)
   - then switch test-performance-gates netem cases to `cargo dev deploy netem`
   - then DELETE scripts/validate-deployment-netem.py

2. Port deployment_driver.py summarize -> cargo dev deploy summarize
   - then DELETE deployment_driver.py + test-performance-gates.py
   - cargo dev check --all must then run zero repo-owned .py validators

3. Continue benchmark suites on the existing foundation:
   vless-encryption, setup-rate*, dns, routing, fallback-ab, matrix, tls-shape,
   soak, descriptor-pressure, interop/*, validate-*, sampling-*, helpers, hotspot

4. Outer workspace: ~18–19 GiB free after reclaiming ~905 MiB tmp cargo targets.
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
