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
scripts/ recursively tracked        42 (verify: git ls-files scripts/ | wc -l)
workflow scripts/ references        0
session start                       46
deleted this session                benchmark-real-path.sh, benchmark-xray.sh,
                                    benchmark-vision-direct.sh,
                                    validate-deployment-netem.py
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
```

### Remaining — exact next actions

```text
1. Port deployment_driver.py summarize -> cargo dev deploy summarize
   - then DELETE deployment_driver.py + test-performance-gates.py
   - cargo dev check --all must then run zero repo-owned .py validators

2. Continue benchmark suites on the existing foundation:
   vless-encryption, setup-rate*, dns, routing, fallback-ab, matrix, tls-shape,
   soak, descriptor-pressure, interop/*, validate-*, sampling-*, helpers, hotspot

3. Outer workspace: ~18–19 GiB free after reclaiming ~905 MiB tmp cargo targets.
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
