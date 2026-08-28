# Engineering handoff — expected post-merge state for PR #148

This file describes the repository tree expected after PR #148 merges. While the
PR is open, `main` remains the authoritative merged state and the PR body is the
authoritative continuation ledger. Verify every mutable GitHub, Git, disk, and
environment fact before relying on it.

## Repository

```text
base main           787ae70   (verify: git rev-parse origin/main)
candidate           PR #148   (verify its head/state with GitHub)
latest release      v1.8.0    (tag on 6618e9d)
tracking issue      #147      (durable scripts-elimination execution state)
```

## scripts/ elimination milestone — in progress

```text
scripts/ recursively tracked        41 (verify: git ls-files scripts/ | wc -l)
workflow scripts/ references        0
session start                       46
deleted this session                benchmark-real-path.sh, benchmark-xray.sh,
                                    benchmark-vision-direct.sh,
                                    validate-deployment-netem.py,
                                    test-performance-gates.py
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
```

### Remaining — exact next actions

```text
1. Migrate the core A/B benchmark family on the existing foundation:
   fallback-ab, matrix, setup-rate, setup-rate-xray.
   - delete all four scripts immediately after native parity
   - do not rebuild process/workspace/lock/identity/report lifecycle

2. Continue DNS/routing/VLESS, TLS/interop/IPv6, soak/profiles/resources,
   deployment, then hotspot/final shell-contract cleanup.

3. Outer workspace: ~18 GiB free; no cleanup was performed for this PR.
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
