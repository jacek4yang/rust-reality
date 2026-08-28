# Engineering handoff — current state

Verify every mutable fact below before relying on it.

## Repository

```text
main                810a616   (verify: git rev-parse origin/main)
latest release      v1.8.0    (tag on 6618e9d)
open PRs            none at time of writing; this branch continues suite migration
```

## scripts/ elimination milestone — in progress

```text
scripts/ recursively tracked        43 (verify: git ls-files scripts/ | wc -l)
workflow scripts/ references        0
session start count                 46
deleted this session                benchmark-real-path.sh, benchmark-xray.sh,
                                    benchmark-vision-direct.sh
```

### Completed families (do not redo)

```text
evaluator      cargo dev perf evaluate
checks         cargo dev check --all
release        cargo dev release {matrix,verify-tag,build,package,smoke,aggregate}
fuzz           cargo dev fuzz {targets,smoke}
config id      cargo dev config fingerprint
perf env       cargo dev perf environment --tool {stat,c2c}
historical     v1.5/v1.5.1/v1.6 release-gate harnesses -> notes/history/release-gates/
bench core     cargo dev bench {list,environment}
deploy canary  cargo dev deploy canary
bench suites   cargo dev bench run --suite {real-path,xray,vision-direct}
               engine + identity + suites + origin + origin_tls + loopback
               live WAN + loopback HTTP + loopback HTTPS smokes passed
               deleted: benchmark-real-path.sh, benchmark-xray.sh,
                        benchmark-vision-direct.sh
pipe budget    checks::pipe_budget owns the matrix pipe-page formula natively
               (legacy Python extract removed from test-performance-gates.py)
```

### Remaining families

```text
benchmark suites   vless-encryption, setup-rate, setup-rate-xray, dns-comparison,
                   routing-comparison, fallback-ab, matrix, tls-shape, soak,
                   descriptor-pressure, openssl-no-ccs-interop, xray-interop,
                   validate-ipv6-e2e, validate-profiles, sampling-xray-resources,
                   run-target-host-validation, record-delay-reader,
                   benchmark-deployment
                   -> consume bench::{engine,suites,loopback,origin*} ; do NOT
                   rebuild the foundation
benchmark helpers  bench-origin/, dns-fake-server.py, cover-flight-shape-proxy.py,
                   tls-shape-helper.py, tls-record-delay-fixture.py, ipv6-e2e/,
                   tls-shape-reference.c, host-exclusive-lock-keeper.py
                   (superseded by bench::host_lock for new suites; still referenced
                   by benchmark-contract.sh + test-performance-gates.py)
deployment         deploy-release-vps.sh, deployment_driver.py,
                   run-dual-vps-canary.sh, validate-deployment-netem.py
                   -> cargo dev deploy {inspect,plan,promote,rollback,netem,canary}
                   canary + netem data-quality landed; mechanism ABBA evaluation
                   and deployment_driver summarize still Python / next to port
                   before deleting test-performance-gates.py
hotspot/profiling  export-hotspot-bundle.sh, profile-*, aggregate-hotspot-samples.py,
                   idalib-export-address.py -> cargo dev perf hotspot; last
last check gate    test-performance-gates.py still invoked by cargo dev check --all
                   (auto-skips when absent). Remaining unique contracts:
                   netem validation + deployment summarize. Host-lock and matrix
                   pipe-budget extracts have moved to native Rust tests.
```

### Outer workspace cleanup — still pending

```text
disk free                           ~18 GiB
artifacts/                          ~5.4 GiB (pinned Xray verified)
verified Xray                       artifacts/xray-reference-v26.7.28
                                    sha256 23d228d78d699306c4782d6b400e2afa97c9bc9f291ae623448b5504904c5268
preserve                            proxy-env.sh, private/
```

## Closed questions — do not reopen without the recorded revisit condition

```text
CompiledRuntimePlan          no new construct required
control-plane bulk cost      ~15 relaxed atomics/connection; not the bulk gap
relay.bufferBytes            rejected on mechanism
pipe-page exhaustion         0 of 80 concurrent streams downgraded
framed copies/allocations    AVOIDABLE = 0
4 * MAX_TLS_RECORD_WIRE_LEN  KEEP
```

## Next action

1. Finish netem mechanism ABBA evaluation in deploy::netem; switch
   test-performance-gates netem cases to cargo dev deploy netem; delete
   validate-deployment-netem.py.
2. Port deployment_driver.py summarize into cargo dev deploy summarize; delete
   deployment_driver.py + test-performance-gates.py.
3. Continue benchmark suites (vless-encryption, setup-rate, matrix, …).
4. Do not rebuild the benchmark foundation.
