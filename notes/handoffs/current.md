# Engineering handoff — current state

Verify every mutable fact below before relying on it.

## Repository

```text
main                3075a09   (verify: git rev-parse origin/main)
latest release      v1.8.0    (tag on 6618e9d)
open PRs            none at time of writing; this branch opens the real-path PR
```

## scripts/ elimination milestone — in progress

The top-level `scripts/` directory is being eliminated: every legacy Bash/Python
tool migrates into typed `rr-dev` functionality (`cargo dev ...`), moves to a
fixture/helper location, or becomes inert historical evidence.

```text
scripts/ recursively tracked        43 after this PR deletes benchmark-vision-direct.sh
                                    (verify: git ls-files scripts/ | wc -l)
workflow scripts/ references        0
```

### Completed families (do not redo)

```text
evaluator      cargo dev perf evaluate            (Python evaluator deleted)
checks         cargo dev check --all              (check.sh deleted; CI switched)
release        cargo dev release {matrix,verify-tag,build,package,smoke,aggregate}
fuzz           cargo dev fuzz {targets,smoke}      (security.yml switched)
config id      cargo dev config fingerprint
perf env       cargo dev perf environment --tool {stat,c2c}
historical     v1.5.0/v1.5.1/v1.6.0 release-gate harnesses moved to
               notes/history/release-gates/ (inert evidence)
bench core     cargo dev bench {list,environment}  (lifecycle foundation)
deploy canary  cargo dev deploy canary            (pure evaluator; Python deleted)
bench real-path cargo dev bench run --suite real-path
bench xray     cargo dev bench run --suite xray
               engine + identity + suites + origin + loopback concurrent lifecycle
               proven with local tests and live smokes (WAN real-path + loopback xray);
               benchmark-real-path.sh, benchmark-xray.sh, and benchmark-vision-direct.sh deleted
```

### Remaining families

```text
benchmark suites   remaining: vless-encryption, setup-rate,
                   setup-rate-xray, dns-comparison, routing-comparison,
                   fallback-ab, matrix, tls-shape, soak-test.sh,
                   test-descriptor-pressure.sh, test-openssl-no-ccs-interop.sh,
                   test-xray-interop.sh, validate-ipv6-e2e.sh,
                   validate-profiles.sh, sampling-xray-resources.sh,
                   run-target-host-validation.sh,
                   record-delay-reader-test-evidence.sh, benchmark-deployment.sh
                   -> consume bench::{engine,suites} lifecycle; do NOT rebuild
                   the foundation. Next: migrate benchmark-xray.sh (loopback
                   origin variant of the same A/B tunnel pattern).
benchmark helpers  bench-origin/ (Go origin), dns-fake-server.py,
                   cover-flight-shape-proxy.py, tls-shape-helper.py,
                   tls-record-delay-fixture.py, ipv6-e2e/, tls-shape-reference.c,
                   host-exclusive-lock-keeper.py (superseded by bench::host_lock)
deployment         deploy-release-vps.sh, deployment_driver.py,
                   run-dual-vps-canary.sh, validate-deployment-netem.py
                   -> cargo dev deploy {inspect,plan,promote,rollback}
                   (LIVE HOST safety: dry-run/fake testable before deleting)
hotspot/profiling  export-hotspot-bundle.sh, profile-{driver,forensics,report,
                   summarize,built-in-benchmark}, aggregate-hotspot-samples.py,
                   idalib-export-address.py (part of the chain, not obsolete)
                   -> cargo dev perf hotspot; last, 0 CI/gate/release refs
last check gate    test-performance-gates.py is the only external validator still
                   invoked by cargo dev check --all (auto-skips when absent)
```

### Outer workspace cleanup — still pending

`~/work/kimi-rust-reality-performance/` still holds unmanaged state, notably
`artifacts/` (~5.4 GB now; previously ~16 GB). Classify evidence-safely before
deleting anything; never delete the only copy of release/performance evidence.
Preserve `proxy-env.sh`; treat `private/` as sensitive.

Verified reusable artifacts:

```text
artifacts/xray-reference-v26.7.28
  sha256 23d228d78d699306c4782d6b400e2afa97c9bc9f291ae623448b5504904c5268
```

## Closed questions — do not reopen without the recorded revisit condition

```text
CompiledRuntimePlan          no new construct required; RuntimeSnapshot::compile plus
                             ArcSwap<RuntimeSnapshot> already provide it
control-plane bulk cost      ~15 relaxed atomics per connection, lock-free, cannot
                             explain a sustained bulk-throughput gap
relay.bufferBytes            rejected on mechanism; bulk download is Direct + splice
pipe-page exhaustion         0 of 80 concurrent streams downgraded
framed copies/allocations    AVOIDABLE = 0; zero allocations per record, 7 CI gates
4 * MAX_TLS_RECORD_WIRE_LEN  KEEP; it buys syscall amortisation, it is not slack
```

## Next action

After this PR merges:

1. update local main to the new HEAD;
2. remove the merged worktree/build output;
3. recount scripts/;
4. fold vless-encryption and remaining A/B tunnel variants onto the same lifecycle;
5. delete each legacy script once its suite is covered.
