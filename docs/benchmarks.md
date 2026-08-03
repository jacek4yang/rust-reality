# Benchmark policy and baseline

## Built-in protocol measurements

Run an optimized binary on an otherwise idle host:

```shell
./scripts/build-release.sh
target/release/rust-reality benchmark \
  --duration-ms 5000 \
  --warmup-ms 1000 \
  > benchmark.json
```

The JSON records build mode, embedded commit, target OS and architecture,
visible CPU count, requested timings, operation counts, aggregate mean, and
per-sample p50/p95. Each case uses nine independent windows. Reported MiB/s is
logical input throughput for the named in-process operation; it is not socket,
proxy, or Internet throughput.

Criterion remains the tool for regression analysis with baselines and plots:

```shell
cargo bench --bench vless_decode
cargo bench --bench vision
```

## Recorded development-host sample

This sample is evidence that the command runs and produces stable bounded data,
not a release performance promise:

- Date: 2026-08-03 (Asia/Shanghai)
- Host: Intel Core i3-8100, 4 logical CPUs
- Kernel: Linux 6.12.94+deb13-amd64
- Rust: 1.96.0
- Measured time: 900 ms per case, 100 ms warm-up
- `vless.decode.ipv4`: 26.99 ns/op, 37.06 million ops/s
- `vision.decode.8k`: 164.93 ns/op, 6.06 million ops/s
- `nxr.auth.encode.domain`: 1237.62 ns/op, 0.808 million ops/s

For a comparison, preserve the complete JSON and repeat runs in randomized
implementation order on the same host, CPU governor, kernel, target, payload,
concurrency, and network impairment. Report every sample and confidence
interval; do not select the fastest run.

## Xray compatibility versus performance

`scripts/test-xray-interop.sh` is a compatibility gate: an unmodified Xray
26.7.28 client transfers a verified payload through the real public VLESS +
REALITY + Vision stack. Its one Internet request is not a benchmark.

Any future Xray performance comparison must separate:

- loopback protocol CPU cost;
- same-host relay throughput at fixed concurrency;
- controlled delay/loss/rate tests with `tc netem`;
- real-web samples whose DNS, origin, and Internet variance are disclosed.

No result may claim resistance to upstream volumetric DDoS or generalize one VPS
measurement to other CPUs and networks.
