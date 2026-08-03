# rust-reality

A from-scratch Rust implementation of a VLESS and REALITY server.

The project is developed incrementally through protocol analysis,
interoperability testing, packet capture, and reproducible benchmarks.

## Status

This project is under active development and is not ready for production use.

## Development

The repository uses stable Rust and cargo-nextest 0.9.140.

Install the test runner:

```bash
cargo install cargo-nextest --version 0.9.140 --locked
```

Run the complete repository validation:

```shell
./scripts/check.sh
```
## Benchmarks

Run the protocol microbenchmarks with:

```bash
cargo bench --bench vless_decode
```

Criterion writes reports below `target/criterion/`.

Benchmark results are intended for comparisons on the same host and under the same system
conditions. End-to-end comparisons against Xray are recorded separately and are not enforced as CI pass/fail thresholds.

## Architecture decisions

Architecture decisions are recorded under [`docs/decisions`](docs/decisions).

## Security

Never commit private keys, UUIDs, credentials, packet captures, access tokens,
or real deployment configuration.
