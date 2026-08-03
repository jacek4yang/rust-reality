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

## Geo assets

GeoIP and GeoSite files are downloaded from configured HTTPS URLs. A minimal override only needs
the two sources; cache location, request deadline, size limit, and refresh interval have bounded
defaults:

```json
{
  "assets": {
    "geoip": "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat",
    "geosite": "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat"
  }
}
```

Downloads are conditionally revalidated with HTTP validators. Only a fully parsed generation is
published; an unavailable or invalid update keeps the previous in-memory snapshot and validated
disk cache. Only labels referenced by routing rules are indexed.

## Architecture decisions

Architecture decisions are recorded under [`docs/decisions`](docs/decisions).

## Security

Never commit private keys, UUIDs, credentials, packet captures, access tokens,
or real deployment configuration.
