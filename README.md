# rust-reality

A from-scratch Rust implementation of a VLESS and REALITY server.

The project is developed incrementally through protocol analysis,
interoperability testing, packet capture, and reproducible benchmarks.

## Status

This project is under active development and is not ready for production use.

## Development

Run the complete local quality gate before committing:

```shell
./scripts/check.sh
```

Changes are developed on short-lived branches and merged through pull requests
after automated checks pass.

## Arachitecture decisions

Architecture decisions are recorded under [`docs/decisions`](docs/decisions).

## Security

Never commit private keys, UUIDs, credentials, packet captures, access tokens,
or real deployment configuration.
