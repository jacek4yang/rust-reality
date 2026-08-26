# Documentation

English | [简体中文](index.zh-CN.md)

## Operator guides

| Document | Purpose |
| --- | --- |
| [Getting started](getting-started.md) | Download, verify, minimal configuration, and the first tunnel. |
| [CLI reference](cli.md) | Every command, option, default, output, signal, and exit behavior. |
| [Configuration reference](configuration.md) | Every JSON field, variant, default, validation bound, routing matcher, and reload rule. |
| [Linux deployment](deployment.md) | Release verification, standalone and line/landing setup, systemd, firewall, files, and upgrades. |
| [Engineering and release program](release-process.md) | Evidence tiers, PR/tag lifecycle, exact candidates, VPS canaries, rollback, and the v1.7→v2.0 train. |
| [Capacity planning and tuning](tuning.md) | Machine profiles, resource knobs, cover-target selection, and latency/throughput diagnosis. |
| [Threat model](threat-model.md) | Security goals, trust boundaries, NXR limitations, resource controls, and non-goals. |
| [Security policy](../SECURITY.md) | Supported versions and private vulnerability reporting. |

## Design and evidence

| Document | Purpose |
| --- | --- |
| [Protocol overview](protocol.md) | The VLESS + REALITY + Vision public stack and the internal NXR hop. |
| [Architecture](architecture.md) | Connection lifecycle, relay backends, descriptor budget, and observability. |
| [Performance](performance.md) | Measured data-plane properties, the ring AEAD provider, and the D1–D11 decision register. |
| [v1.8 memory audit](memory-audit-v1.8.md) | Ownership map, copy ledger, allocation ledger, and async future sizes, with what is deliberately not measured. |
| [Benchmarks](benchmarks.md) | Measurement policy, harnesses, canonical samples, compatibility gate, and limitations. |
| [Architecture decisions](decisions/) | ADRs, including why io_uring was removed. |

## Source of truth

The executable is authoritative for command syntax and configuration shape:

```shell
rust-reality --help
rust-reality COMMAND --help
rust-reality schema > rust-reality.schema.json
rust-reality check --config config.json
```

The JSON Schema describes structural types. `check` additionally applies
cross-field, reference, security, and resource-limit validation documented in
the configuration reference.
