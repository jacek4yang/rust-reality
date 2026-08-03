# Documentation

English | [简体中文](index.zh-CN.md)

## Operator guides

| Document | Purpose |
| --- | --- |
| [CLI reference](cli.md) | Every command, option, default, output, signal, and exit behavior. |
| [Configuration reference](configuration.md) | Every JSON field, variant, default, validation bound, routing matcher, and reload rule. |
| [Linux deployment](deployment.md) | Release verification, standalone and line/landing setup, systemd, firewall, files, and upgrades. |
| [Threat model](threat-model.md) | Security goals, trust boundaries, NXR limitations, resource controls, and non-goals. |
| [Benchmark policy](benchmarks.md) | Reproducible measurements, recorded baselines, and interpretation limits. |
| [Security policy](../SECURITY.md) | Supported versions and private vulnerability reporting. |

## Engineering evidence

These documents preserve design and compatibility evidence. They are written in
English so commands, wire names, and audit references remain identical to their
source material.

- [Xray 26.7.28 interoperability](testing/xray-26.7.28-interop.md)
- [`rust-reality.7z` reuse audit](audits/rust-reality-7z.md)
- [Architecture decisions](decisions/)

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
