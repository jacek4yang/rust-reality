# Documentation

English | [简体中文](../zh-CN/index.md)

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
| [Security policy](../../SECURITY.md) | Supported versions and private vulnerability reporting. |

## Design and evidence

| Document | Purpose |
| --- | --- |
| [Protocol overview](protocol.md) | The VLESS + REALITY + Vision public stack and the internal NXR hop. |
| [Architecture](architecture.md) | Connection lifecycle, relay backends, descriptor budget, and observability. |
| [Performance](performance.md) | Measured data-plane properties, the ring AEAD provider, and the D1–D11 decision register. |
| [v1.8 memory audit](operations/memory-audit-v1.8.md) | Ownership map, copy ledger, allocation ledger, and async future sizes, with what is deliberately not measured. |
| [Performance investigation record](operations/performance-investigation-record.md) | Durable conclusions of closed performance investigations: control-path ledger, rejected mechanisms, historical throughput question. |
| [Frozen evaluator specification](operations/frozen-evaluator-specification.md) | Methodology contract of `cargo dev perf evaluate` and the legacy semantics reproduced exactly. |
| [Fuzz attack-surface map](operations/fuzz-attack-surface.md) | Every externally reachable parser mapped to its fuzz target, with recorded gap justifications. |
| [Benchmarks](benchmarks.md) | Measurement policy, harnesses, canonical samples, compatibility gate, and limitations. |
| [Architecture decisions](../adr/README.md) | ADRs, including why io_uring was removed. |

## Contributing

| Document | Purpose |
| --- | --- |
| [Contributing guide](../../CONTRIBUTING.md) | How to set up, validate, and land a change. |
| [Repository layout and change routing](development/repository-layout.md) | What each directory owns and where a given kind of change belongs. |
| [Development workflow](development/development-workflow.md) | Build, `cargo dev` tooling, the validation escalation ladder, and PR rules. |
| [Testing](development/testing.md) | The validation layers, focused runs, and the tooling gate. |
| [Fuzzing](development/fuzzing.md) | Attack-surface coverage, targets, and commands. |
| [Engineering constitution](../../AGENTS.md) | Normative rules for contributors and coding agents. |

## Source of truth

The executable is authoritative for command syntax and configuration shape:

```shell
rust-reality --help
rust-reality COMMAND --help
cargo dev config schema > rust-reality.schema.json
rust-reality check --config config.json
```

The JSON Schema describes structural types. `check` additionally applies
cross-field, reference, security, and resource-limit validation documented in
the configuration reference.
