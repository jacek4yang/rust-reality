# Documentation

English | [简体中文](../zh-CN/index.md)

## Start here

| Document | Purpose |
| --- | --- |
| [Getting started](getting-started.md) | Install, generate material, write a configuration, connect a client. |
| [How configuration works](configuration/index.md) | The rules that hold across the whole file: roles, names, defaults, secrets, reload. |
| [Troubleshooting](operations/troubleshooting.md) | Organised by symptom, starting with the two failures that account for most of them. |

## Configuration

| Document | Purpose |
| --- | --- |
| [Standalone node](configuration/standalone.md) | Build a single-node configuration one decision at a time. |
| [Users and credentials](configuration/users-and-credentials.md) | What to generate, which half goes where, how to rotate it. |
| [Cover targets](configuration/cover-targets.md) | Choosing and validating the host this server impersonates. |
| [Outbounds](configuration/outbounds.md) | The two built-in outbounds and the three you can declare. |
| [Routing](configuration/routing.md) | Rules, matchers, per-user policies, and geo data. |
| [Line and landing nodes](configuration/line-landing.md) | Two machines, so the IP clients reach is not the IP traffic leaves from. |
| [Handoff](configuration/handoff.md) | The same topology, with a landing that cannot read what it forwards. |
| [Multiple landings](configuration/multi-landing.md) | Several exits, chosen per user. |
| [DNS and network](configuration/dns-and-network.md) | Resolvers, caching, and outbound address-family policy. |
| [Runtime and resources](configuration/runtime-and-resources.md) | Machine posture, derived limits, and when pinning is justified. |
| [Configuration reference](configuration/reference.md) | Every object, field, type, default, and reload rule. |

## Operations

| Document | Purpose |
| --- | --- |
| [Linux deployment](operations/deployment.md) | Release verification, systemd, firewall, files, and upgrades. |
| [CLI reference](cli.md) | Every command, option, default, output, signal, and exit behavior. |
| [Threat model](threat-model.md) | Security goals, trust boundaries, NXR limitations, and non-goals. |
| [Engineering and release program](release-process.md) | Evidence tiers, PR/tag lifecycle, canaries, rollback. |
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
rust-reality check -c config.json
```

A JSON Schema for editor completion is attached to each GitHub release, and
maintainers can generate one with `cargo dev config schema`.

The JSON Schema describes structural types. `check` additionally applies
cross-field, reference, security, and resource-limit validation documented in
the configuration reference.
