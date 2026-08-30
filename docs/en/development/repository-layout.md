# Repository layout and change routing

This document maps what each directory owns and where a given kind of change
belongs. The [architecture overview](../architecture.md) explains how the layers
interact; this page explains where the files live and who owns them.

## Workspace structure

The repository contains two independent Cargo workspaces. The production
workspace (root `Cargo.toml`: the `rust-reality` package plus `crates/`) and the
tooling workspace (`tools/Cargo.toml`). Tooling-only dependencies never enter
the production dependency graph; see [ADR 0001](../../adr/0001-start-with-a-single-cargo-package.md)
for the original packaging decision.

## Directory ownership map

| Directory | Owns |
| --- | --- |
| `src/` | Production application implementation: configuration model and diagnostics, protocol (VLESS, REALITY, Vision, TLS 1.3, Handoff, NXR), runtime orchestration, server lifecycle, transport, crypto key generation, CLI-facing library surface. |
| `crates/rr-session/` | The runtime-independent Session Engine: synchronous, data-only session state machines and decisions (direction phases, raw-relay grants, transfer commits). `no_std`-capable; no Tokio, sockets, clocks, or OS APIs. |
| `crates/rr-linux/` | The Linux-specific OS/ABI boundary: raw syscalls, rlimits, socket options, memory policy. Isolated so the main crate can stay `#![deny(unsafe_code)]`. |
| `tools/rr-dev/` | The repository development control plane (`cargo dev`): quality gates, documentation checks, repository-layout policy, performance evaluation, release packaging, fuzz manifest, benchmark lifecycle, deployment engineering. |
| `tools/reference/` | Deliberately independent reference mechanisms (e.g. the OpenSSL TLS-shape reference program) kept outside production and outside rr-dev so cross-implementation comparisons stay honest. |
| `tools/fixtures/` | Tooling and test fixtures shared by repository tooling (e.g. active-probe cases). |
| `docs/` | Human-maintained canonical documentation. English under `docs/en/`, Chinese under `docs/zh-CN/`, architecture decisions under `docs/adr/`. |
| `docs/adr/` | Architecture decision records. Indexed in [docs/adr/README.md](../../adr/README.md). |
| `benchmarks/contracts/` | Machine-readable benchmark contracts and thresholds enforced by tooling. |
| `benchmarks/baselines/` | Canonical baseline identities and measurements used by current checks or documentation. |
| `benchmarks/evidence/` | Compact durable evidence: acceptance manifests, checksummed golden objects, release evidence. |
| `benches/` | Production Cargo benchmarks. |
| `fuzz/` | Fuzz targets covering the externally reachable attack surface. |
| `tests/` | Integration validation for the production package. |
| `deploy/` | Service packaging (systemd unit). |
| `examples/` | Rust example consuming the library surface. |

General human documentation belongs under `docs/` or in the standard root
entry files. Two exact colocated ownership references are part of their owning
trees: `benchmarks/README.md` defines the benchmark-data categories and
`tools/reference/README.md` defines the independent comparator boundary.
Markdown below `benchmarks/evidence/` is durable evidence, not a second
documentation hierarchy.

## Where should I change this?

| Change intent | Owner |
| --- | --- |
| Configuration schema, validation, diagnostics | `src/config/` |
| VLESS / REALITY / Vision / TLS 1.3 protocol behavior | `src/protocol/` |
| Runtime orchestration, snapshots, generation management | `src/runtime/` |
| Server lifecycle, routing, admission | `src/server/` |
| Transport, descriptor lifetime/accounting, and raw-relay backends | `src/transport/` (with `crates/rr-linux/` where an OS mechanism is involved) |
| Runtime-independent session state transitions | `crates/rr-session/` |
| Linux kernel/platform mechanisms | `crates/rr-linux/` |
| Developer tooling, gates, benchmark/deploy commands | `tools/rr-dev/` |
| Independent comparator or reference mechanism | `tools/reference/` |
| Benchmark contract data | `benchmarks/contracts/` |
| Baseline identities and measurements | `benchmarks/baselines/` |
| Durable evidence objects/manifests | `benchmarks/evidence/` |
| Durable architectural decision | `docs/adr/` (new numbered ADR) |
| Operator/user documentation | `docs/en/` + mirrored `docs/zh-CN/` |
| Fuzz coverage for a new parser/decoder | `fuzz/fuzz_targets/` |

## Paths that must not be created

`scripts/`, `notes/`, `tools/inventory/`, transient state files (`STATUS.md`,
`PLAN.md`, `HANDOFF.md`, `TODO.md`, `CURRENT.md`), arbitrary root JSON/data
dumps, machine-readable data under `docs/`, or vendor-specific agent policy
files (`CLAUDE.md`, `CODEX.md`, and similar — `AGENTS.md` is the one canonical
agent constitution).

`cargo dev repo check` enforces all of this structurally: the explicitly owned
root allowlist, forbidden directories, transient/model-state paths, competing
agent policy files, human-document ownership, canonical onboarding paths and
links, ADR numbering/status/index consistency, benchmark data taxonomy, zero
active shell/Python files, a reviewable tracked-object size bound, and narrow
machine-path hygiene. `cargo dev docs check` separately owns bilingual pairs
and general link correctness; `cargo dev check --all` composes both authorities.
See [AGENTS.md](../../../AGENTS.md).
