# Contributing to rust-reality

rust-reality is a forward-only project: changes should improve the current
contract rather than preserve obsolete product behavior. Read [AGENTS.md](AGENTS.md)
for the engineering invariants before making a change.

## Development setup

Use the toolchain pinned by [`rust-toolchain.toml`](rust-toolchain.toml). The
canonical developer interface is `cargo dev`, backed by the independent
`tools/` workspace so tooling-only dependencies stay out of production builds.

Before opening a pull request, run the checks relevant to the change. The full
repository gate is:

```text
cargo dev check --all
```

Production tests without default features are also required:

```text
cargo test --workspace --no-default-features --locked
```

Formatting and linting are strict. Check formatting before committing, avoid
unrelated formatting churn in the tooling workspace, and treat every Clippy
warning as an error.

## Project policies

- Keep the production workspace and the independent `tools/` workspace
  separate. Add a crate only for a real architectural boundary; prefer modules
  for ordinary source organization.
- Follow the current benchmark process in
  [the benchmark guide](docs/en/benchmarks.md). Preserve exact identities and
  admissible evidence; do not commit large raw captures or binaries.
- Keep fuzz targets aligned with parser and reconstruction attack surfaces. Use
  `cargo dev fuzz` to inspect and exercise the target catalogue.
- Put human documentation under `docs/`, apart from standard root entry files.
  Maintain the designated English/Chinese pairs and validate them with
  `cargo dev docs check`.
- Record durable architectural decisions in the ADR collection under
  `docs/decisions/`. Active plans and handoffs belong in GitHub issues and pull
  requests, not in the repository.
- Keep machine-readable benchmark contracts, baselines, and compact evidence
  under their corresponding `benchmarks/` directories.

Pull requests should be narrowly scoped, explain semantic impact, identify the
tests and evidence run, and leave no required continuation state only on a local
machine. Report security vulnerabilities according to [SECURITY.md](SECURITY.md),
not in a public issue.
