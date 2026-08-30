# Development workflow

How to build, validate, and land a change. For repository layout and change
routing see [repository-layout.md](repository-layout.md); for normative rules
that also bind agents see [AGENTS.md](../../../AGENTS.md).

## Toolchain

Use the toolchain pinned by [`rust-toolchain.toml`](../../../rust-toolchain.toml).
The canonical developer interface is `cargo dev` (the `rr-dev` binary in the
independent `tools/` workspace, exposed through a root cargo alias):

```shell
cargo dev --help        # discover the command groups
cargo dev doctor        # diagnose the development/measurement environment
```

Command groups: `doctor`, `check`, `docs`, `repo`, `perf`, `release`, `fuzz`,
`config`, `bench`, `deploy`. Run `cargo dev <group> --help` for details.

## Build

```shell
cargo build --locked                    # production workspace (root + crates/)
cargo build -p rr-dev --manifest-path tools/rr-dev/Cargo.toml --locked   # tooling
cargo build --release --locked          # release profile (thin LTO, codegen-units=1)
```

## Validation escalation

Match validation depth to the change. Do not run the full gate after every edit;
never merge on focused tests alone.

1. **While editing:** focused unit/module tests
   (`cargo test -p rust-reality <module>` or the rr-dev equivalent).
2. **After a coherent slice:** the affected package suite and strict clippy
   (`cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`).
3. **Before PR-ready:** `cargo dev docs check` when documentation changed,
   `cargo dev repo check` when layout changed, relevant integration tests.
4. **Before merge — the full authoritative gate:**

```shell
cargo dev check --all
cargo test --workspace --no-default-features --locked
git diff --check
```

`cargo dev check --all` runs the repository gate: repository-layout and
documentation policy checks, `cargo fmt --all --check`, strict clippy,
`cargo deny`, `cargo doc` with warnings denied, the nextest suite, doc/release
test profiles, bench compilation, and `cargo audit`. CI runs the same gate plus
the musl release build; the Security workflow adds fuzz shards and sanitizers.

## Pull requests

- Open a Draft PR early for substantial work and keep it pushed; the PR/issue is
  the continuation ledger. Hours of work must never exist only on one machine.
- Keep PRs narrowly scoped; explain semantic impact; identify the tests and
  evidence run.
- CI must pass on the exact head SHA you intend to merge — an older green run
  does not validate a newer commit.
- After merging, `git fetch origin` and start the next branch from the updated
  `origin/main`.

## Tooling formatting discipline

Format only files you intentionally touched. Never run `cargo fmt --all` over
the `tools/` workspace casually: the production and tooling workspaces format
separately, and formatter churn on untouched tooling files pollutes review.
