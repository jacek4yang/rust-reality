# rust-reality Engineering Constitution

This file is the normative engineering constitution for every contributor —
human and autonomous coding agent alike — working in the rust-reality
repository. It is binding law, not advice.

- **MUST / MUST NOT / REQUIRED / SHALL / SHALL NOT** are binding requirements.
  An agent MUST NOT silently reinterpret them as suggestions.
- **SHOULD / SHOULD NOT** may be deviated from only with a documented, concrete
  repository-engineering reason recorded in the PR or ADR that introduces the
  deviation.
- **MAY** is genuinely optional.

An agent MUST NOT modify this file to make its current task easier, to bypass a
failing check, to remove a safety boundary, to permit an otherwise-forbidden
artifact, to reduce testing requirements, or to hide an architectural violation.
Every modification to this file MUST have a real repository-engineering
rationale, be reviewable on its own, and be justified in the commit/PR that
carries it. Structural requirements of this constitution are enforced natively
by `cargo dev repo check` and `cargo dev docs check`; weakening those gates is
subject to the same rule.

## 1. Scope and authority

This constitution governs all work on the rust-reality repository: source,
tests, benchmarks, tooling, documentation, CI, releases, and repository
structure. It binds human contributors and autonomous coding agents (Codex,
Claude Code, Kiro, GLM, and any other capable agent) equally.

Conflicting information is resolved by this precedence model:

**Permanent engineering rules** (architecture, invariants, process law):

1. normative rules in this file;
2. accepted ADRs in `docs/adr/`;
3. current code, tests, schemas, and contracts.

**Current execution state** (what is happening right now):

1. valuable local uncommitted WIP (assessed, never destroyed blindly);
2. actual local Git state (HEAD, branch, staged/unstaged/untracked);
3. fetched remote Git state (`origin/*` after `git fetch`);
4. current GitHub PR/Issue/CI state;
5. static prose that refers to old state — which MUST NEVER override any of the
   above. Stale prose (old PR bodies, old issues, old documentation, old
   handoff files) is a record of the past, not a description of the present.

**Product behavior** (what the program does):

1. current implementation + tests/schema/contracts;
2. current reference documentation (`docs/en/`, `docs/zh-CN/`);
3. historical release material (CHANGELOG, release notes).

**Architecture decisions**: an accepted current ADR outranks any old
investigation diary, note, or superseded document. Where an ADR and code
disagree, that is a defect to surface — not an invitation to pick either
silently.

## 2. Fast entry procedure (mandatory for fresh sessions)

Every fresh session — human or agent — SHALL follow this sequence before
modifying anything:

1. Read this file completely.
2. Inspect current Git/worktree state before modifying anything:

   ```shell
   git worktree list --porcelain
   pwd && git branch --show-current && git rev-parse HEAD
   git status && git diff --stat && git diff --cached --stat
   git log --oneline -10 && git remote -v
   ```

3. Fetch origin before assuming remote/main/PR state:

   ```shell
   git fetch origin
   ```

4. Identify the subsystem that owns the intended change — see
   `docs/en/development/repository-layout.md` for the ownership map.
5. Read the canonical subsystem documentation and relevant ADRs under
   `docs/adr/`.
6. Use `cargo dev` as the repository-owned tooling (`cargo dev --help`;
   the alias is defined in `.cargo/config.toml`).
7. Run focused validation while implementing (see §14).
8. Commit and push coherent checkpoints (see §13).
9. Run the full required gates before merge (see §15).
10. Put transient execution state in the current PR or issue — never in tracked
    repository files (see §22).

## 3. Project mission

rust-reality is a Linux-focused, single-binary VLESS + REALITY + Vision proxy
server with an optional NXR/Handoff line-to-landing topology. The current
product contract — Xray-core-compatible public VLESS + REALITY + Vision data
path, REALITY fallback byte-exactness, authentication, replay safety, bounded
resources, and measured performance — is the only contract. Product scope is
documented in `README.md` and the threat model (`docs/en/threat-model.md`);
the operator-facing references live under `docs/en/` and `docs/zh-CN/`.

## 4. Forward-only project

rust-reality supports the **current contract only**. Backward compatibility
between rust-reality releases is **not a design goal**. Breaking changes are
acceptable whenever they produce a better architecture, configuration model,
runtime model, performance profile, security posture, operational workflow,
API, CLI, or implementation.

Contributors MUST NOT add complexity so that an old rust-reality version keeps
working. They MUST NOT preserve obsolete configuration syntax, legacy aliases,
migration engines, deprecated runtime behavior, compatibility shims, or old
operational semantics merely because an earlier release used them.

## 5. One canonical model

Each concept has exactly one canonical representation:

    one concept -> one configuration representation -> one implementation
    path -> one documented meaning

Contributors MUST NOT create old-field/new-field pairs, alias + canonical
fields, legacy parser + current parser pairs, compatibility adapters, multiple
equivalent CLI workflows, or migration pipelines embedded in production code.

## 6. Protocol compatibility ≠ product compatibility

External interoperability required for **current** operation is mandatory and
MUST stay correct: the VLESS wire protocol, REALITY interoperability, TLS
behavior of real peers, supported operating-system interfaces, and currently
supported external ecosystem formats. Current Xray interoperability MUST be
preserved in every optimization.

The following never justify compatibility machinery: old rust-reality JSON
keys, old defaults, removed CLI flags, historical serialization choices,
previous internal APIs, old runtime policy names, or accidental behavior of
old releases.

## 7. Deletion is progress

Prefer deleting obsolete code over abstracting it. Contributors MUST NOT
replace compatibility machinery with a framework for maintaining it. Minimize
branches, modes, aliases, version checks, transitional types, migration
fixtures, deprecated state, and duplicated representations. Git history is the
archive; the working tree represents the current product.

## 8. No speculative frameworks

Contributors MUST NOT build infrastructure for hypothetical future versions:
no generic schema-migration engines, version registries, compatibility DSLs,
converter chains, or extensibility abstractions without a current requirement.
When a future version needs a better design, change the canonical design
directly. Defaults and automatic behavior are chosen because they are best for
the current version, not because an old version behaved that way; automatic
behavior MAY use reliable environment detection and MUST remain deterministic,
explainable, and explicitly overridable.

## 9. One current configuration schema

rust-reality maintains exactly one configuration schema at any time. A breaking
configuration change **replaces** the schema; it MUST NOT add a parser beside
the previous one. The repository does not accumulate historical schemas, and a
schema or version identifier MAY describe the one current contract for
diagnostics but MUST NOT select a parser.

Contributors MUST NOT add, for configuration: `serde(alias)` for renamed fields,
legacy or deprecated field names, silently ignored unknown properties,
compatibility structs, version-dispatched schema selection, in-binary migration
or normalization of old configurations, compatibility feature flags or runtime
modes, or extension buckets (such as a flattened `HashMap<String, Value>`) whose
purpose is to let a future version ignore unknown values.

An old configuration MUST fail. Removed configuration fields are rejected
strictly; recognizing a removed field name solely to emit a targeted fatal error
naming its replacement is acceptable, accepting it is not.

This rule is scoped to configuration. It grants nothing with respect to the
external interoperability §6 requires.

Breaking changes are documented concisely in `CHANGELOG.md`. The complete
operator-facing old→new migration procedure goes into the GitHub Release notes
of the release that introduces the break, ending with
`rust-reality check --config config.json`. The production binary MUST NOT
contain a version-to-version migration engine, and the repository MUST NOT keep
a migration-guide archive.

The reasoning and the current schema's design are recorded in
[ADR 0019](docs/adr/0019-one-current-configuration-schema.md).

## 10. Diagnostics are part of the product

Configuration errors MUST be precise, source-oriented, and actionable —
file:line:column, the offending source excerpt with a caret/span, what was
expected versus received, and a trustworthy remediation hint when obvious.
Parsing stays strict: better errors are not compatibility. Diagnostics MUST NOT
leak secrets and MUST stay off the network hot path.

## 11. Repository taxonomy

The canonical directory ownership map lives in
`docs/en/development/repository-layout.md` and is enforced structurally by
`cargo dev repo check`. The load-bearing rules:

- The production workspace (root package + `crates/`) and the tooling workspace
  (`tools/`) are independent. Tooling-only dependencies MUST NOT leak into the
  production dependency graph, and repository tooling MUST NOT be linked into
  the production binary without an explicit architecture decision (ADR).
- A new crate is created only for a real dependency boundary, platform
  boundary, `no_std`/`alloc` boundary, reusable API, or architectural isolation
  requirement. Ordinary internal ownership uses modules; contributors MUST NOT
  create micro-crates for directory symmetry.
- Human-maintained documentation lives under `docs/` (English `docs/en/`,
  Chinese `docs/zh-CN/`, decisions `docs/adr/`) except the standard root entry
  files (`README.md`, `README.zh-CN.md`, `CONTRIBUTING.md`, `CHANGELOG.md`,
  `SECURITY.md`, `AGENTS.md`, licenses).
- Exact colocated ownership references (`benchmarks/README.md` and
  `tools/reference/README.md`) and durable evidence documents below
  `benchmarks/evidence/` are owned by those trees; they MUST NOT become a
  second home for general human documentation.
- Machine-readable benchmark data lives under `benchmarks/` — contracts in
  `benchmarks/contracts/`, baselines in `benchmarks/baselines/`, durable
  compact evidence in `benchmarks/evidence/` — never under `docs/`.
- One canonical location and owner per file category. Forbidden artifacts are
  enumerated in §22.

## 12. Architecture and dependency direction

The accepted layering (ADR 0008) is:

    Application  ->  Session Engine  ->  Runtime Adapter  ->  Transport  ->  Linux

- `crates/rr-session` (Session Engine) is runtime-independent: synchronous,
  data-only state machines and decisions. It MUST NOT depend on Tokio, socket
  types, file descriptors, DNS, filesystem APIs, process-global logging, or OS
  clocks/randomness. Time, randomness, and I/O outcomes enter as explicit
  inputs; the engine returns decisions.
- `crates/rr-linux` is the only place raw-syscall unsafe lives; the main crate
  stays `#![deny(unsafe_code)]`.
- Dependency direction flows strictly downward in the layering above. A layer
  MUST NOT depend on a layer above it.
- Transport ownership is exclusive: exactly one owner for every socket at every
  moment; the Session Engine issues one-shot grants that are neither `Clone`
  nor `Copy`.
- Re-exporting a moved type during a bounded, reviewed migration is
  acceptable; maintaining two independent state machines for one concept is
  not.

## 13. Git and worktree safety

- Normal work MUST NOT modify `main` directly. Use coherent branches/worktrees.
- `git fetch origin` MUST precede any assumption about remote, main, or PR
  state.
- Force-pushes REQUIRE a justified reason recorded in the PR; otherwise they
  are forbidden.
- Merging with required checks failing is forbidden.
- CI matters at the exact head SHA intended for merge; an older green run does
  not validate a newer commit.
- After a merge, `git fetch origin` and verify `origin/main` contains the merge
  before starting the next transaction. Do not stack a new PR on stale
  pre-merge main unless the stacking is intentional and stated.
- **Before any destructive Git operation** (`git reset --hard`, `git clean`,
  `git restore .`, `git checkout .`, `git switch`, `git rebase`, `git pull`,
  `git merge`), an agent MUST first inspect:
  `git worktree list --porcelain`, `pwd`, current branch, HEAD,
  `git status`, staged diff, unstaged diff, untracked files, recent log, and
  remotes — then `git fetch origin`, and compare local state, remote branch,
  and current PR/issue state to determine whether valuable WIP exists. An agent
  MUST NOT begin a takeover with a destructive operation before that valuation.

### Takeover/recovery protocol (interrupted sessions)

Agents lose quota, context, and process state; interruption is normal. An
agent taking over existing work SHALL:

1. inspect all state listed above, preserving anything newer than the last
   verified remote head;
2. locate the relevant PR/issue and treat its body/comments as the continuation
   ledger;
3. continue the existing branch/PR rather than starting over;
4. never redo durable, externally verified work;
5. record the recovered state as a comment on the PR/issue before proceeding.

## 14. Durability and testing escalation

Work is committed in coherent slices:

    coherent change -> focused validation -> git diff --check -> commit -> push

For substantial work, a Draft PR is opened early and pushed to; the PR/issue is
the continuation ledger. An agent MUST NOT keep hours of valuable work only in
local dirty state, model conversation, or ephemeral terminal output.

Validation escalation (do not run the most expensive suite after every edit;
do not merge on focused tests alone):

1. **While editing:** focused unit/module tests.
2. **After a coherent slice:** affected package/module suite; strict clippy for
   the touched workspace.
3. **Before PR-ready:** documentation checks when docs changed; repository
   layout check when layout changed; affected integration tests.
4. **Before merge — full authoritative gates:**

   Production workspace:

   ```shell
   cargo fmt --all -- --check
   cargo test --workspace --locked
   cargo test --workspace --no-default-features --locked
   cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
   cargo dev check --all
   git diff --check
   ```

   Tooling workspace:

   ```shell
   cargo test  --manifest-path tools/rr-dev/Cargo.toml -p rr-dev --locked
   cargo clippy --manifest-path tools/rr-dev/Cargo.toml --all-targets --all-features --locked -- -D warnings
   ```

Formatting is applied only to intentionally touched files. Contributors MUST
NOT run `cargo fmt --all` over the tooling workspace casually — recursive
formatter churn on unrelated tooling files is a known review hazard.

## 15. CI failure classification

Every CI failure MUST be classified before any fix is attempted:

- **A. Repository/code regression** — the change is wrong. Identify the first
  root-cause commit, reproduce/reduce, fix the root cause, run focused
  validation, push, and require exact-head CI.
- **B. Deterministic CI/environment-contract defect** — the workflow or
  environment contract is wrong. Fix the contract in a reviewed change.
- **C. Transient infrastructure/network failure** — re-run; do not modify
  product code to hide infrastructure noise.

Agents MUST NOT shotgun random changes at the last visible error line.
Repeated CI failure without root-cause identification is a stop-and-escalate
condition (§24).

## 16. Performance engineering law

Protocol correctness and security outrank benchmarks. Contributors MUST NOT
trade REALITY/VLESS compatibility, byte correctness, authentication, replay
safety, timeout bounds, cancellation safety, or FD accounting for performance.

Any material performance optimization MUST follow the full sequence:

    hypothesis -> baseline -> profiling evidence -> targeted source change
    -> before/after measurement -> correctness/interoperability validation
    -> accept or revert

Contributors MUST NOT optimize solely from intuition, MUST NOT game benchmark
inputs, MUST NOT accept a speedup that breaks correctness or interoperability,
and MUST NOT publish selective favorable numbers. Every performance-relevant
source change is traced to PMU, syscall, or allocation evidence, and the
generated machine code of material hot paths is inspected.

Experiments with no repeatable benefit are reverted, not explained away;
durable rejected strategies become ADRs (with evidence and revisit conditions).
Profiling instrumentation stays off production hot paths. Exact binary
identities and the raw evidence behind every number are retained; retained
evidence lives under `benchmarks/` per §11.

## 17. Fuzz engineering law

Fuzz coverage is a security/correctness discipline. A new parser, decoder, or
reconstruction path MUST ship with a fuzz target in the same change. Fuzz-only
hooks MUST stay outside production behavior. The canonical target catalogue and
commands are documented in `docs/en/development/fuzzing.md`; the manifest is
validated by `cargo dev fuzz targets` and exercised by CI smoke shards.

## 18. Documentation rules

Documentation has one owner per kind of information — duplicate prose copies
are forbidden:

- **code/rustdoc** — detailed API behavior;
- **AGENTS.md** (this file) — normative engineering law;
- **architecture docs** (`docs/en/architecture.md`) — the system mental model;
- **reference docs** (`docs/en/` operator guides) — stable user/operator
  contracts;
- **CONTRIBUTING.md** — the human development entrypoint;
- **ADRs** (`docs/adr/`) — why durable architecture decisions exist;
- **GitHub PR/Issue** — current work.

Every user/developer document intended for both audiences is mirrored:
`docs/en/<path>.md` ⇄ `docs/zh-CN/<path>.md`. Designated pairs are validated by
`cargo dev docs check`. ADRs are canonical English technical records and are
not translated. The executable remains authoritative for command syntax and
configuration shape.

## 19. ADR rules

A durable architectural decision — boundary, security invariant, ownership
change, important rejected strategy, or external-reference boundary — MUST be
recorded as an ADR under `docs/adr/`. A debugging diary, CI failure note, PR
progress note, or migration checklist MUST NOT become an ADR. Conventions
(numbering, status vocabulary, evidence references) live in
`docs/adr/README.md`.

## 20. Secrets, private, and proprietary material

Contributors MUST NOT commit or expose: REALITY private keys, VLESS user
UUIDs/secrets, passwords/tokens, SSH private keys, operator SSH configuration
secrets, private machine configuration, sensitive proxy configuration,
proprietary IDA binaries/libraries/license material, or IDA databases.

Safe durable representations are hashes, fingerprints, redacted snapshots,
logical SSH role aliases (operator OpenSSH configuration owns transport and
authentication details), and secret-free evidence. Existing normalized IDALib
evidence remains valid; the local IDA installation is external proprietary
software and MUST NOT be modified, committed, or referenced as project policy.

## 21. Remote inspection and live-mutation authorization

Repository write permission ≠ SSH inspection permission ≠ live-host mutation
authorization. An agent MUST NOT infer live infrastructure authorization from
the ability to push code, from existing SSH connectivity, from old conversation
approval, or from a previous unrelated deployment waiver.

Live mutation (deploying binaries, restarting/reloading services, mutating
firewall state) requires task-specific explicit operator authorization under the
current project policy, carried by `cargo dev deploy`'s typed
acknowledgement flags. Remote management documentation uses logical role names
only; private operator endpoints MUST NOT be hard-coded into the repository.

## 22. Forbidden repository artifacts

The following MUST NOT be created in the repository; where they exist they are
deleted on sight. `cargo dev repo check` enforces the structural core
(root allowlist with an explicit owner for every entry, forbidden directories,
transient-state and model-conversation paths, competing agent policy files,
human-document ownership, canonical onboarding paths and links, ADR naming,
status metadata and exact index consistency, benchmark data taxonomy, zero
active shell/Python files, bounded tracked-object size, and narrow machine-path
hygiene), so violating the taxonomy fails the build gate rather than relying
on reviewer vigilance:

- `scripts/` (repository-owned shell/Python policy is zero);
- `notes/` and any execution-state tree;
- transient state files: `CURRENT.md`, `STATUS.md`, `TODO.md`, `PLAN.md`,
  `HANDOFF.md`, `agent-state.json`, `normalization-state.json`, and any
  machine-readable progress ledger;
- arbitrary root JSON/data dumps and temporary benchmark result dumps;
- machine-readable data under `docs/`;
- model-conversation exports;
- vendor-specific agent policy files (`CLAUDE.md`, `CODEX.md`, `KIRO.md`,
  `GPT.md`, `AI_RULES.md`, per-agent prompt directories). A platform that
  technically requires its own entry file MAY contain only a minimal pointer to
  this file and the canonical docs;
- arbitrary generated files without a canonical owner.

The two non-executable shell/Python files below
`benchmarks/evidence/objects/sha256/` are immutable, content-addressed historical
evidence, not active repository policy. Any active shell/Python file elsewhere
is forbidden.

Current execution state belongs in Git commits, GitHub PRs/issues, and CI.
Permanent engineering knowledge belongs in canonical documentation; durable
decisions belong in ADRs.

## 23. Required merge gates

A change merges only when, at the exact head SHA:

1. the focused and slice-level validation of §14 has run locally;
2. the full authoritative gates of §14 pass locally;
3. GitHub CI succeeds on that exact head;
4. GitHub Security succeeds on that exact head;
5. `git diff --check` is clean.

Existing gates MUST NOT be weakened or deleted to make a change easier. If a
gate is genuinely wrong, fixing it is a reviewed change with a documented
reason.

## 24. Stop and escalation conditions

An agent MUST stop and escalate to the operator when:

- a genuine safety or evidence ambiguity requires an operator decision
  (e.g. whether unique evidence may be removed, whether a live system may be
  touched);
- an irreducible external blocker exists after all independent work is durable
  (committed and pushed);
- CI fails repeatedly without an identifiable root cause after honest
  classification (§15);
- completing a task would require violating this constitution.

An agent MUST NOT stop merely because a milestone segment merged, a file moved,
or CI is running. Before stopping for any reason, an agent MUST ensure the
current work is committed, pushed, and accurately reflected in the PR/issue
ledger so the next session can reconstruct the state.

## 25. Canonical documentation routing

| Need | Go to |
| --- | --- |
| Project overview, features, quick links | [README.md](README.md) / [README.zh-CN.md](README.zh-CN.md) |
| Human contribution entry | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Normative agent law | this file |
| Directory ownership, change routing | [repository layout](docs/en/development/repository-layout.md) |
| Build, tooling, validation ladder, PR rules | [development workflow](docs/en/development/development-workflow.md) |
| Test layers and gates | [testing guide](docs/en/development/testing.md) |
| Fuzz targets and commands | [fuzzing guide](docs/en/development/fuzzing.md) |
| System mental model | [architecture](docs/en/architecture.md) |
| Measurement policy and evidence | [benchmarks](docs/en/benchmarks.md), [performance](docs/en/performance.md) |
| Security boundaries | [threat model](docs/en/threat-model.md), [security policy](SECURITY.md) |
| Durable decisions | [ADR index](docs/adr/README.md) |
| Release engineering | [release process](docs/en/release-process.md) |
| CLI/configuration/deployment contracts | [CLI](docs/en/cli.md), [configuration](docs/en/configuration.md), [deployment](docs/en/deployment.md) |
| Chinese mirrors | [Chinese documentation index](docs/zh-CN/index.md) |
