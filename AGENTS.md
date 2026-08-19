# rust-reality Engineering Doctrine

This file is the authoritative engineering policy for human contributors and
AI coding agents. Read it before changing anything. It is deliberately short.

## 1. Forward-only project

rust-reality supports the **current contract only**. Backward compatibility
between rust-reality releases is **not a design goal**. Breaking changes are
acceptable whenever they produce a better architecture, configuration model,
runtime model, performance profile, security posture, operational workflow,
API, CLI, or implementation.

Never add complexity so that an old rust-reality version keeps working. Do
not preserve obsolete configuration syntax, legacy aliases, migration
engines, deprecated runtime behavior, compatibility shims, or old operational
semantics merely because an earlier release used them.

## 2. One canonical model

Each concept has exactly one canonical representation:

    one concept -> one configuration representation -> one implementation
    path -> one documented meaning

Rejected patterns: old field + new field, alias + canonical field, legacy
parser + current parser, compatibility adapters, multiple equivalent CLI
workflows, migration pipelines embedded in production code.

## 3. Protocol compatibility ≠ product compatibility

External interoperability required for **current** operation is mandatory and
must stay correct: the VLESS wire protocol, REALITY interoperability, TLS
behavior of real peers, supported operating-system interfaces, and currently
supported external ecosystem formats.

The following never justify compatibility machinery: old rust-reality JSON
keys, old defaults, removed CLI flags, historical serialization choices,
previous internal APIs, old runtime policy names, or accidental behavior of
old releases.

## 4. Deletion is progress

Prefer deleting obsolete code over abstracting it. Do not replace 1,000 lines
of compatibility machinery with a framework for maintaining them. Minimize
branches, modes, aliases, version checks, transitional types, migration
fixtures, deprecated state, and duplicated representations. Git history is
the archive; the working tree represents the current product.

## 5. No speculative frameworks

Do not build infrastructure for hypothetical future versions: no generic
schema-migration engines, version registries, compatibility DSLs, converter
chains, or extensibility abstractions without a current requirement. When a
future version needs a better design, change the canonical design directly.

## 6. Current quality over historical equivalence

Defaults and automatic behavior are chosen because they are best for the
current version, not because an old version behaved that way. Automatic
behavior may use reliable environment detection (CPU, memory, cgroup limits,
IP-family availability, kernel capabilities) and must remain deterministic,
explainable, and explicitly overridable.

## 7. Migration lives in release announcements, not in the binary

Breaking changes are documented concisely in CHANGELOG.md. The **complete**
operator-facing old→new migration procedure goes into the GitHub Release
notes of the release that introduces the break, ending with
`rust-reality config check --config config.json`. The production binary
contains no version-to-version migration engine, and the repository keeps no
migration-guide archive. Removed configuration fields are rejected strictly;
recognizing a removed field name solely to emit a targeted fatal error
(naming its replacement) is acceptable, accepting it is not.

## 8. Diagnostics are part of the product

Configuration errors must be precise, source-oriented, and actionable —
file:line:column, the offending source excerpt with a caret/span, what was
expected versus received, and a trustworthy remediation hint when obvious.
Parsing stays strict: better errors are not compatibility. Diagnostics must
never leak secrets and must stay off the network hot path.

## 9. Performance and correctness gates

Protocol correctness and security outrank benchmarks. Never trade
REALITY/VLESS compatibility, byte correctness, authentication, replay
safety, timeout bounds, cancellation safety, or FD accounting for
performance. Optimizations require reproducible before/after measurements;
experiments that show no repeatable benefit are reverted, not explained
away. Run the full quality gates before merging:

    cargo fmt --all -- --check
    cargo test --workspace --locked
    cargo test --workspace --no-default-features --locked
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    ./scripts/check.sh
    git diff --check

## 10. Decision test

For any questionable compatibility path ask: "If rust-reality were created
today, would we intentionally implement this?" If no — delete it. For any
abstraction ask: "Does the current architecture need this now?" If no — do
not build it. For any diagnostic ask: "Can an operator understand exactly
what is wrong and where, without reading the source?" If no — improve it.
