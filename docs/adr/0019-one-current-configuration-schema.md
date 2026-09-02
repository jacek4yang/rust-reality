# ADR 0019: One current configuration schema

## Status

Accepted for v1.9.0. This decision breaks every existing configuration file and
authorizes no wire-format, protocol, or client-interoperability change.

## Context

The v1.8 configuration model grew by accretion. Several of its structures now
violate the one-canonical-model rule in [AGENTS.md](../../AGENTS.md) §5, and the
violations are load-bearing rather than cosmetic:

- Two independent channels configure the same numbers. `advanced.limits` infers
  operator intent by comparing a value to the built-in default;
  `advanced.overrides` exists because that inference cannot express "pin one
  field without restating its mandatory siblings" or "pin a field to a value
  that equals the default". Both channels are read on every startup, and the
  duality reaches `runtime/plan.rs` as `FieldSource::Override` versus
  `FieldSource::LegacyLimit` and `explain`'s report schema version 2.
- `TuningMode::Fixed` exists only to read `advanced.limits` verbatim and is
  documented in source as "v1.5 behavior".
- Four fields carry no information: `streamSettings.network` must be `tcp`,
  `streamSettings.security` must be `reality`, `settings.decryption` must be
  `none`, and `clients[].flow` must be `xtls-rprx-vision`. Each has a dedicated
  rejection branch in the validator.
- Traffic is routed by two mechanisms that never interact: public VLESS flows
  through `routing.users[]` keyed by UUID, and landing flows through
  `inbounds[].settings.egress`.
- A user identity is declared twice — once in `inbounds[].settings.clients[]`
  and once in `routing.users[].userIds` — and validation must cross-check them.
- `inbounds` is a `Vec` whose length is 1 in every configuration the project
  generates, documents, or tests.
- The runtime snapshot holds the whole user-facing `Config`, and startup
  overwrites `config.advanced.limits` with the resolved effective policy, so one
  type is simultaneously operator input and derived runtime state.

Fixing these individually would preserve the shape that produced them. The
configuration is also the product's public contract, so changing it is a
deliberate breaking act that should happen once, completely, rather than in
increments that each carry compatibility weight.

## Decision

### Exactly one configuration schema exists at any time

rust-reality supports the current schema only. A breaking configuration change
**replaces** the schema; it never adds a parser beside the previous one. The
following are prohibited in production code, permanently and not merely for this
release: `serde(alias)` for renamed fields, legacy or deprecated field names,
silently ignored unknown properties, compatibility structs, version-dispatched
schema selection, in-binary migration or normalization of old configurations,
compatibility feature flags or runtime modes, and extension buckets such as a
flattened `HashMap<String, Value>` that exist so a future version can ignore
unknown values.

An old configuration must fail. Recognizing a removed field name **solely** to
emit a targeted fatal error naming its replacement is permitted; accepting it is
not. The operator-facing migration procedure lives in the release notes of the
release that breaks the format, per §9 — never in the binary.

This rule is scoped to *configuration*. It grants nothing with respect to the
VLESS wire protocol, REALITY, Vision, stock Xray client interoperability, or the
NXR and Handoff wire contracts, all of which remain strict.

### The canonical format is strict UTF-8 JSON

JSON is retained deliberately, not by default. It is visually direct and
structurally explicit; object and array nesting is unambiguous; operators
arriving from Xray already read it; and generated or machine-consumed
configuration stays straightforward. The absence of comments is accepted, and
documentation carries the explanation instead. No comment-tolerant JSON variant,
JSON5, YAML, or TOML is supported, now or as a second format later: every
additional parser is permanent surface area.

Retaining the syntax is not retaining the schema. Field names in the new model
are chosen because they are the best names for the new model; where a name
survives, that is convergence rather than compatibility.

`$schema` is not accepted as an in-file key, because accepting it would require
weakening `deny_unknown_fields`. Editor association is documented out of band.

### Parsing stays strict, and gets stricter

Unknown fields, unknown enum values, and type mismatches are rejected.
Duplicate object keys are rejected: `serde_json` silently keeps the last
occurrence of a repeated known key and `deny_unknown_fields` does not catch it,
which is a real class of operator mistake that the source map is already able to
locate. Cross-object constraints — dangling outbound and policy references,
reserved outbound names, invalid topology, contradictory limits, malformed
secret material — are validation failures, and invariants that the type system
can carry are expressed as types rather than checked.

### The user model is presence-tracked; defaults are applied at validation

Every field with a default is `Option<T>` in the operator-facing model, and
defaults are applied when producing the validated model, not during
deserialization.

This is the structural repair for the two-channel defect. Presence is a fact
about the input rather than an inference from comparing a value to its default,
so a single optional override channel can express everything the two current
channels express together, `explain` reports exact provenance instead of
provenance guessed by comparison, and the formatter reproduces operator intent
directly from the type.

### Operator configuration and effective runtime state are different types

```text
config.json -> UserConfig -> ValidatedConfig -> EffectivePolicy -> RuntimeSnapshot
```

The resolved policy is a distinct type. Startup no longer writes derived values
back into the operator-facing structure, and the runtime snapshot receives what
the runtime needs rather than the whole configuration tree.

This **refines** [ADR 0013](0013-no-compiled-runtime-plan.md) and does not
reverse it. ADR 0013 rejected introducing a new `CompiledRuntimePlan` construct
on the grounds that `validate_config` → `resolve_policy` → `RoutingTable::compile`
→ `OutboundRegistry` → `AdaptiveUserMap` → `RuntimeSnapshot::compile` →
`ArcSwap<RuntimeSnapshot>` already is the compiled plan, and that finding still
holds: no new layer is added here. What ADR 0013 did not address is that the
*control plane* still holds and mutates the user-facing type. Separating input
from derived state removes that coupling without adding a construct.

### Node role replaces the generic inbound array

The top level is discriminated by `role`, with an `entry` variant (public
VLESS + REALITY + Vision) and a `landing` variant (firewall-restricted NXR or
Handoff). The reasoning is topological. LINE-to-LANDING exists to separate a
public, fingerprintable, burnable address from a clean egress address that
should stay hidden; running both roles in one process makes a single machine
simultaneously a public entry point and a landing, which defeats the purpose of
the topology and contradicts the [threat model](../en/threat-model.md). The
combined shape has never been generated, documented, or tested, and its two
halves already use disjoint routing mechanisms.

The `entry` role keeps an array of listeners, so several ports can share one
REALITY identity — which the current model can express only by duplicating the
entire REALITY block. Support for entry and landing in one process is dropped.
If a real deployment ever needs a third topology, it becomes a role variant; it
does not reintroduce a generic array of arbitrary inbounds.

### The binary generates atomic material, never a configuration

rust-reality generates values an operator should not invent by hand — UUIDs,
X25519 key pairs, short IDs, pre-shared keys — and nothing else. It does not
generate an inbound, an outbound, a routing block, a topology, a server
configuration, or an Xray client configuration.

The operator composes the configuration deliberately, so they understand what
they deploy. Whole-configuration generation optimizes for the first five minutes
and against every subsequent operation: an operator who received an opaque file
cannot reason about a routing change, a credential rotation, or a failure. The
documentation teaches the model instead, and the atomic generators stay
automation-friendly so an external installer can compose configurations without
that logic living in the daemon.

### The production CLI carries operator tasks only

A top-level command must correspond to something a normal operator intentionally
does. A command does not exist merely because an internal subsystem can expose
one. Benchmark suites, profiling, schema generation, repository checks, fuzz
inventory, and documentation verification belong to `cargo dev`; the deployed
daemon is not the project's engineering toolbox.

Two boundary consequences follow. `cargo dev` gains a path dependency on the
production crate so that `cargo dev schema` can emit JSON Schema from the model
types; this is the sanctioned direction — §11 forbids tooling being linked *into*
production, not the reverse — and no schema file is tracked, so the artifact is
derived at generation time and cannot go stale. Benchmark orchestration leaves
the shipped executable for `benches/`, which already covers nearly all of it and
which `cargo dev bench` already drives.

## Consequences

- Every existing configuration file stops working at v1.9.0. This is intended
  and is announced in `CHANGELOG.md` and the release notes.
- The validator, the model, the whole-configuration generators, the second
  generator (`autotune`), and their tests are deleted rather than adapted.
- `advanced.limits`, `TuningMode::Fixed`, `FieldSource::LegacyLimit`, and the
  four ceremony fields cease to exist.
- Configuration documentation becomes load-bearing: because the binary no longer
  produces configurations, the guides must teach construction and the reference
  must describe every field exhaustively.
- The JSON source map is retained. Semantic validation failures carry a logical
  path and no source position, so mapping path to span remains necessary for
  the diagnostics quality §10 requires.

## Rejected alternatives

- **Adopt TOML.** Comments, native parser spans, and the deletion of the
  hand-rolled JSON source map are real benefits, but the format is the product's
  most visible operator-facing surface and the ecosystem argument for JSON is
  stronger. Diagnostics implementation cost does not outrank the format choice.
- **Keep the old schema and fix the defects individually.** This preserves the
  shape that produced them and pays compatibility cost forever for a file format
  that has no external consumers.
- **Support both the old and new schema for one release.** Two parsers is the
  outcome this decision exists to prevent, and a transitional period would
  become permanent surface area.
- **Generate complete configurations from CLI flags.** Optimizes onboarding at
  the cost of every later operation, and makes the documentation optional in a
  way that produces operators who cannot debug their own deployment.
- **A configuration schema version field with dispatch.** Turns the repository
  into a museum of historical schemas. A version identifier may describe the one
  current contract for diagnostics; it may never select a parser.

## Revisit conditions

- The format is revisited only if a concrete operator requirement appears that
  strict JSON cannot express — not for aesthetics and not to simplify
  diagnostics.
- The role model gains a variant only when a real deployment needs a topology
  the two current roles cannot express.
- A `status` command returns only if a genuine runtime control plane exists to
  query, not to read an implementation-owned snapshot file by path.
- Whole-configuration generation returns to the binary only if external
  automation proves unable to compose configurations from the atomic generators.

## Evidence

- `src/config/` at 423ebe6: model, validator, generators, and the diagnostic
  subsystem, with 185 operator-facing fields across 49 types and 42 default
  functions.
- `src/server/production.rs` snapshot construction, the effective-policy
  write-back at startup, and the reload path.
- `src/runtime/plan.rs` `FieldSource` and `resolve_policy`, which encode the
  two-channel resolution order.
- `src/crypto/keygen.rs` as the only use site of the ML-DSA dependency, with no
  configuration field or protocol consumer anywhere in the tree.
