# ADR 0027: Preserve the existing v1.8 Handoff landing

## Status

Accepted for v2.0.0. This is a specific exception to ADR 0019 and the
current-schema-only repository policy, required by the operator's v2 release
constraint: upgrade the binary without changing the existing production
configuration, systemd invocation, identities, routing or network exposure.

## Context

The existing LINE uses the current entry schema. The existing LANDING still
uses the v1.8 Handoff schema and starts with `serve --config`. Rewriting that
configuration or unit would evade the requested binary compatibility gate.
The connection keys must continue to mean exactly the same thing.

The v1.8 source at tag `v1.8.0`, `src/config/model.rs`, defines
`advanced.limits` pins by inequality with the old default. A serialized copy
of those defaults therefore means automatic startup derivation, not a fixed
resource ceiling. Handoff nonce retention is different: its default of 120
seconds is an effective replay policy and must survive the upgrade.

## Decision

Accept a bounded v1.8 input subset at the existing configuration read boundary:
one Handoff inbound, one direct outbound, empty routing rules and users,
startup/adaptive tuning, and the unchanged old numeric defaults. Preserve
listener addresses and families, independent keys and retired keys, timeouts,
DNS, logging, runtime profile/objective and direct egress. Asset fields are
structurally checked but inert with empty routing, as in v1.8. Numeric pins,
fixed tuning, nondefault dial heuristics, other protocols, additional
listeners/outbounds, routing rules, unknown fields and duplicate keys fail.

The input becomes the same current `LandingConfig` used by all runtime code.
There is no old server implementation, migration registry, new configuration
file, identity generation or runtime feature flag. An explicit invalid or null
`role` never falls back to the v1.8 reader. Missing `role` selects this reader
only when `inbounds` is present. Ordinary role-tagged inputs remain strict.
`serve` invokes the same implementation as `run`, preserving existing units.

Add optional `landing.nonceRetentionSeconds` to the current Handoff model.
The minimum is twice the accepted clock skew plus one second; the maximum
is 86400 seconds, matching the old validation bound. The cache retains its
65536-entry bound. Absent current-schema retention remains derived; a v1.8
input preserves its explicit value or its 120-second default. Cache retention
changes require restart because existing nonces and deadlines survive reload.
This also closes the existing NXR reload gap when a clock-skew change would
change its derived retention.

Loading, checking, starting and reloading never rewrite the source file.
Explicit `format` renders the current canonical form; it must not be used to
rewrite the protected production configuration during this release.

## Validation and consequences

Synthetic fixtures cover the complete serialized defaults, omitted defaults,
identity/listener/egress preservation, every rejected numeric pin, unsupported
shapes, duplicate keys, key redaction, semantic validation, canonical round
trips and byte-preserving `check`. Reload tests require an unchanged file to
publish normally and a changed retention to leave the last-good generation
intact. The actual private configuration is checked separately without
copying its contents into the repository or evidence logs.

This input support adds parser maintenance. It is deliberately limited to the
observed deployment class and does not authorize broader historical schema
support. Production interoperability, lifecycle, integrity and resource gates
remain required before promotion; accepting JSON alone is not deployment
validation. No firewall, SSH or cloud policy mutation is part of this decision.
