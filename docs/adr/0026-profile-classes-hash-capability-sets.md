# ADR 0026: Profile classes hash capability sets, not GREASE variance

Status: Accepted

Date: 2026-09-04

## Context

[ADR 0025](0025-cover-profiles-observe-but-do-not-reproduce-encrypted-extensions.md)
made tier-3 profile reuse possible, and production validation showed the
mechanism working — but with a hit rate that never reached its ceiling: one
unmodified Xray-core 26.7.28 client produced **four** normalized ClientHello
classes across 40 sessions (85% hits, four cold-start collections per
generation instead of one).

Capturing all 40 ClientHellos and diffing every field answered why. The uTLS
`chrome` fingerprint randomizes four things per handshake, and the class
normalizer was sensitive to every one of them:

| Varying field | Observed across 40 hellos | Classification |
| --- | --- | --- |
| GREASE cipher position in the cipher list | 16 distinct vectors; the non-GREASE set constant | GREASE + order (RFC 8701: no semantics) |
| GREASE extension presence (random subset of 15 types `0x?a?a`) | each type in 2–8 hellos | GREASE |
| GREASE extension body (2 variants) | 2 distinct bodies per type | GREASE |
| GREASE positions inside supported_groups / supported_versions | 16 / 15 distinct orders; the real sets constant | GREASE + order |
| GREASE ECH payload length | 4 distinct lengths in 32-byte steps | GREASE |

Everything capability-relevant was constant across all 40 hellos: SNI, ALPN,
supported version set, supported group set, cipher suite set, session-id
length, key-share groups and lengths. The four classes were pure GREASE noise —
expected client behavior, not four capability sets.

## Decision

The class digest (`classify_profile_message`, domain separator bumped to
`/v2`) hashes **capability sets**:

- GREASE-typed extensions (`0x?a?a`, RFC 8701) are skipped entirely — presence
  and placeholder bytes no longer enter the digest.
- Cipher suites, supported groups, supported versions and signature algorithms
  are hashed as **sorted sets** with GREASE values dropped; preference order
  and GREASE positions no longer carry.
- GREASE ECH (`0xfe0d`) keeps its full structural validation, but hashes only
  constants — content, encapsulation length and payload length are variance,
  not capability.

Everything else is unchanged: PSK offers still refuse classification, session
fields stay excluded, SNI and ALPN still split classes, the extension-count
bound still applies, and the probe template still replays the nominating
client's own raw hello.

## Why this cannot merge incompatible capabilities

The class digest is a **lookup hint, never an authority**.
`CoverProfile::materialize` revalidates the offered cipher suite, the
key-share group and length, and the session-id length against the *actual
incoming* ClientHello, and `cover_compatible_alpn` re-filters ALPN per
connection. Two clients whose hellos differ only in meaningless GREASE
placement are capability-identical by construction; even a hypothetical bad
merge would be caught at materialization and fall back to live cover.

The wire is untouched. The cover sees the client's exact hello either way —
the probe replays the template, and the digest is internal state that never
leaves the process.

## Measurement

Class: LOCAL_SYNTHETIC, same topology as ADR 0025 (netns/veth, netem 25 ms per
direction on the client leg only; unmodified Xray-core 26.7.28; 40 sessions).

| Metric | Before | After |
| --- | ---: | ---: |
| Distinct classes from one client | 4 | **1** |
| Profiles published (refreshes) | 4 | **1** |
| Cold-start sessions (live cover) | 6 | **1** |
| Profile hits / 40 sessions | 34 (85%) | **39 (97.5%)** |

The first-hit index moves from session 5 to session 2. Warm steady state is
unchanged — it was already at the architecture floor
([#238](https://github.com/jacek4yang/rust-reality/issues/238)).

## Consequences

- Cold-start cost per generation drops from `k × cover-RTT` (k = observed
  classes) to a single collection for the common single-fingerprint client.
- Classes remain strict where they are load-bearing: capability changes —
  ALPN, group set, suite set, SNI, session-id length — still split classes,
  which is what tier-3 fidelity requires.
- The digest is versioned `/v2`; profiles are in-process and TTL-bounded, so
  no cross-version state exists, but the bump makes any accidental comparison
  impossible.

## Revisit conditions

- A client appears whose GREASE behavior is *not* variance — no known TLS
  implementation assigns meaning to RFC 8701 values.
- A future profile capability starts depending on vector *order* (for example,
  server choice following client preference order). That would reintroduce
  order into the digest for the affected field only.
