# ADR 0025: Cover profiles observe, but do not reproduce, EncryptedExtensions

Status: Accepted

Date: 2026-09-04

## Context

[ADR 0006](0006-prebuilt-reality-cover-profiles.md) tier 3 exists to remove the
cover round trip from the authenticated critical path: once a cover class has
been observed four times consistently, an authenticated handshake reconstructs
the class locally instead of dialing the cover.

It never activated. A controlled experiment reproduced production's exact
counter signature — state `unavailable`, zero hits, `refresh_failure` — on two
different covers, and the cause was one rule in
`src/protocol/reality/tls13/cover_profile.rs`. The collector decrypted the
cover's first encrypted record, parsed its `EncryptedExtensions`, and rejected
the observation if it contained **any** extension other than ALPN:

```text
ALPN                -> parse it
anything else       -> reject the whole observation
```

Two of the most ordinary things a TLS 1.3 server can send failed that rule:

- extension `0`, length `0` — the empty `server_name` acknowledgement of
  RFC 8446 section 4.2, which OpenSSL- and nginx-derived servers send whenever
  they accept the SNI. This is what the production cover sends.
- extension `17613`, length `158` — `application_settings`, which Google and
  Cloudflare properties answer with when a Chrome-fingerprinted client offers
  it. This is what the repository's default example cover sends.

Between them that excludes most realistic covers, which is why the mechanism
was inert everywhere rather than in an unlucky configuration.

The rule's stated reason was that "silently ignoring it would create a
deterministic authenticated differential". Tracing both paths shows that is not
what happens.

## Why the rule was wrong

Neither path ever re-emits the cover's `EncryptedExtensions` bytes.

- The **live** path takes `selected_alpn` from the *client's* offer
  (`hello.alpn_protocols().next()`), builds its own `EncryptedExtensions` from
  that ALPN and nothing else, and pads the record to the cover's observed wire
  length. It never decrypts the cover's `EncryptedExtensions` at all.
- The **profile** path builds the identical message from the ALPN the profile
  recorded, and pads to the same observed wire length.

So the cover's extension *content* was being used as an admission test for
information that is discarded on both paths. A cover carrying an empty
`server_name` acknowledgement produced exactly the same server flight as one
that did not — the only difference was that one of them was allowed to skip the
cover round trip and the other was not.

## Decision

The profile collector classifies the observed `EncryptedExtensions` instead of
requiring it to be ALPN-only. Every extension falls into one of four classes:

1. **Reproduced — ALPN.** The one value the local flight emits. It must be a
   single protocol, well formed, and offered by the controlled probe.
2. **Validate-only — the message itself.** The record must decrypt under the
   key schedule reconstructed from the probe and the observed ServerHello, and
   must be a well-formed `EncryptedExtensions` handshake message. This is the
   integrity evidence that the observation is a genuine, unmodified response
   from the configured cover, and it is unchanged.
3. **Discarded — every other structurally valid extension.** Declining an
   offered extension is always legal for a TLS 1.3 server, the live path
   already declines all of them, and nothing downstream of a profile reads
   them. `server_name` and `application_settings` are examples, not a list:
   the rule is semantic, and no cover is named in the code.
4. **Unsupported — `early_data`.** It asserts an accepted 0-RTT negotiation.
   `ClientHello::normalized_profile_class` refuses to classify a PSK
   ClientHello at all, so observing an accepted `early_data` means the cover
   negotiated state this mechanism cannot reconstruct. That class stays
   live-only, and reports as `UnsupportedEncryptedExtension` rather than as a
   parse failure, because it is not one.

Structural strictness is unchanged and in one respect stronger. The parser
still rejects truncated headers, length overrun, a malformed or multi-protocol
ALPN, an empty selected protocol, an over-long extension vector, and a
selection the probe did not offer; it now additionally rejects a **repeated
extension type of any kind**, which RFC 8446 section 4.2 forbids and which the
previous rule only caught for ALPN.

Trailing bytes after the framed `EncryptedExtensions` message remain tolerated,
because a cover that coalesces its whole flight into one record puts
Certificate, CertificateVerify and Finished there. Reading past the message
would reject exactly the covers the coalesced record shape exists to reproduce.

## Security argument

- **Nothing new is emitted.** The change alters which observations may be
  cached, never what the server sends. The flight built from a profile is the
  flight the live path would have built, which
  `discarded_cover_extensions_do_not_change_what_the_client_receives` asserts
  by building both and comparing the emitted `EncryptedExtensions` byte for
  byte.
- **No new passive fingerprint.** Record shape still comes from the observed
  plan and is still padded to the cover's own wire lengths. A profile hit and a
  live miss produce the same shape for the same class.
- **No new active-probing differential.** Tier selection happens strictly after
  REALITY authentication and replay reservation. An unauthenticated prober
  never reaches a profile, and the fallback relay is untouched.
- **Poisoning surface unchanged.** Observations are still generated only by
  rust-reality's own `CoverProbe` against the configured cover, never from user
  bytes; a user's ClientHello can nominate a bounded class and nothing else.
  Consensus still requires four byte-identical observations. Per-session
  material — server random, echoed session ID, key exchange — is still erased
  before storage, and materialization still revalidates the cipher suite, key
  share and session-ID length against the real client.
- **Failure still cannot evict.** A failed or unstable collection records a
  cooldown; it does not replace or remove a published profile.
- **Class binding is unchanged and strict.** The normalized class is a SHA-256
  over the ClientHello's version, session-ID length, GREASE-canonicalized
  cipher suites, compression methods and every extension type with its
  normalized body — including the ALPN list. A profile captured for one
  capability set cannot be reused for another.

The argument for discarding an extension is that the emitted flight never
carried it and the live path never carried it either — not that clients
tolerate it.

## Measurement

Class: LOCAL_SYNTHETIC. Namespace and veth pair with `netem delay 25ms` per
direction on the client-to-LINE leg only (RTT 50.1 ms measured); unmodified
Xray-core 26.7.28 (`5ca6f4b`) as the client; cover and origin legs unshaped;
40 sequential authenticated sessions per cell.

| Cover | Arm | State | Hit/miss | p50 | p90 | p95 | p99 |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| production-class (`www.lmu.edu`) | before | `unavailable` | 0/40 | 343.0 ms | 1026.3 ms | 1106.6 ms | 1194.9 ms |
| production-class (`www.lmu.edu`) | after | `validated` | 34/40 | 157.0 ms | 332.4 ms | 600.3 ms | 900.2 ms |
| production-class, profile warm (attempts 7-40) | after | `validated` | 34/34 | 156.9 ms | 157.3 ms | 157.5 ms | 271.1 ms |
| Google-class (`dl.google.com`) | before | `unavailable` | 0/40 | 209.7 ms | 213.1 ms | 214.7 ms | 216.8 ms |
| Google-class (`dl.google.com`) | after | `unstable` | 0/40 | 209.6 ms | 212.9 ms | 215.4 ms | 230.6 ms |

The warm steady state is 156.9 ms against a 50.1 ms RTT — three round trips
(TCP, TLS, request/response) plus scheduling, which is the floor for this
topology. The cover interaction is gone from the authenticated path rather than
merely faster.

## Consequences

- Ordinary TLS 1.3 covers become profilable. The mechanism ADR 0006 specified
  now runs.
- A cover whose flight is not byte-stable across observations still gets no
  profile, and now reports the accurate reason. The Google-class cover moved
  from `refresh_failure` (its `EncryptedExtensions` could not be read) to
  `unstable` with four disagreements (its coalesced record length varied by a
  byte or two between observations). That is the consensus rule working, and it
  is a real remaining unsupported class, not a regression: the before and after
  latency for that cover are within noise of each other.
- `CoverProfileError` gains `UnsupportedEncryptedExtension`, so an unmodellable
  negotiation is distinguishable from a malformed message in diagnostics.

## Revisit conditions

- A cover appears whose `EncryptedExtensions` content must be reproduced for
  the client to accept the flight. That would move an extension from
  "discarded" to "reproduced" and require the local flight to learn to emit it.
- Consensus is relaxed to tolerate a cover whose flight length varies. That is a
  separate decision about shape fidelity, with its own analysis; it is not
  implied by this one.
- `normalized_profile_class` starts admitting PSK ClientHellos, which would
  make the `early_data` classification load-bearing in a way it is not today.
