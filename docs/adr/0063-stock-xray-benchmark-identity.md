# ADR 0063: Stock Xray benchmark identity

Status: Accepted

## Context

The paired setup-rate collector requires a GNU Build ID from every executable.
Unmodified official Xray 26.10.29 and 26.9.9 Linux binaries are stripped Go ELFs
without that note. Requiring it prevents measurements before any workload
runs. Adding a note or rebuilding Xray would invalidate the stock-binary
reference contract in ADR 0059.

## Decision

For the paired setup-rate collector's Xray comparator only, record the observed
GNU Build ID as nullable metadata. SHA-256 registration and the executable's
reported version identity remain mandatory. Failed ELF inspection, malformed
notes and duplicate Build IDs remain errors. Absence must be explicit JSON
null, never an invented digest labeled as a Build ID.

The baseline and candidate rust-reality executables still require GNU Build
IDs. Their source and hash attestations, host locking, workload guards,
statistical tests, protected metric tolerances and release qualification are
unchanged. ADR 0009's content-identity rule remains authoritative. This decision
does not modify historical benchmark evidence or imply a performance result.

## Evidence

Official Xray 26.10.29 archive SHA-256:
`8a5f3e6a1057e4bd0f8a7c57c9d91204b4be0b74222a6e210d070603101163c2`.
Extracted executable SHA-256:
`e783b9d2b46ed1ab3617c59b04dfbce38c999322d018c6e060f18d88bf6158aa`.
The binary reports commit `0afec66`; `readelf -n xray` succeeds with no notes.
The release archive digest matches the official GitHub release asset metadata.

## Revisit conditions

If upstream begins shipping a GNU Build ID it will be recorded automatically.
Changing the authoritative SHA-256/source binding requires separate review.
