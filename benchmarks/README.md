# Benchmark data

This directory owns machine-readable performance policy and compact durable
evidence. Human guidance for running and interpreting benchmarks lives in the
[benchmark documentation](../docs/benchmarks.md).

## Categories

- `contracts/` contains schemas and thresholds enforced by benchmark or
  evaluator tooling.
- `baselines/` contains canonical comparison identities and measurements used
  by current checks or documentation.
- `evidence/` contains compact acceptance manifests, checksummed golden objects,
  and other small evidence that supports a durable claim.
- `final/` contains the current release evidence set. It will be folded into the
  evidence taxonomy once all consumers and identity references have been
  migrated.

Evidence manifests must identify their implementation and inputs precisely.
When a manifest records checksums, the referenced objects must retain their
exact bytes. Never replace measured values with estimates or silently rewrite
an accepted evidence object.

Do not commit raw `perf.data`, large packet captures, IDA databases, release
binaries, full artifact trees, or huge logs. Store large reproducible outputs as
CI artifacts or release assets and retain only the necessary identity, checksum,
and compact acceptance summary here. Proprietary content, credentials, private
keys, and operator configuration must never be committed.
