# Benchmark data

This directory owns machine-readable performance policy and compact durable
evidence. Human guidance for running and interpreting benchmarks lives in the
[benchmark documentation](../docs/en/benchmarks.md).

## Categories

- `contracts/` contains schemas and thresholds enforced by benchmark or
  evaluator tooling.
- `baselines/` contains canonical comparison identities and measurements used
  by current checks or documentation.
- `evidence/` contains compact acceptance manifests, checksummed golden objects,
  and other small evidence that supports a durable claim. Release evidence sets
  and durable per-run evidence records live under `evidence/releases/`.

Evidence manifests must identify their implementation and inputs precisely.
When a manifest records checksums, the referenced objects must retain their
exact bytes. Never replace measured values with estimates or silently rewrite
an accepted evidence object.

The non-executable `.sh` and `.py` objects under `evidence/objects/sha256/` are
immutable historical evidence retained by digest; they are not active
repository policy. Shell or Python source anywhere else is rejected by
`cargo dev repo check`.

Do not commit raw `perf.data`, large packet captures, IDA databases, release
binaries, full artifact trees, or huge logs. Store large reproducible outputs as
CI artifacts or release assets and retain only the necessary identity, checksum,
and compact acceptance summary here. Proprietary content, credentials, private
keys, and operator configuration must never be committed.
