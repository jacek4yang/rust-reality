# Expanded client setup control remains unresolved

This is a same-binary control, not a release performance PASS. Both arms use
`acbe49ccc4e7fdfcb1e89f6bcd58bb90d9725ac7`, SHA-256
`7520eebac6a722d4de86e108ed11c914d653f2677befeb0bac32f92ca0f8dbd6`.
The fixed server is `c02e4882e00dd05c224779b83a8e950fecbf1036`.
Both freeze records are retained. The immutable collector is `7709809`, digest
`b28877879772f020676d9ae14e0ae8c886b5e4c88275bb8df539e7ffc07d6d7c`;
its full local gate and exact-head hosted qualification passed.

The campaign was predeclared in
[PR 408](https://github.com/jacek4yang/rust-reality/pull/408#issuecomment-6505757677):
20 balanced ABBA blocks, 80 fresh-process slots, Chrome in both arms,
concurrency 1/8/32/64, 21 samples per concurrency, 128 connections per sample.
All 6,720 samples completed without connection failures. No local builds or
tests overlapped the campaign. The existing CPU/rate/p50 1% and p99 2% margins
were not changed. The collector records each connection latency and attributes
aggregate client CPU using schedstat; it does not collect PMU events.

| Control metric | Candidate / baseline | Block-bootstrap 95% interval |
| --- | --- | --- |
| CPU per connection | 1.0025344 | 0.9881930 to 1.0287359 |
| Setup rate, concurrency 1 | 0.9873507 | 0.8779112 to 1.0556773 |
| p50, concurrency 1 | 1.0255087 | 0.9493631 to 1.1278836 |
| p99, concurrency 1 | 1.0284417 | 0.9871611 to 1.0678811 |
| p50, concurrency 32 | 1.0072423 | 1.0019170 to 1.0125256 |

All cells, including the other unresolved intervals, remain in `summary.json`.
The summary's `performanceVerdict` remains `NOT_EVALUATED`; this control does
not establish sufficient precision for the protected metrics. It cannot be
used to declare the implementation either faster or regressed: the executable
is identical in both arms. The prior unresolved `1efd418` control is retained
separately, not replaced by this larger experiment.

Subsequent read-only host inspection found heterogeneous CPU cores and
intel_pstate powersave / balance_performance. These are diagnostic observations,
not a recorded frequency/temperature history or proof of causality. The current
unshaped collector uses a three-connection warm-up. Further controlled
measurement is needed before a final performance verdict.

Every slot archive contains the original samples, schedstat, executable identity
and 20 resource observations. `archive-manifest.json` binds each archive and
each decompressed member by SHA-256 and length. All archives and members were
verified against the source files. Process logs, generated configurations and
key-generation output are excluded. The concatenated raw stream duplicates
retained per-slot samples and is not copied. Verify `SHA256SUMS`, then extract
and verify each archive's members against its manifest.

Reproduce with the immutable collector and pinned executable paths:

```text
rr-dev --repo COLLECTOR_SOURCE bench run --suite client-setup-rate --rust-bin ACBE_BINARY --baseline-bin ACBE_BINARY --baseline-identity ACBE_IDENTITY --baseline-commit acbe49ccc4e7fdfcb1e89f6bcd58bb90d9725ac7 --setup-server-bin C02_BINARY --client-fingerprint chrome --baseline-client-fingerprint chrome --measure-mode schedstat --blocks 20 --samples 21 --connections 128 --concurrencies "1 8 32 64" --out-dir NEW_DIRECTORY --run-id UNIQUE_ID
```
