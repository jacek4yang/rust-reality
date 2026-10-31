# Setup-rate comparison: eb91df6 to 876d5d5

This is a local, early server-side performance comparison, not final release
qualification or a measurement of the new outbound client profiles. The stock
Xray client drives both server binaries. Both binaries were frozen from clean
source with the same pinned release toolchain and default features. The gated
collector is commit b648aedf54b47926fd87c7db65c2f499e7fc31d3; executable hashes
and Build IDs are retained alongside every slot.

Each run contains 12 balanced ABBA blocks, 48 slots, concurrency 1/8/32,
96 connections per sample and nine samples per slot: 1,296 samples, zero
failures. The control uses the baseline binary in both arms. The comparison
uses baseline eb91df613a1664a6e744a625652e84756b665c70 and candidate
876d5d55dd5dde7b383ca8361e52814cf53e644b. No local compilation overlapped either
run. Host metadata was recorded after the comparison; frequency/temperature
history and PMU counters were not collected.

| Metric | Candidate / baseline median | Block-bootstrap 95% interval |
| --- | --- | --- |
| Setup throughput, concurrency 1 | 1.00728 | 0.98273 to 1.02857 |
| Setup throughput, concurrency 8 | 1.00100 | 0.99473 to 1.01278 |
| Setup throughput, concurrency 32 | 0.99601 | 0.98573 to 1.00609 |
| Server CPU per connection | 1.00121 | 0.99130 to 1.00717 |

The intervals include equality and do not indicate a regression in these
measured metrics. The collector deliberately emits `performanceVerdict:
NOT_EVALUATED`: this dataset alone is not the protected whole-product contract,
a client-side handshake cost result, or a final release PASS. Raw per-slot
samples retain p50/p95/p99; no separately qualified latency verdict is implied.

The same-binary control, complete ordering, raw throughput and latency samples,
schedstat CPU receipts, per-slot identities, source freezes and checksums are
retained. Generated configurations, key generation output and process logs are
excluded. Absolute binary/build paths in machine receipts are historical
measurement locators, not required installation paths.

Reproduce using the repository-owned collector with the frozen binaries:

```text
rr-dev --repo CANDIDATE_SOURCE bench run --suite setup-rate --rust-bin CANDIDATE_BINARY --baseline-bin BASELINE_BINARY --baseline-identity BASELINE_IDENTITY --baseline-commit eb91df613a1664a6e744a625652e84756b665c70 --xray-bin VERIFIED_XRAY --blocks 12 --concurrencies "1 8 32" --connections 96 --measure-mode schedstat --out-dir NEW_OUTPUT --run-id UNIQUE_ID
```
