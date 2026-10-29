# Client setup and buffer residency observations

This is an intermediate local comparison, not final release qualification.
The immutable collector is source `7709809f240514cb4ffacb003da6d640004063fe`,
SHA-256 `b28877879772f020676d9ae14e0ae8c886b5e4c88275bb8df539e7ffc07d6d7c`.
Its local full gate passed 19/19; exact-head Native is
[40917652426](https://github.com/jacek4yang/rust-reality/actions/runs/40917652426).
Each slot verifies its measured executable and the fixed server. Source freezes,
ELF Build IDs, hashes, workload parameters and complete ordering are retained.

Both campaigns use explicit Chrome, a fixed server built from `c02e488`,
12 balanced ABBA blocks, 48 fresh-process slots, concurrency 1/8/32/64,
nine samples per concurrency and 64 connections per sample (1,728 samples).
No local builds or tests overlapped either campaign. CPU uses the measured
client's schedstat counters; no PMU or frequency/temperature history was
collected. Resource observations follow, outside the timing window: three
samples each at 0/1/8/32/128 held connections and five fixed post-close offsets.

## Control remains unresolved

`aa/` compares `1efd418` with itself. CPU ratio is 1.00180 with a block-bootstrap
95% interval of 0.97967 to 1.02225. Concurrency-64 p50 ratio is 1.00885 with an
interval of 1.00290 to 1.01146. These do not resolve the predeclared 1% margin
for all metrics. The unfavorable and ambiguous observations remain present.
Do not treat this campaign as an established 1% measurement-resolution PASS.

## Buffer comparison

`buffers-ab/` compares `d72abc2` with `1efd418`, before and after deferred raw
scratch allocation and on-demand TLS read-ahead growth. These binaries precede
the subsequent socket, authentication-deadline and task-lifetime fixes.

| Metric | Candidate / baseline median | Block-bootstrap 95% interval |
| --- | --- | --- |
| Client CPU per connection | 0.97334 | 0.96739 to 0.98319 |
| Setup rate, concurrency 1 | 1.00077 | 0.99995 to 1.00127 |
| Setup rate, concurrency 8 | 1.00185 | 0.99794 to 1.00440 |
| Setup rate, concurrency 32 | 1.00187 | 0.99692 to 1.00508 |
| Setup rate, concurrency 64 | 1.00391 | 1.00260 to 1.00846 |

Every latency cell and interval is in the summary, with every individual
connection latency in the slot samples. Both summaries deliberately retain
`performanceVerdict: NOT_EVALUATED`. The unresolved control prevents a blanket
performance-preservation claim even though these comparison intervals are
favorable. Final-candidate qualification must resolve the protected metrics.

At 128 held connections, the median incremental anonymous residency was
102.109375 KiB per connection before the buffer change and 54.03125 KiB after.
This is the difference between each slot's median three held-128 and held-0
observations, divided by 128, then the median across that arm's 24 slots. The
same-binary arms measured 54.234375 and 54.03125 KiB respectively. These are
resident-page observations, not allocation counts or isolated buffer sizes.
All 96 slots had zero descriptor-count delta two seconds after close. This
fixed checkpoint does not establish immediate reclamation or long-term leak
freedom; retained anonymous pages are not themselves evidence of live owners.

## Raw evidence and reproduction

Each slot archive contains the original `samples.json`, `schedstat.json`,
`identity.json` and 20 kernel resource observations. Archive manifests bind
every original member's length and SHA-256 as well as the archive digest.
Generated configurations, key-generation output and process logs are excluded.
The oversized concatenated sample stream is redundant with the retained
per-slot samples and is not duplicated. Absolute paths in receipts are original
measurement locators, not installation requirements.

Verify `SHA256SUMS`, extract each slot archive into a directory named after
that archive (without `.tar.gz`), and verify its manifest's member hashes.
Reproduce with the gated collector and immutable binaries:

```text
rr-dev --repo COLLECTOR_SOURCE bench run --suite client-setup-rate --rust-bin CANDIDATE --baseline-bin BASELINE --baseline-identity BASELINE_IDENTITY --baseline-commit BASELINE_COMMIT --setup-server-bin FIXED_SERVER --client-fingerprint chrome --baseline-client-fingerprint chrome --measure-mode schedstat --blocks 12 --samples 9 --connections 64 --concurrencies "1 8 32 64" --out-dir NEW_DIRECTORY --run-id UNIQUE_ID
```

Use `1efd418` in both arms for the control, and `d72abc2` as baseline for the
buffer comparison. These observations do not qualify Firefox, a WAN workload,
all data-transfer paths, or the final release binary.
