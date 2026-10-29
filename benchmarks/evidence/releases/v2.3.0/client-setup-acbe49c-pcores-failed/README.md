# Failed homogeneous-core setup control

This campaign failed and cannot establish a performance verdict. It used the
same frozen acbe49c client in both arms, c02e488 fixed server, and immutable
7709809 collector as the preceding expanded control. The only planned environment
change was taskset CPUs 0,2,4,6, matching the repository's existing laboratory
recipe. The controller receipt is retained; measured-process status confirms
that affinity and five threads. No local builds or tests overlapped the run.

The predeclared plan was 20 ABBA blocks, 21 samples per concurrency, 128
connections per sample and concurrency 1/8/32/64. After 31 completed slots,
block 8 slot 4 failed. The first reported failure was concurrency 32 sample 16,
with 127/128 completed connections and one failure in that sample. The collector
exited nonzero and did not publish completion or a summary. The failure text,
original environment/order and all 2,604 samples from completed slots are kept.

The old collector returned an error before saving the failed slot's rows.
Therefore the failed slot's full raw results are unavailable, and the total
number of failures in that slot cannot be reconstructed from the first error.
Missing records are not counted as passes or recreated. PR 411 adds retained
failure rows and secret-safe stage/OS-code diagnostics for investigation.

Coarse fixed-server protocol rejection events also occur in successful slots.
This first-byte setup workload intentionally closes without consuming the whole
HTTP response, so those events alone do not identify the rare failure's cause.
No product fix or cause is claimed by this evidence. The next operation is a
diagnostic reproduction, not another unchanged formal retry.

Each archive contains the original 23 JSON evidence files for one completed
slot. The manifest binds archive and member hashes and lengths; all were
verified against the source. Generated configuration, key-generation output
and process logs are excluded. Verify SHA256SUMS and each decompressed member
against archive-manifest.json. The prior unrestricted controls remain separate.
