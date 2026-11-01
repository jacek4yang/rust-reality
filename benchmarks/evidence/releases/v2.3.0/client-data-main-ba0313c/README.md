# Official main client performance

Source: `ba0313c5aab4f4237cb4bae7e10673b44e276296`.
GNU executable SHA-256:
`c11a7b660499424ca1f881c744587dc2e0a061028bfa6e6fc4ff33f1ad66eef2`.
Baseline is official `d72abc250791f804e310818fdee148540aabfed9`, not the
published v2.2.0 source. Collector is qualified `38abe32697a701d0c4450688df02cc0719f4d963`.

All 20 ABBA blocks, 80 slots, 8,000 data batches, 252,000 data requests and
1,600 setup batches completed. All 56 predeclared protected metrics pass;
no pooling or selective retry. The complete intervals are retained in
`performance-assessment.json`. Direct-upload:c1 CPU ratio is 0.93732539
with 95% interval [0.93395845, 0.95368759]. Its throughput ratio is 6.28247744;
these gains include preceding client changes and are not attributed solely to
the NXR encoder. Results describe this loopback workload, not Internet speed.

Every archived member was reopened and verified. JSONL parts reproduce the
original bytes. The exact invocation and non-executable controller sources
are retained. CPU policies restored exactly; 1,317 periodic observations saw
no compiler load or thermal-throttle-count increment.

All 80 slots show descriptor recovery by 2,000 ms. Median anonymous residency
increment per held connection is 84.265625 KiB baseline and 40.21875 KiB
candidate. `resource-observations.json` retains every row. This is the median
held-128 minus median held-0 observation after prior traffic, not cold object
size, allocation count, or a long-term leak verdict.

This is performance evidence for this exact executable. The same source's
Frozen qualification failed offline NXR restart accounting; see ADR 0068.
Performance PASS does not override that failure or establish a release PASS.
