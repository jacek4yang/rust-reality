# Official GNU client performance

Source: `47f039fe62c05e913e69db13572f909933fc07cc`.
Executable SHA-256:
`a8521c7147290c426e62afb3ce7934da84215b8c925458d562186c64c1949290`.
The baseline is official candidate `d72abc250791f804e310818fdee148540aabfed9`,
not the published v2.2.0 source. Collector source is qualified
`38abe32697a701d0c4450688df02cc0719f4d963`.

All 20 ABBA blocks, 80 slots, 8000 data batches, 252000 verified data requests
and 1600 setup batches completed. All 56 predeclared protected intervals pass:
40 data and 16 setup metrics, with no pooling or selective retry. The complete
results and unchanged guards are in `performance-assessment.json`.

Direct upload at concurrency 1 has CPU/GiB ratio 0.94525470, with 95% bootstrap
interval [0.93673511, 0.95547112]. Its throughput ratio is 6.28478514, interval
[6.24425420, 6.30116003]. Ratios compare candidate to baseline and include the
combined client changes; they are not attributable solely to the NXR encoder.
These fixed-host loopback results do not predict Internet throughput.

All 80 slots recover descriptors by the 2000-ms observation. Median anonymous
residency increments per held connection are 79.453125 KiB baseline and
40.203125 KiB candidate. These are held-128 minus held-0 observations after
prior traffic, not cold object size, allocation count or a long-term leak
verdict. Every identity-bound observation is retained.

CPU settings restored exactly. All 1319 periodic host samples retained fixed
frequency policies with no compiler observations or thermal-counter growth.
Control queries used CPU 8; this does not establish exclusive hardware.
Every archive member was reopened and hashed; JSONL parts reconstruct the
original bytes. Non-executable controller sources are included. Private
runtime inputs and process text logs are excluded. Other release gates remain
independent of this performance verdict.
