# Vectored upload diagnostic at 75a1d04

Compare the canonical GNU local build at `75a1d04` with the official GNU
package at `9265a6b`, using the unchanged qualified collector `38abe32` and
fixed server `c02e488`. This is diagnostic evidence, not release acceptance.

All 24 process slots, 1,200 data batches and 46,800 verified data requests
complete successfully. Bidirectional batches contain two requests per lane;
`archive-preflight-correction.json` retains the original accounting error.
CPU policies restore exactly and the collector observes no concurrent compiler.

The six observed Direct-upload concurrency-1 CPU ratios range from 0.94255
to 0.96956, with median 0.95298. These observations motivate further validation;
they do not establish a resolving confidence interval. The unchanged collector
requires at least 12 complete ABBA blocks. The predeclared six-block assessor
incorrectly expected `bootstrap95`, failed closed, and is retained by hash and
error receipt. Every acceptance metric remains UNRESOLVED. Do not rename
`bootstrap95Unresolved` or pool these samples with a later campaign.

`predeclared.json` and `invocation.json` bind conditions and executable hashes.
Slot archives retain all JSON observations; member manifests independently
verify every stored member. Private runtime configurations and process logs
are excluded. Generated-code inspection uses the actual frozen executable;
the symbols-only rebuild is explicitly not an address-identical twin.
