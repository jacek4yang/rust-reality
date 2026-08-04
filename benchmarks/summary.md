# Relay backend benchmark summary

Baseline commit: `14ed098505b5cd9c3f5cc0d00c393c45428b0e42`
Branch commit: recorded in each sample's `commit` field.

Every sample is retained in `relay-baseline.jsonl` and `relay-after.jsonl`.
This table is derived from them and does not replace them.

## Conclusion

**The measured difference is indistinguishable from noise on this host.**
Across the 36 scenario cells, the per-cell median delta ranges from
-18.4% to +24.2% with an overall median of +2.2%. With three
retained samples per cell on a shared 2-vCPU virtual machine, that spread is
measurement noise, not a result.

No throughput improvement is claimed from this data. The improvement this branch
does demonstrate exactly is the framed hot path: the allocation gate proves zero
heap allocations per record after warm-up on the read path, the write path and
the Vision decoder, measured with an instrumented allocator rather than inferred.

A confounded earlier run, in which the two measurements were not taken under the
same conditions, showed a large apparent regression. It was discarded and both
sides were re-measured sequentially on an otherwise idle host, which is what this
table reports. The discarded run is not included in the retained samples.

## Method

* Loopback, single host, 2 vCPU, kernel 6.18.5.
* Both sides use the same scenario matrix, the same seed (`20260804`) and the
  same per-repetition shuffle.
* Baseline is measured in a separate worktree at the baseline commit, with the
  benchmark adapted only where the baseline API differs.
* Three samples per cell; every sample retained; no fastest run selected.

## Per-scenario medians

| direction | payload | conc | requested | baseline p50 MiB/s | branch p50 MiB/s | delta | n |
| --- | ---: | ---: | --- | ---: | ---: | ---: | ---: |
| bidirectional | 1 MiB | 1 | automatic | 612 | 644 | +5.2% | 3 |
| bidirectional | 1 MiB | 1 | buffered | 540 | 598 | +10.9% | 3 |
| bidirectional | 1 MiB | 1 | splice | 557 | 536 | -3.8% | 3 |
| bidirectional | 1 MiB | 4 | automatic | 593 | 580 | -2.2% | 3 |
| bidirectional | 1 MiB | 4 | buffered | 605 | 686 | +13.4% | 3 |
| bidirectional | 1 MiB | 4 | splice | 601 | 548 | -8.8% | 3 |
| bidirectional | 32 MiB | 1 | automatic | 504 | 510 | +1.3% | 3 |
| bidirectional | 32 MiB | 1 | buffered | 556 | 572 | +3.0% | 3 |
| bidirectional | 32 MiB | 1 | splice | 544 | 509 | -6.5% | 3 |
| bidirectional | 32 MiB | 4 | automatic | 542 | 549 | +1.1% | 3 |
| bidirectional | 32 MiB | 4 | buffered | 538 | 585 | +8.7% | 3 |
| bidirectional | 32 MiB | 4 | splice | 520 | 524 | +0.7% | 3 |
| downlink | 1 MiB | 1 | automatic | 476 | 472 | -0.7% | 3 |
| downlink | 1 MiB | 1 | buffered | 424 | 473 | +11.6% | 3 |
| downlink | 1 MiB | 1 | splice | 512 | 533 | +4.0% | 3 |
| downlink | 1 MiB | 4 | automatic | 523 | 536 | +2.5% | 3 |
| downlink | 1 MiB | 4 | buffered | 556 | 608 | +9.3% | 3 |
| downlink | 1 MiB | 4 | splice | 509 | 565 | +11.0% | 3 |
| downlink | 32 MiB | 1 | automatic | 488 | 495 | +1.5% | 3 |
| downlink | 32 MiB | 1 | buffered | 533 | 571 | +7.3% | 3 |
| downlink | 32 MiB | 1 | splice | 514 | 498 | -3.1% | 3 |
| downlink | 32 MiB | 4 | automatic | 486 | 495 | +1.8% | 3 |
| downlink | 32 MiB | 4 | buffered | 546 | 568 | +3.9% | 3 |
| downlink | 32 MiB | 4 | splice | 479 | 483 | +0.8% | 3 |
| uplink | 1 MiB | 1 | automatic | 530 | 501 | -5.5% | 3 |
| uplink | 1 MiB | 1 | buffered | 467 | 512 | +9.7% | 3 |
| uplink | 1 MiB | 1 | splice | 448 | 556 | +24.2% | 3 |
| uplink | 1 MiB | 4 | automatic | 591 | 493 | -16.5% | 3 |
| uplink | 1 MiB | 4 | buffered | 550 | 534 | -3.0% | 3 |
| uplink | 1 MiB | 4 | splice | 494 | 574 | +16.2% | 3 |
| uplink | 32 MiB | 1 | automatic | 597 | 548 | -8.2% | 3 |
| uplink | 32 MiB | 1 | buffered | 748 | 611 | -18.4% | 3 |
| uplink | 32 MiB | 1 | splice | 547 | 601 | +9.9% | 3 |
| uplink | 32 MiB | 4 | automatic | 569 | 542 | -4.6% | 3 |
| uplink | 32 MiB | 4 | buffered | 616 | 692 | +12.4% | 3 |
| uplink | 32 MiB | 4 | splice | 575 | 598 | +4.0% | 3 |

## Limits on any use of this table

* These are loopback numbers measuring relay engine cost. They are not Internet
  throughput and must never be presented as a general speed promise.
* The 512 MiB payload and 32-way concurrency rows of the specification matrix
  were not executed on this host; the retained matrix covers 1 MiB and 32 MiB at
  concurrency 1 and 4.
* io_uring and sockhash rows are absent because both declined on this host.
  A decline is recorded; a number is never invented.
* The specification's "public Direct p50 must not regress more than 5%" gate
  cannot be settled by this data: the noise floor here is wider than 5%. It must
  be re-run on a quiet, pinned target host before the PR is merged.
