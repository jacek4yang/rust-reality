# Combined candidate allocation and resource diagnostic

The exact official GNU `76dd544` client and pinned official `d72abc2` baseline
ran eight rotated ABBA process runs under heaptrack 1.5.0. Each run completed
128 persistent authenticated Chrome connections, two exact one-MiB GETs and
one verified one-MiB PUT per connection. All 3,072 transfers and 1,024 fresh
PUT receipts passed; all eight descriptor counts recovered before process
termination. Private fixture inputs and process text logs are excluded.

Candidate/baseline allocation-call ratios range from 1.01025 to 1.01198,
with median 1.01077. This is a measured increase, below the predeclared 5%
investigation guard, not a claim that allocations decreased. Whole-process
counts include startup and connection lifecycle. Instrumented peak heap text
is 17.88M for baseline and 9.29M for candidate. Instrumented RSS and timing
are not production performance acceptance, and termination-time retained
allocations do not establish a leak or a zero steady-state allocation claim.
See `allocation-assessment.json`, all eight raw traces, and their text analyses.

Use `heaptrack_print --file TRACE --print-peaks=0 --print-allocators=0
--print-temporary=0 --disable-builtin-suppressions
--disable-embedded-suppressions` to reproduce the allocation summaries.
The first fixture attempt incorrectly demanded exit 0 after deliberately
sending SIGTERM; the installed launcher propagates the child signal status.
That failed attempt is retained separately and not pooled. The corrected
fixture requires a live client, FD recovery, controlled SIGTERM, exit 0/143
and complete trace interpretation. Crashes and cleanup timeouts remain errors.
No production code, production deadline or release gate changed.

`uninstrumented-residency.json` separately derives observations from all 80
slots of the [uninstrumented campaign](../client-data-combined-official-76dd544/README.md).
It uses the median of three anonymous-memory snapshots at each occupancy.
The median per-slot held-128 minus held-0 increment, divided by 128, is
82.4375 KiB for baseline and 39 KiB for candidate. All 80 descriptor counts
return to the held-0 count after closure. These processes already performed
traffic: this is descriptive residency, not cold object size, allocation
count, a long-term leak verdict or future final-main qualification.
