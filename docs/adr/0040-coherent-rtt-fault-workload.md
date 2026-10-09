# ADR 0040: Coherent RTT/loss fault workload

Status: Accepted

## Context

Hosted QEMU campaign run `37794750138` at source
`95435b29c7eb5b26ef310c07c7ceacd9a205f53b` retained complete four-cell evidence
and was classified INVALID, not product FAIL for the RTT matrix. Independent
reconstruction showed:

- 1 MiB downloads under 200 ms RTT completed in about 1.9 s median (about 4 s
  max) at two transfers per LINE;
- under 100 ms RTT with 1% loss, in-window completions fell to about 44–48 per
  LINE inside a 60 s fault window;
- the contract still required 100 during-fault transfers per LINE, all started
  and completed inside that same window, while the producer kept admitting work
  after restore.

Those three numbers cannot be true together on ordinary CI guests. Extending
deadlines without resizing concurrency, or raising concurrency without a drain
before restore, would either manufacture late "during-fault" receipts or leave
coverage impossible. Soft-stopping admission must not be reported as a transfer
failure: that would turn a scheduled boundary into a hard batch error.

Authentication-rejection and restart-disconnect attribution were repaired
separately and are outside this decision. Historical `95435b29` evidence remains
INVALID under its original contract.

## Decision

Keep the existing acceptance claims — fixed restore boundary, no post-restore
admissions labelled as during-fault work, ≥100 completed transfers per LINE,
and peak concurrency equal to the contracted RTT matrix — and make the schedule
physically able to satisfy them:

- `rtt_concurrency_per_line = 4` (eight concurrent transfers across both LINEs);
- `rtt_duration_ms = 90000`;
- `rtt_admission_drain_ms = 12000`, reserved inside the window so in-flight
  transfers can finish before restore;
- producers soft-stop admission at the drain deadline without emitting a
  transfer error; offline evaluation still fails missing coverage or any
  during-fault receipt outside `[started, restored]`.

The sizing uses the measured loss-case rate from run `37794750138` (~0.75
completions/s/LINE at concurrency 2) scaled to concurrency 4 across the 78 s
admit interval, which clears 100 completions with margin. Other faults keep
10 s windows and concurrency 4. Numeric resource ceilings, recovery deadlines,
and integrity schedules are unchanged.

## Consequences and limits

This is a test-contract coherence change, not a product behaviour change and
not a claim that latency or loss paths are bug-free. Raising concurrency alone
without the longer window and drain remains insufficient for the loss cell.
Reducing the required transfer count, skipping assertions, or accepting
completions after restore as during-fault work is rejected. New qualification
must run at the exact head that embeds this contract; older green jobs do not
transfer.
