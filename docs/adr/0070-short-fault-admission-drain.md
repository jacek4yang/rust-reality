# ADR 0070: Short-fault admission drain before restore

Status: Accepted

## Context

Hosted QEMU Frozen campaign run `42340270160` on PR #464 retained complete
four-cell evidence and was classified INVALID at merge evaluation, not as a
product FAIL. Offline replay of the receipts against the unchanged interval
and coverage predicates (`evaluate.rs` "during-fault receipt lies outside its
fixed interval" and "during-fault LINE coverage or concurrency was
substituted") showed a single failing cell and fault:

- `handoff/constrained` `cold` only: window `started_ms=2214000`,
  `restored_ms=2224000` (exactly `fault_duration_ms=10000`);
- eight during-fault 1 MiB receipts started 56–240 ms before restore and
  completed 7–147 ms after it (observed durations 203–306 ms; latest complete
  `2224147`);
- LINE-A had 86 during receipts and LINE-B 83, both still peaking at the
  contracted concurrency of 4, so the coverage finding is a count shortfall.

Every other short and RTT/loss fault in all four cells satisfied both
predicates. The campaign runner still labelled the cell `pass`; offline
evaluate fail-closed correctly.

ADR 0040 already reserves `rtt_admission_drain_ms=12000` inside the 90 s
RTT/loss window so in-flight work can finish before the fixed restore
boundary. Short faults used `restored_ms` itself as the admission deadline,
so a 1 MiB transfer admitted in the last ~200–300 ms of the 10 s window can
finish after restore and trip the interval predicate. A 12 s RTT drain cannot
be copied into a 10 s short-fault window.

This does not establish a product Handoff or XUDP defect, and shrinking the
admission window cannot repair the 86/83 count shortfall (late first
admission on that cell left too little time to reach 100 transfers per LINE).

## Decision

Keep the existing acceptance claims — the 10 s short-fault duration, the fixed
restore boundary, no during-fault receipt completed after restore, ≥100
completed transfers per impaired LINE, and peak concurrency equal to
`fault_concurrency_per_line` — and make short-fault admission coherent with
in-flight completion:

- add `fault_admission_drain_ms = 500`, reserved inside every non-RTT fault
  window so in-flight during transfers can finish before restore;
- producers already soft-stop at `Contract::fault_admission_deadline_ms`
  without emitting a transfer error; that helper now subtracts the short-fault
  drain for non-RTT names, exactly as it subtracts `rtt_admission_drain_ms`
  for RTT/loss;
- offline evaluation keeps the interval and coverage predicates strict and
  unchanged, and additionally rejects a during-fault receipt whose `started_ms`
  is after the admission deadline even if it still completes by restore.

The 500 ms drain is bounded above the observed in-flight completions on
`42340270160` (max duration 306 ms, max start 240 ms before restore, max
overrun 147 ms) and is far smaller than the 10 s window. Completions after
restore remain INVALID. Historical `42340270160` evidence remains INVALID
under the original contract, both for the eight late completions and for the
86/83 coverage shortfall.

## Consequences and limits

This is a test-contract coherence change, not a product behaviour change and
not a claim that the `handoff/constrained` cold path is bug-free. It does not
fix the 86/83 coverage shortfall; a later during-admission start still fails
coverage even when every in-window receipt finishes by restore. Reducing the
required transfer count, widening the 10 s window, or accepting completions
after restore as during-fault work is rejected. New qualification must run at
the exact head that embeds this contract; older green jobs do not transfer.
The compiled contract SHA-256 changes deliberately with `stability.json`.
