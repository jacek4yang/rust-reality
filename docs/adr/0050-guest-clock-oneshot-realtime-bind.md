# ADR 0050: One-shot guest REALTIME bind before kvm-clock witness

Status: Accepted (amends ADR 0049)

## Context

Frozen run `38045882781` on `dfa5b78` (ADR 0049) fail-closed at **startup**
clock bind on `handoff/constrained` and `nxr/ordinary`:

- Primary: `line-b: guest clock is not bounded to the host workload schedule`
- Finalization: `No such file or directory (os error 2)`

Retained probes show Class B harness, not product:

| Cell | line-b before skew (host_after − guest) | Start offset (250) |
| --- | --- | --- |
| handoff/constrained | ~952 ms behind | fail |
| nxr/ordinary | ~471 ms behind | fail |

`line-a` before on the same cells stayed within tens of milliseconds. Roles are
probed in contract order `[line-a, line-b, landing]`, so the line-b failure
aborts before `landing-clock-before.json` is written; assemble then reports
ENOENT. After-phase probes (including line-b) still satisfied
`clock_max_end_offset_ms` (1000).

ADR 0049 removed `date --set` on the premise that kvm-clock alone tracks the
host. kvm-clock is the clocksource for *ongoing* timekeeping; it does **not**
correct CLOCK_REALTIME inherited from a wrong guest image/RTC. Pre-0049 cells
(with one-shot `date --set`) kept start skew within ~30 ms. The ordinary
landing *end* skew (~421 ms) that motivated ADR 0049 remains a campaign-length
uncertainty and is still covered by `clock_max_end_offset_ms`.

## Decision

1. Before bind is three ordered observations: `timedatectl set-ntp false`,
   one-shot `date --utc --set=@… +%s%3N` echoing the host bind instant, then
   witness `/sys/.../current_clocksource == kvm-clock`.
2. Keep ADR 0049 end-phase offset (`clock_max_end_offset_ms` = 1000) and
   start-phase offset (250). Checkpoint `clock_guard_ms` stays derived from the
   start offset.
3. Do not sleep, hold, or loosen start skew to paper over unbound REALTIME.
4. No production timer or admission change.

## Consequences

Start bind restores deterministic host/guest REALTIME alignment; kvm-clock
witness still rejects non-kvm sources; end-of-campaign bound stays tolerant of
observed ordinary-landing drift. ADR 0049's "no `date --set`" clause is
superseded; its end-offset and diagnosis/retain rules remain.

## References

- Frozen cells: https://github.com/jacek4yang/rust-reality/actions/runs/38045882781
  (jobs 114198345456 handoff/constrained, 114198345461 nxr/ordinary)
- [Guest clock end offset and kvm-clock witness](0049-guest-clock-end-offset-and-kvm-witness.md)
