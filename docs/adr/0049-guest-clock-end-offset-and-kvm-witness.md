# ADR 0049: Guest clock end offset and kvm-clock witness

Status: Accepted

## Context

Frozen run `38037827211` on `0918150` fail-closed handoff/ordinary after a
fully green fault pack (`primary_error: null`, all ten faults through
`rtt-100-loss-1`). The only finalization error was
`guest clock is not bounded to the host workload schedule`. Automatic
`class_hint` labeled A-product; full cell evidence shows Class B harness.

Retained `landing-clock-after.json` had host RTT 81 ms and guest date
421 ms ahead of `host_after` (502 ms ahead of `host_before`), exceeding
`clock_max_offset_ms` (250). `line-a`/`line-b` after-probes on the same cell
and landing after on handoff/constrained stayed within tens of milliseconds.
Small diagnostics uploaded only empty `*-clock-transport-*.log` files and
omitted the probe JSON, which delayed triage.

Pre-start bind previously ran `timedatectl set-ntp false` then `date --set` to
warp guest REALTIME to the host. Guests already use `kvm-clock` (serial and
clocksource). Warping REALTIME is unnecessary for host tracking and does not
prevent multi-hour skew under parallel hosted QEMU on ordinary (2 vCPU)
landing. Sleeping longer cannot re-bind clocks; the after-phase bound must
match campaign-length uncertainty while start/checkpoint guards stay tight.

## Decision

1. Before bind: disable NTP, witness
   `/sys/.../current_clocksource == kvm-clock`, then measure skew. Do **not**
   `date --set`.
2. Start-phase skew still uses `clock_max_offset_ms` (250). After-phase skew
   uses new contract field `clock_max_end_offset_ms` (1000), covering the
   observed ~421 ms ordinary-landing skew with margin while remaining below
   `checkpoint_tolerance_ms` (2000).
3. `clock_guard_ms` / checkpoint windows stay derived from the start offset and
   drift only — campaign checkpoints are not loosened.
4. Clock verify errors are role-prefixed. Diagnosis classifies guest-clock bind
   phrases as Class B harness.
5. Small cell failure diagnostics retain `*clock-*.json` probe receipts, not
   only transport logs.
6. No production timer, sleep, or admission change.

## Consequences

End-of-campaign host/guest binding tolerates NTP-free kvm-clock skew seen under
parallel hosted QEMU without manufacturing green via sleeps or wall-clock holds.
Start bind stays strict and refuses non-kvm clocksources. Historical receipts
that already recorded the old error remain immutable. Unit coverage replays the
Frozen landing after-probe numbers against the end offset.

## References

- Frozen cell job: https://github.com/jacek4yang/rust-reality/actions/runs/38037827211/job/114174972532
- [Qualify resource ownership and lifetime](0034-qualify-resource-ownership-and-lifetime.md)
- [Four-cell QEMU matrix parallelism](0042-four-cell-qemu-matrix-parallelism.md)
