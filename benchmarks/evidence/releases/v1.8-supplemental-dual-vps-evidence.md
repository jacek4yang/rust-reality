# v1.8 supplemental dual-VPS Handoff/NXR evidence

- Evidence class: **REAL WAN SUPPLEMENTAL EVIDENCE**
- Explicitly **not** controlled netem evidence, and not a soak
- LINE: `rust-reality-vps`, v1.8.0, binary SHA-256 `450392ccc73fd4dd8441c04dcdcc93f0eb8b0ea2524e17904ca4bb376416ed1c`
- Client: pinned stock Xray-core 26.7.28 (`23d228d7…04c5268`) on a loopback SOCKS5 inbound
- Runner: `artifacts/v18-supplemental/run-leg.py`
- Verdict: **PASS on all four legs**

This closes the gap recorded in the v1.8.0 deployment record, where neither the
formal loopback legs nor the daily canary exercised the LINE-to-LANDING Handoff
or NXR path.

## Method, and why it does not disturb the daily node

The v1.7.0 Handoff canary replaced LINE's entire configuration, which also
replaced its REALITY/VLESS identity and therefore disconnected ordinary clients
for the duration. This run does not do that.

`artifacts/v18-supplemental/build-supplemental-configs.py` *extends* the live
daily configuration instead:

- the REALITY identity (private key, target, serverNames), port, and listen
  policy are copied verbatim — verified equal by hash;
- both existing user entries and their routing groups are copied verbatim —
  verified equal by hash;
- one canary-only user is appended with its own short ID, routed to a Handoff or
  NXR outbound. Short IDs are unique per inbound and the configuration validator
  rejected the first attempt that reused a live one, which is how that constraint
  was discovered;
- warm-connection policy is enabled so warm checkout, idle retirement, and cold
  fallback are all reachable within minutes;
- log level is raised to `info` only in the supplemental generation, because
  `transport_pool_summary` is emitted at generation retirement and the daily
  configuration logs at `error`.

Existing client links therefore keep working throughout. After the run LINE was
returned to the daily generation and its live configuration hash was verified
byte-identical to the original (`b4042c54…bdbd504`), and an existing daily client
was confirmed to still connect (HTTP 204).

No listener was opened on either host, and the LANDING firewall rule restricting
443 to the LINE `/32` was read but never modified.

## Results

| protocol | LANDING | attempts | success | warm hits | misses | cold fallback | stale discards | connect failures | failed checks |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Handoff | 1.7.0 | 1063 | 100.00% | 1062 | 1 | 1 | 27 | 0 | 0 |
| NXR | 1.7.0 | 1063 | 100.00% | 1061 | 1 | 1 | 17 | 0 | 0 |
| Handoff | 1.8.0 | 1063 | 100.00% | 1062 | 1 | 1 | 27 | 0 | 0 |
| NXR | 1.8.0 | 1063 | 100.00% | 1059 | 3 | 3 | 20 | 0 | 0 |

Per-leg checks, all passing: cold-path first flight, 1 MiB byte-exact integrity,
post-idle request after the warm sockets crossed their 30 s idle threshold,
LANDING restart, LANDING recovery, post-recovery churn, LINE reload, post-reload
request, LINE no-restart, warm checkout observed, cold fallback observed, no
authentication/replay/protocol rejection, and listener policy unchanged on both
hosts.

Resource envelopes (before / peak / after):

| leg | LINE RSS KiB | LINE FD | LINE threads | LANDING RSS KiB |
| --- | --- | --- | ---: | --- |
| Handoff / L1.7.0 | 9040 / 9108 / 9092 | 57 / 76 / 57 | 3 | 9344 / 9664 / 9664 |
| NXR / L1.7.0 | 7600 / 9404 / 9352 | 25 / 75 / 57 | 2 | 7384 / 8064 / 7816 |
| Handoff / L1.8.0 | 7640 / 8968 / 8968 | 25 / 79 / 57 | 3 | 7852 / 9868 / 9280 |
| NXR / L1.8.0 | 7632 / 9228 / 9228 | 25 / 80 / 59 | 2 | 7564 / 8164 / 7744 |

LINE descriptors returned to 57 in every leg after peaking near 80, and RSS
stayed under 10 MiB throughout on a 1 vCPU / 1973 MiB node.

## Mixed-version result

`LINE v1.8.0 → LANDING v1.7.0` and `LINE v1.8.0 → LANDING v1.8.0` are
behaviourally indistinguishable in this measurement for both protocols. That is
the expected outcome — v1.8.0 changed no wire byte — and it is now a measurement
rather than an argument from the diff.

LANDING has since been upgraded to v1.8.0, so the version skew is closed.

## Rejections

Every leg recorded exactly 7 `connection_rejected` events with reason
`outbound`, plus at most 1 on LANDING. These fall in the deliberate LANDING
restart window and are the expected bounded in-flight outbound failures. **Zero**
authentication, replay, or protocol rejections occurred in any leg, which is the
check that is never allowed to fail.

## Honest limits

- Supplemental real-WAN evidence. Network conditions were not controlled and this
  is not netem evidence.
- Minutes-long high-density legs. Nothing here extrapolates a leak slope.
- LANDING descriptor counts read as 0 because `/proc/<pid>/fd` was not readable
  without elevation from the sampler, so **LANDING FD recovery is not
  established** by this run. LINE FD recovery is.
- The 1000-connection phase is driven at concurrency 8 rather than strictly
  sequentially. Each request is still its own connection; the concurrency exists
  only because 1000 sequential real-WAN round trips took over twelve minutes and
  produced no extra information.
