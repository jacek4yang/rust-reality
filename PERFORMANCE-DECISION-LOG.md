# Performance decision log (1.0)

Format per candidate: ID, parent/candidate SHA, hypothesis, mechanism, changed
files, gates, focused bench, end-to-end result, profile movement, resource
result, security review, keep/revert, confidence.

## Register

| ID | status | hypothesis | verdict |
|---|---|---|---|
| D1 | accepted | Reload/asset-refresh multiplies process ceilings (MB1) | KEPT: authorities hoisted to ProcessAuthorities (f8cd340+5b3f778); reload x10 tests |
| D2 | accepted | Abort indistinguishable from clean FIN (MB2) | KEPT: SO_LINGER{on,0} on abort paths + DirectionAbortGuard (9bbd534); RST-vs-EOF tests |
| D3 | accepted | DNS work insufficiently bounded/accounted (12.3) | KEPT: DnsLookup pool, permit held in blocking op, fail-fast, no queue (510cd61) |
| D4 | accepted | No coherent kernel liveness backstop (12.4) | KEPT: SO_KEEPALIVE 30/10/3 on all data sockets; netns experiment validated formula (1cac77e); TCP_USER_TIMEOUT rejected with reason |
| D5 | accepted | Diagnostics can mislabel source; pipe cliff invisible (12.5) | KEPT: MemorySampleSource + MemorySamplerChanged; pipe downgrade in ledger->outcome->connection log; orphan constant deleted (24068cc) |
| D6 | falsified-as-cause, kept-with-tradeoff | PipePool: per-session pipe create/resize/destroy costs fallback c32 (Opus hypothesis, CREDIBLE) | Mechanism CONFIRMED (Go/Xray pool 1MiB pipes, ~0/session; rust-reality paid 2 pipe2+2 fcntl+4 close/session). Implemented PipePool (90eb08c). strace A/B on identical fallback workload (96 sessions): pipe2 192→64, close/fcntl ~eliminated; splice(2) itself is 97% of syscall time (~101k calls, 15.5KiB/call avg) so end-to-end did not move: fallback c32 C/X=0.767, c64 0.76, 512:32 0.675 (gate target >=1.00 FAILED); C/P≈1.0 everywhere, no regression, integrity matched. Verdict: the hypothesis is FALSIFIED as the fallback gap's cause — the gap is splice-call cost vs Xray's 64KiB readv/writev (Xray fallback does not splice at all). KEPT with explicitly documented tradeoff: proven syscall/FD-churn reduction at zero measured cost, bounded retention, exact accounting; it makes NO fallback-throughput claim. |
| D7 | pending | Sockhash pair-path unreachable after c1ec2cf → delete privileged code | — |

## Reverted / rejected

(none yet)

## New hypotheses registered

- D8: fallback c32 gap = splice(2) call cost at availability-limited chunk sizes
  (2 syscalls per <=32KiB vs readv+writev 2 per 64KiB, plus pipe middleman
  copies) vs Xray's plain readv/writev fallback. NOT to be patched with a
  short-flow classifier without new evidence. Candidates: bigger effective
  splice chunks when availability is high (measure first), buffered-backend
  buffer sizing research, or accepting splice only for long sessions based on
  a measured (not guessed) criterion.
