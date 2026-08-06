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
| D6 | pending | PipePool: per-session pipe create/resize/destroy costs fallback c32 (Opus hypothesis, CREDIBLE) | — |
| D7 | pending | Sockhash pair-path unreachable after c1ec2cf → delete privileged code | — |

## Reverted / rejected

(none yet)
