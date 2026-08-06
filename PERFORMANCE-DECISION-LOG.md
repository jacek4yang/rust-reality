# Performance decision log (1.0)

Format per candidate: ID, parent/candidate SHA, hypothesis, mechanism, changed
files, gates, focused bench, end-to-end result, profile movement, resource
result, security review, keep/revert, confidence.

## Register

| ID | status | hypothesis | verdict |
|---|---|---|---|
| D1 | pending | Reload/asset-refresh multiplies process ceilings (MB1) | — |
| D2 | pending | Abort indistinguishable from clean FIN (MB2) | — |
| D3 | pending | DNS work insufficiently bounded/accounted (12.3) | — |
| D4 | pending | No coherent kernel liveness backstop (12.4) | — |
| D5 | pending | Diagnostics can mislabel source; pipe cliff invisible (12.5) | — |
| D6 | pending | PipePool: per-session pipe create/resize/destroy costs fallback c32 (Opus hypothesis, CREDIBLE) | — |
| D7 | pending | Sockhash pair-path unreachable after c1ec2cf → delete privileged code | — |

## Reverted / rejected

(none yet)
