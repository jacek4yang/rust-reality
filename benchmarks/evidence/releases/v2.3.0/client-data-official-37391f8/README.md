# Combined official client candidate performance

Source: `37391f86c8d58ade672c25453a855b69e7d81932`.
GNU executable SHA-256:
`cba868a43e3f1fbd0d2a7bdb4cd7bd1113359f201bc1bec55d8b877c5b836182`.
The comparison uses the pinned official `d72abc250791f804e310818fdee148540aabfed9`
executable and qualified collector `38abe32697a701d0c4450688df02cc0719f4d963`.
The baseline package label is not the published v2.2.0 source identity.

The predeclared 20 ABBA blocks completed all 80 slots, 8,000 data batches,
252,000 data requests and 1,600 setup batches. All 40 data and 16 setup
protected metrics pass the unchanged bootstrap-interval guards. No intervals
were pooled with previous campaigns. `performance-assessment.json` retains
every metric and interval; `summary.json` retains the collector results.
Direct-upload:c1 CPU candidate/baseline median is 0.94965919, with 95% interval
[0.94015360, 0.96142408]. Large throughput/setup improvements versus d72 already
existed before the NXR frame-writer optimization; they are not attributed to
that change. This measures the Chrome profile on loopback, not Internet speed.

`invocation.json` retains the exact collector command, source and binary
identities. The controller, supervisor and assessment sources are retained as
non-executable text. `predeclared.json` preserves the original declaration;
its inherited `preflightCorrection` field describes the earlier 76dd campaign's
root-HOME preflight failure, not a failed attempt of this 37391 campaign.

Every archived slot member was reopened and checked against its original bytes
and SHA-256. JSONL chunks reconstruct original bytes exactly. Private runtime
inputs and process text logs are excluded. CPU policy restoration was exact;
1,314 host samples record no compiler observations or thermal-throttle-count
increment. `control-plane-observation.json` records monitoring scope.

This qualifies the specified performance surface of this exact candidate.
It does not replace final-main binary qualification, Native/Frozen acceptance,
package verification, allocation diagnostics or a published Release.
