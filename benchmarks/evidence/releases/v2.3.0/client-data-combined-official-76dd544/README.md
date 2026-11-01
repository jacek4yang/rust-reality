# Combined official client candidate performance

Source: `76dd5448fbdd488f2d1cfa8b03a6ff8e7ef51506`.
GNU executable SHA-256:
`d37ea2bf06ad419f89f49071091d30ccbce3094e45c8f878095edf8990442b59`.
The comparison uses the pinned official `d72abc250791f804e310818fdee148540aabfed9`
executable and qualified collector `38abe32697a701d0c4450688df02cc0719f4d963`.
The historical baseline package label is not a claim that it is the published
v2.2.0 source. Full identities are retained in this directory.

The predeclared 20 ABBA blocks completed all 80 slots, 8,000 data batches,
252,000 data requests and 1,600 setup batches. All 40 data and 16 setup
protected metrics passed the unchanged bootstrap-interval guards. No intervals
were pooled with earlier campaigns. See `performance-assessment.json` and
`summary.json` for every metric, interval and block.

Direct-upload:c1 CPU candidate/baseline median is 0.95145894, with 95% interval
[0.93808855, 0.96106170]. The large throughput difference versus d72 already
appears in the [prior official-package comparison](../client-data-final-package/performance-assessment.json);
it is not attributed solely to the new upload-copy removal. Loopback results
are not Internet throughput predictions.

Every archived slot member was reopened and checked against its original bytes
and SHA-256. JSONL chunks reconstruct the original bytes exactly. Private
runtime inputs and process text logs are excluded. The initial environment
preflight failure and corrected predeclaration are retained in
[combined candidate evidence](../combined-candidate-76dd544/performance-declaration/predeclared.json).
CPU policies were restored exactly. Host-monitor scope and auxiliary activity
are recorded in `control-plane-observation.json`.

This qualifies the specified client performance surface of this exact candidate.
It does not replace final-main binary qualification, Native/Frozen acceptance,
package verification, allocation diagnostics, or a published Release.
