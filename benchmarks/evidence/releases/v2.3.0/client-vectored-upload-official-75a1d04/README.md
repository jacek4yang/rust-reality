# Official vectored-upload candidate validation

The immutable predeclaration uses the actual GNU CI candidate at `75a1d04`
and the official `9265a6b` comparator. It specifies 20 independent ABBA blocks,
exceeding the qualified collector minimum of 12, with unchanged thresholds.
Earlier local-build observations are not pooled. Final release qualification
against the historical `d72abc2` baseline remains a separate requirement.

The earlier 20-block local-build plan collected zero samples and is retained
as NOT_RUN. Its replacement follows verification that local and hosted ELF
text differs despite matching source, compiler, target CPU and feature policy.
The hosted GNU package has seven successful native command receipts bound to
its exact archive and ELF digests. These identity checks do not establish a
performance result or final Frozen qualification.

## Resolving experiment outcome

All 80 slots, 4,000 data batches and 156,000 verified requests complete with
exact CPU-policy restoration. All 20 data-transfer metrics pass their
predeclared bounds. Direct-upload concurrency-1 CPU has median ratio 0.968728
and bootstrap95 interval [0.956905, 0.975118], meeting the benefit criterion.

Setup has six PASS and two UNRESOLVED results: concurrency-1 CPU interval
[0.990997, 1.011646] crosses 1.01, and p99 interval [0.992917, 1.036189]
crosses 1.02. No metric is FAIL. Overall is UNRESOLVED; the predeclared decision
is PROMISING_REQUIRES_FORMAL_QUALIFICATION. This does not qualify final main
or replace its required comparison against the historical d72 baseline.
