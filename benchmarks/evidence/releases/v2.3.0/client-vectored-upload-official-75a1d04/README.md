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
