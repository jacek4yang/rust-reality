# Native profile setup cost

Both sides use official GNU source
`47f039fe62c05e913e69db13572f909933fc07cc`, executable SHA-256
`a8521c7147290c426e62afb3ce7934da84215b8c925458d562186c64c1949290`.
Chrome is the baseline profile and Firefox is the candidate profile. The
qualified collector, fixed server, CPU policies and exact invocation are
retained. This compares different required browser capabilities, not a
cross-revision regression or complete browser traffic behavior.

All 20 ABBA blocks, 80 slots and 1600 setup batches completed with zero
collector failures. CPU policies restored exactly; 107 host observations
show no compiler activity or thermal-counter growth. All 16 metric intervals
are retained in `profile-cost-assessment.json` without selective retries.

| Concurrency | Firefox/Chrome CPU per connection | Connection-rate ratio |
| --- | --- | --- |
| 1 | 1.44761715 | 0.75815883 |
| 8 | 1.44284991 | 0.84325415 |
| 32 | 1.46148347 | 0.85058741 |
| 64 | 1.46109123 | 0.85552520 |

Firefox retains its required valid P-256 share and different browser
capabilities. The higher observed setup cost is reported, not normalized
away or treated as a same-capability performance PASS. The separate protected
default-Chrome comparison owns the version-regression verdict.

Two earlier diagnostic invocations were rejected before creating a workload.
The first supplied the package verification identity instead of the collector
sidecar schema. The second controller still referenced the first directory.
It overwrote the first controller's runtime observations; the retained first
directory must not be described as an independent original runtime log bundle.
The original rejection and restoration were recorded in Issue #325 before
that overwrite. Both supervisors record exact CPU restoration and exit 1.
The corrected declaration records these limitations and binds the sidecar
to independently verified package bytes. The successful controller resolves
its own directory. No samples from the rejected invocations exist or were
pooled. Every successful raw slot archive was reopened and hash-verified.
