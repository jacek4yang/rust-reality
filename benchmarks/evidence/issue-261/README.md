# Anonymous-memory investigation evidence

**Root cause remains unproven; no product fix is justified by these data.**
The original failure and all rejected diagnostic results remain available.
The unchanged gate uses a 2.0 MiB/hour aggregate PSS tail-slope limit.
[comparison.json](comparison.json) independently recomputes each verdict from
the native samples without changing the window or warmup.

| Observation | Product SHA256 prefix | Tail slope (MiB/hour) | Result |
| --- | --- | ---: | --- |
| Historical failure | `1c77e38ed55f` | 3.596465581 | Fail |
| Historical repeat | `1c77e38ed55f` | 0.432756491 | Pass |
| Pinned allocation diagnostic | `b8ab364ca79c` | 3.169552473 | Fail |
| Pinned uninstrumented control | `b8ab364ca79c` | 1.919933042 | Pass |

The two archived native workloads in `same-binary.json` used source
`3b581bdc9d4fbd55fc9e6b02caab67e0d6860949` and identical frozen binary bytes.
Their original aggregate PSS tail slopes were **3.596465581 MiB/hour (fail)**
and **0.432756491 MiB/hour (pass)** against the unchanged **2.0 MiB/hour**
limit. Both outcomes are retained. They establish variation without a product
binary change; they establish neither a leak nor harmless retention.

Both ZIP digests and all 45/47 retained archive checksums were independently
verified. The selected JSON/JSONL files are byte-exact archive members, with
their digests recorded in the manifest. The failed run has no soak completion
or environment member; its summary explicitly reports the final identity check
as not run. Its archive identity and frozen binary checksum must not be
misrepresented as successful terminal workload binding.

Allocation stacks were not collected in either historical run. See
[issue #261](https://github.com/jacek4yang/rust-reality/issues/261) for the
investigation ledger and the pinned experimental source. Passing repeats must
not supersede the failed observations.

The [pinned-source allocation diagnostic](pinned-profile/README.md) retains a
second resource-gate failure, actual service allocation/free traces, allocator
snapshots, process observations, and the separately identified diagnostic
inputs. Its profiling and trace-accounting limits do not establish the cause
of the historical failure.

The [control](pinned-control/README.md) uses the exact same local product,
fixtures, and explicitly identified diagnostic harness, without child
instrumentation. One local pair cannot separate instrumentation effects from
ordinary variation. The local Ubuntu 26.04/glibc 2.43/16-worker environment
differs from the historical Ubuntu 24.04 workflow. No 12-hour qualification or
allocation trace of the historical failure is available. A validated trace of
a failing run in the historical environment is needed before selecting a fix.

The standalone diagnostic's first conflicting pointer records are explained
by Heaptrack recording a moved reallocation after the underlying allocator
has freed the old address. This explains the rejected diagnostic accounting,
not the historical uninstrumented failure. The five other checked traces and
allocator snapshots support retention as a hypothesis; they do not prove it.

[Validation evidence](validation/manifest.json) preserves the full gate's
original storage-quota failure and its unchanged successful repeat. The
diagnostic source's full gate is retained in the profile receipts. No gate,
allocator policy, product source, or workflow is changed. The experimental
source remains pinned to `dbf4773`; the separate soak-storage fix on the phase
branch is not included or duplicated here.
