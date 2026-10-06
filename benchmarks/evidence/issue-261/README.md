# Anonymous-memory investigation evidence

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
