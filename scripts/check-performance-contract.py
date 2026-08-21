#!/usr/bin/env python3
"""Semantic checks for the protected-metric and cache-foundation manifests."""

import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
contract = json.loads(
    (ROOT / "benchmarks/contracts/protected-metrics-v1.json").read_text()
)
baseline = json.loads(
    (ROOT / "benchmarks/baselines/v1.6.1-cache-foundation.json").read_text()
)
assert contract["schemaVersion"] == 1 and baseline["schemaVersion"] == 1
assert len(contract["workloadFamilies"]) == len(set(contract["workloadFamilies"]))
assert contract["concurrency"] == [1, 8, 32, 64] and contract["effectiveCpuCounts"] == [
    1,
    2,
    4,
    8,
]
assert contract["policyCardinalities"]["users"] == [1, 64, 128, 512, 1000, 10000]
assert contract["policyCardinalities"]["routingRules"] == [10, 100, 1000, 10000]
required_workloads = {
    "setup-x25519",
    "setup-x25519mlkem768",
    "traffic-small-interactive",
    "traffic-large-sustained",
    "traffic-sparse",
    "traffic-half-close",
    "traffic-reset",
    "traffic-idle",
}
assert required_workloads <= set(contract["workloadFamilies"])
assert all(value >= 0 for value in contract["equivalenceMarginsPercent"].values())
assert contract["equivalenceMarginsPercent"]["descriptors"] == 0
assert baseline["host"]["architecture"] == "x86_64"
assert len(baseline["binarySha256"]) == 64 and len(baseline["sourceCommit"]) == 40
assert baseline["pmu"]["status"] in {"PASS", "UNAVAILABLE_WITH_HARNESS"}
assert all(value > 0 for value in baseline["structureSizesBytes"].values())
assert all(
    value == 0
    for key, value in baseline["allocationBaselines"].items()
    if key != "source"
)
for script in ("perf-stat-evidence.py", "perf-c2c-evidence.py"):
    compile((ROOT / "scripts" / script).read_text(), script, "exec")
print("performance/cache contract: PASS")
