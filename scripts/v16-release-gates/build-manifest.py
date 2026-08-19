#!/usr/bin/env python3
"""Build the evaluate-release-performance.py manifest for the v1.6.0 gates evidence.

The candidate commit is not pinned at harness-authoring time, so the
candidate identity comes from the environment (exported by env-common.sh):
RUST_REALITY_COMMIT / RUST_REALITY_SHA256.  Round numbers default to r01;
override with RR_GATE_ROUND (zero-padded, e.g. 02).
"""

import hashlib
import json
import os
from pathlib import Path

GATES = Path("/home/jacek/work/kimi-rust-reality-performance/artifacts/v1.6.0/gates")

PAIR_FILES = ["summary.json", "environment.json", "order.json",
              "raw-samples.jsonl", "completion.json"]
MATRIX_FILES = ["summary.json", "samples.jsonl",
                "run-contract.json", "run-completion.json"]

candidate_commit = os.environ["RUST_REALITY_COMMIT"]
candidate_sha256 = os.environ["RUST_REALITY_SHA256"].lower()
gate_round = os.environ.get("RR_GATE_ROUND", "01")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def entry(kind: str, name: str, run_dir: Path, files: list[str]) -> dict:
    return {
        "kind": kind,
        "name": name,
        "runDir": str(run_dir),
        "files": {relative: sha(run_dir / relative) for relative in files},
    }


manifest = {
    "schemaVersion": 1,
    "tier": "portable",
    "candidate": {
        "commit": candidate_commit,
        "sha256": candidate_sha256,
    },
    "baseline": {
        "commit": "149f126d9f852bafeca85bc14a0f8f0b2c096640",
        "sha256": "49f3246f571b63043dd3fa198c84d6f2c113c64372e6955c1a0282fb0926956b",
    },
    "bootstrapIterations": 20000,
    "workloads": [
        entry("setup-abba", "setup", GATES / f"setup-abba-r{gate_round}", PAIR_FILES),
        entry("fallback-abba", "fallback", GATES / f"fallback-abba-r{gate_round}", PAIR_FILES),
        entry("matrix", "matrix-c1", GATES / f"matrix-formal-r{gate_round}", MATRIX_FILES),
    ],
}
out = GATES / "evaluator-manifest.json"
out.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
print(out)
