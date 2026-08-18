#!/usr/bin/env python3
"""Build the evaluate-release-performance.py manifest for the gates evidence."""

import hashlib
import json
from pathlib import Path

GATES = Path("/home/jacek/work/kimi-rust-reality-performance/artifacts/v1.5.0/gates")

PAIR_FILES = ["summary.json", "environment.json", "order.json",
              "raw-samples.jsonl", "completion.json"]
MATRIX_FILES = ["summary.json", "samples.jsonl",
                "run-contract.json", "run-completion.json"]


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
        "commit": "47a71514e7b33261f510f8c0ad62af76b6c66ae2",
        "sha256": "cf532adfa9406dc44eeda513e07e44fa2875869f3b1306dc40e41c80f0de7b7b",
    },
    "baseline": {
        "commit": "572c077115a89b95f1ba559df2debcf13d29115c",
        "sha256": "7c6f66517dc448abdbd4b6247d1c28c29dccedb599ca505c59e11c28086ec3f2",
    },
    "bootstrapIterations": 20000,
    "workloads": [
        entry("setup-abba", "setup", GATES / "setup-abba-r01", PAIR_FILES),
        entry("fallback-abba", "fallback", GATES / "fallback-abba-r01", PAIR_FILES),
        entry("matrix", "matrix-c1", GATES / "matrix-formal-r01", MATRIX_FILES),
    ],
}
out = GATES / "evaluator-manifest.json"
out.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
print(out)
