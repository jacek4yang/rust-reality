#!/usr/bin/env python3
"""Synthetic PASS/regression/missing-evidence tests for release performance gates."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
EVALUATOR = ROOT / "evaluate-release-performance.py"
NETEM = ROOT / "validate-deployment-netem.py"
DEPLOYMENT_DRIVER = ROOT / "deployment_driver.py"
CANDIDATE = {"commit": "c" * 40, "sha256": "c" * 64}
BASELINE = {"commit": "b" * 40, "sha256": "b" * 64}


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def order_rows() -> list[dict]:
    rows = []
    for block, sequence in enumerate(
        (("baseline", "candidate", "candidate", "baseline"),
         ("candidate", "baseline", "baseline", "candidate"),
         ("baseline", "candidate", "candidate", "baseline")), 1
    ):
        for position, implementation in enumerate(sequence, 1):
            rows.append({
                "block": block,
                "position": position,
                "implementation": implementation,
                "serverPort": 20_000 + block * 10 + position,
            })
    return rows


def pair_fixture(root: Path, kind: str, candidate_factor: float = 1.02) -> dict:
    run = root / kind
    run.mkdir()
    setup = kind == "setup-abba"
    throughput_field = "connectionsPerSecond" if setup else "throughputMiBPerSecond"
    order = order_rows()
    rows = []
    for slot in order:
        candidate = slot["implementation"] == "candidate"
        row = {
            "block": slot["block"],
            "position": slot["position"],
            "implementation": slot["implementation"],
            "concurrency": 1,
            "sampleIndex": 0,
            "failed": 0,
            throughput_field: 100.0 * (candidate_factor if candidate else 1.0),
        }
        if setup:
            row.update(connections=4, p99Seconds=0.1 * (0.98 if candidate else 1.0))
        else:
            row.update(
                requests=1,
                bytesObserved=[1_048_576],
                perRequestSeconds=[0.1 * (0.98 if candidate else 1.0)],
            )
        rows.append(row)
    cpu_field = "serverCpuPerConnection" if setup else "serverCpuPerGiB"
    cpu_unit = "microsecondsPerConnection" if setup else "secondsPerGiB"
    summary = {
        "schemaVersion": 2,
        "status": "COMPLETE",
        "performanceVerdict": "NOT_EVALUATED",
        "failures": 0,
        cpu_field: {
            "unit": cpu_unit,
            "blocks": [
                {"baseline": 1.0, "candidate": 0.98, "candidateVsBaseline": 0.98}
                for _ in range(3)
            ],
        },
    }
    environment = {
        "schemaVersion": 2,
        "repository": {"head": CANDIDATE["commit"], "dirty": False},
        "blocks": 3,
        "samplesPerSlot": 1,
        "connectionsPerSample": 4,
        "payloadMiB": 1,
        "concurrencies": "1",
        "baseline": {**BASELINE, "buildId": "b1"},
        "candidate": {**CANDIDATE, "buildId": "c1"},
    }
    write_json(run / "summary.json", summary)
    write_json(run / "environment.json", environment)
    write_json(run / "order.json", {"slots": order})
    write_jsonl(run / "raw-samples.jsonl", rows)
    files = {
        name: sha(run / name)
        for name in ("summary.json", "environment.json", "order.json", "raw-samples.jsonl")
    }
    return {"name": "setup" if setup else "fallback", "kind": kind,
            "runDir": str(run), "files": files}


def matrix_fixture(root: Path, candidate_factor: float = 1.02) -> dict:
    run = root / "matrix"
    run.mkdir()
    key = "direct-download:1:1"
    summary = {
        "schemaVersion": 1,
        "harness": "benchmark-matrix",
        "status": "COMPLETE",
        "performanceVerdict": "NOT_EVALUATED",
        "identity": {
            "candidateCommit": CANDIDATE["commit"],
            "baselineCommit": BASELINE["commit"],
            "binariesPinned": True,
            "binaries": {
                "final": {"sha256": CANDIDATE["sha256"]},
                "baseline": {"sha256": BASELINE["sha256"]},
            },
        },
        "totals": {"invalidSamples": 0},
        "failures": [],
        "cells": {
            key: {
                "scenario": "direct-download",
                "direction": "download",
                "payloadMiB": 1,
                "concurrency": 1,
                "samplesPerImplementation": 6,
                "interleaveOrder": [
                    "baseline", "final", "xray", "final", "baseline", "xray",
                    "final", "baseline", "xray", "baseline", "final", "xray",
                    "baseline", "final", "xray", "final", "baseline", "xray",
                ],
            }
        },
    }
    contract = {
        "phase": "complete",
        "exploratory": False,
        "script": {"harnessCommit": CANDIDATE["commit"]},
        "binaries": [
            {"label": "candidate", **CANDIDATE, "sourceCommit": CANDIDATE["commit"],
             "buildId": "c1"},
            {"label": "baseline", **BASELINE, "sourceCommit": BASELINE["commit"],
             "buildId": "b1"},
        ],
    }
    factors = {
        "baseline": (1.0, 0.1),
        "final": (candidate_factor, 0.098),
        "xray": (1.0, 0.1),
    }
    next_sample = {implementation: 0 for implementation in factors}
    rows = []
    for implementation in summary["cells"][key]["interleaveOrder"]:
        factor, latency = factors[implementation]
        sample = next_sample[implementation]
        next_sample[implementation] += 1
        rows.append({
                "implementation": implementation,
                "scenario": "direct-download",
                "direction": "download",
                "payloadBytes": 1_048_576,
                "concurrency": 1,
                "sampleIndex": sample,
                "invalid": False,
                "bytesVerified": True,
                "throughputMiBPerSecond": 100.0 * factor,
                "perRequestSeconds": [latency],
        })
    write_json(run / "summary.json", summary)
    write_json(run / "run-contract.json", contract)
    write_jsonl(run / "samples.jsonl", rows)
    files = {
        name: sha(run / name)
        for name in ("summary.json", "run-contract.json", "samples.jsonl")
    }
    return {"name": "matrix", "kind": "matrix", "runDir": str(run), "files": files}


def manifest(root: Path, candidate_factor: float = 1.02) -> tuple[Path, list[dict]]:
    workloads = [
        pair_fixture(root, "setup-abba", candidate_factor),
        pair_fixture(root, "fallback-abba", candidate_factor),
        matrix_fixture(root, candidate_factor),
    ]
    path = root / "manifest.json"
    write_json(path, {
        "schemaVersion": 1,
        "tier": "portable",
        "candidate": CANDIDATE,
        "baseline": BASELINE,
        "bootstrapIterations": 20_000,
        "workloads": workloads,
    })
    return path, workloads


def invoke(script: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(script), *arguments],
        capture_output=True, text=True, check=False,
    )


def test_evaluator(root: Path) -> None:
    passing = root / "pass"
    passing.mkdir()
    passing_manifest, _ = manifest(passing)
    passing_output = passing / "result.json"
    result = invoke(EVALUATOR, "--manifest", str(passing_manifest),
                    "--output", str(passing_output))
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert json.loads(passing_output.read_text())["overallPerformanceVerdict"] == "PASS"

    regression = root / "regression"
    regression.mkdir()
    regression_manifest, _ = manifest(regression, 0.80)
    regression_output = regression / "result.json"
    result = invoke(EVALUATOR, "--manifest", str(regression_manifest),
                    "--output", str(regression_output))
    assert result.returncode == 1, (result.stdout, result.stderr)
    report = json.loads(regression_output.read_text())
    assert report["overallPerformanceVerdict"] == "FAIL"
    assert report["regressions"]

    missing = root / "missing"
    missing.mkdir()
    missing_manifest, workloads = manifest(missing)
    setup = Path(workloads[0]["runDir"])
    rows = (setup / "raw-samples.jsonl").read_text().splitlines()
    (setup / "raw-samples.jsonl").write_text("\n".join(rows[:-1]) + "\n")
    document = json.loads(missing_manifest.read_text())
    document["workloads"][0]["files"]["raw-samples.jsonl"] = sha(
        setup / "raw-samples.jsonl"
    )
    write_json(missing_manifest, document)
    missing_output = missing / "result.json"
    result = invoke(EVALUATOR, "--manifest", str(missing_manifest),
                    "--output", str(missing_output))
    assert result.returncode == 2, (result.stdout, result.stderr)
    assert json.loads(missing_output.read_text())["overallPerformanceVerdict"] == "INVALID"

    reordered = root / "reordered"
    reordered.mkdir()
    reordered_manifest, workloads = manifest(reordered)
    matrix = Path(workloads[2]["runDir"])
    rows = (matrix / "samples.jsonl").read_text().splitlines()
    rows[0], rows[1] = rows[1], rows[0]
    (matrix / "samples.jsonl").write_text("\n".join(rows) + "\n")
    document = json.loads(reordered_manifest.read_text())
    document["workloads"][2]["files"]["samples.jsonl"] = sha(
        matrix / "samples.jsonl"
    )
    write_json(reordered_manifest, document)
    reordered_output = reordered / "result.json"
    result = invoke(EVALUATOR, "--manifest", str(reordered_manifest),
                    "--output", str(reordered_output))
    assert result.returncode == 2, (result.stdout, result.stderr)
    assert json.loads(reordered_output.read_text())["overallPerformanceVerdict"] == "INVALID"


def netem_fixture(root: Path, omit_last: bool = False) -> tuple[Path, list[Path]]:
    profiles = root / "profiles.jsonl"
    profile_rows = []
    raw_paths = []
    for rtt in (0, 20):
        for loss in (0.0, 1.0):
            raw = {}
            for leg in ("nxr", "socks"):
                path = root / f"rtt{rtt}-loss{loss}-{leg}.jsonl"
                rows = [
                    {"concurrency": concurrency, "sampleIndex": sample,
                     "failed": 0, "connections": 3,
                     "connectionsPerSecond": 100.0, "p50Seconds": 0.01,
                     "p95Seconds": 0.02, "p99Seconds": 0.03}
                    for concurrency in (1, 2) for sample in (0, 1)
                ]
                if omit_last and rtt == 20 and loss == 1.0 and leg == "socks":
                    rows.pop()
                write_jsonl(path, rows)
                raw[leg] = str(path)
                raw_paths.append(path)
            profile_rows.append({"targetRttMs": rtt,
                                 "perDirectionLossPercent": loss, "raw": raw})
    write_jsonl(profiles, profile_rows)
    return profiles, raw_paths


def test_netem(root: Path) -> None:
    passing = root / "netem-pass"
    passing.mkdir()
    profiles, _ = netem_fixture(passing)
    output = passing / "summary.json"
    result = invoke(NETEM, "--profiles", str(profiles), "--output", str(output),
                    "--rtts", "0 20", "--losses", "0 1",
                    "--concurrencies", "1 2", "--samples", "2",
                    "--connections", "3")
    assert result.returncode == 0, (result.stdout, result.stderr)
    report = json.loads(output.read_text())
    assert report["expectedRawRecordCount"] == 32
    assert report["actualRawRecordCount"] == 32

    missing = root / "netem-missing"
    missing.mkdir()
    profiles, _ = netem_fixture(missing, omit_last=True)
    output = missing / "summary.json"
    result = invoke(NETEM, "--profiles", str(profiles), "--output", str(output),
                    "--rtts", "0 20", "--losses", "0 1",
                    "--concurrencies", "1 2", "--samples", "2",
                    "--connections", "3")
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert json.loads(output.read_text())["dataQualityVerdict"] == "FAIL"


def deployment_summary_fixture(root: Path) -> None:
    cost_labels = (
        "cost-simple", "cost-medium", "cost-complex",
        "cost-complex-ipifnonmatch", "cost-complex-ipondemand",
    )
    labels = list(cost_labels) + [f"topo-{name}" for name in "abcd"]
    labels.extend(
        f"rtt{rtt}-loss{str(loss).replace('.', 'p')}-{leg}"
        for rtt in (0, 20, 50, 100, 200)
        for loss in (0, 0.1, 1)
        for leg in ("nxr", "socks")
    )
    for label in labels:
        rows = [
            {
                "concurrency": concurrency,
                "sampleIndex": sample,
                "connections": 96,
                "failed": 0,
                "connectionsPerSecond": 100.0,
                "p50Seconds": 0.01,
                "p95Seconds": 0.02,
                "p99Seconds": 0.03,
            }
            for concurrency in (8, 32) for sample in range(3)
        ]
        write_jsonl(root / f"setup-{label}.jsonl", rows)
    for topology in "abcd":
        for mib, concurrency in ((32, 1), (32, 32), (512, 32)):
            rows = [
                {
                    "sampleIndex": sample,
                    "throughputMiBPerSecond": 100.0,
                    "integrity": "pass" if sample == 0 else "skip",
                }
                for sample in range(3)
            ]
            write_jsonl(
                root / f"tput-topo-{topology}-{mib}mib-c{concurrency}.jsonl", rows
            )
    write_json(root / "summary-routing.json", {
        "cases": 26, "passed": 26, "failed": 0, "verdict": "PASS",
    })
    write_json(root / "summary-longflow.json", {"verdict": "PASS"})
    write_json(root / "summary-netem.json", {
        "verdict": "PASS",
        "dataQualityVerdict": "PASS",
        "performanceVerdict": "NOT_EVALUATED",
        "expectedDimensions": {
            "rttsMs": [0, 20, 50, 100, 200],
            "perDirectionLossPercent": [0.0, 0.1, 1.0],
            "legs": ["nxr", "socks"],
            "concurrencies": [8, 32],
            "samplesPerConcurrency": 3,
            "connectionsPerSample": 96,
        },
        "expectedProfileCount": 15,
        "actualProfileCount": 15,
        "expectedRawRecordCount": 180,
        "actualRawRecordCount": 180,
        "missingProfiles": [],
        "unexpectedProfiles": [],
    })


def test_deployment_summary(root: Path) -> None:
    deployment = root / "deployment-summary"
    deployment.mkdir()
    deployment_summary_fixture(deployment)
    arguments = (
        "summarize", "--out-dir", str(deployment), "--formal-plan",
        "--samples", "3", "--connections", "96",
        "--concurrencies", "8 32", "--throughput-samples", "3",
        "--throughput-cells", "32:1 32:32 512:32",
        "--rtts", "0 20 50 100 200", "--losses", "0 0.1 1",
    )
    result = invoke(DEPLOYMENT_DRIVER, *arguments)
    assert result.returncode == 0, (result.stdout, result.stderr)
    report = json.loads((deployment / "summary.json").read_text())
    assert report["gateVerdict"] == "PASS"
    assert report["performanceVerdict"] == "NOT_EVALUATED"
    assert len(report["setup"]) == 39

    (deployment / "setup-topo-d.jsonl").unlink()
    result = invoke(DEPLOYMENT_DRIVER, *arguments)
    assert result.returncode == 1, (result.stdout, result.stderr)
    report = json.loads((deployment / "summary.json").read_text())
    assert report["dataQualityVerdict"] == "FAIL"
    assert "formal:setup-label-set" in report["dataQualityFailures"]


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="rust-reality-performance-gate-") as value:
        root = Path(value).resolve()
        test_evaluator(root)
        test_netem(root)
        test_deployment_summary(root)
    print("release performance evaluator synthetic gates: PASS")


if __name__ == "__main__":
    main()
