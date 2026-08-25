#!/usr/bin/env python3
"""Synthetic PASS/regression/missing-evidence tests for release performance gates."""

from __future__ import annotations

import hashlib
import json
import math
import os
import runpy
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
EVALUATOR = ROOT / "evaluate-release-performance.py"
NETEM = ROOT / "validate-deployment-netem.py"
DEPLOYMENT_DRIVER = ROOT / "deployment_driver.py"
HOST_LOCK_CONTRACT = ROOT / "benchmark-contract.sh"
HOST_LOCK_HELPER = ROOT / "host-exclusive-lock-keeper.py"
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


def lock_metadata(root: Path, ordinal: int) -> dict:
    lock = root / "host-exclusive.lock"
    lock.touch(exist_ok=True)
    identity = f"{lock.stat().st_dev}:{lock.stat().st_ino}"
    base = {
        "protocolVersion": 1,
        "path": str(lock.resolve()),
        "deviceInode": identity,
        "mode": "dedicatedKeeper",
        "keeperPid": 1001 + ordinal * 10,
        "keeperStarttime": str(10001 + ordinal * 100),
        "keeperExe": str(Path(sys.executable).resolve()),
        "parentPid": 1000 + ordinal * 10,
        "parentStarttime": str(10000 + ordinal * 100),
        "keeperHelper": {
            "path": str(HOST_LOCK_HELPER.resolve()),
            "sha256": sha(HOST_LOCK_HELPER),
        },
        "required": True,
    }
    return {**base, "preflight": dict(base), "postflight": dict(base)}


def write_success_marker(
    run: Path, evidence_name: str, marker_name: str, run_id: str, collector: str,
) -> None:
    evidence = run / evidence_name
    write_json(run / marker_name, {
        "schemaVersion": 1,
        "status": "COMPLETE",
        "exitCode": 0,
        "runId": run_id,
        "collector": collector,
        "evidence": {"path": str(evidence.resolve()), "sha256": sha(evidence)},
        "recordedUtc": "2026-08-13T00:00:00Z",
    })


def order_rows(blocks: int = 12) -> list[dict]:
    rows = []
    orders = (
        ("baseline", "candidate", "candidate", "baseline"),
        ("candidate", "baseline", "baseline", "candidate"),
    )
    for block in range(1, blocks + 1):
        sequence = orders[(block - 1) % len(orders)]
        for position, implementation in enumerate(sequence, 1):
            rows.append({
                "block": block,
                "position": position,
                "implementation": implementation,
                "serverPort": 20_000 + block * 10 + position,
            })
    return rows


def pair_fixture(
    root: Path, kind: str, candidate_factor: float = 1.02, blocks: int = 12,
) -> dict:
    run = root / kind
    run.mkdir()
    setup = kind == "setup-abba"
    throughput_field = "connectionsPerSecond" if setup else "throughputMiBPerSecond"
    order = order_rows(blocks)
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
                for _ in range(blocks)
            ],
        },
    }
    run_id = f"{kind}-run"
    host_lock = lock_metadata(root, 1 if setup else 2)
    environment = {
        "schemaVersion": 2,
        "runId": run_id,
        "repository": {"head": CANDIDATE["commit"], "dirty": False},
        "blocks": blocks,
        "samplesPerSlot": 1,
        "connectionsPerSample": 4,
        "payloadMiB": 1,
        "concurrencies": "1",
        "baseline": {**BASELINE, "buildId": "b1"},
        "candidate": {**CANDIDATE, "buildId": "c1"},
        "harness": {
            "contract": {
                "path": str(HOST_LOCK_CONTRACT.resolve()),
                "sha256": sha(HOST_LOCK_CONTRACT),
            },
            "keeperHelper": host_lock["keeperHelper"],
        },
        "hostExclusiveLock": host_lock,
    }
    write_json(run / "summary.json", summary)
    write_json(run / "environment.json", environment)
    write_json(run / "order.json", {"slots": order})
    write_jsonl(run / "raw-samples.jsonl", rows)
    write_success_marker(
        run, "environment.json", "completion.json", run_id,
        "benchmark-setup-rate" if setup else "benchmark-fallback-ab",
    )
    files = {
        name: sha(run / name)
        for name in (
            "summary.json", "environment.json", "order.json", "raw-samples.jsonl",
            "completion.json",
        )
    }
    return {"name": "setup" if setup else "fallback", "kind": kind,
            "runDir": str(run), "files": files}


def matrix_fixture(
    root: Path, candidate_factor: float = 1.02, blocks: int = 12,
) -> dict:
    run = root / "matrix"
    run.mkdir()
    key = "direct-download:1:1"
    interleave = []
    paired_orders = (
        ("baseline", "final", "final", "baseline"),
        ("final", "baseline", "baseline", "final"),
    )
    for block in range(blocks):
        paired = paired_orders[block % len(paired_orders)]
        interleave.extend((paired[0], paired[1], "xray",
                           paired[2], paired[3], "xray"))
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
                "samplesPerImplementation": blocks * 2,
                "interleaveOrder": interleave,
            }
        },
    }
    contract = {
        "runId": "matrix-run",
        "phase": "complete",
        "exploratory": False,
        "script": {"harnessCommit": CANDIDATE["commit"]},
        "contract": {
            "path": str(HOST_LOCK_CONTRACT.resolve()),
            "sha256": sha(HOST_LOCK_CONTRACT),
        },
        "binaries": [
            {"label": "candidate", **CANDIDATE, "sourceCommit": CANDIDATE["commit"],
             "buildId": "c1"},
            {"label": "baseline", **BASELINE, "sourceCommit": BASELINE["commit"],
             "buildId": "b1"},
        ],
        "hostExclusiveLock": {
            key: value for key, value in lock_metadata(root, 3).items()
            if key not in {"preflight", "postflight"}
        },
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
    write_success_marker(
        run, "run-contract.json", "run-completion.json", "matrix-run",
        "benchmark-matrix",
    )
    files = {
        name: sha(run / name)
        for name in (
            "summary.json", "run-contract.json", "samples.jsonl", "run-completion.json"
        )
    }
    return {"name": "matrix", "kind": "matrix", "runDir": str(run), "files": files}


def manifest(
    root: Path, candidate_factor: float = 1.02, blocks: int = 12,
) -> tuple[Path, list[dict]]:
    workloads = [
        pair_fixture(root, "setup-abba", candidate_factor, blocks),
        pair_fixture(root, "fallback-abba", candidate_factor, blocks),
        matrix_fixture(root, candidate_factor, blocks),
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


def bash_command(source: str, *arguments: str) -> list[str]:
    return ["bash", "-c", source, "host-lock-test", *arguments]


def test_host_lock_keeper(root: Path) -> None:
    repository = str(ROOT.parent.resolve())
    contract = str(HOST_LOCK_CONTRACT.resolve())
    lock = str((root / "keeper-host-exclusive.lock").resolve())
    holder_script = r'''
set -Eeuo pipefail
source "$1"
rr_host_lock_acquire "$2" "$3"
trap 'rr_host_lock_stop >/dev/null 2>&1 || true' EXIT
rr_host_lock_verify
echo READY
read -r _
rr_host_lock_stop
trap - EXIT
'''
    contender_script = r'''
set -Eeuo pipefail
source "$1"
if rr_host_lock_acquire "$2" "$3" >/dev/null 2>&1; then
    rr_host_lock_verify
    rr_host_lock_stop
    exit 0
fi
rr_host_lock_stop >/dev/null 2>&1 || true
exit 23
'''
    holder = subprocess.Popen(
        bash_command(holder_script, contract, repository, lock),
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout is not None and holder.stdout.readline().strip() == "READY"
        contender = subprocess.run(
            bash_command(contender_script, contract, repository, lock),
            capture_output=True, text=True, check=False, timeout=10,
        )
        assert contender.returncode == 23, (contender.stdout, contender.stderr)
        assert holder.stdin is not None
        holder.stdin.write("stop\n")
        holder.stdin.flush()
        stdout, stderr = holder.communicate(timeout=10)
        assert holder.returncode == 0, (stdout, stderr)
        after = subprocess.run(
            bash_command(contender_script, contract, repository, lock),
            capture_output=True, text=True, check=False, timeout=10,
        )
        assert after.returncode == 0, (after.stdout, after.stderr)
    finally:
        if holder.poll() is None:
            holder.terminate()
            holder.wait(timeout=10)

    background_script = r'''
set -Eeuo pipefail
source "$1"
rr_host_lock_acquire "$2" "$3"
sleep 30 &
child=$!
trap 'kill -TERM "$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true; rr_host_lock_stop >/dev/null 2>&1 || true' EXIT
rr_host_lock_stop
kill -0 "$child"
echo "RELEASED $child"
read -r _
kill -TERM "$child" 2>/dev/null || true
wait "$child" 2>/dev/null || true
trap - EXIT
'''
    background = subprocess.Popen(
        bash_command(background_script, contract, repository, lock),
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert background.stdout is not None
        released = background.stdout.readline().strip().split()
        assert len(released) == 2 and released[0] == "RELEASED"
        after = subprocess.run(
            bash_command(contender_script, contract, repository, lock),
            capture_output=True, text=True, check=False, timeout=10,
        )
        assert after.returncode == 0, (after.stdout, after.stderr)
        assert background.stdin is not None
        background.stdin.write("stop\n")
        background.stdin.flush()
        stdout, stderr = background.communicate(timeout=10)
        assert background.returncode == 0, (stdout, stderr)
    finally:
        if background.poll() is None:
            background.terminate()
            background.wait(timeout=10)

    marker_root = root / "success-marker"
    marker_root.mkdir()
    evidence = marker_root / "evidence.json"
    write_json(evidence, {"status": "COMPLETE"})
    marker = marker_root / "completion.json"
    marker_script = r'''
set -Eeuo pipefail
source "$1"
rr_write_success_marker "$2" "$3" marker-run marker-test
if rr_write_success_marker "$2" "$3" marker-run marker-test >/dev/null 2>&1; then
    exit 31
fi
'''
    result = subprocess.run(
        bash_command(
            marker_script, contract, str(marker.resolve()), str(evidence.resolve())
        ), capture_output=True, text=True, check=False, timeout=10,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    marker_record = json.loads(marker.read_text())
    assert marker_record["exitCode"] == 0
    assert marker_record["evidence"]["sha256"] == sha(evidence)


def test_collector_early_failure_releases_lock(root: Path) -> None:
    repository = str(ROOT.parent.resolve())
    contract = str(HOST_LOCK_CONTRACT.resolve())
    lock = str((root / "collector-failure.lock").resolve())
    contender_script = r'''
set -Eeuo pipefail
source "$1"
rr_host_lock_acquire "$2" "$3"
rr_host_lock_verify
rr_host_lock_stop
'''
    environment = os.environ.copy()
    for name in (
        "RUN_ID", "OUT_DIR", "TMPDIR", "PORT_BASE", "SELF_TEST",
        "RR_HOST_EXCLUSIVE_FD", "RR_HOST_LOCK_PYTHON3_TEST_ONLY",
    ):
        environment.pop(name, None)
    environment["RR_HOST_EXCLUSIVE_LOCK"] = lock
    for collector in (ROOT / "benchmark-setup-rate.sh", ROOT / "benchmark-fallback-ab.sh"):
        failed = subprocess.run(
            ["bash", str(collector)], capture_output=True, text=True, check=False,
            timeout=15, env=environment,
        )
        assert failed.returncode != 0, (collector, failed.stdout, failed.stderr)
        after = subprocess.run(
            bash_command(contender_script, contract, repository, lock),
            capture_output=True, text=True, check=False, timeout=15,
        )
        assert after.returncode == 0, (collector, after.stdout, after.stderr)


def test_evaluator(root: Path) -> None:
    passing = root / "pass"
    passing.mkdir()
    passing_manifest, _ = manifest(passing)
    passing_output = passing / "result.json"
    result = invoke(EVALUATOR, "--manifest", str(passing_manifest),
                    "--output", str(passing_output))
    assert result.returncode == 0, (result.stdout, result.stderr)
    passing_report = json.loads(passing_output.read_text())
    assert passing_report["overallPerformanceVerdict"] == "PASS"
    assert len({
        row["hostExclusiveLock"]["keeperPid"] for row in passing_report["inputs"]
    }) == 3
    assert passing_report["method"]["hypothesisFamilySize"] == 8
    assert passing_report["method"]["hypothesisFamilies"] == {
        "regression": 8, "improvement": 8,
    }
    assert not any(row["significant"] for row in passing_report["protectedMetrics"])
    assert all(
        row["improvementSignificant"] for row in passing_report["protectedMetrics"]
    )
    deterministic_output = passing / "result-deterministic.json"
    result = invoke(EVALUATOR, "--manifest", str(passing_manifest),
                    "--output", str(deterministic_output))
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert passing_output.read_bytes() == deterministic_output.read_bytes()

    three_same_direction = root / "three-same-direction"
    three_same_direction.mkdir()
    three_manifest, _ = manifest(three_same_direction, 0.80, blocks=3)
    three_output = three_same_direction / "result.json"
    result = invoke(EVALUATOR, "--manifest", str(three_manifest),
                    "--output", str(three_output))
    assert result.returncode == 2, (result.stdout, result.stderr)
    report = json.loads(three_output.read_text())
    assert report["overallPerformanceVerdict"] == "INVALID"
    assert "requires 12..16 complete ABBA blocks" in report["errors"][0]

    regression = root / "regression-twelve-blocks"
    regression.mkdir()
    regression_manifest, _ = manifest(regression, 0.80, blocks=12)
    regression_output = regression / "result.json"
    result = invoke(EVALUATOR, "--manifest", str(regression_manifest),
                    "--output", str(regression_output))
    assert result.returncode == 1, (result.stdout, result.stderr)
    report = json.loads(regression_output.read_text())
    assert report["overallPerformanceVerdict"] == "FAIL"
    assert report["regressions"]
    throughput = next(
        row for row in report["protectedMetrics"]
        if row["id"] == "setup:c1:throughput"
    )
    assert throughput["rawPValue"] == 1.0 / 4096.0
    assert throughput["holmAdjustedPValue"] <= 0.05
    assert throughput["significant"] is True

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

    missing_lock = root / "missing-lock"
    missing_lock.mkdir()
    missing_lock_manifest, workloads = manifest(missing_lock)
    setup = Path(workloads[0]["runDir"])
    environment = json.loads((setup / "environment.json").read_text())
    del environment["hostExclusiveLock"]
    write_json(setup / "environment.json", environment)
    completion = json.loads((setup / "completion.json").read_text())
    completion["evidence"]["sha256"] = sha(setup / "environment.json")
    write_json(setup / "completion.json", completion)
    document = json.loads(missing_lock_manifest.read_text())
    document["workloads"][0]["files"]["environment.json"] = sha(
        setup / "environment.json"
    )
    document["workloads"][0]["files"]["completion.json"] = sha(
        setup / "completion.json"
    )
    write_json(missing_lock_manifest, document)
    missing_lock_output = missing_lock / "result.json"
    result = invoke(EVALUATOR, "--manifest", str(missing_lock_manifest),
                    "--output", str(missing_lock_output))
    assert result.returncode == 2, (result.stdout, result.stderr)
    assert json.loads(missing_lock_output.read_text())["overallPerformanceVerdict"] == "INVALID"

    failed_exit = root / "failed-exit"
    failed_exit.mkdir()
    failed_exit_manifest, workloads = manifest(failed_exit)
    fallback = Path(workloads[1]["runDir"])
    completion = json.loads((fallback / "completion.json").read_text())
    completion["exitCode"] = 2
    write_json(fallback / "completion.json", completion)
    document = json.loads(failed_exit_manifest.read_text())
    document["workloads"][1]["files"]["completion.json"] = sha(
        fallback / "completion.json"
    )
    write_json(failed_exit_manifest, document)
    failed_exit_output = failed_exit / "result.json"
    result = invoke(EVALUATOR, "--manifest", str(failed_exit_manifest),
                    "--output", str(failed_exit_output))
    assert result.returncode == 2, (result.stdout, result.stderr)
    assert json.loads(failed_exit_output.read_text())["overallPerformanceVerdict"] == "INVALID"

    missing_completion = root / "missing-completion"
    missing_completion.mkdir()
    missing_completion_manifest, workloads = manifest(missing_completion)
    matrix = Path(workloads[2]["runDir"])
    (matrix / "run-completion.json").unlink()
    missing_completion_output = missing_completion / "result.json"
    result = invoke(EVALUATOR, "--manifest", str(missing_completion_manifest),
                    "--output", str(missing_completion_output))
    assert result.returncode == 2, (result.stdout, result.stderr)
    assert json.loads(missing_completion_output.read_text())[
        "overallPerformanceVerdict"
    ] == "INVALID"

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


def test_exact_statistics() -> None:
    evaluator = runpy.run_path(str(EVALUATOR))
    exact = evaluator["exact_sign_flip_pvalues"]
    holm = evaluator["holm_adjusted_pvalues"]
    floating_regression = [-math.log(2.0), -math.log(3.0), -math.log(5.0)]
    regression, improvement = exact(floating_regression)
    assert regression == 1.0 / 8.0
    assert improvement == 1.0
    regression, improvement = exact([-1.0] * 12)
    assert regression == 1.0 / 4096.0
    assert improvement == 1.0

    hypotheses = [("a", 0.01), ("b", 0.04), ("c", 0.03)]
    adjusted = holm(hypotheses)
    reversed_adjusted = holm(list(reversed(hypotheses)))
    assert adjusted == reversed_adjusted
    assert math.isclose(adjusted["a"], 0.03)
    assert math.isclose(adjusted["b"], 0.06)
    assert math.isclose(adjusted["c"], 0.06)

    formal_family = holm([
        (f"metric-{index:03d}", 1.0 / 4096.0) for index in range(110)
    ])
    assert len(formal_family) == 110
    assert all(math.isclose(value, 110.0 / 4096.0)
               for value in formal_family.values())
    assert all(value <= 0.05 for value in formal_family.values())


def netem_fixture(root: Path, omit_last: bool = False) -> tuple[Path, list[Path]]:
    profiles = root / "profiles.jsonl"
    profile_rows = []
    raw_paths = []
    for rtt in (0, 20):
        for loss in (0.0, 1.0):
            raw = {}
            for leg in (
                "handoff-warm", "handoff-cold", "nxr-warm", "nxr-cold",
                "socks-warm", "socks-cold",
            ):
                path = root / f"rtt{rtt}-loss{loss}-{leg}.jsonl"
                rows = [
                    {"concurrency": concurrency, "sampleIndex": sample,
                     "failed": 0, "connections": 3,
                     "connectionsPerSecond": 100.0, "p50Seconds": 0.01,
                     "p90Seconds": 0.015, "p95Seconds": 0.02,
                     "p99Seconds": 0.03}
                    for concurrency in (1, 2) for sample in (0, 1)
                ]
                if omit_last and rtt == 20 and loss == 1.0 and leg == "socks-cold":
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
    assert report["expectedRawRecordCount"] == 96
    assert report["actualRawRecordCount"] == 96

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
    rtt_labels = [
        f"rtt{rtt}-loss{str(loss).replace('.', 'p')}-{leg}"
        for rtt in (1, 10, 50, 100, 200)
        for loss in (0, 0.1, 1)
        for leg in (
            "handoff-warm", "handoff-cold", "nxr-warm", "nxr-cold",
            "socks-warm", "socks-cold",
        )
    ]
    labels.extend(rtt_labels)
    for label in labels:
        if label in rtt_labels:
            concurrencies = (1, 8, 32, 128, 512)
            samples = range(6)
            connections = 512
        else:
            concurrencies = (8, 32)
            samples = range(3)
            connections = 96
        rows = [
            {
                "concurrency": concurrency,
                "sampleIndex": sample,
                "connections": connections,
                "failed": 0,
                "connectionsPerSecond": 100.0,
                "p50Seconds": 0.01,
                "p90Seconds": 0.015,
                "p95Seconds": 0.02,
                "p99Seconds": 0.03,
            }
            for concurrency in concurrencies for sample in samples
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
    write_jsonl(root / "tput-longflow-512mib-c1.jsonl", [{
        "sampleIndex": 0,
        "throughputMiBPerSecond": 100.0,
        "integrity": "pass",
    }])
    write_json(root / "summary-routing.json", {
        "cases": 26, "passed": 26, "failed": 0, "verdict": "PASS",
    })
    write_json(root / "summary-longflow.json", {"verdict": "PASS"})
    write_json(root / "summary-netem.json", {
        "verdict": "PASS",
        "dataQualityVerdict": "PASS",
        "performanceVerdict": "NOT_EVALUATED",
        "expectedDimensions": {
            "rttsMs": [1, 10, 50, 100, 200],
            "perDirectionLossPercent": [0.0, 0.1, 1.0],
            "legs": [
                "handoff-warm", "handoff-cold", "nxr-warm", "nxr-cold",
                "socks-warm", "socks-cold",
            ],
            "concurrencies": [1, 8, 32, 128, 512],
            "samplesPerConcurrency": 6,
            "connectionsPerSample": 512,
        },
        "expectedProfileCount": 15,
        "actualProfileCount": 15,
        "expectedRawRecordCount": 2700,
        "actualRawRecordCount": 2700,
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
        "--longflow-mib", "512",
        "--rtt-samples", "6", "--rtt-connections", "512",
        "--rtt-concurrencies", "1 8 32 128 512",
        "--rtts", "1 10 50 100 200", "--losses", "0 0.1 1",
    )
    result = invoke(DEPLOYMENT_DRIVER, *arguments)
    assert result.returncode == 0, (result.stdout, result.stderr)
    report = json.loads((deployment / "summary.json").read_text())
    assert report["gateVerdict"] == "PASS"
    assert report["performanceVerdict"] == "NOT_EVALUATED"
    assert len(report["setup"]) == 99

    (deployment / "setup-topo-d.jsonl").unlink()
    result = invoke(DEPLOYMENT_DRIVER, *arguments)
    assert result.returncode == 1, (result.stdout, result.stderr)
    report = json.loads((deployment / "summary.json").read_text())
    assert report["dataQualityVerdict"] == "FAIL"
    assert "formal:setup-label-set" in report["dataQualityFailures"]


def test_matrix_pipe_budget_model() -> None:
    script = (ROOT / "benchmark-matrix.sh").read_text(encoding="utf-8")
    variables = (
        "rust_pages_per_pipe",
        "xray_pages_per_pipe",
        "pipe_policy_tunnel_peak",
        "pipe_policy_fallback_peak",
        "pipe_policy_peak",
        "pipe_policy_required",
    )
    assignments = []
    for variable in variables:
        matches = [
            line for line in script.splitlines()
            if line.startswith(f"{variable}=$((")
        ]
        assert len(matches) == 1, (variable, matches)
        assignments.extend(matches)

    command = "\n".join((
        "set -eu",
        "pipe_policy_page_size=4096",
        "max_concurrency=32",
        *assignments,
        'printf "%s %s %s %s\\n" "$pipe_policy_tunnel_peak" '
        '"$pipe_policy_fallback_peak" "$pipe_policy_peak" '
        '"$pipe_policy_required"',
    ))
    result = subprocess.run(
        ["bash", "-c", command], text=True, capture_output=True, check=False,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    tunnel, fallback, peak, required = map(int, result.stdout.split())
    assert tunnel == 147_456
    assert fallback == 24_576
    assert peak == 172_032
    assert required == 344_064

    assert "calculated_peak_pages: $pipe_policy_peak" in script
    assert "calculated_tunnel_peak_pages: $pipe_policy_tunnel_peak" in script
    assert "calculated_fallback_peak_pages: $pipe_policy_fallback_peak" in script
    assert "bidirectional_connection_multiplier: 2" in script


def main() -> None:
    test_exact_statistics()
    with tempfile.TemporaryDirectory(prefix="rust-reality-performance-gate-") as value:
        root = Path(value).resolve()
        test_evaluator(root)
        test_netem(root)
        test_deployment_summary(root)
        test_host_lock_keeper(root)
        test_collector_early_failure_releases_lock(root)
        test_matrix_pipe_budget_model()
    print("release performance evaluator synthetic gates: PASS")


if __name__ == "__main__":
    main()
