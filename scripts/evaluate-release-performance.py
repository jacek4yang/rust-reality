#!/usr/bin/env python3
"""Fail-closed final evaluator for release ABBA performance evidence.

The workload scripts only claim that collection completed. This offline gate is
the sole component allowed to turn identity-pinned setup, fallback, and matrix
evidence into an overall performance PASS.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import re
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
BUILD_ID = re.compile(r"^[0-9a-f]+$")
DEVICE_INODE = re.compile(r"^[1-9][0-9]*:[1-9][0-9]*$")
HOST_LOCK_PROTOCOL_VERSION = 1
REQUIRED_KINDS = {"setup-abba", "fallback-abba", "matrix"}
FILES_BY_KIND = {
    "setup-abba": {
        "summary.json", "environment.json", "order.json", "raw-samples.jsonl",
        "completion.json",
    },
    "fallback-abba": {
        "summary.json", "environment.json", "order.json", "raw-samples.jsonl",
        "completion.json",
    },
    "matrix": {
        "summary.json", "samples.jsonl", "run-contract.json", "run-completion.json"
    },
}


class InvalidEvidence(RuntimeError):
    """Evidence is incomplete, malformed, or not bound to the requested build."""


def require(condition: Any, message: str) -> None:
    if not condition:
        raise InvalidEvidence(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise InvalidEvidence(f"cannot read JSON {path}: {error}") from error
    require(isinstance(value, dict), f"JSON root is not an object: {path}")
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise InvalidEvidence(f"cannot read JSONL {path}: {error}") from error
    for line_number, line in enumerate(lines, 1):
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise InvalidEvidence(f"{path}:{line_number}: {error}") from error
        require(isinstance(value, dict), f"{path}:{line_number}: row is not an object")
        rows.append(value)
    return rows


def verify_success_marker(
    marker: dict[str, Any], evidence_path: Path, run_id: Any, collector: str,
    context: str,
) -> None:
    require(marker.get("schemaVersion") == 1 and marker.get("status") == "COMPLETE",
            f"{context}: success marker is not COMPLETE schema 1")
    exit_code = marker.get("exitCode")
    require(isinstance(exit_code, int) and not isinstance(exit_code, bool)
            and exit_code == 0, f"{context}: collector exit code is not zero")
    require(isinstance(run_id, str) and run_id
            and marker.get("runId") == run_id,
            f"{context}: success marker run ID mismatch")
    require(marker.get("collector") == collector,
            f"{context}: success marker collector mismatch")
    evidence = marker.get("evidence")
    require(isinstance(evidence, dict), f"{context}: marker evidence identity missing")
    expected_path = str(evidence_path.resolve())
    require(evidence.get("path") == expected_path,
            f"{context}: marker evidence path mismatch")
    require(evidence.get("sha256") == sha256_file(evidence_path),
            f"{context}: marker evidence SHA-256 mismatch")


def positive_number(value: Any, context: str) -> float:
    require(
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value > 0,
        f"{context} must be a positive finite number",
    )
    return float(value)


def nearest_rank(values: Iterable[float], fraction: float) -> float:
    ordered = sorted(values)
    require(bool(ordered), "tail-latency sample list is empty")
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def bootstrap_interval(ratios: list[float], iterations: int, seed_text: str) -> list[float]:
    require(len(ratios) >= 3, f"{seed_text}: fewer than three complete ABBA blocks")
    seed = int.from_bytes(hashlib.sha256(seed_text.encode()).digest()[:8], "big")
    rng = random.Random(seed)
    medians = sorted(
        statistics.median(rng.choices(ratios, k=len(ratios)))
        for _ in range(iterations)
    )
    return [medians[iterations // 40], medians[(iterations * 39) // 40 - 1]]


def metric(
    metric_id: str,
    workload: str,
    measure: str,
    unit: str,
    direction: str,
    ratios: list[float],
    iterations: int,
) -> dict[str, Any]:
    require(direction in {"higher-is-better", "lower-is-better"}, "bad direction")
    for index, ratio in enumerate(ratios):
        positive_number(ratio, f"{metric_id} block ratio {index}")
    interval = bootstrap_interval(ratios, iterations, metric_id)
    point = statistics.median(ratios)
    if direction == "higher-is-better":
        regression = interval[1] < 1.0
        improvement = interval[0] > 1.0
        keep_improvement = point >= 1.01 and improvement
    else:
        regression = interval[0] > 1.0
        improvement = interval[1] < 1.0
        keep_improvement = point <= 1.0 / 1.01 and improvement
    classification = (
        "REGRESSION" if regression else
        "KEEP_IMPROVEMENT" if keep_improvement else
        "SMALL_IMPROVEMENT" if improvement else
        "NO_SIGNIFICANT_CHANGE"
    )
    return {
        "id": metric_id,
        "workload": workload,
        "measure": measure,
        "unit": unit,
        "direction": direction,
        "blocks": ratios,
        "blockCount": len(ratios),
        "medianCandidateVsBaseline": point,
        "bootstrap95": interval,
        "classification": classification,
        "pass": not regression,
    }


def identity(value: Any, context: str) -> dict[str, str]:
    require(isinstance(value, dict), f"{context} identity is not an object")
    commit = value.get("commit")
    sha = value.get("sha256")
    require(isinstance(commit, str) and HEX40.fullmatch(commit), f"{context} commit invalid")
    require(isinstance(sha, str) and HEX64.fullmatch(sha), f"{context} SHA-256 invalid")
    return {"commit": commit, "sha256": sha}


def verify_host_lock_metadata(value: Any, context: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{context}: host lock metadata missing")
    require(value.get("protocolVersion") == HOST_LOCK_PROTOCOL_VERSION,
            f"{context}: host lock protocol version mismatch")
    require(value.get("required") is True and value.get("mode") == "dedicatedKeeper",
            f"{context}: dedicated host lock was not required/held")
    path_text = value.get("path")
    require(isinstance(path_text, str) and path_text.startswith("/"),
            f"{context}: host lock path is not absolute")
    path = Path(path_text)
    require(path.is_file() and not path.is_symlink() and str(path.resolve()) == path_text,
            f"{context}: host lock path is not a canonical regular file")
    recorded_device_inode = value.get("deviceInode")
    require(isinstance(recorded_device_inode, str)
            and DEVICE_INODE.fullmatch(recorded_device_inode),
            f"{context}: host lock device/inode is invalid")
    observed = path.stat()
    require(recorded_device_inode == f"{observed.st_dev}:{observed.st_ino}",
            f"{context}: host lock device/inode no longer matches its path")
    for field in ("keeperPid", "parentPid"):
        require(isinstance(value.get(field), int) and value[field] > 1,
                f"{context}: {field} is invalid")
    for field in ("keeperStarttime", "parentStarttime"):
        observed_start = value.get(field)
        require(isinstance(observed_start, str) and observed_start.isdecimal()
                and int(observed_start) > 0, f"{context}: {field} is invalid")
    keeper_exe = value.get("keeperExe")
    require(isinstance(keeper_exe, str) and keeper_exe.startswith("/"),
            f"{context}: keeper executable path is invalid")
    keeper_exe_path = Path(keeper_exe)
    require(keeper_exe_path.is_file()
            and str(keeper_exe_path.resolve()) == keeper_exe,
            f"{context}: keeper executable path is not canonical")
    helper = value.get("keeperHelper")
    require(isinstance(helper, dict), f"{context}: keeper helper identity missing")
    helper_path = helper.get("path")
    helper_sha = helper.get("sha256")
    require(isinstance(helper_path, str) and helper_path.startswith("/"),
            f"{context}: keeper helper path is not absolute")
    require(isinstance(helper_sha, str) and HEX64.fullmatch(helper_sha),
            f"{context}: keeper helper SHA-256 is invalid")
    helper_file = Path(helper_path)
    require(helper_file.is_file() and not helper_file.is_symlink()
            and str(helper_file.resolve()) == helper_path,
            f"{context}: keeper helper path is invalid")
    require(sha256_file(helper_file) == helper_sha,
            f"{context}: keeper helper SHA-256 no longer matches")
    return {
        "protocolVersion": value["protocolVersion"],
        "path": path_text,
        "deviceInode": recorded_device_inode,
        "mode": value["mode"],
        "keeperPid": value["keeperPid"],
        "keeperStarttime": value["keeperStarttime"],
        "keeperExe": keeper_exe,
        "parentPid": value["parentPid"],
        "parentStarttime": value["parentStarttime"],
        "keeperHelper": {"path": helper_path, "sha256": helper_sha},
        "required": True,
    }


def verify_contract_identity(value: Any, context: str) -> dict[str, str]:
    require(isinstance(value, dict)
            and isinstance(value.get("path"), str)
            and value["path"].startswith("/")
            and isinstance(value.get("sha256"), str)
            and HEX64.fullmatch(value["sha256"]),
            f"{context}: lock contract identity missing")
    path = Path(value["path"])
    require(path.is_file() and not path.is_symlink()
            and str(path.resolve()) == value["path"]
            and sha256_file(path) == value["sha256"],
            f"{context}: lock contract path/SHA-256 mismatch")
    return {"path": value["path"], "sha256": value["sha256"]}


def verify_pair_host_lock(environment: dict[str, Any], context: str) -> dict[str, Any]:
    evidence = environment.get("hostExclusiveLock")
    current = verify_host_lock_metadata(evidence, context)
    require(isinstance(evidence.get("preflight"), dict)
            and isinstance(evidence.get("postflight"), dict),
            f"{context}: host lock preflight/postflight evidence missing")
    preflight = verify_host_lock_metadata(evidence["preflight"], f"{context} preflight")
    postflight = verify_host_lock_metadata(evidence["postflight"], f"{context} postflight")
    require(current == preflight == postflight,
            f"{context}: host lock identity changed during collection")
    harness = environment.get("harness")
    require(isinstance(harness, dict), f"{context}: harness identity missing")
    contract = verify_contract_identity(harness.get("contract"), context)
    helper = harness.get("keeperHelper")
    require(helper == current["keeperHelper"],
            f"{context}: harness keeper identity disagrees with lock evidence")
    current["contract"] = contract
    return current


def coordination_identity(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "protocolVersion": value["protocolVersion"],
        "path": value["path"],
        "deviceInode": value["deviceInode"],
        "mode": value["mode"],
        "keeperExe": value["keeperExe"],
        "keeperHelperSha256": value["keeperHelper"]["sha256"],
        "contractSha256": value["contract"]["sha256"],
    }


def verify_files(entry: dict[str, Any], kind: str) -> tuple[Path, dict[str, str]]:
    raw_run_dir = entry.get("runDir")
    require(isinstance(raw_run_dir, str) and raw_run_dir.startswith("/"),
            f"{kind}: runDir must be absolute")
    run_dir = Path(raw_run_dir)
    require(run_dir.is_dir() and not run_dir.is_symlink(), f"{kind}: invalid runDir")
    expected_files = FILES_BY_KIND[kind]
    files = entry.get("files")
    require(isinstance(files, dict) and set(files) == expected_files,
            f"{kind}: files must be exactly {sorted(expected_files)}")
    observed = {}
    for relative in sorted(expected_files):
        expected_sha = files.get(relative)
        require(isinstance(expected_sha, str) and HEX64.fullmatch(expected_sha),
                f"{kind}: invalid expected SHA for {relative}")
        path = run_dir / relative
        require(path.is_file() and not path.is_symlink(), f"{kind}: invalid {relative}")
        require(path.resolve().parent == run_dir.resolve(), f"{kind}: path escaped runDir")
        actual_sha = sha256_file(path)
        require(actual_sha == expected_sha, f"{kind}: SHA mismatch for {relative}")
        observed[relative] = actual_sha
    return run_dir, observed


def verify_pair_environment(
    environment: dict[str, Any], candidate: dict[str, str], baseline: dict[str, str],
    context: str,
) -> dict[str, Any]:
    repository = environment.get("repository")
    require(isinstance(repository, dict) and repository.get("dirty") is False,
            f"{context}: repository was dirty")
    for label, expected in (("candidate", candidate), ("baseline", baseline)):
        observed = environment.get(label)
        require(isinstance(observed, dict), f"{context}: missing {label} identity")
        require(observed.get("sha256") == expected["sha256"],
                f"{context}: {label} SHA mismatch")
        require(observed.get("commit") == expected["commit"],
                f"{context}: {label} commit mismatch")
        require(isinstance(observed.get("buildId"), str)
                and BUILD_ID.fullmatch(observed["buildId"]),
                f"{context}: {label} Build ID missing")
    return verify_pair_host_lock(environment, context)


def verify_order(order: dict[str, Any], blocks: int) -> list[dict[str, Any]]:
    slots = order.get("slots")
    require(isinstance(slots, list) and len(slots) == blocks * 4,
            "order manifest does not contain exactly four slots per block")
    previous = None
    for block in range(1, blocks + 1):
        rows = sorted(
            (row for row in slots if row.get("block") == block),
            key=lambda row: row.get("position", -1),
        )
        require([row.get("position") for row in rows] == [1, 2, 3, 4],
                f"block {block}: positions are incomplete")
        sequence = [row.get("implementation") for row in rows]
        require(sequence in (["baseline", "candidate", "candidate", "baseline"],
                             ["candidate", "baseline", "baseline", "candidate"]),
                f"block {block}: not ABBA/BAAB")
        require(previous is None or sequence != previous,
                f"block {block}: direction did not alternate")
        previous = sequence
    return slots


def ratios_for_rows(
    rows: list[dict[str, Any]], blocks: int, concurrency: int, field: str,
) -> list[float]:
    ratios = []
    for block in range(1, blocks + 1):
        values = {}
        for implementation in ("baseline", "candidate"):
            selected = [
                positive_number(row.get(field), f"{field} row")
                for row in rows
                if row.get("block") == block
                and row.get("implementation") == implementation
                and row.get("concurrency") == concurrency
            ]
            require(bool(selected), f"block {block} {implementation} {field}: no samples")
            values[implementation] = statistics.median(selected)
        ratios.append(values["candidate"] / values["baseline"])
    return ratios


def cpu_metrics(
    summary: dict[str, Any], field: str, blocks: int, workload: str,
    unit: str, iterations: int,
) -> dict[str, Any]:
    cpu = summary.get(field)
    require(isinstance(cpu, dict), f"{workload}: missing {field}")
    rows = cpu.get("blocks")
    require(isinstance(rows, list) and len(rows) == blocks,
            f"{workload}: incomplete CPU blocks")
    ratios = []
    for index, row in enumerate(rows, 1):
        require(isinstance(row, dict), f"{workload}: CPU block {index} invalid")
        baseline = positive_number(row.get("baseline"), f"{workload} CPU baseline")
        candidate = positive_number(row.get("candidate"), f"{workload} CPU candidate")
        ratio = candidate / baseline
        recorded = positive_number(row.get("candidateVsBaseline"),
                                   f"{workload} CPU recorded ratio")
        require(math.isclose(ratio, recorded, rel_tol=1e-9),
                f"{workload}: CPU ratio mismatch in block {index}")
        ratios.append(ratio)
    return metric(f"{workload}:server-cpu", workload, "serverCpu", unit,
                  "lower-is-better", ratios, iterations)


def evaluate_pair_run(
    entry: dict[str, Any], kind: str, candidate: dict[str, str],
    baseline: dict[str, str], iterations: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    run_dir, hashes = verify_files(entry, kind)
    summary = load_json(run_dir / "summary.json")
    environment = load_json(run_dir / "environment.json")
    completion = load_json(run_dir / "completion.json")
    order = load_json(run_dir / "order.json")
    rows = load_jsonl(run_dir / "raw-samples.jsonl")
    verify_success_marker(
        completion, run_dir / "environment.json", environment.get("runId"),
        "benchmark-setup-rate" if kind == "setup-abba" else "benchmark-fallback-ab",
        kind,
    )
    require(summary.get("status") == "COMPLETE", f"{kind}: status is not COMPLETE")
    require(summary.get("performanceVerdict") == "NOT_EVALUATED",
            f"{kind}: collector claimed a performance verdict")
    require(summary.get("failures") == 0, f"{kind}: collector recorded failures")
    host_lock = verify_pair_environment(environment, candidate, baseline, kind)
    blocks = environment.get("blocks")
    samples = environment.get("samplesPerSlot")
    require(isinstance(blocks, int) and blocks >= 3, f"{kind}: need at least 3 blocks")
    require(isinstance(samples, int) and samples >= 1, f"{kind}: samples invalid")
    raw_concurrencies = environment.get("concurrencies")
    if isinstance(raw_concurrencies, str):
        try:
            concurrencies = [int(value) for value in raw_concurrencies.split()]
        except ValueError as error:
            raise InvalidEvidence(f"{kind}: invalid concurrencies") from error
    elif isinstance(raw_concurrencies, list):
        concurrencies = raw_concurrencies
    else:
        raise InvalidEvidence(f"{kind}: concurrencies missing")
    require(concurrencies and len(concurrencies) == len(set(concurrencies))
            and all(isinstance(value, int) and value > 0 for value in concurrencies),
            f"{kind}: concurrencies invalid")
    slots = verify_order(order, blocks)
    expected_slots = {
        (slot["block"], slot["position"]): slot["implementation"] for slot in slots
    }
    grouped: dict[tuple[int, int, int], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        key = (row.get("block"), row.get("position"))
        require(key in expected_slots, f"{kind}: raw row references an unknown slot")
        require(row.get("implementation") == expected_slots[key],
                f"{kind}: raw row implementation disagrees with order")
        concurrency = row.get("concurrency")
        require(concurrency in concurrencies, f"{kind}: unexpected concurrency")
        require(row.get("failed") == 0, f"{kind}: raw row has failures")
        if kind == "setup-abba":
            expected_connections = environment.get("connectionsPerSample")
            require(isinstance(expected_connections, int) and expected_connections > 0,
                    f"{kind}: connectionsPerSample invalid")
            require(row.get("connections") == expected_connections,
                    f"{kind}: setup row has a missing connection")
        else:
            payload_mib = environment.get("payloadMiB")
            expected_bytes = payload_mib * 1024 * 1024 if isinstance(payload_mib, int) else 0
            require(expected_bytes > 0, f"{kind}: payloadMiB invalid")
            require(row.get("requests") == concurrency,
                    f"{kind}: fallback request count mismatch")
            observed_bytes = row.get("bytesObserved")
            require(isinstance(observed_bytes, list)
                    and len(observed_bytes) == concurrency
                    and all(value == expected_bytes for value in observed_bytes),
                    f"{kind}: fallback short read or missing byte count")
            per_request = row.get("perRequestSeconds")
            require(isinstance(per_request, list) and len(per_request) == concurrency,
                    f"{kind}: fallback latency count mismatch")
        grouped[(key[0], key[1], concurrency)].append(row)
    for block, position in expected_slots:
        for concurrency in concurrencies:
            selected = grouped.get((block, position, concurrency), [])
            require(len(selected) == samples,
                    f"{kind}: block {block} slot {position} c{concurrency} missing samples")
            require(sorted(row.get("sampleIndex") for row in selected) == list(range(samples)),
                    f"{kind}: duplicate or missing sample index")

    workload = str(entry.get("name"))
    metrics = []
    for concurrency in concurrencies:
        throughput_field = (
            "connectionsPerSecond" if kind == "setup-abba" else
            "throughputMiBPerSecond"
        )
        metrics.append(metric(
            f"{workload}:c{concurrency}:throughput", workload, throughput_field,
            "connectionsPerSecond" if kind == "setup-abba" else "MiBPerSecond",
            "higher-is-better",
            ratios_for_rows(rows, blocks, concurrency, throughput_field), iterations,
        ))
        if kind == "setup-abba":
            tail_ratios = ratios_for_rows(rows, blocks, concurrency, "p99Seconds")
        else:
            tail_ratios = []
            for block in range(1, blocks + 1):
                values = {}
                for implementation in ("baseline", "candidate"):
                    per_request = []
                    for row in rows:
                        if (row.get("block") == block
                                and row.get("implementation") == implementation
                                and row.get("concurrency") == concurrency):
                            requests = row.get("perRequestSeconds")
                            require(isinstance(requests, list) and requests,
                                    f"{kind}: per-request latency missing")
                            per_request.extend(
                                positive_number(value, f"{kind} request latency")
                                for value in requests
                            )
                    values[implementation] = nearest_rank(per_request, 0.99)
                tail_ratios.append(values["candidate"] / values["baseline"])
        metrics.append(metric(
            f"{workload}:c{concurrency}:p99-latency", workload, "p99Latency",
            "seconds", "lower-is-better", tail_ratios, iterations,
        ))
    cpu_field = (
        "serverCpuPerConnection" if kind == "setup-abba" else "serverCpuPerGiB"
    )
    cpu_unit = "microsecondsPerConnection" if kind == "setup-abba" else "secondsPerGiB"
    metrics.append(cpu_metrics(summary, cpu_field, blocks, workload, cpu_unit, iterations))
    return metrics, {
        "name": workload, "kind": kind, "runDir": str(run_dir), "files": hashes,
        "status": summary["status"],
        "dataQualityVerdict": "PASS",
        "collectorPerformanceVerdict": summary["performanceVerdict"],
        "hostExclusiveLock": host_lock,
    }


def verify_matrix_identity(
    summary: dict[str, Any], contract: dict[str, Any], candidate: dict[str, str],
    baseline: dict[str, str],
) -> dict[str, Any]:
    require(summary.get("status") == "COMPLETE", "matrix: status is not COMPLETE")
    require(summary.get("performanceVerdict") == "NOT_EVALUATED",
            "matrix: collector claimed a performance verdict")
    require(summary.get("failures") == [], "matrix: failures are present")
    require(summary.get("totals", {}).get("invalidSamples") == 0,
            "matrix: invalid samples are present")
    observed = summary.get("identity")
    require(isinstance(observed, dict), "matrix: identity missing")
    require(observed.get("candidateCommit") == candidate["commit"],
            "matrix: candidate commit mismatch")
    require(observed.get("baselineCommit") == baseline["commit"],
            "matrix: baseline commit mismatch")
    binaries = observed.get("binaries", {})
    require(binaries.get("final", {}).get("sha256") == candidate["sha256"],
            "matrix: candidate SHA mismatch")
    require(binaries.get("baseline", {}).get("sha256") == baseline["sha256"],
            "matrix: baseline SHA mismatch")
    require(observed.get("binariesPinned") is True, "matrix: binaries are not pinned")
    require(contract.get("phase") == "complete" and contract.get("exploratory") is False,
            "matrix: formal contract is not complete")
    require(contract.get("script", {}).get("harnessCommit") == candidate["commit"],
            "matrix: harness commit mismatch")
    registered = {row.get("label"): row for row in contract.get("binaries", [])}
    for label, expected in (("candidate", candidate), ("baseline", baseline)):
        row = registered.get(label, {})
        require(row.get("sha256") == expected["sha256"],
                f"matrix: contract {label} SHA mismatch")
        require(row.get("sourceCommit") == expected["commit"],
                f"matrix: contract {label} commit mismatch")
        require(isinstance(row.get("buildId"), str) and BUILD_ID.fullmatch(row["buildId"]),
                f"matrix: contract {label} Build ID missing")
    host_lock = verify_host_lock_metadata(contract.get("hostExclusiveLock"), "matrix")
    host_lock["contract"] = verify_contract_identity(contract.get("contract"), "matrix")
    return host_lock


def evaluate_matrix(
    entry: dict[str, Any], candidate: dict[str, str], baseline: dict[str, str],
    iterations: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    kind = "matrix"
    run_dir, hashes = verify_files(entry, kind)
    summary = load_json(run_dir / "summary.json")
    contract = load_json(run_dir / "run-contract.json")
    completion = load_json(run_dir / "run-completion.json")
    rows = load_jsonl(run_dir / "samples.jsonl")
    verify_success_marker(
        completion, run_dir / "run-contract.json", contract.get("runId"),
        "benchmark-matrix", "matrix",
    )
    host_lock = verify_matrix_identity(summary, contract, candidate, baseline)
    cells = summary.get("cells")
    require(isinstance(cells, dict) and cells, "matrix: no protected cells")
    raw_cell_keys = {
        f"{row.get('scenario')}:{row.get('payloadBytes', 0) // (1024 * 1024)}:"
        f"{row.get('concurrency')}"
        for row in rows
        if row.get("scenario") != "integrity"
    }
    require(raw_cell_keys == set(cells),
            "matrix: summary cells do not exactly cover raw samples")
    workload = str(entry.get("name"))
    metrics = []
    for key, cell in sorted(cells.items()):
        require(isinstance(cell, dict), f"matrix cell {key} invalid")
        count = cell.get("samplesPerImplementation")
        require(isinstance(count, int) and count >= 6 and count % 2 == 0,
                f"matrix cell {key}: need at least three complete ABBA blocks")
        interleave = cell.get("interleaveOrder")
        require(isinstance(interleave, list), f"matrix cell {key}: order missing")
        require(
            len(interleave) == count * 3
            and set(interleave) == {"baseline", "final", "xray"}
            and all(interleave.count(name) == count
                    for name in ("baseline", "final", "xray")),
            f"matrix cell {key}: interleave implementations/cardinality invalid",
        )
        paired_order = [value for value in interleave if value in {"baseline", "final"}]
        previous_order = None
        for offset in range(0, len(paired_order), 4):
            block_order = paired_order[offset:offset + 4]
            require(block_order in (
                ["baseline", "final", "final", "baseline"],
                ["final", "baseline", "baseline", "final"],
            ), f"matrix cell {key}: non-ABBA block")
            require(previous_order is None or block_order != previous_order,
                    f"matrix cell {key}: ABBA direction did not alternate")
            previous_order = block_order
        selected = [
            row for row in rows
            if row.get("scenario") == cell.get("scenario")
            and row.get("direction") == cell.get("direction")
            and row.get("payloadBytes") == cell.get("payloadMiB") * 1024 * 1024
            and row.get("concurrency") == cell.get("concurrency")
        ]
        next_sample = {"baseline": 0, "final": 0, "xray": 0}
        expected_raw_order = []
        for implementation in interleave:
            expected_raw_order.append((implementation, next_sample[implementation]))
            next_sample[implementation] += 1
        actual_raw_order = [
            (row.get("implementation"), row.get("sampleIndex")) for row in selected
        ]
        require(actual_raw_order == expected_raw_order,
                f"matrix cell {key}: raw sample order disagrees with interleaveOrder")
        per_impl = {}
        for implementation in ("baseline", "final"):
            implementation_rows = [
                row for row in selected if row.get("implementation") == implementation
            ]
            require(len(implementation_rows) == count,
                    f"matrix cell {key}: {implementation} sample count mismatch")
            require(sorted(row.get("sampleIndex") for row in implementation_rows)
                    == list(range(count)),
                    f"matrix cell {key}: {implementation} sample indexes incomplete")
            for row in implementation_rows:
                require(row.get("invalid") is False and row.get("bytesVerified") is True,
                        f"matrix cell {key}: invalid/unverified sample")
                positive_number(row.get("throughputMiBPerSecond"),
                                f"matrix cell {key} throughput")
                latencies = row.get("perRequestSeconds")
                require(isinstance(latencies, list) and latencies,
                        f"matrix cell {key}: latency samples missing")
                for latency in latencies:
                    positive_number(latency, f"matrix cell {key} latency")
            per_impl[implementation] = implementation_rows
        xray_rows = [row for row in selected if row.get("implementation") == "xray"]
        require(len(xray_rows) == count
                and sorted(row.get("sampleIndex") for row in xray_rows) == list(range(count)),
                f"matrix cell {key}: Xray comparator samples incomplete")
        throughput_ratios = []
        latency_ratios = []
        for block in range(count // 2):
            indexes = {2 * block, 2 * block + 1}
            values = {}
            tails = {}
            for implementation in ("baseline", "final"):
                block_rows = [
                    row for row in per_impl[implementation]
                    if row["sampleIndex"] in indexes
                ]
                require(len(block_rows) == 2,
                        f"matrix cell {key}: block {block + 1} incomplete")
                values[implementation] = statistics.median(
                    row["throughputMiBPerSecond"] for row in block_rows
                )
                tails[implementation] = nearest_rank(
                    [value for row in block_rows for value in row["perRequestSeconds"]],
                    0.99,
                )
            throughput_ratios.append(values["final"] / values["baseline"])
            latency_ratios.append(tails["final"] / tails["baseline"])
        safe_key = re.sub(r"[^A-Za-z0-9._-]+", "_", key)
        metrics.append(metric(
            f"{workload}:{safe_key}:throughput", workload, "throughput",
            "MiBPerSecond", "higher-is-better", throughput_ratios, iterations,
        ))
        metrics.append(metric(
            f"{workload}:{safe_key}:p99-latency", workload, "p99Latency",
            "seconds", "lower-is-better", latency_ratios, iterations,
        ))
    return metrics, {
        "name": workload, "kind": kind, "runDir": str(run_dir), "files": hashes,
        "status": summary["status"], "dataQualityVerdict": "PASS",
        "collectorPerformanceVerdict": summary["performanceVerdict"],
        "hostExclusiveLock": host_lock,
    }


def evaluate(manifest: dict[str, Any]) -> dict[str, Any]:
    require(manifest.get("schemaVersion") == 1, "manifest schemaVersion must be 1")
    require(manifest.get("tier") in {"portable", "x86-64-v3"}, "invalid CPU tier")
    candidate = identity(manifest.get("candidate"), "candidate")
    baseline = identity(manifest.get("baseline"), "baseline")
    require(candidate != baseline, "candidate and baseline identities are identical")
    iterations = manifest.get("bootstrapIterations", 20_000)
    require(isinstance(iterations, int) and 20_000 <= iterations <= 100_000,
            "bootstrapIterations must be in 20000..100000")
    workloads = manifest.get("workloads")
    require(isinstance(workloads, list) and len(workloads) == len(REQUIRED_KINDS),
            "manifest must contain exactly setup, fallback, and matrix workloads")
    kinds = [entry.get("kind") for entry in workloads if isinstance(entry, dict)]
    require(set(kinds) == REQUIRED_KINDS and len(kinds) == len(set(kinds)),
            "workload kinds must be exactly setup-abba, fallback-abba, and matrix")
    names = [entry.get("name") for entry in workloads]
    require(all(isinstance(name, str) and name for name in names)
            and len(names) == len(set(names)), "workload names must be unique")

    metrics = []
    inputs = []
    for entry in workloads:
        kind = entry["kind"]
        if kind == "matrix":
            current_metrics, current_input = evaluate_matrix(
                entry, candidate, baseline, iterations
            )
        else:
            current_metrics, current_input = evaluate_pair_run(
                entry, kind, candidate, baseline, iterations
            )
        metrics.extend(current_metrics)
        inputs.append(current_input)
    coordination = [
        coordination_identity(current["hostExclusiveLock"]) for current in inputs
    ]
    require(all(value == coordination[0] for value in coordination[1:]),
            "workloads used different host-exclusive lock protocols/identities")
    require(metrics, "no protected metrics were produced")
    regressions = [row["id"] for row in metrics if not row["pass"]]
    improvements = [
        row["id"] for row in metrics
        if row["classification"] in {"KEEP_IMPROVEMENT", "SMALL_IMPROVEMENT"}
    ]
    return {
        "schemaVersion": 1,
        "status": "COMPLETE",
        "tier": manifest["tier"],
        "candidate": candidate,
        "baseline": baseline,
        "method": {
            "design": "warmed alternating ABBA blocks",
            "statistic": "median block ratio",
            "confidence": "deterministic 95% block bootstrap",
            "iterations": iterations,
            "regressionRule": (
                "FAIL only when the 95% interval excludes 1.0 in the regression direction"
            ),
        },
        "inputs": inputs,
        "protectedMetrics": metrics,
        "regressions": regressions,
        "improvements": improvements,
        "overallPerformanceVerdict": "FAIL" if regressions else "PASS",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.manifest.is_absolute() or not args.output.is_absolute():
        parser.error("--manifest and --output must be absolute")
    if args.output.exists() or args.output.is_symlink():
        parser.error(f"output must not exist: {args.output}")
    if not args.output.parent.is_dir():
        parser.error(f"output parent does not exist: {args.output.parent}")
    manifest_sha = None
    try:
        manifest_sha = sha256_file(args.manifest)
        report = evaluate(load_json(args.manifest))
        report["manifest"] = {"path": str(args.manifest), "sha256": manifest_sha}
        exit_code = 0 if report["overallPerformanceVerdict"] == "PASS" else 1
    except (InvalidEvidence, KeyError, TypeError, ValueError, OSError,
            json.JSONDecodeError) as error:
        report = {
            "schemaVersion": 1,
            "status": "INVALID",
            "manifest": {"path": str(args.manifest), "sha256": manifest_sha},
            "errors": [str(error)],
            "overallPerformanceVerdict": "INVALID",
        }
        exit_code = 2
    report["evaluator"] = {
        "path": str(Path(__file__).resolve()),
        "sha256": sha256_file(Path(__file__).resolve()),
    }
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
