#!/usr/bin/env python3
"""Supplementary gate statistics for evidence the formal evaluator cannot cover.

The formal evaluator (scripts/evaluate-release-performance.py) judges the
formal setup-abba, fallback-abba, and formal matrix legs.  This script covers
the legs that cannot be formal on this host:

* the exploratory c32 throughput matrix rounds (formal c32 would require
  raising fs.pipe-user-pages-soft, which is forbidden here), and
* the cpu-per-gib A/B runs (perf stat task-clock per GiB on the Direct path).

Method mirrors the evaluator where applicable: per-cell candidate/baseline
ratio of medians, deterministic block bootstrap 95% interval (reporting
only), and an exact one-sided sign-flip regression p-value across the
available paired ratios.  A cell is a MEANINGFUL regression only when the
point estimate exceeds the gate AND the bootstrap interval excludes the gate
threshold.
"""

from __future__ import annotations

import hashlib
import json
import math
import random
import statistics
import sys
from collections import defaultdict
from pathlib import Path

GATES = Path("/home/jacek/work/kimi-rust-reality-performance/artifacts/v1.6.0/gates")
THROUGHPUT_GATE = 0.02  # no regression > 2%
CPU_GATE = 0.02


def bootstrap_interval(values: list[float], iterations: int, seed_text: str) -> list[float]:
    seed = int.from_bytes(hashlib.sha256(seed_text.encode()).digest()[:8], "big")
    rng = random.Random(seed)
    medians = sorted(
        statistics.median(rng.choices(values, k=len(values)))
        for _ in range(iterations)
    )
    return [medians[iterations // 40], medians[(iterations * 39) // 40 - 1]]


def sign_flip_regression_p(log_ratios: list[float], higher_is_better: bool) -> float:
    oriented = [v if higher_is_better else -v for v in log_ratios]
    observed = math.fsum(oriented)
    count = len(oriented)
    hits = 0
    for assignment in range(1 << count):
        permuted = math.fsum(
            value if assignment & (1 << index) else -value
            for index, value in enumerate(oriented)
        )
        if permuted <= observed:
            hits += 1
    return hits / (1 << count)


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def analyze_exploratory_matrix(rounds: list[Path]) -> list[dict]:
    """Per-cell candidate/baseline throughput ratios across the ABBA rounds.

    Within one round each cell has SAMPLES interleaved samples per
    implementation.  Paired block ratios come from consecutive ABBA quads in
    the recorded interleave order (2 baseline + 2 final per block); with
    SAMPLES=5 that yields two complete quads per round, four across two
    rounds.
    """
    per_cell_quads: dict[str, list[float]] = defaultdict(list)
    per_cell_medians: dict[str, dict[str, list[float]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for run_dir in rounds:
        rows = load_jsonl(run_dir / "samples.jsonl")
        cells: dict[tuple, list[dict]] = defaultdict(list)
        for row in rows:
            if row.get("scenario") == "integrity":
                continue
            key = (
                row["scenario"], row.get("direction"),
                row.get("payloadBytes"), row.get("concurrency"),
            )
            cells[key].append(row)
        for key, cell_rows in sorted(cells.items()):
            name = f"{key[0]}:{key[1]}:{key[2] // (1024 * 1024)}MiB:c{key[3]}"
            by_impl: dict[str, list[dict]] = defaultdict(list)
            for row in cell_rows:
                by_impl[row["implementation"]].append(row)
            for impl in by_impl:
                by_impl[impl].sort(key=lambda row: row["sampleIndex"])
            base = [r["throughputMiBPerSecond"] for r in by_impl.get("baseline", [])]
            cand = [r["throughputMiBPerSecond"] for r in by_impl.get("final", [])]
            if not base or not cand:
                continue
            per_cell_medians[name]["baseline"].append(statistics.median(base))
            per_cell_medians[name]["final"].append(statistics.median(cand))
            quads = min(len(base), len(cand)) // 2
            for quad in range(quads):
                b = statistics.median(base[2 * quad:2 * quad + 2])
                c = statistics.median(cand[2 * quad:2 * quad + 2])
                per_cell_quads[name].append(c / b)
    results = []
    for name in sorted(per_cell_quads):
        ratios = per_cell_quads[name]
        point = statistics.median(ratios)
        interval = bootstrap_interval(ratios, 20000, f"matrix-x:{name}")
        p_value = sign_flip_regression_p([math.log(r) for r in ratios], True)
        med = per_cell_medians[name]
        results.append({
            "cell": name,
            "blocks": len(ratios),
            "baselineMedianMiBs": round(statistics.median(med["baseline"]), 1),
            "candidateMedianMiBs": round(statistics.median(med["final"]), 1),
            "medianCandidateVsBaseline": round(point, 4),
            "bootstrap95": [round(v, 4) for v in interval],
            "regressionSignFlipP": round(p_value, 4),
            "meaningfulRegression": bool(
                point < 1 - THROUGHPUT_GATE and interval[1] < 1 - THROUGHPUT_GATE
            ),
        })
    return results


def analyze_cpu_per_gib(runs: dict[str, list[Path]]) -> list[dict]:
    """ABBA-paired server ms/GiB ratios for the Direct-path CPU cells."""
    samples: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    for label, paths in runs.items():
        for path in paths:
            for row in load_jsonl(path):
                key = f"{row['scenario']}:{row['payloadMiB']}MiB:c{row['concurrency']}"
                samples[key][label].append(row["serverMsPerGiB"])
    results = []
    for key in sorted(samples):
        base = samples[key].get("baseline", [])
        cand = samples[key].get("candidate", [])
        pairs = min(len(base), len(cand))
        if pairs == 0:
            continue
        ratios = [cand[i] / base[i] for i in range(pairs)]
        point = statistics.median(ratios)
        interval = bootstrap_interval(ratios, 20000, f"cpu:{key}")
        results.append({
            "cell": key,
            "pairs": pairs,
            "baselineMedianMsPerGiB": round(statistics.median(base), 1),
            "candidateMedianMsPerGiB": round(statistics.median(cand), 1),
            "medianCandidateVsBaseline": round(point, 4),
            "bootstrap95": [round(v, 4) for v in interval],
            "meaningfulRegression": bool(
                point > 1 + CPU_GATE and interval[0] > 1 + CPU_GATE
            ),
        })
    return results


def main() -> int:
    matrix_rounds = [GATES / f"matrix-r{index:02d}" for index in (1, 2)]
    matrix_rounds = [path for path in matrix_rounds if (path / "samples.jsonl").is_file()]
    cpu_runs = {
        "baseline": sorted(GATES.glob("cpu-base-r*/cpu-samples.jsonl")),
        "candidate": sorted(GATES.glob("cpu-cand-r*/cpu-samples.jsonl")),
    }
    report = {
        "exploratoryMatrix": analyze_exploratory_matrix(matrix_rounds),
        "cpuPerGiB": analyze_cpu_per_gib(cpu_runs),
    }
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    print()
    bad = [r for r in report["exploratoryMatrix"] if r["meaningfulRegression"]]
    bad += [r for r in report["cpuPerGiB"] if r["meaningfulRegression"]]
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
