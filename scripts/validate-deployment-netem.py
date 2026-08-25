#!/usr/bin/env python3
"""Validate the complete deployment netem Cartesian product, fail closed."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import statistics
from pathlib import Path
from typing import Any


LEGS = (
    "handoff-warm",
    "handoff-cold",
    "nxr-warm",
    "nxr-cold",
    "socks-warm",
    "socks-cold",
)
WARM_TRANSPORTS = ("handoff", "nxr", "socks5")
MECHANISM_RTTS_MS = (50, 100, 200)
MECHANISM_CONCURRENCY = 1
MECHANISM_LOSS_PERCENT = 0.0
BOOTSTRAP_ITERATIONS = 20_000


def parse_words(raw: str, converter: type[int] | type[float]) -> list[int] | list[float]:
    values = [converter(value) for value in raw.split()]
    if not values or len(values) != len(set(values)):
        raise ValueError("dimension must be non-empty and contain no duplicates")
    return values


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line:
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_number}: row is not an object")
        rows.append(value)
    return rows


def read_pool_summaries(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    errors: list[str] = []
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list):
        return [], ["pool summaries must be an array"]
    transports = [row.get("transport") for row in value if isinstance(row, dict)]
    if sorted(transports) != sorted(WARM_TRANSPORTS):
        errors.append(
            f"pool summaries must contain exactly {list(WARM_TRANSPORTS)}"
        )
    required_counters = (
        "pool_ready",
        "pool_connecting",
        "pool_in_use",
        "pool_checkout_total",
        "pool_checkout_hit",
        "pool_checkout_miss",
        "pool_cold_fallback",
        "pool_stale_discard",
        "pool_connect_failure",
        "pool_refill",
        "pool_target_ready",
        "pool_growth",
        "pool_shrink",
    )
    for index, row in enumerate(value):
        if not isinstance(row, dict):
            errors.append(f"pool summary {index} is not an object")
            continue
        for field in required_counters:
            counter = row.get(field)
            if not isinstance(counter, int) or counter < 0:
                errors.append(
                    f"pool summary {row.get('transport', index)} has invalid {field}"
                )
        total = row.get("pool_checkout_total")
        hits = row.get("pool_checkout_hit")
        misses = row.get("pool_checkout_miss")
        if all(isinstance(item, int) for item in (total, hits, misses)):
            if total != hits + misses:
                errors.append(
                    f"pool summary {row.get('transport', index)} checkout accounting mismatch"
                )
            if total <= 0:
                errors.append(
                    f"pool summary {row.get('transport', index)} has no measured checkouts"
                )
        for field in (
            "checkoutAcquisitionRatio",
            "successfulWarmRatioLowerBound",
        ):
            ratio = row.get(field)
            if not isinstance(ratio, (int, float)) or not 0 <= ratio <= 1:
                errors.append(
                    f"pool summary {row.get('transport', index)} has invalid {field}"
                )
    return value, errors


def bootstrap_interval(
    values: list[float], iterations: int, seed_text: str
) -> list[float]:
    if len(values) < 3:
        raise ValueError(f"{seed_text}: fewer than three complete ABBA blocks")
    seed = int.from_bytes(hashlib.sha256(seed_text.encode()).digest()[:8], "big")
    rng = random.Random(seed)
    medians = sorted(
        statistics.median(rng.choices(values, k=len(values)))
        for _ in range(iterations)
    )
    return [medians[iterations // 40], medians[(iterations * 39) // 40 - 1]]


def mechanism_evaluation(
    profiles: list[dict[str, Any]], args: argparse.Namespace
) -> tuple[dict[str, Any], list[str]]:
    """Evaluate only the controlled RTT mechanism claimed by v1.7.

    Every two consecutive sample indexes form one balanced ABBA block: the
    collector runs warm, cold, cold, warm and stores the two warm and two cold
    aggregates under the same pair of indexes.  The block effect is therefore
    median(cold p50) - median(warm p50), normalized by measured RTT.
    """
    errors: list[str] = []
    if args.samples < 6 or args.samples % 2:
        errors.append(
            "mechanism evaluation requires an even samples count of at least 6"
        )
    expected_rtts = set(parse_words(args.rtts, int))
    expected_losses = set(parse_words(args.losses, float))
    expected_concurrencies = set(parse_words(args.concurrencies, int))
    if not set(MECHANISM_RTTS_MS).issubset(expected_rtts):
        errors.append(
            f"mechanism evaluation requires RTTs {list(MECHANISM_RTTS_MS)}"
        )
    if MECHANISM_LOSS_PERCENT not in expected_losses:
        errors.append("mechanism evaluation requires a zero-loss profile")
    if MECHANISM_CONCURRENCY not in expected_concurrencies:
        errors.append("mechanism evaluation requires concurrency 1")

    by_key = {
        (row.get("targetRttMs"), row.get("perDirectionLossPercent")): row
        for row in profiles
    }
    cells: list[dict[str, Any]] = []
    leg_prefix = {"handoff": "handoff", "nxr": "nxr", "socks5": "socks"}
    if errors:
        return {
            "verdict": "FAIL",
            "cells": cells,
            "errors": errors,
        }, errors

    for rtt_ms in MECHANISM_RTTS_MS:
        profile = by_key.get((rtt_ms, MECHANISM_LOSS_PERCENT))
        if profile is None:
            errors.append(f"missing zero-loss RTT {rtt_ms} ms mechanism profile")
            continue
        observed_rtt = profile.get("observedRttMs")
        if not isinstance(observed_rtt, (int, float)) or observed_rtt <= 0:
            errors.append(f"RTT {rtt_ms} ms profile has no positive measured RTT")
            continue
        raw_results = profile.get("rawResults", {})
        for transport, prefix in leg_prefix.items():
            warm_rows = {
                row.get("sampleIndex"): row
                for row in raw_results.get(f"{prefix}-warm", [])
                if row.get("concurrency") == MECHANISM_CONCURRENCY
            }
            cold_rows = {
                row.get("sampleIndex"): row
                for row in raw_results.get(f"{prefix}-cold", [])
                if row.get("concurrency") == MECHANISM_CONCURRENCY
            }
            normalized_deltas: list[float] = []
            block_rows: list[dict[str, Any]] = []
            cell_errors: list[str] = []
            for first in range(0, args.samples, 2):
                indexes = (first, first + 1)
                try:
                    warm_ms = statistics.median(
                        float(warm_rows[index]["p50Seconds"]) * 1000
                        for index in indexes
                    )
                    cold_ms = statistics.median(
                        float(cold_rows[index]["p50Seconds"]) * 1000
                        for index in indexes
                    )
                except (KeyError, TypeError, ValueError) as error:
                    cell_errors.append(
                        f"block {first // 2}: {error}"
                    )
                    continue
                delta_ms = cold_ms - warm_ms
                normalized = delta_ms / float(observed_rtt)
                normalized_deltas.append(normalized)
                block_rows.append(
                    {
                        "block": first // 2,
                        "sampleIndexes": list(indexes),
                        "warmP50Ms": warm_ms,
                        "coldP50Ms": cold_ms,
                        "removedHandshakeMs": delta_ms,
                        "removedHandshakePerMeasuredRtt": normalized,
                    }
                )
            try:
                point = statistics.median(normalized_deltas)
                interval = bootstrap_interval(
                    normalized_deltas,
                    BOOTSTRAP_ITERATIONS,
                    f"{transport}:rtt{rtt_ms}:cold-minus-warm",
                )
            except (statistics.StatisticsError, ValueError) as error:
                point = None
                interval = None
                cell_errors.append(str(error))
            if point is not None:
                if point <= 0:
                    cell_errors.append("cold-minus-warm latency delta is not positive")
                if not 0.65 <= point <= 1.35:
                    cell_errors.append(
                        "median removed-handshake delta is outside 0.65..1.35 measured RTT"
                    )
                if rtt_ms >= 100 and interval is not None and interval[0] <= 0.5:
                    cell_errors.append(
                        "bootstrap lower bound does not exceed 0.5 measured RTT"
                    )
            errors.extend(
                f"{transport} RTT {rtt_ms} ms: {message}"
                for message in cell_errors
            )
            cells.append(
                {
                    "transport": transport,
                    "targetRttMs": rtt_ms,
                    "measuredRttMs": observed_rtt,
                    "perDirectionLossPercent": MECHANISM_LOSS_PERCENT,
                    "concurrency": MECHANISM_CONCURRENCY,
                    "metric": "cold p50 minus warm p50",
                    "blockCount": len(normalized_deltas),
                    "blocks": block_rows,
                    "medianRemovedHandshakePerMeasuredRtt": point,
                    "bootstrap95": interval,
                    "verdict": "PASS" if not cell_errors else "FAIL",
                    "errors": cell_errors,
                }
            )

    passed = len(cells) == len(MECHANISM_RTTS_MS) * len(WARM_TRANSPORTS) and not errors
    return {
        "verdict": "PASS" if passed else "FAIL",
        "claim": (
            "on a valid warm hit, the user flow does not wait for a new "
            "LINE-to-peer TCP handshake"
        ),
        "scope": (
            "zero-loss concurrency-1 cold-versus-warm p50; loss and higher "
            "concurrency cells are mandatory robustness evidence, not mechanism gates"
        ),
        "pairing": "balanced ABBA blocks",
        "effect": "median(cold p50) - median(warm p50)",
        "normalization": "measured ICMP RTT for the shaped veth pair",
        "bootstrapIterations": BOOTSTRAP_ITERATIONS,
        "gate": {
            "rttsMs": list(MECHANISM_RTTS_MS),
            "pointEstimateMeasuredRttRange": [0.65, 1.35],
            "bootstrapLowerBoundAboveMeasuredRtt": {
                "rttsMs": [100, 200],
                "exclusiveMinimum": 0.5,
            },
        },
        "cells": cells,
        "errors": errors,
    }, errors


def validate(args: argparse.Namespace) -> tuple[dict[str, Any], bool]:
    expected_rtts = parse_words(args.rtts, int)
    expected_losses = parse_words(args.losses, float)
    expected_concurrencies = parse_words(args.concurrencies, int)
    if args.samples <= 0 or args.connections <= 0:
        raise ValueError("samples and connections must be positive")
    expected_keys = {
        (rtt, loss) for rtt in expected_rtts for loss in expected_losses
    }
    profiles: list[dict[str, Any]] = []
    seen_keys: set[tuple[Any, Any]] = set()
    actual_raw_record_count = 0
    pool_summaries, pool_errors = read_pool_summaries(args.pool_summaries)

    for profile in read_jsonl(args.profiles):
        errors: list[str] = []
        key = (
            profile.get("targetRttMs"),
            profile.get("perDirectionLossPercent"),
        )
        if key not in expected_keys:
            errors.append(f"unexpected or malformed profile: {key}")
        if key in seen_keys:
            errors.append(f"duplicate profile: {key}")
        seen_keys.add(key)
        raw = profile.get("raw")
        if not isinstance(raw, dict) or set(raw) != set(LEGS):
            errors.append(f"raw legs must be exactly {list(LEGS)}")
            raw = raw if isinstance(raw, dict) else {}
        raw_counts: dict[str, int] = {}
        raw_results: dict[str, list[dict[str, Any]]] = {}
        for leg in LEGS:
            raw_path = raw.get(leg)
            try:
                if not isinstance(raw_path, str):
                    raise ValueError("missing raw path")
                path = Path(raw_path)
                if not path.is_absolute():
                    raise ValueError("raw path is not absolute")
                rows = read_jsonl(path)
            except (OSError, ValueError, json.JSONDecodeError) as error:
                rows = []
                errors.append(f"{leg}: {error}")
            raw_counts[leg] = len(rows)
            raw_results[leg] = rows
            actual_raw_record_count += len(rows)
            expected_rows = args.samples * len(expected_concurrencies)
            if len(rows) != expected_rows:
                errors.append(
                    f"{leg}: expected {expected_rows} raw records, got {len(rows)}"
                )
            observed: dict[int, list[int]] = {
                concurrency: [] for concurrency in expected_concurrencies
            }
            for row in rows:
                concurrency = row.get("concurrency")
                if concurrency not in observed:
                    errors.append(f"{leg}: unexpected concurrency {concurrency}")
                    continue
                observed[concurrency].append(row.get("sampleIndex"))
                if row.get("failed") != 0:
                    errors.append(
                        f"{leg}: c{concurrency} sample {row.get('sampleIndex')} failed"
                    )
                if row.get("connections") != args.connections:
                    errors.append(
                        f"{leg}: c{concurrency} sample {row.get('sampleIndex')} "
                        f"has {row.get('connections')} connections, expected {args.connections}"
                    )
                for field in (
                    "connectionsPerSecond",
                    "p50Seconds",
                    "p90Seconds",
                    "p95Seconds",
                    "p99Seconds",
                ):
                    value = row.get(field)
                    if (
                        not isinstance(value, (int, float))
                        or not math.isfinite(value)
                        or value <= 0
                    ):
                        errors.append(
                            f"{leg}: c{concurrency} sample {row.get('sampleIndex')} "
                            f"has invalid {field}"
                        )
            for concurrency, sample_indexes in observed.items():
                if sorted(sample_indexes) != list(range(args.samples)):
                    errors.append(
                        f"{leg}: c{concurrency} sample indexes are incomplete or duplicated"
                    )
        profile["rawRecordCounts"] = raw_counts
        profile["rawResults"] = raw_results
        profile["dataQualityVerdict"] = "PASS" if not errors else "FAIL"
        profile["performanceVerdict"] = "NOT_EVALUATED"
        profile["verdict"] = "PASS" if not errors else "FAIL"
        profile["errors"] = errors
        profiles.append(profile)

    missing = sorted(expected_keys - seen_keys)
    unexpected = sorted(seen_keys - expected_keys)
    expected_profile_count = len(expected_keys)
    expected_samples_per_leg = args.samples * len(expected_concurrencies)
    expected_raw_record_count = (
        expected_profile_count * len(LEGS) * expected_samples_per_leg
    )
    data_passed = (
        len(profiles) == expected_profile_count
        and not missing
        and not unexpected
        and actual_raw_record_count == expected_raw_record_count
        and not pool_errors
        and all(row["verdict"] == "PASS" for row in profiles)
    )
    performance_report: dict[str, Any] | None = None
    performance_errors: list[str] = []
    if args.evaluate_performance and data_passed:
        performance_report, performance_errors = mechanism_evaluation(profiles, args)
        performance_verdict = performance_report["verdict"]
        cells_by_rtt: dict[int, list[dict[str, Any]]] = {}
        for cell in performance_report["cells"]:
            cells_by_rtt.setdefault(cell["targetRttMs"], []).append(cell)
        for profile in profiles:
            key = (
                profile.get("targetRttMs"),
                profile.get("perDirectionLossPercent"),
            )
            if key[0] in MECHANISM_RTTS_MS and key[1] == MECHANISM_LOSS_PERCENT:
                cells = cells_by_rtt.get(key[0], [])
                profile["performanceVerdict"] = (
                    "PASS"
                    if len(cells) == len(WARM_TRANSPORTS)
                    and all(cell["verdict"] == "PASS" for cell in cells)
                    else "FAIL"
                )
            else:
                profile["performanceVerdict"] = "NOT_APPLICABLE"
    elif args.evaluate_performance:
        performance_verdict = "INVALID"
    else:
        performance_verdict = "NOT_EVALUATED"
    passed = data_passed and (
        not args.evaluate_performance or performance_verdict == "PASS"
    )
    report = {
        "schemaVersion": 3,
        "status": "COMPLETE",
        "verdict": "PASS" if passed else "FAIL",
        "dataQualityVerdict": "PASS" if data_passed else "FAIL",
        "performanceVerdict": performance_verdict,
        "networkModel": (
            "tc netem delay and loss applied independently per veth direction"
        ),
        "expectedDimensions": {
            "rttsMs": expected_rtts,
            "perDirectionLossPercent": expected_losses,
            "legs": list(LEGS),
            "concurrencies": expected_concurrencies,
            "samplesPerConcurrency": args.samples,
            "connectionsPerSample": args.connections,
        },
        "expectedProfileCount": expected_profile_count,
        "actualProfileCount": len(profiles),
        "expectedSamplesPerLeg": expected_samples_per_leg,
        "expectedConcurrencies": expected_concurrencies,
        "expectedRawRecordCount": expected_raw_record_count,
        "actualRawRecordCount": actual_raw_record_count,
        "poolSummaries": pool_summaries,
        "poolSummaryErrors": pool_errors,
        "performanceMechanism": performance_report,
        "performanceErrors": performance_errors,
        "missingProfiles": missing,
        "unexpectedProfiles": unexpected,
        "profiles": profiles,
    }
    return report, passed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profiles", type=Path, required=True)
    parser.add_argument("--pool-summaries", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rtts", required=True)
    parser.add_argument("--losses", required=True)
    parser.add_argument("--concurrencies", required=True)
    parser.add_argument("--samples", type=int, required=True)
    parser.add_argument("--connections", type=int, required=True)
    parser.add_argument("--evaluate-performance", action="store_true")
    args = parser.parse_args()
    if args.output.exists():
        parser.error(f"output must not exist: {args.output}")
    try:
        report, passed = validate(args)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        report = {
            "schemaVersion": 3,
            "status": "INVALID",
            "verdict": "FAIL",
            "dataQualityVerdict": "FAIL",
            "performanceVerdict": "INVALID",
            "errors": [str(error)],
        }
        passed = False
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
