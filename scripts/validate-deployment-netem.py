#!/usr/bin/env python3
"""Validate the complete deployment netem Cartesian product, fail closed."""

from __future__ import annotations

import argparse
import json
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
                    if not isinstance(value, (int, float)) or value <= 0:
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
    passed = (
        len(profiles) == expected_profile_count
        and not missing
        and not unexpected
        and actual_raw_record_count == expected_raw_record_count
        and all(row["verdict"] == "PASS" for row in profiles)
    )
    report = {
        "schemaVersion": 2,
        "status": "COMPLETE",
        "verdict": "PASS" if passed else "FAIL",
        "dataQualityVerdict": "PASS" if passed else "FAIL",
        "performanceVerdict": "NOT_EVALUATED",
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
        "missingProfiles": missing,
        "unexpectedProfiles": unexpected,
        "profiles": profiles,
    }
    return report, passed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profiles", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rtts", required=True)
    parser.add_argument("--losses", required=True)
    parser.add_argument("--concurrencies", required=True)
    parser.add_argument("--samples", type=int, required=True)
    parser.add_argument("--connections", type=int, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error(f"output must not exist: {args.output}")
    try:
        report, passed = validate(args)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        report = {
            "schemaVersion": 2,
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
