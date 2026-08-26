#!/usr/bin/env python3
"""Fail-closed evaluator for the exact-candidate dual-VPS release canary."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


REQUIRED_CHECKS = (
    "lineSsh",
    "landingSsh",
    "lineServiceActive",
    "landingServiceActive",
    "linePublicPortsRestricted",
    "landingPublicPortsRestricted",
    "landingFirewallLineOnly",
    "stockXray",
    "oneMiBIntegrity",
    "largeIntegrity",
    "uploadIntegrity",
    "bidirectionalIntegrity",
    "lineReload",
    "generationRetirement",
    "landingRestart",
    "restartRecovery",
    "coldFallback",
    "warmHandoff",
    "noRestartLoop",
    "noAuthenticationRegression",
    "noReplayRegression",
)


def load_object(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("canary input must be a JSON object")
    return value


def integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer")
    return value


def resource_reasons(report: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    resources = report.get("resources")
    if not isinstance(resources, dict):
        return ["resources must be an object"]
    for host in ("line", "landing"):
        samples = resources.get(host)
        if not isinstance(samples, list) or len(samples) < 12:
            reasons.append(f"resources.{host} requires at least 12 samples")
            continue
        normalized: list[dict[str, int]] = []
        for index, sample in enumerate(samples):
            if not isinstance(sample, dict):
                reasons.append(f"resources.{host}[{index}] must be an object")
                continue
            try:
                normalized.append(
                    {
                        name: integer(sample.get(name), f"resources.{host}[{index}].{name}")
                        for name in ("rssKiB", "fd", "threads")
                    }
                )
            except ValueError as error:
                reasons.append(str(error))
        if len(normalized) != len(samples):
            continue
        first = normalized[0]
        last = normalized[-1]
        peak = {name: max(sample[name] for sample in normalized) for name in first}
        if last["fd"] > first["fd"] + 32:
            reasons.append(f"{host} FD count did not recover within +32")
        if peak["fd"] > first["fd"] + 256:
            reasons.append(f"{host} FD peak exceeded baseline +256")
        if last["threads"] > first["threads"] + 8:
            reasons.append(f"{host} thread count did not recover within +8")
        if peak["threads"] > first["threads"] + 16:
            reasons.append(f"{host} thread peak exceeded baseline +16")
        if last["rssKiB"] > first["rssKiB"] + 32 * 1024:
            reasons.append(f"{host} RSS did not recover within +32 MiB")
        if peak["rssKiB"] > first["rssKiB"] + 96 * 1024:
            reasons.append(f"{host} RSS peak exceeded baseline +96 MiB")
    return reasons


def evaluate(report: dict[str, Any]) -> dict[str, Any]:
    reasons: list[str] = []
    if report.get("schemaVersion") != 1:
        reasons.append("schemaVersion must be 1")

    candidate = report.get("candidate")
    if not isinstance(candidate, dict):
        reasons.append("candidate must be an object")
    else:
        for field in ("commit", "sha256", "buildId", "version", "target", "rustc"):
            if not isinstance(candidate.get(field), str) or not candidate[field]:
                reasons.append(f"candidate.{field} must be a non-empty string")

    try:
        elapsed = integer(report.get("elapsedSeconds"), "elapsedSeconds")
        if not 480 <= elapsed <= 900:
            reasons.append("elapsedSeconds must be in the active-canary range 480..900")
    except ValueError as error:
        reasons.append(str(error))

    checks = report.get("checks")
    if not isinstance(checks, dict):
        reasons.append("checks must be an object")
    else:
        for check in REQUIRED_CHECKS:
            if checks.get(check) is not True:
                reasons.append(f"required check failed or missing: {check}")

    traffic = report.get("traffic")
    if not isinstance(traffic, dict):
        reasons.append("traffic must be an object")
    else:
        try:
            attempted = integer(traffic.get("connectionsAttempted"), "traffic.connectionsAttempted")
            successful = integer(traffic.get("connectionsSuccessful"), "traffic.connectionsSuccessful")
            if attempted < 500:
                reasons.append("traffic.connectionsAttempted must be at least 500")
            if successful < 450 or successful * 100 < attempted * 95:
                reasons.append("traffic success must be at least 450 and 95%")
        except ValueError as error:
            reasons.append(str(error))

    pool = report.get("handoffPool")
    if not isinstance(pool, dict):
        reasons.append("handoffPool must be an object")
    else:
        try:
            hit = integer(pool.get("checkoutHit"), "handoffPool.checkoutHit")
            miss = integer(pool.get("checkoutMiss"), "handoffPool.checkoutMiss")
            cold = integer(pool.get("coldFallback"), "handoffPool.coldFallback")
            target_peak = integer(pool.get("targetReadyPeak"), "handoffPool.targetReadyPeak")
            max_ready = integer(pool.get("maxReady"), "handoffPool.maxReady")
            connecting_peak = integer(pool.get("connectingPeak"), "handoffPool.connectingPeak")
            max_connecting = integer(pool.get("maxConnecting"), "handoffPool.maxConnecting")
            if hit <= 0:
                reasons.append("handoff warm checkout was not observed")
            if hit + miss <= 0:
                reasons.append("handoff pool recorded no checkout attempts")
            if cold <= 0:
                reasons.append("handoff cold fallback was not exercised")
            if target_peak > max_ready:
                reasons.append("handoff target_ready exceeded maxReady")
            if connecting_peak > max_connecting:
                reasons.append("handoff connecting exceeded maxConnecting")
        except ValueError as error:
            reasons.append(str(error))

    rejections = report.get("landingRejections")
    if not isinstance(rejections, dict):
        reasons.append("landingRejections must be an object")
    else:
        systematic = rejections.get("systematic")
        if systematic is not False:
            reasons.append("systematic LANDING rejection churn detected or not measured")

    reasons.extend(resource_reasons(report))
    return {
        "schemaVersion": 1,
        "gate": "dual-vps-active-release-canary",
        "candidate": candidate,
        "elapsedSeconds": report.get("elapsedSeconds"),
        "reasons": reasons,
        "ok": not reasons,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    try:
        verdict = evaluate(load_object(arguments.input))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"canary evaluation failed: {error}", file=sys.stderr)
        return 2
    encoded = json.dumps(verdict, indent=2, sort_keys=True) + "\n"
    if arguments.output:
        arguments.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if verdict["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
