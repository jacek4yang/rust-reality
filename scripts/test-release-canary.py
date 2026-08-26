#!/usr/bin/env python3
"""Deterministic contract tests for evaluate-release-canary.py."""

from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "evaluate_release_canary", ROOT / "scripts/evaluate-release-canary.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def fixture() -> dict:
    samples = [
        {"rssKiB": 20_000 + (index % 4) * 64, "fd": 20 + (index % 5), "threads": 4}
        for index in range(24)
    ]
    return {
        "schemaVersion": 1,
        "candidate": {
            "commit": "a" * 40,
            "sha256": "b" * 64,
            "buildId": "c" * 40,
            "version": "1.7.0",
            "target": "x86_64-unknown-linux-gnu",
            "rustc": "rustc 1.96.0",
        },
        "elapsedSeconds": 600,
        "checks": {name: True for name in MODULE.REQUIRED_CHECKS},
        "traffic": {"connectionsAttempted": 1_000, "connectionsSuccessful": 999},
        "handoffPool": {
            "checkoutHit": 995,
            "checkoutMiss": 5,
            "coldFallback": 5,
            "targetReadyPeak": 64,
            "maxReady": 128,
            "connectingPeak": 24,
            "maxConnecting": 32,
        },
        "landingRejections": {"count": 4, "authenticationOrProtocol": 0},
        "resources": {"line": samples, "landing": list(samples)},
    }


passing = MODULE.evaluate(fixture())
assert passing["ok"] is True, passing

bad = fixture()
bad["checks"]["lineReload"] = False
bad["handoffPool"]["connectingPeak"] = 33
bad["resources"]["line"][-1]["fd"] = 3_000
failing = MODULE.evaluate(bad)
assert failing["ok"] is False
assert any("lineReload" in reason for reason in failing["reasons"])
assert any("maxConnecting" in reason for reason in failing["reasons"])
assert any("FD count" in reason for reason in failing["reasons"])

bad_rejections = fixture()
bad_rejections["landingRejections"] = {
    "count": 4,
    "authenticationOrProtocol": 1,
}
rejected = MODULE.evaluate(bad_rejections)
assert rejected["ok"] is False
assert any("authentication/protocol" in reason for reason in rejected["reasons"])

print("release canary evaluator tests passed")
