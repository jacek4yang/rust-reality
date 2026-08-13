#!/usr/bin/env python3
"""Synthetic fail-closed tests for profile resource-boundary evidence."""

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
SUMMARIZER = ROOT / "scripts" / "profile-summarize.py"
MEMORY_BYTES = 1024 * 1024 * 1024


def machine_report():
    return {
        "memory_source": "cgroup_v2",
        "memory_max": MEMORY_BYTES,
        "memory_total": MEMORY_BYTES,
        "cpu_quota_us": 100_000,
        "cpu_period_us": 100_000,
    }


def cgroup_evidence(run):
    return {
        "schemaVersion": 1,
        "unit": f"rrprof-1c1g-{run}-123.scope",
        "controlGroup": f"/system.slice/rrprof-1c1g-{run}-123.scope",
        "requested": {
            "cpuQuotaPercent": 100,
            "memoryMax": "1G",
            "memoryMaxBytes": MEMORY_BYTES,
            "memorySwapMaxBytes": 0,
        },
        "actual": {
            "cpuMax": "100000 100000",
            "cpuQuotaUs": 100_000,
            "cpuPeriodUs": 100_000,
            "memoryMaxBytes": MEMORY_BYTES,
            "memorySwapMaxBytes": 0,
            "memorySwapCurrentBytes": 0,
        },
        "matchesRequested": True,
    }


def startup(run):
    return {
        "cell": "startup",
        "run": run,
        "machineReport": machine_report(),
        "cgroupEvidence": cgroup_evidence(run),
        "idle": {
            "serverRssBytes": 16 * 1024 * 1024,
            "serverFdCount": 15,
            "cgroupMemoryCurrent": 20 * 1024 * 1024,
            "cgroupMemorySwapCurrent": 0,
        },
    }


def ladder(tag):
    return {
        "cell": "ladder",
        "tag": tag,
        "level": 100,
        "connectionsHeld": 100,
        "serverEstablishedSessions": 100,
        "connectionsFailedTotal": 0,
        "serverAlive": True,
        "serverRssBytes": 24 * 1024 * 1024,
        "serverFdCount": 215,
        "cgroupMemoryCurrent": 28 * 1024 * 1024,
        "cgroupMemoryPeak": 30 * 1024 * 1024,
        "cgroupMemorySwapCurrent": 0,
        "cgroupOomKills": 0,
        "logEvents": {},
        "latestPressureState": None,
        "ladderComplete": True,
        "abortReason": None,
    }


def passing_cells():
    return [
        startup("nogeo"),
        startup("geo"),
        startup("tuned"),
        {"cell": "churn", "concurrency": 8, "failed": 0,
         "connectionsPerSecond": 100, "p50Seconds": 0.01,
         "p99Seconds": 0.02, "serverCpuSeconds": 1},
        {"cell": "churn", "concurrency": 32, "failed": 0,
         "connectionsPerSecond": 100, "p50Seconds": 0.01,
         "p99Seconds": 0.02, "serverCpuSeconds": 1},
        {"cell": "download", "concurrency": 1, "errors": [],
         "sizeMismatches": 0, "throughputMiBPerSecond": 100,
         "serverCpuSeconds": 1},
        {"cell": "download", "concurrency": 32, "errors": [],
         "sizeMismatches": 0, "throughputMiBPerSecond": 100,
         "serverCpuSeconds": 1},
        ladder(None),
        ladder("tuned"),
        {"cell": "cgroup_final", "cgroupOomKills": 0,
         "cgroupMemorySwapCurrent": 0},
    ]


class ProfileCgroupEvidenceTests(unittest.TestCase):
    def summarize(self, cells, sample="1\t16777216\t15\t20971520\t0\n"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (root / "cells.jsonl").open("w", encoding="utf-8") as handle:
                for cell in cells:
                    handle.write(json.dumps(cell) + "\n")
            (root / "samples-geo.tsv").write_text(sample, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SUMMARIZER), str(root),
                 "--class", "1c1g", "--mode", "dedicated",
                 "--cpu-quota", "100", "--mem-max", "1G",
                 "--mem-max-bytes", str(MEMORY_BYTES),
                 "--mem-swap-max", "0"],
                check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True,
            )
            summary = json.loads((root / "summary.json").read_text(
                encoding="utf-8"))
            return result, summary

    def assert_rejected(self, cells, sample=None):
        kwargs = {} if sample is None else {"sample": sample}
        result, summary = self.summarize(cells, **kwargs)
        self.assertNotEqual(result.returncode, 0)
        self.assertIs(summary["pass"], False)

    def test_matching_limits_and_zero_swap_pass(self):
        result, summary = self.summarize(passing_cells())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIs(summary["pass"], True)
        self.assertIs(summary["resourceBoundaryEvidence"]["pass"], True)
        self.assertIs(summary["swapEvidence"]["pass"], True)

    def test_nonzero_swap_limit_is_rejected(self):
        cells = copy.deepcopy(passing_cells())
        cells[1]["cgroupEvidence"]["actual"]["memorySwapMaxBytes"] = 1
        self.assert_rejected(cells)

    def test_machine_cpu_quota_mismatch_is_rejected(self):
        cells = copy.deepcopy(passing_cells())
        cells[1]["machineReport"]["cpu_quota_us"] = 200_000
        self.assert_rejected(cells)

    def test_nonzero_cell_swap_is_rejected(self):
        cells = copy.deepcopy(passing_cells())
        cells[-1]["cgroupMemorySwapCurrent"] = 4096
        self.assert_rejected(cells)

    def test_nonzero_series_swap_is_rejected(self):
        self.assert_rejected(
            passing_cells(), sample="1\t16777216\t15\t20971520\t4096\n")

    def test_legacy_series_without_swap_column_is_rejected(self):
        self.assert_rejected(
            passing_cells(), sample="1\t16777216\t15\t20971520\n")


if __name__ == "__main__":
    unittest.main()
