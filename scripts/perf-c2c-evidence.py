#!/usr/bin/env python3
"""Capture identity-bound perf-c2c evidence or an explicit unavailable result."""

import argparse
import hashlib
import json
import os
import pathlib
import platform
import subprocess
import tempfile


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--binary", required=True, type=pathlib.Path)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    binary = args.binary.resolve()
    output = args.output.resolve()
    if not command:
        parser.error("a workload command is required after --")
    if sha(binary) != args.binary_sha256.lower():
        raise SystemExit("binary SHA-256 mismatch")
    if pathlib.Path(command[0]).resolve() != binary:
        raise SystemExit("workload must execute the identified binary")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="rr-perf-c2c-") as directory:
        data = pathlib.Path(directory) / "perf.data"
        record = subprocess.run(
            ["perf", "c2c", "record", "-o", str(data), "--", *command],
            capture_output=True,
            text=True,
            check=False,
        )
        report = (
            subprocess.run(
                ["perf", "c2c", "report", "-i", str(data), "--stdio"],
                capture_output=True,
                text=True,
                check=False,
            )
            if record.returncode == 0
            else None
        )
    diagnostic = record.stderr + (report.stderr if report else "")
    unavailable = record.returncode != 0 and any(
        word in diagnostic.lower()
        for word in (
            "permission",
            "not supported",
            "no permission",
            "access to performance monitoring",
        )
    )
    status = (
        "UNAVAILABLE"
        if unavailable
        else (
            "PASS"
            if record.returncode == 0 and report and report.returncode == 0
            else "FAIL"
        )
    )
    evidence = {
        "schemaVersion": 1,
        "tool": "perf-c2c",
        "status": status,
        "binary": {"path": str(binary), "sha256": args.binary_sha256.lower()},
        "command": command,
        "perfVersion": subprocess.run(
            ["perf", "--version"], capture_output=True, text=True, check=False
        ).stdout.strip(),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "effectiveAffinity": sorted(os.sched_getaffinity(0)),
        "recordExitCode": record.returncode,
        "reportExitCode": report.returncode if report else None,
        "report": report.stdout if report else "",
        "diagnostic": diagnostic,
        "unavailableReason": diagnostic.strip() if unavailable else None,
    }
    temporary = output.with_name("." + output.name + ".tmp")
    temporary.write_text(json.dumps(evidence, indent=2) + "\n")
    os.replace(temporary, output)
    if status == "FAIL":
        raise SystemExit(record.returncode or (report.returncode if report else 1))


if __name__ == "__main__":
    main()
