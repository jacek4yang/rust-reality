#!/usr/bin/env python3
"""Capture identity-bound perf-stat evidence or an explicit unavailable result."""

import argparse
import hashlib
import json
import os
import pathlib
import platform
import subprocess
import tempfile

EVENTS = "task-clock,cycles,instructions,branches,branch-misses,cache-references,cache-misses,context-switches,cpu-migrations,page-faults"


def file_sha(path):
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
    if file_sha(binary) != args.binary_sha256.lower():
        raise SystemExit("binary SHA-256 mismatch")
    if pathlib.Path(command[0]).resolve() != binary:
        raise SystemExit("workload must execute the identified binary")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="rr-perf-stat-") as temporary:
        raw = pathlib.Path(temporary) / "perf.csv"
        invocation = [
            "perf",
            "stat",
            "-x",
            ";",
            "-e",
            EVENTS,
            "-o",
            str(raw),
            "--",
            *command,
        ]
        done = subprocess.run(invocation, check=False, capture_output=True, text=True)
        raw_text = (
            raw.read_text(encoding="utf-8", errors="replace") if raw.exists() else ""
        )
    diagnostic = raw_text + done.stderr
    unavailable = done.returncode != 0 and any(
        word in diagnostic.lower()
        for word in (
            "permission",
            "not supported",
            "no permission",
            "access to performance monitoring",
        )
    )
    evidence = {
        "schemaVersion": 1,
        "tool": "perf-stat",
        "status": "UNAVAILABLE"
        if unavailable
        else ("PASS" if done.returncode == 0 else "FAIL"),
        "binary": {"path": str(binary), "sha256": args.binary_sha256.lower()},
        "command": command,
        "events": EVENTS.split(","),
        "perfVersion": subprocess.run(
            ["perf", "--version"], capture_output=True, text=True, check=False
        ).stdout.strip(),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "effectiveAffinity": sorted(os.sched_getaffinity(0)),
        "exitCode": done.returncode,
        "raw": raw_text,
        "workloadStdoutSha256": hashlib.sha256(done.stdout.encode()).hexdigest(),
        "diagnostic": done.stderr,
        "unavailableReason": diagnostic.strip() if unavailable else None,
    }
    temporary = output.with_name("." + output.name + ".tmp")
    temporary.write_text(json.dumps(evidence, indent=2) + "\n")
    os.replace(temporary, output)
    if evidence["status"] == "FAIL":
        raise SystemExit(done.returncode or 1)


if __name__ == "__main__":
    main()
