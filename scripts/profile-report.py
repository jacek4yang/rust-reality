#!/usr/bin/env python3
"""Aggregate per-class summary.json files into one cross-class SUMMARY.md.

Usage: profile-report.py <out_root>   (default benchmarks/profile-validation)
"""
import glob
import json
import os
import sys


def mib(nbytes):
    return round(nbytes / 1024 / 1024, 1) if nbytes is not None else None


def fmt(value, digits=0):
    if value is None:
        return "-"
    return f"{value:.{digits}f}"


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "benchmarks/profile-validation"
    summaries = []
    for path in sorted(glob.glob(os.path.join(root, "*", "summary.json"))):
        with open(path, encoding="utf-8") as handle:
            summaries.append(json.load(handle))
    if not summaries:
        raise SystemExit(f"no summary.json files under {root}")

    lines = []
    lines.append("# rust-reality machine-profile validation")
    lines.append("")
    env_path = os.path.join(root, "environment.json")
    if os.path.isfile(env_path):
        with open(env_path, encoding="utf-8") as handle:
            env = json.load(handle)
        lines.append(f"- commit: `{env['commit']}`")
        lines.append(f"- binary: `{env['binary']}` sha256 `{env['binarySha256']}`")
        lines.append(f"- host: {env['host']}, kernel {env['kernel']}, "
                     f"client {env['xray']}")
        lines.append(f"- measured: {env['dateUtc']} — {env['note']}")
        lines.append("")
    lines.append("| class | mode | pass | idle RSS MiB | assets RSS MiB | "
                 "churn c8 conn/s (p99 ms) | churn c32 conn/s (p99 ms) | "
                 "512MiB c1 MiB/s | 512MiB c32 MiB/s | clean lvl (default) | "
                 "clean lvl (tuned) | first pressure (tuned) | oom | "
                 "peak cgroup MiB | peak FDs |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for s in summaries:
        churn8 = s["churn"].get("c8") or {}
        churn32 = s["churn"].get("c32") or {}
        dl1 = s["download512MiB"].get("c1") or {}
        dl32 = s["download512MiB"].get("c32") or {}
        ladder = s.get("ladder") or {}
        tuned = s.get("ladderTuned") or {}
        lines.append(
            f"| {s['class']} | {s['resourceMode']} | {s['pass']} | "
            f"{mib(s['idle'].get('serverRssBytes'))} | "
            f"{mib(s['assets'].get('serverRssBytes'))} | "
            f"{fmt(churn8.get('connectionsPerSecondMedian'))} "
            f"({fmt(churn8.get('p99MsWorst'))}) | "
            f"{fmt(churn32.get('connectionsPerSecondMedian'))} "
            f"({fmt(churn32.get('p99MsWorst'))}) | "
            f"{fmt(dl1.get('throughputMiBPerSecondMedian'))} | "
            f"{fmt(dl32.get('throughputMiBPerSecondMedian'))} | "
            f"{ladder.get('maxCleanLevel')} | "
            f"{tuned.get('maxCleanLevel')} | "
            f"{tuned.get('firstPressureLevel')} | "
            f"{s['peaks']['cgroupOomKills']} | "
            f"{mib(s['peaks'].get('cgroupMemoryPeak'))} | "
            f"{s['peaks'].get('serverFdMax')} |")
    lines.append("")
    lines.append("## Derived budgets per class")
    lines.append("")
    lines.append("| class | cpus seen | cpu.max us | memory total MiB | "
                 "fd soft -> effective | fd budget | fd clamped |")
    lines.append("|---|---|---|---|---|---|---|")
    for s in summaries:
        m = s["derivedBudgets"].get("machineReport") or {}
        b = s["derivedBudgets"].get("descriptorBudgetReport") or {}
        lines.append(
            f"| {s['class']} | {m.get('available_cpus')} | "
            f"{m.get('cpu_quota_us')}/{m.get('cpu_period_us')} | "
            f"{mib(m.get('memory_total'))} | "
            f"{m.get('fd_soft_limit')} -> {m.get('fd_effective_soft_limit')} | "
            f"{b.get('fd_effective_budget')} | {b.get('fd_clamped')} |")
    lines.append("")
    out = os.path.join(root, "SUMMARY.md")
    with open(out, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
