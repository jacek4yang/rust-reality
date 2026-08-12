#!/usr/bin/env python3
"""Summarize one machine-class directory of profile-validation cells.

Reads <classdir>/cells.jsonl and samples-*.tsv, writes summary.json and
summary.md into the same directory. Usage:

    profile-summarize.py <classdir> --class 1c1g --mode dedicated \
        --cpu-quota 100 --mem-max 1G
"""
import argparse
import glob
import json
import os
import statistics
import sys


def load_cells(path):
    cells = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                cells.append(json.loads(line))
    return cells


def median(values):
    values = [v for v in values if v is not None]
    return statistics.median(values) if values else None


def mib(nbytes):
    return round(nbytes / 1024 / 1024, 1) if nbytes is not None else None


def summarize_churn(cells, concurrency):
    rows = [c for c in cells if c.get("cell") == "churn"
            and c.get("concurrency") == concurrency]
    if not rows:
        return None
    return {
        "connectionsPerSecondMedian": median(
            [r.get("connectionsPerSecond") for r in rows]),
        "p50MsWorst": max((r.get("p50Seconds") or 0) for r in rows) * 1000,
        "p99MsWorst": max((r.get("p99Seconds") or 0) for r in rows) * 1000,
        "failedTotal": sum(r.get("failed", 0) for r in rows),
        "serverCpuSecondsTotal": sum(r.get("serverCpuSeconds") or 0 for r in rows),
        "samples": len(rows),
    }


def summarize_download(cells, concurrency):
    rows = [c for c in cells if c.get("cell") == "download"
            and c.get("concurrency") == concurrency]
    if not rows:
        return None
    return {
        "throughputMiBPerSecondMedian": median(
            [r.get("throughputMiBPerSecond") for r in rows]),
        "sizeMismatches": sum(r.get("sizeMismatches", 0) for r in rows),
        "errors": [e for r in rows for e in r.get("errors", [])],
        "serverCpuSecondsTotal": sum(r.get("serverCpuSeconds") or 0 for r in rows),
        "samples": len(rows),
    }


PRESSURE_KEYS = ("resource_pressure_changed", "descriptor_pressure_changed",
                 "admission_limited", "connection_rejected")

BASE_FDS = 15  # listener, stdio, runtime descriptors before any session


def summarize_ladder(cells, tag=None):
    rows = [c for c in cells if c.get("cell") == "ladder"
            and c.get("tag") == tag]
    if not rows:
        return None
    # Group the records of each level (initial sample, optional recheck,
    # final steady-state); log event counters are cumulative across records.
    by_level = {}
    order = []
    for row in rows:
        level = row.get("level", 0)
        if level not in by_level:
            by_level[level] = []
            order.append(level)
        by_level[level].append(row)

    levels = []
    max_clean = 0
    first_pressure = None
    prev_events = {k: 0 for k in PRESSURE_KEYS}
    prev_failed = 0
    oom_kills = 0
    abort_reason = None
    complete = False
    max_established = 0
    for level in order:
        group = by_level[level]
        established = max(
            (r.get("serverEstablishedSessions")
             if r.get("serverEstablishedSessions") is not None
             else max(0, ((r.get("serverFdCount") or BASE_FDS) - BASE_FDS) // 2))
            for r in group)
        held = max(r.get("connectionsHeld") or 0 for r in group)
        new_pressure = 0
        new_failed = 0
        oom = 0
        alive = True
        state = None
        rss = fds = current = 0
        for row in group:
            events = row.get("logEvents") or {}
            new_pressure += sum(max(0, events.get(k, 0) - prev_events.get(k, 0))
                                for k in PRESSURE_KEYS)
            prev_events = {k: max(events.get(k, 0), prev_events.get(k, 0))
                           for k in PRESSURE_KEYS}
            failed_total = row.get("connectionsFailedTotal") or 0
            new_failed += max(0, failed_total - prev_failed)
            prev_failed = max(prev_failed, failed_total)
            oom = max(oom, row.get("cgroupOomKills") or 0)
            alive = alive and row.get("serverAlive", False)
            state = row.get("latestPressureState") or state
            rss = max(rss, row.get("serverRssBytes") or 0)
            fds = max(fds, row.get("serverFdCount") or 0)
            current = max(current, row.get("cgroupMemoryCurrent") or 0)
            if "ladderComplete" in row:
                complete = row["ladderComplete"]
                abort_reason = row.get("abortReason")
        oom_kills = max(oom_kills, oom)
        max_established = max(max_established, established)
        entry = {
            "level": level,
            "held": held,
            "established": established,
            "newFailures": new_failed,
            "newPressureEvents": new_pressure,
            "latestPressureState": state,
            "serverRssBytes": rss,
            "serverFdCount": fds,
            "cgroupMemoryCurrent": current,
            "cgroupOomKills": oom,
            "serverAlive": alive,
        }
        levels.append(entry)
        clean = (established >= level * 0.98 and new_pressure == 0
                 and new_failed == 0 and oom == 0 and alive)
        if clean:
            max_clean = max(max_clean, level)
        elif first_pressure is None:
            first_pressure = level
    return {
        "levels": levels,
        "maxCleanLevel": max_clean,
        "maxEstablishedSessions": max_established,
        "firstPressureLevel": first_pressure,
        "oomKills": oom_kills,
        "completed": complete,
        "abortReason": abort_reason,
    }


def peaks_from_samples(classdir):
    max_rss = max_fd = max_cur = 0
    for path in glob.glob(os.path.join(classdir, "samples-*.tsv")):
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) != 4:
                    continue
                _, rss, fds, cur = parts
                max_rss = max(max_rss, int(rss or 0))
                max_fd = max(max_fd, int(fds or 0))
                max_cur = max(max_cur, int(cur or 0))
    return max_rss, max_fd, max_cur


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("classdir")
    parser.add_argument("--class", dest="klass", required=True)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--cpu-quota", required=True)
    parser.add_argument("--mem-max", required=True)
    args = parser.parse_args()

    cells = load_cells(os.path.join(args.classdir, "cells.jsonl"))

    startup_geo = next((c for c in cells
                        if c.get("cell") == "startup" and c.get("run") == "geo"), {})
    startup_nogeo = next((c for c in cells
                          if c.get("cell") == "startup" and c.get("run") == "nogeo"), {})
    machine = startup_geo.get("machineReport") or startup_nogeo.get("machineReport")
    budget = startup_geo.get("descriptorBudgetReport") or startup_nogeo.get(
        "descriptorBudgetReport")
    backends = startup_geo.get("relayBackendReport") or startup_nogeo.get(
        "relayBackendReport")

    finals = [c for c in cells if c.get("cell") == "cgroup_final"]
    ladder = summarize_ladder(cells, None)
    ladder_tuned = summarize_ladder(cells, "tuned")
    churn8 = summarize_churn(cells, 8)
    churn32 = summarize_churn(cells, 32)
    dl1 = summarize_download(cells, 1)
    dl32 = summarize_download(cells, 32)
    max_rss, max_fd, max_cur = peaks_from_samples(args.classdir)

    churn_ok = bool(churn8 and churn32
                    and churn8["failedTotal"] == 0 and churn32["failedTotal"] == 0)
    download_ok = bool(
        dl1 and dl32 and not dl1["errors"] and not dl32["errors"]
        and dl1["sizeMismatches"] == 0 and dl32["sizeMismatches"] == 0)
    oom_kills = max(
        [ladder["oomKills"] if ladder else 0,
         ladder_tuned["oomKills"] if ladder_tuned else 0]
        + [f.get("cgroupOomKills") or 0 for f in finals])
    ladder_ok = bool(
        ladder
        and ladder["completed"]
        and ladder["abortReason"] is None
        and ladder["maxCleanLevel"] > 0
    )
    tuned_ladder_ok = bool(
        ladder_tuned
        and ladder_tuned["completed"]
        and ladder_tuned["abortReason"] is None
        and ladder_tuned["maxCleanLevel"] > 0
    )
    passed = churn_ok and download_ok and oom_kills == 0 and ladder_ok and tuned_ladder_ok

    ladder_fd_max = 0
    ladder_peak_max = 0
    for lad in (ladder, ladder_tuned):
        if lad:
            ladder_fd_max = max(ladder_fd_max,
                                *(l["serverFdCount"] or 0 for l in lad["levels"]))
    for c in cells:
        if c.get("cell") in ("ladder", "cgroup_final"):
            ladder_peak_max = max(ladder_peak_max, c.get("cgroupMemoryPeak") or 0)
    cgroup_memory_peak = ladder_peak_max or None
    summary = {
        "class": args.klass,
        "resourceMode": args.mode,
        "cgroupLimits": {"cpuQuotaPercent": int(args.cpu_quota),
                         "memoryMax": args.mem_max},
        "pass": passed,
        "derivedBudgets": {
            "machineReport": machine,
            "descriptorBudgetReport": budget,
            "relayBackendReport": backends,
        },
        "idle": (startup_nogeo.get("idle") or {}),
        "assets": (startup_geo.get("idle") or {}),
        "churn": {"c8": churn8, "c32": churn32},
        "download512MiB": {"c1": dl1, "c32": dl32},
        "ladder": ladder,
        "ladderTuned": ladder_tuned,
        "peaks": {
            "cgroupMemoryPeak": cgroup_memory_peak,
            "cgroupMemoryCurrentMax": max_cur,
            "serverRssMax": max_rss,
            "serverFdMax": max(max_fd, ladder_fd_max),
            "cgroupOomKills": oom_kills,
        },
    }

    with open(os.path.join(args.classdir, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
        fh.write("\n")

    def fmt_ms(value):
        return f"{value:.0f}" if value is not None else "-"

    def fmt_rate(value):
        return f"{value:.0f}" if value is not None else "-"

    def fmt_tp(value):
        return f"{value:.0f}" if value is not None else "-"

    md = []
    md.append(f"# {args.klass} (resourceMode={args.mode}, "
              f"CPUQuota={args.cpu_quota}%, MemoryMax={args.mem_max})")
    md.append("")
    if machine:
        md.append("Derived budgets (machine_report / descriptor_budget_report):")
        md.append("")
        md.append(f"- cpus visible: {machine.get('available_cpus')}, "
                  f"cpu.max quota: {machine.get('cpu_quota_us')}/"
                  f"{machine.get('cpu_period_us')} us")
        md.append(f"- memory: source={machine.get('memory_source')} "
                  f"max={mib(machine.get('memory_max'))} MiB "
                  f"total={mib(machine.get('memory_total'))} MiB")
        md.append(f"- fd: soft {machine.get('fd_soft_limit')} -> effective "
                  f"{machine.get('fd_effective_soft_limit')} "
                  f"(raised: {machine.get('fd_soft_limit_raised')})")
    if budget:
        md.append(f"- fd budget: reserve {budget.get('fd_fixed_reserve')} + "
                  f"headroom {budget.get('fd_safety_headroom')} -> effective "
                  f"{budget.get('fd_effective_budget')} "
                  f"(clamped: {budget.get('fd_clamped')})")
    if backends:
        states = ", ".join(
            f"{b['backend']}={'ok' if b['available'] else b.get('decline_reason', 'no')}"
            for b in backends.get("backends", []))
        md.append(f"- relay backends: {states}")
    md.append("")
    md.append("| metric | value |")
    md.append("|---|---|")
    idle = summary["idle"]
    assets = summary["assets"]
    md.append(f"| idle RSS (no assets) | {mib(idle.get('serverRssBytes'))} MiB "
              f"(cgroup {mib(idle.get('cgroupMemoryCurrent'))} MiB, "
              f"{idle.get('serverFdCount')} fds) |")
    md.append(f"| assets RSS (geo loaded) | {mib(assets.get('serverRssBytes'))} MiB "
              f"(cgroup {mib(assets.get('cgroupMemoryCurrent'))} MiB, "
              f"{assets.get('serverFdCount')} fds) |")
    if churn8:
        md.append(f"| setup churn c8 | {fmt_rate(churn8['connectionsPerSecondMedian'])} "
                  f"conn/s, p99 {fmt_ms(churn8['p99MsWorst'])} ms, "
                  f"failed {churn8['failedTotal']} |")
    if churn32:
        md.append(f"| setup churn c32 | {fmt_rate(churn32['connectionsPerSecondMedian'])} "
                  f"conn/s, p99 {fmt_ms(churn32['p99MsWorst'])} ms, "
                  f"failed {churn32['failedTotal']} |")
    if dl1:
        md.append(f"| 512 MiB download c1 | "
                  f"{fmt_tp(dl1['throughputMiBPerSecondMedian'])} MiB/s |")
    if dl32:
        md.append(f"| 512 MiB download c32 | "
                  f"{fmt_tp(dl32['throughputMiBPerSecondMedian'])} MiB/s |")
    if ladder:
        md.append(f"| max clean idle-connection level (default policy) | "
                  f"{ladder['maxCleanLevel']} |")
        md.append(f"| first pressure level (default policy) | "
                  f"{ladder['firstPressureLevel']} |")
        md.append(f"| max established sessions (default policy) | "
                  f"{ladder['maxEstablishedSessions']} |")
    if ladder_tuned:
        md.append(f"| max clean idle-connection level (tuned policy) | "
                  f"{ladder_tuned['maxCleanLevel']} |")
        md.append(f"| first pressure level (tuned policy) | "
                  f"{ladder_tuned['firstPressureLevel']} |")
        md.append(f"| max established sessions (tuned policy) | "
                  f"{ladder_tuned['maxEstablishedSessions']} |")
        md.append(f"| tuned ladder completed | {ladder_tuned['completed']} "
                  f"({ladder_tuned['abortReason'] or 'no abort'}) |")
    md.append(f"| oom_kills | {oom_kills} |")
    md.append(f"| peak cgroup memory.current | {mib(max_cur)} MiB "
              f"(memory.peak {mib(cgroup_memory_peak)} MiB) |")
    md.append(f"| peak server RSS | {mib(max_rss)} MiB |")
    md.append(f"| peak server FDs | {summary['peaks']['serverFdMax']} |")
    md.append(f"| **pass** | {passed} |")
    md.append("")
    for title, lad in (("Default policy", ladder), ("Tuned policy", ladder_tuned)):
        if not lad:
            continue
        md.append(f"Idle-connection ladder ({title.lower()}):")
        md.append("")
        md.append("| level | established | new fails | new pressure events | RSS MiB | "
                  "cgroup MiB | fds | state |")
        md.append("|---|---|---|---|---|---|---|---|")
        for entry in lad["levels"]:
            md.append(
                f"| {entry['level']} | {entry['established']} | "
                f"{entry['newFailures']} | "
                f"{entry['newPressureEvents']} | {mib(entry['serverRssBytes'])} | "
                f"{mib(entry['cgroupMemoryCurrent'])} | {entry['serverFdCount']} | "
                f"{entry['latestPressureState'] or ''} |")
        md.append("")

    with open(os.path.join(args.classdir, "summary.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(md))

    if not passed:
        raise SystemExit("profile validation failed; inspect summary.json")


if __name__ == "__main__":
    main()
