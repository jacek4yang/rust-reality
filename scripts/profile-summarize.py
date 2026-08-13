#!/usr/bin/env python3
"""Summarize one machine-class directory of profile-validation cells.

Reads <classdir>/cells.jsonl and samples-*.tsv, writes summary.json and
summary.md into the same directory. Usage:

    profile-summarize.py <classdir> --class 1c1g --mode dedicated \
        --cpu-quota 100 --mem-max 1G --mem-max-bytes 1073741824 \
        --mem-swap-max 0
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


def positive_int(value):
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def nonnegative_int(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def cpu_quota_matches(quota, period, requested_percent):
    return (positive_int(quota) and positive_int(period)
            and quota * 100 == requested_percent * period)


def summarize_resource_boundaries(startups, requested_cpu_percent,
                                  requested_memory_bytes,
                                  requested_swap_bytes):
    scopes = []
    for startup in startups:
        machine = startup.get("machineReport") or {}
        evidence = startup.get("cgroupEvidence") or {}
        requested = evidence.get("requested") or {}
        actual = evidence.get("actual") or {}
        machine_matches = bool(
            machine.get("memory_source") == "cgroup_v2"
            and machine.get("memory_max") == requested_memory_bytes
            and machine.get("memory_total") == requested_memory_bytes
            and cpu_quota_matches(machine.get("cpu_quota_us"),
                                  machine.get("cpu_period_us"),
                                  requested_cpu_percent)
        )
        evidence_matches = bool(
            evidence.get("schemaVersion") == 1
            and evidence.get("matchesRequested") is True
            and isinstance(evidence.get("unit"), str) and evidence.get("unit")
            and isinstance(evidence.get("controlGroup"), str)
            and evidence.get("controlGroup", "").startswith("/")
            and requested.get("cpuQuotaPercent") == requested_cpu_percent
            and requested.get("memoryMaxBytes") == requested_memory_bytes
            and requested.get("memorySwapMaxBytes") == requested_swap_bytes
            and cpu_quota_matches(actual.get("cpuQuotaUs"),
                                  actual.get("cpuPeriodUs"),
                                  requested_cpu_percent)
            and actual.get("memoryMaxBytes") == requested_memory_bytes
            and actual.get("memorySwapMaxBytes") == requested_swap_bytes
            and actual.get("memorySwapCurrentBytes") == 0
        )
        scopes.append({
            "run": startup.get("run"),
            "machineReportMatches": machine_matches,
            "cgroupEvidenceMatches": evidence_matches,
            "pass": machine_matches and evidence_matches,
            "evidence": evidence,
        })
    return {
        "pass": bool(scopes) and all(scope["pass"] for scope in scopes),
        "expected": {
            "cpuQuotaPercent": requested_cpu_percent,
            "memoryMaxBytes": requested_memory_bytes,
            "memorySwapMaxBytes": requested_swap_bytes,
        },
        "scopeCount": len(scopes),
        "scopes": scopes,
    }


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
    oom_status_known = True
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
        level_oom_known = True
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
            row_oom = row.get("cgroupOomKills")
            if row_oom is None:
                level_oom_known = False
                oom_status_known = False
            else:
                oom = max(oom, row_oom)
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
            "cgroupOomKills": oom if level_oom_known else None,
            "cgroupOomStatusKnown": level_oom_known,
            "serverAlive": alive,
        }
        levels.append(entry)
        clean = (level_oom_known and established >= level * 0.98 and new_pressure == 0
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
        "oomKills": oom_kills if oom_status_known else None,
        "oomStatusKnown": oom_status_known,
        "completed": complete,
        "abortReason": abort_reason,
    }


def peaks_from_samples(classdir):
    max_rss = max_fd = max_cur = max_swap = 0
    rows = invalid_rows = 0
    for path in glob.glob(os.path.join(classdir, "samples-*.tsv")):
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) != 5:
                    invalid_rows += 1
                    continue
                _, rss, fds, cur, swap = parts
                try:
                    parsed = [int(value) for value in (rss, fds, cur, swap)]
                except ValueError:
                    invalid_rows += 1
                    continue
                if any(value < 0 for value in parsed):
                    invalid_rows += 1
                    continue
                rss_value, fd_value, cur_value, swap_value = parsed
                rows += 1
                max_rss = max(max_rss, rss_value)
                max_fd = max(max_fd, fd_value)
                max_cur = max(max_cur, cur_value)
                max_swap = max(max_swap, swap_value)
    return {
        "serverRssMax": max_rss,
        "serverFdMax": max_fd,
        "cgroupMemoryCurrentMax": max_cur,
        "cgroupMemorySwapCurrentMax": max_swap,
        "rows": rows,
        "invalidRows": invalid_rows,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("classdir")
    parser.add_argument("--class", dest="klass", required=True)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--cpu-quota", required=True, type=int)
    parser.add_argument("--mem-max", required=True)
    parser.add_argument("--mem-max-bytes", required=True, type=int)
    parser.add_argument("--mem-swap-max", required=True, type=int)
    args = parser.parse_args()

    if args.cpu_quota <= 0 or args.mem_max_bytes <= 0 or args.mem_swap_max != 0:
        parser.error("resource limits must be positive with --mem-swap-max exactly 0")

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
    sample_peaks = peaks_from_samples(args.classdir)
    max_rss = sample_peaks["serverRssMax"]
    max_fd = sample_peaks["serverFdMax"]
    max_cur = sample_peaks["cgroupMemoryCurrentMax"]

    startups = [cell for cell in cells if cell.get("cell") == "startup"]
    resource_boundaries = summarize_resource_boundaries(
        startups, args.cpu_quota, args.mem_max_bytes, args.mem_swap_max)
    swap_cell_values = []
    for cell in cells:
        if cell.get("cell") == "startup":
            swap_cell_values.append((cell.get("idle") or {}).get(
                "cgroupMemorySwapCurrent"))
        elif cell.get("cell") in ("ladder", "cgroup_final"):
            swap_cell_values.append(cell.get("cgroupMemorySwapCurrent"))
    swap_cells_known = bool(swap_cell_values) and all(
        nonnegative_int(value) for value in swap_cell_values)
    swap_evidence = {
        "pass": bool(
            resource_boundaries["pass"]
            and sample_peaks["rows"] > 0
            and sample_peaks["invalidRows"] == 0
            and sample_peaks["cgroupMemorySwapCurrentMax"] == 0
            and swap_cells_known
            and max(swap_cell_values, default=-1) == 0
        ),
        "cellStatusKnown": swap_cells_known,
        "cellSamples": len(swap_cell_values),
        "cellMaxBytes": max(swap_cell_values) if swap_cells_known else None,
        "seriesRows": sample_peaks["rows"],
        "seriesInvalidRows": sample_peaks["invalidRows"],
        "seriesMaxBytes": sample_peaks["cgroupMemorySwapCurrentMax"],
    }

    churn_ok = bool(churn8 and churn32
                    and churn8["failedTotal"] == 0 and churn32["failedTotal"] == 0)
    download_ok = bool(
        dl1 and dl32 and not dl1["errors"] and not dl32["errors"]
        and dl1["sizeMismatches"] == 0 and dl32["sizeMismatches"] == 0)
    oom_values = [ladder["oomKills"] if ladder else None,
                  ladder_tuned["oomKills"] if ladder_tuned else None]
    oom_values.extend(f.get("cgroupOomKills") for f in finals)
    oom_status_known = bool(oom_values) and all(value is not None for value in oom_values)
    oom_kills = max(oom_values) if oom_status_known else None
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
    passed = (churn_ok and download_ok and oom_status_known and oom_kills == 0
              and ladder_ok and tuned_ladder_ok and resource_boundaries["pass"]
              and swap_evidence["pass"])

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
        "cgroupLimits": {"cpuQuotaPercent": args.cpu_quota,
                         "memoryMax": args.mem_max,
                         "memoryMaxBytes": args.mem_max_bytes,
                         "memorySwapMaxBytes": args.mem_swap_max},
        "resourceBoundaryEvidence": resource_boundaries,
        "swapEvidence": swap_evidence,
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
            "cgroupMemorySwapCurrentMax": sample_peaks[
                "cgroupMemorySwapCurrentMax"],
            "serverRssMax": max_rss,
            "serverFdMax": max(max_fd, ladder_fd_max),
            "cgroupOomKills": oom_kills,
            "cgroupOomStatusKnown": oom_status_known,
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
              f"CPUQuota={args.cpu_quota}%, MemoryMax={args.mem_max}, "
              f"MemorySwapMax={args.mem_swap_max})")
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
    md.append(f"| cgroup resource-boundary evidence | "
              f"{resource_boundaries['pass']} "
              f"({resource_boundaries['scopeCount']} scopes) |")
    md.append(f"| swap.current evidence | {swap_evidence['pass']} "
              f"(cells max {mib(swap_evidence['cellMaxBytes'])} MiB, "
              f"series max {mib(swap_evidence['seriesMaxBytes'])} MiB) |")
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
