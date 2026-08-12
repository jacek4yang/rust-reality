#!/usr/bin/env python3
"""Measurement driver for scripts/validate-profiles.sh.

Subcommands (each prints one JSON object per line on stdout):

  churn     cN connection setup churn through a SOCKS5 client fronting the
            server under test (raw-socket SOCKS5 + HTTP/1.0, the
            benchmark-setup-rate.sh pattern: setup dominates).
  download  512 MiB framed download via curl --socks5-hostname (the
            benchmark-matrix.sh pattern; curl env is proxy-stripped).
  ladder    cumulative idle-connection ladder: hold N authenticated but idle
            tunnel sessions open level by level, sampling server RSS, server
            FD count and the cgroup memory files at each level. Aborts early
            when the server dies, the cgroup OOM-kills, or a wave mostly fails.

Common arguments: --server-pid (for /proc CPU/RSS/FD sampling) and
--server-log (to correlate pressure/rejection log events with ladder levels).
Proxy environment variables are stripped from every child process.
"""
import argparse
import concurrent.futures
import json
import os
import socket
import subprocess
import sys
import time

MIB = 1024 * 1024

# Merged into every emitted record (set from --tag).
RECORD_TAG = None

CLEAN_ENV = {
    key: value
    for key, value in os.environ.items()
    if not key.lower().endswith("_proxy")
}


def proc_cpu_seconds(pid):
    """utime + stime of the server process, in seconds."""
    with open(f"/proc/{pid}/stat") as handle:
        parts = handle.read().rsplit(")", 1)[1].split()
    utime, stime = int(parts[11]), int(parts[12])
    return (utime + stime) / os.sysconf("SC_CLK_TCK")


def proc_rss_bytes(pid):
    with open(f"/proc/{pid}/status") as handle:
        for line in handle:
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    return None


def proc_fd_count(pid):
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return None


def pid_alive(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def cgroup_read(cgroup, name):
    if not cgroup:
        return None
    try:
        with open(os.path.join(cgroup, name)) as handle:
            return handle.read().strip()
    except OSError:
        return None


def cgroup_int(cgroup, name):
    value = cgroup_read(cgroup, name)
    if value is None or value == "max":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def cgroup_oom_kills(cgroup):
    events = cgroup_read(cgroup, "memory.events")
    if not events:
        return None
    for line in events.splitlines():
        key, _, value = line.partition(" ")
        if key == "oom_kill":
            try:
                return int(value)
            except ValueError:
                return None
    return None


def log_marker_counts(path):
    """Counts of the pressure/rejection log events emitted so far."""
    counts = {
        "resource_pressure_changed": 0,
        "descriptor_pressure_changed": 0,
        "admission_limited": 0,
        "connection_rejected": 0,
        "accept_error_recovered": 0,
    }
    latest_pressure_state = None
    try:
        with open(path, "rb") as handle:
            for raw in handle:
                if b'"event"' not in raw:
                    continue
                try:
                    event = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                name = event.get("event")
                if name in counts:
                    counts[name] += 1
                if name == "resource_pressure_changed":
                    latest_pressure_state = event.get("pressure_state")
    except OSError:
        pass
    return counts, latest_pressure_state


def emit(record):
    print(json.dumps(record), flush=True)


def percentile(ordered, fraction):
    return ordered[min(len(ordered) - 1, int(len(ordered) * fraction))]


def socks5_connect(socks_port, target_host, target_port, timeout=30):
    """One raw SOCKS5 no-auth CONNECT through the fronting client."""
    sock = socket.create_connection(("127.0.0.1", socks_port), timeout=timeout)
    sock.settimeout(timeout)
    sock.sendall(b"\x05\x01\x00")
    if sock.recv(2) != b"\x05\x00":
        sock.close()
        raise OSError("socks greeting rejected")
    ip = bytes(int(x) for x in target_host.split("."))
    sock.sendall(b"\x05\x01\x00\x01" + ip + int(target_port).to_bytes(2, "big"))
    reply = sock.recv(10)
    if len(reply) < 10 or reply[1] != 0:
        sock.close()
        raise OSError(f"socks connect rejected rep={reply[1] if len(reply) > 1 else '?'}")
    return sock


def cmd_churn(args):
    def one_connection(_):
        started = time.perf_counter()
        try:
            with socks5_connect(args.socks, "127.0.0.1", args.origin_port) as sock:
                sock.sendall(
                    b"GET /payload.bin HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n"
                )
                if not sock.recv(4096):
                    return None
            return time.perf_counter() - started
        except OSError:
            return None

    for conc in args.concurrency:
        one_connection(0)  # warm the client and server paths
        for sample in range(args.samples):
            cpu0 = proc_cpu_seconds(args.server_pid)
            wall0 = time.perf_counter()
            with concurrent.futures.ThreadPoolExecutor(max_workers=conc) as ex:
                latencies = list(ex.map(one_connection, range(args.conns)))
            wall = time.perf_counter() - wall0
            cpu = proc_cpu_seconds(args.server_pid) - cpu0
            good = sorted(x for x in latencies if x is not None)
            record = {
                "cell": "churn",
                "concurrency": conc,
                "sampleIndex": sample,
                "wallSeconds": wall,
                "serverCpuSeconds": cpu,
                "connections": len(good),
                "failed": len(latencies) - len(good),
            }
            if good:
                record.update({
                    "connectionsPerSecond": len(good) / wall,
                    "p50Seconds": percentile(good, 0.50),
                    "p95Seconds": percentile(good, 0.95),
                    "p99Seconds": percentile(good, 0.99),
                })
            emit(record)


def cmd_download(args):
    started_any = None
    for sample in range(args.samples):
        cpu0 = proc_cpu_seconds(args.server_pid)
        wall0 = time.perf_counter()
        procs = []
        for _ in range(args.concurrency):
            procs.append(subprocess.Popen(
                [
                    "curl", "--fail", "--silent", "--show-error",
                    "--max-time", "900",
                    "--socks5-hostname", f"127.0.0.1:{args.socks}",
                    "--output", os.devnull,
                    "--write-out", "%{size_download} %{time_total}",
                    args.url,
                ],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, env=CLEAN_ENV,
            ))
        sizes, times, errors = [], [], []
        for proc in procs:
            out, err = proc.communicate()
            if proc.returncode != 0:
                errors.append(f"curl rc={proc.returncode}: {err.strip()[:200]}")
                continue
            size, elapsed = out.split()
            sizes.append(int(size))
            times.append(float(elapsed))
        wall = time.perf_counter() - wall0
        cpu = proc_cpu_seconds(args.server_pid) - cpu0
        total = sum(sizes)
        record = {
            "cell": "download",
            "concurrency": args.concurrency,
            "sampleIndex": sample,
            "wallSeconds": wall,
            "serverCpuSeconds": cpu,
            "totalBytes": total,
            "requests": len(sizes),
            "errors": errors,
            "throughputMiBPerSecond": total / wall / MIB if wall > 0 else None,
            "perRequestSeconds": times,
            "sizeMismatches": sum(1 for s in sizes if s != args.expected_bytes),
        }
        emit(record)
        started_any = True
    if not started_any:
        emit({"cell": "download", "concurrency": args.concurrency, "errors": ["no samples"]})


def cmd_ladder(args):
    import asyncio

    levels = [int(x) for x in args.levels.split(",") if x]
    baseline_oom = cgroup_oom_kills(args.cgroup)
    base_fds = proc_fd_count(args.server_pid) or 0
    held = []          # asyncio StreamWriter objects kept open
    total_failed = 0
    abort_reason = None

    async def open_one(sem):
        async with sem:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection("127.0.0.1", args.socks), timeout=15)
                writer.write(b"\x05\x01\x00")
                await writer.drain()
                if await asyncio.wait_for(reader.readexactly(2), 15) != b"\x05\x00":
                    writer.close()
                    return None
                target = b"\x05\x01\x00\x01\x7f\x00\x00\x01" + int(
                    args.origin_port).to_bytes(2, "big")
                writer.write(target)
                await writer.drain()
                reply = await asyncio.wait_for(reader.readexactly(10), 20)
                if len(reply) < 10 or reply[1] != 0:
                    writer.close()
                    return None
                return writer
            except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                return None

    async def open_wave(count):
        sem = asyncio.Semaphore(256)
        results = await asyncio.gather(*(open_one(sem) for _ in range(count)))
        return results

    def sample(level, opened, failed):
        counts, pressure_state = log_marker_counts(args.server_log)
        fds = proc_fd_count(args.server_pid)
        current_oom = cgroup_oom_kills(args.cgroup)
        oom_delta = (None if baseline_oom is None or current_oom is None
                     else current_oom - baseline_oom)
        established = max(0, (fds - base_fds) // 2) if fds is not None else None
        return {
            "cell": "ladder",
            "tag": RECORD_TAG,
            "level": level,
            "connectionsHeld": opened,
            "serverEstablishedSessions": established,
            "connectionsFailedTotal": failed,
            "serverAlive": pid_alive(args.server_pid),
            "serverRssBytes": proc_rss_bytes(args.server_pid),
            "serverFdCount": fds,
            "serverCpuSeconds": proc_cpu_seconds(args.server_pid)
            if pid_alive(args.server_pid) else None,
            "cgroupMemoryCurrent": cgroup_int(args.cgroup, "memory.current"),
            "cgroupMemoryPeak": cgroup_int(args.cgroup, "memory.peak"),
            "cgroupOomKills": oom_delta,
            "logEvents": counts,
            "latestPressureState": pressure_state,
        }

    async def run():
        nonlocal total_failed, abort_reason
        opened = 0
        for level in levels:
            if not pid_alive(args.server_pid):
                abort_reason = "server process died"
                break
            wave = level - opened
            if wave > 0:
                results = await open_wave(wave)
                for writer in results:
                    if writer is None:
                        total_failed += 1
                    else:
                        held.append(writer)
                opened = len(held)
            await asyncio.sleep(args.settle)
            record = sample(level, opened, total_failed)
            emit(record)
            oom = record["cgroupOomKills"]
            if not record["serverAlive"]:
                abort_reason = "server process died"
                break
            if oom is None:
                abort_reason = "cgroup oom_kill status unavailable"
                break
            if oom > 0:
                abort_reason = "cgroup oom_kill"
                break
            if wave > 0 and opened < level * 0.5:
                abort_reason = "majority of the wave failed to connect"
                break
            established = record["serverEstablishedSessions"]
            plateau = (level >= 1000 and established is not None
                       and established < level * 0.6)
            await asyncio.sleep(args.hold)
            if plateau:
                # Sessions may still be filling via client retries; recheck
                # once after the hold before declaring the plateau real.
                recheck = sample(level, opened, total_failed)
                recheck["recheck"] = True
                emit(recheck)
                established = recheck["serverEstablishedSessions"]
                if established is not None and established < level * 0.6:
                    abort_reason = (
                        "server-side sessions plateaued at "
                        f"{established} (admission ceiling or pressure)"
                    )
                    break

        # Final steady-state sample after the hold, then drop everything.
        await asyncio.sleep(2)
        final = sample(levels[-1] if levels else 0, opened, total_failed)
        final["ladderComplete"] = abort_reason is None
        final["abortReason"] = abort_reason
        emit(final)
        for writer in held:
            writer.close()
        if held:
            await asyncio.sleep(0.5)

    asyncio.run(run())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p):
        p.add_argument("--socks", type=int, required=True)
        p.add_argument("--server-pid", type=int, required=True)
        p.add_argument("--server-log", required=True)
        p.add_argument("--cgroup", default=None)
        p.add_argument("--tag", default=None)

    p = sub.add_parser("churn")
    common(p)
    p.add_argument("--origin-port", type=int, required=True)
    p.add_argument("--concurrency", type=int, nargs="+", required=True)
    p.add_argument("--conns", type=int, default=96)
    p.add_argument("--samples", type=int, default=3)
    p.set_defaults(func=cmd_churn)

    p = sub.add_parser("download")
    common(p)
    p.add_argument("--url", required=True)
    p.add_argument("--expected-bytes", type=int, required=True)
    p.add_argument("--concurrency", type=int, required=True)
    p.add_argument("--samples", type=int, default=2)
    p.set_defaults(func=cmd_download)

    p = sub.add_parser("ladder")
    common(p)
    p.add_argument("--origin-port", type=int, required=True)
    p.add_argument("--levels", required=True)
    p.add_argument("--settle", type=float, default=3.0)
    p.add_argument("--hold", type=float, default=8.0)
    p.set_defaults(func=cmd_ladder)

    args = parser.parse_args()
    global RECORD_TAG
    RECORD_TAG = args.tag
    args.func(args)


if __name__ == "__main__":
    main()
