#!/usr/bin/env python3
"""Hold the formal benchmark host lock without leaking its FD to workloads."""

from __future__ import annotations

import argparse
import ctypes
import fcntl
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time


PR_SET_PDEATHSIG = 1
POLL_SECONDS = 0.05
stopping = False


def proc_starttime(pid: int) -> str:
    text = (Path("/proc") / str(pid) / "stat").read_text(encoding="ascii")
    fields = text[text.rfind(") ") + 2 :].split()
    if len(fields) <= 19:
        raise RuntimeError(f"short /proc/{pid}/stat")
    return fields[19]


def parent_is_expected(pid: int, starttime: str) -> bool:
    if os.getppid() != pid:
        return False
    try:
        return proc_starttime(pid) == starttime
    except (FileNotFoundError, ProcessLookupError, PermissionError, RuntimeError):
        return False


def set_parent_death_signal() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0) != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))


def request_stop(_signum: int, _frame: object) -> None:
    global stopping
    stopping = True


def write_ready(path: Path, payload: dict[str, object]) -> None:
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(temporary, flags, 0o600)
    try:
        try:
            data = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
            offset = 0
            while offset < len(data):
                offset += os.write(fd, data[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        os.link(temporary, path, follow_symlinks=False)
        temporary.unlink()
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--parent-pid", type=int, required=True)
    parser.add_argument("--parent-starttime", required=True)
    parser.add_argument("--ready", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.lock.is_absolute() or not args.ready.is_absolute():
        raise RuntimeError("lock and ready paths must be absolute")
    if args.parent_pid <= 1 or not args.parent_starttime.isdecimal():
        raise RuntimeError("invalid parent identity")
    if not parent_is_expected(args.parent_pid, args.parent_starttime):
        raise RuntimeError("parent identity did not match before prctl")

    set_parent_death_signal()
    if not parent_is_expected(args.parent_pid, args.parent_starttime):
        raise RuntimeError("parent identity changed while installing PDEATHSIG")

    flags = os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    lock_fd = os.open(args.lock, flags, 0o600)
    os.set_inheritable(lock_fd, False)
    try:
        opened = os.fstat(lock_fd)
        if not stat.S_ISREG(opened.st_mode):
            raise RuntimeError("host-exclusive lock is not a regular file")
        current = os.lstat(args.lock)
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode):
            raise RuntimeError("host-exclusive lock path is not a regular non-symlink")
        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            raise RuntimeError("host-exclusive lock path changed while opening")

        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("host-exclusive lock is already held") from exc

        current = os.lstat(args.lock)
        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            raise RuntimeError("host-exclusive lock path changed while locking")
        if not parent_is_expected(args.parent_pid, args.parent_starttime):
            raise RuntimeError("parent identity changed before keeper readiness")

        keeper_pid = os.getpid()
        keeper_starttime = proc_starttime(keeper_pid)
        keeper_exe = str(Path("/proc/self/exe").resolve(strict=True))
        write_ready(
            args.ready,
            {
                "schemaVersion": 1,
                "mode": "dedicatedKeeper",
                "lockPath": str(args.lock),
                "lockDevice": opened.st_dev,
                "lockInode": opened.st_ino,
                "lockDeviceInode": f"{opened.st_dev}:{opened.st_ino}",
                "lockFd": lock_fd,
                "keeperPid": keeper_pid,
                "keeperStarttime": keeper_starttime,
                "keeperExe": keeper_exe,
                "parentPid": args.parent_pid,
                "parentStarttime": args.parent_starttime,
            },
        )

        signal.signal(signal.SIGTERM, request_stop)
        signal.signal(signal.SIGINT, request_stop)
        while not stopping and parent_is_expected(args.parent_pid, args.parent_starttime):
            time.sleep(POLL_SECONDS)
    finally:
        os.close(lock_fd)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"host-exclusive lock keeper: {exc}", file=sys.stderr)
        raise SystemExit(2)
