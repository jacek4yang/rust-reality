#!/usr/bin/env python3
# Copyright (c) rust-reality contributors.
"""GitHub Actions custom `run` shell: bash -euo pipefail without cancel noise.

Why this exists
---------------
Workflows previously used::

    python3 -c "… subprocess.call(['bash', …], close_fds=True) …" {0}

``subprocess.call`` waits in a way that turns runner cancel/timeout SIGINT into
an uncaught ``KeyboardInterrupt`` traceback (Frozen run 37940381711 cancelled
QEMU cells). Those stacks drown the real product/harness failure that mattered.

This wrapper keeps the intentional properties of that shell:

- ``bash --noprofile --norc -e -o pipefail`` for every ``run:`` script;
- ``close_fds=True`` so runner-owned descriptors are not inherited at the
  test-launch boundary (native qualification contract);
- forwards SIGINT/SIGTERM/(SIGHUP) to the bash process group;
- never prints a KeyboardInterrupt traceback; exits with the child status
  (128+signal when the process group dies by signal).

Workflows MUST invoke this file (not reintroduce bare ``subprocess.call``).
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from collections.abc import Sequence


def normalize_returncode(returncode: int | None) -> int:
    """Map ``Popen.wait`` status to a shell-style exit code."""
    if returncode is None:
        return 1
    if returncode < 0:
        return 128 + (-returncode)
    return returncode


def forward_signal(proc: subprocess.Popen[bytes], signum: int) -> None:
    """Deliver ``signum`` to the bash process group if it is still running."""
    try:
        if proc.poll() is None:
            os.killpg(proc.pid, signum)
    except ProcessLookupError:
        return


def run_script(script: str) -> int:
    """Execute one Actions ``run`` script path; return the process exit code."""
    proc = subprocess.Popen(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", script],
        close_fds=True,
        start_new_session=True,
    )

    def _handler(signum: int, _frame: object | None) -> None:
        forward_signal(proc, signum)

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, _handler)

    while True:
        try:
            return normalize_returncode(proc.wait())
        except KeyboardInterrupt:
            # SIGINT should already have been forwarded; never dump a traceback.
            forward_signal(proc, signal.SIGINT)


def main(argv: Sequence[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write("usage: gha_pipefail_shell.py SCRIPT\n")
        return 2
    return run_script(argv[1])


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
