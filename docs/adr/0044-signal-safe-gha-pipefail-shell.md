# ADR 0044: Signal-safe GitHub Actions pipefail shell

Status: Accepted

## Context

Qualification workflows (`qualification.yml`, `qemu-specialist.yml`,
`frozen-qualification.yml`) used a custom Actions `run` shell:

```text
python3 -c "… subprocess.call(['bash','--noprofile','--norc','-e','-o','pipefail', …], close_fds=True)" {0}
```

That wrapper correctly forced login-free bash, `-e`/`pipefail`, and
`close_fds=True` (native descriptor-isolation at the test-launch boundary).
It incorrectly waited with ``subprocess.call``: on runner cancel or timeout,
Python converted SIGINT into an uncaught ``KeyboardInterrupt`` while blocked in
``Popen.wait``, dumping a traceback into the job log (Frozen run
`37940381711` cancelled QEMU cells). Those stacks drowned the real
fail-closed product or harness verdict and made multi-hour INVALID noise.

## Decision

Replace the bare ``subprocess.call`` one-liner with the checked-in wrapper
`tools/ci/gha_pipefail_shell.py`:

1. Spawn `bash --noprofile --norc -e -o pipefail SCRIPT` with `close_fds=True`
   and a new session.
2. Forward SIGINT/SIGTERM/SIGHUP to the bash process group.
3. On residual `KeyboardInterrupt`, forward SIGINT again and keep waiting —
   never print a traceback.
4. Exit with the child status (`128+signal` when killed by signal).

Workflows MUST reference that file via
`python3 ${{ github.workspace }}/tools/ci/gha_pipefail_shell.py {0}`.
Jobs that run before a full tree checkout (hosted KVM probe) MUST sparse-check
out `tools/ci` first. The file is the sole allowlisted active Python path in `cargo dev repo check`
(`ALLOWED_SCRIPT_PATHS`). Local proof:
`cargo test --manifest-path tools/Cargo.toml -p rr-dev -- gha_shell`.

## Consequences and limits

Cancel/timeout logs stay short and diagnosable; product and Class B harness
failures remain visible. This does not change bash semantics, FD closing, or
fail-closed qualification contracts. It does not claim hosted QEMU is green.
