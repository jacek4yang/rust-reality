# ADR 0044: Signal-safe GitHub Actions pipefail shell

Status: Accepted

## Context

Qualification workflows (`qualification.yml`, `qemu-specialist.yml`,
`frozen-qualification.yml`) previously used a custom Actions `run` shell:

```text
python3 -c "… subprocess.call(['bash','--noprofile','--norc','-e','-o','pipefail', …], close_fds=True)" {0}
```

and briefly a checked-in `tools/ci/gha_pipefail_shell.py` that still waited in
Python. Both forms forced login-free bash and `-e`/`pipefail`. They incorrectly
coupled cancel/timeout to Python's `SIGINT` → `KeyboardInterrupt` path while
blocked in `Popen.wait`, dumping tracebacks into job logs (Frozen run
`37940381711`). Those stacks drowned fail-closed product or harness verdicts.

The repository already migrated ordinary CI scripts into typed `cargo-dev`
(`rr-dev`) commands. A Python Actions shell was the remaining exception and
reintroduced the exact failure mode the migration was meant to end.

## Decision

1. **Actions `defaults.run.shell` is bash-native** (no Python):

   ```text
   bash --noprofile --norc -e -o pipefail {0}
   ```

   Relative argv only — `${{ github.workspace }}` is illegal in that field.
   Cancel/timeout is handled by the runner and bash; there is no Python frame
   to convert SIGINT into a traceback.

2. **Typed twin is `cargo-dev ci gha-shell SCRIPT`** in `tools/rr-dev`. It
   spawns the same bash flags for local proof and explicit script runs. Policy
   tests and `cargo-dev repo check` require the three qualification workflows to
   keep the bash-native shell and forbid `gha_pipefail_shell.py` /
   `subprocess.call([...bash...])`.

3. **`tools/ci/gha_pipefail_shell.py` is removed.** `ALLOWED_SCRIPT_PATHS` stays
   empty; active repository-owned Python/shell scripts remain forbidden by
   `cargo-dev repo check`.

4. **Descriptor isolation for the product under test** stays where ownership is
   asserted (qualification receipts / unexpected-FD fail-closed rules). The
   Actions shell no longer pretends to be that boundary via Python
   `close_fds=True`. `rr-dev` forbids `unsafe_code`, so a Rust `pre_exec`
   close-all-fds path is not the vehicle for this ADR.

Hosted KVM capability probes do not sparse-check out `tools/ci` solely to
obtain a shell wrapper; bash is on the runner image.

## Consequences and limits

Cancel/timeout logs stay short and diagnosable; product and Class B harness
failures remain visible. This does not change bash `-e`/`pipefail` semantics or
fail-closed qualification contracts. It does not claim hosted QEMU is green.
Local proof: `cargo test --manifest-path tools/Cargo.toml -p rr-dev -- ci::`.
