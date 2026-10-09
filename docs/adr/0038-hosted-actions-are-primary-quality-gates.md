# ADR 0038: Hosted Actions are the primary quality gates

Status: Accepted

## Context

Contributor environments differ in loopback UDP, sysfs, namespace and process
capabilities. A development sandbox can bind a socket yet deny its send syscall.
Requiring the same complete suite to pass there and on a suitable Linux runner
confuses environment availability with product correctness. Removing a test to
fit that sandbox would reduce coverage instead of validating the product.

## Decision

At the owner's explicit direction, GitHub Actions is the primary merge-quality
authority. Keep `cargo dev check --all` unchanged, including both workspaces,
all declared features/profiles and every existing stage. Exact-head CI and
Security must succeed. Required release, resource, interoperability and package
qualification remain additional obligations; a green subset is insufficient.

Run focused/slice-level tests locally during development and the full gate
where feasible. When a demonstrated sandbox capability restriction prevents
local execution, retain the original failure and a narrow capability reproducer,
and require the identical affected tests and full canonical gate to pass for
the exact candidate in GitHub Actions. Record source identity, commands, stage
outcomes and hosted run links in the PR. Missing, skipped, cancelled, or old-head
checks do not satisfy this requirement. Never relabel a failed local run PASS.

This exception does not cover unexplained failures or a defect in a supported
deployment environment. Classify and fix those even if a different environment
passes. Do not weaken assertions, shorten workloads, omit a workspace, loosen
thresholds or alter production architecture to accommodate a development sandbox.

The historical stability-receipt name `local-full-gate` denotes execution of
the canonical command in the qualification environment, which may itself be a
GitHub runner. It is not an exemption from executing and retaining that command.

## Consequences

Local feedback remains useful and honest while reproducible hosted execution
provides the merge gate. CI is not proof of zero bugs; declared platform/fault
coverage and retained failures remain reviewable. Repository authorization,
release publication and production deployment still need their own permissions.
No branch-protection setting or workflow test command is weakened by this policy.

## References

- [Engineering constitution](../../AGENTS.md)
- [Development workflow](../en/development/development-workflow.md)
- [Qualification responsibilities](0036-separate-native-and-qemu-qualification.md)
