# ADR 0009: Durable Evidence Identity for Replayable Benchmark Runs

## Status

Accepted. Applies to benchmark evidence provenance only. This decision authorizes no
change to statistical methodology, verdict computation, or any wire format.

## Context

The formal evaluator re-verifies several external inputs against the live filesystem
when it replays recorded evidence. `verify_contract_identity` and
`verify_host_lock_metadata` both require a recorded absolute path to still exist, to be
a canonical regular file, and — for two of the four fields — to hash to the digest
recorded at run time.

This surfaced while building the differential parity harness for the Rust evaluator
migration. Auditing every filesystem-bound identity in the recorded v1.8.0 gate found
four, not one, in two distinct durability classes:

| field | class | re-verified | recoverable |
| --- | --- | --- | --- |
| `hostExclusiveLock.contract` | CONTRACT | path, canonical, **SHA-256** | yes, repository content |
| `hostExclusiveLock.keeperHelper` | EXECUTABLE | path, canonical, **SHA-256** | yes, repository content |
| `hostExclusiveLock.path` + `deviceInode` | LOCK_FILE | path, canonical, **device:inode** | **no** |
| `hostExclusiveLock.keeperExe` | EXECUTABLE | path, canonical | **no**, not repository content |

Both recoverable inputs pointed into `worktrees/v18-final/scripts/`, an ephemeral
detached checkout. Two sibling worktrees had already been pruned for disk pressure
earlier in the same session, so the ability to replay the v1.8.0 release gate was one
routine cleanup away from being lost silently.

The immediate trigger is the `scripts/` removal target: `benchmark-contract.sh` carries
a MERGE disposition, and merging its behaviour into the typed benchmark runner will
necessarily change its digest.

## Decision

**Archived benchmark evidence is made self-contained by immutable content identity.**

1. **An absolute execution path is provenance, not identity.** It records *where* a run
   happened. A SHA-256 records *what* was used. Historical replay resolves external
   inputs by content identity; a temporary checkout path is never the durable root of
   trust.

2. **Recoverable external inputs are archived content-addressed**, under
   `benchmarks/evidence/objects/sha256/<digest>/<descriptive-name>`. The digest is the
   identity; the filename is descriptive only. Objects are stored read-only.

3. **Capture is refused unless the bytes are exact.** The archiving step reads the file
   at the recorded path, computes SHA-256 independently, requires equality with the
   digest recorded by the evidence, copies, then re-verifies the copy. A mismatch aborts
   rather than archiving a substitute from `main` or a reconstruction.

4. **Verification stays mandatory in both modes, and the modes stay distinct.** Fresh
   runs verify the live artifact; archived replay verifies the archived artifact. Both
   require the exact SHA-256 recorded by the evidence. There is no fallback from live to
   archived, so a current benchmark cannot pass because an old archived object happens to
   exist.

5. **Original evidence is never modified.** Durability metadata lives in a separate
   sidecar, `benchmarks/evidence/v180-release-gate-archival-resolution.json`, which
   states plainly that it is not part of the recorded evidence. The original answers
   *what was recorded at release time*; the sidecar answers *how those exact external
   bytes can still be recovered*.

## Consequences, including the part that does not work

Two artifacts are now archived and verified: the benchmark contract
(`817aab78…`) and the host-lock keeper helper (`e117f3d1…`). At capture time the
contract was independently verifiable from two locations — the recorded worktree path
and `main` — which is the strongest provenance obtainable, and both matched.

**Archiving is necessary but not sufficient, and this must not be overstated.** The
binding constraint on replay durability is the lock file: `/tmp/v18-bench.lock` at
device:inode `43:509895`. A device:inode pair is a runtime property of one inode on one
filesystem. It cannot be archived, reconstructed, or content-addressed, and the file is
a zero-byte lock in `/tmp`. Replay of v1.8.0 evidence will stop working at the next
reboot of that host regardless of this decision. `keeperExe` has the same character: a
uv-managed interpreter path, not repository content, and archiving a Python interpreter
is not a defensible response.

So the honest statement of what this decision achieves:

```text
achieved     the two recoverable artifacts are permanently preserved and verifiable,
             independent of any worktree or scripts/ change
not achieved durable replay of v1.8.0 evidence as a whole
blocked by   a device:inode and an interpreter path, neither of which is content
```

Full replay durability requires an **evidence schema change for future runs**, not an
archival fix for past ones: a run should record host-lock provenance without making a
later replay depend on that lock still existing. That is deliberately left to a separate
focused change after evaluator authority transfer completes, so the schema is not
reinterpreted casually mid-migration.

## Alternatives rejected

**Allow historical replay to disappear.** Rejected: the recoverable half of the problem
is cheap to fix and was one `git worktree remove` from permanent loss.

**Make lock-contract verification advisory for archived evidence.** Rejected: it
converts a real integrity check into a comment. An evaluator that accepts evidence whose
contract it cannot verify is not verifying the contract.

**Rewrite the original evidence to point at the archive.** Rejected: it destroys the
record of what was actually recorded at release time, which is the only thing the
archive exists to protect.

**Store the artifact back under `scripts/`.** Rejected: it is evidence data now, not
active repository policy, and it must not re-enter the directory whose removal is a
repository target. Archived bytes that originated from a `.sh` file are not active shell
tooling.

## Effect on the `scripts/` removal target

Unchanged and unblocked. Once the typed replacement reaches parity,
`scripts/benchmark-contract.sh` and `scripts/host-exclusive-lock-keeper.py` may be
merged and deleted per their assigned dispositions; their exact historical bytes survive
as immutable evidence objects. Historical origin does not make archived data active
tooling, so the target remains a `scripts/` directory that does not exist and zero
active shell policy.
