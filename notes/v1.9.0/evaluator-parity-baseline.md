# Evaluator authority transfer: parity baseline and a blocking dependency

Status: **parity baseline established; one previously unknown dependency found that
constrains the `scripts/` removal target.** The Python evaluator remains
authoritative. No caller has been switched.

## The replay baseline

The recorded v1.8.0 gate is fully replayable, which is the prerequisite for any
differential parity work:

```bash
python3 scripts/evaluate-release-performance.py \
  --manifest $S/artifacts/v180-release-gate/gates/evaluator-manifest-r01.json \
  --output /tmp/replay-old.json
# exit 0, status COMPLETE, verdict PASS, 32 protected metrics
```

Comparing that fresh replay against the archived `evaluation-r01.json` field by field
yields **exactly one difference**:

```text
.evaluator.path
  recorded: …/worktrees/v18-final/scripts/evaluate-release-performance.py
  replayed: …/worktrees/rrdev/scripts/evaluate-release-performance.py
```

Two conclusions follow, and the second corrects an assumption worth stating
explicitly.

**The evaluator is bit-deterministic on this evidence.** Every metric, p-value,
adjusted p-value, classification, bootstrap interval and the global verdict reproduce
exactly. That is what makes byte-level parity a realistic acceptance gate rather than
an aspiration.

**The allowed-difference set is two fields, not one.** The migration plan anticipated
`evaluator.sha256` as the sole legitimate difference. In fact `evaluator.path` also
differs, and it demonstrably already differs *between two Python runs* from different
checkouts — so it is not a Rust-specific exception at all. The parity harness must
normalise both:

```text
allowed differences: evaluator.path, evaluator.sha256
required: byte differences after normalising those two = 0
```

Recording this now prevents a later temptation to widen the exception list once a diff
appears.

## The dependency that constrains `scripts/` removal

`verify_contract_identity` does not merely record the host-exclusive-lock contract
identity — it **re-verifies it against the live filesystem**:

```python
path = Path(value["path"])
require(path.is_file() and not path.is_symlink()
        and str(path.resolve()) == value["path"]
        and sha256_file(path) == value["sha256"],
        f"{context}: lock contract path/SHA-256 mismatch")
```

The recorded v1.8.0 evidence names:

```text
hostExclusiveLock.contract.path
  /home/jacek/work/kimi-rust-reality-performance/worktrees/v18-final/scripts/benchmark-contract.sh
hostExclusiveLock.contract.sha256
  817aab781f3db676b574645d90e0d0a2c49143cb37a5cc77517eaa0b739eed14
```

That file exists today, which is *why* the replay above succeeds. So:

**Recorded benchmark evidence embeds an absolute path and digest of a
`scripts/` file, and replaying that evidence requires the file to still be present
and unchanged.**

Consequences, in order of importance:

1. **Historical replay already rests on an ephemeral worktree.** The recorded path
   points into `worktrees/v18-final/`, a detached checkout, not the tracked `scripts/`
   in `main`. Worktrees are routinely pruned — two were removed earlier for disk
   pressure. So the ability to replay v1.8.0 evidence is fragile *independently* of any
   `scripts/` decision, and will break silently the first time that worktree is removed.
2. **The `scripts/` removal target needs an explicit answer here.** Deleting
   `benchmark-contract.sh` does not corrupt the archived report, but it does end the
   ability to re-derive it. The disposition assigned in the inventory is MERGE, meaning
   its behaviour moves into the typed `BenchmarkRunner`; that migration will change its
   digest and therefore invalidate the recorded lock identity for future replays.
3. **This is a pre-existing property, not something the migration introduced.** It is
   recorded here because it was found while building the parity gate, and because
   discovering it *after* deleting the file would have been considerably worse.

No decision is taken here. Three defensible options exist and the choice is a
methodology question rather than a migration one:

- accept that replay of pre-migration evidence ends when the contract file changes, and
  rely on the archived report plus its digest as the durable record;
- copy the referenced contract files into the evidence archive so a run stays
  self-contained, which changes what "evidence" means and is a schema decision;
- treat lock-contract verification as advisory for archived evidence while keeping it
  mandatory for fresh runs, which weakens a real integrity check and should not be done
  casually.

## What remains for authority transfer

Unchanged and unstarted:

```text
evidence loading        transcribe verify_files, evaluate_pair_run, evaluate_matrix
report assembly         the inputs array, method block, protectedMetrics
cargo dev perf evaluate CLI with the captured contract
parity harness          old vs new, classified difference types
acceptance              historical_verdict_changes = 0
caller switch           then delete the Python evaluator
```

The evidence-loading layer is the bulk of it: `evaluate_pair_run` and
`evaluate_matrix` are dense validation code whose every rule has to be transcribed
rather than approximated, and the `inputs` array in the report is derived from that
same validation, so the two cannot be separated.

## Epistemic status

```text
measured    recorded v1.8.0 evidence replays: exit 0, PASS, 32 metrics
measured    fresh replay differs from the archive in exactly one field, evaluator.path
established the allowed-difference set is evaluator.path plus evaluator.sha256
established byte-level parity is achievable, so it stays the acceptance gate
measured    verify_contract_identity re-verifies a scripts/ file against the filesystem
established historical replay depends on a file inside an ephemeral worktree
open        the durability policy for lock-contract identity in archived evidence
not started evidence loading, report assembly, CLI, parity harness, caller switch
```
