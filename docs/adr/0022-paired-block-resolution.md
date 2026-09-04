# ADR 0022: A paired benchmark interval must not outrun its block count

## Status

Accepted.

## Context

The paired suites (`setup-rate`, `fallback`) compare two builds in balanced ABBA
blocks. Each block contributes one median per side, their ratio is the block's
statistic, and the cell reports the median of those ratios with a deterministic
95% block bootstrap. `--blocks` defaulted to **3**, which was also the minimum
the suites accepted.

The bootstrap resamples *blocks*. With three of them there are 27 distinct
resamples, so the 2.5th and 97.5th percentiles land on the extremes of a
three-element set: the interval is approximately the range of the three observed
ratios. That is not an arithmetic error. It is an interval that carries no
information about the sampling distribution while presenting itself, under the
key `bootstrap95`, as a confidence bound.

Issue #228 found this the expensive way. A three-block paired run comparing two
rust-reality binaries reported

```
serverCpuPerConnection  median 1.0218  bootstrap95 [1.0158, 1.0256]
```

— ±0.5%, excluding 1.0, all three blocks agreeing in sign, which reads as a
measurable end-to-end regression. The same configuration **with the same binary
on both sides** then reported `median 1.0064  bootstrap95 [1.0058, 1.0139]`: an
identical artifact "regressing" by 0.6%, with an interval that also excluded
1.0.

The repository already had the right answer for its formal gate and had not
applied it here. `perf::stats::MIN_EXACT_BLOCKS` requires 12 through 16 complete
blocks before the release evaluator will render a verdict, and the evaluator
treats the bootstrap as an effect interval rather than a significance test.
`bench run` produces the same kind of evidence, for the same readers, and was
publishing it under a weaker rule and a stronger-looking name.

## Evidence

A same-binary A/A ladder on the laboratory host — i5-1240P, four P-cores pinned
with `taskset -c 0,2,4,6`, `--measure-mode schedstat`, one frozen ELF from
`81a204d0a9cb85d859dea51b70ece7dda5e0de62` on both sides of every run, 20 runs
over 37 minutes — measured what the default was worth on the primary acceptance
metric, `serverCpuPerConnection`:

| blocks | A/A runs | reported an interval excluding 1.0 | median ratio | within-run block sd | reported interval width |
| ---: | ---: | ---: | --- | --- | --- |
| 3 | 14 | **4** | 0.9968 – 1.0107 | 0.15% – 1.04% | 0.27% – 2.00% |
| 12 | 4 | **0** | 0.9987 – 1.0019 | 0.39% – 0.71% | 0.57% – 0.79% |
| 20 | 2 | **0** | 1.0032 – 1.0043 | 2.35% – 2.37% | 0.91% – 1.51% |

Four identical-binary runs in fourteen were declared significantly different at
three blocks, against a nominal 5%. Six in six were not, at twelve and twenty.

The width column is the sharper finding. At three blocks the reported width is
uncorrelated with the run's real uncertainty — it is the luck of three draws, so
a run can report ±0.13% and exclude 1.0 while an identical run reports ±1%. At
twelve it settles near 0.7% across every run and tracks the dispersion it came
from. Subsampling each long run's own blocks and re-running the harness's exact
estimator — CPython-compatible generator, same seeds, same percentile indices —
reproduces the three-block figure at 28.2% against the 28.6% measured directly.
That agreement is a consistency check on the mechanism at three blocks; it is
*not* offered as a calibrated error rate at larger counts, because subsampling
and then bootstrapping is not the same operation as running that many blocks.

Two secondary results matter for reading past and future evidence:

- **The floor is a property of the topology, not of the suite.** On four pinned
  P-cores the within-run per-block sd is 0.39–0.71% for a twelve-block run,
  agreeing with the independently recorded 0.54% A/A floor for that topology.
  #228's control observed a ±4–5% block spread; that number describes a noisier
  arrangement and must not be inherited as this measurement's floor.
- **The two twenty-block runs picked up sporadic host interference** — four
  individual blocks whose baseline slot cost 316–324 µs/connection against a
  ~305 µs run median — which raised their block sd to 2.4%. The estimator
  responded correctly: it widened the interval and still declined to claim a
  difference. That is the behaviour the three-block configuration cannot
  produce, because it has no blocks left over to notice with.
- There is **no cold-first-block effect**: across all 20 runs the first block's
  mean ratio is 0.9993 against 1.0007 for later blocks. The per-slot warm-up is
  doing its job, so the block count is the whole defect.

## Decision

`bench run`'s paired suites adopt the evaluator's floor as their own.

1. `--blocks` defaults to `aggregate::RESOLVING_BLOCKS`, defined as
   `perf::stats::MIN_EXACT_BLOCKS`. One number, one justification; a second,
   softer benchmark-only threshold would be a new thing to keep true.
2. Below that count a cell publishes **`bootstrap95Unresolved`** together with a
   `resolutionCaveat` naming what the interval is not. The interval is renamed
   rather than deleted, because deleting it would hide the run's own dispersion,
   while leaving it called `bootstrap95` invites the exact reading that produced
   this ADR — including by a future reader who greps for the key.
3. Every cell carries `blockCount` and `blockRatioSpread` (observed minimum,
   maximum, sample standard deviation of the per-block ratios). The spread, not
   the interval, is what says whether a sub-percent median is distinguishable
   from the run's own noise.
4. The summary carries `runKind`, `control` when both sides are the same
   artifact and `comparison` otherwise, so a same-binary control identifies
   itself in the archive instead of being reconstructed from two digests.

A characterization run may still pass a lower `--blocks`. Its artifact will say
what it is.

## Consequences

- The default `setup-rate` run costs about three and a half minutes on the
  laboratory host instead of about 56 seconds. That is the price of the
  interval meaning something, and it is small.
- Recorded three-block intervals in existing evidence documents keep their
  historical value as *what was reported*, and lose their standing as
  resolution. Any conclusion that rested on one is re-derivable only from its
  retained per-block ratios.
- The demonstrated floor bounds what may be claimed. At twelve blocks the A/A
  median moves within about ±0.2% on this host, so an effect below that is not
  resolvable here regardless of how the interval is presented. The X25519
  whole-product candidate's expected −0.06% of server CPU (#225) sits about
  three times below that floor; its honest verdict is
  `ACCEPTED_ARCHITECTURAL_CONSOLIDATION_PERFORMANCE_NEUTRAL`, justified by the
  measured floor rather than by an absence of signal.

## Rejected alternatives

- **A new statistical framework for `bench run`.** The evaluator's exact
  sign-flip test with Holm adjustment already exists and already has a block
  requirement. Building a second, parallel apparatus for the exploratory harness
  would create two authorities to keep consistent for no measured gain.
- **Deleting the interval below the floor.** It removes information the reader
  needs — the dispersion of the blocks that were actually run — and produces an
  artifact that is silent rather than honest.
- **Keeping `bootstrap95` and adding a caveat field beside it.** The failure
  mode being fixed is a reader, or a script, taking `bootstrap95` at face value.
  A sibling field that has to be noticed does not fix that.
- **Choosing eight blocks**, the count at which #228's own control was run.
  Nothing in the ladder distinguishes eight from twelve — no A/A run at either
  count produced a false exclusion — so eight would be a second floor with a
  weaker justification than the one the evaluator already enforces, bought for
  about ninety seconds per run.

## Revisit condition

Re-open if the release evaluator's `MIN_EXACT_BLOCKS` changes, if a host is
added whose A/A floor is materially different from 0.56% per block, or if a
paired suite acquires a metric whose per-block variance is small enough that
fewer blocks demonstrably reach the nominal error rate. Re-measure with the same
A/A ladder before changing the number; the ladder is the evidence, not the
constant.
