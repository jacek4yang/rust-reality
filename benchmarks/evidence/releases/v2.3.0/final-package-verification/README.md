# Final package evidence at 9265a6b

The immutable candidate source is
`9265a6b919691e5f377cd5f85ef439415dc7136e`. These are observations of that
candidate, not a claim that a GitHub Release has been published.

- `packages.json`: all four Frozen package archives, ELF identities, source
  contents and native execution receipts independently verified.
- `native-artifact.json`: exact-source Native run 41242923588, artifact ZIP
  identity and verification of all 3,132 checksummed members. Its publication
  inventory identifies retained evidence and exclusions.
- `../client-cli-final-package/`: 64 production-client ClientHello captures,
  32 per profile, independently compared to the frozen browser corpus. Chrome
  includes both omitted and explicit selection. This stops before ServerHello;
  it does not establish authenticated-session success by itself.
- `../client-memory-final-package/`: eight process runs, 128 persistent
  connections per run, 3,072 verified one-MiB transfers and exact descriptor
  recovery in all runs. Anonymous memory is a snapshot observation, not an
  allocation count, timing verdict or long-term leak test.
- `../client-data-final-package/`: complete fixed-frequency 20-block ABBA
  campaign against the identity-qualified historical d72 GNU candidate package.
  All 8,000 data batches and 1,600 setup batches are retained. The result is
  **UNRESOLVED**: 55 metrics pass, while direct upload at concurrency 1 has a
  CPU ratio median of 1.0010455 and a 95% interval of
  [0.9829852, 1.0117158], crossing the 1.01 upper bound. It is neither a pass
  nor a statistically established regression. Original observations are not
  pooled with development-binary campaigns or discarded for a later attempt.

The GNU candidate executable SHA-256 is
`ee7e0092849a6e8b35fe1ac31544bad9d254d7a78cef40d8c02818e1588881ed`.
The historical GNU baseline executable SHA-256 is
`610746b002c7837d4fdffab3c63360ea35647ef556922337d47a51b548d68f72`.
They have matching compiler, CPU target and default features. Rates include
connection setup on the recorded loopback hardware and are not WAN throughput
claims. CPU policies were restored exactly after collection. Raw private
configuration, credentials and process logs are excluded.

Frozen run 41242900924 attempt 1 ended cancelled: the Handoff ordinary TCP
job exceeded its two-hour limit. The other seven VM cells and four native
package jobs passed, but the two dependent aggregate jobs were skipped.
`frozen-attempt1-annotations.json` retains GitHub's timeout annotation;
`frozen-attempt1-terminal.json` retains exact-source job outcomes. The terminal
job log was unavailable (HTTP 404 / BlobNotFound). This does not establish a
product root cause or a passing aggregate. A same-source failed-job rerun leaves
all deadlines and contract checks unchanged.

The independent 20-block / 15-sample concurrency-1 precision campaign also
remains **UNRESOLVED**. Its 6,000 data batches represent 7,200 verified data
requests; 1,200 setup batches are retained. Thirteen metrics pass. Direct
upload CPU has median 1.0108742 and 95% interval [0.9878449, 1.0152365], still
crossing the unchanged 1.01 ceiling. CPU policies were restored exactly.
`../client-data-final-precision-20x15/` preserves every slot. No further
acceptance retry by increasing sample count is authorized by this plan; the
next step is causal profiling or a demonstrated measurement defect. Neither
unresolved campaign establishes a passing release performance claim.
