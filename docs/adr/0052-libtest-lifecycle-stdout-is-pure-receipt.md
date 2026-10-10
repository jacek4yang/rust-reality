# ADR 0052: Libtest lifecycle stdout is a pure receipt

Status: Accepted

## Context

Frozen run `38072511040` on `180ad50` completed all four QEMU cells and merge
evaluation (ADR 0051), then failed **Frozen native lifecycle receipts** only.
`cargo test --lib --locked` exited 0, but offline `test_receipt::verify`
reported `unexpected libtest output record` for every deterministic family
(`cancellation`, `descriptor-permit-ownership`, `generation-retirement`,
`half-close`, `inactivity`, `pipe-pool-reuse`, `replay-expiry-reuse`,
`write-stall`).

Retained `required-lifecycle/output.json` interleaved pretty-printed generator
JSON (`uuids` / `privateKey` / `shortIds` / `psk`) between libtest lines. The
source is `cli::commands::tests::every_generator_emits_only_what_was_asked_for`,
which called `run_generate` and wrote JSON to the process stdout shared with
libtest. The pure-libtest parser intentionally rejects any non-header /
non-`test …` / non-summary line. Class B harness stdout hygiene, not Class A
product failure. Exact-head Native PASS does not exercise this Frozen receipt
path. Historical `180ad50` / `38072511040` verdict remains immutable.

## Decision

1. Keep `test_receipt::parse` fail-closed: do not skip arbitrary stdout lines.
2. CLI generator unit tests MUST write through an injected `Write` sink
   (`generate_into`); production `run_generate` still uses stdout.
3. Library tests that exercise operator-facing emit paths MUST NOT print
   payloads to real stdout when they run under `cargo test --lib`.
4. Add a synthetic receipt regression that JSON pollution fails `parse`.

## Consequences and limits

Frozen lifecycle can Pass once libtest stdout is pure again. This does not
loosen ignored/missing/filtered case rules, does not reinterpret stderr
logging as a receipt, and does not authorize sleep or Python CI shells.
