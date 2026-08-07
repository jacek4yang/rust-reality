#!/usr/bin/env bash
# Target-host validation for the rust-reality data plane.
#
# Runs every available gate in order and records a transcript.
#
# Usage:
#   scripts/run-target-host-validation.sh [--skip-benchmarks]
#
# Environment:
#   XRAY_BIN                 Xray reference binary (default: xray from PATH)
#   RUST_REALITY_BASELINE_BIN  baseline binary for matrix runs (optional)
#   OUT_DIR                  transcript/output directory
#                            (default: diagnostics/validation-<UTC>)
set -Eeuo pipefail

repository=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository"

skip_benchmarks=0
for argument in "$@"; do
    case "$argument" in
        --skip-benchmarks) skip_benchmarks=1 ;;
        *) echo "unknown argument: $argument" >&2; exit 2 ;;
    esac
done

out_dir=${OUT_DIR:-diagnostics/validation-$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$out_dir"
transcript="$out_dir/transcript.log"

step() {
    echo "==> $*" | tee -a "$transcript"
}

record() {
    local name=$1
    shift
    step "$name"
    if "$@" >>"$transcript" 2>&1; then
        echo "PASS $name" | tee -a "$transcript"
    else
        echo "FAIL $name (see transcript)" | tee -a "$transcript"
        return 1
    fi
}

failures=0

record "fmt" cargo fmt --check || failures=$((failures + 1))
record "clippy" cargo clippy --workspace --all-targets -- -D warnings || failures=$((failures + 1))
record "test-workspace" cargo test --workspace || failures=$((failures + 1))
record "test-workspace-release" cargo test --workspace --release || failures=$((failures + 1))
record "test-doc" cargo test --doc --workspace || failures=$((failures + 1))
if command -v cargo-nextest >/dev/null 2>&1; then
    record "nextest" cargo nextest run --workspace || failures=$((failures + 1))
else
    step "nextest: SKIPPED (not installed)"
fi
record "deny" cargo deny check || failures=$((failures + 1))
if cargo audit --version >/dev/null 2>&1; then
    record "audit" cargo audit || failures=$((failures + 1))
else
    step "audit: SKIPPED (not installed)"
fi
record "benches-compile" cargo bench --workspace --no-run || failures=$((failures + 1))
record "fuzz-compile" cargo check --manifest-path fuzz/Cargo.toml || failures=$((failures + 1))
record "docs-links" python3 scripts/check-docs.py || failures=$((failures + 1))

if (( skip_benchmarks == 0 )); then
    xray=${XRAY_BIN:-xray}
    if command -v "$xray" >/dev/null 2>&1; then
        record "xray-interop" env XRAY_BIN="$xray" scripts/test-xray-interop.sh || failures=$((failures + 1))
        if [[ -n ${RUST_REALITY_BASELINE_BIN:-} ]]; then
            record "benchmark-matrix" env \
                XRAY_BIN="$xray" \
                RUST_REALITY_BASELINE_BIN="$RUST_REALITY_BASELINE_BIN" \
                OUT_DIR="$out_dir/matrix" \
                scripts/benchmark-matrix.sh || failures=$((failures + 1))
        else
            step "benchmark-matrix: SKIPPED (RUST_REALITY_BASELINE_BIN unset)"
        fi
    else
        step "interop/matrix: SKIPPED (no Xray binary; set XRAY_BIN)"
    fi
fi

step "done: $failures failing gate(s); transcript at $transcript"
exit "$failures"
