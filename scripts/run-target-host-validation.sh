#!/usr/bin/env bash
# Target-host validation for the rust-reality data plane.
#
# Runs every available gate in order and records a transcript. Privileged
# gates run the built test binaries under sudo (never `sudo cargo`, which
# pollutes target/ with root-owned files).
#
# Usage:
#   scripts/run-target-host-validation.sh [--skip-benchmarks] [--skip-privileged]
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
skip_privileged=0
for argument in "$@"; do
    case "$argument" in
        --skip-benchmarks) skip_benchmarks=1 ;;
        --skip-privileged) skip_privileged=1 ;;
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

if (( skip_privileged == 0 )); then
    if sudo -n true 2>/dev/null; then
        record "build-privileged-tests" \
            cargo test -p rr-linux --test sockhash_privileged --no-run || failures=$((failures + 1))
        record "build-runtime-tests" \
            cargo test --test sockhash_runtime --no-run || failures=$((failures + 1))
        sockhash_bin=$(ls -t target/debug/deps/sockhash_privileged-* 2>/dev/null | grep -v '\.' | head -1 || true)
        runtime_bin=$(ls -t target/debug/deps/sockhash_runtime-* 2>/dev/null | grep -v '\.' | head -1 || true)
        if [[ -n $sockhash_bin ]]; then
            record "sudo-sockhash-privileged" \
                sudo -n "$sockhash_bin" --ignored --test-threads=1 || failures=$((failures + 1))
        fi
        if [[ -n $runtime_bin ]]; then
            record "sudo-sockhash-runtime" \
                sudo -n "$runtime_bin" --ignored --test-threads=1 || failures=$((failures + 1))
        fi
    else
        step "privileged: SKIPPED (passwordless sudo unavailable)"
    fi
fi

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
