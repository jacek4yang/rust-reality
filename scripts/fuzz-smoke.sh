#!/usr/bin/env bash
# Deterministic short smoke run for every libFuzzer target.
#
# Each target runs for a fixed wall-clock budget (default 20s, override with
# FUZZ_SMOKE_SECONDS, bounded by FUZZ_SMOKE_MAX_SECONDS, default 30s) against
# its checked-in seed corpus
# (fuzz/seeds/<target>) plus a scratch corpus in a temporary directory, so
# the run is reproducible and checked-in seeds are never mutated. A local
# grown corpus (fuzz/corpus/<target>, gitignored) is also read when present.
# Usage: scripts/fuzz-smoke.sh [target ...]
# Requirements: nightly toolchain with cargo-fuzz installed.

set -Eeuo pipefail

REPO_ROOT="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
    pwd
)"
readonly REPO_ROOT
seconds="${FUZZ_SMOKE_SECONDS:-20}"
max_seconds="${FUZZ_SMOKE_MAX_SECONDS:-30}"
case_timeout="${FUZZ_CASE_TIMEOUT_SECONDS:-5}"
toolchain="${FUZZ_TOOLCHAIN:-nightly}"
max_len="${FUZZ_MAX_LEN:-131072}"
if ! [[ $seconds =~ ^[1-9][0-9]*$ && $max_seconds =~ ^[1-9][0-9]*$ && $case_timeout =~ ^[1-9][0-9]*$ ]]; then
    echo "fuzz-smoke: time budgets must be positive integers" >&2
    exit 2
fi
if (( case_timeout > 30 )); then
    echo "fuzz-smoke: FUZZ_CASE_TIMEOUT_SECONDS must be 1..30" >&2
    exit 2
fi
if ! [[ $max_len =~ ^[1-9][0-9]*$ ]] || (( max_len > 1048576 )); then
    echo "fuzz-smoke: FUZZ_MAX_LEN must be 1..1048576" >&2
    exit 2
fi
if (( seconds > max_seconds )); then
    echo "fuzz-smoke: capping FUZZ_SMOKE_SECONDS at $max_seconds" >&2
    seconds=$max_seconds
fi

target_output="$(python3 "$REPO_ROOT/scripts/fuzz-targets.py")"
mapfile -t all_targets <<<"$target_output"
if (($# > 0)); then
    targets=("$@")
else
    targets=("${all_targets[@]}")
fi

for target in "${targets[@]}"; do
    known=false
    for declared in "${all_targets[@]}"; do
        [[ $target == "$declared" ]] && known=true
    done
    if [[ $known != true ]]; then
        echo "fuzz-smoke: unknown target: $target" >&2
        exit 2
    fi
done

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
output_dir="${FUZZ_OUTPUT_DIR:-$scratch/output}"
if [[ $output_dir != /* ]]; then
    output_dir="$REPO_ROOT/$output_dir"
fi
mkdir -p "$output_dir"

cd "$REPO_ROOT"

status=0
for target in "${targets[@]}"; do
    echo "==> fuzz-smoke: $target (${seconds}s)"
    corpus_args=()
    # libFuzzer writes new units to the first corpus directory; the scratch
    # directory comes first so checked-in seeds and any local grown corpus
    # stay untouched and the run remains reproducible.
    mkdir -p "$scratch/$target"
    corpus_args+=("$scratch/$target")
    if [[ -d "fuzz/seeds/$target" ]]; then
        corpus_args+=("fuzz/seeds/$target")
    fi
    if [[ -d "fuzz/corpus/$target" ]]; then
        corpus_args+=("fuzz/corpus/$target")
    fi
    dict_args=()
    if [[ -f "fuzz/dictionaries/$target.dict" ]]; then
        dict_args+=("-dict=fuzz/dictionaries/$target.dict")
    fi
    if ! cargo "+$toolchain" fuzz run "$target" -- \
        -max_total_time="$seconds" \
        -timeout="$case_timeout" \
        -max_len="$max_len" \
        -rss_limit_mb=2048 \
        -print_final_stats=1 \
        -artifact_prefix="$output_dir/$target-" \
        "${dict_args[@]}" \
        "${corpus_args[@]}" 2>&1 | tee "$output_dir/$target.log"; then
        echo "fuzz-smoke: $target FAILED" >&2
        status=1
    fi
done

exit "$status"
