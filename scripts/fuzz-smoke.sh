#!/usr/bin/env bash
# Deterministic short smoke run for every libFuzzer target.
#
# Each target runs for a fixed wall-clock budget (default 20s, override with
# FUZZ_SMOKE_SECONDS, hard cap 30s) against its checked-in seed corpus
# (fuzz/seeds/<target>) plus a scratch corpus in a temporary directory, so
# the run is reproducible and checked-in seeds are never mutated. A local
# grown corpus (fuzz/corpus/<target>, gitignored) is also read when present.
# Callable from CI later; deliberately not wired into .github/workflows here
# (CI wiring is owned separately).
#
# Usage: scripts/fuzz-smoke.sh [target ...]
# Requirements: nightly toolchain with cargo-fuzz installed.

set -Eeuo pipefail

readonly REPO_ROOT="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
    pwd
)"
readonly ALL_TARGETS=(
    wire_parsers
    vision_decoder
    vision_transitions
    handoff_header
    handoff_blob
    handoff_open_transfer
    handoff_round_trip
    cover_flight
    tls13_record
    transcript_diff
    config_json
    config_diagnostic
    nxr_round_trip
)

seconds="${FUZZ_SMOKE_SECONDS:-20}"
if (( seconds > 30 )); then
    echo "fuzz-smoke: capping FUZZ_SMOKE_SECONDS at 30" >&2
    seconds=30
fi

if (($# > 0)); then
    targets=("$@")
else
    targets=("${ALL_TARGETS[@]}")
fi

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

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
    if ! cargo +nightly fuzz run "$target" -- \
        -max_total_time="$seconds" \
        -rss_limit_mb=2048 \
        -print_final_stats=1 \
        "${dict_args[@]}" \
        "${corpus_args[@]}"; then
        echo "fuzz-smoke: $target FAILED" >&2
        status=1
    fi
done

exit "$status"
