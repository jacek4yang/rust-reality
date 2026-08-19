#!/usr/bin/env bash
# run-fallback-abba.sh <round> — formal fallback-path A/B (release gate).
# 12 ABBA blocks x 4 slots x {1,4,32} x 3 samples of 32 MiB requests,
# MEASURE_MODE=perf, ports 61300+ (above the ephemeral range).
set -Eeuo pipefail
round=${1:?round number required}
source "$(dirname -- "${BASH_SOURCE[0]}")/env-common.sh"
cd "$REPOSITORY"
export RUN_ID="gates-fallback-abba-r${round}-v151"
export OUT_DIR="$GATES/fallback-abba-r${round}"
export PORT_BASE=61300
export BLOCKS=12
export SAMPLES=3
export CONCURRENCIES="1 4 32"
export PAYLOAD_MIB=32
export MEASURE_MODE=perf
export ABBA_START=${ABBA_START:-baseline}
exec scripts/benchmark-fallback-ab.sh
