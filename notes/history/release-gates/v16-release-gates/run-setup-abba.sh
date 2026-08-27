#!/usr/bin/env bash
# run-setup-abba.sh <round> — formal setup-latency/CPU A/B (release gate).
# 12 ABBA blocks x 4 slots x {1,8,32,128} x 3 samples x 96 connections,
# MEASURE_MODE=perf, ports 61000+ (above the ephemeral range 32768-60999).
set -Eeuo pipefail
round=${1:?round number required}
source "$(dirname -- "${BASH_SOURCE[0]}")/env-common.sh"
cd "$REPOSITORY"
export RUN_ID="gates-setup-abba-r${round}-v16"
export OUT_DIR="$GATES/setup-abba-r${round}"
export PORT_BASE=61000
export BLOCKS=12
export SAMPLES=3
export CONNS=96
export CONCURRENCIES="1 8 32 128"
export MEASURE_MODE=perf
export ABBA_START=${ABBA_START:-baseline}
exec scripts/benchmark-setup-rate.sh
