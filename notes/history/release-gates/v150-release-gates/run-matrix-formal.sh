#!/usr/bin/env bash
# run-matrix-formal.sh <round> — formal throughput matrix, concurrency-1 cells.
#
# The formal matrix contract refuses c32 on this host: at max_concurrency=32
# the required fs.pipe-user-pages-soft budget is ~344k pages while the host
# has 16384 and writing that sysctl is forbidden.  With CONCURRENCIES="1"
# (max_concurrency=1) the required budget is 10752 pages, which fits, so the
# c1 cells run formally with 24 samples per implementation (12 ABBA blocks,
# the evaluator minimum).  c32 cells are covered by run-matrix.sh
# (exploratory ABBA, 2 rounds, reversed ABBA_START on round 2).
set -Eeuo pipefail
round=${1:?round number required}
source "$(dirname -- "${BASH_SOURCE[0]}")/env-common.sh"
cd "$REPOSITORY"
export RUN_ID="gates-matrix-formal-r${round}-47a7151"
export OUT_DIR="$GATES/matrix-formal-r${round}"
export PORT_BASE=61500
export PAYLOADS="1 32"
export CONCURRENCIES="1"
export LARGE_PAYLOAD_MIB=32
export LARGE_CONCURRENCIES="1"
export SAMPLES=24
export SAMPLES_LARGE=24
export INTEGRITY_MIB=1024
export RUST_LOG_LEVEL=warn
export ABBA_START=${ABBA_START:-baseline}
exec scripts/benchmark-matrix.sh
