#!/usr/bin/env bash
# run-matrix.sh <round> — throughput A/B matrix (release gate).
# Same cell plan as worker C's baseline-matrix-r01 (PAYLOADS "1 32",
# CONCURRENCIES "1 32", SAMPLES=5, INTEGRITY_MIB=1024) but baseline-binary vs
# release-candidate.  EXPLORATORY=1 because the formal matrix contract demands
# fs.pipe-user-pages-soft >= ~344k pages at c32 and writing that sysctl is
# forbidden on this host; MANAGE_PIPE_USER_PAGES_SOFT=0 is pinned regardless.
# Round 2 should run with ABBA_START=final to balance cross-round drift.
set -Eeuo pipefail
round=${1:?round number required}
source "$(dirname -- "${BASH_SOURCE[0]}")/env-common.sh"
cd "$REPOSITORY"
export EXPLORATORY=1
export OUT_DIR="$GATES/matrix-r${round}"
export PORT_BASE=${PORT_BASE:-61500}
export PAYLOADS="1 32"
export CONCURRENCIES="1 32"
export LARGE_PAYLOAD_MIB=32
export LARGE_CONCURRENCIES="1 32"
export SAMPLES=${SAMPLES:-5}
export SAMPLES_LARGE=${SAMPLES_LARGE:-5}
export INTEGRITY_MIB=${INTEGRITY_MIB:-1024}
export CELLS=${CELLS:-}
export RUST_LOG_LEVEL=warn
export ABBA_START=${ABBA_START:-baseline}
exec scripts/benchmark-matrix.sh
