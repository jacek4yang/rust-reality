#!/usr/bin/env bash
# run-soak.sh <baseline|candidate> <round> — 10-minute bounded loopback soak
# with /proc resource snapshots (fd/thread/RSS growth gates are built into
# scripts/soak-test.sh).  Ports 61700+/61800+ (above the ephemeral range).
set -Eeuo pipefail
label=${1:?baseline or candidate required}
round=${2:?round number required}
source "$(dirname -- "${BASH_SOURCE[0]}")/env-common.sh"
cd "$REPOSITORY"
case $label in
    baseline)
        export RUST_REALITY_BIN=$BASELINE_BIN
        export RUST_REALITY_SHA256=$BASELINE_SHA256
        export PORT_BASE=61700
        ;;
    candidate)
        export RUST_REALITY_BIN=$CANDIDATE_BIN
        export RUST_REALITY_SHA256=$CANDIDATE_SHA256
        export PORT_BASE=61800
        ;;
    *) echo "unknown label: $label" >&2; exit 2 ;;
esac
export RUN_ID="gates-soak-${label}-r${round}"
export OUT_DIR="$GATES/soak-${label}-r${round}"
export DURATION_MIN=10
export ROUND_SLEEP=5
exec scripts/soak-test.sh
