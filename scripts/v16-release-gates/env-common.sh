# shellcheck shell=bash
# Shared environment for the v1.6.0 release-gate A/B evidence runs.
# Source this from the per-workload wrappers.  All runs execute from the
# candidate worktree and are wrapped in
# `flock -x /tmp/v16-bench.lock` by the caller.
#
# Baseline: the published v1.5.1 release asset (gitCommit 149f126), extracted
# read-only under artifacts/v1.6.0/baseline/extracted/ and bound by the
# baseline-identity-149f126.json sidecar next to this file.
#
# Candidate: the v1.6.0 candidate commit is not merged when this harness
# lands, so the candidate binary is supplied as a prebuilt read-only path via
# RR_CANDIDATE_BIN (required).  Its source commit defaults to the HEAD of
# REPOSITORY; override RUST_REALITY_COMMIT only if you know what you are
# doing.  The candidate SHA-256 is computed from the binary at source time.
ROOT=/home/jacek/work/kimi-rust-reality-performance
GATES=$ROOT/artifacts/v1.6.0/gates
REPOSITORY=$ROOT/rust-reality
DATAPATH=$ROOT/artifacts/v1.6.0

BASELINE_BIN=$DATAPATH/baseline/extracted/rust-reality
CANDIDATE_BIN=${RR_CANDIDATE_BIN:?'RR_CANDIDATE_BIN must name the prebuilt read-only candidate binary'}
XRAY_BIN=$ROOT/artifacts/xray-reference-v26.7.28

BASELINE_COMMIT=149f126d9f852bafeca85bc14a0f8f0b2c096640
CANDIDATE_COMMIT=${RUST_REALITY_COMMIT:-$(git -C "$REPOSITORY" rev-parse --verify 'HEAD^{commit}' 2>/dev/null || echo MISSING-CANDIDATE-COMMIT)}
BASELINE_SHA256=49f3246f571b63043dd3fa198c84d6f2c113c64372e6955c1a0282fb0926956b
CANDIDATE_SHA256=$(sha256sum "$CANDIDATE_BIN" | awk '{print $1}')
XRAY_SHA256=23d228d78d699306c4782d6b400e2afa97c9bc9f291ae623448b5504904c5268

export RUST_REALITY_BASELINE_BIN=$BASELINE_BIN
export RUST_REALITY_BIN=$CANDIDATE_BIN
export XRAY_BIN
export RUST_REALITY_BASELINE_COMMIT=$BASELINE_COMMIT
export RUST_REALITY_COMMIT=$CANDIDATE_COMMIT
export RUST_REALITY_BASELINE_SHA256=$BASELINE_SHA256
export RUST_REALITY_SHA256=$CANDIDATE_SHA256
export XRAY_SHA256
export RUST_REALITY_BASELINE_IDENTITY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/baseline-identity-149f126.json"
export TMPDIR=$GATES/tmp
export RUST_REALITY_BUILD_PROFILE=release-portable
export RUST_REALITY_BUILD_FEATURES=default
# Host-exclusive benchmark lock shared with every other v1.6.0 worker.  This
# overrides benchmark-contract.sh's compiled-in .coord/v1.5.0/ default without
# editing that script.
export RR_HOST_EXCLUSIVE_LOCK=${RR_HOST_EXCLUSIVE_LOCK:-/tmp/v16-bench.lock}
# The worktree .git indirection breaks go's VCS stamping probe.
export GOFLAGS=-buildvcs=false
# Forbidden on this host: never let any harness write sysctls.
export MANAGE_PIPE_USER_PAGES_SOFT=0
