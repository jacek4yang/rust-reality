# shellcheck shell=bash
# Shared environment for the v1.5.0 release-gate A/B evidence runs.
# Source this from the per-workload wrappers.  All runs execute from the
# test/v15-release-gates worktree and are wrapped in
# `flock -x /tmp/v150-bench.lock` by the caller.
ROOT=/home/jacek/work/kimi-rust-reality-performance
GATES=$ROOT/artifacts/v1.5.0/gates
REPOSITORY=$ROOT/worktrees/v150-gates
DATAPATH=$ROOT/artifacts/v1.5.0/datapath

BASELINE_BIN=$DATAPATH/bin/rust-reality-base-572c077
CANDIDATE_BIN=$GATES/bin/rust-reality-candidate-47a7151
XRAY_BIN=$ROOT/artifacts/xray-reference

BASELINE_COMMIT=572c077115a89b95f1ba559df2debcf13d29115c
CANDIDATE_COMMIT=47a71514e7b33261f510f8c0ad62af76b6c66ae2
BASELINE_SHA256=7c6f66517dc448abdbd4b6247d1c28c29dccedb599ca505c59e11c28086ec3f2
CANDIDATE_SHA256=cf532adfa9406dc44eeda513e07e44fa2875869f3b1306dc40e41c80f0de7b7b
XRAY_SHA256=23d228d78d699306c4782d6b400e2afa97c9bc9f291ae623448b5504904c5268

export RUST_REALITY_BASELINE_BIN=$BASELINE_BIN
export RUST_REALITY_BIN=$CANDIDATE_BIN
export XRAY_BIN
export RUST_REALITY_BASELINE_COMMIT=$BASELINE_COMMIT
export RUST_REALITY_COMMIT=$CANDIDATE_COMMIT
export RUST_REALITY_BASELINE_SHA256=$BASELINE_SHA256
export RUST_REALITY_SHA256=$CANDIDATE_SHA256
export XRAY_SHA256
export RUST_REALITY_BASELINE_IDENTITY=$DATAPATH/baseline-identity-572c077.json
export TMPDIR=$GATES/tmp
export RUST_REALITY_BUILD_PROFILE=release-portable
export RUST_REALITY_BUILD_FEATURES=default
# The worktree .git indirection breaks go's VCS stamping probe.
export GOFLAGS=-buildvcs=false
# Forbidden on this host: never let any harness write sysctls.
export MANAGE_PIPE_USER_PAGES_SOFT=0
