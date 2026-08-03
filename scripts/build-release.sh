#!/usr/bin/env bash
set -Eeuo pipefail

readonly REPO_ROOT="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
    pwd
)"

cd "$REPO_ROOT"

readonly GIT_COMMIT="$(git rev-parse --verify HEAD)"
readonly SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
export RUST_REALITY_GIT_COMMIT="$GIT_COMMIT"
export SOURCE_DATE_EPOCH

cargo build --release --locked
sha256sum target/release/rust-reality
