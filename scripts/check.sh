#!/usr/bin/env bash

set -Eeuo pipefail

readonly REPO_ROOT="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
    pwd
)"

cd "$REPO_ROOT"

run() {
    printf '\n==> %s\n' "$*"
    "$@"
}

run cargo fmt --all --check

run cargo clippy \
    --all-targets \
    --all-features \
    --locked \
    -- \
    -D warnings

run cargo test \
    --all-features \
    --locked
