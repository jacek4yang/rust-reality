#!/usr/bin/env bash
set -Eeuo pipefail

readonly REPO_ROOT="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
    pwd
)"
readonly NEXTEST_PROFILE="${NEXTEST_PROFILE:-default}"

cd "$REPO_ROOT"

run() {
    printf '\n==> %s\n' "$*"
    "$@"
}

run cargo fmt --all --check
run cargo clippy --all-targets --all-features --locked -- -D warnings
run env RUSTDOCFLAGS="-D warnings" \
    cargo doc --all-features --locked --no-deps
run cargo nextest run \
    --profile "$NEXTEST_PROFILE" \
    --all-features \
    --locked
run cargo test --doc --all-features --locked
run cargo test --release --all-features --locked
run cargo test --benches --all-features --locked
