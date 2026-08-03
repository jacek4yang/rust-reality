#!/usr/bin/env bash
set -Eeuo pipefail

readonly REPO_ROOT="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
    pwd
)"
readonly NEXTEST_PROFILE="${NEXTEST_PROFILE:-default}"
readonly AUDIT_FETCH_TIMEOUT="${AUDIT_FETCH_TIMEOUT:-120s}"

cd "$REPO_ROOT"

run() {
    printf '\n==> %s\n' "$*"
    "$@"
}

run_audit() {
    printf '\n==> cargo audit --deny warnings\n'
    if timeout --signal=TERM "$AUDIT_FETCH_TIMEOUT" cargo audit --deny warnings; then
        return
    fi

    printf '%s\n' \
        'fresh advisory retrieval failed; retrying the cached database without network access' >&2
    cargo audit --no-fetch --deny warnings
}

for script in scripts/*.sh; do
    run bash -n "$script"
done

run cargo fmt --all --check
run cargo clippy --all-targets --all-features --locked -- -D warnings
run cargo deny --all-features check bans licenses sources
run_audit
run env RUSTDOCFLAGS="-D warnings" \
    cargo doc --all-features --locked --no-deps
run cargo nextest run \
    --profile "$NEXTEST_PROFILE" \
    --all-features \
    --locked
run cargo test --doc --all-features --locked
run cargo test --release --all-features --locked
run cargo test --benches --all-features --locked
