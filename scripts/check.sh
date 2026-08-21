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

run python3 scripts/check-docs.py
run python3 scripts/fuzz-targets.py
run python3 scripts/active-probe-gate.py --check
run python3 scripts/check-performance-contract.py
run python3 scripts/test-performance-gates.py
run scripts/test-package-release.sh
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
run cargo test --benches --all-features --locked --no-run
