#!/usr/bin/env bash
set -Eeuo pipefail

readonly REPO_ROOT="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
    pwd
)"

cd "$REPO_ROOT"

readonly GIT_COMMIT="$(git rev-parse --verify HEAD)"
readonly SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
readonly PORTABLE_TARGET_DIRECTORY="$REPO_ROOT/target"
readonly X86_64_V3_TARGET_DIRECTORY="$REPO_ROOT/target/x86-64-v3"
readonly PORTABLE_RUSTFLAGS="-C target-cpu=x86-64"
readonly X86_64_V3_RUSTFLAGS="-C target-cpu=x86-64-v3"
export RUST_REALITY_GIT_COMMIT="$GIT_COMMIT"
export SOURCE_DATE_EPOCH

test_and_build_release_tier() {
    local label=$1
    local target_directory=$2
    local rustflags=$3

    printf 'testing %s release in %s\n' "$label" "$target_directory"
    env -u CARGO_ENCODED_RUSTFLAGS \
        CARGO_TARGET_DIR="$target_directory" \
        RUSTFLAGS="$rustflags" \
        cargo test --workspace --release --locked

    printf 'building %s release in %s\n' "$label" "$target_directory"
    env -u CARGO_ENCODED_RUSTFLAGS \
        CARGO_TARGET_DIR="$target_directory" \
        RUSTFLAGS="$rustflags" \
        cargo build --workspace --release --locked
}

test_and_build_release_tier \
    portable \
    "$PORTABLE_TARGET_DIRECTORY" \
    "$PORTABLE_RUSTFLAGS"
test_and_build_release_tier \
    x86-64-v3 \
    "$X86_64_V3_TARGET_DIRECTORY" \
    "$X86_64_V3_RUSTFLAGS"

readonly PORTABLE_BINARY="$PORTABLE_TARGET_DIRECTORY/release/rust-reality"
readonly X86_64_V3_BINARY="$X86_64_V3_TARGET_DIRECTORY/release/rust-reality"

printf 'portable: '
sha256sum "$PORTABLE_BINARY"
printf 'x86-64-v3: '
sha256sum "$X86_64_V3_BINARY"
