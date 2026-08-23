#!/usr/bin/env bash
set -Eeuo pipefail

readonly REPO_ROOT="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
    pwd
)"

# shellcheck source=scripts/release-matrix.sh
source "$REPO_ROOT/scripts/release-matrix.sh"

if (( $# < 1 || $# > 2 )); then
    printf 'usage: %s TIER [--build-only]\n' "$0" >&2
    printf 'tiers: %s\n' "$(release_matrix_tiers | tr '\n' ' ')" >&2
    exit 2
fi

readonly TIER="$1"
readonly BUILD_ONLY="${2:-}"
if [[ -n $BUILD_ONLY && $BUILD_ONLY != "--build-only" ]]; then
    printf 'unknown option: %s\n' "$BUILD_ONLY" >&2
    exit 2
fi

readonly TARGET="$(release_matrix_field "$TIER" target)"
readonly TARGET_CPU="$(release_matrix_field "$TIER" target-cpu)"
readonly TARGET_FEATURES="$(release_matrix_field "$TIER" target-features)"
readonly TARGET_DIRECTORY="$REPO_ROOT/$(release_matrix_target_dir "$TIER")"

RUSTFLAGS="-C target-cpu=$TARGET_CPU"
if [[ -n $TARGET_FEATURES ]]; then
    RUSTFLAGS="$RUSTFLAGS -C target-feature=$TARGET_FEATURES"
fi
readonly RUSTFLAGS

readonly HOST_TARGET="$(rustc -vV | sed -n 's/^host: //p')"
CARGO_TARGET_ARGS=()
if [[ $TARGET != "$HOST_TARGET" ]]; then
    # Cross targets normally cannot execute on the build host and therefore
    # require --build-only. The x86_64 musl target is the one intentional
    # exception: its fully static binaries execute directly on the same
    # x86_64 kernel/ISA even though rustc's host libc is GNU.
    CARGO_TARGET_ARGS=(--target "$TARGET")
    cross_runnable=false
    if [[ $HOST_TARGET == x86_64-unknown-linux-gnu &&
          $TARGET == x86_64-unknown-linux-musl ]]; then
        cross_runnable=true
    fi
    if [[ $cross_runnable != true && -z $BUILD_ONLY ]]; then
        printf '%s\n' \
            "cross tier $TIER ($TARGET on $HOST_TARGET) requires --build-only" \
            >&2
        exit 2
    fi
fi

cd "$REPO_ROOT"

readonly GIT_COMMIT="$(git rev-parse --verify HEAD)"
readonly SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
export RUST_REALITY_GIT_COMMIT="$GIT_COMMIT"
export SOURCE_DATE_EPOCH

target_environment=()
if [[ $TARGET == x86_64-unknown-linux-musl ]]; then
    musl_cc=${CC_x86_64_unknown_linux_musl:-}
    if [[ -z $musl_cc ]]; then
        if command -v musl-gcc >/dev/null 2>&1; then
            musl_cc=musl-gcc
        elif [[ $HOST_TARGET == "$TARGET" ]] && command -v cc >/dev/null 2>&1; then
            musl_cc=cc
        else
            printf '%s\n' \
                'x86_64 musl release requires musl-gcc (install musl-tools)' \
                >&2
            exit 1
        fi
    fi
    target_environment+=(
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=$musl_cc"
        "CC_x86_64_unknown_linux_musl=$musl_cc"
    )
fi

build_command=(
    env -u CARGO_ENCODED_RUSTFLAGS
    "${target_environment[@]}"
    CARGO_TARGET_DIR="$TARGET_DIRECTORY"
    RUSTFLAGS="$RUSTFLAGS"
    cargo
)

if [[ -z $BUILD_ONLY ]]; then
    printf 'testing %s release in %s\n' "$TIER" "$TARGET_DIRECTORY"
    "${build_command[@]}" test --workspace --release --locked \
        "${CARGO_TARGET_ARGS[@]}"
fi

printf 'building %s release in %s\n' "$TIER" "$TARGET_DIRECTORY"
"${build_command[@]}" build --workspace --release --locked \
    "${CARGO_TARGET_ARGS[@]}"

if ((${#CARGO_TARGET_ARGS[@]})); then
    readonly BINARY="$TARGET_DIRECTORY/$TARGET/release/rust-reality"
else
    readonly BINARY="$TARGET_DIRECTORY/release/rust-reality"
fi

printf '%s: ' "$TIER"
sha256sum "$BINARY"
