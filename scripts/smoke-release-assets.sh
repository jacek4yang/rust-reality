#!/usr/bin/env bash
set -Eeuo pipefail

if (( $# < 2 || $# > 3 )); then
    printf 'usage: %s vMAJOR.MINOR.PATCH TARGET [ASSET_DIRECTORY]\n' "$0" >&2
    exit 2
fi

readonly RELEASE_TAG=$1
readonly RELEASE_TARGET=$2
readonly ASSET_DIRECTORY=${3:-dist}
readonly VERSION=${RELEASE_TAG#v}
readonly PORTABLE_ARCHIVE="rust-reality-${RELEASE_TAG}-${RELEASE_TARGET}.tar.gz"
readonly V3_TARGET_LABEL="${RELEASE_TARGET/x86_64/x86_64-v3}"
readonly V3_ARCHIVE="rust-reality-${RELEASE_TAG}-${V3_TARGET_LABEL}.tar.gz"

[[ $RELEASE_TAG =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
    printf 'invalid release tag: %s\n' "$RELEASE_TAG" >&2
    exit 2
}
[[ $RELEASE_TARGET == x86_64-* ]] || {
    printf 'dual-tier smoke requires an x86_64 target: %s\n' "$RELEASE_TARGET" >&2
    exit 2
}

for file in SHA256SUMS release-manifest.json "$PORTABLE_ARCHIVE" "$V3_ARCHIVE"; do
    [[ -f $ASSET_DIRECTORY/$file ]] || {
        printf 'missing release asset: %s\n' "$ASSET_DIRECTORY/$file" >&2
        exit 1
    }
done

(
    cd "$ASSET_DIRECTORY"
    sha256sum --check SHA256SUMS
)

work_directory=$(mktemp -d)
cleanup() {
    rm -rf -- "$work_directory"
}
trap cleanup EXIT

smoke_tier() {
    local tier=$1 archive=$2 directory="$work_directory/$1"
    mkdir -m 700 -- "$directory"
    tar -xzf "$ASSET_DIRECTORY/$archive" -C "$directory"
    local binary="$directory/rust-reality"
    [[ -x $binary ]] || {
        printf '%s archive has no executable rust-reality\n' "$tier" >&2
        return 1
    }
    "$binary" --version | grep -Fx "rust-reality $VERSION"
    "$binary" --help >/dev/null
    "$binary" schema >/dev/null
    printf '%s packaged binary smoke: PASS\n' "$tier"
}

smoke_tier portable "$PORTABLE_ARCHIVE"
# Executing the binary is the authoritative CPU+OS AVX-state gate. A host that
# cannot run x86-64-v3 must fail the release instead of publishing an untested
# optimized artifact.
smoke_tier x86-64-v3 "$V3_ARCHIVE"
