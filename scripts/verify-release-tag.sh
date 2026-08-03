#!/usr/bin/env bash
set -Eeuo pipefail

if (( $# < 1 || $# > 2 )); then
    printf 'usage: %s vMAJOR.MINOR.PATCH [main-ref]\n' "$0" >&2
    exit 2
fi

readonly RELEASE_TAG="$1"
readonly MAIN_REF="${2:-origin/main}"

if [[ ! "$RELEASE_TAG" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    printf 'release tag must be stable SemVer in vMAJOR.MINOR.PATCH form: %s\n' \
        "$RELEASE_TAG" >&2
    exit 1
fi

readonly TAG_VERSION="${RELEASE_TAG#v}"
PACKAGE_VERSION="$(
    cargo metadata --locked --no-deps --format-version 1 | python3 -c '
import json
import sys

metadata = json.load(sys.stdin)
versions = [
    package["version"]
    for package in metadata["packages"]
    if package["name"] == "rust-reality"
]
if len(versions) != 1:
    raise SystemExit("cargo metadata must contain exactly one rust-reality package")
print(versions[0])
'
)"
readonly PACKAGE_VERSION

if [[ "$TAG_VERSION" != "$PACKAGE_VERSION" ]]; then
    printf 'release tag %s does not match Cargo package version %s\n' \
        "$RELEASE_TAG" "$PACKAGE_VERSION" >&2
    exit 1
fi

TAG_COMMIT="$(git rev-parse --verify "${RELEASE_TAG}^{commit}")"
HEAD_COMMIT="$(git rev-parse --verify HEAD)"
readonly TAG_COMMIT HEAD_COMMIT

if [[ "$TAG_COMMIT" != "$HEAD_COMMIT" ]]; then
    printf 'release tag %s points to %s, but the checkout is %s\n' \
        "$RELEASE_TAG" "$TAG_COMMIT" "$HEAD_COMMIT" >&2
    exit 1
fi

if ! git merge-base --is-ancestor "$TAG_COMMIT" "$MAIN_REF"; then
    printf 'release commit %s is not reachable from %s\n' \
        "$TAG_COMMIT" "$MAIN_REF" >&2
    exit 1
fi

printf 'release identity verified: %s at %s\n' "$RELEASE_TAG" "$TAG_COMMIT"
