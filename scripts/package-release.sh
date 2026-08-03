#!/usr/bin/env bash
set -Eeuo pipefail

if (( $# < 2 || $# > 3 )); then
    printf 'usage: %s vMAJOR.MINOR.PATCH TARGET [OUTPUT_DIRECTORY]\n' "$0" >&2
    exit 2
fi

readonly RELEASE_TAG="$1"
readonly RELEASE_TARGET="$2"
readonly OUTPUT_DIRECTORY="${3:-dist}"

if [[ ! "$RELEASE_TAG" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    printf 'invalid release tag: %s\n' "$RELEASE_TAG" >&2
    exit 1
fi
if [[ ! "$RELEASE_TARGET" =~ ^[a-zA-Z0-9._-]+$ ]]; then
    printf 'invalid release target: %s\n' "$RELEASE_TARGET" >&2
    exit 1
fi

REPO_ROOT="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
    pwd
)"
readonly REPO_ROOT
readonly BINARY="$REPO_ROOT/target/release/rust-reality"

if [[ ! -x "$BINARY" ]]; then
    printf 'release binary does not exist or is not executable: %s\n' "$BINARY" >&2
    exit 1
fi

mkdir -p -- "$OUTPUT_DIRECTORY"
if find "$OUTPUT_DIRECTORY" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
    printf 'release output directory must be empty: %s\n' "$OUTPUT_DIRECTORY" >&2
    exit 1
fi

readonly VERSION="${RELEASE_TAG#v}"
COMMIT="$(git -C "$REPO_ROOT" rev-parse --verify HEAD)"
SOURCE_DATE_EPOCH="$(git -C "$REPO_ROOT" show -s --format=%ct HEAD)"
readonly COMMIT SOURCE_DATE_EPOCH
readonly ARCHIVE_NAME="rust-reality-${RELEASE_TAG}-${RELEASE_TARGET}.tar.gz"
readonly ARCHIVE_PATH="$OUTPUT_DIRECTORY/$ARCHIVE_NAME"
readonly MANIFEST_PATH="$OUTPUT_DIRECTORY/release-manifest.json"
STAGING_DIRECTORY="$(mktemp -d)"
readonly STAGING_DIRECTORY

cleanup() {
    rm -rf -- "$STAGING_DIRECTORY"
}
trap cleanup EXIT

install -m 0755 "$BINARY" "$STAGING_DIRECTORY/rust-reality"
install -m 0644 "$REPO_ROOT/README.md" "$STAGING_DIRECTORY/README.md"
install -m 0644 "$REPO_ROOT/README.zh-CN.md" "$STAGING_DIRECTORY/README.zh-CN.md"
install -m 0644 "$REPO_ROOT/SECURITY.md" "$STAGING_DIRECTORY/SECURITY.md"
install -m 0644 "$REPO_ROOT/SECURITY.zh-CN.md" "$STAGING_DIRECTORY/SECURITY.zh-CN.md"
install -d -m 0755 "$STAGING_DIRECTORY/deploy" "$STAGING_DIRECTORY/docs"
install -m 0644 "$REPO_ROOT/deploy/rust-reality.service" \
    "$STAGING_DIRECTORY/deploy/rust-reality.service"
install -m 0644 "$REPO_ROOT"/docs/*.md "$STAGING_DIRECTORY/docs/"

tar \
    --sort=name \
    --mtime="@$SOURCE_DATE_EPOCH" \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    -C "$STAGING_DIRECTORY" \
    -cf - . | gzip -n -9 > "$ARCHIVE_PATH"

ARCHIVE_SHA256="$(sha256sum "$ARCHIVE_PATH" | cut -d ' ' -f 1)"
readonly ARCHIVE_SHA256
export VERSION RELEASE_TAG RELEASE_TARGET COMMIT SOURCE_DATE_EPOCH
export ARCHIVE_NAME ARCHIVE_SHA256
python3 -c '
import json
import os
import sys

manifest = {
    "schemaVersion": 1,
    "package": "rust-reality",
    "version": os.environ["VERSION"],
    "tag": os.environ["RELEASE_TAG"],
    "commit": os.environ["COMMIT"],
    "target": os.environ["RELEASE_TARGET"],
    "sourceDateEpoch": int(os.environ["SOURCE_DATE_EPOCH"]),
    "artifact": os.environ["ARCHIVE_NAME"],
    "sha256": os.environ["ARCHIVE_SHA256"],
}
json.dump(manifest, sys.stdout, indent=2)
print()
' > "$MANIFEST_PATH"

(
    cd -- "$OUTPUT_DIRECTORY"
    sha256sum "$ARCHIVE_NAME" "$(basename -- "$MANIFEST_PATH")" > SHA256SUMS
    sha256sum --check SHA256SUMS
)
