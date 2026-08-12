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
if [[ "$RELEASE_TARGET" != x86_64-* ]]; then
    printf 'dual-tier release packaging requires an x86_64 target: %s\n' "$RELEASE_TARGET" >&2
    exit 1
fi

REPO_ROOT="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
    pwd
)"
readonly REPO_ROOT
readonly PORTABLE_BINARY="${RUST_REALITY_PORTABLE_BIN:-$REPO_ROOT/target/release/rust-reality}"
readonly X86_64_V3_BINARY="${RUST_REALITY_X86_64_V3_BIN:-$REPO_ROOT/target/x86-64-v3/release/rust-reality}"

for binary in "$PORTABLE_BINARY" "$X86_64_V3_BINARY"; do
    if [[ ! -x "$binary" ]]; then
        printf 'release binary does not exist or is not executable: %s\n' "$binary" >&2
        exit 1
    fi
done

mkdir -p -- "$OUTPUT_DIRECTORY"
if find "$OUTPUT_DIRECTORY" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
    printf 'release output directory must be empty: %s\n' "$OUTPUT_DIRECTORY" >&2
    exit 1
fi

readonly VERSION="${RELEASE_TAG#v}"
COMMIT="$(git -C "$REPO_ROOT" rev-parse --verify HEAD)"
SOURCE_DATE_EPOCH="$(git -C "$REPO_ROOT" show -s --format=%ct HEAD)"
readonly COMMIT SOURCE_DATE_EPOCH
readonly PORTABLE_ARCHIVE_NAME="rust-reality-${RELEASE_TAG}-${RELEASE_TARGET}.tar.gz"
readonly X86_64_V3_TARGET_LABEL="${RELEASE_TARGET/x86_64/x86_64-v3}"
readonly X86_64_V3_ARCHIVE_NAME="rust-reality-${RELEASE_TAG}-${X86_64_V3_TARGET_LABEL}.tar.gz"
readonly PORTABLE_ARCHIVE_PATH="$OUTPUT_DIRECTORY/$PORTABLE_ARCHIVE_NAME"
readonly X86_64_V3_ARCHIVE_PATH="$OUTPUT_DIRECTORY/$X86_64_V3_ARCHIVE_NAME"
readonly MANIFEST_PATH="$OUTPUT_DIRECTORY/release-manifest.json"
STAGING_DIRECTORIES=()

cleanup() {
    local directory
    for directory in "${STAGING_DIRECTORIES[@]:-}"; do
        rm -rf -- "$directory"
    done
}
trap cleanup EXIT

package_binary() {
    local binary=$1
    local archive_path=$2
    local staging_directory
    staging_directory="$(mktemp -d)"
    STAGING_DIRECTORIES+=("$staging_directory")

    install -m 0755 "$binary" "$staging_directory/rust-reality"
    install -m 0644 "$REPO_ROOT/README.md" "$staging_directory/README.md"
    install -m 0644 "$REPO_ROOT/README.zh-CN.md" "$staging_directory/README.zh-CN.md"
    install -m 0644 "$REPO_ROOT/SECURITY.md" "$staging_directory/SECURITY.md"
    install -m 0644 "$REPO_ROOT/SECURITY.zh-CN.md" "$staging_directory/SECURITY.zh-CN.md"
    install -m 0644 "$REPO_ROOT/LICENSE-MIT" "$staging_directory/LICENSE-MIT"
    install -m 0644 "$REPO_ROOT/LICENSE-APACHE" "$staging_directory/LICENSE-APACHE"
    install -m 0644 "$REPO_ROOT/CHANGELOG.md" "$staging_directory/CHANGELOG.md"
    install -d -m 0755 "$staging_directory/deploy" "$staging_directory/docs"
    install -m 0644 "$REPO_ROOT/deploy/rust-reality.service" \
        "$staging_directory/deploy/rust-reality.service"
    install -m 0644 "$REPO_ROOT"/docs/*.md "$staging_directory/docs/"

    tar \
        --sort=name \
        --mtime="@$SOURCE_DATE_EPOCH" \
        --owner=0 \
        --group=0 \
        --numeric-owner \
        -C "$staging_directory" \
        -cf - . | gzip -n -9 > "$archive_path"
}

package_binary "$PORTABLE_BINARY" "$PORTABLE_ARCHIVE_PATH"
package_binary "$X86_64_V3_BINARY" "$X86_64_V3_ARCHIVE_PATH"

PORTABLE_ARCHIVE_SHA256="$(sha256sum "$PORTABLE_ARCHIVE_PATH" | cut -d ' ' -f 1)"
X86_64_V3_ARCHIVE_SHA256="$(sha256sum "$X86_64_V3_ARCHIVE_PATH" | cut -d ' ' -f 1)"
readonly PORTABLE_ARCHIVE_SHA256 X86_64_V3_ARCHIVE_SHA256
export VERSION RELEASE_TAG RELEASE_TARGET COMMIT SOURCE_DATE_EPOCH
export PORTABLE_ARCHIVE_NAME PORTABLE_ARCHIVE_SHA256
export X86_64_V3_ARCHIVE_NAME X86_64_V3_ARCHIVE_SHA256
python3 -c '
import json
import os
import sys

manifest = {
    "schemaVersion": 2,
    "package": "rust-reality",
    "version": os.environ["VERSION"],
    "tag": os.environ["RELEASE_TAG"],
    "commit": os.environ["COMMIT"],
    "target": os.environ["RELEASE_TARGET"],
    "sourceDateEpoch": int(os.environ["SOURCE_DATE_EPOCH"]),
    # Schema-v1 aliases intentionally continue to identify the portable asset.
    "artifact": os.environ["PORTABLE_ARCHIVE_NAME"],
    "sha256": os.environ["PORTABLE_ARCHIVE_SHA256"],
    "artifacts": [
        {
            "artifact": os.environ["PORTABLE_ARCHIVE_NAME"],
            "sha256": os.environ["PORTABLE_ARCHIVE_SHA256"],
            "target": os.environ["RELEASE_TARGET"],
            "cpuTier": "portable",
            "requirements": {
                "architecture": "x86_64",
                "isaLevel": "x86-64",
                "runtimeDispatch": False,
            },
        },
        {
            "artifact": os.environ["X86_64_V3_ARCHIVE_NAME"],
            "sha256": os.environ["X86_64_V3_ARCHIVE_SHA256"],
            "target": os.environ["RELEASE_TARGET"],
            "cpuTier": "x86-64-v3",
            "requirements": {
                "architecture": "x86_64",
                "isaLevel": "x86-64-v3",
                "runtimeDispatch": False,
                "requiredCpuFeatures": [
                    "avx",
                    "avx2",
                    "bmi1",
                    "bmi2",
                    "cmpxchg16b",
                    "f16c",
                    "fma",
                    "fxsr",
                    "lzcnt",
                    "movbe",
                    "popcnt",
                    "sse",
                    "sse2",
                    "sse3",
                    "sse4.1",
                    "sse4.2",
                    "ssse3",
                    "xsave",
                ],
            },
        },
    ],
}
json.dump(manifest, sys.stdout, indent=2)
print()
' > "$MANIFEST_PATH"

(
    cd -- "$OUTPUT_DIRECTORY"
    sha256sum \
        "$PORTABLE_ARCHIVE_NAME" \
        "$X86_64_V3_ARCHIVE_NAME" \
        "$(basename -- "$MANIFEST_PATH")" \
        > SHA256SUMS
    sha256sum --check SHA256SUMS
)
