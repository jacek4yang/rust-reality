#!/usr/bin/env bash
set -Eeuo pipefail

if (( $# < 2 || $# > 3 )); then
    printf 'usage: %s vMAJOR.MINOR.PATCH TIER [OUTPUT_DIRECTORY]\n' "$0" >&2
    exit 2
fi

readonly RELEASE_TAG="$1"
readonly TIER="$2"
readonly OUTPUT_DIRECTORY="${3:-dist}"

REPO_ROOT="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
    pwd
)"
readonly REPO_ROOT

# shellcheck source=scripts/release-matrix.sh
source "$REPO_ROOT/scripts/release-matrix.sh"

if [[ ! "$RELEASE_TAG" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    printf 'invalid release tag: %s\n' "$RELEASE_TAG" >&2
    exit 1
fi

readonly TARGET="$(release_matrix_field "$TIER" target)"
readonly TARGET_CPU="$(release_matrix_field "$TIER" target-cpu)"
readonly TARGET_FEATURES="$(release_matrix_field "$TIER" target-features)"
readonly TARGET_DIRECTORY="$REPO_ROOT/$(release_matrix_target_dir "$TIER")"
readonly MEASURED_NATIVELY="${RUST_REALITY_MEASURED_NATIVELY:-$(release_matrix_field "$TIER" measured-natively)}"
case $MEASURED_NATIVELY in
    true | false) ;;
    *)
        printf 'measuredNatively must be true or false: %s\n' \
            "$MEASURED_NATIVELY" >&2
        exit 2
        ;;
esac

if [[ -n ${RUST_REALITY_RELEASE_BIN:-} ]]; then
    BINARY="$RUST_REALITY_RELEASE_BIN"
elif [[ -x $TARGET_DIRECTORY/release/rust-reality ]]; then
    BINARY="$TARGET_DIRECTORY/release/rust-reality"
elif [[ -x $TARGET_DIRECTORY/$TARGET/release/rust-reality ]]; then
    BINARY="$TARGET_DIRECTORY/$TARGET/release/rust-reality"
else
    printf 'no built binary for tier %s under %s\n' "$TIER" "$TARGET_DIRECTORY" >&2
    exit 1
fi
readonly BINARY
if [[ ! -x $BINARY ]]; then
    printf 'release binary does not exist or is not executable: %s\n' "$BINARY" >&2
    exit 1
fi

mkdir -p -- "$OUTPUT_DIRECTORY"
readonly ARCHIVE_NAME="rust-reality-${RELEASE_TAG}-${TIER}.tar.gz"
readonly FRAGMENT_NAME="${TIER}.tier.json"
for existing in "$ARCHIVE_NAME" "$FRAGMENT_NAME"; do
    if [[ -e $OUTPUT_DIRECTORY/$existing ]]; then
        printf 'release output already contains %s: %s\n' \
            "$existing" "$OUTPUT_DIRECTORY" >&2
        exit 1
    fi
done

readonly VERSION="${RELEASE_TAG#v}"
COMMIT="$(git -C "$REPO_ROOT" rev-parse --verify HEAD)"
SOURCE_DATE_EPOCH="$(git -C "$REPO_ROOT" show -s --format=%ct HEAD)"
COMPILER="$(rustc --version)"
readonly COMMIT SOURCE_DATE_EPOCH COMPILER
readonly CARGO_FEATURES="${RUST_REALITY_CARGO_FEATURES:-default}"
readonly ARCHIVE_PATH="$OUTPUT_DIRECTORY/$ARCHIVE_NAME"
readonly FRAGMENT_PATH="$OUTPUT_DIRECTORY/$FRAGMENT_NAME"
STAGING_DIRECTORIES=()

cleanup() {
    local directory
    for directory in "${STAGING_DIRECTORIES[@]:-}"; do
        rm -rf -- "$directory"
    done
}
trap cleanup EXIT

staging_directory="$(mktemp -d)"
STAGING_DIRECTORIES+=("$staging_directory")

install -m 0755 "$BINARY" "$staging_directory/rust-reality"
install -m 0644 "$REPO_ROOT/README.md" "$staging_directory/README.md"
install -m 0644 "$REPO_ROOT/README.zh-CN.md" "$staging_directory/README.zh-CN.md"
install -m 0644 "$REPO_ROOT/SECURITY.md" "$staging_directory/SECURITY.md"
install -m 0644 "$REPO_ROOT/SECURITY.zh-CN.md" "$staging_directory/SECURITY.zh-CN.md"
install -m 0644 "$REPO_ROOT/LICENSE-MIT" "$staging_directory/LICENSE-MIT"
install -m 0644 "$REPO_ROOT/LICENSE-APACHE" "$staging_directory/LICENSE-APACHE"
install -m 0644 "$REPO_ROOT/CHANGELOG.md" "$staging_directory/CHANGELOG.md"
install -d -m 0755 "$staging_directory/deploy" \
    "$staging_directory/docs" "$staging_directory/docs/decisions"
install -m 0644 "$REPO_ROOT/deploy/rust-reality.service" \
    "$staging_directory/deploy/rust-reality.service"
install -m 0644 "$REPO_ROOT"/docs/*.md "$staging_directory/docs/"
install -m 0644 "$REPO_ROOT"/docs/decisions/*.md \
    "$staging_directory/docs/decisions/"

tar \
    --sort=name \
    --mtime="@$SOURCE_DATE_EPOCH" \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    -C "$staging_directory" \
    -cf - . | gzip -n -9 > "$ARCHIVE_PATH"

ARCHIVE_SHA256="$(sha256sum "$ARCHIVE_PATH" | cut -d ' ' -f 1)"
readonly ARCHIVE_SHA256
CPU_TIER_ALIAS="$(release_matrix_cpu_tier_alias "$TIER")"
readonly CPU_TIER_ALIAS
REQUIREMENTS_JSON="$(release_matrix_requirements_json "$TIER")"
readonly REQUIREMENTS_JSON
export VERSION RELEASE_TAG TIER TARGET TARGET_CPU TARGET_FEATURES COMMIT
export SOURCE_DATE_EPOCH COMPILER CARGO_FEATURES MEASURED_NATIVELY
export ARCHIVE_NAME ARCHIVE_SHA256 CPU_TIER_ALIAS REQUIREMENTS_JSON
python3 -c '
import json
import os
import sys

features = [feature.strip() for feature in
            os.environ["TARGET_FEATURES"].split(",") if feature.strip()]
fragment = {
    "schemaVersion": 3,
    "package": "rust-reality",
    "version": os.environ["VERSION"],
    "tag": os.environ["RELEASE_TAG"],
    "commit": os.environ["COMMIT"],
    "sourceDateEpoch": int(os.environ["SOURCE_DATE_EPOCH"]),
    "compiler": os.environ["COMPILER"],
    "cargoFeatures": [feature.strip() for feature in
                      os.environ["CARGO_FEATURES"].split(",")
                      if feature.strip()],
    "tier": os.environ["TIER"],
    "cpuTier": os.environ["CPU_TIER_ALIAS"],
    "artifact": os.environ["ARCHIVE_NAME"],
    "sha256": os.environ["ARCHIVE_SHA256"],
    "target": os.environ["TARGET"],
    "targetCpu": os.environ["TARGET_CPU"],
    "targetFeatures": features,
    "measuredNatively": os.environ["MEASURED_NATIVELY"] == "true",
    "requirements": json.loads(os.environ["REQUIREMENTS_JSON"]),
}
json.dump(fragment, sys.stdout, indent=2)
print()
' > "$FRAGMENT_PATH"

printf 'packaged %s -> %s\n' "$TIER" "$ARCHIVE_PATH"
