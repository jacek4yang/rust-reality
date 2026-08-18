#!/usr/bin/env bash
# aggregate-release.sh — merge per-tier packaging fragments into ONE combined
# release-manifest.json + SHA256SUMS across the full release matrix.
#
# Usage: aggregate-release.sh vMAJOR.MINOR.PATCH [DIST_DIRECTORY]
#
# The dist directory must contain, for every tier in
# scripts/release-matrix.sh, exactly one tarball plus the matching
# <tier>.tier.json fragment produced by package-release.sh. A missing or
# unexpected tier fails the release: partial publishes are impossible.
# Fragments are removed after successful aggregation; the release ships only
# tarballs, release-manifest.json, and SHA256SUMS.
set -Eeuo pipefail

if (( $# < 1 || $# > 2 )); then
    printf 'usage: %s vMAJOR.MINOR.PATCH [DIST_DIRECTORY]\n' "$0" >&2
    exit 2
fi

readonly RELEASE_TAG="$1"
readonly DIST_DIRECTORY="${2:-dist}"

if [[ ! "$RELEASE_TAG" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    printf 'invalid release tag: %s\n' "$RELEASE_TAG" >&2
    exit 1
fi

REPO_ROOT="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
    pwd
)"
readonly REPO_ROOT

# shellcheck source=scripts/release-matrix.sh
source "$REPO_ROOT/scripts/release-matrix.sh"

EXPECTED_TIERS=()
while IFS= read -r tier; do
    EXPECTED_TIERS+=("$tier")
done < <(release_matrix_tiers)
readonly EXPECTED_TIERS

for tier in "${EXPECTED_TIERS[@]}"; do
    for file in "rust-reality-${RELEASE_TAG}-${tier}.tar.gz" "${tier}.tier.json"; do
        [[ -f $DIST_DIRECTORY/$file ]] || {
            printf 'missing aggregated release input: %s\n' \
                "$DIST_DIRECTORY/$file" >&2
            exit 1
        }
    done
done

unexpected="$(
    expected="$(
        for tier in "${EXPECTED_TIERS[@]}"; do
            printf 'rust-reality-%s-%s.tar.gz\n%s.tier.json\n' \
                "$RELEASE_TAG" "$tier" "$tier"
        done
    )"
    comm -23 \
        <(find "$DIST_DIRECTORY" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort) \
        <(printf '%s\n' "$expected" | sort)
)"
if [[ -n $unexpected ]]; then
    printf 'unexpected files in aggregate dist directory:\n%s\n' "$unexpected" >&2
    exit 1
fi

export RELEASE_TAG DIST_DIRECTORY
python3 - "${EXPECTED_TIERS[@]}" <<'PY'
import hashlib
import json
import os
import sys
from pathlib import Path

tag = os.environ["RELEASE_TAG"]
dist = Path(os.environ["DIST_DIRECTORY"])
tiers = sys.argv[1:]

fragments = []
for tier in tiers:
    fragment_path = dist / f"{tier}.tier.json"
    fragment = json.loads(fragment_path.read_text(encoding="utf-8"))
    fragments.append(fragment)

    assert fragment["schemaVersion"] == 3, fragment_path
    assert fragment["tag"] == tag, fragment_path
    assert fragment["tier"] == tier, fragment_path
    archive = dist / fragment["artifact"]
    assert archive.name == f"rust-reality-{tag}-{tier}.tar.gz", archive
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != fragment["sha256"]:
        raise SystemExit(
            f"sha256 mismatch for {archive.name}: "
            f"fragment {fragment['sha256']} != actual {digest}"
        )

first = fragments[0]
global_keys = ("package", "version", "tag", "commit", "sourceDateEpoch",
               "compiler", "cargoFeatures")
for fragment in fragments[1:]:
    for key in global_keys:
        if fragment[key] != first[key]:
            raise SystemExit(
                f"fragment {fragment['tier']} disagrees on {key}: "
                f"{fragment[key]!r} != {first[key]!r}"
            )

artifacts = []
for fragment in fragments:
    artifact = {
        "artifact": fragment["artifact"],
        "sha256": fragment["sha256"],
        "tier": fragment["tier"],
        # Schema-v2 alias retained for existing consumers.
        "cpuTier": fragment["cpuTier"],
        "target": fragment["target"],
        "targetCpu": fragment["targetCpu"],
        "targetFeatures": fragment["targetFeatures"],
        "measuredNatively": fragment["measuredNatively"],
        "requirements": fragment["requirements"],
    }
    artifacts.append(artifact)

# Schema-v1/v2 aliases intentionally continue to identify the recommended
# generic x86_64 asset.
generic = next(fragment for fragment in fragments
               if fragment["tier"] == "linux-x86_64-generic")
manifest = {
    "schemaVersion": 3,
    "package": first["package"],
    "version": first["version"],
    "tag": first["tag"],
    "commit": first["commit"],
    "target": generic["target"],
    "sourceDateEpoch": first["sourceDateEpoch"],
    "compiler": first["compiler"],
    "cargoFeatures": first["cargoFeatures"],
    "artifact": generic["artifact"],
    "sha256": generic["sha256"],
    "artifacts": artifacts,
}
manifest_path = dist / "release-manifest.json"
manifest_path.write_text(json.dumps(manifest, indent=2) + "\n",
                         encoding="utf-8")
PY

for tier in "${EXPECTED_TIERS[@]}"; do
    rm -f -- "$DIST_DIRECTORY/${tier}.tier.json"
done

(
    cd -- "$DIST_DIRECTORY"
    : > SHA256SUMS
    for tier in "${EXPECTED_TIERS[@]}"; do
        sha256sum "rust-reality-${RELEASE_TAG}-${tier}.tar.gz"
    done >> SHA256SUMS
    sha256sum release-manifest.json >> SHA256SUMS
    sha256sum --check SHA256SUMS
)

printf 'aggregated %d tiers into %s/release-manifest.json\n' \
    "${#EXPECTED_TIERS[@]}" "$DIST_DIRECTORY"
