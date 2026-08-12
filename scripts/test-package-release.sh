#!/usr/bin/env bash
set -Eeuo pipefail

readonly REPO_ROOT="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
    pwd
)"
WORK_DIRECTORY="$(mktemp -d)"
readonly WORK_DIRECTORY

cleanup() {
    rm -rf -- "$WORK_DIRECTORY"
}
trap cleanup EXIT

mkdir -p "$WORK_DIRECTORY/bin" "$WORK_DIRECTORY/first" "$WORK_DIRECTORY/second"
printf '#!/usr/bin/env sh\nprintf portable\n' > "$WORK_DIRECTORY/bin/portable"
printf '#!/usr/bin/env sh\nprintf x86-64-v3\n' > "$WORK_DIRECTORY/bin/x86-64-v3"
chmod 0755 "$WORK_DIRECTORY/bin/portable" "$WORK_DIRECTORY/bin/x86-64-v3"

run_package() {
    env \
        RUST_REALITY_PORTABLE_BIN="$WORK_DIRECTORY/bin/portable" \
        RUST_REALITY_X86_64_V3_BIN="$WORK_DIRECTORY/bin/x86-64-v3" \
        "$REPO_ROOT/scripts/package-release.sh" \
        v9.8.7 x86_64-unknown-linux-gnu "$1"
}

run_package "$WORK_DIRECTORY/first"
run_package "$WORK_DIRECTORY/second"

diff --brief --recursive "$WORK_DIRECTORY/first" "$WORK_DIRECTORY/second"
(
    cd "$WORK_DIRECTORY/first"
    sha256sum --check SHA256SUMS
)

python3 - "$WORK_DIRECTORY/first" <<'PY'
import hashlib
import json
import pathlib
import sys
import tarfile

root = pathlib.Path(sys.argv[1])
portable_name = "rust-reality-v9.8.7-x86_64-unknown-linux-gnu.tar.gz"
v3_name = "rust-reality-v9.8.7-x86_64-v3-unknown-linux-gnu.tar.gz"
expected_files = {
    portable_name,
    v3_name,
    "release-manifest.json",
    "SHA256SUMS",
}
actual_files = {path.name for path in root.iterdir()}
assert actual_files == expected_files, (actual_files, expected_files)

manifest = json.loads((root / "release-manifest.json").read_text())
assert manifest["schemaVersion"] == 2
assert manifest["target"] == "x86_64-unknown-linux-gnu"
assert manifest["artifact"] == portable_name
assert manifest["sha256"] == hashlib.sha256(
    (root / portable_name).read_bytes()
).hexdigest()

artifacts = manifest["artifacts"]
assert [artifact["cpuTier"] for artifact in artifacts] == [
    "portable",
    "x86-64-v3",
]
assert [artifact["artifact"] for artifact in artifacts] == [
    portable_name,
    v3_name,
]
for artifact in artifacts:
    path = root / artifact["artifact"]
    assert artifact["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert artifact["requirements"]["runtimeDispatch"] is False
assert artifacts[0]["requirements"]["isaLevel"] == "x86-64"
assert artifacts[1]["requirements"]["isaLevel"] == "x86-64-v3"
assert "avx2" in artifacts[1]["requirements"]["requiredCpuFeatures"]

for archive_name, expected_binary in (
    (portable_name, b"#!/usr/bin/env sh\nprintf portable\n"),
    (v3_name, b"#!/usr/bin/env sh\nprintf x86-64-v3\n"),
):
    with tarfile.open(root / archive_name, "r:gz") as archive:
        names = set(archive.getnames())
        assert "./rust-reality" in names
        binary = archive.extractfile("./rust-reality")
        assert binary is not None
        assert binary.read() == expected_binary
PY

printf 'dual-tier deterministic package test: PASS\n'
