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

write_fake_binary() {
    local path=$1 tier=$2
    {
        printf '#!/usr/bin/env bash\n'
        printf 'set -Eeuo pipefail\n'
        printf 'readonly tier=%q\n' "$tier"
        cat <<'FAKE'
case "${1:-}" in
    --version)
        printf '%s\n' 'rust-reality 9.8.7'
        ;;
    --help)
        printf 'fake rust-reality (%s)\n' "$tier"
        ;;
    schema)
        printf '{"title":"fake schema","tier":"%s"}\n' "$tier"
        ;;
    config)
        [[ ${2:-} == generate && ${3:-} == standalone ]]
        printf '{"fakeTier":"%s"}\n' "$tier"
        printf '%s\n' 'REALITY public key for the client: fake' >&2
        ;;
    check)
        [[ ${2:-} == --config && -s ${3:-} ]]
        printf 'configuration %s is valid\n' "$3"
        ;;
    self-test)
        [[ ${2:-} == --config && -s ${3:-} ]]
        printf '%s\n' '{"configuration":"ok","routing":"ok","realityDestinations":[{"compatible":true,"target":"127.0.0.1:9","serverName":"localhost"}]}'
        ;;
    *)
        printf 'unexpected fake command: %s\n' "$*" >&2
        exit 2
        ;;
esac
FAKE
    } >"$path"
}

write_fake_binary "$WORK_DIRECTORY/bin/portable" portable
write_fake_binary "$WORK_DIRECTORY/bin/x86-64-v3" x86-64-v3
chmod 0755 "$WORK_DIRECTORY/bin/portable" "$WORK_DIRECTORY/bin/x86-64-v3"

mkdir -p "$WORK_DIRECTORY/fake-tools"
cat >"$WORK_DIRECTORY/fake-tools/cargo" <<'FAKE_CARGO'
#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${1:-} == metadata ]]; then
    printf '%s\n' '{"packages":[{"name":"rust-reality","version":"9.8.7"}]}'
    exit 0
fi

printf '%s\t%s\t%s\n' \
    "${CARGO_TARGET_DIR:?}" "${RUSTFLAGS:?}" "$*" >>"${FAKE_CARGO_LOG:?}"
if [[ ${1:-} == build ]]; then
    mkdir -p "$CARGO_TARGET_DIR/release"
    printf '#!/usr/bin/env sh\nprintf fake-release\n' \
        >"$CARGO_TARGET_DIR/release/rust-reality"
    chmod 0755 "$CARGO_TARGET_DIR/release/rust-reality"
fi
FAKE_CARGO
chmod 0755 "$WORK_DIRECTORY/fake-tools/cargo"

test_build_release_tiers() {
    local root="$WORK_DIRECTORY/build-release"
    local log="$WORK_DIRECTORY/fake-cargo.log"
    mkdir -p "$root/scripts"
    cp "$REPO_ROOT/scripts/build-release.sh" "$root/scripts/"
    git -C "$root" init -q -b main
    git -C "$root" config user.name release-test
    git -C "$root" config user.email release-test@example.invalid
    git -C "$root" add scripts/build-release.sh
    git -C "$root" commit -q -m fixture

    env \
        PATH="$WORK_DIRECTORY/fake-tools:$PATH" \
        FAKE_CARGO_LOG="$log" \
        "$root/scripts/build-release.sh" >/dev/null

    python3 - "$root" "$log" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
records = [line.split("\t") for line in Path(sys.argv[2]).read_text().splitlines()]
assert records == [
    [str(root / "target"), "-C target-cpu=x86-64",
     "test --workspace --release --locked"],
    [str(root / "target"), "-C target-cpu=x86-64",
     "build --workspace --release --locked"],
    [str(root / "target/x86-64-v3"), "-C target-cpu=x86-64-v3",
     "test --workspace --release --locked"],
    [str(root / "target/x86-64-v3"), "-C target-cpu=x86-64-v3",
     "build --workspace --release --locked"],
], records
PY
}

test_annotated_release_tag_gate() {
    local root="$WORK_DIRECTORY/tag-gate"
    local error="$WORK_DIRECTORY/lightweight-tag.error"
    mkdir -p "$root/scripts"
    cp "$REPO_ROOT/scripts/verify-release-tag.sh" "$root/scripts/"
    git -C "$root" init -q -b main
    git -C "$root" config user.name release-test
    git -C "$root" config user.email release-test@example.invalid
    git -C "$root" add scripts/verify-release-tag.sh
    git -C "$root" commit -q -m fixture
    git -C "$root" tag -a v9.8.7 -m 'annotated release fixture'
    (
        cd "$root"
        env PATH="$WORK_DIRECTORY/fake-tools:$PATH" \
            ./scripts/verify-release-tag.sh v9.8.7 main >/dev/null
    )

    git -C "$root" tag -d v9.8.7 >/dev/null
    git -C "$root" tag v9.8.7
    if (
        cd "$root"
        env PATH="$WORK_DIRECTORY/fake-tools:$PATH" \
            ./scripts/verify-release-tag.sh v9.8.7 main \
            >"$WORK_DIRECTORY/lightweight-tag.out" 2>"$error"
    ); then
        printf '%s\n' 'lightweight release tag unexpectedly passed' >&2
        return 1
    fi
    grep -F 'must be annotated' "$error" >/dev/null
}

test_build_release_tiers
test_annotated_release_tag_gate

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

python3 - "$WORK_DIRECTORY/first" "$WORK_DIRECTORY/bin" <<'PY'
import hashlib
import json
import pathlib
import sys
import tarfile

root = pathlib.Path(sys.argv[1])
binary_root = pathlib.Path(sys.argv[2])
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
assert artifacts[1]["requirements"]["requiredCpuFeatures"] == [
    "avx", "avx2", "bmi1", "bmi2", "cx16", "f16c", "fma", "lahf_lm", "lzcnt",
    "movbe", "popcnt", "sse3", "sse4_1", "sse4_2", "ssse3", "xsave",
]
assert artifacts[1]["requirements"]["requiresOsAvxState"] is True

for archive_name, expected_binary_path in (
    (portable_name, binary_root / "portable"),
    (v3_name, binary_root / "x86-64-v3"),
):
    with tarfile.open(root / archive_name, "r:gz") as archive:
        names = set(archive.getnames())
        assert "./rust-reality" in names
        binary = archive.extractfile("./rust-reality")
        assert binary is not None
        assert binary.read() == expected_binary_path.read_bytes()
PY

env \
    RUST_REALITY_SMOKE_COVER_TARGET=127.0.0.1:9 \
    RUST_REALITY_SMOKE_SERVER_NAME=localhost \
    "$REPO_ROOT/scripts/smoke-release-assets.sh" \
    v9.8.7 x86_64-unknown-linux-gnu "$WORK_DIRECTORY/first"

printf 'dual-tier deterministic package and fake-binary smoke test: PASS\n'
