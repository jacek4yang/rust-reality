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

TIERS=(
    linux-x86_64-generic
    linux-x86_64-musl
    linux-x86_64-v3
    linux-aarch64-generic
)
for tier in "${TIERS[@]}"; do
    write_fake_binary "$WORK_DIRECTORY/bin/$tier" "$tier"
    chmod 0755 "$WORK_DIRECTORY/bin/$tier"
done

cat >"$WORK_DIRECTORY/bin/fake-qemu" <<'FAKE_QEMU'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$*" >>"${FAKE_QEMU_LOG:?}"
# Drop the emulated -L sysroot prefix, then exec the "foreign" binary.
if [[ ${1:-} == -L ]]; then
    shift 2
fi
exec "$@"
FAKE_QEMU
chmod 0755 "$WORK_DIRECTORY/bin/fake-qemu"

mkdir -p "$WORK_DIRECTORY/fake-tools"
cat >"$WORK_DIRECTORY/fake-tools/cargo" <<'FAKE_CARGO'
#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${1:-} == metadata ]]; then
    printf '%s\n' '{"packages":[{"name":"rust-reality","version":"9.8.7"}]}'
    exit 0
fi

printf '%s\t%s\t%s\t%s\t%s\n' \
    "${CARGO_TARGET_DIR:?}" \
    "${RUSTFLAGS:?}" \
    "${CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER:-}" \
    "${CC_x86_64_unknown_linux_musl:-}" \
    "$*" >>"${FAKE_CARGO_LOG:?}"
if [[ ${1:-} == build ]]; then
    output="$CARGO_TARGET_DIR/release"
    previous=
    for argument in "$@"; do
        if [[ $previous == --target ]]; then
            output="$CARGO_TARGET_DIR/$argument/release"
        fi
        previous=$argument
    done
    mkdir -p "$output"
    printf '#!/usr/bin/env sh\nprintf fake-release\n' \
        >"$output/rust-reality"
    chmod 0755 "$output/rust-reality"
fi
FAKE_CARGO
chmod 0755 "$WORK_DIRECTORY/fake-tools/cargo"

cat >"$WORK_DIRECTORY/fake-tools/musl-gcc" <<'FAKE_MUSL_GCC'
#!/usr/bin/env sh
exit 0
FAKE_MUSL_GCC
chmod 0755 "$WORK_DIRECTORY/fake-tools/musl-gcc"

init_fixture_repo() {
    local root=$1
    mkdir -p "$root/scripts"
    cp "$REPO_ROOT/scripts/release-matrix.sh" "$root/scripts/"
    git -C "$root" init -q -b main
    git -C "$root" config user.name release-test
    git -C "$root" config user.email release-test@example.invalid
}

test_build_release_tiers() {
    local root="$WORK_DIRECTORY/build-release"
    local log="$WORK_DIRECTORY/fake-cargo.log"
    init_fixture_repo "$root"
    cp "$REPO_ROOT/scripts/build-release.sh" "$root/scripts/"
    git -C "$root" add scripts
    git -C "$root" commit -q -m fixture

    env \
        PATH="$WORK_DIRECTORY/fake-tools:$PATH" \
        FAKE_CARGO_LOG="$log" \
        "$root/scripts/build-release.sh" linux-x86_64-generic >/dev/null
    env \
        PATH="$WORK_DIRECTORY/fake-tools:$PATH" \
        FAKE_CARGO_LOG="$log" \
        "$root/scripts/build-release.sh" linux-x86_64-musl >/dev/null
    env \
        PATH="$WORK_DIRECTORY/fake-tools:$PATH" \
        FAKE_CARGO_LOG="$log" \
        "$root/scripts/build-release.sh" linux-x86_64-v3 >/dev/null
    # The aarch64 tier is a cross build on this x86_64 host: it must demand
    # --build-only and then drive cargo with an explicit --target.
    if env \
        PATH="$WORK_DIRECTORY/fake-tools:$PATH" \
        FAKE_CARGO_LOG="$log" \
        "$root/scripts/build-release.sh" linux-aarch64-generic \
        >"$WORK_DIRECTORY/cross.out" 2>"$WORK_DIRECTORY/cross.error"; then
        printf '%s\n' 'cross tier unexpectedly ran tests without --build-only' >&2
        return 1
    fi
    grep -F 'requires --build-only' "$WORK_DIRECTORY/cross.error" >/dev/null
    env \
        PATH="$WORK_DIRECTORY/fake-tools:$PATH" \
        FAKE_CARGO_LOG="$log" \
        "$root/scripts/build-release.sh" linux-aarch64-generic --build-only \
        >/dev/null

    python3 - "$root" "$log" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
records = [line.split("\t") for line in Path(sys.argv[2]).read_text().splitlines()]
assert records == [
    [str(root / "target"), "-C target-cpu=x86-64", "", "",
     "test --workspace --release --locked"],
    [str(root / "target"), "-C target-cpu=x86-64", "", "",
     "build --workspace --release --locked"],
    [str(root / "target/x86_64-musl"), "-C target-cpu=x86-64",
     "musl-gcc", "musl-gcc",
     "test --workspace --release --locked --target x86_64-unknown-linux-musl"],
    [str(root / "target/x86_64-musl"), "-C target-cpu=x86-64",
     "musl-gcc", "musl-gcc",
     "build --workspace --release --locked --target x86_64-unknown-linux-musl"],
    [str(root / "target/x86-64-v3"), "-C target-cpu=x86-64-v3", "", "",
     "test --workspace --release --locked"],
    [str(root / "target/x86-64-v3"), "-C target-cpu=x86-64-v3", "", "",
     "build --workspace --release --locked"],
    [str(root / "target/aarch64-generic"), "-C target-cpu=generic", "", "",
     "build --workspace --release --locked --target aarch64-unknown-linux-gnu"],
], records
PY
}

test_unknown_tier_rejected() {
    local error="$WORK_DIRECTORY/unknown-tier.error"
    if "$REPO_ROOT/scripts/build-release.sh" linux-riscv64-generic \
        >"$WORK_DIRECTORY/unknown-tier.out" 2>"$error"; then
        printf '%s\n' 'unknown tier unexpectedly accepted' >&2
        return 1
    fi
    grep -F 'unknown release tier: linux-riscv64-generic' "$error" >/dev/null
    if "$REPO_ROOT/scripts/package-release.sh" v9.8.7 linux-riscv64-generic \
        "$WORK_DIRECTORY/unknown-tier-dist" \
        >"$WORK_DIRECTORY/unknown-tier-package.out" 2>"$error"; then
        printf '%s\n' 'unknown tier unexpectedly packaged' >&2
        return 1
    fi
    grep -F 'unknown release tier: linux-riscv64-generic' "$error" >/dev/null
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

test_publish_rejects_existing_prerelease() {
    local root="$WORK_DIRECTORY/prerelease-gate"
    local publish_script="$root/publish-release.sh"
    local gh_log="$root/gh.log"
    mkdir -p "$root/bin" "$root/run/dist"

    python3 - "$REPO_ROOT/.github/workflows/release.yml" "$publish_script" <<'PY'
from pathlib import Path
import sys

workflow = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
destination = Path(sys.argv[2])
step = next(i for i, line in enumerate(workflow)
            if line.strip() == "- name: Publish GitHub Release")
run = next(i for i in range(step + 1, len(workflow))
           if workflow[i].strip() == "run: |")
run_indent = len(workflow[run]) - len(workflow[run].lstrip())
body = []
for line in workflow[run + 1:]:
    indent = len(line) - len(line.lstrip())
    if line.strip() and indent <= run_indent:
        break
    body.append(line[run_indent + 2:] if line else "")
assert body, "Publish GitHub Release run block is empty"
destination.write_text("\n".join(body) + "\n", encoding="utf-8")
PY
    bash -n "$publish_script"

    cat >"$root/bin/gh" <<'FAKE_GH'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$*" >>"${FAKE_GH_LOG:?}"
if [[ ${1:-} == release && ${2:-} == view ]]; then
    printf 'false\ttrue\n'
    exit 0
fi
printf 'unexpected gh mutation: %s\n' "$*" >&2
exit 99
FAKE_GH
    chmod 0755 "$root/bin/gh"

    if (
        cd "$root/run"
        env PATH="$root/bin:$PATH" FAKE_GH_LOG="$gh_log" \
            GH_REPO=example/rust-reality GH_TOKEN=fake \
            GITHUB_REF_NAME=v9.8.7 bash "$publish_script" \
            >"$root/publish.out" 2>"$root/publish.error"
    ); then
        printf '%s\n' 'existing prerelease unexpectedly passed publish gate' >&2
        return 1
    fi
    grep -F 'refusing to publish over prerelease v9.8.7' \
        "$root/publish.error" >/dev/null
    grep -F 'release view v9.8.7' "$gh_log" >/dev/null
    if grep -Eq 'release (create|download|edit|upload)' "$gh_log"; then
        printf '%s\n' 'prerelease rejection performed a release mutation' >&2
        return 1
    fi
}

test_build_release_tiers
test_unknown_tier_rejected
test_annotated_release_tag_gate
test_publish_rejects_existing_prerelease

run_package() {
    local output=$1 tier=$2
    env \
        RUST_REALITY_RELEASE_BIN="$WORK_DIRECTORY/bin/$tier" \
        "$REPO_ROOT/scripts/package-release.sh" \
        v9.8.7 "$tier" "$output" >/dev/null
}

for tier in "${TIERS[@]}"; do
    run_package "$WORK_DIRECTORY/first" "$tier"
    run_package "$WORK_DIRECTORY/second" "$tier"
done

diff --brief --recursive "$WORK_DIRECTORY/first" "$WORK_DIRECTORY/second"

"$REPO_ROOT/scripts/aggregate-release.sh" v9.8.7 "$WORK_DIRECTORY/first" >/dev/null
"$REPO_ROOT/scripts/aggregate-release.sh" v9.8.7 "$WORK_DIRECTORY/second" >/dev/null

diff --brief --recursive "$WORK_DIRECTORY/first" "$WORK_DIRECTORY/second"
(
    cd "$WORK_DIRECTORY/first"
    sha256sum --check SHA256SUMS
)

test_aggregate_rejects_missing_tier() {
    local partial="$WORK_DIRECTORY/partial"
    local error="$WORK_DIRECTORY/partial.error"
    mkdir -p "$partial"
    run_package "$partial" linux-x86_64-generic
    if "$REPO_ROOT/scripts/aggregate-release.sh" v9.8.7 "$partial" \
        >"$WORK_DIRECTORY/partial.out" 2>"$error"; then
        printf '%s\n' 'partial matrix unexpectedly aggregated' >&2
        return 1
    fi
    grep -F 'missing aggregated release input:' "$error" >/dev/null
    [[ ! -e $partial/release-manifest.json ]]
    [[ ! -e $partial/SHA256SUMS ]]
}
test_aggregate_rejects_missing_tier

test_aggregate_rejects_unlisted_asset() {
    local poisoned="$WORK_DIRECTORY/poisoned"
    local error="$WORK_DIRECTORY/poisoned.error"
    mkdir -p "$poisoned"
    local tier
    for tier in "${TIERS[@]}"; do
        run_package "$poisoned" "$tier"
    done
    : >"$poisoned/rust-reality-v9.8.7-linux-x86_64-v4.tar.gz"
    if "$REPO_ROOT/scripts/aggregate-release.sh" v9.8.7 "$poisoned" \
        >"$WORK_DIRECTORY/poisoned.out" 2>"$error"; then
        printf '%s\n' 'unlisted asset unexpectedly aggregated' >&2
        return 1
    fi
    grep -F 'unexpected files in aggregate dist directory:' "$error" >/dev/null
    [[ ! -e $poisoned/release-manifest.json ]]
    [[ ! -e $poisoned/SHA256SUMS ]]
}
test_aggregate_rejects_unlisted_asset

python3 - "$WORK_DIRECTORY/first" "$WORK_DIRECTORY/bin" "$REPO_ROOT" <<'PY'
import hashlib
import json
import pathlib
import sys
import tarfile

root = pathlib.Path(sys.argv[1])
binary_root = pathlib.Path(sys.argv[2])
repository_root = pathlib.Path(sys.argv[3])
names = {
    "linux-x86_64-generic": "rust-reality-v9.8.7-linux-x86_64-generic.tar.gz",
    "linux-x86_64-musl": "rust-reality-v9.8.7-linux-x86_64-musl.tar.gz",
    "linux-x86_64-v3": "rust-reality-v9.8.7-linux-x86_64-v3.tar.gz",
    "linux-aarch64-generic": "rust-reality-v9.8.7-linux-aarch64-generic.tar.gz",
}
expected_files = set(names.values()) | {"release-manifest.json", "SHA256SUMS"}
actual_files = {path.name for path in root.iterdir()}
assert actual_files == expected_files, (actual_files, expected_files)

manifest = json.loads((root / "release-manifest.json").read_text())
assert manifest["schemaVersion"] == 3
assert manifest["version"] == "9.8.7"
assert manifest["tag"] == "v9.8.7"
assert manifest["compiler"].startswith("rustc "), manifest["compiler"]
assert manifest["cargoFeatures"] == ["default"]
assert len(manifest["commit"]) == 40

# Schema-v1/v2 aliases keep identifying the recommended generic asset.
generic_name = names["linux-x86_64-generic"]
assert manifest["target"] == "x86_64-unknown-linux-gnu"
assert manifest["artifact"] == generic_name
assert manifest["sha256"] == hashlib.sha256(
    (root / generic_name).read_bytes()
).hexdigest()

artifacts = manifest["artifacts"]
assert [artifact["tier"] for artifact in artifacts] == [
    "linux-x86_64-generic",
    "linux-x86_64-musl",
    "linux-x86_64-v3",
    "linux-aarch64-generic",
]
assert [artifact["cpuTier"] for artifact in artifacts] == [
    "portable",
    "portable-musl",
    "x86-64-v3",
    "aarch64-generic",
]
for artifact in artifacts:
    tier = artifact["tier"]
    path = root / names[tier]
    assert artifact["artifact"] == names[tier]
    assert artifact["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert artifact["measuredNatively"] is True
    assert artifact["requirements"]["runtimeDispatch"] is True
    assert artifact["targetCpu"] in ("x86-64", "x86-64-v3", "generic")
    assert isinstance(artifact["targetFeatures"], list)

by_tier = {artifact["tier"]: artifact for artifact in artifacts}
generic = by_tier["linux-x86_64-generic"]
musl = by_tier["linux-x86_64-musl"]
v3 = by_tier["linux-x86_64-v3"]
aarch64 = by_tier["linux-aarch64-generic"]
assert generic["target"] == "x86_64-unknown-linux-gnu"
assert generic["requirements"]["isaLevel"] == "x86-64"
assert generic["requirements"]["requiredCpuFeatures"] == ["sse2"]
assert musl["target"] == "x86_64-unknown-linux-musl"
assert musl["requirements"]["isaLevel"] == "x86-64"
assert musl["requirements"]["requiredCpuFeatures"] == ["sse2"]
assert musl["requirements"]["libc"] == "musl"
assert musl["requirements"]["linkage"] == "static"
assert musl["requirements"]["dynamicLoaderRequired"] is False
assert v3["target"] == "x86_64-unknown-linux-gnu"
assert v3["requirements"]["isaLevel"] == "x86-64-v3"
assert v3["requirements"]["requiredCpuFeatures"] == [
    "avx", "avx2", "bmi1", "bmi2", "cx16", "f16c", "fma", "lahf_lm", "lzcnt",
    "movbe", "popcnt", "sse3", "sse4_1", "sse4_2", "ssse3", "xsave",
]
assert v3["requirements"]["requiresOsAvxState"] is True
assert aarch64["target"] == "aarch64-unknown-linux-gnu"
assert aarch64["requirements"]["architecture"] == "aarch64"
assert aarch64["requirements"]["isaLevel"] == "armv8-a"
assert aarch64["requirements"]["requiredCpuFeatures"] == ["neon"]

for tier, archive_name in names.items():
    expected_binary_path = binary_root / tier
    with tarfile.open(root / archive_name, "r:gz") as archive:
        names_in_archive = set(archive.getnames())
        assert "./rust-reality" in names_in_archive
        expected_decisions = {
            f"./docs/decisions/{path.name}"
            for path in (repository_root / "docs/decisions").glob("*.md")
        }
        assert expected_decisions
        assert expected_decisions <= names_in_archive, (
            expected_decisions - names_in_archive, archive_name)
        for document_name in ("deployment.md", "deployment.zh-CN.md"):
            document_path = f"./docs/{document_name}"
            link_target = "decisions/0005-handoff-server-record-sequences.md"
            document = archive.extractfile(document_path)
            assert document is not None
            assert link_target in document.read().decode("utf-8")
            assert f"./docs/{link_target}" in names_in_archive
        index = archive.extractfile("./docs/index.md")
        assert index is not None
        assert "(decisions/)" in index.read().decode("utf-8")
        binary = archive.extractfile("./rust-reality")
        assert binary is not None
        assert binary.read() == expected_binary_path.read_bytes()
PY

# Native smoke for every tier, then an emulated smoke for the aarch64 tier
# to pin the RUST_REALITY_SMOKE_RUNNER wrapper path used by qemu jobs.
for tier in "${TIERS[@]}"; do
    env \
        RUST_REALITY_SMOKE_COVER_TARGET=127.0.0.1:9 \
        RUST_REALITY_SMOKE_SERVER_NAME=localhost \
        "$REPO_ROOT/scripts/smoke-release-assets.sh" \
        v9.8.7 "$tier" "$WORK_DIRECTORY/first" >/dev/null
done

env \
    RUST_REALITY_SMOKE_COVER_TARGET=127.0.0.1:9 \
    RUST_REALITY_SMOKE_SERVER_NAME=localhost \
    RUST_REALITY_SMOKE_RUNNER="$WORK_DIRECTORY/bin/fake-qemu -L /fake-sysroot" \
    FAKE_QEMU_LOG="$WORK_DIRECTORY/fake-qemu.log" \
    "$REPO_ROOT/scripts/smoke-release-assets.sh" \
    v9.8.7 linux-aarch64-generic "$WORK_DIRECTORY/first" \
    >"$WORK_DIRECTORY/qemu-smoke.out" 2>"$WORK_DIRECTORY/qemu-smoke.error"
grep -F 'validates functionality only, never native performance' \
    "$WORK_DIRECTORY/qemu-smoke.error" >/dev/null
grep -F 'rust-reality --version' "$WORK_DIRECTORY/fake-qemu.log" >/dev/null

printf 'release-matrix deterministic package, aggregate, and fake-binary smoke test: PASS\n'
