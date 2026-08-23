#!/usr/bin/env bash
# release-matrix.sh — canonical release tier matrix (single source of truth).
# Source it for the shell API, or execute it:
#
#   release-matrix.sh --tiers            space-separated tier ids
#   release-matrix.sh --github-matrix    GitHub Actions matrix JSON (one line,
#                                        "matrix={...}" for $GITHUB_OUTPUT)
#   release-matrix.sh --field TIER FIELD one metadata field for a tier
#
# Matrix design rationale (measured, see
# artifacts/v1.5.0/release-tiers/dispatch-inspection.md):
# - ring (default record AEAD) and the RustCrypto fallback crates already
#   dispatch AES-NI/AVX2/SHA-NI at runtime, so cpu tiers change mostly LLVM
#   codegen of the proxy's own code, not the crypto path.
# - linux-x86_64-v3 is kept as an opt-in tier with a documented "no crypto
#   advantage" expectation; the GNU generic build remains the recommended
#   asset for conventional glibc distributions.
# - linux-x86_64-musl is a baseline x86-64, fully static musl asset for
#   Alpine, other musl systems, and minimal containers. It is cross-libc
#   built on an x86_64 GNU runner, then executed directly on the same native
#   ISA; measuredNatively therefore remains true.
# - an aarch64-crypto tier (+aes,+sha2) was evaluated and DROPPED: ring does
#   HWCAP runtime dispatch on aarch64, the remaining gain is restricted to
#   non-default fallback paths, and no aarch64 hardware is available to
#   measure it (QEMU is functionality-only evidence).
# - target-cpu=native is never used: release assets must run on any host
#   meeting the documented tier baseline.
set -Eeuo pipefail

# Fields per tier (pipe-separated):
#   tier|target triple|target-cpu|extra target-features|runs-on|measuredNatively
# measuredNatively records whether validation runs on real hardware of that
# architecture (native runner); cross/qemu tiers must set it to false.
readonly RELEASE_MATRIX=(
    "linux-x86_64-generic|x86_64-unknown-linux-gnu|x86-64||ubuntu-22.04|true"
    "linux-x86_64-musl|x86_64-unknown-linux-musl|x86-64||ubuntu-22.04|true"
    "linux-x86_64-v3|x86_64-unknown-linux-gnu|x86-64-v3||ubuntu-22.04|true"
    "linux-aarch64-generic|aarch64-unknown-linux-gnu|generic||ubuntu-22.04-arm|true"
)

release_matrix_tiers() {
    local spec
    for spec in "${RELEASE_MATRIX[@]}"; do
        printf '%s\n' "${spec%%|*}"
    done
}

release_matrix_field() {
    local tier=$1 field=$2 spec rest
    for spec in "${RELEASE_MATRIX[@]}"; do
        if [[ ${spec%%|*} == "$tier" ]]; then
            rest=${spec#*|}
            case $field in
                target) cut -d '|' -f 1 <<<"$rest" ;;
                target-cpu) cut -d '|' -f 2 <<<"$rest" ;;
                target-features) cut -d '|' -f 3 <<<"$rest" ;;
                runs-on) cut -d '|' -f 4 <<<"$rest" ;;
                measured-natively) cut -d '|' -f 5 <<<"$rest" ;;
                *)
                    printf 'unknown release-matrix field: %s\n' "$field" >&2
                    return 2
                    ;;
            esac
            return 0
        fi
    done
    printf 'unknown release tier: %s (known: %s)\n' \
        "$tier" "$(release_matrix_tiers | tr '\n' ' ')" >&2
    return 1
}

# Per-tier minimum CPU requirements, as a JSON object embedded into the
# release manifest fragment. runtimeDispatch records that hot paths (record
# AEAD, SHA-2, ChaCha20, memchr) select ISA extensions beyond the static
# baseline at process start.
release_matrix_requirements_json() {
    case $1 in
        linux-x86_64-generic)
            cat <<'JSON'
{
  "architecture": "x86_64",
  "isaLevel": "x86-64",
  "requiredCpuFeatures": ["sse2"],
  "runtimeDispatch": true
}
JSON
            ;;
        linux-x86_64-musl)
            cat <<'JSON'
{
  "architecture": "x86_64",
  "isaLevel": "x86-64",
  "requiredCpuFeatures": ["sse2"],
  "runtimeDispatch": true,
  "libc": "musl",
  "linkage": "static",
  "dynamicLoaderRequired": false
}
JSON
            ;;
        linux-x86_64-v3)
            cat <<'JSON'
{
  "architecture": "x86_64",
  "isaLevel": "x86-64-v3",
  "requiredCpuFeatures": [
    "avx", "avx2", "bmi1", "bmi2", "cx16", "f16c", "fma", "lahf_lm",
    "lzcnt", "movbe", "popcnt", "sse3", "sse4_1", "sse4_2", "ssse3", "xsave"
  ],
  "requiresOsAvxState": true,
  "runtimeDispatch": true
}
JSON
            ;;
        linux-aarch64-generic)
            cat <<'JSON'
{
  "architecture": "aarch64",
  "isaLevel": "armv8-a",
  "requiredCpuFeatures": ["neon"],
  "runtimeDispatch": true
}
JSON
            ;;
        *)
            printf 'no requirements metadata for tier: %s\n' "$1" >&2
            return 1
            ;;
    esac
}

# Short tier alias kept for schema-v2 manifest consumers (cpuTier field).
release_matrix_cpu_tier_alias() {
    case $1 in
        linux-x86_64-generic) printf 'portable\n' ;;
        linux-x86_64-musl) printf 'portable-musl\n' ;;
        linux-x86_64-v3) printf 'x86-64-v3\n' ;;
        linux-aarch64-generic) printf 'aarch64-generic\n' ;;
        *)
            printf 'no cpuTier alias for tier: %s\n' "$1" >&2
            return 1
            ;;
    esac
}

# Default CARGO_TARGET_DIR per tier (relative to the repository root). The
# x86_64-generic tier keeps the plain target/ directory so it shares the
# cache with check.sh.
release_matrix_target_dir() {
    case $1 in
        linux-x86_64-generic) printf 'target\n' ;;
        linux-x86_64-musl) printf 'target/x86_64-musl\n' ;;
        linux-x86_64-v3) printf 'target/x86-64-v3\n' ;;
        linux-aarch64-generic) printf 'target/aarch64-generic\n' ;;
        *)
            printf 'no target directory mapping for tier: %s\n' "$1" >&2
            return 1
            ;;
    esac
}

release_matrix_github_json() {
    python3 - "$@" <<'PY'
import json
import sys

include = []
for spec in sys.argv[1:]:
    tier, target, cpu, features, runs_on, measured = spec.split("|")
    include.append({
        "tier": tier,
        "target": target,
        "runs-on": runs_on,
        "measured-natively": measured,
    })
print("matrix=" + json.dumps({"include": include}, separators=(",", ":")))
PY
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    case ${1:-} in
        --tiers)
            release_matrix_tiers | tr '\n' ' '
            printf '\n'
            ;;
        --github-matrix)
            release_matrix_github_json "${RELEASE_MATRIX[@]}"
            ;;
        --field)
            (($# == 3)) || {
                printf 'usage: %s --field TIER FIELD\n' "$0" >&2
                exit 2
            }
            release_matrix_field "$2" "$3"
            ;;
        *)
            printf 'usage: %s --tiers | --github-matrix | --field TIER FIELD\n' \
                "$0" >&2
            exit 2
            ;;
    esac
fi
