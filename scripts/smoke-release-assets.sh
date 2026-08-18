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
temporary_root=${TMPDIR:-/tmp}
cover_target=${RUST_REALITY_SMOKE_COVER_TARGET:-}
cover_server_name=${RUST_REALITY_SMOKE_SERVER_NAME:-}
cover_pid=
cover_start_time=

umask 077

[[ $RELEASE_TAG =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
    printf 'invalid release tag: %s\n' "$RELEASE_TAG" >&2
    exit 2
}
[[ $RELEASE_TARGET == x86_64-* ]] || {
    printf 'dual-tier smoke requires an x86_64 target: %s\n' "$RELEASE_TARGET" >&2
    exit 2
}
if [[ -n $cover_target || -n $cover_server_name ]]; then
    [[ -n $cover_target && -n $cover_server_name ]] || {
        printf '%s\n' \
            'RUST_REALITY_SMOKE_COVER_TARGET and RUST_REALITY_SMOKE_SERVER_NAME must be set together' >&2
        exit 2
    }
fi

for program in grep mktemp openssl python3 readlink sha256sum tar; do
    command -v "$program" >/dev/null 2>&1 || {
        printf 'required release-smoke program is unavailable: %s\n' "$program" >&2
        exit 1
    }
done

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

temporary_root=$(readlink -f -- "$temporary_root")
readonly temporary_root
work_directory=$(mktemp -d "$temporary_root/rust-reality-release-smoke.XXXXXX")
work_directory=$(readlink -f -- "$work_directory")
readonly work_directory

pid_start_time() {
    python3 - "$1" <<'PY'
from pathlib import Path
import sys

raw = Path(f"/proc/{sys.argv[1]}/stat").read_text()
end = raw.rfind(")")
if end < 0:
    raise SystemExit(1)
# The suffix begins with field 3 (state); field 22 is suffix index 19.
print(raw[end + 2:].split()[19])
PY
}

pid_is_owned() {
    local observed
    [[ -n $cover_pid && -n $cover_start_time && -r /proc/$cover_pid/stat ]] || return 1
    observed=$(pid_start_time "$cover_pid" 2>/dev/null) || return 1
    [[ $observed == "$cover_start_time" ]]
}

cleanup() {
    local status=$? attempt
    trap - EXIT INT TERM
    set +e
    if pid_is_owned; then
        kill -TERM "$cover_pid" 2>/dev/null || true
        for ((attempt = 0; attempt < 50; attempt++)); do
            pid_is_owned || break
            sleep 0.1
        done
        pid_is_owned && kill -KILL "$cover_pid" 2>/dev/null || true
    fi
    [[ -n $cover_pid ]] && wait "$cover_pid" 2>/dev/null || true
    if [[ -d $work_directory && $work_directory == "$temporary_root"/rust-reality-release-smoke.* ]]; then
        rm -rf -- "$work_directory"
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

start_loopback_cover() {
    local ready_file="$work_directory/cover.ready" attempt

    openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
        -subj '/CN=localhost' \
        -addext 'subjectAltName=DNS:localhost' \
        -keyout "$work_directory/cover.key" \
        -out "$work_directory/cover.crt" \
        >"$work_directory/cover-cert.log" 2>&1

    python3 - \
        "$work_directory/cover.crt" \
        "$work_directory/cover.key" \
        "$ready_file" \
        >"$work_directory/cover.log" 2>&1 <<'PY' &
import socket
import ssl
import sys
from pathlib import Path

certificate, key, ready_path = sys.argv[1:]
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.maximum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain(certificate, key)

with socket.socket() as listener:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    ready = Path(ready_path)
    ready.write_text(f"{listener.getsockname()[1]}\n", encoding="ascii")
    ready.chmod(0o600)
    while True:
        connection, _ = listener.accept()
        try:
            connection.settimeout(5)
            with context.wrap_socket(connection, server_side=True) as tls:
                tls.recv(1)
        except (ConnectionError, OSError, TimeoutError, ssl.SSLError):
            connection.close()
PY
    cover_pid=$!
    cover_start_time=$(pid_start_time "$cover_pid") || {
        printf 'cannot identify loopback cover PID %s\n' "$cover_pid" >&2
        return 1
    }

    for ((attempt = 0; attempt < 100; attempt++)); do
        [[ -s $ready_file ]] && break
        pid_is_owned || {
            printf '%s\n' 'loopback TLS cover exited before becoming ready' >&2
            return 1
        }
        sleep 0.05
    done
    [[ -s $ready_file ]] || {
        printf '%s\n' 'loopback TLS cover did not become ready' >&2
        return 1
    }
    local cover_port
    read -r cover_port <"$ready_file"
    [[ $cover_port =~ ^[1-9][0-9]{0,4}$ ]] && (( cover_port <= 65535 )) || {
        printf 'loopback TLS cover returned an invalid port: %s\n' "$cover_port" >&2
        return 1
    }
    cover_target="127.0.0.1:$cover_port"
    cover_server_name=localhost
}

# The release workflow uses a real local TLS 1.3 peer, so self-test exercises
# its live cover probe without relying on Internet reachability. The explicit
# pair of environment overrides exists only for the fake-binary regression
# harness in test-package-release.sh.
if [[ -z $cover_target ]]; then
    start_loopback_cover
fi
readonly cover_target cover_server_name

smoke_tier() {
    local tier=$1 archive=$2 listen_port=$3 directory="$work_directory/$1"
    local config_directory="$directory/config"
    local config="$config_directory/standalone.json"
    mkdir -m 700 -- "$directory"
    tar -xzf "$ASSET_DIRECTORY/$archive" -C "$directory"
    local binary="$directory/rust-reality"
    [[ -x $binary ]] || {
        printf '%s archive has no executable rust-reality\n' "$tier" >&2
        return 1
    }
    "$binary" --version | grep -Fx "rust-reality $VERSION"
    "$binary" --help >/dev/null
    "$binary" schema >"$directory/schema.json"
    python3 - "$directory/schema.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    json.load(stream)
PY
    mkdir -m 700 -- "$config_directory"
    "$binary" config generate standalone \
        --listen 127.0.0.1 \
        --port "$listen_port" \
        --target "$cover_target" \
        --server-name "$cover_server_name" \
        >"$config" 2>"$config_directory/client-values.txt"
    "$binary" check --config "$config" \
        >"$config_directory/check.txt"
    "$binary" self-test --config "$config" \
        >"$config_directory/self-test.json"
    python3 - \
        "$config_directory/self-test.json" \
        "$cover_target" \
        "$cover_server_name" <<'PY'
import json
import sys

report_path, expected_target, expected_server_name = sys.argv[1:]
with open(report_path, encoding="utf-8") as stream:
    report = json.load(stream)
assert report["configuration"] == "ok", report
assert report["routing"] == "ok", report
destinations = report["realityDestinations"]
assert len(destinations) == 1, destinations
destination = destinations[0]
assert destination["compatible"] is True, destination
assert destination["target"] == expected_target, destination
assert destination["serverName"] == expected_server_name, destination
PY
    printf '%s packaged binary smoke: PASS\n' "$tier"
}

smoke_tier portable "$PORTABLE_ARCHIVE" 19443
# Executing the binary is the authoritative CPU+OS AVX-state gate. A host that
# cannot run x86-64-v3 must fail the release instead of publishing an untested
# optimized artifact.
smoke_tier x86-64-v3 "$V3_ARCHIVE" 19444
