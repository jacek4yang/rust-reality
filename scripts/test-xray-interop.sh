#!/usr/bin/env bash
set -euo pipefail

repository=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$repository/scripts/benchmark-contract.sh"
xray=${XRAY_BIN:-xray}
rust_bin=${RUST_REALITY_BIN:-}
cover_target=${COVER_TARGET:-www.microsoft.com:443}
cover_sni=${COVER_SNI:-www.microsoft.com}
internet_url=${INTERNET_URL:-https://www.bing.com/}
rr_contract_init "$repository" test-xray-interop diagnostics/final 16
if [[ $RR_EXPLORATORY == 1 ]]; then
    [[ $xray == /* ]] || xray=$(command -v "$xray")
fi
rr_register_binary rust-reality "$rust_bin" "${RUST_REALITY_SHA256:-}" rust \
    "${EXPECTED_SOURCE_COMMIT:-}"
rust_bin=${RR_BINARY_PATHS[rust-reality]}
rr_register_binary xray "$xray" "${XRAY_SHA256:-}" xray
xray=${RR_BINARY_PATHS[xray]}
rr_write_contract_metadata
out_dir=$RR_OUT_DIR
temporary_root=$RR_TMPDIR
work=$(mktemp -d "$temporary_root/rust-reality-xray.XXXXXX")
rust_pid=
xray_pid=
http_pid=

cleanup() {
    for pid in "$xray_pid" "$rust_pid" "$http_pid"; do
        if [[ -n "$pid" ]]; then
            rr_stop_registered_pid "$pid"
        fi
    done
    if [[ -d "$work" && "$work" == "$temporary_root"/rust-reality-xray.* ]]; then
        rm -rf -- "$work"
    fi
}
trap cleanup EXIT

unset ALL_PROXY HTTP_PROXY HTTPS_PROXY NO_PROXY all_proxy http_proxy https_proxy no_proxy

for program in "$xray" curl jq python3 sha256sum; do
    if ! command -v "$program" >/dev/null 2>&1; then
        echo "required program is unavailable: $program" >&2
        exit 1
    fi
done
free_port() { rr_next_port; }

wait_port() {
    local port=$1
    python3 - "$port" <<'PY'
import socket
import sys
import time
port = int(sys.argv[1])
deadline = time.monotonic() + 5
while time.monotonic() < deadline:
    with socket.socket() as sock:
        sock.settimeout(0.1)
        if sock.connect_ex(("127.0.0.1", port)) == 0:
            raise SystemExit(0)
    time.sleep(0.02)
raise SystemExit(f"port {port} did not become ready")
PY
}

cd "$repository"

server_port=$(free_port)
socks_port=$(free_port)
http_port=$(free_port)

"$rust_bin" config generate \
    standalone \
    --listen 127.0.0.1 \
    --port "$server_port" \
    --target "$cover_target" \
    --server-name "$cover_sni" \
    >"$work/server.raw.json" 2>"$work/generate.log"

public_key=$(sed -n 's/^REALITY public key for the client: //p' "$work/generate.log")
uuid=$(jq -r '.inbounds[0].settings.clients[0].id' "$work/server.raw.json")
short_id=$(jq -r '.inbounds[0].settings.clients[0].shortIds[0]' "$work/server.raw.json")
jq --arg cache "$work/assets" \
    '.assets.cacheDirectory = $cache | .assets.requestTimeoutSeconds = 15' \
    "$work/server.raw.json" >"$work/server.json"

"$rust_bin" serve --config "$work/server.json" \
    >"$work/rust.log" 2>&1 &
rust_pid=$!
rr_register_pid "$rust_pid" "$rust_bin"
wait_port "$server_port"

jq -n \
    --arg uuid "$uuid" \
    --arg public_key "$public_key" \
    --arg short_id "$short_id" \
    --arg server_name "$cover_sni" \
    --argjson server_port "$server_port" \
    --argjson socks_port "$socks_port" \
    '{
      log: {loglevel: "debug"},
      inbounds: [{
        tag: "socks-in",
        listen: "127.0.0.1",
        port: $socks_port,
        protocol: "socks",
        settings: {auth: "noauth", udp: false}
      }],
      outbounds: [{
        tag: "rust-reality",
        protocol: "vless",
        settings: {vnext: [{
          address: "127.0.0.1",
          port: $server_port,
          users: [{id: $uuid, encryption: "none", flow: "xtls-rprx-vision"}]
        }]},
        streamSettings: {
          network: "tcp",
          security: "reality",
          realitySettings: {
            fingerprint: "chrome",
            serverName: $server_name,
            publicKey: $public_key,
            shortId: $short_id,
            spiderX: "/"
          }
        }
      }]
    }' >"$work/xray.json"

"$xray" run -config "$work/xray.json" >"$work/xray.log" 2>&1 &
xray_pid=$!
rr_register_pid "$xray_pid" "$xray"
wait_port "$socks_port"

python3 - "$work" <<'PY'
from pathlib import Path
import sys
Path(sys.argv[1], "payload.bin").write_bytes(bytes(range(256)) * 4096)
PY
(
    cd "$work"
    python3 -m http.server "$http_port" --bind 127.0.0.1 >"$work/http.log" 2>&1
) &
http_pid=$!
rr_register_pid "$http_pid"
wait_port "$http_port"

set +e
curl --fail --silent --show-error \
    --socks5-hostname "127.0.0.1:$socks_port" \
    --max-time 10 \
    "http://127.0.0.1:$http_port/payload.bin" \
    --output "$work/download.bin"
local_status=$?
set -e

if [[ $local_status -ne 0 ]]; then
    echo "local Xray interoperability test failed: $local_status" >&2
    echo '=== rust-reality log ===' >&2
    tail -200 "$work/rust.log" >&2
    echo '=== Xray log ===' >&2
    tail -200 "$work/xray.log" >&2
    exit "$local_status"
fi

source_sha=$(sha256sum "$work/payload.bin" | awk '{print $1}')
download_sha=$(sha256sum "$work/download.bin" | awk '{print $1}')
if [[ "$source_sha" != "$download_sha" ]]; then
    echo "local Xray interoperability payload hash mismatch" >&2
    exit 1
fi

internet_result=skipped
if [[ ${SKIP_INTERNET:-0} != 1 ]]; then
    internet_result=$(curl --fail --silent --show-error \
        --socks5-hostname "127.0.0.1:$socks_port" \
        --max-time 15 \
        --output /dev/null \
        --write-out 'http=%{http_code} connect=%{time_connect} start=%{time_starttransfer} total=%{time_total}' \
        "$internet_url")
fi

mldsa_seed=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
rust_verify=$("$rust_bin" mldsa65 --seed "$mldsa_seed" | jq -r .verify)
xray_verify=$("$xray" mldsa65 -i "$mldsa_seed" | sed -n 's/^Verify: //p')
if [[ -z "$xray_verify" || "$rust_verify" != "$xray_verify" ]]; then
    echo "ML-DSA-65 differential verification-key mismatch" >&2
    exit 1
fi
mldsa_sha=$(printf %s "$rust_verify" | sha256sum | awk '{print $1}')

jq -n --arg xray_version "$($xray version | head -1)" \
    --argjson local_bytes "$(stat -c %s "$work/download.bin")" \
    --arg local_sha256 "$download_sha" --arg mldsa65_verify_sha256 "$mldsa_sha" \
    --arg internet "$internet_result" \
    '{pass:true,xrayVersion:$xray_version,localBytes:$local_bytes,
      localSha256:$local_sha256,mldsa65VerifySha256:$mldsa65_verify_sha256,
      internet:$internet}' >"$out_dir/report.json"
rr_finalize_contract
printf 'Xray interoperability report: %s\n' "$out_dir/report.json"
