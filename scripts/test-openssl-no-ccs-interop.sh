#!/usr/bin/env bash
# Canonical local interoperability gate for a TLS 1.3 cover target that omits
# the server middlebox-compatibility CCS.
#
# Required absolute paths: RUST_REALITY_BIN, XRAY_BIN, OPENSSL_BIN, OUT_DIR.
# RUN_ID is also required. Optional identity pins: RUST_REALITY_SHA256,
# XRAY_SHA256. The script never builds either measured binary.
set -Eeuo pipefail

repository=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
run_id=${RUN_ID:-}
rust_bin=${RUST_REALITY_BIN:-}
xray_bin=${XRAY_BIN:-}
openssl_bin=${OPENSSL_BIN:-}
out_dir=${OUT_DIR:-}
expected_rust_sha256=${RUST_REALITY_SHA256:-}
expected_xray_sha256=${XRAY_SHA256:-}

die() {
    printf '%s\n' "$*" >&2
    exit 1
}

[[ -n $run_id ]] || die 'RUN_ID is required'
[[ $run_id =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] \
    || die 'RUN_ID must contain only ASCII letters, digits, dot, underscore, or dash'
for name in RUST_REALITY_BIN XRAY_BIN OPENSSL_BIN OUT_DIR; do
    value=${!name:-}
    [[ $value == /* ]] || die "$name must be an absolute path"
done
[[ -x $rust_bin ]] || die "RUST_REALITY_BIN is not executable: $rust_bin"
[[ -x $xray_bin ]] || die "XRAY_BIN is not executable: $xray_bin"
[[ -x $openssl_bin ]] || die "OPENSSL_BIN is not executable: $openssl_bin"
[[ ! -e $out_dir && ! -L $out_dir ]] || die "OUT_DIR already exists: $out_dir"

for program in curl jq python3 sha256sum stat; do
    command -v "$program" >/dev/null 2>&1 || die "required program is unavailable: $program"
done

# Start from an empty ambient override. The ephemeral CA is injected later
# into the rust-reality server child only.
unset SSL_CERT_FILE

validate_expected_sha256() {
    local label=$1 expected=$2 actual=$3
    [[ -z $expected || $expected =~ ^[[:xdigit:]]{64}$ ]] \
        || die "$label expected SHA-256 is not 64 hexadecimal characters"
    if [[ -n $expected && ${expected,,} != "$actual" ]]; then
        die "$label SHA-256 mismatch: expected $expected, got $actual"
    fi
}

rust_bin=$(readlink -f -- "$rust_bin")
xray_bin=$(readlink -f -- "$xray_bin")
openssl_bin=$(readlink -f -- "$openssl_bin")
rust_sha256=$(sha256sum "$rust_bin" | awk '{print $1}')
xray_sha256=$(sha256sum "$xray_bin" | awk '{print $1}')
openssl_sha256=$(sha256sum "$openssl_bin" | awk '{print $1}')
validate_expected_sha256 RUST_REALITY_BIN "$expected_rust_sha256" "$rust_sha256"
validate_expected_sha256 XRAY_BIN "$expected_xray_sha256" "$xray_sha256"

openssl_version=$("$openssl_bin" version)
[[ $openssl_version == 'OpenSSL 3.5.6 '* ]] \
    || die "OPENSSL_BIN must be the validated OpenSSL 3.5.6 build, got: $openssl_version"

mkdir -m 700 -- "$out_dir"
temporary_root=${TMPDIR:-/tmp}
[[ $temporary_root == /* ]] || die 'TMPDIR must be an absolute path'
work=$(mktemp -d "$temporary_root/rust-reality-openssl-no-ccs.XXXXXX")
rust_pid=
xray_pid=
openssl_pid=
http_pid=

stop_pid() {
    local pid=${1:-}
    [[ -n $pid ]] || return 0
    if kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null || true
        for _ in {1..50}; do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.02
        done
        if kill -0 "$pid" 2>/dev/null; then
            kill -KILL "$pid" 2>/dev/null || true
        fi
    fi
    wait "$pid" 2>/dev/null || true
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    stop_pid "$xray_pid"
    stop_pid "$rust_pid"
    stop_pid "$openssl_pid"
    stop_pid "$http_pid"
    if [[ -d $work && $work == "$temporary_root"/rust-reality-openssl-no-ccs.* ]]; then
        rm -rf -- "$work"
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

free_ports() {
    python3 - <<'PY'
import socket

sockets = []
try:
    for _ in range(4):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sockets.append(sock)
    print(*(sock.getsockname()[1] for sock in sockets))
finally:
    for sock in sockets:
        sock.close()
PY
}

wait_port() {
    local port=$1 pid=$2
    python3 - "$port" "$pid" <<'PY'
import os
import socket
import sys
import time

port, pid = int(sys.argv[1]), int(sys.argv[2])
deadline = time.monotonic() + 10
while time.monotonic() < deadline:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        raise SystemExit(f"process {pid} exited before port {port} became ready")
    with socket.socket() as sock:
        sock.settimeout(0.1)
        if sock.connect_ex(("127.0.0.1", port)) == 0:
            raise SystemExit(0)
    time.sleep(0.02)
raise SystemExit(f"port {port} did not become ready")
PY
}

clean_curl() {
    env -u ALL_PROXY -u all_proxy -u HTTP_PROXY -u http_proxy \
        -u HTTPS_PROXY -u https_proxy -u NO_PROXY -u no_proxy curl "$@"
}

read -r cover_port server_port socks_port http_port < <(free_ports)

# Use a dedicated self-signed CA and a SAN-bearing server leaf. The CA is
# exposed only to the rust-reality child through SSL_CERT_FILE below.
"$openssl_bin" req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
    -subj "/CN=rust-reality no-CCS test CA $run_id" \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout "$work/ca.key" -out "$work/ca.crt" >"$work/ca-generate.log" 2>&1
"$openssl_bin" req -new -newkey rsa:2048 -nodes -sha256 \
    -subj '/CN=localhost' \
    -addext 'basicConstraints=critical,CA:FALSE' \
    -addext 'keyUsage=critical,digitalSignature,keyEncipherment' \
    -addext 'extendedKeyUsage=serverAuth' \
    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
    -keyout "$work/server.key" -out "$work/server.csr" \
    >"$work/server-csr.log" 2>&1
"$openssl_bin" x509 -req -sha256 -days 1 \
    -in "$work/server.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" \
    -CAcreateserial -copy_extensions copy -out "$work/server.crt" \
    >"$work/server-sign.log" 2>&1
"$openssl_bin" verify -CAfile "$work/ca.crt" -verify_hostname localhost \
    "$work/server.crt" >"$out_dir/certificate-verify.log" 2>&1
"$openssl_bin" x509 -in "$work/server.crt" -noout -ext subjectAltName \
    >"$out_dir/certificate-san.txt"
grep -Fq 'DNS:localhost' "$out_dir/certificate-san.txt" \
    || die 'server certificate is missing DNS:localhost SAN'
grep -Fq 'IP Address:127.0.0.1' "$out_dir/certificate-san.txt" \
    || die 'server certificate is missing IP:127.0.0.1 SAN'

"$openssl_bin" s_server -accept "127.0.0.1:$cover_port" -www -ign_eof \
    -cert "$work/server.crt" -key "$work/server.key" -CAfile "$work/ca.crt" \
    -tls1_3 -no_middlebox -alpn 'h2,http/1.1' -trace -msg -state \
    >"$out_dir/openssl-trace.log" 2>&1 &
openssl_pid=$!
wait_port "$cover_port" "$openssl_pid"

cd "$repository"
"$rust_bin" config generate standalone \
    --listen 127.0.0.1 --port "$server_port" \
    --target "localhost:$cover_port" --server-name localhost \
    >"$work/server.raw.json" 2>"$work/generate.log"
public_key=$(sed -n 's/^REALITY public key for the client: //p' "$work/generate.log")
uuid=$(jq -r '.inbounds[0].settings.clients[0].id' "$work/server.raw.json")
short_id=$(jq -r '.inbounds[0].settings.clients[0].shortIds[0]' "$work/server.raw.json")
[[ -n $public_key && $uuid != null && $short_id != null ]] \
    || die 'generated REALITY client parameters are incomplete'
jq --arg cache "$work/assets" \
    '.log.level = "warn" | .assets.cacheDirectory = $cache | .assets.requestTimeoutSeconds = 15' \
    "$work/server.raw.json" >"$work/server.json"

# Do not export SSL_CERT_FILE: no sibling process may inherit this private
# test trust root. Only the cover-probing server child receives it.
env SSL_CERT_FILE="$work/ca.crt" "$rust_bin" serve --config "$work/server.json" \
    >"$out_dir/rust-reality.log" 2>&1 &
rust_pid=$!
wait_port "$server_port" "$rust_pid"

jq -n \
    --arg uuid "$uuid" --arg public_key "$public_key" --arg short_id "$short_id" \
    --argjson server_port "$server_port" --argjson socks_port "$socks_port" \
    '{
      log:{loglevel:"debug"},
      inbounds:[{listen:"127.0.0.1",port:$socks_port,protocol:"socks",
        settings:{auth:"noauth",udp:false}}],
      outbounds:[{protocol:"vless",settings:{vnext:[{address:"127.0.0.1",
        port:$server_port,users:[{id:$uuid,encryption:"none",flow:"xtls-rprx-vision"}]}]},
        streamSettings:{network:"tcp",security:"reality",realitySettings:{
          fingerprint:"chrome",serverName:"localhost",publicKey:$public_key,
          shortId:$short_id,spiderX:"/"}}}]
    }' >"$work/xray.json"
"$xray_bin" run -config "$work/xray.json" >"$out_dir/xray.log" 2>&1 &
xray_pid=$!
wait_port "$socks_port" "$xray_pid"

python3 - "$work/payload.bin" <<'PY'
from pathlib import Path
import sys

Path(sys.argv[1]).write_bytes(bytes(range(256)) * 4096)
PY
(
    cd "$work"
    exec python3 -m http.server "$http_port" --bind 127.0.0.1
) >"$out_dir/http-origin.log" 2>&1 &
http_pid=$!
wait_port "$http_port" "$http_pid"

clean_curl --fail --silent --show-error \
    --socks5-hostname "127.0.0.1:$socks_port" --max-time 20 \
    "http://127.0.0.1:$http_port/payload.bin" --output "$work/download.bin"
source_sha256=$(sha256sum "$work/payload.bin" | awk '{print $1}')
download_sha256=$(sha256sum "$work/download.bin" | awk '{print $1}')
[[ $(stat -c %s "$work/download.bin") == 1048576 ]] \
    || die 'Xray interoperability download is not exactly 1 MiB'
[[ $source_sha256 == "$download_sha256" ]] \
    || die 'Xray interoperability payload SHA-256 mismatch'

mldsa_seed=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
rust_verify=$("$rust_bin" mldsa65 --seed "$mldsa_seed" | jq -r .verify)
xray_verify=$("$xray_bin" mldsa65 -i "$mldsa_seed" | sed -n 's/^Verify: //p')
[[ -n $xray_verify && $rust_verify == "$xray_verify" ]] \
    || die 'ML-DSA-65 differential verification-key mismatch'
mldsa_sha256=$(printf %s "$rust_verify" | sha256sum | awk '{print $1}')

# Stop s_server explicitly so stdio is flushed before inspecting the retained
# trace. Match only server-to-client message lines (`>>>`); client messages are
# irrelevant to the middlebox-compatibility assertion.
stop_pid "$openssl_pid"
openssl_pid=
grep -Eq '^[[:space:]]*>>> .*ServerHello' "$out_dir/openssl-trace.log" \
    || die 'OpenSSL trace has no server-direction ServerHello'
if grep -Eq '^[[:space:]]*>>> .*ChangeCipherSpec' "$out_dir/openssl-trace.log"; then
    die 'OpenSSL -no_middlebox emitted a server-direction ChangeCipherSpec'
fi

final_rust_sha256=$(sha256sum "$rust_bin" | awk '{print $1}')
final_xray_sha256=$(sha256sum "$xray_bin" | awk '{print $1}')
[[ $final_rust_sha256 == "$rust_sha256" ]] || die 'RUST_REALITY_BIN changed during the run'
[[ $final_xray_sha256 == "$xray_sha256" ]] || die 'XRAY_BIN changed during the run'

jq -n \
    --arg run_id "$run_id" --arg completed_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg rust_bin "$rust_bin" --arg rust_sha256 "$rust_sha256" \
    --arg xray_bin "$xray_bin" --arg xray_sha256 "$xray_sha256" \
    --arg openssl_bin "$openssl_bin" --arg openssl_sha256 "$openssl_sha256" \
    --arg openssl_version "$openssl_version" --arg payload_sha256 "$download_sha256" \
    --arg mldsa_sha256 "$mldsa_sha256" --argjson cover_port "$cover_port" \
    --argjson server_port "$server_port" --argjson socks_port "$socks_port" \
    --argjson http_port "$http_port" \
    '{schemaVersion:1,runId:$run_id,completedAt:$completed_at,
      rustReality:{path:$rust_bin,sha256:$rust_sha256,immutableDuringRun:true},
      xray:{path:$xray_bin,sha256:$xray_sha256,immutableDuringRun:true},
      openssl:{path:$openssl_bin,sha256:$openssl_sha256,version:$openssl_version,
        tls:"1.3",middlebox:false,alpn:["h2","http/1.1"]},
      topology:{address:"127.0.0.1",ports:{cover:$cover_port,reality:$server_port,
        socks:$socks_port,origin:$http_port}},
      certificate:{authority:"ephemeral self-signed CA",leafSan:["DNS:localhost","IP:127.0.0.1"],
        trustInjection:"rust-reality child SSL_CERT_FILE only"},
      assertions:{serverHello:true,serverChangeCipherSpec:false,
        payloadBytes:1048576,payloadSha256:$payload_sha256,
        mldsa65VerifySha256:$mldsa_sha256},trace:"openssl-trace.log",ok:true}' \
    >"$out_dir/summary.json"

printf 'run_id=%s\n' "$run_id"
printf 'result=PASS\n'
printf 'summary=%s/summary.json\n' "$out_dir"
