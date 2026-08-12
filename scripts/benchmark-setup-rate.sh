#!/usr/bin/env bash
# Connection setup-rate A/B: measures accept -> REALITY handshake -> VLESS ->
# routing -> outbound connect -> first payload byte, as connections/sec,
# per-connection latency distribution, and server CPU per connection.
#
# Each connection is a fresh SOCKS5 -> tunnel -> HTTP/1.0 request for a tiny
# payload, so setup dominates. Server CPU is captured with perf stat on the
# server process; an Xray leg provides the reference.
#
# Env: RUST_REALITY_BIN, XRAY_BIN, SAMPLES (3), CONCURRENCIES ("1 8 32"),
#      CONNS (96 per sample per concurrency), OUT_DIR. STRACE_OUT optionally
#      enables a separate, non-authoritative syscall-attribution round while
#      keeping RUST_REALITY_BIN pinned to the exact ELF under test.
set -Eeuo pipefail

repository=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
rust_bin=${RUST_REALITY_BIN:-target/release/rust-reality}
xray=${XRAY_BIN:-../artifacts/xray-reference}
samples=${SAMPLES:-3}
concurrencies=${CONCURRENCIES:-1 8 32}
conns=${CONNS:-96}
out_dir=${OUT_DIR:-benchmarks/final/setup-rate-$(date -u +%Y%m%dT%H%M%SZ)}
strace_out=${STRACE_OUT:-}
work=$(readlink -f "$(mktemp -d "$repository/benchmarks/setup-rate.XXXXXX")")
pids=()
traced_server_pid=

cleanup() {
    if [[ $traced_server_pid =~ ^[1-9][0-9]*$ ]] && kill -0 "$traced_server_pid" 2>/dev/null; then
        kill -TERM "$traced_server_pid" 2>/dev/null || true
        for _ in {1..100}; do
            kill -0 "$traced_server_pid" 2>/dev/null || break
            sleep 0.02
        done
        if kill -0 "$traced_server_pid" 2>/dev/null; then
            kill -KILL "$traced_server_pid" 2>/dev/null || true
        fi
    fi
    for pid in "${pids[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    rm -rf -- "$work"
}
trap cleanup EXIT

for program in curl jq openssl python3 go readelf sha256sum; do
    command -v "$program" >/dev/null || { echo "missing: $program" >&2; exit 1; }
done
if [[ -n $strace_out ]]; then
    command -v strace >/dev/null || { echo "missing: strace" >&2; exit 1; }
    [[ $strace_out = /* ]] || { echo "STRACE_OUT must be absolute" >&2; exit 1; }
    [[ ! -e $strace_out ]] || { echo "STRACE_OUT already exists: $strace_out" >&2; exit 1; }
fi
sudo -n true || { echo "passwordless sudo required for perf stat" >&2; exit 1; }

cd "$repository"
[[ -x $rust_bin ]] || { echo "RUST_REALITY_BIN not executable: $rust_bin" >&2; exit 1; }
command -v "$xray" >/dev/null 2>&1 || { echo "XRAY_BIN not executable: $xray" >&2; exit 1; }
rust_bin=$(realpath "$rust_bin")
xray=$(realpath "$(command -v "$xray")")
rust_sha256=$(sha256sum "$rust_bin" | awk '{print $1}')
xray_sha256=$(sha256sum "$xray" | awk '{print $1}')
expected_rust_sha256=${RUST_REALITY_SHA256:-}
expected_xray_sha256=${XRAY_SHA256:-}
if [[ -n $expected_rust_sha256 && ${expected_rust_sha256,,} != "$rust_sha256" ]]; then
    echo "RUST_REALITY_SHA256 mismatch: expected $expected_rust_sha256, got $rust_sha256" >&2
    exit 1
fi
if [[ -n $expected_xray_sha256 && ${expected_xray_sha256,,} != "$xray_sha256" ]]; then
    echo "XRAY_SHA256 mismatch: expected $expected_xray_sha256, got $xray_sha256" >&2
    exit 1
fi
rust_build_id=$(readelf -n "$rust_bin" | awk '/Build ID:/ {print $3; exit}')
xray_build_id=$(readelf -n "$xray" | awk '/Build ID:/ {print $3; exit}')
[[ ! -e $out_dir ]] || { echo "OUT_DIR already exists: $out_dir" >&2; exit 1; }
mkdir -p "$(dirname "$out_dir")"
mkdir "$out_dir"
jq -n --arg rustBin "$rust_bin" --arg rustSha256 "$rust_sha256" \
    --arg rustBuildId "$rust_build_id" --arg xrayBin "$xray" \
    --arg xraySha256 "$xray_sha256" --arg xrayBuildId "$xray_build_id" \
    --arg startedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg concurrencies "$concurrencies" --argjson samples "$samples" \
    --argjson connectionsPerSample "$conns" --arg straceOut "$strace_out" \
    '{schemaVersion:1,startedAt:$startedAt,samples:$samples,
      connectionsPerSample:$connectionsPerSample,concurrencies:$concurrencies,
      attribution:{straceOut:(if $straceOut == "" then null else $straceOut end)},
      rustReality:{path:$rustBin,sha256:$rustSha256,buildId:$rustBuildId},
      xray:{path:$xrayBin,sha256:$xraySha256,buildId:$xrayBuildId}}' \
    >"$out_dir/environment.json"

free_port() {
    python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

wait_port() {
    python3 - "$1" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
deadline = time.monotonic() + 10
while time.monotonic() < deadline:
    with socket.socket() as sock:
        sock.settimeout(0.1)
        if sock.connect_ex(("127.0.0.1", port)) == 0:
            raise SystemExit(0)
    time.sleep(0.02)
raise SystemExit(f"port {port} did not become ready")
PY
}

http_port=$(free_port)
https_port=$(free_port)
python3 -c "open('$work/payload.bin','wb').write(bytes(range(256)))"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/o.key" -out "$work/o.crt" \
    -days 1 -subj "/CN=localhost" >/dev/null 2>&1
(cd scripts/bench-origin && go build -o "$work/bench-origin" .)
"$work/bench-origin" --port "$http_port" --payload-dir "$work" \
    --put-log "$work/put.jsonl" > "$work/origin.log" 2>&1 &
pids+=("$!")
"$work/bench-origin" --port "$https_port" --payload-dir "$work" \
    --put-log "$work/https-put.jsonl" --tls-cert "$work/o.crt" --tls-key "$work/o.key" \
    > "$work/https-origin.log" 2>&1 &
pids+=("$!")
wait_port "$http_port"
wait_port "$https_port"

rust_port=$(free_port); xray_port=$(free_port)
rust_socks=$(free_port); xray_socks=$(free_port)

"$rust_bin" config generate standalone --listen 127.0.0.1 --port "$rust_port" \
    --target "127.0.0.1:$https_port" --server-name localhost \
    > "$work/rust.raw.json" 2> "$work/gen.log"
rust_pub=$(sed -n 's/^REALITY public key for the client: //p' "$work/gen.log")
uuid=$(jq -r '.inbounds[0].settings.clients[0].id' "$work/rust.raw.json")
sid=$(jq -r '.inbounds[0].settings.clients[0].shortIds[0]' "$work/rust.raw.json")
"$xray" x25519 > "$work/keys"
xpriv=$(sed -n 's/^PrivateKey: //p' "$work/keys")
xpub=$(sed -n 's/^Password (PublicKey): //p' "$work/keys")
jq --arg c "$work/assets" '.log.level="warn" | .assets.cacheDirectory=$c' \
    "$work/rust.raw.json" > "$work/rust.json"

jq -n --arg uuid "$uuid" --arg pk "$xpriv" --arg sid "$sid" --argjson port "$xray_port" --arg target "127.0.0.1:$https_port" \
    '{log:{loglevel:"warning"},inbounds:[{listen:"127.0.0.1",port:$port,protocol:"vless",settings:{clients:[{id:$uuid,flow:"xtls-rprx-vision"}],decryption:"none"},streamSettings:{network:"tcp",security:"reality",realitySettings:{show:false,target:$target,xver:0,serverNames:["localhost"],privateKey:$pk,shortIds:[$sid]}}}],outbounds:[{tag:"direct",protocol:"freedom",settings:{finalRules:[{action:"allow"}]}}]}' \
    > "$work/xray-server.json"

make_client() {
    jq -n --arg uuid "$uuid" --arg pk "$3" --arg sid "$sid" \
        --argjson sp "$1" --argjson cp "$2" \
        '{log:{loglevel:"warning"},inbounds:[{listen:"127.0.0.1",port:$cp,protocol:"socks",settings:{auth:"noauth",udp:false}}],outbounds:[{protocol:"vless",settings:{vnext:[{address:"127.0.0.1",port:$sp,users:[{id:$uuid,encryption:"none",flow:"xtls-rprx-vision"}]}]},streamSettings:{network:"tcp",security:"reality",realitySettings:{fingerprint:"chrome",serverName:"localhost",publicKey:$pk,shortId:$sid,spiderX:"/"}}}]}' > "$4"
}
make_client "$rust_port" "$rust_socks" "$rust_pub" "$work/rust-client.json"
make_client "$xray_port" "$xray_socks" "$xpub" "$work/xray-client.json"

if [[ -n $strace_out ]]; then
    [[ $(realpath -m "$(dirname "$strace_out")") == $(realpath "$out_dir") ]] || {
        echo "STRACE_OUT must be a direct child of OUT_DIR" >&2
        exit 1
    }
    strace --kill-on-exit -f -qq -c -e trace=recvfrom,recvmsg,read \
        -o "$strace_out" "$rust_bin" serve --config "$work/rust.json" \
        > "$work/rust.log" 2>&1 &
    pids+=("$!"); strace_pid=$!
    rust_pid=
    for _ in {1..250}; do
        if [[ -r /proc/$strace_pid/task/$strace_pid/children ]]; then
            for child in $(</proc/$strace_pid/task/$strace_pid/children); do
                if [[ $(readlink -f "/proc/$child/exe" 2>/dev/null || true) == "$rust_bin" ]]; then
                    rust_pid=$child
                    break 2
                fi
            done
        fi
        sleep 0.02
    done
    [[ $rust_pid =~ ^[1-9][0-9]*$ ]] || {
        echo "could not identify the straced rust-reality child" >&2
        exit 1
    }
    [[ $(sha256sum "/proc/$rust_pid/exe" | awk '{print $1}') == "$rust_sha256" ]] || {
        echo "straced server ELF identity mismatch" >&2
        exit 1
    }
    traced_server_pid=$rust_pid
else
    "$rust_bin" serve --config "$work/rust.json" > "$work/rust.log" 2>&1 &
    pids+=("$!"); rust_pid=$!
fi
"$xray" run -config "$work/xray-server.json" > "$work/xray-server.log" 2>&1 &
pids+=("$!"); xray_pid=$!
"$xray" run -config "$work/rust-client.json" > /dev/null 2>&1 &
pids+=("$!")
"$xray" run -config "$work/xray-client.json" > /dev/null 2>&1 &
pids+=("$!")
wait_port "$rust_socks"; wait_port "$xray_socks"

run_leg() {
    local label=$1 socks_port=$2 server_pid=$3
    sudo -n perf stat -e task-clock,instructions,context-switches -p "$server_pid" \
        -o "$out_dir/perf-$label.txt" -- \
        python3 - "$samples" "$conns" "$socks_port" "$http_port" "$label" \
                  "$concurrencies" "$out_dir/samples-$label.json" <<'PY'
import concurrent.futures
import json
import os
import statistics
import subprocess
import sys
import time

samples, conns, socks_port, http_port, label = (
    int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5])
concurrencies = [int(c) for c in sys.argv[6].split()]
samples_out = sys.argv[7]
url = f"http://127.0.0.1:{http_port}/payload.bin"
curl_env = {k: v for k, v in os.environ.items()
            if k.lower() not in ("all_proxy", "http_proxy", "https_proxy", "no_proxy")}

def one_connection(_):
    # Raw SOCKS5 + HTTP/1.0 on a plain socket: no subprocess, so the
    # measurement is connection setup, not curl startup.
    import socket
    started = time.perf_counter()
    try:
        with socket.create_connection(("127.0.0.1", socks_port), timeout=30) as sock:
            target = f"127.0.0.1:{http_port}"
            request = (
                b"\x05\x01\x00"  # greeting: no auth
            )
            sock.sendall(request)
            if sock.recv(2) != b"\x05\x00":
                return None
            host, port = target.rsplit(":", 1)
            ip = bytes(int(x) for x in host.split("."))
            sock.sendall(b"\x05\x01\x00\x01" + ip + int(port).to_bytes(2, "big"))
            reply = sock.recv(10)
            if len(reply) < 10 or reply[1] != 0:
                return None
            sock.sendall(f"GET /payload.bin HTTP/1.0\r\nHost: {target}\r\n\r\n".encode())
            first = sock.recv(4096)
            if not first:
                return None
        return time.perf_counter() - started
    except OSError:
        return None

out = []
for conc in concurrencies:
    one_connection(0)  # warm the client and server paths
    for sample in range(samples):
        wall0 = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=conc) as ex:
            latencies = [x for x in ex.map(one_connection, range(conns))]
        wall = time.perf_counter() - wall0
        good = [x for x in latencies if x is not None]
        if not good:
            continue
        ordered = sorted(good)
        p = lambda f: ordered[min(len(ordered)-1, int(len(ordered)*f))]
        out.append({
            "implementation": label, "concurrency": conc, "sampleIndex": sample,
            "wallSeconds": wall, "connections": len(good), "failed": len(latencies)-len(good),
            "connectionsPerSecond": len(good) / wall,
            "p50Seconds": p(0.50), "p95Seconds": p(0.95), "p99Seconds": p(0.99),
        })
with open(samples_out, "w") as fh:
    json.dump(out, fh)
for conc in concurrencies:
    cells = [x for x in out if x["concurrency"] == conc]
    if cells:
        print(f"{label} c{conc}: " + "; ".join(
            f"{x['connectionsPerSecond']:.0f} conn/s (p50 {x['p50Seconds']*1000:.0f}ms, "
            f"p99 {x['p99Seconds']*1000:.0f}ms, fail {x['failed']})" for x in cells))
PY
    jq -e --argjson samples "$samples" --argjson conns "$conns" \
        --arg concurrencies "$concurrencies" '
        ($concurrencies | split(" ") | map(select(length > 0) | tonumber)) as $cs
        | length == ($samples * ($cs | length))
        and all(.[];
            .connections == $conns
            and .failed == 0
            and (.concurrency as $c | $cs | index($c) != null)
        )
    ' "$out_dir/samples-$label.json" >/dev/null || {
        echo "$label setup samples are incomplete or contain failures" >&2
        return 1
    }
}

run_leg rust "$rust_socks" "$rust_pid"
run_leg xray "$xray_socks" "$xray_pid"
