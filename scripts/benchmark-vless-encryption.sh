#!/usr/bin/env bash
# Xray v26.7.28-compatible A/B for the exact deployment considered here:
# VLESS + REALITY + Vision with `encryption:none` versus VLESS Encryption
# inside the same REALITY transport. Measures TLS payload throughput, server
# CPU/GiB, and fresh-connection setup after a warm-up makes 0-RTT available.
#
# Env: XRAY_BIN (xray), SAMPLES (5), CONCURRENCY (4), PAYLOAD_MIB (64),
#      SETUP_CONNECTIONS (128), SETUP_CONCURRENCY (8), OUT_DIR, KEEP_WORK (0).
set -Eeuo pipefail

repository=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$repository/scripts/benchmark-contract.sh"
xray=${XRAY_BIN:-xray}
samples=${SAMPLES:-5}
concurrency=${CONCURRENCY:-4}
payload_mib=${PAYLOAD_MIB:-64}
setup_connections=${SETUP_CONNECTIONS:-128}
setup_concurrency=${SETUP_CONCURRENCY:-8}
xray_log_level=${XRAY_LOG_LEVEL:-warning}
transfer_timeout=${TRANSFER_TIMEOUT:-120}
cover_target=${COVER_TARGET:-dl.google.com:443}
cover_sni=${COVER_SNI:-dl.google.com}
rr_contract_init "$repository" benchmark-vless-encryption benchmarks/final 16
if [[ $RR_EXPLORATORY == 1 ]]; then
    [[ $xray == /* ]] || xray=$(command -v "$xray")
fi
rr_register_binary xray "$xray" "${XRAY_SHA256:-}" xray
xray=${RR_BINARY_PATHS[xray]}
rr_write_contract_metadata
out_dir=$RR_OUT_DIR
temporary_root=$RR_TMPDIR
work=$(mktemp -d "$temporary_root/rust-reality-vless-encryption.XXXXXX")
pids=()

cleanup() {
    local exit_status=$?
    trap - EXIT
    set +e
    for pid in "${pids[@]}"; do
        rr_stop_registered_pid "$pid"
    done
    if [[ ${KEEP_WORK:-0} == 1 ]]; then
        printf 'benchmark temporary directory retained: %s\n' "$work" >&2
    elif [[ -d $work && $work == "$temporary_root"/rust-reality-vless-encryption.* ]]; then
        rm -rf -- "$work"
    fi
    local final_rc
    rr_contract_verify_on_exit "$exit_status"
    final_rc=$?
    exit "$final_rc"
}
trap cleanup EXIT

for program in "$xray" curl jq openssl python3; do
    command -v "$program" >/dev/null 2>&1 || {
        echo "required program is unavailable: $program" >&2
        exit 1
    }
done
for value in "$samples" "$concurrency" "$payload_mib" "$setup_connections" "$setup_concurrency"; do
    [[ $value =~ ^[1-9][0-9]*$ ]] || { echo "benchmark bounds must be positive integers" >&2; exit 1; }
done
[[ $transfer_timeout =~ ^[1-9][0-9]*$ ]] || { echo "TRANSFER_TIMEOUT must be a positive integer" >&2; exit 1; }
if (( samples > 100 || concurrency > 64 || payload_mib > 1024 || setup_connections > 10000 || setup_concurrency > 256 )); then
    echo "benchmark bounds exceeded" >&2
    exit 1
fi

free_port() { rr_next_port; }

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

start_process() {
    "$@" &
    started_pid=$!
    pids+=("$started_pid")
    local expected=
    [[ $1 == "$xray" ]] && expected=$xray
    rr_register_pid "$started_pid" "$expected"
}

cd "$repository"
none_server_port=$(free_port)
encrypted_server_port=$(free_port)
none_socks_port=$(free_port)
encrypted_socks_port=$(free_port)
https_port=$(free_port)
http_port=$(free_port)

uuid=$("$xray" uuid | tail -n 1)
short_id=$(openssl rand -hex 8)
"$xray" x25519 >"$work/reality.keys"
reality_private=$(sed -n 's/^PrivateKey: //p' "$work/reality.keys")
reality_public=$(sed -n 's/^Password (PublicKey): //p' "$work/reality.keys")
"$xray" vlessenc >"$work/vlessenc.keys"
decryption=$(sed -n 's/^"decryption": "\(.*\)"$/\1/p' "$work/vlessenc.keys" | head -n 1)
encryption=$(sed -n 's/^"encryption": "\(.*\)"$/\1/p' "$work/vlessenc.keys" | head -n 1)
[[ -n $uuid && -n $reality_private && -n $reality_public && -n $decryption && -n $encryption ]] || {
    echo "Xray key generation output was not understood" >&2
    exit 1
}

python3 - "$work/payload.bin" "$payload_mib" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
remaining = int(sys.argv[2]) * 1024 * 1024
chunk = bytes(range(256)) * 4096
with path.open("wb") as output:
    while remaining:
        part = chunk[:min(len(chunk), remaining)]
        output.write(part)
        remaining -= len(part)
(path.parent / "tiny.bin").write_bytes(bytes(range(256)))
PY
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$work/origin.key" -out "$work/origin.crt" \
    -days 1 -subj "/CN=localhost" >/dev/null 2>&1

python3 - "$https_port" "$work" >"$work/https.log" 2>&1 <<'PY' &
import functools, http.server, ssl, sys
port, directory = int(sys.argv[1]), sys.argv[2]
handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=directory)
server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.maximum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain(f"{directory}/origin.crt", f"{directory}/origin.key")
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PY
origin_tls_pid=$!
pids+=("$origin_tls_pid")
rr_register_pid "$origin_tls_pid"
python3 -m http.server "$http_port" --bind 127.0.0.1 --directory "$work" \
    >"$work/http.log" 2>&1 &
origin_http_pid=$!
pids+=("$origin_http_pid")
rr_register_pid "$origin_http_pid"
wait_port "$https_port"
wait_port "$http_port"

make_server() {
    local port=$1 mode=$2 output=$3
    jq -n \
        --arg uuid "$uuid" --arg private_key "$reality_private" \
        --arg short_id "$short_id" --arg decryption "$mode" \
        --arg target "$cover_target" --arg server_name "$cover_sni" \
        --arg level "$xray_log_level" --argjson port "$port" \
        '{
          log: {loglevel: $level},
          inbounds: [{
            listen: "127.0.0.1", port: $port, protocol: "vless",
            settings: {
              clients: [{id: $uuid, flow: "xtls-rprx-vision"}],
              decryption: $decryption
            },
            streamSettings: {
              network: "tcp", security: "reality",
              realitySettings: {
                show: false, target: $target, xver: 0,
                serverNames: [$server_name], privateKey: $private_key,
                shortIds: [$short_id]
              }
            }
          }],
          outbounds: [{
            tag: "direct", protocol: "freedom",
            settings: {finalRules: [{action: "allow"}]}
          }]
        }' >"$output"
}

make_client() {
    local server_port=$1 socks_port=$2 mode=$3 output=$4
    jq -n \
        --arg uuid "$uuid" --arg public_key "$reality_public" \
        --arg short_id "$short_id" --arg encryption "$mode" --arg level "$xray_log_level" \
        --arg server_name "$cover_sni" \
        --argjson server_port "$server_port" --argjson socks_port "$socks_port" \
        '{
          log: {loglevel: $level},
          inbounds: [{
            listen: "127.0.0.1", port: $socks_port, protocol: "socks",
            settings: {auth: "noauth", udp: false}
          }],
          outbounds: [{
            protocol: "vless",
            settings: {vnext: [{
              address: "127.0.0.1", port: $server_port,
              users: [{id: $uuid, encryption: $encryption, flow: "xtls-rprx-vision"}]
            }]},
            streamSettings: {
              network: "tcp", security: "reality",
              realitySettings: {
                fingerprint: "chrome", serverName: $server_name,
                publicKey: $public_key, shortId: $short_id, spiderX: "/"
              }
            }
          }]
        }' >"$output"
}

make_server "$none_server_port" none "$work/server-none.json"
make_server "$encrypted_server_port" "$decryption" "$work/server-encrypted.json"
make_client "$none_server_port" "$none_socks_port" none "$work/client-none.json"
make_client "$encrypted_server_port" "$encrypted_socks_port" "$encryption" "$work/client-encrypted.json"

start_process "$xray" run -config "$work/server-none.json" >"$work/server-none.log" 2>&1
none_server_pid=$started_pid
start_process "$xray" run -config "$work/server-encrypted.json" >"$work/server-encrypted.log" 2>&1
encrypted_server_pid=$started_pid
wait_port "$none_server_port"
wait_port "$encrypted_server_port"
start_process "$xray" run -config "$work/client-none.json" >"$work/client-none.log" 2>&1
start_process "$xray" run -config "$work/client-encrypted.json" >"$work/client-encrypted.log" 2>&1
wait_port "$none_socks_port"
wait_port "$encrypted_socks_port"

report=$out_dir/report.json
python3 - \
    "$samples" "$concurrency" "$payload_mib" "$setup_connections" "$setup_concurrency" \
    "$none_socks_port" "$encrypted_socks_port" "$https_port" "$http_port" \
    "$none_server_pid" "$encrypted_server_pid" "$transfer_timeout" "$xray" >"$report" <<'PY'
import concurrent.futures, json, math, os, platform, random, socket, statistics, subprocess, sys, time

(samples, concurrency, payload_mib, setup_connections, setup_concurrency,
 none_socks, encrypted_socks, https_port, http_port, none_pid, encrypted_pid,
 transfer_timeout) = map(int, sys.argv[1:13])
xray = sys.argv[13]
ports = {"none": none_socks, "vless-encryption": encrypted_socks}
pids = {"none": none_pid, "vless-encryption": encrypted_pid}
expected = payload_mib * 1024 * 1024
curl_env = {k: v for k, v in os.environ.items()
            if k.lower() not in ("all_proxy", "http_proxy", "https_proxy", "no_proxy")}
clock_ticks = os.sysconf("SC_CLK_TCK")

def cpu_seconds(pid):
    text = open(f"/proc/{pid}/stat", encoding="ascii").read()
    fields = text[text.rfind(")") + 2:].split()
    return (int(fields[11]) + int(fields[12])) / clock_ticks

def transfer(port):
    completed = subprocess.run([
        "curl", "--fail", "--silent", "--show-error", "--insecure", "--tlsv1.3",
        "--socks5-hostname", f"127.0.0.1:{port}", "--max-time", str(transfer_timeout),
        "--output", os.devnull, "--write-out", "%{size_download} %{time_total}",
        f"https://127.0.0.1:{https_port}/payload.bin",
    ], check=True, capture_output=True, text=True, env=curl_env)
    size, elapsed = completed.stdout.split()
    if int(size) != expected:
        raise RuntimeError(f"payload length mismatch: {size} != {expected}")
    return float(elapsed)

def throughput_sample(name):
    cpu0 = cpu_seconds(pids[name])
    wall0 = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        latencies = list(executor.map(lambda _: transfer(ports[name]), range(concurrency)))
    wall = time.perf_counter() - wall0
    cpu = cpu_seconds(pids[name]) - cpu0
    gib = payload_mib * concurrency / 1024
    return {
        "mode": name, "wallSeconds": wall,
        "meanRequestSeconds": statistics.fmean(latencies),
        "throughputMiBPerSecond": payload_mib * concurrency / wall,
        "serverCpuSeconds": cpu, "serverCpuSecondsPerGiB": cpu / gib,
    }

def recv_exact(sock, length):
    output = bytearray()
    while len(output) < length:
        part = sock.recv(length - len(output))
        if not part:
            raise OSError("unexpected EOF")
        output.extend(part)
    return bytes(output)

def setup_once(port):
    started = time.perf_counter()
    with socket.create_connection(("127.0.0.1", port), timeout=30) as sock:
        sock.sendall(b"\x05\x01\x00")
        if recv_exact(sock, 2) != b"\x05\x00":
            raise OSError("SOCKS authentication failed")
        sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + http_port.to_bytes(2, "big"))
        reply = recv_exact(sock, 10)
        if reply[1] != 0:
            raise OSError("SOCKS connect failed")
        sock.sendall(b"GET /tiny.bin HTTP/1.0\r\nHost: localhost\r\n\r\n")
        if not sock.recv(4096):
            raise OSError("empty HTTP response")
    return time.perf_counter() - started

def setup_sample(name):
    cpu0 = cpu_seconds(pids[name])
    wall0 = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=setup_concurrency) as executor:
        latencies = list(executor.map(lambda _: setup_once(ports[name]), range(setup_connections)))
    wall = time.perf_counter() - wall0
    cpu = cpu_seconds(pids[name]) - cpu0
    ordered = sorted(latencies)
    percentile = lambda f: ordered[max(0, math.ceil(len(ordered) * f) - 1)]
    return {
        "mode": name, "connections": len(latencies), "wallSeconds": wall,
        "connectionsPerSecond": len(latencies) / wall,
        "p50Milliseconds": percentile(0.50) * 1000,
        "p95Milliseconds": percentile(0.95) * 1000,
        "serverCpuMicrosecondsPerConnection": cpu * 1_000_000 / len(latencies),
    }

# Warm both paths. For VLESS Encryption this also obtains the reusable ticket,
# so the measured setup path is its intended best-case 0-RTT mode.
for mode in ports:
    transfer(ports[mode])
    setup_once(ports[mode])

order = [mode for _ in range(samples) for mode in ports]
random.Random(0x564C4553).shuffle(order)
throughput = [throughput_sample(mode) for mode in order]
setup = [setup_sample(mode) for mode in order]

def summarize(field, rows, mode):
    values = [row[field] for row in rows if row["mode"] == mode]
    return {"mean": statistics.fmean(values), "p50": statistics.median(values),
            "minimum": min(values), "maximum": max(values)}

summary = {}
for mode in ports:
    summary[mode] = {
        "throughputMiBPerSecond": summarize("throughputMiBPerSecond", throughput, mode),
        "serverCpuSecondsPerGiB": summarize("serverCpuSecondsPerGiB", throughput, mode),
        "connectionsPerSecond": summarize("connectionsPerSecond", setup, mode),
        "setupP50Milliseconds": summarize("p50Milliseconds", setup, mode),
        "serverCpuMicrosecondsPerConnection": summarize("serverCpuMicrosecondsPerConnection", setup, mode),
    }

base = summary["none"]
enc = summary["vless-encryption"]
report = {
    "schemaVersion": 1,
    "harness": "benchmark-vless-encryption",
    "environment": {"kernel": platform.release(), "machine": platform.machine(),
                    "cpuCount": os.cpu_count(),
                    "xrayVersion": subprocess.run([xray, "version"], check=True,
                        capture_output=True, text=True).stdout.splitlines()[0]},
    "method": {"outerTransport": "REALITY", "flow": "xtls-rprx-vision",
               "encryptedMode": "mlkem768x25519plus.native.0rtt after warm-up",
               "samplesPerMode": samples, "concurrency": concurrency,
               "payloadMiBPerRequest": payload_mib,
               "setupConnectionsPerSample": setup_connections,
               "setupConcurrency": setup_concurrency, "randomizedOrder": order},
    "throughputMeasurements": throughput,
    "setupMeasurements": setup,
    "summary": summary,
    "ratios": {
        "encryptedToNoneP50Throughput": enc["throughputMiBPerSecond"]["p50"] / base["throughputMiBPerSecond"]["p50"],
        "encryptedToNoneMeanServerCpuPerGiB": enc["serverCpuSecondsPerGiB"]["mean"] / base["serverCpuSecondsPerGiB"]["mean"],
        "encryptedToNoneP50ConnectionsPerSecond": enc["connectionsPerSecond"]["p50"] / base["connectionsPerSecond"]["p50"],
    },
    "limitations": [
        "single-host loopback; results are host-specific, not universal",
        "both modes use the same Xray build, REALITY, Vision, client, and origins",
        "VLESS Encryption is measured after ticket warm-up, favoring its 0-RTT setup path",
        "server CPU excludes client-side encryption and the origin",
    ],
}
print(json.dumps(report, indent=2, sort_keys=True))
PY

rr_finalize_contract
printf 'VLESS Encryption benchmark written to %s\n' "$report"
