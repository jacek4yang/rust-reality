#!/usr/bin/env bash
# Bounded loopback soak: mixed tunnel traffic + connection churn against a
# local rust-reality server, with resource snapshots proving nothing leaks.
#
# Workload mix per round: direct download (TLS origin), framed download
# (plain origin), fallback (direct-to-listener), and rapid connect/drop
# churn. /proc snapshots (FDs, RSS, threads) are captured at start, each
# round, and end; the summary fails the run if the end snapshot exceeds the
# start by more than a bounded slack after a drain pause.
#
# Env: DURATION_MIN (30), ROUND_SLEEP (5), RUST_REALITY_BIN, XRAY_BIN, OUT_DIR.
set -Eeuo pipefail

repository=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
rust_bin=${RUST_REALITY_BIN:-target/release/rust-reality}
xray=${XRAY_BIN:-../artifacts/xray-reference}
duration_min=${DURATION_MIN:-30}
round_sleep=${ROUND_SLEEP:-5}
minimum_rounds=${MIN_ROUNDS:-$duration_min}
expected_rust_sha256=${RUST_REALITY_SHA256:-}
out_dir=${OUT_DIR:-diagnostics/final/soak-$(date -u +%Y%m%dT%H%M%SZ)}
work=$(readlink -f "$(mktemp -d "$repository/benchmarks/soak.XXXXXX")")
pids=()

cleanup() {
    for pid in "${pids[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    rm -rf -- "$work"
}
trap cleanup EXIT

cd "$repository"
for program in curl jq openssl python3 sha256sum; do
    command -v "$program" >/dev/null || { echo "missing: $program" >&2; exit 1; }
done
[[ $duration_min =~ ^[1-9][0-9]*$ ]] || { echo "DURATION_MIN must be positive" >&2; exit 2; }
[[ $round_sleep =~ ^[0-9]+$ ]] || { echo "ROUND_SLEEP must be non-negative" >&2; exit 2; }
[[ $minimum_rounds =~ ^[1-9][0-9]*$ ]] || { echo "MIN_ROUNDS must be positive" >&2; exit 2; }
[[ -x $rust_bin ]] || { echo "RUST_REALITY_BIN not executable: $rust_bin" >&2; exit 1; }
rust_bin=$(realpath "$rust_bin")
rust_sha256=$(sha256sum "$rust_bin" | awk '{print $1}')
if [[ -n $expected_rust_sha256 && ${expected_rust_sha256,,} != $rust_sha256 ]]; then
    echo "RUST_REALITY_SHA256 mismatch: expected $expected_rust_sha256, got $rust_sha256" >&2
    exit 1
fi
command -v "$xray" >/dev/null 2>&1 || { echo "XRAY_BIN is required" >&2; exit 1; }
xray=$(realpath "$(command -v "$xray")")
xray_sha256=$(sha256sum "$xray" | awk '{print $1}')

[[ ! -e $out_dir ]] || { echo "OUT_DIR already exists: $out_dir" >&2; exit 1; }
mkdir -p "$(dirname "$out_dir")"
mkdir "$out_dir"
jq -n --arg rustBin "$rust_bin" --arg rustSha256 "$rust_sha256" \
    --arg xrayBin "$xray" --arg xraySha256 "$xray_sha256" \
    --arg startedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson durationMinutes "$duration_min" \
    '{schemaVersion:1,startedAt:$startedAt,durationMinutes:$durationMinutes,
      rustReality:{path:$rustBin,sha256:$rustSha256},
      xray:{path:$xrayBin,sha256:$xraySha256}}' \
    >"$out_dir/environment.json"

allocate_ports() {
    python3 - <<'PY'
import socket
sockets = []
try:
    for _ in range(4):
        sock = socket.socket()
        sockets.append(sock)
        sock.bind(("127.0.0.1", 0))
    print(*(sock.getsockname()[1] for sock in sockets))
finally:
    for sock in sockets:
        sock.close()
PY
}

read -r rust_port rust_socks https_port http_port < <(allocate_ports)

"$rust_bin" config generate standalone --listen 127.0.0.1 --port "$rust_port" \
    --target "127.0.0.1:$https_port" --server-name localhost \
    > "$work/base.json" 2> "$work/gen.log"
rust_pub=$(sed -n 's/^REALITY public key for the client: //p' "$work/gen.log")
uuid=$(jq -r '.inbounds[0].settings.clients[0].id' "$work/base.json")
sid=$(jq -r '.inbounds[0].settings.clients[0].shortIds[0]' "$work/base.json")
jq --arg c "$work/assets" '.log.level="warn" | .assets.cacheDirectory=$c' \
    "$work/base.json" > "$work/rust.json"
jq -n --arg uuid "$uuid" --arg pk "$rust_pub" --arg sid "$sid" \
    --argjson sp "$rust_port" --argjson cp "$rust_socks" \
    '{log:{loglevel:"warning"},inbounds:[{listen:"127.0.0.1",port:$cp,protocol:"socks",settings:{auth:"noauth",udp:false}}],outbounds:[{protocol:"vless",settings:{vnext:[{address:"127.0.0.1",port:$sp,users:[{id:$uuid,encryption:"none",flow:"xtls-rprx-vision"}]}]},streamSettings:{network:"tcp",security:"reality",realitySettings:{fingerprint:"chrome",serverName:"localhost",publicKey:$pk,shortId:$sid,spiderX:"/"}}}]}' \
    > "$work/rust-client.json"

python3 -c "
chunk = bytes(range(256)) * 4096
open('$work/payload-4.bin','wb').write(chunk * 4)"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/o.key" -out "$work/o.crt" \
    -days 1 -subj "/CN=localhost" >/dev/null 2>&1
(cd scripts/bench-origin && go build -o "$work/bench-origin" .)
"$work/bench-origin" --port "$https_port" --payload-dir "$work" \
    --put-log "$work/https-put.jsonl" --tls-cert "$work/o.crt" --tls-key "$work/o.key" \
    > "$work/https-origin.log" 2>&1 &
pids+=("$!")
"$work/bench-origin" --port "$http_port" --payload-dir "$work" \
    --put-log "$work/http-put.jsonl" > "$work/http-origin.log" 2>&1 &
pids+=("$!")

"$rust_bin" serve --config "$work/rust.json" > "$work/rust.log" 2>&1 &
pids+=("$!")
server_pid=$!
"$xray" run -config "$work/rust-client.json" > /dev/null 2>&1 &
pids+=("$!")
sleep 1.5

snapshot() {
    python3 - "$server_pid" "$1" >> "$out_dir/resources.jsonl" <<'PY'
import json, os, sys
pid, label = sys.argv[1], sys.argv[2]
with open(f"/proc/{pid}/status") as fh:
    fields = dict(line.split(":", 1) for line in fh if ":" in line)
print(json.dumps({
    "label": label,
    "monotonicSeconds": __import__("time").monotonic(),
    "serverAlive": True,
    "fds": len(os.listdir(f"/proc/{pid}/fd")),
    "vmRssKiB": int(fields["VmRSS"].split()[0]),
    "threads": int(fields["Threads"].split()[0]),
}))
PY
}

clean_curl() {
    env -u ALL_PROXY -u all_proxy -u HTTP_PROXY -u http_proxy \
        -u HTTPS_PROXY -u https_proxy -u NO_PROXY -u no_proxy curl "$@"
}

expected_payload_sha256=$(sha256sum "$work/payload-4.bin" | awk '{print $1}')
verify_download() {
    local actual
    if ! actual=$(clean_curl "$@" | sha256sum | awk '{print $1}'); then
        return 1
    fi
    [[ $actual == "$expected_payload_sha256" ]]
}

failures=0
round=0
deadline=$(( $(date +%s) + duration_min * 60 ))
snapshot start
while (( $(date +%s) < deadline )); do
    round=$((round + 1))
    verify_download -sS --insecure --fail --socks5-hostname 127.0.0.1:$rust_socks \
        --max-time 60 https://127.0.0.1:$https_port/payload-4.bin \
        || failures=$((failures + 1))
    verify_download -sS --fail --socks5-hostname 127.0.0.1:$rust_socks \
        --max-time 60 http://127.0.0.1:$http_port/payload-4.bin \
        || failures=$((failures + 1))
    verify_download -sS --insecure --fail --max-time 60 \
        https://127.0.0.1:$rust_port/payload-4.bin || failures=$((failures + 1))
    # churn: rapid short-lived connections through every path
    for _ in $(seq 1 16); do
        clean_curl -sS --insecure --max-time 5 -o /dev/null -r 0-1023 \
            https://127.0.0.1:$rust_port/payload-4.bin 2>/dev/null \
            || failures=$((failures + 1))
    done
    snapshot "round-$round"
    sleep "$round_sleep"
done
sleep 5
snapshot end

python3 - "$out_dir/resources.jsonl" "$failures" "$round" "$minimum_rounds" \
    "$expected_payload_sha256" "$out_dir/soak-summary.json" <<'PY'
import json, statistics, sys
records = [json.loads(line) for line in open(sys.argv[1])]
failures, rounds, minimum_rounds = map(int, sys.argv[2:5])
payload_sha256, output = sys.argv[5:7]
start, end = records[0], records[-1]
# Slack: a few dozen FDs/threads and 32 MiB RSS cover allocator arenas and
# parked runtime state; anything beyond that is a leak.
fd_growth = end["fds"] - start["fds"]
thread_growth = end["threads"] - start["threads"]
rss_growth_mib = (end["vmRssKiB"] - start["vmRssKiB"]) / 1024
fd_peak_growth = max(r["fds"] for r in records) - start["fds"]
thread_peak_growth = max(r["threads"] for r in records) - start["threads"]
rss_peak_growth_mib = (max(r["vmRssKiB"] for r in records) - start["vmRssKiB"]) / 1024
tail = records[max(1, len(records) // 2):]
xs = [r["monotonicSeconds"] for r in tail]
ys = [r["vmRssKiB"] / 1024 for r in tail]
if len(xs) >= 2 and len(set(xs)) > 1:
    xbar, ybar = statistics.mean(xs), statistics.mean(ys)
    denominator = sum((x - xbar) ** 2 for x in xs)
    rss_slope_mib_per_hour = 3600 * sum(
        (x - xbar) * (y - ybar) for x, y in zip(xs, ys)
    ) / denominator
else:
    rss_slope_mib_per_hour = 0.0
ok = (
    failures == 0
    and rounds >= minimum_rounds
    and fd_growth <= 32
    and thread_growth <= 8
    and rss_growth_mib <= 32
    and fd_peak_growth <= 128
    and thread_peak_growth <= 8
    and rss_peak_growth_mib <= 64
    and rss_slope_mib_per_hour <= 2
    and all(r.get("serverAlive") for r in records)
)
summary = {
    "rounds": rounds,
    "transferFailures": failures,
    "start": start,
    "end": end,
    "fdGrowth": fd_growth,
    "threadGrowth": thread_growth,
    "rssGrowthMiB": round(rss_growth_mib, 1),
    "minimumRounds": minimum_rounds,
    "payloadSha256": payload_sha256,
    "fdPeakGrowth": fd_peak_growth,
    "threadPeakGrowth": thread_peak_growth,
    "rssPeakGrowthMiB": round(rss_peak_growth_mib, 1),
    "rssTailSlopeMiBPerHour": round(rss_slope_mib_per_hour, 3),
    "ok": ok,
}
with open(output, "x") as fh:
    json.dump({"summary": summary, "snapshots": records}, fh, indent=2)
print(json.dumps(summary))
sys.exit(0 if ok else 1)
PY
