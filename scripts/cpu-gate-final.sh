#!/usr/bin/env bash
# One-off: perf stat CPU/GiB for the final build on the raw Direct path.
set -Eeuo pipefail
repository=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository"
rust_bin=${1:-target/release/rust-reality}
stat_out=${2:-diagnostics/final/perf-stat/rust-final-followup.txt}
w=$(readlink -f "$(mktemp -d benchmarks/cpu-final.XXXXXX)")
rust_port=27101; rust_socks=27103; https_port=27105
trap 'kill $(cat "$w"/*.pid 2>/dev/null) 2>/dev/null || true; rm -rf "$w"' EXIT

"$rust_bin" config generate standalone --listen 127.0.0.1 --port "$rust_port" --target dl.google.com:443 --server-name dl.google.com > "$w/rust.raw.json" 2> "$w/gen.log"
rust_pub=$(sed -n 's/^REALITY public key for the client: //p' "$w/gen.log")
uuid=$(jq -r '.inbounds[0].settings.clients[0].id' "$w/rust.raw.json")
sid=$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0]' "$w/rust.raw.json")
jq --arg c "$w/assets" '.log.level="debug" | .assets.cacheDirectory=$c' "$w/rust.raw.json" > "$w/rust.json"
jq -n --arg uuid "$uuid" --arg pk "$rust_pub" --arg sid "$sid" --argjson sp "$rust_port" --argjson cp "$rust_socks" '{log:{loglevel:"warning"},inbounds:[{listen:"127.0.0.1",port:$cp,protocol:"socks",settings:{auth:"noauth",udp:false}}],outbounds:[{protocol:"vless",settings:{vnext:[{address:"127.0.0.1",port:$sp,users:[{id:$uuid,encryption:"none",flow:"xtls-rprx-vision"}]}]},streamSettings:{network:"tcp",security:"reality",realitySettings:{fingerprint:"chrome",serverName:"dl.google.com",publicKey:$pk,shortId:$sid,spiderX:"/"}}}]}' > "$w/rust-client.json"

"$rust_bin" serve --config "$w/rust.json" > "$w/rust.log" 2>&1 & echo $! > "$w/server.pid"
../artifacts/xray-reference run -config "$w/rust-client.json" > /dev/null 2>&1 & echo $! > "$w/client.pid"
python3 -c "
chunk=bytes(range(256))*4096
open('$w/payload-256.bin','wb').write(chunk*256)"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$w/o.key" -out "$w/o.crt" -days 1 -subj "/CN=localhost" >/dev/null 2>&1
(cd scripts/bench-origin && go build -o "$w/bench-origin" .)
"$w/bench-origin" --port "$https_port" --payload-dir "$w" --put-log "$w/put.jsonl" --tls-cert "$w/o.crt" --tls-key "$w/o.key" > "$w/origin.log" 2>&1 & echo $! > "$w/origin.pid"
sleep 1.2

export -n ALL_PROXY all_proxy HTTP_PROXY http_proxy HTTPS_PROXY https_proxy NO_PROXY no_proxy 2>/dev/null || true
curl -sS --insecure --socks5-hostname 127.0.0.1:$rust_socks -o /dev/null -w "warm %{size_download}\n" --max-time 120 https://127.0.0.1:$https_port/payload-256.bin

grep -a connection_completed "$w/rust.log" | tail -2
sudo -n perf stat -e task-clock,instructions,context-switches,page-faults -p "$(cat "$w/server.pid")" \
    -o "$stat_out" -- bash -c '
for i in $(seq 1 10); do
  curl -sS --insecure --socks5-hostname 127.0.0.1:27103 -o /dev/null --max-time 120 https://127.0.0.1:27105/payload-256.bin
done'
grep -E "task-clock|instructions|context-switches|page-faults|seconds" "$stat_out" | grep -v "^#"
sleep 1
grep -a connection_completed "$w/rust.log" | tail -3
