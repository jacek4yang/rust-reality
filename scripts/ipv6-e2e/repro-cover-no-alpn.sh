#!/usr/bin/env bash
# Minimal repro: a REALITY cover that negotiates NO ALPN silently breaks
# VLESS+REALITY+Vision session establishment in rust-reality v1.5.0 — every
# authenticated session falls back to the cover, and the client sees the raw
# cover certificate.
#
# Root cause: src/server/reality.rs builds the generated EncryptedExtensions
# with the *client's* first offered ALPN (chrome: "h2"), ignoring the cover's
# ALPN selection. A no-ALPN cover emits a minimal 23-byte EE record; the
# generated EE carrying ALPN "h2" needs ~37 wire bytes, so
# shaped_record_padding() fails and accept() transitions to cover fallback
# (src/protocol/reality/tls13/handshake.rs).
#
# `probe-dest` still reports "compatible: true" for such a cover — it checks
# only the ServerHello, never the EE/ALPN flight shape.
#
# Usage: repro-cover-no-alpn.sh [rust-reality-bin] [xray-bin]
set -euo pipefail
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
RR=${1:-$REPO/target/debug/rust-reality}
XRAY=${2:-$REPO/tmp/bin/xray}
HELPERS=$REPO/scripts/ipv6-e2e
WORK=$(mktemp -d /tmp/rr-noalpn-repro.XXXXXX)
trap 'rm -rf "$WORK"; kill $(jobs -p) 2>/dev/null' EXIT
unset ALL_PROXY all_proxy HTTP_PROXY http_proxy HTTPS_PROXY https_proxy \
      NO_PROXY no_proxy || true

# ephemeral CA + SAN leaf (the cover-dial TLS client verifies the chain)
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
    -subj "/CN=repro CA" -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout "$WORK/ca.key" -out "$WORK/ca.crt" 2>/dev/null
openssl req -new -newkey rsa:2048 -nodes -sha256 -subj "/CN=cover.test" \
    -addext 'basicConstraints=critical,CA:FALSE' \
    -addext 'keyUsage=critical,digitalSignature,keyEncipherment' \
    -addext 'extendedKeyUsage=serverAuth' \
    -addext 'subjectAltName=DNS:cover.test,IP:127.0.0.1,IP:::1' \
    -keyout "$WORK/cover.key" -out "$WORK/cover.csr" 2>/dev/null
openssl x509 -req -sha256 -days 1 -in "$WORK/cover.csr" \
    -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" -CAcreateserial \
    -copy_extensions copy -out "$WORK/cover.crt" 2>/dev/null

port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'; }
CP=$(port); SP=$(port); OP=$(port); XP=$(port)

# cover WITHOUT ALPN (plain TLS 1.3 terminator — a plausible operator cover)
python3 "$HELPERS/tls_cover_server.py" --bind 127.0.0.1 --port "$CP" \
    --cert "$WORK/cover.crt" --key "$WORK/cover.key" --alpn '' \
    >"$WORK/cover.log" 2>&1 &
python3 "$HELPERS/transfer_server.py" --bind 127.0.0.1 --port "$OP" \
    --directory "$WORK" --label origin >"$WORK/origin.log" 2>&1 &
head -c 65536 /dev/urandom >"$WORK/payload.bin"
sleep 0.5

"$RR" config generate standalone --listen 127.0.0.1 --port "$SP" \
    --target "127.0.0.1:$CP" --server-name cover.test \
    >"$WORK/server.raw.json" 2>"$WORK/gen.log"
PUB=$(sed -n 's/^REALITY public key for the client: //p' "$WORK/gen.log" | head -1)
UUID=$(jq -r '.inbounds[0].settings.clients[0].id' "$WORK/server.raw.json")
SID=$(jq -r '.inbounds[0].settings.clients[0].shortIds[0]' "$WORK/server.raw.json")
jq --arg cache "$WORK/assets" \
    '.assets.cacheDirectory=$cache | .assets.requestTimeoutSeconds=5' \
    "$WORK/server.raw.json" >"$WORK/server.json"
env SSL_CERT_FILE="$WORK/ca.crt" "$RR" serve --config "$WORK/server.json" \
    >"$WORK/rust.log" 2>&1 &
jq -n --arg uuid "$UUID" --arg pk "$PUB" --arg sid "$SID" \
    --argjson sp "$SP" --argjson xp "$XP" '{
  log:{loglevel:"warning"},
  inbounds:[{listen:"127.0.0.1",port:$xp,protocol:"socks",settings:{auth:"noauth"}}],
  outbounds:[{protocol:"vless",settings:{vnext:[{address:"127.0.0.1",port:$sp,
    users:[{id:$uuid,encryption:"none",flow:"xtls-rprx-vision"}]}]},
    streamSettings:{network:"tcp",security:"reality",realitySettings:{
      fingerprint:"chrome",serverName:"cover.test",publicKey:$pk,shortId:$sid}}}]
}' >"$WORK/xray.json"
"$XRAY" run -config "$WORK/xray.json" >"$WORK/xray.log" 2>&1 &
sleep 1.5

echo "== probe-dest verdict =="
env SSL_CERT_FILE="$WORK/ca.crt" "$RR" probe-dest \
    --target "127.0.0.1:$CP" --server-name cover.test | jq -c '{compatible,cipherSuite,keyExchangeGroup}'

echo "== session through the REALITY inbound =="
set +e
curl -sS --socks5-hostname "127.0.0.1:$XP" --max-time 10 \
    -o "$WORK/got.bin" "http://127.0.0.1:$OP/payload.bin"
rc=$?
set -e
if [[ $rc == 0 ]] && cmp -s "$WORK/got.bin" "$WORK/payload.bin"; then
    echo "UNEXPECTED: session established and payload is byte-exact"
    exit 0
fi
echo "REPRODUCED: session failed (curl rc=$rc) — connections fall back to the cover"
echo "== client-side evidence (last retry error) =="
tail -1 "$WORK/xray.log"
exit 1
