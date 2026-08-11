#!/usr/bin/env python3
"""deployment_driver.py — measurement driver for scripts/benchmark-deployment.sh.

Standard library only. Subcommands:

  socks-server          Minimal threaded SOCKS5 CONNECT server. Transparent by
                        default; --fixed-target rewrites every CONNECT to one
                        destination (used to prove outbound selection: traffic
                        can only surface at that one origin).
  pick-domain           Walk a community geosite.dat and print one concrete
                        domain for the first available candidate label, so the
                        routing proof never hard-codes DAT contents.
  gen-routing-config    Build the multi-UUID/multi-group routing proof config
                        from a `config generate standalone` base.
  gen-scale-config      Build simple/medium/complex routing-cost configs
                        (N UUIDs, K rules for the measured user, strategy).
  route-probe           Execute the (uuid, destination) correctness matrix and
                        emit one JSONL record per case with pass/fail.
  setup-rate            accept->first-payload latency distribution and
                        connections/sec through a SOCKS entry (raw sockets).
  throughput            curl-based transfer cells with per-cell byte integrity.
  relay-evidence        Parse a server JSON log for connection_completed
                        events and verify the steady-state relay backend.

Every subprocess spawned here (curl) runs with a scrubbed environment: all
proxy variables are removed so loopback traffic must go through the tunnel.
"""

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time

PROXY_VARS = ("all_proxy", "http_proxy", "https_proxy", "no_proxy")


def clean_env():
    return {k: v for k, v in os.environ.items() if k.lower() not in PROXY_VARS}


def percentile(ordered, fraction):
    return ordered[min(len(ordered) - 1, int(len(ordered) * fraction))]


# ---------------------------------------------------------------------------
# Raw SOCKS5 client (same measurement pattern as benchmark-setup-rate.sh).
# ---------------------------------------------------------------------------

def _recv_exact(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise RuntimeError("unexpected eof in socks reply")
        data += chunk
    return data


def socks_open(socks_port, host, port, timeout=30.0):
    """Open a connection through the local SOCKS5 entry. Returns the socket
    after a successful CONNECT. Raises OSError/RuntimeError otherwise."""
    sock = socket.create_connection(("127.0.0.1", socks_port), timeout=timeout)
    sock.settimeout(timeout)
    sock.sendall(b"\x05\x01\x00")
    if _recv_exact(sock, 2) != b"\x05\x00":
        sock.close()
        raise RuntimeError("socks greeting rejected")
    try:
        ip = socket.inet_aton(host)
        atyp = b"\x01"
        addr = ip
    except OSError:
        encoded = host.encode("idna")
        if len(encoded) > 255:
            sock.close()
            raise RuntimeError("domain too long")
        atyp = b"\x03"
        addr = bytes([len(encoded)]) + encoded
    sock.sendall(b"\x05\x01\x00" + atyp + addr + int(port).to_bytes(2, "big"))
    reply = _recv_exact(sock, 4)
    if reply[1] != 0:
        sock.close()
        raise RuntimeError(f"socks connect rejected (rep={reply[1]})")
    # Consume the bound address (ipv4/ipv6/domain).
    if reply[3] == 1:
        _recv_exact(sock, 4 + 2)
    elif reply[3] == 4:
        _recv_exact(sock, 16 + 2)
    else:
        length = _recv_exact(sock, 1)[0]
        _recv_exact(sock, length + 2)
    return sock


def http_get_body(sock, host, port, path, max_bytes=8 * 1024 * 1024):
    """Issue a minimal HTTP/1.0 GET on an open socket; return (status, body).

    Stops after Content-Length body bytes when the header is present rather
    than depending on FIN propagation through the tunnel."""
    sock.sendall(
        f"GET {path} HTTP/1.0\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n".encode()
    )
    buffer = b""
    while b"\r\n\r\n" not in buffer:
        data = sock.recv(65536)
        if not data:
            raise RuntimeError("eof before response headers")
        buffer += data
        if len(buffer) > 65536:
            raise RuntimeError("response headers too large")
    head, _, body = buffer.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = int(lines[0].split(b" ", 2)[1])
    content_length = None
    for line in lines[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            content_length = int(value.strip())
    if content_length is not None and content_length > max_bytes:
        raise RuntimeError("response too large for a correctness probe")
    while content_length is None or len(body) < content_length:
        data = sock.recv(65536)
        if not data:
            break
        body += data
    if content_length is not None:
        body = body[:content_length]
    return status, body


# ---------------------------------------------------------------------------
# socks-server
# ---------------------------------------------------------------------------

def run_socks_server(port, fixed_target):
    """Minimal no-auth SOCKS5 CONNECT server.

    Transparent mode dials the requested address. Fixed-target mode rewrites
    every CONNECT to one host:port, so any traffic arriving at that origin is
    proof that the server selected the outbound pointing at this listener.
    """
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", port))
    listener.listen(128)

    def handle(client):
        upstream = None
        try:
            greeting = _recv_exact(client, 2)
            if greeting[0] != 5:
                return
            _recv_exact(client, greeting[1])  # methods
            client.sendall(b"\x05\x00")
            header = _recv_exact(client, 4)
            if header[1] != 1:  # CONNECT only
                return
            atyp = header[3]
            if atyp == 1:
                host = socket.inet_ntoa(_recv_exact(client, 4))
            elif atyp == 3:
                host = _recv_exact(client, _recv_exact(client, 1)[0]).decode("idna", "replace")
            elif atyp == 4:
                host = socket.inet_ntop(socket.AF_INET6, _recv_exact(client, 16))
            else:
                return
            dport = struct.unpack(">H", _recv_exact(client, 2))[0]
            if fixed_target:
                host, dport = fixed_target
            try:
                upstream = socket.create_connection((host, dport), timeout=15)
            except OSError:
                client.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)  # connection refused
                return
            client.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
            done = threading.Event()

            def pump(source, sink):
                try:
                    while not done.is_set():
                        data = source.recv(65536)
                        if not data:
                            break
                        sink.sendall(data)
                except OSError:
                    pass
                finally:
                    done.set()
                    for s in (source, sink):
                        try:
                            s.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass

            threading.Thread(target=pump, args=(client, upstream), daemon=True).start()
            threading.Thread(target=pump, args=(upstream, client), daemon=True).start()
            done.wait()
        except (OSError, RuntimeError):
            # Abrupt client aborts (including port-readiness probes) are
            # expected noise for a test SOCKS server.
            pass
        finally:
            client.close()
            if upstream is not None:
                upstream.close()

    while True:
        conn, _ = listener.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


# ---------------------------------------------------------------------------
# pick-domain: minimal protobuf walk of a geosite.dat
# ---------------------------------------------------------------------------

def _read_varint(buf, pos):
    value = 0
    shift = 0
    while True:
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7


def _fields(buf):
    """Yield (field_number, wire_type, value) for a protobuf buffer."""
    pos = 0
    while pos < len(buf):
        key, pos = _read_varint(buf, pos)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, pos = _read_varint(buf, pos)
            yield number, wire, value
        elif wire == 2:
            length, pos = _read_varint(buf, pos)
            yield number, wire, buf[pos:pos + length]
            pos += length
        elif wire == 5:
            yield number, wire, buf[pos:pos + 4]
            pos += 4
        elif wire == 1:
            yield number, wire, buf[pos:pos + 8]
            pos += 8
        else:
            raise ValueError(f"unsupported wire type {wire}")


_HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")


def pick_domain(dat_path, labels):
    """Print one concrete domain carried by the first available label.

    Preference: Full entries (type 3) without attributes, then Domain entries
    (type 2) without attributes. Attribute-bearing and keyword/regexp entries
    are skipped because their match semantics depend on extra context.
    """
    wanted = [label.strip().lower() for label in labels.split(",") if label.strip()]
    with open(dat_path, "rb") as fh:
        data = fh.read()
    sites = {}
    for number, wire, value in _fields(data):
        if number != 1 or wire != 2:
            continue
        code = None
        domains = []
        for snumber, swire, svalue in _fields(value):
            if snumber == 1 and swire == 2:
                code = svalue.decode("utf-8", "replace").lower()
            elif snumber == 2 and swire == 2:
                dtype, dvalue, has_attr = None, None, False
                for dnumber, dwire, dval in _fields(svalue):
                    if dnumber == 1 and dwire == 0:
                        dtype = dval
                    elif dnumber == 2 and dwire == 2:
                        dvalue = dval.decode("utf-8", "replace")
                    elif dnumber == 3:
                        has_attr = True
                domains.append((dtype, dvalue, has_attr))
        if code:
            sites[code] = domains
    for label in wanted:
        domains = sites.get(label)
        if not domains:
            continue
        for prefer in (3, 2):
            for dtype, dvalue, has_attr in domains:
                if dtype == prefer and not has_attr and dvalue and _HOST_RE.match(dvalue):
                    print(f"{label} {dvalue}")
                    return 0
        print(f"label {label} has no attribute-free full/domain entry", file=sys.stderr)
        return 1
    print(f"none of the candidate labels exist: {wanted}", file=sys.stderr)
    return 1


# ---------------------------------------------------------------------------
# Config generators
# ---------------------------------------------------------------------------

def load_json(path):
    with open(path) as fh:
        return json.load(fh)


def dump_json(config, path):
    with open(path, "w") as fh:
        json.dump(config, fh, indent=2)
        fh.write("\n")


def clients_with_owned_short_ids(base_client, uuids, email_prefix=None):
    """Build replacement VLESS clients without losing short-ID ownership.

    Keep the generated base client's IDs on the first (measured) UUID so the
    shell harness can reuse its generated client environment. Added UUIDs get
    one deterministic, unique 16-hex-character ID each.
    """
    base_short_ids = base_client.get("shortIds")
    if not isinstance(base_short_ids, list) or not base_short_ids:
        raise SystemExit("base VLESS client must contain at least one shortIds entry")
    used = {short_id.lower() for short_id in base_short_ids}
    clients = []
    for index, uuid in enumerate(uuids):
        if index == 0:
            short_ids = list(base_short_ids)
        else:
            for salt in range(256):
                short_id = hashlib.sha256(f"{uuid}:{salt}".encode()).hexdigest()[:16]
                if short_id.lower() not in used:
                    break
            else:
                raise SystemExit("could not derive a unique short ID for VLESS client")
            short_ids = [short_id]
        used.update(short_id.lower() for short_id in short_ids)
        client = {
            "id": uuid,
            "shortIds": short_ids,
            "flow": "xtls-rprx-vision",
        }
        if email_prefix is not None:
            client["email"] = f"{email_prefix}-{index}"
        clients.append(client)
    return clients


def gen_routing_config(args):
    """Routing correctness proof config: 4 UUIDs in 2 groups, direct +
    blackhole + fixed-target socks5 outbounds, global and per-group rules
    mixing domain / geosite / IP / port matchers, a late-match rule, and a
    restrictive default per group."""
    config = load_json(args.base)
    uuids = [u.strip() for u in args.uuids.split(",")]
    if len(uuids) != 4:
        raise SystemExit("exactly four UUIDs required")
    settings = config["inbounds"][0]["settings"]
    settings["clients"] = clients_with_owned_short_ids(
        settings["clients"][0], uuids, email_prefix="proof"
    )
    config["outbounds"] = [
        {"protocol": "direct", "tag": "direct"},
        {"protocol": "blackhole", "tag": "block", "settings": {"responseDelayMs": 0}},
        {
            "protocol": "socks5",
            "tag": "via-socks-b",
            "settings": {"address": "127.0.0.1", "port": args.socks_b_port},
        },
    ]
    config["routing"] = {
        "domainStrategy": "IPIfNonMatch",
        "globalRules": [
            {
                "name": "global-block-domain",
                "outbound": "block",
                "domain": ["full:blocked.example"],
            },
            {
                "name": "global-block-geosite",
                "outbound": "block",
                "domain": [f"geosite:{args.geosite_label}"],
            },
            {
                "name": "global-block-port",
                "outbound": "block",
                "port": [str(args.blocked_port)],
            },
        ],
        "users": [
            {
                "name": "group-alpha",
                "userIds": uuids[:2],
                "defaultOutbound": "block",
                "rules": [
                    {
                        "name": "alpha-allow-origin-a-by-domain",
                        "outbound": "direct",
                        "domain": ["full:localhost"],
                        "port": [str(args.origin_a_port)],
                    },
                    {
                        "name": "alpha-allow-origin-a-by-ip",
                        "outbound": "direct",
                        "ip": ["127.0.0.1"],
                        "port": [str(args.origin_a_port)],
                    },
                    {
                        # Late-match: only evaluated when both allow rules
                        # above missed; demonstrates first-match ordering.
                        "name": "alpha-late-block-loopback-rest",
                        "outbound": "block",
                        "ip": ["127.0.0.0/8"],
                    },
                ],
            },
            {
                "name": "group-beta",
                "userIds": uuids[2:],
                "defaultOutbound": "via-socks-b",
                "rules": [
                    {
                        "name": "beta-block-private-geoip",
                        "outbound": "block",
                        "ip": ["geoip:private"],
                    },
                ],
            },
        ],
    }
    config["log"] = {"level": args.log_level}
    config.setdefault("assets", {})["cacheDirectory"] = args.assets
    # Bound the startup revalidation: with validator metadata present the
    # conditional request is a fast 304; with a dead network the fetch error
    # falls back to the cached DATs instead of hanging for the default 120 s.
    config["assets"]["requestTimeoutSeconds"] = 15
    dump_json(config, args.out)


def _scale_rules(count, with_ip):
    """Deterministic non-matching rules for the measured user. Kept realistic:
    full domains, keywords, regexps, ports, and (optionally) CIDRs."""
    rules = []
    for i in range(count):
        kind = i % 5 if with_ip else i % 4
        if kind == 0:
            rules.append({
                "name": f"r{i}-full",
                "outbound": "block",
                "domain": [f"full:host{i}.scale-example.test"],
            })
        elif kind == 1:
            rules.append({
                "name": f"r{i}-keyword",
                "outbound": "block",
                "domain": [f"keyword:needle-{i}-scale"],
            })
        elif kind == 2:
            rules.append({
                "name": f"r{i}-regexp",
                "outbound": "block",
                "domain": [rf"regexp:^cdn-[0-9]+\.scale-{i}\.test$"],
            })
        elif kind == 3:
            rules.append({
                "name": f"r{i}-port",
                "outbound": "block",
                "port": [f"{20000 + (i % 1000)}-{21000 + (i % 1000)}"],
            })
        else:
            rules.append({
                "name": f"r{i}-cidr",
                "outbound": "block",
                "ip": [f"10.{i % 250}.0.0/16"],
            })
    return rules


def gen_scale_config(args):
    """simple/medium/complex routing-cost config: N total UUIDs (the measured
    UUID plus N-1 bulk UUIDs in one inert group), K non-matching rules for the
    measured user's group, G global rules, selectable domainStrategy."""
    config = load_json(args.base)
    uuids = [line.strip() for line in open(args.uuid_file) if line.strip()]
    if len(uuids) != args.uuids:
        raise SystemExit(f"uuid file must hold exactly {args.uuids} UUIDs")
    measured, bulk = uuids[0], uuids[1:]
    settings = config["inbounds"][0]["settings"]
    settings["clients"] = clients_with_owned_short_ids(settings["clients"][0], uuids)
    config["outbounds"] = [
        {"protocol": "direct", "tag": "direct"},
        {"protocol": "blackhole", "tag": "block", "settings": {"responseDelayMs": 0}},
    ]
    users = [{
        "name": "measured",
        "userIds": [measured],
        "defaultOutbound": "direct",
        "rules": _scale_rules(args.rules, args.with_ip),
    }]
    if bulk:
        users.append({
            "name": "bulk",
            "userIds": bulk,
            "defaultOutbound": "block",
            "rules": [],
        })
    config["routing"] = {
        "domainStrategy": args.strategy,
        "globalRules": _scale_rules(args.global_rules, args.with_ip),
        "users": users,
    }
    for rule in config["routing"]["globalRules"]:
        rule["name"] = "global-" + rule["name"]
    config["log"] = {"level": args.log_level}
    config.setdefault("assets", {})["cacheDirectory"] = args.assets
    dump_json(config, args.out)
    print(measured)


# ---------------------------------------------------------------------------
# route-probe
# ---------------------------------------------------------------------------

def probe_case(case):
    """Run one (uuid, destination) case. Returns the result record."""
    started = time.perf_counter()
    observed = "error"
    detail = ""
    try:
        # 30 s: the first connection through a freshly started client/server
        # pair also pays REALITY session setup and (section 1) Geo asset
        # revalidation; blocked cases return immediately.
        sock = socks_open(case["socksPort"], case["host"], case["port"], timeout=30)
        try:
            status, body = http_get_body(sock, case["host"], case["port"], case["path"])
        finally:
            sock.close()
        if status != 200:
            observed = "error"
            detail = f"http status {status}"
        else:
            observed = "sha256:" + hashlib.sha256(body).hexdigest()
    except (OSError, RuntimeError) as exc:
        observed = "blocked"
        detail = str(exc)[:200]
    expected = case["expect"]
    if expected == "blocked":
        passed = observed == "blocked"
    else:
        passed = observed in (expected, "sha256:" + expected)
    return {
        "uuid": case["uuid"],
        "group": case["group"],
        "label": case["label"],
        "destination": f"{case['host']}:{case['port']}",
        "expected": expected,
        "observed": observed,
        "detail": detail,
        "seconds": round(time.perf_counter() - started, 6),
        "pass": passed,
    }


def route_probe(args):
    with open(args.plan) as fh:
        plan = json.load(fh)
    results = [probe_case(case) for case in plan["cases"]]
    passed = sum(1 for r in results if r["pass"])
    with open(args.out, "w") as fh:
        for record in results:
            fh.write(json.dumps(record) + "\n")
    summary = {
        "cases": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "verdict": "PASS" if passed == len(results) else "FAIL",
    }
    with open(args.summary, "w") as fh:
        json.dump(summary, fh, indent=2)
        fh.write("\n")
    for record in results:
        mark = "PASS" if record["pass"] else "FAIL"
        print(f"  [{mark}] {record['group']}/{record['label']} "
              f"{record['destination']} expected={record['expected'][:19]} "
              f"observed={record['observed'][:19]} {record['detail']}")
    print(f"routing correctness: {summary['verdict']} "
          f"({passed}/{len(results)} cases)")
    return 0 if summary["verdict"] == "PASS" else 1


# ---------------------------------------------------------------------------
# setup-rate
# ---------------------------------------------------------------------------

def cmd_setup_rate(args):
    """accept -> SOCKS CONNECT -> HTTP first-byte latency through the tunnel,
    per concurrency: distribution + connections/sec. Raw sockets, so the
    measurement is connection setup, not client startup."""

    def one_connection(_):
        started = time.perf_counter()
        try:
            sock = socks_open(args.socks_port, args.host, args.port, timeout=30)
            try:
                sock.sendall(
                    f"GET {args.path} HTTP/1.0\r\nHost: {args.host}:{args.port}\r\n\r\n".encode()
                )
                first = sock.recv(4096)
                if not first:
                    return None
            finally:
                sock.close()
            return time.perf_counter() - started
        except (OSError, RuntimeError):
            return None

    concurrencies = [int(c) for c in args.concurrencies.split()]
    out = []
    for conc in concurrencies:
        one_connection(0)  # warm client and server paths
        for sample in range(args.samples):
            wall0 = time.perf_counter()
            with concurrent.futures.ThreadPoolExecutor(max_workers=conc) as ex:
                latencies = list(ex.map(one_connection, range(args.conns)))
            wall = time.perf_counter() - wall0
            good = sorted(x for x in latencies if x is not None)
            if not good:
                out.append({"concurrency": conc, "sampleIndex": sample,
                            "wallSeconds": wall, "connections": 0,
                            "failed": len(latencies)})
                continue
            out.append({
                "concurrency": conc,
                "sampleIndex": sample,
                "wallSeconds": wall,
                "connections": len(good),
                "failed": len(latencies) - len(good),
                "connectionsPerSecond": len(good) / wall,
                "p50Seconds": percentile(good, 0.50),
                "p95Seconds": percentile(good, 0.95),
                "p99Seconds": percentile(good, 0.99),
            })
    with open(args.out, "w") as fh:
        for record in out:
            fh.write(json.dumps(record) + "\n")
    for conc in concurrencies:
        cells = [x for x in out if x["concurrency"] == conc and x.get("connections")]
        if cells:
            print(f"{args.label} c{conc}: " + "; ".join(
                f"{x['connectionsPerSecond']:.0f} conn/s "
                f"(p50 {x['p50Seconds'] * 1000:.1f}ms, p99 {x['p99Seconds'] * 1000:.1f}ms, "
                f"fail {x['failed']})" for x in cells))
        else:
            print(f"{args.label} c{conc}: ALL CONNECTIONS FAILED")
    return 0


# ---------------------------------------------------------------------------
# throughput
# ---------------------------------------------------------------------------

def cmd_throughput(args):
    """curl transfer cells through the tunnel. The first transfer of every
    cell is byte-verified against --expected-sha256; the rest go to /dev/null.
    Emits one JSONL record per sample."""
    concurrencies = [int(c) for c in args.concurrencies.split()]
    verify_file = os.path.join(os.path.dirname(args.out) or ".",
                               f".verify-{args.label}-{os.getpid()}.bin")

    def transfer(verify):
        target = verify_file if verify else os.devnull
        result = subprocess.run(
            ["curl", "--fail", "-sS", "--max-time", str(args.max_time),
             "--socks5-hostname", f"127.0.0.1:{args.socks_port}",
             "-o", target, "-w", "%{size_download} %{time_total}", args.url],
            capture_output=True, text=True, env=clean_env())
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip()[:160])
        size, elapsed = result.stdout.split()
        if int(size) != args.mib * 1024 * 1024:
            raise RuntimeError(f"short read {size}")
        if verify and args.expected_sha256:
            digest = hashlib.sha256()
            with open(verify_file, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    digest.update(chunk)
            if digest.hexdigest() != args.expected_sha256:
                raise RuntimeError("integrity mismatch")
        return float(elapsed)

    out = []
    try:
        for conc in concurrencies:
            integrity = "skip"
            for sample in range(args.samples):
                started = time.perf_counter()
                try:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=conc) as ex:
                        lats = list(ex.map(transfer, [sample == 0] + [False] * (conc - 1)))
                    if sample == 0 and args.expected_sha256:
                        integrity = "pass"
                except RuntimeError as exc:
                    out.append({"label": args.label, "concurrency": conc,
                                "sampleIndex": sample, "error": str(exc)[:200]})
                    print(f"{args.label} c{conc} s{sample}: ERROR {exc}")
                    continue
                wall = time.perf_counter() - started
                out.append({
                    "label": args.label,
                    "concurrency": conc,
                    "sampleIndex": sample,
                    "wallSeconds": wall,
                    "throughputMiBPerSecond": args.mib * conc / wall,
                    "perRequestSeconds": lats,
                    "integrity": integrity if sample == 0 else "skip",
                })
    finally:
        if os.path.exists(verify_file):
            os.unlink(verify_file)
    with open(args.out, "w") as fh:
        for record in out:
            fh.write(json.dumps(record) + "\n")
    for conc in concurrencies:
        cells = [x for x in out
                 if x["concurrency"] == conc and "throughputMiBPerSecond" in x]
        if cells:
            med = statistics.median(x["throughputMiBPerSecond"] for x in cells)
            integ = cells[0].get("integrity", "skip")
            print(f"{args.label} c{conc}: {med:.0f} MiB/s median "
                  f"({len(cells)} samples, integrity {integ})")
        else:
            print(f"{args.label} c{conc}: ALL TRANSFERS FAILED")
    return 0


# ---------------------------------------------------------------------------
# relay-evidence
# ---------------------------------------------------------------------------

def cmd_relay_evidence(args):
    """Parse a rust-reality JSON log for long-flow relay evidence.

    Collects, from the landing's debug log:
      * the startup relay_backend_report (was the expected backend available?),
      * connection_accepted / connection_closed / connection_rejected counts,
      * any connection_completed events and their relay_backend values.

    Verdict PASS requires: expected backend reported available, at least one
    accepted and one cleanly closed connection, zero rejections, and — when
    per-connection completion events exist at all — every one of them carrying
    the expected backend. The report explicitly states whether per-connection
    backend evidence was emitted by production (`emitted` vs `not-emitted`):
    the NXR landing path currently emits no connection_completed events, which
    is surfaced as a caveat instead of being silently treated as proof."""
    backend_report = {}
    accepted = closed = rejected = 0
    completed = []
    with open(args.log) as fh:
        for line in fh:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            event = record.get("event")
            if event == "relay_backend_report":
                for entry in record.get("backends", []):
                    backend_report[entry["backend"]] = entry["available"]
            elif event == "connection_accepted":
                accepted += 1
            elif event == "connection_closed":
                closed += 1
            elif event == "connection_rejected":
                rejected += 1
            elif event == "connection_completed":
                completed.append(record)
    backends = sorted({e.get("relay_backend") for e in completed if e.get("relay_backend")})
    missing_backend = sum(1 for e in completed if not e.get("relay_backend"))
    evidence = "emitted" if completed else "not-emitted"
    verdict = (
        backend_report.get(args.expect_backend) is True
        and accepted >= 1
        and closed >= 1
        and rejected == 0
        and missing_backend == 0
        and (not completed or backends == [args.expect_backend])
    )
    report = {
        "log": args.log,
        "expectedBackend": args.expect_backend,
        "backendReport": backend_report,
        "expectedBackendAvailable": backend_report.get(args.expect_backend) is True,
        "connectionAccepted": accepted,
        "connectionClosed": closed,
        "connectionRejected": rejected,
        "connectionCompletedEvents": len(completed),
        "relayBackends": backends,
        "eventsMissingRelayBackend": missing_backend,
        "perConnectionBackendEvidence": evidence,
        "note": (
            "NXR post-auth is raw bytes by protocol design; splice availability "
            "plus a clean relayed, integrity-verified flow is the log-level "
            "evidence. Production does not emit connection_completed for NXR "
            "landings, so per-connection backend attribution is unavailable."
            if evidence == "not-emitted" else
            "Per-connection relay backend events were emitted and checked."
        ),
        "verdict": "PASS" if verdict else "FAIL",
    }
    with open(args.out, "w") as fh:
        json.dump(report, fh, indent=2)
        fh.write("\n")
    print(f"relay evidence: {report['verdict']} backendReport={backend_report} "
          f"accepted={accepted} closed={closed} rejected={rejected} "
          f"completed={len(completed)} backends={backends} ({evidence})")
    return 0 if verdict else 1


# ---------------------------------------------------------------------------
# summarize
# ---------------------------------------------------------------------------

def _read_jsonl(path):
    records = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def cmd_summarize(args):
    """Aggregate every samples file in the output directory into summary.json."""
    import glob
    out_dir = args.out_dir
    summary = {"generatedAtUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    def median_or_none(values):
        return statistics.median(values) if values else None

    setup = {}
    for path in sorted(glob.glob(os.path.join(out_dir, "setup-*.jsonl"))):
        label = os.path.basename(path)[len("setup-"):-len(".jsonl")]
        records = _read_jsonl(path)
        per_conc = {}
        for record in records:
            per_conc.setdefault(record["concurrency"], []).append(record)
        cell = {}
        total_connections = 0
        for conc, rows in sorted(per_conc.items()):
            good = [r for r in rows if r.get("connections")]
            total_connections += sum(r.get("connections", 0) for r in rows)
            cell[f"c{conc}"] = {
                "samples": len(rows),
                "medianConnectionsPerSecond": median_or_none(
                    [r["connectionsPerSecond"] for r in good]),
                "medianP50Ms": median_or_none(
                    [r["p50Seconds"] * 1000 for r in good]),
                "medianP95Ms": median_or_none(
                    [r["p95Seconds"] * 1000 for r in good]),
                "medianP99Ms": median_or_none(
                    [r["p99Seconds"] * 1000 for r in good]),
                "failedConnections": sum(r.get("failed", 0) for r in rows),
            }
        entry = {"byConcurrency": cell, "totalConnections": total_connections}
        cpu_path = os.path.join(out_dir, f"cpu-{label}.json")
        if os.path.exists(cpu_path):
            with open(cpu_path) as fh:
                cpu = json.load(fh)
            entry["cpuMethod"] = cpu.get("method")
            entry["cpuSeconds"] = cpu.get("cpuSeconds")
            if total_connections and cpu.get("cpuSeconds") is not None:
                entry["cpuMsPerConnection"] = cpu["cpuSeconds"] * 1000 / total_connections
        setup[label] = entry
    summary["setup"] = setup

    throughput = {}
    integrity_failures = []
    transfer_errors = []
    for path in sorted(glob.glob(os.path.join(out_dir, "tput-*.jsonl"))):
        stem = os.path.basename(path)[len("tput-"):-len(".jsonl")]
        label, mib, conc = stem.rsplit("-", 2)
        records = _read_jsonl(path)
        rates = [r["throughputMiBPerSecond"] for r in records
                 if "throughputMiBPerSecond" in r]
        for record in records:
            if record.get("integrity") == "fail":
                integrity_failures.append(stem)
            if record.get("error"):
                transfer_errors.append({stem: record["error"]})
        throughput.setdefault(label, {}).setdefault(mib, {})[conc] = {
            "samples": len(records),
            "medianMiBPerSecond": median_or_none(rates),
            "errors": sum(1 for r in records if r.get("error")),
            "integrity": next((r.get("integrity") for r in records
                               if r.get("integrity") != "skip"), "skip"),
        }
    summary["throughput"] = throughput

    verdicts = {}
    for name, key in (("summary-routing.json", "routingCorrectness"),
                      ("summary-longflow.json", "longFlowRelay")):
        path = os.path.join(out_dir, name)
        if os.path.exists(path):
            with open(path) as fh:
                report = json.load(fh)
            summary[key] = report
            verdicts[key] = report.get("verdict")
    failed = [k for k, v in verdicts.items() if v != "PASS"]
    if integrity_failures:
        failed.append("byteIntegrity")
    summary["integrityFailures"] = integrity_failures
    summary["transferErrors"] = transfer_errors[:20]
    if failed:
        summary["overallVerdict"] = "FAIL"
        summary["failedSections"] = failed
    elif transfer_errors:
        summary["overallVerdict"] = "DEGRADED"
    else:
        summary["overallVerdict"] = "PASS"
    with open(os.path.join(out_dir, "summary.json"), "w") as fh:
        json.dump(summary, fh, indent=2)
        fh.write("\n")
    print(f"overall verdict: {summary['overallVerdict']}"
          + (f" failed={failed}" if failed else ""))
    return 0 if summary["overallVerdict"] == "PASS" else 1


# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("socks-server", help="minimal SOCKS5 CONNECT server")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--fixed-target", help="rewrite every CONNECT to host:port")

    p = sub.add_parser("pick-domain", help="pick a concrete domain from geosite.dat")
    p.add_argument("--dat", required=True)
    p.add_argument("--labels", required=True, help="comma-separated candidate labels")

    p = sub.add_parser("gen-routing-config", help="routing correctness proof config")
    p.add_argument("--base", required=True)
    p.add_argument("--uuids", required=True, help="four comma-separated UUIDs")
    p.add_argument("--origin-a-port", type=int, required=True)
    p.add_argument("--socks-b-port", type=int, required=True)
    p.add_argument("--blocked-port", type=int, required=True)
    p.add_argument("--geosite-label", required=True)
    p.add_argument("--assets", required=True)
    p.add_argument("--log-level", default="warn")
    p.add_argument("--out", required=True)

    p = sub.add_parser("gen-scale-config", help="routing decision cost config")
    p.add_argument("--base", required=True)
    p.add_argument("--uuid-file", required=True)
    p.add_argument("--uuids", type=int, required=True)
    p.add_argument("--rules", type=int, required=True)
    p.add_argument("--global-rules", type=int, required=True)
    p.add_argument("--with-ip", action="store_true")
    p.add_argument("--strategy", choices=["AsIs", "IPIfNonMatch", "IPOnDemand"],
                   default="AsIs")
    p.add_argument("--assets", required=True)
    p.add_argument("--log-level", default="warn")
    p.add_argument("--out", required=True)

    p = sub.add_parser("route-probe", help="run the (uuid, destination) matrix")
    p.add_argument("--plan", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--summary", required=True)

    p = sub.add_parser("setup-rate", help="setup latency + connections/sec")
    p.add_argument("--label", required=True)
    p.add_argument("--socks-port", type=int, required=True)
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--path", default="/payload-0.bin")
    p.add_argument("--samples", type=int, default=3)
    p.add_argument("--conns", type=int, default=96)
    p.add_argument("--concurrencies", default="8 32")
    p.add_argument("--out", required=True)

    p = sub.add_parser("throughput", help="curl transfer cells with integrity")
    p.add_argument("--label", required=True)
    p.add_argument("--socks-port", type=int, required=True)
    p.add_argument("--url", required=True)
    p.add_argument("--mib", type=int, required=True)
    p.add_argument("--samples", type=int, default=3)
    p.add_argument("--concurrencies", default="1 32")
    p.add_argument("--max-time", type=int, default=600)
    p.add_argument("--expected-sha256")
    p.add_argument("--out", required=True)

    p = sub.add_parser("relay-evidence", help="verify steady-state relay backend")
    p.add_argument("--log", required=True)
    p.add_argument("--expect-backend", default="splice")
    p.add_argument("--out", required=True)

    p = sub.add_parser("summarize", help="aggregate output dir into summary.json")
    p.add_argument("--out-dir", required=True)

    args = parser.parse_args()
    if args.command == "socks-server":
        target = None
        if args.fixed_target:
            host, port = args.fixed_target.rsplit(":", 1)
            target = (host, int(port))
        print(f"socks-server listening on {args.port} fixed_target={target}",
              file=sys.stderr)
        return run_socks_server(args.port, target)
    if args.command == "pick-domain":
        return pick_domain(args.dat, args.labels)
    if args.command == "gen-routing-config":
        gen_routing_config(args)
        return 0
    if args.command == "gen-scale-config":
        gen_scale_config(args)
        return 0
    if args.command == "route-probe":
        return route_probe(args)
    if args.command == "setup-rate":
        return cmd_setup_rate(args)
    if args.command == "throughput":
        return cmd_throughput(args)
    if args.command == "relay-evidence":
        return cmd_relay_evidence(args)
    if args.command == "summarize":
        return cmd_summarize(args)
    return 2

if __name__ == "__main__":
    sys.exit(main())
