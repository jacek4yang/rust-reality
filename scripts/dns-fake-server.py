#!/usr/bin/env python3
"""Deterministic loopback fake DNS server with counted queries.

Companion to scripts/benchmark-dns-comparison.sh and
scripts/benchmark-routing-comparison.sh (mirrors tests/dns_resolver.rs's
FakeDns in Python).  Speaks real DNS wire format over UDP on 127.0.0.1:

* A queries get one fixed IPv4 answer (default 127.0.0.1) with the
  configured TTL.
* AAAA queries get a NODATA answer carrying an SOA (negative TTL = TTL), so
  resolvers with negative caching behave like they would against a real
  dual-stack zone with no AAAA records.
* Every parsed query is counted per (name, qtype); counts are served as JSON
  over a loopback TCP control port (one "counts\n" line in, one JSON line
  out).  Unparseable queries are dropped, like FakeDns's Drop scenario.

No external network is used: every datagram stays on loopback.
"""

import argparse
import json
import socket
import socketserver
import struct
import threading

TYPE_A = 1
TYPE_AAAA = 28
TYPE_SOA = 6
CLASS_IN = 1


def parse_question(packet: bytes):
    if len(packet) < 12:
        return None
    qdcount = struct.unpack_from(">H", packet, 4)[0]
    if qdcount < 1:
        return None
    offset = 12
    labels = []
    while True:
        if offset >= len(packet):
            return None
        length = packet[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 or offset + 1 + length > len(packet):
            return None
        labels.append(packet[offset + 1:offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
    if offset + 4 > len(packet):
        return None
    qtype, qclass = struct.unpack_from(">HH", packet, offset)
    if qclass != CLASS_IN:
        return None
    return ".".join(labels).lower(), qtype


def soa_rdata(minimum: int) -> bytes:
    # mname=ns1.invalid. rname=hostmaster.invalid. + serial/refresh/retry/expire/minimum
    name = b"\x03ns1\x07invalid\x00" + b"\x0ahostmaster\x07invalid\x00"
    return name + struct.pack(">IIIII", 1, 60, 30, 604800, minimum)


def build_response(packet: bytes, name: str, qtype: int, a_answer: str, ttl: int) -> bytes:
    ident, flags = struct.unpack_from(">HH", packet, 0)
    question_end = 12
    while packet[question_end] != 0:
        question_end += 1 + packet[question_end]
    question = packet[12:question_end + 5]
    rflags = 0x8180  # QR | RD(copied below) | RA, RCODE=0
    rflags |= flags & 0x0100  # copy RD
    if qtype == TYPE_A:
        header = struct.pack(">HHHHHH", ident, rflags, 1, 1, 0, 0)
        answer = b"\xc0\x0c" + struct.pack(">HHIH", TYPE_A, CLASS_IN, ttl, 4)
        answer += socket.inet_aton(a_answer)
        return header + question + answer
    if qtype == TYPE_AAAA:
        rdata = soa_rdata(ttl)
        header = struct.pack(">HHHHHH", ident, rflags, 1, 0, 1, 0)
        authority = b"\xc0\x0c" + struct.pack(">HHIH", TYPE_SOA, CLASS_IN, ttl, len(rdata))
        return header + question + authority + rdata
    # Unsupported qtype: NODATA without authority (never cached).
    header = struct.pack(">HHHHHH", ident, rflags, 1, 0, 0, 0)
    return header + question


class State:
    def __init__(self, a_answer: str, ttl: int):
        self.a_answer = a_answer
        self.ttl = ttl
        self.lock = threading.Lock()
        self.by_name: dict[str, int] = {}
        self.by_type: dict[str, int] = {}
        self.total = 0

    def record(self, name: str, qtype: int) -> None:
        with self.lock:
            self.total += 1
            self.by_name[name] = self.by_name.get(name, 0) + 1
            label = {TYPE_A: "A", TYPE_AAAA: "AAAA"}.get(qtype, str(qtype))
            self.by_type[label] = self.by_type.get(label, 0) + 1

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "total": self.total,
                "byName": dict(sorted(self.by_name.items())),
                "byType": dict(sorted(self.by_type.items())),
            }


class UdpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        packet, sock = self.request
        state: State = self.server.state  # type: ignore[attr-defined]
        parsed = parse_question(packet)
        if parsed is None:
            return  # Drop scenario: never answer.
        name, qtype = parsed
        state.record(name, qtype)
        response = build_response(packet, name, qtype, state.a_answer, state.ttl)
        sock.sendto(response, self.client_address)


class ControlHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        state: State = self.server.state  # type: ignore[attr-defined]
        line = self.rfile.readline().strip()
        if line != b"counts":
            return
        self.wfile.write(json.dumps(state.snapshot(), sort_keys=True).encode() + b"\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen-port", type=int, required=True, help="UDP DNS port")
    parser.add_argument("--control-port", type=int, required=True, help="TCP counts port")
    parser.add_argument("--a-answer", default="127.0.0.1")
    parser.add_argument("--ttl", type=int, default=300)
    args = parser.parse_args()

    state = State(args.a_answer, args.ttl)

    class UdpServer(socketserver.ThreadingUDPServer):
        daemon_threads = True

    class TcpServer(socketserver.ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = True

    udp = UdpServer(("127.0.0.1", args.listen_port), UdpHandler)
    udp.state = state  # type: ignore[attr-defined]
    tcp = TcpServer(("127.0.0.1", args.control_port), ControlHandler)
    tcp.state = state  # type: ignore[attr-defined]
    threading.Thread(target=udp.serve_forever, daemon=True).start()
    tcp.serve_forever()


if __name__ == "__main__":
    main()
