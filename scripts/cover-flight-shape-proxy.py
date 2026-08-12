#!/usr/bin/env python3
"""Append deterministic opaque records to bounded loopback TLS 1.3 flights."""

from __future__ import annotations

import argparse
import json
import socket

MAX_TLS_CIPHERTEXT_LEN = 16_640
FAKE_FIFTH = b"\x17\x03\x03\x00\x86" + bytes(134)


def read_exact(connection: socket.socket, length: int) -> bytes:
    """Read exactly length bytes or reject a truncated record."""
    output = bytearray()
    while len(output) < length:
        chunk = connection.recv(length - len(output))
        if not chunk:
            raise EOFError("TLS record truncated")
        output.extend(chunk)
    return bytes(output)


def read_record(connection: socket.socket) -> bytes:
    """Read one bounded TLS outer record."""
    header = read_exact(connection, 5)
    length = int.from_bytes(header[3:5], "big")
    if length == 0 or length > MAX_TLS_CIPHERTEXT_LEN:
        raise ValueError(f"invalid TLS record length: {length}")
    return header + read_exact(connection, length)


def handle(client: socket.socket, upstream_port: int) -> bool:
    """Forward one ClientHello and shape the corresponding server flight."""
    try:
        client.settimeout(2)
        client_hello = read_record(client)
        with socket.create_connection(("127.0.0.1", upstream_port), timeout=2) as upstream:
            upstream.settimeout(5)
            upstream.sendall(client_hello)
            response: list[bytes] = []
            encrypted_wire_lengths: list[int] = []
            while len(encrypted_wire_lengths) < 4:
                record = read_record(upstream)
                response.append(record)
                if record[0] == 0x17:
                    encrypted_wire_lengths.append(len(record))
                if len(response) > 8:
                    raise ValueError(
                        "cover emitted too many records before its fourth encrypted record"
                    )
            client.sendall(b"".join(response) + FAKE_FIFTH)
            print(
                json.dumps(
                    {
                        "event": "flight_shaped",
                        "upstreamEncryptedWireLengths": encrypted_wire_lengths,
                        "appendedWireLength": len(FAKE_FIFTH),
                        "singleWriteBytes": sum(map(len, response)) + len(FAKE_FIFTH),
                    },
                    separators=(",", ":"),
                ),
                flush=True,
            )
            return True
    except (EOFError, TimeoutError, ConnectionError, OSError, ValueError) as error:
        print(
            json.dumps(
                {"event": "connection_ignored", "error": type(error).__name__},
                separators=(",", ":"),
            ),
            flush=True,
        )
        return False
    finally:
        client.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--upstream-port", type=int, required=True)
    parser.add_argument("--max-shaped", type=int, default=1)
    parser.add_argument("--max-accepted", type=int, default=8)
    args = parser.parse_args()
    if args.max_shaped <= 0:
        parser.error("--max-shaped must be positive")
    if args.max_accepted < args.max_shaped:
        parser.error("--max-accepted must be at least --max-shaped")
    return args


def main() -> None:
    args = parse_args()
    accepted = 0
    shaped = 0
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", args.listen_port))
        listener.listen(16)
        while accepted < args.max_accepted and shaped < args.max_shaped:
            connection, _ = listener.accept()
            accepted += 1
            if handle(connection, args.upstream_port):
                shaped += 1
        print(
            json.dumps(
                {
                    "event": "proxy_complete",
                    "accepted": accepted,
                    "shaped": shaped,
                    "maxAccepted": args.max_accepted,
                    "maxShaped": args.max_shaped,
                },
                separators=(",", ":"),
            ),
            flush=True,
        )
        if shaped != args.max_shaped:
            raise SystemExit(
                f"shaped {shaped} of {args.max_shaped} flights after "
                f"{accepted} accepted connections"
            )


if __name__ == "__main__":
    main()
