#!/usr/bin/env python3
"""Append one deterministic opaque record to a loopback TLS 1.3 server flight."""

from __future__ import annotations

import argparse
import json
import socket
import threading

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


def handle(client: socket.socket, upstream_port: int) -> None:
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
    except (EOFError, TimeoutError, ConnectionError, OSError, ValueError) as error:
        print(
            json.dumps(
                {"event": "connection_ignored", "error": type(error).__name__},
                separators=(",", ":"),
            ),
            flush=True,
        )
    finally:
        client.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--upstream-port", type=int, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", args.listen_port))
        listener.listen(16)
        while True:
            connection, _ = listener.accept()
            threading.Thread(
                target=handle,
                args=(connection, args.upstream_port),
                daemon=True,
            ).start()


if __name__ == "__main__":
    main()
