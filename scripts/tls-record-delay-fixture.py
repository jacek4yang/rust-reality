#!/usr/bin/env python3
"""Bounded loopback TLS-record delay and fifth-record probe fixture."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import select
import socket
import threading
import time
from pathlib import Path


DELAYS_MS = (0, 20, 50, 100, 200)
PROBE_CASES = ("already-buffered", "single-probe-present", "absent-would-block")
MAX_RECORD_WIRE_BYTES = 16_645
CASE_TIMEOUT_SECONDS = 5.0


def tls_record(content_type: int, payload: bytes) -> bytes:
    if not payload or len(payload) + 5 > MAX_RECORD_WIRE_BYTES:
        raise ValueError("fixture TLS record payload is outside its bound")
    return bytes((content_type, 3, 3)) + len(payload).to_bytes(2, "big") + payload


def server_hello_record(
    session_id: bytes = bytes(range(32)), cipher: bytes = b"\x13\x01"
) -> bytes:
    if len(session_id) > 32 or len(cipher) != 2:
        raise ValueError("invalid ServerHello echo parameters")
    key_share = b"\x00\x1d\x00\x20" + bytes((index ^ 0x5A) for index in range(32))
    extensions = b"\x00\x2b\x00\x02\x03\x04" + b"\x00\x33" + len(
        key_share
    ).to_bytes(2, "big") + key_share
    body = (
        b"\x03\x03"
        + bytes((index ^ 0xA5) for index in range(32))
        + bytes((len(session_id),))
        + session_id
        + cipher
        + b"\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    message = b"\x02" + len(body).to_bytes(3, "big") + body
    return tls_record(22, message)


def fixture_records(
    ccs_present: bool,
    session_id: bytes = bytes(range(32)),
    cipher: bytes = b"\x13\x01",
) -> list[tuple[str, bytes]]:
    records = [("server-hello", server_hello_record(session_id, cipher))]
    if ccs_present:
        records.append(("change-cipher-spec", tls_record(20, b"\x01")))
    for position, body_len in enumerate((32, 48, 64, 80), start=1):
        records.append(
            (
                f"encrypted-{position}",
                tls_record(23, bytes((0x30 + position,)) * body_len),
            )
        )
    records.append(("fifth-ticket", tls_record(23, b"\xF5" * 24)))
    return records


def receive_client_hello(connection: socket.socket) -> tuple[bytes, bytes, bytes]:
    header = read_exact(connection, 5, [])
    if header[0] != 22 or header[1:3] != b"\x03\x01":
        raise ValueError("fixture expected one TLS ClientHello record")
    body_length = int.from_bytes(header[3:5], "big")
    if body_length <= 0 or body_length + 5 > MAX_RECORD_WIRE_BYTES:
        raise ValueError("ClientHello record length is outside the fixture bound")
    body = read_exact(connection, body_length, [])
    if len(body) < 44 or body[0] != 1:
        raise ValueError("fixture received a malformed ClientHello")
    if int.from_bytes(body[1:4], "big") + 4 != len(body):
        raise ValueError("fixture requires exactly one complete ClientHello")
    cursor = 4 + 2 + 32
    session_id_length = body[cursor]
    cursor += 1
    if session_id_length > 32 or cursor + session_id_length + 2 > len(body):
        raise ValueError("ClientHello legacy session id is malformed")
    session_id = body[cursor : cursor + session_id_length]
    cursor += session_id_length
    suites_length = int.from_bytes(body[cursor : cursor + 2], "big")
    cursor += 2
    if suites_length < 2 or suites_length % 2 or cursor + suites_length > len(body):
        raise ValueError("ClientHello cipher suites are malformed")
    suites = [body[index : index + 2] for index in range(cursor, cursor + suites_length, 2)]
    cipher = next(
        (suite for suite in (b"\x13\x01", b"\x13\x02", b"\x13\x03") if suite in suites),
        None,
    )
    if cipher is None:
        raise ValueError("ClientHello offered no supported TLS 1.3 cipher")
    return header + body, session_id, cipher


def serve_cover(arguments: argparse.Namespace) -> None:
    if arguments.delay_ms not in DELAYS_MS:
        raise ValueError("unsupported fixture record delay")
    if arguments.max_accepted != 1:
        raise ValueError("serve-cover requires --max-accepted 1")
    started_ns = time.monotonic_ns()
    send_events: list[dict] = []
    with socket.create_server(("127.0.0.1", arguments.listen_port)) as listener:
        listener.settimeout(arguments.absolute_timeout_seconds)
        actual_port = listener.getsockname()[1]
        print(
            json.dumps({"event": "READY", "listenPort": actual_port, "pid": os.getpid()}),
            flush=True,
        )
        connection, peer = listener.accept()
        with connection:
            connection.settimeout(arguments.absolute_timeout_seconds)
            client_hello, session_id, cipher = receive_client_hello(connection)
            records = fixture_records(arguments.emit_ccs, session_id, cipher)
            before_ticket = records[:-1]
            write_id = 0
            for index, (role, record) in enumerate(before_ticket):
                if index:
                    time.sleep(arguments.delay_ms / 1000)
                payload = record
                if role == "encrypted-4" and arguments.probe_case == "already-buffered":
                    payload += records[-1][1]
                sent_at = time.monotonic_ns()
                connection.sendall(payload)
                send_events.append(
                    {"role": role, "wireLength": len(record), "writeId": write_id, "sentAtNs": sent_at}
                )
                if len(payload) != len(record):
                    send_events.append(
                        {"role": "fifth-ticket", "wireLength": len(records[-1][1]), "writeId": write_id, "sentAtNs": sent_at}
                    )
                write_id += 1
            if arguments.probe_case == "single-probe-present":
                time.sleep(0.001)
                ticket = records[-1][1]
                sent_at = time.monotonic_ns()
                connection.sendall(ticket)
                send_events.append(
                    {"role": "fifth-ticket", "wireLength": len(ticket), "writeId": write_id, "sentAtNs": sent_at}
                )
            try:
                while connection.recv(512):
                    pass
            except (ConnectionResetError, socket.timeout):
                pass

    retained = b"".join(record for _role, record in before_ticket)
    if arguments.probe_case == "already-buffered":
        retained += records[-1][1][:5]
    result = {
        "schemaVersion": 1,
        "mode": "serve-cover",
        "status": "PASS",
        "pid": os.getpid(),
        "peer": peer[0],
        "listenPort": actual_port,
        "delayMs": arguments.delay_ms,
        "expectedClassification": arguments.probe_case,
        "emitCcs": arguments.emit_ccs,
        "clientHello": {
            "bytes": len(client_hello),
            "sha256": hashlib.sha256(client_hello).hexdigest(),
            "legacySessionIdBytes": len(session_id),
        },
        "expectedCandidatePlan": {
            "layout": "positional",
            "encryptedRecordWireLengths": [
                len(record) for role, record in records if role.startswith("encrypted-")
            ],
            "nstWireLength": (
                len(records[-1][1]) if arguments.probe_case != "absent-would-block" else None
            ),
            "retainedPrefixBytes": len(retained),
            "retainedPrefixSha256": hashlib.sha256(retained).hexdigest(),
        },
        "records": [
            {
                **event,
                "sentOffsetMs": round((event["sentAtNs"] - started_ns) / 1_000_000, 3),
            }
            for event in send_events
        ],
        "absoluteTimeoutSeconds": arguments.absolute_timeout_seconds,
        "maxAccepted": arguments.max_accepted,
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    with arguments.output.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")
    print(json.dumps({"event": "COMPLETE", "status": "PASS"}), flush=True)


def read_exact(connection: socket.socket, length: int, events: list[dict]) -> bytes:
    output = bytearray()
    while len(output) < length:
        chunk = connection.recv(length - len(output))
        if not chunk:
            raise EOFError("fixture peer closed before a complete TLS record")
        events.append(
            {
                "receivedAtNs": time.monotonic_ns(),
                "bytes": len(chunk),
                "mode": "blocking-server-hello",
            }
        )
        output.extend(chunk)
    return bytes(output)


class BufferedRecordReader:
    def __init__(self, connection: socket.socket, prefix: bytes, receive_events: list[dict]):
        self.connection = connection
        self.buffer = bytearray(prefix)
        self.consumed = len(prefix)
        self.receive_events = receive_events
        self.record_events: list[dict] = []

    def fill(self, length: int) -> None:
        target = self.consumed + length
        while len(self.buffer) < target:
            needed = target - len(self.buffer)
            request = min(4096, needed + 5)
            chunk = self.connection.recv(request)
            if not chunk:
                raise EOFError("fixture peer closed during a positional record")
            self.receive_events.append(
                {
                    "receivedAtNs": time.monotonic_ns(),
                    "bytes": len(chunk),
                    "mode": "blocking-refill",
                    "requestedBytes": request,
                }
            )
            self.buffer.extend(chunk)

    def consume_record(self, role: str, expected_type: int) -> None:
        self.fill(5)
        header = self.buffer[self.consumed : self.consumed + 5]
        if header[0] != expected_type or header[1:3] != b"\x03\x03":
            raise ValueError(f"unexpected {role} TLS record header")
        wire_length = 5 + int.from_bytes(header[3:5], "big")
        if wire_length <= 5 or wire_length > MAX_RECORD_WIRE_BYTES:
            raise ValueError(f"invalid {role} TLS record length")
        self.fill(wire_length)
        self.consumed += wire_length
        self.record_events.append(
            {
                "role": role,
                "wireLength": wire_length,
                "consumedAtNs": time.monotonic_ns(),
            }
        )

    def probe_fifth(self) -> tuple[str, int | None, int]:
        buffered_before = len(self.buffer) - self.consumed
        probe_reads = 0
        if buffered_before < 5:
            try:
                chunk = self.connection.recv(512, socket.MSG_DONTWAIT)
            except BlockingIOError:
                chunk = b""
            probe_reads = 1
            self.receive_events.append(
                {
                    "receivedAtNs": time.monotonic_ns(),
                    "bytes": len(chunk),
                    "mode": "single-nonblocking-probe",
                    "wouldBlock": not chunk,
                    "requestedBytes": 512,
                }
            )
            self.buffer.extend(chunk)
        available = len(self.buffer) - self.consumed
        if available < 5:
            return "absent-would-block", None, probe_reads
        header = self.buffer[self.consumed : self.consumed + 5]
        if header[0] != 23 or header[1:3] != b"\x03\x03":
            raise ValueError("fifth record header is not TLS ApplicationData")
        wire_length = 5 + int.from_bytes(header[3:5], "big")
        classification = "already-buffered" if buffered_before >= 5 else "single-probe-present"
        return classification, wire_length, probe_reads


def run_case(delay_ms: int, probe_case: str, listen_port: int) -> dict:
    if delay_ms not in DELAYS_MS or probe_case not in PROBE_CASES:
        raise ValueError("unsupported fixture matrix case")
    ccs_present = probe_case != "single-probe-present"
    records = fixture_records(ccs_present)
    prefix_without_fifth = b"".join(record for _role, record in records[:-1])
    fifth_header = records[-1][1][:5]
    case_started_ns = time.monotonic_ns()
    fourth_consumed = threading.Event()
    probe_may_run = threading.Event()
    probe_done = threading.Event()
    ready = threading.Event()
    server_errors: list[str] = []
    send_events: list[dict] = []
    actual_port: list[int] = []

    def server() -> None:
        try:
            with socket.create_server(("127.0.0.1", listen_port)) as listener:
                listener.settimeout(CASE_TIMEOUT_SECONDS)
                actual_port.append(listener.getsockname()[1])
                ready.set()
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(CASE_TIMEOUT_SECONDS)
                    write_id = 0
                    for index, (role, record) in enumerate(records[:-2]):
                        if index:
                            time.sleep(delay_ms / 1000)
                        started = time.monotonic_ns()
                        connection.sendall(record)
                        completed = time.monotonic_ns()
                        send_events.append(
                            {
                                "role": role,
                                "wireLength": len(record),
                                "writeId": write_id,
                                "sendStartedNs": started,
                                "sendCompletedNs": completed,
                            }
                        )
                        write_id += 1
                    time.sleep(delay_ms / 1000)
                    fourth_role, fourth = records[-2]
                    fifth_role, fifth = records[-1]
                    if probe_case == "already-buffered":
                        started = time.monotonic_ns()
                        connection.sendall(fourth + fifth)
                        completed = time.monotonic_ns()
                        for role, record in ((fourth_role, fourth), (fifth_role, fifth)):
                            send_events.append(
                                {
                                    "role": role,
                                    "wireLength": len(record),
                                    "writeId": write_id,
                                    "sendStartedNs": started,
                                    "sendCompletedNs": completed,
                                }
                            )
                    else:
                        started = time.monotonic_ns()
                        connection.sendall(fourth)
                        completed = time.monotonic_ns()
                        send_events.append(
                            {
                                "role": fourth_role,
                                "wireLength": len(fourth),
                                "writeId": write_id,
                                "sendStartedNs": started,
                                "sendCompletedNs": completed,
                            }
                        )
                        if not fourth_consumed.wait(CASE_TIMEOUT_SECONDS):
                            raise TimeoutError("reader did not consume fourth record")
                        if probe_case == "single-probe-present":
                            started = time.monotonic_ns()
                            connection.sendall(fifth)
                            completed = time.monotonic_ns()
                            send_events.append(
                                {
                                    "role": fifth_role,
                                    "wireLength": len(fifth),
                                    "writeId": write_id + 1,
                                    "sendStartedNs": started,
                                    "sendCompletedNs": completed,
                                }
                            )
                            # sendall() only hands bytes to the local kernel. Do
                            # not release the production-style one-shot probe
                            # until the peer socket reports those bytes readable.
                            readable, _, _ = select.select(
                                [client_connection], [], [], CASE_TIMEOUT_SECONDS
                            )
                            if not readable:
                                raise TimeoutError("fifth record did not become readable")
                        probe_may_run.set()
        except Exception as error:  # self-test evidence must preserve server failures
            server_errors.append(f"{type(error).__name__}: {error}")
            ready.set()

    server_thread = threading.Thread(target=server, name="tls-record-fixture", daemon=True)
    server_thread.start()
    if not ready.wait(CASE_TIMEOUT_SECONDS) or not actual_port:
        raise TimeoutError("fixture listener did not become ready")
    receive_events: list[dict] = []
    with socket.create_connection(("127.0.0.1", actual_port[0]), timeout=CASE_TIMEOUT_SECONDS) as client:
        client_connection = client
        client.settimeout(CASE_TIMEOUT_SECONDS)
        header = read_exact(client, 5, receive_events)
        server_hello = header + read_exact(
            client, int.from_bytes(header[3:5], "big"), receive_events
        )
        reader = BufferedRecordReader(client, server_hello, receive_events)
        if ccs_present:
            reader.consume_record("change-cipher-spec", 20)
        for position in range(1, 5):
            reader.consume_record(f"encrypted-{position}", 23)
        fourth_consumed.set()
        if probe_case != "already-buffered" and not probe_may_run.wait(CASE_TIMEOUT_SECONDS):
            raise TimeoutError("fixture server did not release the probe")
        try:
            classification, fifth_wire_length, probe_reads = reader.probe_fifth()
        finally:
            probe_done.set()
        observed_prefix = bytes(reader.buffer)
    server_thread.join(CASE_TIMEOUT_SECONDS)
    if server_thread.is_alive():
        raise TimeoutError("fixture server exceeded its absolute bound")
    if server_errors:
        raise RuntimeError(server_errors[0])
    expected_prefix = {
        "already-buffered": prefix_without_fifth + fifth_header,
        "single-probe-present": prefix_without_fifth + records[-1][1],
        "absent-would-block": prefix_without_fifth,
    }[probe_case]
    ok = (
        classification == probe_case
        and observed_prefix == expected_prefix
        and (probe_reads == 0) == (probe_case == "already-buffered")
        and (fifth_wire_length == len(records[-1][1]))
        == (probe_case != "absent-would-block")
    )
    return {
        "status": "PASS" if ok else "FAIL",
        "delayMs": delay_ms,
        "expectedClassification": probe_case,
        "observedClassification": classification,
        "ccsPresent": ccs_present,
        "pid": os.getpid(),
        "listenAddress": "127.0.0.1",
        "listenPort": actual_port[0],
        "absoluteTimeoutSeconds": CASE_TIMEOUT_SECONDS,
        "probeReads": probe_reads,
        "fifthWireLength": fifth_wire_length,
        "prefix": {
            "bytes": len(observed_prefix),
            "sha256": hashlib.sha256(observed_prefix).hexdigest(),
            "expectedBytes": len(expected_prefix),
            "expectedSha256": hashlib.sha256(expected_prefix).hexdigest(),
            "byteExact": observed_prefix == expected_prefix,
        },
        "records": [
            {
                **event,
                "sendStartedOffsetMs": round(
                    (event["sendStartedNs"] - case_started_ns) / 1_000_000, 3
                ),
                "sendCompletedOffsetMs": round(
                    (event["sendCompletedNs"] - case_started_ns) / 1_000_000, 3
                ),
            }
            for event in send_events
        ],
        "readerRecords": reader.record_events,
        "receiveCalls": receive_events,
    }


def run_matrix(arguments: argparse.Namespace) -> None:
    if not 0 <= arguments.listen_port <= 65535:
        raise ValueError("listen port is outside 0..65535")
    cases = [
        run_case(delay, probe_case, arguments.listen_port)
        for delay in DELAYS_MS
        for probe_case in PROBE_CASES
    ]
    classifications = {case["observedClassification"] for case in cases}
    result = {
        "schemaVersion": 1,
        "gate": "tls-server-record-delay-and-nst-probe",
        "transport": "real loopback TCP with TLS-record-aware server writes; no tc/netem",
        "delaysMs": list(DELAYS_MS),
        "probeClassifications": list(PROBE_CASES),
        "caseCount": len(cases),
        "productionReaderTests": [
            "protocol::reality::tls13::target_read::tests::positional_shape_probes_and_retains_a_fifth_ticket_record",
            "protocol::reality::tls13::target_read::tests::positional_shape_without_ccs_or_ticket_is_retained_exactly",
            "protocol::reality::tls13::target_read::tests::tcp_record_delay_matrix_covers_fifth_probe_timing",
        ],
        "cases": cases,
        "ok": all(case["status"] == "PASS" for case in cases)
        and classifications == set(PROBE_CASES),
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    with arguments.output.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")
    print(json.dumps({key: result[key] for key in ("gate", "caseCount", "ok")}))
    if not result["ok"]:
        raise SystemExit("TLS record delay fixture gate failed")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    matrix = subparsers.add_parser("matrix")
    matrix.add_argument("--listen-port", type=int, required=True)
    matrix.add_argument("--output", type=Path, required=True)
    matrix.set_defaults(function=run_matrix)
    self_test = subparsers.add_parser("self-test")
    self_test.add_argument("--output", type=Path, required=True)
    self_test.set_defaults(
        function=lambda arguments: run_matrix(
            argparse.Namespace(listen_port=0, output=arguments.output)
        )
    )
    cover = subparsers.add_parser("serve-cover")
    cover.add_argument("--listen-port", type=int, required=True)
    cover.add_argument("--delay-ms", type=int, choices=DELAYS_MS, required=True)
    cover.add_argument("--probe-case", choices=PROBE_CASES, required=True)
    cover.add_argument("--emit-ccs", type=int, choices=(0, 1), required=True)
    cover.add_argument("--max-accepted", type=int, default=1)
    cover.add_argument("--absolute-timeout-seconds", type=float, default=10.0)
    cover.add_argument("--output", type=Path, required=True)
    cover.set_defaults(function=serve_cover)
    return parser


def main() -> None:
    arguments = build_parser().parse_args()
    if hasattr(arguments, "emit_ccs"):
        arguments.emit_ccs = bool(arguments.emit_ccs)
    arguments.function(arguments)


if __name__ == "__main__":
    main()
