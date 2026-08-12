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


def server_hello_record() -> bytes:
    session_id = bytes(range(32))
    key_share = b"\x00\x1d\x00\x20" + bytes((index ^ 0x5A) for index in range(32))
    extensions = b"\x00\x2b\x00\x02\x03\x04" + b"\x00\x33" + len(
        key_share
    ).to_bytes(2, "big") + key_share
    body = (
        b"\x03\x03"
        + bytes((index ^ 0xA5) for index in range(32))
        + bytes((len(session_id),))
        + session_id
        + b"\x13\x01\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    message = b"\x02" + len(body).to_bytes(3, "big") + body
    return tls_record(22, message)


def fixture_records(ccs_present: bool) -> list[tuple[str, bytes]]:
    records = [("server-hello", server_hello_record())]
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
    return parser


def main() -> None:
    arguments = build_parser().parse_args()
    arguments.function(arguments)


if __name__ == "__main__":
    main()
