#!/usr/bin/env python3
"""Capture, replay, and summarize TLS first-flight wire shape."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import selectors
import socket
import statistics
import tempfile
import time
from pathlib import Path

TLS13_CIPHER_SUITES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}

TLS_GROUPS = {
    0x001D: "X25519",
    0x11EC: "X25519MLKEM768",
}

MAX_CLIENT_HELLO_RECORD_BYTES = 5 + 16 * 1024
DEFAULT_CAPTURE_TIMEOUT = 5.0
DEFAULT_MAX_FIRST_FLIGHT_BYTES = 1024 * 1024


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def parse_records(wire: bytes) -> list[dict[str, int]]:
    records: list[dict[str, int]] = []
    offset = 0
    while offset + 5 <= len(wire):
        length = int.from_bytes(wire[offset + 3 : offset + 5], "big")
        end = offset + 5 + length
        if end > len(wire):
            break
        records.append(
            {
                "offset": offset,
                "contentType": wire[offset],
                "legacyVersion": int.from_bytes(wire[offset + 1 : offset + 3], "big"),
                "recordLength": length,
                "wireLength": 5 + length,
            }
        )
        offset = end
    if offset != len(wire):
        records.append({"offset": offset, "trailingBytes": len(wire) - offset})
    return records


def parse_server_hello(
    wire: bytes, records: list[dict[str, int]]
) -> dict[str, str | int | None]:
    handshake_record = next(
        (record for record in records if record.get("contentType") == 22), None
    )
    if handshake_record is None:
        return {
            "negotiatedCipherSuite": None,
            "negotiatedCipherSuiteId": None,
            "negotiatedKeyShareGroup": None,
            "negotiatedKeyShareGroupId": None,
        }

    payload_offset = handshake_record["offset"] + 5
    payload_length = handshake_record["recordLength"]
    payload = wire[payload_offset : payload_offset + payload_length]
    if len(payload) < 44 or payload[0] != 2:
        raise ValueError("first handshake record is not a complete ServerHello")

    session_id_length = payload[38]
    cipher_offset = 39 + session_id_length
    if cipher_offset + 5 > len(payload):
        raise ValueError("truncated ServerHello before extensions")
    cipher_suite = int.from_bytes(payload[cipher_offset : cipher_offset + 2], "big")
    extensions_length = int.from_bytes(
        payload[cipher_offset + 3 : cipher_offset + 5], "big"
    )
    extension_offset = cipher_offset + 5
    extensions_end = extension_offset + extensions_length
    if extensions_end > len(payload):
        raise ValueError("truncated ServerHello extensions")

    key_share_group = None
    while extension_offset + 4 <= extensions_end:
        extension_type = int.from_bytes(
            payload[extension_offset : extension_offset + 2], "big"
        )
        extension_length = int.from_bytes(
            payload[extension_offset + 2 : extension_offset + 4], "big"
        )
        extension_data = extension_offset + 4
        extension_end = extension_data + extension_length
        if extension_end > extensions_end:
            raise ValueError("truncated ServerHello extension")
        if extension_type == 0x0033:
            if extension_length < 2:
                raise ValueError("truncated ServerHello key_share")
            key_share_group = int.from_bytes(
                payload[extension_data : extension_data + 2], "big"
            )
            break
        extension_offset = extension_end

    return {
        "negotiatedCipherSuite": TLS13_CIPHER_SUITES.get(
            cipher_suite, f"0x{cipher_suite:04x}"
        ),
        "negotiatedCipherSuiteId": cipher_suite,
        "negotiatedKeyShareGroup": None
        if key_share_group is None
        else TLS_GROUPS.get(key_share_group, f"0x{key_share_group:04x}"),
        "negotiatedKeyShareGroupId": key_share_group,
    }


def capture_proxy(arguments: argparse.Namespace) -> None:
    if arguments.absolute_timeout <= 0:
        raise ValueError("absolute timeout must be positive")
    if arguments.max_client_hello_bytes < 5:
        raise ValueError("ClientHello byte cap must include a TLS record header")
    deadline = time.monotonic() + arguments.absolute_timeout
    with socket.create_server(
        (arguments.listen_host, arguments.listen_port)
    ) as listener:
        print(f"READY port={arguments.listen_port}", flush=True)
        listener.settimeout(arguments.absolute_timeout)
        try:
            client, _ = listener.accept()
        except TimeoutError:
            arguments.output.write_bytes(b"")
            raise TimeoutError("capture proxy absolute deadline elapsed") from None
        remaining_time = deadline - time.monotonic()
        if remaining_time <= 0:
            arguments.output.write_bytes(b"")
            raise TimeoutError("capture proxy absolute deadline elapsed")
        with (
            client,
            socket.create_connection(
                (arguments.upstream_host, arguments.upstream_port),
                timeout=min(10.0, remaining_time),
            ) as upstream,
        ):
            client.setblocking(False)
            upstream.setblocking(False)
            selector = selectors.DefaultSelector()
            selector.register(client, selectors.EVENT_READ, upstream)
            selector.register(upstream, selectors.EVENT_READ, client)
            captured = bytearray()
            expected = None
            while selector.get_map():
                remaining_time = deadline - time.monotonic()
                if remaining_time <= 0:
                    arguments.output.write_bytes(captured)
                    raise TimeoutError("capture proxy absolute deadline elapsed")
                events = selector.select(timeout=min(1.0, remaining_time))
                if not events:
                    continue
                for key, _ in events:
                    source = key.fileobj
                    destination = key.data
                    try:
                        chunk = source.recv(65536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(source)
                        try:
                            destination.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        continue
                    if source is client and (
                        expected is None or len(captured) < expected
                    ):
                        remaining_capacity = arguments.max_client_hello_bytes - len(
                            captured
                        )
                        captured.extend(chunk[:remaining_capacity])
                        if len(chunk) > remaining_capacity:
                            arguments.output.write_bytes(captured)
                            raise ValueError("ClientHello capture exceeded byte cap")
                        if expected is None and len(captured) >= 5:
                            expected = 5 + int.from_bytes(captured[3:5], "big")
                            if expected > arguments.max_client_hello_bytes:
                                arguments.output.write_bytes(captured)
                                raise ValueError(
                                    "declared ClientHello record exceeds byte cap"
                                )
                        if expected is not None and len(captured) >= expected:
                            arguments.output.write_bytes(captured[:expected])
                            print(f"CAPTURED bytes={expected}", flush=True)
                    view = memoryview(chunk)
                    while view:
                        if time.monotonic() >= deadline:
                            arguments.output.write_bytes(captured)
                            raise TimeoutError(
                                "capture proxy absolute deadline elapsed"
                            )
                        try:
                            written = destination.send(view)
                        except BlockingIOError:
                            continue
                        view = view[written:]
            if expected is None or len(captured) < expected:
                raise RuntimeError("ClientHello record was incomplete")


def replay(arguments: argparse.Namespace) -> None:
    if arguments.capture_timeout <= 0 or arguments.read_timeout <= 0:
        raise ValueError("capture and read timeouts must be positive")
    if arguments.max_response_bytes < 1:
        raise ValueError("response byte cap must be positive")
    client_hello = arguments.client_hello.read_bytes()
    response = bytearray()
    connected_ns = time.monotonic_ns()
    first_byte_ns = None
    last_byte_ns = None
    capture_end_reason = "unknown"
    capture_deadline = time.monotonic() + arguments.capture_timeout
    with socket.create_connection(
        (arguments.host, arguments.port),
        timeout=min(arguments.connect_timeout, arguments.capture_timeout),
    ) as connection:
        peer_address = connection.getpeername()[0]
        before_send_ns = time.monotonic_ns()
        connection.sendall(client_hello)
        after_send_ns = time.monotonic_ns()
        while True:
            remaining_time = capture_deadline - time.monotonic()
            if remaining_time <= 0:
                capture_end_reason = "absolute_timeout"
                break
            connection.settimeout(min(arguments.read_timeout, remaining_time))
            try:
                chunk = connection.recv(65536)
            except TimeoutError:
                capture_end_reason = (
                    "absolute_timeout"
                    if time.monotonic() >= capture_deadline
                    else "idle_timeout"
                )
                break
            if not chunk:
                capture_end_reason = "peer_eof"
                break
            now = time.monotonic_ns()
            if first_byte_ns is None:
                first_byte_ns = now
            last_byte_ns = now
            remaining_capacity = arguments.max_response_bytes - len(response)
            response.extend(chunk[:remaining_capacity])
            if len(chunk) > remaining_capacity:
                capture_end_reason = "byte_limit"
                break

    arguments.wire_output.write_bytes(response)
    records = parse_records(response)
    if capture_end_reason in {"absolute_timeout", "byte_limit"}:
        write_json(
            arguments.summary_output,
            {
                "sampleStatus": "INVALID",
                "validationErrors": [
                    "absolute first-flight deadline elapsed"
                    if capture_end_reason == "absolute_timeout"
                    else "first-flight byte cap reached"
                ],
                "clientHelloSha256": hashlib.sha256(client_hello).hexdigest(),
                "responseSha256": hashlib.sha256(response).hexdigest(),
                "firstFlightBytes": len(response),
                "captureEndReason": capture_end_reason,
                "records": records,
            },
        )
        raise RuntimeError(
            "TLS first-flight capture exceeded its absolute bound; "
            "partial evidence is marked INVALID"
        )
    if any("trailingBytes" in record for record in records):
        raise ValueError("response ended within a TLS record")
    server_hello = parse_server_hello(response, records)
    encrypted_lengths = [
        record["recordLength"] for record in records if record.get("contentType") == 23
    ]
    server_hello_length = next(
        (
            record["recordLength"]
            for record in records
            if record.get("contentType") == 22
        ),
        None,
    )
    summary = {
        "clientHelloSha256": hashlib.sha256(client_hello).hexdigest(),
        "clientHelloRecordBytes": len(client_hello),
        "responseSha256": hashlib.sha256(response).hexdigest(),
        "serverHelloRecordLength": server_hello_length,
        "ccsPresent": any(record.get("contentType") == 20 for record in records),
        "encryptedHandshakeRecordLengths": encrypted_lengths,
        "applicationRecordLengths": [],
        "firstFlightBytes": len(response),
        "captureScope": "server first flight before ClientFinished",
        "captureEndReason": capture_end_reason,
        "closeNotifyObserved": None,
        "peerAddress": peer_address,
        **server_hello,
        "records": records,
        "timingUs": {
            "connectToSendStart": (before_send_ns - connected_ns) // 1000,
            "sendDuration": (after_send_ns - before_send_ns) // 1000,
            "clientHelloToServerHello": None
            if first_byte_ns is None
            else (first_byte_ns - after_send_ns) // 1000,
            "firstFlightCompletion": None
            if last_byte_ns is None
            else (last_byte_ns - after_send_ns) // 1000,
        },
        "timingMethod": {
            "clock": "client-side monotonic clock",
            "completionObservation": "last recv() before capture end",
            "idleTimeoutUs": int(arguments.read_timeout * 1_000_000),
            "absoluteTimeoutUs": int(arguments.capture_timeout * 1_000_000),
            "maxFirstFlightBytes": arguments.max_response_bytes,
        },
    }
    write_json(arguments.summary_output, summary)


def first_flight_strace(
    prefix: Path, server_port: int, expected_bytes: int
) -> dict[str, object] | None:
    paths = sorted(prefix.parent.glob(prefix.name + ".*"))
    if not paths:
        return None
    events: list[tuple[float, str, int]] = []
    for path in paths:
        for line in path.read_text(errors="replace").splitlines():
            if "TCP:" not in line or f":{server_port}" not in line:
                continue
            call = next(
                (
                    name
                    for name in ("writev", "write", "sendto", "sendmsg")
                    if f"{name}(" in line
                ),
                None,
            )
            if call is None:
                continue
            timestamp = re.match(r"^(\d+(?:\.\d+)?)", line)
            result = re.search(r"=\s*(-?\d+)(?:\s|$)", line)
            if (
                timestamp is not None
                and result is not None
                and int(result.group(1)) > 0
            ):
                events.append((float(timestamp.group(1)), call, int(result.group(1))))
    events.sort()
    selected: list[tuple[float, str, int]] = []
    total = 0
    for start in range(len(events)):
        candidate: list[tuple[float, str, int]] = []
        candidate_total = 0
        for event in events[start:]:
            candidate.append(event)
            candidate_total += event[2]
            if candidate_total >= expected_bytes:
                break
        if candidate_total == expected_bytes:
            selected = candidate
            total = candidate_total
            break
    if not selected:
        for event in events:
            selected.append(event)
            total += event[2]
            if total >= expected_bytes:
                break
    return {
        "syscalls": [event[1] for event in selected],
        "sizes": [event[2] for event in selected],
        "totalBytes": total,
        "complete": total == expected_bytes,
    }


def first_flight_packets(
    path: Path, server_port: int, expected_bytes: int
) -> dict[str, object] | None:
    if not path.exists():
        return None
    all_packets: list[dict[str, object]] = []
    source = re.compile(rf"(?:^|\s)(?:[0-9a-fA-F:.]+\.)?{server_port}\s+>")
    for line in path.read_text(errors="replace").splitlines():
        if source.search(line) is None:
            continue
        length = re.search(r"length (\d+)$", line)
        flags = re.search(r"Flags \[([^]]+)\]", line)
        if length is None or int(length.group(1)) == 0:
            continue
        size = int(length.group(1))
        all_packets.append(
            {"payloadBytes": size, "flags": flags.group(1) if flags else None}
        )
    packets: list[dict[str, object]] = []
    total = 0
    for start in range(len(all_packets)):
        candidate: list[dict[str, object]] = []
        candidate_total = 0
        for packet in all_packets[start:]:
            candidate.append(packet)
            candidate_total += int(packet["payloadBytes"])
            if candidate_total >= expected_bytes:
                break
        if candidate_total == expected_bytes:
            packets = candidate
            total = candidate_total
            break
    if not packets:
        for packet in all_packets:
            packets.append(packet)
            total += int(packet["payloadBytes"])
            if total >= expected_bytes:
                break
    return {
        "packets": packets,
        "totalBytes": total,
        "complete": total == expected_bytes,
    }


def sequence_delta(
    reference: list[int], candidate: list[int]
) -> list[dict[str, int | None]]:
    result = []
    for position in range(max(len(reference), len(candidate))):
        left = reference[position] if position < len(reference) else None
        right = candidate[position] if position < len(candidate) else None
        result.append(
            {
                "position": position,
                "reference": left,
                "candidate": right,
                "delta": None if left is None or right is None else right - left,
            }
        )
    return result


def record_signature(result: dict[str, object]) -> list[tuple[int, int, int]]:
    return [
        (
            int(record["contentType"]),
            int(record["legacyVersion"]),
            int(record["recordLength"]),
        )
        for record in result["records"]
    ]


def complete_measurement(value: object) -> bool:
    return isinstance(value, dict) and value.get("complete") is True


def tls_sample_validation_errors(result: dict[str, object]) -> list[str]:
    errors = []
    records = result.get("records")
    if not isinstance(records, list) or not records:
        errors.append("server flight contains no complete TLS records")
        return errors
    if records[0].get("contentType") != 22:
        errors.append("server flight does not begin with a handshake record")
    if result.get("serverHelloRecordLength") is None:
        errors.append("ServerHello record is absent")
    first_flight_bytes = result.get("firstFlightBytes")
    if not isinstance(first_flight_bytes, int) or first_flight_bytes <= 0:
        errors.append("first-flight byte count is not positive")
    elif sum(record.get("wireLength", 0) for record in records) != first_flight_bytes:
        errors.append("complete TLS record lengths do not cover the first flight")
    return errors


def compare_shape(
    reference: dict[str, object], candidate: dict[str, object]
) -> dict[str, object]:
    reference_signature = record_signature(reference)
    candidate_signature = record_signature(candidate)
    reference_types = [record[0] for record in reference_signature]
    candidate_types = [record[0] for record in candidate_signature]
    reference_versions = [record[1] for record in reference_signature]
    candidate_versions = [record[1] for record in candidate_signature]
    reference_record_lengths = [record[2] for record in reference_signature]
    candidate_record_lengths = [record[2] for record in candidate_signature]
    reference_lengths = reference["encryptedHandshakeRecordLengths"]
    candidate_lengths = candidate["encryptedHandshakeRecordLengths"]
    reference_write = reference.get("processWriteShape")
    candidate_write = candidate.get("processWriteShape")
    reference_packets = reference.get("packetShape")
    candidate_packets = candidate.get("packetShape")
    record_comparable = (
        reference.get("sampleStatus", "VALID") == "VALID"
        and candidate.get("sampleStatus", "VALID") == "VALID"
    )
    record_equal = (
        record_comparable
        and reference_signature == candidate_signature
        and reference["firstFlightBytes"] == candidate["firstFlightBytes"]
    )
    write_comparable = complete_measurement(reference_write) and complete_measurement(
        candidate_write
    )
    write_size_equal = (
        write_comparable and reference_write["sizes"] == candidate_write["sizes"]
    )
    write_syscall_equal = (
        write_comparable and reference_write["syscalls"] == candidate_write["syscalls"]
    )
    write_equal = write_size_equal and write_syscall_equal
    packet_comparable = complete_measurement(
        reference_packets
    ) and complete_measurement(candidate_packets)
    observed_packet_equal = (
        packet_comparable
        and reference_packets["packets"] == candidate_packets["packets"]
    )
    timing_delta = {}
    for field in ("clientHelloToServerHello", "firstFlightCompletion"):
        reference_timing = reference["timingUs"][field]
        candidate_timing = candidate["timingUs"][field]
        timing_delta[field] = (
            None
            if reference_timing is None or candidate_timing is None
            else candidate_timing - reference_timing
        )
    timing_classifications = {
        reference.get("timingMeasurement", {}).get("classification"),
        candidate.get("timingMeasurement", {}).get("classification"),
    }
    timing_classification = (
        "NOT_COMPARABLE"
        if "NOT_COMPARABLE" in timing_classifications
        else "EXPLORATORY"
    )
    reference_server_hello_length = reference["serverHelloRecordLength"]
    candidate_server_hello_length = candidate["serverHelloRecordLength"]
    return {
        "recordSequenceEqual": reference_signature == candidate_signature,
        "outerContentTypeSequenceEqual": reference_types == candidate_types,
        "legacyRecordVersionSequenceEqual": reference_versions == candidate_versions,
        "recordLengthSequenceEqual": reference_record_lengths
        == candidate_record_lengths,
        "recordCountDifference": len(candidate_types) - len(reference_types),
        "encryptedHandshakeRecordCountDifference": len(candidate_lengths)
        - len(reference_lengths),
        "encryptedHandshakeRecordLengthDelta": sequence_delta(
            reference_lengths, candidate_lengths
        ),
        "firstFlightByteDelta": candidate["firstFlightBytes"]
        - reference["firstFlightBytes"],
        "serverHelloRecordLengthDelta": None
        if reference_server_hello_length is None
        or candidate_server_hello_length is None
        else candidate_server_hello_length - reference_server_hello_length,
        "ccsEqual": candidate["ccsPresent"] == reference["ccsPresent"],
        "processWriteCallCountDelta": None
        if not write_comparable
        else len(candidate_write["sizes"]) - len(reference_write["sizes"]),
        "processWriteSizeSequenceEqual": None
        if not write_comparable
        else write_size_equal,
        "processWriteSyscallSequenceEqual": None
        if not write_comparable
        else write_syscall_equal,
        "processWriteSizeDelta": None
        if not write_comparable
        else sequence_delta(reference_write["sizes"], candidate_write["sizes"]),
        "packetCountDifference": None
        if not packet_comparable
        else len(candidate_packets["packets"]) - len(reference_packets["packets"]),
        "packetPayloadSizeDelta": None
        if not packet_comparable
        else sequence_delta(
            [packet["payloadBytes"] for packet in reference_packets["packets"]],
            [packet["payloadBytes"] for packet in candidate_packets["packets"]],
        ),
        "observedPacketShapeEqual": None
        if not packet_comparable
        else observed_packet_equal,
        "timingUsDelta": timing_delta,
        "timingClassification": timing_classification,
        "recordShapeClassification": "NOT_COMPARABLE"
        if not record_comparable
        else ("MATCH" if record_equal else "MATERIAL_DIFFERENCE"),
        "writeShapeClassification": "NOT_COMPARABLE"
        if not write_comparable
        else ("MATCH" if write_equal else "MATERIAL_DIFFERENCE"),
        "packetShapeClassification": "NOT_COMPARABLE"
        if not packet_comparable
        else "NETWORK_DEPENDENT",
    }


def summarize(arguments: argparse.Namespace) -> None:
    identity = json.loads(arguments.identity.read_text())
    identity_has_baseline = identity.get("baselineRustReality") is not None
    if identity_has_baseline != arguments.baseline_rust_present:
        raise ValueError("baseline flag does not match the pinned run identity")
    implementation_specs = [
        ("opensslReference", "reference", arguments.reference_port),
    ]
    if arguments.baseline_rust_present:
        implementation_specs.append(
            ("baselineRustReality", "baseline-rust", arguments.rust_port)
        )
    implementation_specs.extend(
        (
            ("rustReality", "rust", arguments.rust_port),
            ("xray", "xray", arguments.xray_port),
        )
    )
    comparison_specs = [
        ("rustRealityVsOpenSslReference", "opensslReference", "rustReality"),
        ("xrayVsOpenSslReference", "opensslReference", "xray"),
    ]
    if arguments.baseline_rust_present:
        comparison_specs.extend(
            (
                (
                    "baselineRustRealityVsOpenSslReference",
                    "opensslReference",
                    "baselineRustReality",
                ),
                (
                    "candidateVsBaselineRustReality",
                    "baselineRustReality",
                    "rustReality",
                ),
            )
        )
    samples = []
    expected_client_hello_hash = None
    for sample_index in range(1, arguments.sample_count + 1):
        directory = arguments.samples_root / f"{sample_index:03d}"
        implementations: dict[str, dict[str, object]] = {}
        for name, stem, port in implementation_specs:
            result = json.loads((directory / f"{stem}.json").read_text())
            validation_errors = tls_sample_validation_errors(result)
            result["sampleStatus"] = "INVALID" if validation_errors else "VALID"
            result["validationErrors"] = validation_errors
            client_hello_hash = result["clientHelloSha256"]
            if expected_client_hello_hash is None:
                expected_client_hello_hash = client_hello_hash
            if client_hello_hash != expected_client_hello_hash:
                raise ValueError(
                    "implementations did not receive one identical ClientHello"
                )
            if arguments.strace_status == "available":
                result["processWriteShape"] = first_flight_strace(
                    directory / f"{stem}.strace", port, result["firstFlightBytes"]
                )
                result["timingMeasurement"] = {
                    "classification": "NOT_COMPARABLE",
                    "instrumentedByStrace": True,
                    "reason": "strace perturbs process scheduling and syscall latency",
                }
            else:
                result["processWriteShape"] = None
                result["timingMeasurement"] = {
                    "classification": "EXPLORATORY",
                    "instrumentedByStrace": False,
                    "reason": "client-side sequential samples; not a controlled latency benchmark",
                }
            if arguments.tcpdump_status == "available":
                result["packetShape"] = first_flight_packets(
                    directory / f"{stem}.packets.txt",
                    port,
                    result["firstFlightBytes"],
                )
            else:
                result["packetShape"] = None
            implementations[name] = result
        sample_status = (
            "INVALID"
            if any(
                result["sampleStatus"] == "INVALID"
                for result in implementations.values()
            )
            else "VALID"
        )
        samples.append(
            {
                "sample": sample_index,
                "status": sample_status,
                **implementations,
                "comparisons": {
                    label: compare_shape(
                        implementations[reference_name],
                        implementations[candidate_name],
                    )
                    for label, reference_name, candidate_name in comparison_specs
                },
            }
        )

    timing_medians: dict[str, dict[str, float | None]] = {}
    for name, _stem, _port in implementation_specs:
        timing_medians[name] = {}
        for field in ("clientHelloToServerHello", "firstFlightCompletion"):
            values = [sample[name]["timingUs"][field] for sample in samples]
            present = [value for value in values if value is not None]
            timing_medians[name][field] = (
                statistics.median(present) if present else None
            )

    timing_median_differences: dict[str, dict[str, float | None]] = {}
    for label, reference_name, candidate_name in comparison_specs:
        timing_median_differences[label] = {}
        for field in ("clientHelloToServerHello", "firstFlightCompletion"):
            reference_value = timing_medians[reference_name][field]
            candidate_value = timing_medians[candidate_name][field]
            timing_median_differences[label][field] = (
                None
                if reference_value is None or candidate_value is None
                else candidate_value - reference_value
            )

    summary = {
        "schemaVersion": 1,
        "identity": identity,
        "clientHelloSha256": expected_client_hello_hash,
        "sampleCount": arguments.sample_count,
        "baselineRustRealityPresent": arguments.baseline_rust_present,
        "invalidSampleCount": sum(sample["status"] == "INVALID" for sample in samples),
        "samples": samples,
        "timingComparisonClassification": "NOT_COMPARABLE"
        if arguments.strace_status == "available"
        else "EXPLORATORY",
        "timingMedianUs": timing_medians,
        "timingMedianDifferenceUs": timing_median_differences,
    }
    write_json(arguments.output, summary)
    if summary["invalidSampleCount"] != 0:
        raise ValueError("one or more TLS-shape samples were invalid; see summary")


def self_test() -> None:
    session_id = bytes(range(32))
    key_share = b"\x00\x1d\x00\x01\x00"
    extension = b"\x00\x33" + len(key_share).to_bytes(2, "big") + key_share
    body = (
        b"\x03\x03"
        + bytes(32)
        + bytes([len(session_id)])
        + session_id
        + b"\x13\x01\x00"
        + len(extension).to_bytes(2, "big")
        + extension
    )
    message = b"\x02" + len(body).to_bytes(3, "big") + body
    wire = b"\x16\x03\x03" + len(message).to_bytes(2, "big") + message
    wire += b"\x14\x03\x03\x00\x01\x01"
    wire += b"\x17\x03\x03\x00\x20" + bytes(32)
    records = parse_records(wire)
    parsed = parse_server_hello(wire, records)
    assert [record["contentType"] for record in records] == [22, 20, 23]
    assert parsed["negotiatedCipherSuite"] == "TLS_AES_128_GCM_SHA256"
    assert parsed["negotiatedKeyShareGroup"] == "X25519"
    base_result = {
        "records": records,
        "encryptedHandshakeRecordLengths": [32],
        "firstFlightBytes": len(wire),
        "serverHelloRecordLength": len(message),
        "ccsPresent": True,
        "timingUs": {
            "clientHelloToServerHello": 10,
            "firstFlightCompletion": 11,
        },
        "timingMeasurement": {"classification": "NOT_COMPARABLE"},
        "processWriteShape": {
            "syscalls": ["write"],
            "sizes": [len(wire)],
            "totalBytes": len(wire),
            "complete": True,
        },
        "packetShape": {
            "packets": [{"payloadBytes": len(wire), "flags": "P."}],
            "totalBytes": len(wire),
            "complete": True,
        },
    }
    assert tls_sample_validation_errors(base_result) == []
    assert tls_sample_validation_errors({**base_result, "records": []}) != []
    changed_syscall = {
        **base_result,
        "processWriteShape": {
            **base_result["processWriteShape"],
            "syscalls": ["sendto"],
        },
    }
    syscall_comparison = compare_shape(base_result, changed_syscall)
    assert syscall_comparison["processWriteSizeSequenceEqual"] is True
    assert syscall_comparison["processWriteSyscallSequenceEqual"] is False
    assert syscall_comparison["writeShapeClassification"] == "MATERIAL_DIFFERENCE"

    changed_records = [dict(record) for record in records]
    changed_records[0]["recordLength"] += 1
    changed_server_hello = {
        **base_result,
        "records": changed_records,
        "serverHelloRecordLength": len(message) + 1,
        "firstFlightBytes": len(wire) + 1,
    }
    record_comparison = compare_shape(base_result, changed_server_hello)
    assert record_comparison["recordSequenceEqual"] is False
    assert record_comparison["firstFlightByteDelta"] == 1
    assert record_comparison["recordShapeClassification"] == "MATERIAL_DIFFERENCE"

    incomplete = {
        **base_result,
        "processWriteShape": {
            "syscalls": [],
            "sizes": [],
            "totalBytes": 0,
            "complete": False,
        },
        "packetShape": {"packets": [], "totalBytes": 0, "complete": False},
    }
    incomplete_comparison = compare_shape(incomplete, incomplete)
    assert incomplete_comparison["writeShapeClassification"] == "NOT_COMPARABLE"
    assert incomplete_comparison["packetShapeClassification"] == "NOT_COMPARABLE"
    assert compare_shape(base_result, base_result)["packetShapeClassification"] == (
        "NETWORK_DEPENDENT"
    )
    assert syscall_comparison["timingClassification"] == "NOT_COMPARABLE"
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "summary.json"
        write_json(path, parsed)
        assert json.loads(path.read_text()) == parsed
    print("tls-shape helper self-test: PASS")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    proxy_parser = subparsers.add_parser("proxy")
    proxy_parser.add_argument("--listen-host", default="127.0.0.1")
    proxy_parser.add_argument("--listen-port", type=int, required=True)
    proxy_parser.add_argument("--upstream-host", default="127.0.0.1")
    proxy_parser.add_argument("--upstream-port", type=int, required=True)
    proxy_parser.add_argument("--output", type=Path, required=True)
    proxy_parser.add_argument(
        "--absolute-timeout", type=float, default=DEFAULT_CAPTURE_TIMEOUT
    )
    proxy_parser.add_argument(
        "--max-client-hello-bytes",
        type=int,
        default=MAX_CLIENT_HELLO_RECORD_BYTES,
    )
    proxy_parser.set_defaults(function=capture_proxy)

    replay_parser = subparsers.add_parser("replay")
    replay_parser.add_argument("--host", default="127.0.0.1")
    replay_parser.add_argument("--port", type=int, required=True)
    replay_parser.add_argument("--client-hello", type=Path, required=True)
    replay_parser.add_argument("--wire-output", type=Path, required=True)
    replay_parser.add_argument("--summary-output", type=Path, required=True)
    replay_parser.add_argument("--connect-timeout", type=float, default=3.0)
    replay_parser.add_argument("--read-timeout", type=float, default=0.25)
    replay_parser.add_argument(
        "--capture-timeout", type=float, default=DEFAULT_CAPTURE_TIMEOUT
    )
    replay_parser.add_argument(
        "--max-response-bytes", type=int, default=DEFAULT_MAX_FIRST_FLIGHT_BYTES
    )
    replay_parser.set_defaults(function=replay)

    summary_parser = subparsers.add_parser("summarize")
    summary_parser.add_argument("--identity", type=Path, required=True)
    summary_parser.add_argument("--samples-root", type=Path, required=True)
    summary_parser.add_argument("--sample-count", type=int, required=True)
    summary_parser.add_argument("--reference-port", type=int, required=True)
    summary_parser.add_argument("--rust-port", type=int, required=True)
    summary_parser.add_argument("--xray-port", type=int, required=True)
    summary_parser.add_argument("--baseline-rust-present", action="store_true")
    summary_parser.add_argument(
        "--strace-status",
        choices=("available", "unavailable", "disabled"),
        required=True,
    )
    summary_parser.add_argument(
        "--tcpdump-status",
        choices=("available", "unavailable", "disabled"),
        required=True,
    )
    summary_parser.add_argument("--output", type=Path, required=True)
    summary_parser.set_defaults(function=summarize)

    test_parser = subparsers.add_parser("self-test")
    test_parser.set_defaults(function=lambda _arguments: self_test())
    return parser


def main() -> None:
    arguments = build_parser().parse_args()
    arguments.function(arguments)


if __name__ == "__main__":
    main()
