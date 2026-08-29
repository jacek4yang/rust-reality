//! Native TLS first-flight capture, parsing, comparison, and shaping.
//!
//! The legacy TLS-shape family mixed four concerns in Bash, Python, and C:
//! capturing one stock-Xray `ClientHello`, replaying it against independent
//! servers, interpreting the returned TLS records, and inserting a deterministic
//! fifth record for the handoff soak.  This module keeps those concerns typed and
//! bounded.  The dynamic independent reference remains OpenSSL itself (invoked by
//! the suite with explicit argv and identity); no repository-owned C shim is
//! needed merely to call `SSL_accept`.

use std::{
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    time::{Duration, Instant},
};

use crate::{hash, perf::json_out::Json};

/// Maximum legal TLS 1.3 ciphertext payload.
pub const MAX_TLS_CIPHERTEXT_BYTES: usize = 16_640;
/// Maximum captured stock-Xray `ClientHello`: one legal plaintext TLS record.
pub const MAX_CLIENT_HELLO_BYTES: usize = 5 + 16 * 1024;
/// Maximum server first flight retained as evidence.
pub const MAX_FIRST_FLIGHT_BYTES: usize = 1024 * 1024;
/// Deterministic opaque record appended by the handoff flight shaper.
pub const SHAPED_FIFTH_RECORD_BYTES: usize = 139;

/// One complete outer TLS record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsRecord {
    /// Offset in the captured wire flight.
    pub offset: usize,
    /// Outer content type.
    pub content_type: u8,
    /// Outer legacy record version.
    pub legacy_version: u16,
    /// TLS record payload bytes, excluding the five-byte header.
    pub payload_bytes: usize,
}

impl TlsRecord {
    /// Complete record bytes including the outer header.
    #[must_use]
    pub const fn wire_bytes(&self) -> usize {
        self.payload_bytes + 5
    }

    fn to_json(&self) -> Json {
        Json::object([
            ("contentType", Json::Int(i64::from(self.content_type))),
            ("legacyVersion", Json::Int(i64::from(self.legacy_version))),
            ("offset", Json::Int(to_i64(self.offset))),
            ("recordLength", Json::Int(to_i64(self.payload_bytes))),
            ("wireLength", Json::Int(to_i64(self.wire_bytes()))),
        ])
    }
}

/// Negotiated values visible in a TLS 1.3 `ServerHello`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    /// Selected TLS cipher-suite id.
    pub cipher_suite: u16,
    /// Selected key-share group, when present.
    pub key_share_group: Option<u16>,
}

/// One bounded replay observation.
#[derive(Debug, Clone)]
pub struct Flight {
    /// Raw server flight bytes.
    pub wire: Vec<u8>,
    /// Parsed complete outer records.
    pub records: Vec<TlsRecord>,
    /// Parsed first `ServerHello`.
    pub server_hello: ServerHello,
    /// Why collection stopped.
    pub capture_end: &'static str,
    /// Time from completed `ClientHello` write to the first response byte.
    pub first_byte_us: Option<u64>,
    /// Time from completed `ClientHello` write to the last response byte.
    pub completion_us: Option<u64>,
}

impl Flight {
    /// Renders the durable per-implementation observation.
    #[must_use]
    pub fn to_json(&self, client_hello: &[u8]) -> Json {
        let encrypted = self
            .records
            .iter()
            .filter(|record| record.content_type == 23)
            .map(|record| Json::Int(to_i64(record.payload_bytes)))
            .collect();
        Json::object([
            ("applicationRecordLengths", Json::Array(Vec::new())),
            (
                "captureScope",
                Json::string("server first flight before ClientFinished"),
            ),
            ("captureEndReason", Json::string(self.capture_end)),
            (
                "ccsPresent",
                Json::Bool(self.records.iter().any(|record| record.content_type == 20)),
            ),
            (
                "clientHelloRecordBytes",
                Json::Int(to_i64(client_hello.len())),
            ),
            (
                "clientHelloSha256",
                Json::string(hash::sha256_hex(client_hello)),
            ),
            ("encryptedHandshakeRecordLengths", Json::Array(encrypted)),
            ("firstFlightBytes", Json::Int(to_i64(self.wire.len()))),
            (
                "negotiatedCipherSuite",
                Json::string(cipher_suite_name(self.server_hello.cipher_suite)),
            ),
            (
                "negotiatedCipherSuiteId",
                Json::Int(i64::from(self.server_hello.cipher_suite)),
            ),
            (
                "negotiatedKeyShareGroup",
                self.server_hello
                    .key_share_group
                    .map_or(Json::Null, |group| Json::string(group_name(group))),
            ),
            (
                "negotiatedKeyShareGroupId",
                self.server_hello
                    .key_share_group
                    .map_or(Json::Null, |group| Json::Int(i64::from(group))),
            ),
            (
                "records",
                Json::Array(self.records.iter().map(TlsRecord::to_json).collect()),
            ),
            ("responseSha256", Json::string(hash::sha256_hex(&self.wire))),
            (
                "serverHelloRecordLength",
                Json::Int(to_i64(self.records[0].payload_bytes)),
            ),
            (
                "timingUs",
                Json::object([
                    (
                        "clientHelloToServerHello",
                        self.first_byte_us.map_or(Json::Null, |value| {
                            Json::Int(i64::try_from(value).unwrap_or(i64::MAX))
                        }),
                    ),
                    (
                        "firstFlightCompletion",
                        self.completion_us.map_or(Json::Null, |value| {
                            Json::Int(i64::try_from(value).unwrap_or(i64::MAX))
                        }),
                    ),
                ]),
            ),
        ])
    }
}

/// Record-level comparison against an independent reference flight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShapeComparison {
    /// Exact `(content type, legacy version, payload length)` sequence equality.
    pub record_sequence_equal: bool,
    /// Difference in complete first-flight byte count.
    pub first_flight_byte_delta: i64,
    /// Difference in record count.
    pub record_count_delta: i64,
    /// Whether the server CCS presence agrees.
    pub ccs_equal: bool,
}

impl ShapeComparison {
    /// Renders the comparison. A material difference is an observation, not an
    /// invalid sample: the suite exists to expose differences rather than hide
    /// them behind a pass/fail threshold.
    #[must_use]
    pub fn to_json(&self) -> Json {
        Json::object([
            ("ccsEqual", Json::Bool(self.ccs_equal)),
            (
                "firstFlightByteDelta",
                Json::Int(self.first_flight_byte_delta),
            ),
            ("recordCountDifference", Json::Int(self.record_count_delta)),
            (
                "recordSequenceEqual",
                Json::Bool(self.record_sequence_equal),
            ),
            (
                "recordShapeClassification",
                Json::string(if self.record_sequence_equal {
                    "MATCH"
                } else {
                    "MATERIAL_DIFFERENCE"
                }),
            ),
        ])
    }
}

/// Parses a complete TLS record sequence, rejecting a truncated tail.
///
/// # Errors
///
/// Returns a bounded diagnostic for an empty flight, an invalid record length,
/// or bytes that do not form complete records.
pub fn parse_records(wire: &[u8]) -> Result<Vec<TlsRecord>, String> {
    let mut records = Vec::new();
    let mut offset = 0;
    while offset < wire.len() {
        let header = wire
            .get(offset..offset + 5)
            .ok_or_else(|| format!("TLS flight ends in a partial header at byte {offset}"))?;
        let payload_bytes = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if payload_bytes == 0 || payload_bytes > MAX_TLS_CIPHERTEXT_BYTES {
            return Err(format!(
                "TLS record at byte {offset} declares invalid payload length {payload_bytes}"
            ));
        }
        let end = offset + 5 + payload_bytes;
        if end > wire.len() {
            return Err(format!(
                "TLS record at byte {offset} is truncated: needs {end}, flight has {}",
                wire.len()
            ));
        }
        records.push(TlsRecord {
            offset,
            content_type: header[0],
            legacy_version: u16::from_be_bytes([header[1], header[2]]),
            payload_bytes,
        });
        offset = end;
    }
    if records.is_empty() {
        return Err("server flight contains no complete TLS records".to_owned());
    }
    Ok(records)
}

/// Parses the first TLS 1.3 `ServerHello` and its selected key share.
///
/// # Errors
///
/// Returns a diagnostic when the flight does not begin with one complete
/// `ServerHello` or its extension vector is malformed.
pub fn parse_server_hello(wire: &[u8], records: &[TlsRecord]) -> Result<ServerHello, String> {
    let Some(record) = records.first() else {
        return Err("server flight contains no records".to_owned());
    };
    if record.content_type != 22 {
        return Err("server flight does not begin with a handshake record".to_owned());
    }
    let payload = &wire[record.offset + 5..record.offset + record.wire_bytes()];
    if payload.len() < 44 || payload[0] != 2 {
        return Err("first handshake record is not a complete ServerHello".to_owned());
    }
    let declared = 4 + usize::try_from(u32::from_be_bytes([0, payload[1], payload[2], payload[3]]))
        .unwrap_or(usize::MAX);
    if declared > payload.len() {
        return Err("ServerHello handshake body is truncated".to_owned());
    }
    let session_id_bytes = usize::from(payload[38]);
    let cipher_offset = 39 + session_id_bytes;
    let fixed_end = cipher_offset + 5;
    if fixed_end > declared {
        return Err("ServerHello is truncated before its extensions".to_owned());
    }
    let cipher_suite = u16::from_be_bytes([payload[cipher_offset], payload[cipher_offset + 1]]);
    let extensions_bytes = usize::from(u16::from_be_bytes([
        payload[cipher_offset + 3],
        payload[cipher_offset + 4],
    ]));
    let extensions_end = fixed_end + extensions_bytes;
    if extensions_end > declared {
        return Err("ServerHello extensions are truncated".to_owned());
    }
    let mut cursor = fixed_end;
    let mut key_share_group = None;
    while cursor < extensions_end {
        let header = payload
            .get(cursor..cursor + 4)
            .ok_or_else(|| "ServerHello extension header is truncated".to_owned())?;
        let extension_type = u16::from_be_bytes([header[0], header[1]]);
        let data_bytes = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let data = cursor + 4;
        let end = data + data_bytes;
        if end > extensions_end {
            return Err("ServerHello extension data is truncated".to_owned());
        }
        if extension_type == 0x0033 {
            let group = payload
                .get(data..data + 2)
                .ok_or_else(|| "ServerHello key_share is truncated".to_owned())?;
            key_share_group = Some(u16::from_be_bytes([group[0], group[1]]));
            break;
        }
        cursor = end;
    }
    Ok(ServerHello {
        cipher_suite,
        key_share_group,
    })
}

/// Replays one exact `ClientHello` and collects the complete first server flight.
///
/// Collection stops at peer EOF or after a 250-ms idle gap, subject to a five
/// second absolute deadline and a one-MiB byte cap.
///
/// # Errors
///
/// Returns a diagnostic for connection, bound, truncation, or parsing failures.
pub fn replay(port: u16, client_hello: &[u8]) -> Result<Flight, String> {
    validate_client_hello(client_hello)?;
    let address = ([127, 0, 0, 1], port).into();
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(3))
        .map_err(|error| format!("could not connect replay socket 127.0.0.1:{port}: {error}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| format!("could not bound replay writes: {error}"))?;
    let started = Instant::now();
    stream
        .write_all(client_hello)
        .map_err(|error| format!("could not replay ClientHello: {error}"))?;
    let sent = Instant::now();
    let absolute = started + Duration::from_secs(5);
    let mut wire = Vec::new();
    let mut first = None;
    let mut last = None;
    let capture_end;
    loop {
        let now = Instant::now();
        if now >= absolute {
            return Err(format!(
                "absolute first-flight deadline elapsed after {} bytes",
                wire.len()
            ));
        }
        stream
            .set_read_timeout(Some(Duration::from_millis(250).min(absolute - now)))
            .map_err(|error| format!("could not bound replay reads: {error}"))?;
        let mut buffer = vec![0_u8; 65_536];
        match stream.read(&mut buffer) {
            Ok(0) => {
                capture_end = "peer_eof";
                break;
            }
            Ok(bytes) => {
                let observed = Instant::now();
                first.get_or_insert(observed);
                last = Some(observed);
                if wire.len() + bytes > MAX_FIRST_FLIGHT_BYTES {
                    return Err(
                        "first-flight byte cap reached; partial evidence is invalid".to_owned()
                    );
                }
                wire.extend_from_slice(&buffer[..bytes]);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                capture_end = "idle_timeout";
                break;
            }
            Err(error) => return Err(format!("could not read replay response: {error}")),
        }
    }
    let records = parse_records(&wire)?;
    let server_hello = parse_server_hello(&wire, &records)?;
    Ok(Flight {
        wire,
        records,
        server_hello,
        capture_end,
        first_byte_us: first.map(|instant| micros(instant.duration_since(sent))),
        completion_us: last.map(|instant| micros(instant.duration_since(sent))),
    })
}

/// Compares the complete record sequence and basic first-flight shape.
#[must_use]
pub fn compare(reference: &Flight, candidate: &Flight) -> ShapeComparison {
    let signature = |flight: &Flight| {
        flight
            .records
            .iter()
            .map(|record| {
                (
                    record.content_type,
                    record.legacy_version,
                    record.payload_bytes,
                )
            })
            .collect::<Vec<_>>()
    };
    ShapeComparison {
        record_sequence_equal: signature(reference) == signature(candidate),
        first_flight_byte_delta: signed_delta(candidate.wire.len(), reference.wire.len()),
        record_count_delta: signed_delta(candidate.records.len(), reference.records.len()),
        ccs_equal: candidate
            .records
            .iter()
            .any(|record| record.content_type == 20)
            == reference
                .records
                .iter()
                .any(|record| record.content_type == 20),
    }
}

/// Captures one exact `ClientHello` while forwarding a single connection.
///
/// This is run in a native thread by the suite. The returned bytes are the first
/// and only complete client TLS record; forwarding continues until either side
/// closes so the compatibility transfer proves the captured hello was usable.
///
/// # Errors
///
/// Returns a diagnostic on timeout, truncation, or forwarding failure.
pub fn capture_one(listen_port: u16, upstream_port: u16) -> Result<Vec<u8>, String> {
    let listener = TcpListener::bind(("127.0.0.1", listen_port))
        .map_err(|error| format!("capture proxy could not bind: {error}"))?;
    listener
        .set_nonblocking(false)
        .map_err(|error| format!("capture proxy could not become blocking: {error}"))?;
    let (mut client, _) = listener
        .accept()
        .map_err(|error| format!("capture proxy could not accept: {error}"))?;
    let mut upstream = TcpStream::connect(("127.0.0.1", upstream_port))
        .map_err(|error| format!("capture proxy could not connect upstream: {error}"))?;
    for stream in [&client, &upstream] {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|error| format!("capture proxy could not bound reads: {error}"))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|error| format!("capture proxy could not bound writes: {error}"))?;
    }
    let hello = read_record(&mut client, MAX_CLIENT_HELLO_BYTES)?;
    validate_client_hello(&hello)?;
    upstream
        .write_all(&hello)
        .map_err(|error| format!("capture proxy could not forward ClientHello: {error}"))?;

    // The compatibility probe only needs the handshake and one small HTTP
    // response. Two directional threads avoid assuming which side closes first.
    let mut client_read = client
        .try_clone()
        .map_err(|error| format!("capture proxy could not clone client: {error}"))?;
    let mut upstream_write = upstream
        .try_clone()
        .map_err(|error| format!("capture proxy could not clone upstream: {error}"))?;
    let uplink = std::thread::spawn(move || std::io::copy(&mut client_read, &mut upstream_write));
    std::io::copy(&mut upstream, &mut client)
        .map_err(|error| format!("capture proxy downlink failed: {error}"))?;
    match uplink.join() {
        Ok(Ok(_)) => Ok(hello),
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(hello),
        Ok(Err(error)) => Err(format!("capture proxy uplink failed: {error}")),
        Err(_) => Err("capture proxy uplink thread panicked".to_owned()),
    }
}

/// Runs the bounded handoff cover-flight shaper as a separate helper process.
///
/// It forwards one complete `ClientHello` to an OpenSSL cover, retains records
/// through the fourth encrypted record, then appends one deterministic opaque
/// record in the same `write_all` call. Invalid readiness connections are
/// ignored up to `max_accepted`, exactly as the legacy helper required.
///
/// # Errors
///
/// Returns a diagnostic if the listener cannot bind or the requested number of
/// flights cannot be shaped within the accepted-connection bound.
pub fn run_shape_proxy(
    listen_port: u16,
    upstream_port: u16,
    max_shaped: usize,
    max_accepted: usize,
) -> Result<(), String> {
    if max_shaped == 0 || max_accepted < max_shaped {
        return Err("max-shaped must be positive and no larger than max-accepted".to_owned());
    }
    let listener = TcpListener::bind(("127.0.0.1", listen_port))
        .map_err(|error| format!("flight shaper could not bind: {error}"))?;
    println!("READY port={listen_port}");
    let mut accepted = 0;
    let mut shaped = 0;
    while accepted < max_accepted && shaped < max_shaped {
        let (mut client, _) = listener
            .accept()
            .map_err(|error| format!("flight shaper accept failed: {error}"))?;
        accepted += 1;
        if shape_connection(&mut client, upstream_port).is_ok() {
            shaped += 1;
            println!(
                "{}",
                Json::object([
                    ("event", Json::string("flight_shaped")),
                    ("shaped", Json::Int(to_i64(shaped))),
                ])
                .to_jq_json()
            );
        } else {
            println!(
                "{}",
                Json::object([("event", Json::string("connection_ignored"))]).to_jq_json()
            );
        }
    }
    println!(
        "{}",
        Json::object([
            ("accepted", Json::Int(to_i64(accepted))),
            ("event", Json::string("proxy_complete")),
            ("maxAccepted", Json::Int(to_i64(max_accepted))),
            ("maxShaped", Json::Int(to_i64(max_shaped))),
            ("shaped", Json::Int(to_i64(shaped))),
        ])
        .to_jq_json()
    );
    if shaped == max_shaped {
        Ok(())
    } else {
        Err(format!(
            "shaped {shaped} of {max_shaped} flights after {accepted} accepted connections"
        ))
    }
}

fn shape_connection(client: &mut TcpStream, upstream_port: u16) -> Result<(), String> {
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| error.to_string())?;
    client
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| error.to_string())?;
    let hello = read_record(client, MAX_CLIENT_HELLO_BYTES)?;
    validate_client_hello(&hello)?;
    let mut upstream = TcpStream::connect_timeout(
        &([127, 0, 0, 1], upstream_port).into(),
        Duration::from_secs(2),
    )
    .map_err(|error| error.to_string())?;
    upstream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    upstream
        .write_all(&hello)
        .map_err(|error| error.to_string())?;
    let mut response = Vec::new();
    let mut encrypted = 0;
    let mut record_count = 0;
    while encrypted < 4 {
        let record = read_record(&mut upstream, 5 + MAX_TLS_CIPHERTEXT_BYTES)?;
        if record[0] == 23 {
            encrypted += 1;
        }
        response.extend_from_slice(&record);
        record_count += 1;
        if record_count > 8 {
            return Err(
                "cover emitted too many records before its fourth encrypted record".to_owned(),
            );
        }
    }
    response.extend_from_slice(&shaped_fifth_record());
    client
        .write_all(&response)
        .map_err(|error| error.to_string())
}

fn shaped_fifth_record() -> [u8; SHAPED_FIFTH_RECORD_BYTES] {
    let mut record = [0_u8; SHAPED_FIFTH_RECORD_BYTES];
    record[..5].copy_from_slice(&[23, 3, 3, 0, 134]);
    record
}

fn read_record(stream: &mut TcpStream, cap: usize) -> Result<Vec<u8>, String> {
    let mut header = [0_u8; 5];
    stream
        .read_exact(&mut header)
        .map_err(|error| format!("TLS record header is truncated: {error}"))?;
    let payload_bytes = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if payload_bytes == 0 || payload_bytes + 5 > cap {
        return Err(format!(
            "TLS record length {} is outside the helper bound {cap}",
            payload_bytes + 5
        ));
    }
    let mut record = Vec::with_capacity(payload_bytes + 5);
    record.extend_from_slice(&header);
    record.resize(payload_bytes + 5, 0);
    stream
        .read_exact(&mut record[5..])
        .map_err(|error| format!("TLS record body is truncated: {error}"))?;
    Ok(record)
}

fn validate_client_hello(wire: &[u8]) -> Result<(), String> {
    if wire.len() < 9 || wire.len() > MAX_CLIENT_HELLO_BYTES {
        return Err("ClientHello is outside the one-record bound".to_owned());
    }
    if wire[0] != 22 || wire[1..3] != [3, 1] {
        return Err("expected one TLS ClientHello record with legacy version 0x0301".to_owned());
    }
    let record_bytes = 5 + usize::from(u16::from_be_bytes([wire[3], wire[4]]));
    if record_bytes != wire.len() || wire[5] != 1 {
        return Err("captured bytes are not exactly one complete ClientHello".to_owned());
    }
    let handshake_bytes = 4 + usize::try_from(u32::from_be_bytes([0, wire[6], wire[7], wire[8]]))
        .unwrap_or(usize::MAX);
    if handshake_bytes != wire.len() - 5 {
        return Err("ClientHello handshake length does not cover its record".to_owned());
    }
    Ok(())
}

fn cipher_suite_name(id: u16) -> String {
    match id {
        0x1301 => "TLS_AES_128_GCM_SHA256".to_owned(),
        0x1302 => "TLS_AES_256_GCM_SHA384".to_owned(),
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256".to_owned(),
        other => format!("0x{other:04x}"),
    }
}

fn group_name(id: u16) -> String {
    match id {
        0x001d => "X25519".to_owned(),
        0x11ec => "X25519MLKEM768".to_owned(),
        other => format!("0x{other:04x}"),
    }
}

fn signed_delta(left: usize, right: usize) -> i64 {
    let left = i64::try_from(left).unwrap_or(i64::MAX);
    let right = i64::try_from(right).unwrap_or(i64::MAX);
    left.saturating_sub(right)
}

fn to_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_server_flight() -> Vec<u8> {
        let session_id = (0_u8..32).collect::<Vec<_>>();
        let key_share = [0, 0x1d, 0, 1, 0];
        let mut extension = vec![0, 0x33, 0, u8::try_from(key_share.len()).unwrap()];
        extension.extend_from_slice(&key_share);
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0; 32]);
        body.push(u8::try_from(session_id.len()).unwrap());
        body.extend_from_slice(&session_id);
        body.extend_from_slice(&[0x13, 1, 0]);
        body.extend_from_slice(&u16::try_from(extension.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&extension);
        let mut message = vec![2];
        let len = u32::try_from(body.len()).unwrap().to_be_bytes();
        message.extend_from_slice(&len[1..]);
        message.extend_from_slice(&body);
        let mut wire = vec![22, 3, 3];
        wire.extend_from_slice(&u16::try_from(message.len()).unwrap().to_be_bytes());
        wire.extend_from_slice(&message);
        wire.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
        wire.extend_from_slice(&[23, 3, 3, 0, 1, 0]);
        wire
    }

    #[test]
    fn parses_the_complete_outer_sequence_and_server_hello() {
        let wire = sample_server_flight();
        let records = parse_records(&wire).unwrap();
        assert_eq!(
            records
                .iter()
                .map(|record| record.content_type)
                .collect::<Vec<_>>(),
            [22, 20, 23]
        );
        let hello = parse_server_hello(&wire, &records).unwrap();
        assert_eq!(hello.cipher_suite, 0x1301);
        assert_eq!(hello.key_share_group, Some(0x001d));
    }

    #[test]
    fn truncated_or_empty_flights_never_become_valid_samples() {
        assert!(parse_records(&[]).is_err());
        assert!(parse_records(&[22, 3, 3, 0]).is_err());
        assert!(parse_records(&[22, 3, 3, 0, 2, 0]).is_err());
        assert!(parse_records(&[22, 3, 3, 0, 0]).is_err());
    }

    #[test]
    fn comparison_reports_material_record_differences() {
        let wire = sample_server_flight();
        let records = parse_records(&wire).unwrap();
        let flight = Flight {
            wire: wire.clone(),
            records: records.clone(),
            server_hello: parse_server_hello(&wire, &records).unwrap(),
            capture_end: "idle_timeout",
            first_byte_us: Some(10),
            completion_us: Some(11),
        };
        let mut changed = flight.clone();
        changed.records[2].payload_bytes += 1;
        changed.wire.push(0);
        let comparison = compare(&flight, &changed);
        assert!(!comparison.record_sequence_equal);
        assert_eq!(comparison.first_flight_byte_delta, 1);
        assert_eq!(comparison.record_count_delta, 0);
        assert!(comparison.ccs_equal);
        assert!(
            comparison
                .to_json()
                .to_python_json()
                .contains("MATERIAL_DIFFERENCE")
        );
    }

    #[test]
    fn the_handoff_record_is_fixed_and_bounded() {
        let record = shaped_fifth_record();
        assert_eq!(record.len(), 139);
        assert_eq!(&record[..5], &[23, 3, 3, 0, 134]);
        assert!(record[5..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn the_real_tcp_shaper_appends_after_four_encrypted_records() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_port = probe.local_addr().unwrap().port();
        drop(probe);

        let cover = std::thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let hello = read_record(&mut stream, MAX_CLIENT_HELLO_BYTES).unwrap();
            validate_client_hello(&hello).unwrap();
            for byte in 1_u8..=4 {
                stream.write_all(&[23, 3, 3, 0, 1, byte]).unwrap();
            }
        });
        let proxy = std::thread::spawn(move || {
            run_shape_proxy(listen_port, upstream_port, 1, 1).unwrap();
        });

        let deadline = Instant::now() + Duration::from_secs(2);
        let mut client = loop {
            match TcpStream::connect(("127.0.0.1", listen_port)) {
                Ok(stream) => break stream,
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("flight shaper did not listen: {error}"),
            }
        };
        client.write_all(&[22, 3, 1, 0, 4, 1, 0, 0, 0]).unwrap();
        let mut shaped = Vec::new();
        client.read_to_end(&mut shaped).unwrap();

        proxy.join().unwrap();
        cover.join().unwrap();
        assert_eq!(shaped.len(), 4 * 6 + SHAPED_FIFTH_RECORD_BYTES);
        let records = parse_records(&shaped).unwrap();
        assert_eq!(records.len(), 5);
        assert_eq!(records.last().unwrap().wire_bytes(), 139);
    }
}
