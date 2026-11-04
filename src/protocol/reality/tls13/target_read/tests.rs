use std::{
    io,
    io::Write as _,
    net::{TcpListener as StdTcpListener, TcpStream as StdTcpStream},
    pin::Pin,
    sync::mpsc,
    task::Poll,
    thread,
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWriteExt, DuplexStream, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};

use super::{
    BufferedFlightReader, CoverFlightIo, CoverHandshakePlan, CoverHandshakeRecordShape,
    MAX_RETAINED_COVER_PREFIX_LEN, TargetServerHelloReadErrorKind, read_target_server_flight,
    read_target_server_hello,
};
use crate::protocol::reality::{ClientHello, SESSION_ID_LEN, X25519_GROUP, client_hello::fixtures};

struct OneByteReader {
    bytes: Vec<u8>,
    position: usize,
}

impl AsyncRead for OneByteReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut std::task::Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let Some(byte) = self.bytes.get(self.position).copied() else {
            return Poll::Ready(Ok(()));
        };
        output.put_slice(&[byte]);
        self.position += 1;
        Poll::Ready(Ok(()))
    }
}

impl CoverFlightIo for OneByteReader {
    fn try_read_now(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let remaining = self.bytes.len().saturating_sub(self.position);
        let read = remaining.min(output.len());
        if read == 0 {
            return Ok(0);
        }
        output[..read].copy_from_slice(&self.bytes[self.position..self.position + read]);
        self.position += read;
        Ok(read)
    }
}

impl CoverFlightIo for DuplexStream {
    fn try_read_now(&mut self, _output: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::WouldBlock))
    }
}

/// Real TCP reader whose blocking reads stop on fixture record boundaries.
/// `try_read_now` remains the production `TcpStream::try_read` operation.
struct RecordBoundaryTcpReader {
    stream: TcpStream,
    position: usize,
    boundaries: Vec<usize>,
}

impl AsyncRead for RecordBoundaryTcpReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let boundary = self
            .boundaries
            .iter()
            .copied()
            .find(|boundary| *boundary > self.position)
            .unwrap_or(usize::MAX);
        let limit = boundary
            .saturating_sub(self.position)
            .min(output.remaining())
            .min(4 * 1024);
        if limit == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut scratch = [0_u8; 4 * 1024];
        let mut read_buffer = ReadBuf::new(&mut scratch[..limit]);
        match Pin::new(&mut self.stream).poll_read(context, &mut read_buffer) {
            Poll::Ready(Ok(())) => {
                let read = read_buffer.filled().len();
                output.put_slice(read_buffer.filled());
                self.position += read;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl CoverFlightIo for RecordBoundaryTcpReader {
    fn try_read_now(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.stream.try_read(output)
    }
}

#[tokio::test(flavor = "current_thread")]
async fn retained_prefix_accepts_the_exact_global_limit_and_rejects_one_more_byte() {
    let mut reader = OneByteReader {
        bytes: vec![0x5a],
        position: 0,
    };
    let mut flight = BufferedFlightReader {
        reader: &mut reader,
        deadline: tokio::time::Instant::now() + Duration::from_secs(1),
        buffer: vec![0; MAX_RETAINED_COVER_PREFIX_LEN - 1],
        consumed: MAX_RETAINED_COVER_PREFIX_LEN - 1,
    };

    flight
        .fill(1)
        .await
        .expect("the exact 66,642-byte prefix limit must be accepted");
    assert_eq!(flight.buffer.len(), MAX_RETAINED_COVER_PREFIX_LEN);
    assert_eq!(flight.buffer.last(), Some(&0x5a));
    assert!(matches!(
        flight.fill(2).await,
        Err(TargetServerHelloReadErrorKind::RecordTooLarge)
    ));
    assert_eq!(flight.buffer.len(), MAX_RETAINED_COVER_PREFIX_LEN);
}

#[tokio::test(flavor = "current_thread")]
async fn reads_fragmented_target_record_without_consuming_next_record() {
    let client = client();
    let record = target_record(&[0x55; 32]);
    let mut input = record.clone();
    input.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
    let mut reader = OneByteReader {
        bytes: input,
        position: 0,
    };

    let read = read_target_server_hello(&mut reader, &client, Duration::from_secs(1))
        .await
        .expect("compatible target ServerHello must be read");

    assert_eq!(read.wire_record(), record);
    assert_eq!(read.template().key_share_group(), X25519_GROUP);
    assert_eq!(reader.position, record.len());
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_target_returns_complete_byte_exact_record() {
    let client = client();
    let mut record = target_record(&[0x55; 32]);
    record[5] = 1;
    let mut reader = OneByteReader {
        bytes: record.clone(),
        position: 0,
    };

    let error = read_target_server_hello(&mut reader, &client, Duration::from_secs(1))
        .await
        .expect_err("non-ServerHello handshake must fail");

    assert!(matches!(
        error.kind(),
        TargetServerHelloReadErrorKind::Invalid(_)
    ));
    assert_eq!(error.fallback_prefix(), record);
}

#[tokio::test(flavor = "current_thread")]
async fn timeout_returns_partial_target_prefix() {
    let client = client();
    let (mut local, mut remote) = tokio::io::duplex(16);
    let prefix = [22, 3, 3, 0, 128, 2, 0];
    remote
        .write_all(&prefix)
        .await
        .expect("partial target response must be written");

    let error = read_target_server_hello(&mut local, &client, Duration::from_millis(20))
        .await
        .expect_err("incomplete target response must time out");

    assert!(matches!(
        error.kind(),
        TargetServerHelloReadErrorKind::Timeout
    ));
    assert_eq!(error.fallback_prefix(), prefix);
}

#[tokio::test(flavor = "current_thread")]
async fn rejects_non_handshake_header_without_reading_declared_body() {
    let client = client();
    let header = [21, 3, 3, 0, 64];
    let mut reader = OneByteReader {
        bytes: header.to_vec(),
        position: 0,
    };

    let error = read_target_server_hello(&mut reader, &client, Duration::from_secs(1))
        .await
        .expect_err("alert record must not be accepted as ServerHello");

    assert!(matches!(
        error.kind(),
        TargetServerHelloReadErrorKind::UnexpectedRecord
    ));
    assert_eq!(error.fallback_prefix(), header);
    assert_eq!(reader.position, header.len());
}

#[tokio::test(flavor = "current_thread")]
async fn coalesced_shape_consumes_the_header_and_first_body_byte() {
    let client = client();
    let server_hello = target_record(&[0x55; 32]);
    let ccs = [20, 3, 3, 0, 1, 1];
    let encrypted = opaque_record(23, 600, 0xa5);
    let expected_prefix_len = server_hello.len() + ccs.len() + 6;
    let mut input = server_hello.clone();
    input.extend_from_slice(&ccs);
    input.extend_from_slice(&encrypted);
    let mut reader = OneByteReader {
        bytes: input.clone(),
        position: 0,
    };

    let read = read_target_server_flight(&mut reader, &client, Duration::from_secs(1))
        .await
        .expect("large first encrypted record must select coalescing");
    let (_, plan, prefix) = read.into_parts();

    assert_eq!(
        plan,
        CoverHandshakePlan {
            emit_ccs: true,
            shape: CoverHandshakeRecordShape::Coalesced { wire_len: 605 },
        }
    );
    assert_eq!(prefix, input[..expected_prefix_len]);
    assert_eq!(reader.position, expected_prefix_len);
}

#[tokio::test(flavor = "current_thread")]
async fn coalesced_header_without_a_body_byte_times_out_with_exact_prefix() {
    let client = client();
    let mut prefix = target_record(&[0x55; 32]);
    prefix.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
    prefix.extend_from_slice(&[23, 3, 3, 2, 88]);
    let (mut local, mut remote) = tokio::io::duplex(2_048);
    remote
        .write_all(&prefix)
        .await
        .expect("header-only target flight must be written");

    let error = read_target_server_flight(&mut local, &client, Duration::from_millis(20))
        .await
        .expect_err("a declared coalesced record must contain ciphertext");

    assert!(matches!(
        error.kind(),
        TargetServerHelloReadErrorKind::Timeout
    ));
    assert_eq!(error.fallback_prefix(), prefix);
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_change_cipher_spec_retains_the_exact_consumed_prefix() {
    let client = client();
    let mut input = target_record(&[0x55; 32]);
    input.extend_from_slice(&[20, 3, 3, 0, 1, 2]);
    let mut reader = OneByteReader {
        bytes: input.clone(),
        position: 0,
    };

    let error = read_target_server_flight(&mut reader, &client, Duration::from_secs(1))
        .await
        .expect_err("invalid CCS content must be rejected");

    assert!(matches!(
        error.kind(),
        TargetServerHelloReadErrorKind::UnexpectedRecord
    ));
    assert_eq!(error.fallback_prefix(), input);
    assert_eq!(reader.position, input.len());
}

#[tokio::test(flavor = "current_thread")]
async fn positional_shape_probes_and_retains_a_fifth_ticket_record() {
    let client = client();
    let mut input = target_record(&[0x55; 32]);
    input.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
    let body_lens = [32_usize, 208, 89, 53];
    for (index, body_len) in body_lens.into_iter().enumerate() {
        input.extend_from_slice(&opaque_record(23, body_len, index as u8));
    }
    input.extend_from_slice(&opaque_record(23, 24, 0xff));
    let mut reader = OneByteReader {
        bytes: input.clone(),
        position: 0,
    };

    let read = read_target_server_flight(&mut reader, &client, Duration::from_secs(1))
        .await
        .expect("four small encrypted records must be read positionally");
    let (_, plan, prefix) = read.into_parts();

    assert_eq!(
        plan,
        CoverHandshakePlan {
            emit_ccs: true,
            shape: CoverHandshakeRecordShape::PositionalRecords {
                wire_lens: [37, 213, 94, 58],
                nst_wire_len: Some(29),
            },
        }
    );
    assert_eq!(prefix, input);
    assert_eq!(reader.position, input.len());
}

#[tokio::test(flavor = "current_thread")]
async fn positional_shape_without_ccs_or_ticket_is_retained_exactly() {
    let client = client();
    let mut input = target_record(&[0x55; 32]);
    for (index, body_len) in [32_usize, 208, 89, 53].into_iter().enumerate() {
        input.extend_from_slice(&opaque_record(23, body_len, index as u8));
    }
    let mut reader = OneByteReader {
        bytes: input.clone(),
        position: 0,
    };

    let read = read_target_server_flight(&mut reader, &client, Duration::from_secs(1))
        .await
        .expect("CCS-less four-record cover flight must be accepted");
    let (_, plan, prefix) = read.into_parts();

    assert_eq!(
        plan,
        CoverHandshakePlan {
            emit_ccs: false,
            shape: CoverHandshakeRecordShape::PositionalRecords {
                wire_lens: [37, 213, 94, 58],
                nst_wire_len: None,
            },
        }
    );
    assert_eq!(prefix, input);
    assert_eq!(reader.position, input.len());
}

#[tokio::test(flavor = "current_thread")]
async fn tcp_record_delay_matrix_covers_fifth_probe_timing() {
    const DELAYS_MS: [u64; 5] = [0, 20, 50, 100, 200];
    const CASES: [&str; 3] = [
        "already-buffered",
        "single-probe-present",
        "absent-would-block",
    ];

    for delay_ms in DELAYS_MS {
        for case in CASES {
            let client = client();
            let server_hello = target_record(&[0x55; 32]);
            let ccs = [20, 3, 3, 0, 1, 1].to_vec();
            let encrypted: Vec<Vec<u8>> = [32_usize, 48, 64, 80]
                .into_iter()
                .enumerate()
                .map(|(index, body_len)| opaque_record(23, body_len, index as u8))
                .collect();
            let ticket = opaque_record(23, 24, 0xf5);
            let emit_ccs = case != "single-probe-present";
            let mut records = vec![server_hello.clone()];
            if emit_ccs {
                records.push(ccs.clone());
            }
            records.extend(encrypted.iter().cloned());
            if case != "absent-would-block" {
                records.push(ticket.clone());
            }
            let prefix_without_ticket: Vec<u8> = records
                .iter()
                .take(records.len() - usize::from(case != "absent-would-block"))
                .flatten()
                .copied()
                .collect();

            let listener = StdTcpListener::bind("127.0.0.1:0")
                .expect("record-delay fixture listener must bind");
            let address = listener
                .local_addr()
                .expect("record-delay fixture must have an address");
            let (sent_tx, sent_rx) = mpsc::sync_channel(1);
            let (done_tx, done_rx) = mpsc::sync_channel(1);
            let server = thread::spawn(move || {
                let (mut stream, _) = listener
                    .accept()
                    .expect("record-delay fixture connection must arrive");
                for (index, record) in records.iter().enumerate() {
                    if index > 0 {
                        thread::sleep(Duration::from_millis(delay_ms));
                    }
                    stream
                        .write_all(record)
                        .expect("complete TLS record must be sent in one fixture write");
                }
                sent_tx
                    .send(())
                    .expect("reader must await the complete scheduled flight");
                done_rx
                    .recv_timeout(Duration::from_secs(2))
                    .expect("reader must complete before fixture closes");
            });
            let stream = StdTcpStream::connect(address)
                .expect("record-delay fixture TCP connection must open");
            stream
                .set_nonblocking(true)
                .expect("Tokio TCP stream requires nonblocking mode");
            sent_rx
                .recv_timeout(Duration::from_secs(3))
                .expect("record-delay fixture must send within its bound");
            let stream =
                TcpStream::from_std(stream).expect("fixture std stream must convert to Tokio");

            let mut position = 0;
            let mut boundaries = Vec::new();
            let records_before_ticket = 1 + usize::from(emit_ccs) + encrypted.len();
            for record in std::iter::once(&server_hello)
                .chain(emit_ccs.then_some(&ccs))
                .chain(encrypted.iter())
            {
                position += record.len();
                boundaries.push(position);
            }
            if case == "already-buffered" {
                *boundaries
                    .get_mut(records_before_ticket - 1)
                    .expect("fourth encrypted boundary must exist") += 5;
            }
            let mut reader = RecordBoundaryTcpReader {
                stream,
                position: 0,
                boundaries,
            };
            let read = read_target_server_flight(&mut reader, &client, Duration::from_secs(2))
                .await
                .expect("record-delay matrix flight must parse");
            let (_, plan, prefix) = read.into_parts();
            let expected_ticket_len = (case != "absent-would-block").then_some(ticket.len());
            assert_eq!(
                plan,
                CoverHandshakePlan {
                    emit_ccs,
                    shape: CoverHandshakeRecordShape::PositionalRecords {
                        wire_lens: [37, 53, 69, 85],
                        nst_wire_len: expected_ticket_len,
                    },
                },
                "delay={delay_ms}ms case={case}"
            );
            let expected_prefix = match case {
                "already-buffered" => {
                    let mut expected = prefix_without_ticket.clone();
                    expected.extend_from_slice(&ticket[..5]);
                    expected
                }
                "single-probe-present" => {
                    let mut expected = prefix_without_ticket.clone();
                    expected.extend_from_slice(&ticket);
                    expected
                }
                "absent-would-block" => prefix_without_ticket.clone(),
                _ => unreachable!(),
            };
            assert_eq!(prefix, expected_prefix, "delay={delay_ms}ms case={case}");
            done_tx
                .send(())
                .expect("fixture server must still be waiting");
            server
                .join()
                .expect("record-delay fixture server must finish");
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn positional_timeout_retains_the_exact_partial_record() {
    let client = client();
    let mut prefix = target_record(&[0x55; 32]);
    prefix.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
    prefix.extend_from_slice(&opaque_record(23, 32, 0x01));
    prefix.extend_from_slice(&[23, 3, 3, 0, 64, 0xaa, 0xbb, 0xcc]);
    let (mut local, mut remote) = tokio::io::duplex(2_048);
    remote
        .write_all(&prefix)
        .await
        .expect("partial target flight must be written");

    let error = read_target_server_flight(&mut local, &client, Duration::from_millis(20))
        .await
        .expect_err("partial positional record must time out");

    assert!(matches!(
        error.kind(),
        TargetServerHelloReadErrorKind::Timeout
    ));
    assert_eq!(error.fallback_prefix(), prefix);
}

#[tokio::test(flavor = "current_thread")]
async fn tcp_mid_record_close_returns_exact_prefix_and_unexpected_eof() {
    let client = client();
    let prefix = partial_positional_flight();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ephemeral TCP listener must bind");
    let address = listener
        .local_addr()
        .expect("ephemeral TCP listener must have an address");
    let server_prefix = prefix.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener
            .accept()
            .await
            .expect("cover TCP connection must arrive");
        stream
            .write_all(&server_prefix)
            .await
            .expect("partial cover flight must be written");
        stream
            .shutdown()
            .await
            .expect("partial cover connection must close cleanly");
    });
    let mut stream = TcpStream::connect(address)
        .await
        .expect("cover TCP connection must open");

    let error = tokio::time::timeout(
        Duration::from_secs(1),
        read_target_server_flight(&mut stream, &client, Duration::from_millis(250)),
    )
    .await
    .expect("closed cover connection must fail within the outer test deadline")
    .expect_err("closing in the middle of a record must fail");
    server.await.expect("cover TCP task must complete");

    assert!(matches!(
        error.kind(),
        TargetServerHelloReadErrorKind::UnexpectedEof
    ));
    assert_eq!(error.fallback_prefix(), prefix);
}

#[tokio::test(flavor = "current_thread")]
async fn tcp_mid_record_stall_returns_exact_prefix_and_timeout() {
    let client = client();
    let prefix = partial_positional_flight();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ephemeral TCP listener must bind");
    let address = listener
        .local_addr()
        .expect("ephemeral TCP listener must have an address");
    let server_prefix = prefix.clone();
    let (written_tx, written_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener
            .accept()
            .await
            .expect("cover TCP connection must arrive");
        stream
            .write_all(&server_prefix)
            .await
            .expect("partial cover flight must be written");
        written_tx
            .send(())
            .expect("test reader must await the written prefix");
        let _ = release_rx.await;
    });
    let mut stream = TcpStream::connect(address)
        .await
        .expect("cover TCP connection must open");
    written_rx
        .await
        .expect("cover TCP task must report the written prefix");

    let error = tokio::time::timeout(
        Duration::from_secs(1),
        read_target_server_flight(&mut stream, &client, Duration::from_millis(100)),
    )
    .await
    .expect("stalled cover connection must fail within the outer test deadline")
    .expect_err("stalling in the middle of a record must time out");
    assert!(matches!(
        error.kind(),
        TargetServerHelloReadErrorKind::Timeout
    ));
    assert_eq!(error.fallback_prefix(), prefix);

    let _ = release_tx.send(());
    server.await.expect("cover TCP task must complete");
}

#[tokio::test(flavor = "current_thread")]
async fn every_positional_flight_truncation_retains_the_exact_prefix() {
    let client = client();
    let mut complete = target_record(&[0x55; 32]);
    complete.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
    for (index, body_len) in [32_usize, 48, 64, 40].into_iter().enumerate() {
        complete.extend_from_slice(&opaque_record(23, body_len, index as u8));
    }

    for cutoff in 0..complete.len() {
        let expected = complete[..cutoff].to_vec();
        let mut reader = OneByteReader {
            bytes: expected.clone(),
            position: 0,
        };
        let error = read_target_server_flight(&mut reader, &client, Duration::from_secs(1))
            .await
            .expect_err("every truncated flight must fail closed");

        assert!(matches!(
            error.kind(),
            TargetServerHelloReadErrorKind::UnexpectedEof
        ));
        assert_eq!(error.fallback_prefix(), expected);
        assert_eq!(reader.position, cutoff);
    }
}

fn client() -> ClientHello {
    ClientHello::parse_message(&fixtures::client_hello_with_key_share(
        [0x44; 32],
        &[0x11; SESSION_ID_LEN],
        "www.example.com",
        &[b"h2"],
        X25519_GROUP,
        &[0x22; 32],
    ))
    .expect("test ClientHello must parse")
}

fn target_record(key_exchange: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303_u16.to_be_bytes());
    body.extend_from_slice(&[0x33; 32]);
    body.push(u8::try_from(SESSION_ID_LEN).expect("test session ID must fit"));
    body.extend_from_slice(&[0x11; SESSION_ID_LEN]);
    body.extend_from_slice(&0x1301_u16.to_be_bytes());
    body.push(0);

    let mut extensions = Vec::new();
    push_extension(&mut extensions, 0x002b, &0x0304_u16.to_be_bytes());
    let mut share = Vec::new();
    share.extend_from_slice(&X25519_GROUP.to_be_bytes());
    share.extend_from_slice(
        &u16::try_from(key_exchange.len())
            .expect("test key share must fit")
            .to_be_bytes(),
    );
    share.extend_from_slice(key_exchange);
    push_extension(&mut extensions, 0x0033, &share);
    body.extend_from_slice(
        &u16::try_from(extensions.len())
            .expect("test extensions must fit")
            .to_be_bytes(),
    );
    body.extend_from_slice(&extensions);

    let mut message = vec![2];
    let message_len = u32::try_from(body.len()).expect("test ServerHello body must fit");
    message.extend_from_slice(&message_len.to_be_bytes()[1..]);
    message.extend_from_slice(&body);

    let mut record = vec![22, 3, 3];
    record.extend_from_slice(
        &u16::try_from(message.len())
            .expect("test record must fit")
            .to_be_bytes(),
    );
    record.extend_from_slice(&message);
    record
}

fn opaque_record(content_type: u8, body_len: usize, fill: u8) -> Vec<u8> {
    let mut record = vec![content_type, 3, 3];
    record.extend_from_slice(
        &u16::try_from(body_len)
            .expect("test record body must fit")
            .to_be_bytes(),
    );
    record.resize(5 + body_len, fill);
    record
}

fn partial_positional_flight() -> Vec<u8> {
    let mut prefix = target_record(&[0x55; 32]);
    prefix.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
    prefix.extend_from_slice(&opaque_record(23, 32, 0x01));
    prefix.extend_from_slice(&[23, 3, 3, 0, 64, 0xaa, 0xbb, 0xcc]);
    prefix
}

fn push_extension(output: &mut Vec<u8>, extension_type: u16, value: &[u8]) {
    output.extend_from_slice(&extension_type.to_be_bytes());
    output.extend_from_slice(
        &u16::try_from(value.len())
            .expect("test extension must fit")
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
}
