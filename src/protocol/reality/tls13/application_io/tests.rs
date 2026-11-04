use std::{
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use futures_util::task::AtomicWaker;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf, duplex};

use super::{
    KEY_UPDATE_REQUESTED, KEY_UPDATE_RESPONSE, KeyUpdateCoordination, TlsApplicationIo,
    TlsApplicationIoError, VectoredRead, resume_application_halves,
};
use crate::protocol::reality::tls13::record::{
    BATCHED_SLOT_COUNT, BATCHED_WIRE_CAPACITY, RECORD_SLOT_WIRE_CAPACITY,
    grow_batched_record_storage,
};
use crate::protocol::reality::tls13::{
    CipherSuite, ContentType, EstablishedTls, ExportedRecordState, MAX_PLAINTEXT_LEN,
    TLS_RECORD_HEADER_LEN, Tls13KeySchedule, Tls13RecordError, Tls13RecordLayer,
    TlsRecordReadErrorKind, read_tls_record,
};

const TIMEOUT: Duration = Duration::from_secs(1);

#[tokio::test(flavor = "current_thread")]
async fn decrypts_and_encrypts_application_records_without_plaintext_copy() {
    let (established, mut client_write_records, mut client_read_records) = key_update_states();
    let (mut client, server) = duplex(64 * 1024);
    let application = TlsApplicationIo::new(server, established);
    let (mut application_reader, mut application_writer) = application.into_split();

    let mut request_record = Vec::new();
    client_write_records
        .seal_into(
            ContentType::ApplicationData,
            b"VLESS request",
            0,
            &mut request_record,
        )
        .expect("request must seal");
    client
        .write_all(&request_record)
        .await
        .expect("request record must be written");
    let request = application_reader
        .read_application(TIMEOUT)
        .await
        .expect("request record must authenticate");
    assert_eq!(request.plaintext(), b"VLESS request");
    assert_eq!(request.len(), b"VLESS request".len());

    let stats = application_writer
        .write_application(b"VLESS response", TIMEOUT)
        .await
        .expect("response must encrypt");
    assert_eq!(stats.plaintext_bytes(), b"VLESS response".len() as u64);
    assert_eq!(stats.records(), 1);
    let mut response_record = read_tls_record(&mut client, TIMEOUT)
        .await
        .expect("response record must be read")
        .into_wire();
    let response = client_read_records
        .open_in_place(&mut response_record)
        .expect("response record must authenticate");
    assert_eq!(response.content_type(), ContentType::ApplicationData);
    assert_eq!(response.plaintext(), b"VLESS response");

    application_writer
        .shutdown(TIMEOUT)
        .await
        .expect("close notify must be sent");
    let mut close_record = read_tls_record(&mut client, TIMEOUT)
        .await
        .expect("close notify record must be read")
        .into_wire();
    let close = client_read_records
        .open_in_place(&mut close_record)
        .expect("close notify must authenticate");
    assert_eq!(close.content_type(), ContentType::Alert);
    assert_eq!(close.plaintext(), [1, 0]);
}

#[tokio::test(flavor = "current_thread")]
async fn authenticated_peer_alert_is_not_application_eof() {
    let (established, mut client_records, _client_read_records) = key_update_states();
    let (mut client, server) = duplex(1024);
    let mut application = TlsApplicationIo::new(server, established);
    let mut alert = Vec::new();
    client_records
        .seal_into(ContentType::Alert, &[2, 40], 0, &mut alert)
        .expect("fatal handshake alert must seal");
    client
        .write_all(&alert)
        .await
        .expect("alert record must be written");

    assert!(matches!(
        application.read_application(TIMEOUT).await,
        Err(TlsApplicationIoError::PeerAlert {
            level: 2,
            description: 40
        })
    ));
}

fn schedule(suite: CipherSuite) -> Tls13KeySchedule {
    Tls13KeySchedule::new(
        suite,
        &[0x31; 32],
        &suite.hash().digest(b"server hello transcript"),
    )
    .expect("test key schedule must derive")
}

fn key_update_states() -> (EstablishedTls, Tls13RecordLayer, Tls13RecordLayer) {
    let suite = CipherSuite::Aes128GcmSha256;
    let schedule = schedule(suite);
    let transcript = suite.hash().digest(b"server finished transcript");
    let (server_client_secret, server_server_secret) = schedule
        .application_traffic_secrets(&transcript)
        .expect("server application secrets must derive")
        .into_parts();
    let (client_write_secret, client_read_secret) = schedule
        .application_traffic_secrets(&transcript)
        .expect("client application secrets must derive")
        .into_parts();
    let server_client_records = Tls13RecordLayer::from_traffic_secret(suite, server_client_secret)
        .expect("server read records must initialize");
    let server_server_records = Tls13RecordLayer::from_traffic_secret(suite, server_server_secret)
        .expect("server write records must initialize");
    (
        EstablishedTls::from_test_records(suite, server_client_records, server_server_records),
        Tls13RecordLayer::from_traffic_secret(suite, client_write_secret)
            .expect("client write records must initialize"),
        Tls13RecordLayer::from_traffic_secret(suite, client_read_secret)
            .expect("client read records must initialize"),
    )
}

fn seal(records: &mut Tls13RecordLayer, content_type: ContentType, plaintext: &[u8]) -> Vec<u8> {
    let mut record = Vec::new();
    records
        .seal_into(content_type, plaintext, 0, &mut record)
        .expect("test record must seal");
    record
}

#[tokio::test(flavor = "current_thread")]
async fn split_reader_reassembles_unrequested_key_update_before_application_data() {
    let (established, mut client_write, _client_read) = key_update_states();
    let (mut client, server) = duplex(4096);
    let application = TlsApplicationIo::new(server, established);
    let (mut reader, writer) = application.into_split();

    let mut wire = seal(
        &mut client_write,
        ContentType::Handshake,
        &KEY_UPDATE_RESPONSE[..2],
    );
    wire.extend_from_slice(&seal(
        &mut client_write,
        ContentType::Handshake,
        &KEY_UPDATE_RESPONSE[2..],
    ));
    client_write
        .update_traffic_secret()
        .expect("client write secret must update");
    wire.extend_from_slice(&seal(
        &mut client_write,
        ContentType::ApplicationData,
        b"after update",
    ));
    client
        .write_all(&wire)
        .await
        .expect("fragmented KeyUpdate and application record must be written");

    for _ in 0..2 {
        let control = reader
            .read_application(TIMEOUT)
            .await
            .expect("KeyUpdate fragment must authenticate");
        assert!(control.is_empty());
    }
    let application = reader
        .read_application(TIMEOUT)
        .await
        .expect("next application record must authenticate");
    assert_eq!(application.plaintext(), b"after update");
    assert!(
        !writer.into_handoff_parts().2,
        "update_not_requested must not schedule a response"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn key_update_returns_without_waiting_for_application_data() {
    let (established, mut client_write, _client_read) = key_update_states();
    let (mut client, server) = duplex(4096);
    let application = TlsApplicationIo::new(server, established);
    let (mut reader, writer) = application.into_split();
    let wire = seal(
        &mut client_write,
        ContentType::Handshake,
        &KEY_UPDATE_RESPONSE,
    );
    client_write
        .update_traffic_secret()
        .expect("client write secret must update");
    client
        .write_all(&wire)
        .await
        .expect("KeyUpdate must be written");

    let control = reader
        .read_application(TIMEOUT)
        .await
        .expect("KeyUpdate must return at its record boundary");
    assert!(control.is_empty());
    assert!(!writer.into_handoff_parts().2);
}

#[tokio::test(flavor = "current_thread")]
async fn requested_key_update_response_precedes_next_generation_application_data() {
    let (established, mut client_write, mut client_read) = key_update_states();
    let (_, _, mut stale_client_read) = key_update_states();
    let (mut client, server) = duplex(4096);
    let application = TlsApplicationIo::new(server, established);
    let (mut reader, mut writer) = application.into_split();

    let request = [
        KEY_UPDATE_RESPONSE[0],
        KEY_UPDATE_RESPONSE[1],
        KEY_UPDATE_RESPONSE[2],
        KEY_UPDATE_RESPONSE[3],
        KEY_UPDATE_REQUESTED,
    ];
    let mut wire = seal(&mut client_write, ContentType::Handshake, &request);
    client_write
        .update_traffic_secret()
        .expect("client write secret must update");
    wire.extend_from_slice(&seal(
        &mut client_write,
        ContentType::ApplicationData,
        b"request body",
    ));
    client
        .write_all(&wire)
        .await
        .expect("requested KeyUpdate and application record must be written");

    let control = reader
        .read_application(TIMEOUT)
        .await
        .expect("requested KeyUpdate must authenticate");
    assert!(control.is_empty());
    let request_body = reader
        .read_application(TIMEOUT)
        .await
        .expect("next application record must authenticate");
    assert_eq!(request_body.plaintext(), b"request body");
    writer
        .write_assembled(
            b"reply".len(),
            |plaintext| plaintext.copy_from_slice(b"reply"),
            TIMEOUT,
        )
        .await
        .expect("response and application record must be written");

    let mut response_wire = read_tls_record(&mut client, TIMEOUT)
        .await
        .expect("KeyUpdate response must be first")
        .into_wire();
    let mut application_wire = read_tls_record(&mut client, TIMEOUT)
        .await
        .expect("application record must follow")
        .into_wire();
    let mut stale_response_wire = response_wire.clone();
    let response = stale_client_read
        .open_in_place(&mut stale_response_wire)
        .expect("response must use the old write key");
    assert_eq!(response.content_type(), ContentType::Handshake);
    assert_eq!(response.plaintext(), KEY_UPDATE_RESPONSE);
    let mut stale_application_wire = application_wire.clone();
    assert!(matches!(
        stale_client_read.open_in_place(&mut stale_application_wire),
        Err(Tls13RecordError::AuthenticationFailed)
    ));

    let response = client_read
        .open_in_place(&mut response_wire)
        .expect("response must authenticate under the old key");
    assert_eq!(response.content_type(), ContentType::Handshake);
    assert_eq!(response.plaintext(), KEY_UPDATE_RESPONSE);
    client_read
        .update_traffic_secret()
        .expect("client read secret must update");
    let application = client_read
        .open_in_place(&mut application_wire)
        .expect("application data must use the next write key");
    assert_eq!(application.content_type(), ContentType::ApplicationData);
    assert_eq!(application.plaintext(), b"reply");
}

#[tokio::test(flavor = "current_thread")]
async fn unsplit_io_processes_requested_key_update_transparently() {
    let (established, mut client_write, mut client_read) = key_update_states();
    let (mut client, server) = duplex(4096);
    let mut application = TlsApplicationIo::new(server, established);
    let request = [24, 0, 0, 1, KEY_UPDATE_REQUESTED];
    let mut wire = seal(&mut client_write, ContentType::Handshake, &request);
    client_write
        .update_traffic_secret()
        .expect("client write secret must update");
    wire.extend_from_slice(&seal(
        &mut client_write,
        ContentType::ApplicationData,
        b"unsplit request",
    ));
    client
        .write_all(&wire)
        .await
        .expect("unsplit request must be written");

    let control = application
        .read_application(TIMEOUT)
        .await
        .expect("unsplit KeyUpdate must authenticate");
    assert!(control.is_empty());
    let request = application
        .read_application(TIMEOUT)
        .await
        .expect("unsplit application record must authenticate");
    assert_eq!(request.plaintext(), b"unsplit request");
    application
        .write_application(b"unsplit reply", TIMEOUT)
        .await
        .expect("unsplit response must be written");

    let mut response_wire = read_tls_record(&mut client, TIMEOUT)
        .await
        .expect("unsplit KeyUpdate response must be written first")
        .into_wire();
    let response = client_read
        .open_in_place(&mut response_wire)
        .expect("unsplit response must use the old key");
    assert_eq!(response.content_type(), ContentType::Handshake);
    assert_eq!(response.plaintext(), KEY_UPDATE_RESPONSE);
    client_read
        .update_traffic_secret()
        .expect("client read secret must update");
    let mut application_wire = read_tls_record(&mut client, TIMEOUT)
        .await
        .expect("unsplit application response must follow")
        .into_wire();
    let response = client_read
        .open_in_place(&mut application_wire)
        .expect("unsplit application response must use the next key");
    assert_eq!(response.content_type(), ContentType::ApplicationData);
    assert_eq!(response.plaintext(), b"unsplit reply");
}

#[tokio::test(flavor = "current_thread")]
async fn application_data_after_key_update_rejects_the_old_read_key() {
    let (established, mut client_write, _client_read) = key_update_states();
    let (mut client, server) = duplex(4096);
    let mut application = TlsApplicationIo::new(server, established);
    let mut wire = seal(
        &mut client_write,
        ContentType::Handshake,
        &KEY_UPDATE_RESPONSE,
    );
    wire.extend_from_slice(&seal(
        &mut client_write,
        ContentType::ApplicationData,
        b"stale generation",
    ));
    client
        .write_all(&wire)
        .await
        .expect("stale-generation test records must be written");

    let control = application
        .read_application(TIMEOUT)
        .await
        .expect("KeyUpdate must authenticate");
    assert!(control.is_empty());
    assert!(matches!(
        application.read_application(TIMEOUT).await,
        Err(TlsApplicationIoError::Record(
            Tls13RecordError::AuthenticationFailed
        ))
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn unsplit_reader_rejects_malformed_and_interleaved_key_updates() {
    let malformed = [
        vec![(ContentType::Handshake, Vec::new())],
        vec![(ContentType::Handshake, vec![25, 0, 0, 1, 0])],
        vec![(ContentType::Handshake, vec![24, 0, 0, 2, 0])],
        vec![(ContentType::Handshake, vec![24, 0, 0, 1, 2])],
        vec![(ContentType::Handshake, vec![24, 0, 0, 1, 0, 7])],
        vec![(
            ContentType::Handshake,
            [
                KEY_UPDATE_RESPONSE.as_slice(),
                KEY_UPDATE_RESPONSE.as_slice(),
            ]
            .concat(),
        )],
        vec![
            (ContentType::Handshake, vec![24, 0]),
            (ContentType::ApplicationData, b"interleaved".to_vec()),
        ],
        vec![
            (ContentType::Handshake, vec![24, 0]),
            (ContentType::Alert, vec![2, 40]),
        ],
    ];

    for records in malformed {
        let (established, mut client_write, _client_read) = key_update_states();
        let (mut client, server) = duplex(4096);
        let mut application = TlsApplicationIo::new(server, established);
        let record_count = records.len();
        let mut wire = Vec::new();
        for (content_type, plaintext) in records {
            wire.extend_from_slice(&seal(&mut client_write, content_type, &plaintext));
        }
        client
            .write_all(&wire)
            .await
            .expect("malformed test records must be written");

        let mut rejected = false;
        for _ in 0..record_count {
            match application.read_application(TIMEOUT).await {
                Ok(control) if control.is_empty() => {}
                Err(TlsApplicationIoError::InvalidKeyUpdate) => {
                    rejected = true;
                    break;
                }
                result => panic!("unexpected malformed KeyUpdate result: {result:?}"),
            }
        }
        assert!(rejected);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn handoff_resume_preserves_requested_key_update_response() {
    let (established, mut client_write, mut client_read) = key_update_states();
    let (mut client, server) = duplex(4096);
    let application = TlsApplicationIo::new(server, established);
    let (mut reader, writer) = application.into_split();
    let request = [24, 0, 0, 1, KEY_UPDATE_REQUESTED];
    let mut wire = seal(&mut client_write, ContentType::Handshake, &request);
    client_write
        .update_traffic_secret()
        .expect("client write secret must update");
    wire.extend_from_slice(&seal(
        &mut client_write,
        ContentType::ApplicationData,
        b"handoff boundary",
    ));
    client
        .write_all(&wire)
        .await
        .expect("handoff input must be written");
    let control = reader
        .read_application(TIMEOUT)
        .await
        .expect("handoff KeyUpdate must authenticate");
    assert!(control.is_empty());
    let boundary = reader
        .read_application(TIMEOUT)
        .await
        .expect("handoff boundary must authenticate");
    assert_eq!(boundary.plaintext(), b"handoff boundary");

    let (writer_half, server_records, key_update_response_pending) = writer.into_handoff_parts();
    assert!(key_update_response_pending);
    let (pending_ciphertext, reader_half, client_records) = reader.into_handoff_parts();
    let tls = EstablishedTls::from_test_records(
        CipherSuite::Aes128GcmSha256,
        client_records,
        server_records,
    );
    let (_reader, mut writer) = resume_application_halves(
        reader_half,
        pending_ciphertext,
        writer_half,
        tls,
        key_update_response_pending,
    );
    writer
        .write_application(b"after handoff", TIMEOUT)
        .await
        .expect("resumed writer must answer before application data");

    let mut response_wire = read_tls_record(&mut client, TIMEOUT)
        .await
        .expect("resumed response must be written")
        .into_wire();
    let response = client_read
        .open_in_place(&mut response_wire)
        .expect("resumed response must use the old write key");
    assert_eq!(response.content_type(), ContentType::Handshake);
    assert_eq!(response.plaintext(), KEY_UPDATE_RESPONSE);
    client_read
        .update_traffic_secret()
        .expect("client read secret must update");
    let mut application_wire = read_tls_record(&mut client, TIMEOUT)
        .await
        .expect("resumed application data must be written")
        .into_wire();
    let application = client_read
        .open_in_place(&mut application_wire)
        .expect("resumed application data must use the next write key");
    assert_eq!(application.plaintext(), b"after handoff");
}

/// Server-side TLS state plus the client's write record layer.
fn buffered_reader_states() -> (EstablishedTls, Tls13RecordLayer) {
    let (established, client_write, _client_read) = key_update_states();
    (established, client_write)
}

/// A transport replaying input in bounded chunks and counting socket reads.
struct CountingTransport {
    input: Vec<u8>,
    position: usize,
    chunk: usize,
    reads: Arc<AtomicUsize>,
}

impl AsyncRead for CountingTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        let available = self.input.len().saturating_sub(self.position);
        let length = available.min(output.remaining()).min(self.chunk);
        if length == 0 {
            return Poll::Ready(Ok(()));
        }
        let start = self.position;
        output.put_slice(
            self.input
                .get(start..start + length)
                .expect("replay window must exist"),
        );
        self.position += length;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for CountingTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn sealed_records(records: &mut Tls13RecordLayer, plaintexts: &[&[u8]]) -> Vec<u8> {
    let mut stream = Vec::new();
    for plaintext in plaintexts {
        let mut record = Vec::new();
        records
            .seal_into(ContentType::ApplicationData, plaintext, 0, &mut record)
            .expect("record must seal");
        stream.extend_from_slice(&record);
    }
    stream
}

#[tokio::test(flavor = "current_thread")]
async fn two_records_in_one_burst_cost_one_socket_read() {
    let (established, mut client_write) = buffered_reader_states();
    let stream = sealed_records(&mut client_write, &[b"first", b"second"]);
    let reads = Arc::new(AtomicUsize::new(0));
    let transport = CountingTransport {
        input: stream,
        position: 0,
        chunk: usize::MAX,
        reads: reads.clone(),
    };
    let application = TlsApplicationIo::new(transport, established);
    let (mut reader, _writer) = application.into_split();

    {
        let first = reader
            .read_application(TIMEOUT)
            .await
            .expect("first record must authenticate");
        assert_eq!(first.plaintext(), b"first");
        assert_eq!(reads.load(Ordering::Relaxed), 1);
    }

    let second = reader
        .read_application(TIMEOUT)
        .await
        .expect("second record must come from the buffer");
    assert_eq!(second.plaintext(), b"second");
    assert_eq!(
        reads.load(Ordering::Relaxed),
        1,
        "the buffered second record must not touch the socket"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn has_buffered_record_peeks_complete_records_only() {
    let (established, mut client_write) = buffered_reader_states();
    let stream = sealed_records(&mut client_write, &[b"first", b"second"]);
    // Keep the complete first record plus a partial second record: the
    // peek must not mistake the partial tail for a buffered record.
    let first_wire_len = 5 + b"first".len() + 1 + 16;
    let transport = CountingTransport {
        input: stream[..first_wire_len + 7].to_vec(),
        position: 0,
        chunk: usize::MAX,
        reads: Arc::new(AtomicUsize::new(0)),
    };
    let application = TlsApplicationIo::new(transport, established);
    let (mut reader, _writer) = application.into_split();

    assert!(
        !reader.has_buffered_record(),
        "an empty socket buffer holds no record"
    );
    {
        let first = reader
            .read_application(TIMEOUT)
            .await
            .expect("first record must authenticate");
        assert_eq!(first.plaintext(), b"first");
    }
    assert!(
        !reader.has_buffered_record(),
        "a partial record tail is not a complete buffered record"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn fragmented_record_is_reassembled_across_refills() {
    let (established, mut client_write) = buffered_reader_states();
    let stream = sealed_records(&mut client_write, &[b"fragmented plaintext"]);
    let reads = Arc::new(AtomicUsize::new(0));
    let transport = CountingTransport {
        input: stream,
        position: 0,
        chunk: 7,
        reads: reads.clone(),
    };
    let application = TlsApplicationIo::new(transport, established);
    let (mut reader, _writer) = application.into_split();

    let record = reader
        .read_application(TIMEOUT)
        .await
        .expect("fragmented record must authenticate");
    assert_eq!(record.plaintext(), b"fragmented plaintext");
    assert!(
        reads.load(Ordering::Relaxed) > 1,
        "a fragmented record must span multiple refills"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn clean_eof_at_a_record_boundary_keeps_the_exact_error_shape() {
    let (established, mut client_write) = buffered_reader_states();
    let stream = sealed_records(&mut client_write, &[b"only record"]);
    let transport = CountingTransport {
        input: stream,
        position: 0,
        chunk: usize::MAX,
        reads: Arc::new(AtomicUsize::new(0)),
    };
    let application = TlsApplicationIo::new(transport, established);
    let (mut reader, _writer) = application.into_split();

    {
        let record = reader
            .read_application(TIMEOUT)
            .await
            .expect("record must authenticate");
        assert_eq!(record.plaintext(), b"only record");
    }

    let error = reader
        .read_application(TIMEOUT)
        .await
        .expect_err("EOF at the boundary must fail the next read");
    let TlsApplicationIoError::Read(read) = error else {
        panic!("boundary EOF must surface as a record read error");
    };
    assert!(matches!(read.kind(), TlsRecordReadErrorKind::UnexpectedEof));
    assert_eq!(read.wire_prefix(), b"");
}

#[tokio::test(flavor = "current_thread")]
async fn eof_mid_record_reports_exactly_the_buffered_partial_bytes() {
    let (established, mut client_write) = buffered_reader_states();
    let stream = sealed_records(&mut client_write, &[b"truncated record body"]);
    let partial = stream[..stream.len() / 2].to_vec();
    let transport = CountingTransport {
        input: partial.clone(),
        position: 0,
        chunk: usize::MAX,
        reads: Arc::new(AtomicUsize::new(0)),
    };
    let application = TlsApplicationIo::new(transport, established);
    let (mut reader, _writer) = application.into_split();

    let error = reader
        .read_application(TIMEOUT)
        .await
        .expect_err("a truncated record must fail");
    let TlsApplicationIoError::Read(read) = error else {
        panic!("mid-record EOF must surface as a record read error");
    };
    assert!(matches!(read.kind(), TlsRecordReadErrorKind::UnexpectedEof));
    assert_eq!(read.wire_prefix(), partial.as_slice());
}

#[tokio::test(flavor = "current_thread")]
async fn alert_is_read_out_of_a_multi_record_burst() {
    let (established, mut client_write) = buffered_reader_states();
    let mut stream = Vec::new();
    client_write
        .seal_into(ContentType::Alert, &[2, 40], 0, &mut stream)
        .expect("alert must seal");
    stream.extend_from_slice(&sealed_records(&mut client_write, &[b"after alert"]));
    let transport = CountingTransport {
        input: stream,
        position: 0,
        chunk: usize::MAX,
        reads: Arc::new(AtomicUsize::new(0)),
    };
    let application = TlsApplicationIo::new(transport, established);
    let (mut reader, _writer) = application.into_split();

    assert!(matches!(
        reader.read_application(TIMEOUT).await,
        Err(TlsApplicationIoError::PeerAlert {
            level: 2,
            description: 40
        })
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn pending_drain_returns_exactly_the_pipelined_raw_bytes() {
    let (established, mut client_write) = buffered_reader_states();
    let mut stream = sealed_records(&mut client_write, &[b"boundary record"]);
    stream.extend_from_slice(b"raw-after-boundary");
    let transport = CountingTransport {
        input: stream,
        position: 0,
        chunk: usize::MAX,
        reads: Arc::new(AtomicUsize::new(0)),
    };
    let application = TlsApplicationIo::new(transport, established);
    let (mut reader, _writer) = application.into_split();

    {
        let record = reader
            .read_application(TIMEOUT)
            .await
            .expect("boundary record must authenticate");
        assert_eq!(record.plaintext(), b"boundary record");
    }

    let (pending, _transport) = reader.into_inner_with_pending();
    assert_eq!(pending, b"raw-after-boundary");
}

#[tokio::test(flavor = "current_thread")]
async fn oversized_declared_length_fails_with_the_five_byte_header() {
    let (established, _client_write) = buffered_reader_states();
    let header = [23, 3, 3, 0xff, 0xff];
    let transport = CountingTransport {
        input: header.to_vec(),
        position: 0,
        chunk: usize::MAX,
        reads: Arc::new(AtomicUsize::new(0)),
    };
    let application = TlsApplicationIo::new(transport, established);
    let (mut reader, _writer) = application.into_split();

    let error = reader
        .read_application(TIMEOUT)
        .await
        .expect_err("an oversized declared length must fail at its header");
    let TlsApplicationIoError::Read(read) = error else {
        panic!("an invalid length must surface as a record read error");
    };
    assert!(matches!(
        read.kind(),
        TlsRecordReadErrorKind::RecordTooLarge
    ));
    assert_eq!(read.wire_prefix(), header);
}

/// Server-side TLS state plus the client layer that opens server records.
fn batched_writer_states() -> (EstablishedTls, Tls13RecordLayer) {
    let (established, _client_write, client_read) = key_update_states();
    (established, client_read)
}

/// Opens every record on the wire and returns the plaintexts in order.
fn open_wire_records(records: &mut Tls13RecordLayer, wire: &[u8]) -> Vec<Vec<u8>> {
    let mut plaintexts = Vec::new();
    let mut rest = wire;
    while !rest.is_empty() {
        let body_len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
        let record_len = 5 + body_len;
        let mut record = rest
            .get(..record_len)
            .expect("wire bytes must hold a whole record")
            .to_vec();
        let opened = records
            .open_in_place(&mut record)
            .expect("record must authenticate");
        assert_eq!(opened.content_type(), ContentType::ApplicationData);
        plaintexts.push(opened.plaintext().to_vec());
        rest = &rest[record_len..];
    }
    plaintexts
}

fn split_wire_records(wire: &[u8]) -> Vec<Vec<u8>> {
    let mut records = Vec::new();
    let mut rest = wire;
    while !rest.is_empty() {
        let body_len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
        let record_len = 5 + body_len;
        records.push(
            rest.get(..record_len)
                .expect("wire bytes must hold a whole record")
                .to_vec(),
        );
        rest = &rest[record_len..];
    }
    records
}
/// A deterministic byte pattern that differs between test inputs.
fn patterned(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| seed.wrapping_add((index % 251) as u8))
        .collect()
}

/// A destination replaying input through bounded reads, counting read calls.
struct ReplaySource {
    input: Vec<u8>,
    position: usize,
    chunk: usize,
    reads: usize,
}

impl ReplaySource {
    fn new(input: Vec<u8>, chunk: usize) -> Self {
        Self {
            input,
            position: 0,
            chunk,
            reads: 0,
        }
    }
}

impl AsyncRead for ReplaySource {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.reads += 1;
        let available = self.input.len().saturating_sub(self.position);
        let length = available.min(output.remaining()).min(self.chunk);
        output.put_slice(
            self.input
                .get(self.position..self.position + length)
                .expect("replay window must exist"),
        );
        self.position += length;
        Poll::Ready(Ok(()))
    }
}

impl VectoredRead for ReplaySource {
    /// Fills the buffers in order, bounded by one chunk like a socket read.
    async fn read_vectored<'buf>(
        &'buf mut self,
        buffers: &'buf mut [io::IoSliceMut<'buf>],
    ) -> io::Result<usize> {
        self.reads += 1;
        let mut budget = self.chunk;
        let mut total = 0;
        for buffer in buffers.iter_mut() {
            let available = self.input.len().saturating_sub(self.position);
            let length = available.min(buffer.len()).min(budget);
            if length > 0 {
                buffer[..length].copy_from_slice(
                    self.input
                        .get(self.position..self.position + length)
                        .expect("replay window must exist"),
                );
                self.position += length;
                budget -= length;
                total += length;
            }
            if length < buffer.len() {
                break;
            }
        }
        Ok(total)
    }
}

/// A client-side sink capturing wire bytes and counting write calls.
#[derive(Clone, Default)]
struct RecordingSink {
    output: Arc<Mutex<Vec<u8>>>,
    writes: Arc<AtomicUsize>,
    request_after_first_write: Arc<Mutex<Option<Arc<KeyUpdateCoordination>>>>,
}

impl RecordingSink {
    fn wire(&self) -> std::sync::MutexGuard<'_, Vec<u8>> {
        self.output
            .lock()
            .expect("sink output must not be poisoned")
    }

    fn writes(&self) -> usize {
        self.writes.load(Ordering::Relaxed)
    }

    fn request_key_update_after_first_write(&self, coordination: Arc<KeyUpdateCoordination>) {
        *self
            .request_after_first_write
            .lock()
            .expect("request trigger must not be poisoned") = Some(coordination);
    }
}

impl AsyncRead for RecordingSink {
    fn poll_read(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for RecordingSink {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let write_index = self.writes.fetch_add(1, Ordering::Relaxed);
        self.output
            .lock()
            .expect("sink output must not be poisoned")
            .extend_from_slice(buffer);
        if write_index == 0
            && let Some(coordination) = self
                .request_after_first_write
                .lock()
                .expect("request trigger must not be poisoned")
                .take()
        {
            coordination
                .response_observed
                .store(true, Ordering::Release);
        }
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Clone)]
struct BlockingSink {
    output: Arc<Mutex<Vec<u8>>>,
    entered: Arc<AtomicBool>,
    released: Arc<AtomicBool>,
    waker: Arc<AtomicWaker>,
}

impl BlockingSink {
    fn new() -> Self {
        Self {
            output: Arc::new(Mutex::new(Vec::new())),
            entered: Arc::new(AtomicBool::new(false)),
            released: Arc::new(AtomicBool::new(false)),
            waker: Arc::new(AtomicWaker::new()),
        }
    }

    fn release(&self) {
        self.released.store(true, Ordering::Release);
        self.waker.wake();
    }

    fn wire(&self) -> std::sync::MutexGuard<'_, Vec<u8>> {
        self.output
            .lock()
            .expect("blocking sink output must not be poisoned")
    }
}

impl AsyncWrite for BlockingSink {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.entered.store(true, Ordering::Release);
        if !self.released.load(Ordering::Acquire) {
            self.waker.register(context.waker());
            if !self.released.load(Ordering::Acquire) {
                return Poll::Pending;
            }
        }
        self.output
            .lock()
            .expect("blocking sink output must not be poisoned")
            .extend_from_slice(buffer);
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Clone, Copy)]
enum InterruptedWrite {
    Pending,
    Error,
    Complete,
}

#[derive(Clone)]
struct PartialWriteSink {
    state: Arc<Mutex<(Vec<u8>, usize, InterruptedWrite)>>,
}

impl PartialWriteSink {
    fn new(prefix: usize, outcome: InterruptedWrite) -> Self {
        Self {
            state: Arc::new(Mutex::new((Vec::new(), prefix, outcome))),
        }
    }

    fn complete(&self) {
        self.state.lock().expect("sink state").2 = InterruptedWrite::Complete;
    }

    fn wire(&self) -> Vec<u8> {
        self.state.lock().expect("sink state").0.clone()
    }
}

impl AsyncWrite for PartialWriteSink {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut state = self.state.lock().expect("sink state");
        let length = buffer.len().min(state.1);
        if length > 0 {
            state.0.extend_from_slice(&buffer[..length]);
            state.1 -= length;
            return Poll::Ready(Ok(length));
        }
        match state.2 {
            InterruptedWrite::Pending => Poll::Pending,
            InterruptedWrite::Error => Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe))),
            InterruptedWrite::Complete => {
                state.0.extend_from_slice(buffer);
                Poll::Ready(Ok(buffer.len()))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_partial_key_update_rejects_retry() {
    let (established, _client_write, _client_read) = key_update_states();
    let sink = PartialWriteSink::new(7, InterruptedWrite::Pending);
    let (_reader, mut writer) = resume_application_halves(
        tokio::io::empty(),
        Vec::new(),
        sink.clone(),
        established,
        true,
    );
    let mut write = Box::pin(writer.write_application(b"reply", TIMEOUT));
    poll_fn(|context| {
        assert!(write.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(write);
    let partial = sink.wire();
    assert_eq!(
        partial.len(),
        7,
        "the peer received an incomplete KeyUpdate"
    );
    sink.complete();
    assert!(
        writer.write_application(b"retry", TIMEOUT).await.is_err(),
        "a canceled sealed record must permanently close the TLS write direction"
    );
    assert_eq!(sink.wire(), partial, "retry must not emit more ciphertext");
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_partial_key_update_rejects_handoff_export() {
    let (established, _client_write, _client_read) = key_update_states();
    let sink = PartialWriteSink::new(7, InterruptedWrite::Pending);
    let (_reader, mut writer) =
        resume_application_halves(tokio::io::empty(), Vec::new(), sink, established, true);
    let mut write = Box::pin(writer.write_application(b"reply", TIMEOUT));
    poll_fn(|context| {
        assert!(write.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(write);
    let (_transport, records, _pending) = writer.into_handoff_parts();
    assert!(
        records.into_exported_state().is_err(),
        "ambiguous ciphertext must not be represented as a valid Handoff boundary"
    );
}

#[derive(Clone, Copy, Debug)]
enum WritePath {
    Copied,
    Assembled,
    FilledStorage,
    ReadFrom,
    Batched,
    Shutdown,
}

const WRITE_PATHS: [WritePath; 6] = [
    WritePath::Copied,
    WritePath::Assembled,
    WritePath::FilledStorage,
    WritePath::ReadFrom,
    WritePath::Batched,
    WritePath::Shutdown,
];

async fn write_path(
    writer: &mut super::TlsApplicationWriter<PartialWriteSink>,
    path: WritePath,
) -> Result<(), TlsApplicationIoError> {
    match path {
        WritePath::Copied => writer
            .write_application(b"reply", TIMEOUT)
            .await
            .map(|_| ()),
        WritePath::Assembled => {
            writer
                .write_assembled(5, |region| region.copy_from_slice(b"reply"), TIMEOUT)
                .await
        }
        WritePath::FilledStorage => {
            let mut storage = writer.take_write_storage();
            storage.resize(2 * RECORD_SLOT_WIRE_CAPACITY, 0x6a);
            for slot in storage.as_chunks_mut::<RECORD_SLOT_WIRE_CAPACITY>().0 {
                slot[TLS_RECORD_HEADER_LEN..TLS_RECORD_HEADER_LEN + MAX_PLAINTEXT_LEN].fill(0x6a);
            }
            writer
                .write_filled_storage(&mut storage, 2 * MAX_PLAINTEXT_LEN, TIMEOUT)
                .await
        }
        WritePath::ReadFrom => {
            let mut source = ReplaySource::new(b"reply".to_vec(), usize::MAX);
            writer
                .write_application_read_from(&mut source, TIMEOUT)
                .await
                .map(|_| ())
        }
        WritePath::Batched => {
            let mut source = ReplaySource::new(vec![0x6a; 2 * MAX_PLAINTEXT_LEN], usize::MAX);
            writer
                .write_application_read_from_batched(&mut source, TIMEOUT)
                .await
                .map(|_| ())
        }
        WritePath::Shutdown => writer.shutdown(TIMEOUT).await,
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn interrupted_records_reject_every_write_path_and_export() {
    // Cover incomplete application records, incomplete KeyUpdates, and
    // complete KeyUpdates followed by an incomplete next-generation record.
    for trigger in 0..3 {
        let prefixes: &[usize] = if trigger != 0 {
            &[0, 7, super::KEY_UPDATE_RECORD_WIRE_LEN + 7]
        } else {
            &[0, 7]
        };
        for &prefix in prefixes {
            for path in WRITE_PATHS {
                for interruption in 0..3 {
                    let (mut established, _client_write, _client_read) = key_update_states();
                    if trigger == 2 {
                        established.server_records_mut().set_test_key_usage_limit(2);
                    }
                    let outcome = if interruption == 1 {
                        InterruptedWrite::Error
                    } else {
                        InterruptedWrite::Pending
                    };
                    let sink = PartialWriteSink::new(0, InterruptedWrite::Complete);
                    let (_reader, mut writer) = resume_application_halves(
                        tokio::io::empty(),
                        Vec::new(),
                        sink.clone(),
                        established,
                        trigger == 1,
                    );
                    if trigger == 2 {
                        writer
                            .write_application(b"warmup", TIMEOUT)
                            .await
                            .expect("warmup");
                    }
                    *sink.state.lock().expect("sink state") = (Vec::new(), prefix, outcome);
                    grow_batched_record_storage(&mut writer.write_record).expect("batch storage");
                    let mut write = Box::pin(write_path(&mut writer, path));
                    if interruption == 1 {
                        assert!(matches!(
                            write.as_mut().await,
                            Err(TlsApplicationIoError::Io(_))
                        ));
                    } else {
                        poll_fn(|context| {
                            assert!(write.as_mut().poll(context).is_pending());
                            Poll::Ready(())
                        })
                        .await;
                        if interruption == 2 {
                            tokio::time::advance(TIMEOUT).await;
                            assert!(matches!(
                                write.as_mut().await,
                                Err(TlsApplicationIoError::Timeout)
                            ));
                        }
                    }
                    drop(write);
                    let partial = sink.wire();
                    assert_eq!(partial.len(), prefix, "{path:?}");
                    sink.complete();
                    for retry in WRITE_PATHS {
                        assert!(
                            write_path(&mut writer, retry).await.is_err(),
                            "{path:?} interruption must reject {retry:?} retry"
                        );
                    }
                    assert!(
                        writer.write_application(b"", TIMEOUT).await.is_err(),
                        "empty writes must not hide a failed direction"
                    );
                    assert_eq!(sink.wire(), partial, "failed retries must write nothing");
                    let (_transport, records, _pending) = writer.into_handoff_parts();
                    assert!(records.into_exported_state().is_err(), "{path:?}");
                }
            }
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn complete_partial_writes_decrypt_for_every_update_write_path() {
    for proactive in [false, true] {
        for path in WRITE_PATHS {
            let (mut established, _client_write, mut client_read) = key_update_states();
            if proactive {
                established.server_records_mut().set_test_key_usage_limit(2);
            }
            let sink = PartialWriteSink::new(0, InterruptedWrite::Complete);
            let (_reader, mut writer) = resume_application_halves(
                tokio::io::empty(),
                Vec::new(),
                sink.clone(),
                established,
                !proactive,
            );
            if proactive {
                writer
                    .write_application(b"warmup", TIMEOUT)
                    .await
                    .expect("warmup");
                let mut warmup = sink.wire();
                let opened = client_read
                    .open_in_place(&mut warmup)
                    .expect("warmup decrypts");
                assert_eq!(opened.plaintext(), b"warmup");
            }
            *sink.state.lock().expect("sink state") = (Vec::new(), 7, InterruptedWrite::Complete);
            grow_batched_record_storage(&mut writer.write_record).expect("batch storage");
            write_path(&mut writer, path)
                .await
                .expect("complete partial writes");
            let wire = sink.wire();
            let records = split_wire_records(&wire);
            let mut application = Vec::new();
            let mut updates = 0;
            for mut record in records {
                let opened = client_read
                    .open_in_place(&mut record)
                    .expect("peer decrypts");
                match opened.content_type() {
                    ContentType::Handshake => {
                        assert_eq!(opened.plaintext(), KEY_UPDATE_RESPONSE);
                        updates += 1;
                        client_read
                            .update_traffic_secret()
                            .expect("peer updates key");
                    }
                    ContentType::ApplicationData => {
                        application.extend_from_slice(opened.plaintext());
                    }
                    ContentType::Alert => {
                        assert!(matches!(path, WritePath::Shutdown));
                        assert_eq!(opened.plaintext(), &[1, 0]);
                    }
                    content_type => panic!("unexpected content type {content_type:?}"),
                }
            }
            assert!(updates > 0, "{path:?} must send an update");
            match path {
                WritePath::Batched | WritePath::FilledStorage => {
                    assert_eq!(application, vec![0x6a; 2 * MAX_PLAINTEXT_LEN])
                }
                WritePath::Shutdown => assert!(application.is_empty()),
                _ => assert_eq!(application, b"reply"),
            }
            let (_transport, records, pending) = writer.into_handoff_parts();
            assert!(!pending);
            assert!(records.into_exported_state().is_ok(), "{path:?}");
        }
    }
}

impl AsyncRead for PartialWriteSink {
    fn poll_read(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn interrupted_unsplit_writes_remain_invalid_after_split() {
    for trigger in 0..3 {
        for shutdown in [false, true] {
            for interruption in 0..3 {
                let (mut established, _client_write, _client_read) = key_update_states();
                if trigger == 2 {
                    established.server_records_mut().set_test_key_usage_limit(2);
                }
                let sink = PartialWriteSink::new(0, InterruptedWrite::Complete);
                let mut application = TlsApplicationIo::new(sink.clone(), established);
                if trigger == 2 {
                    application
                        .write_application(b"warmup", TIMEOUT)
                        .await
                        .expect("warmup");
                }
                application
                    .key_update_coordination
                    .response_pending
                    .store(trigger == 1, Ordering::Release);
                let outcome = if interruption == 1 {
                    InterruptedWrite::Error
                } else {
                    InterruptedWrite::Pending
                };
                *sink.state.lock().expect("sink state") = (Vec::new(), 7, outcome);
                let mut write = Box::pin(async {
                    if shutdown {
                        application.shutdown(TIMEOUT).await
                    } else {
                        application
                            .write_application(b"reply", TIMEOUT)
                            .await
                            .map(|_| ())
                    }
                });
                if interruption == 1 {
                    assert!(matches!(
                        write.as_mut().await,
                        Err(TlsApplicationIoError::Io(_))
                    ));
                } else {
                    poll_fn(|context| {
                        assert!(write.as_mut().poll(context).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                    if interruption == 2 {
                        tokio::time::advance(TIMEOUT).await;
                        assert!(matches!(
                            write.as_mut().await,
                            Err(TlsApplicationIoError::Timeout)
                        ));
                    }
                }
                drop(write);
                let partial = sink.wire();
                assert_eq!(partial.len(), 7);
                sink.complete();
                assert!(
                    application
                        .write_application(b"retry", TIMEOUT)
                        .await
                        .is_err()
                );
                assert!(application.shutdown(TIMEOUT).await.is_err());
                let (_reader, mut writer) = application.into_split();
                assert!(
                    writer
                        .write_application(b"after split", TIMEOUT)
                        .await
                        .is_err()
                );
                let (_transport, records, _pending) = writer.into_handoff_parts();
                assert!(records.into_exported_state().is_err());
                assert_eq!(sink.wire(), partial);
            }
        }
    }
}

struct InterruptedShutdownSink {
    inner: PartialWriteSink,
    outcome: InterruptedWrite,
}

impl AsyncWrite for InterruptedShutdownSink {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.outcome {
            InterruptedWrite::Pending => Poll::Pending,
            InterruptedWrite::Error => Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe))),
            InterruptedWrite::Complete => Poll::Ready(Ok(())),
        }
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn interrupted_transport_shutdown_rejects_retry_and_export() {
    for interruption in 0..3 {
        let (established, _client_write, mut client_read) = key_update_states();
        let sink = PartialWriteSink::new(7, InterruptedWrite::Complete);
        let transport = InterruptedShutdownSink {
            inner: sink.clone(),
            outcome: if interruption == 1 {
                InterruptedWrite::Error
            } else {
                InterruptedWrite::Pending
            },
        };
        let (_reader, mut writer) =
            resume_application_halves(tokio::io::empty(), Vec::new(), transport, established, true);
        let mut shutdown = Box::pin(writer.shutdown(TIMEOUT));
        if interruption == 1 {
            assert!(matches!(
                shutdown.as_mut().await,
                Err(TlsApplicationIoError::Io(_))
            ));
        } else {
            poll_fn(|context| {
                assert!(shutdown.as_mut().poll(context).is_pending());
                Poll::Ready(())
            })
            .await;
            if interruption == 2 {
                tokio::time::advance(TIMEOUT).await;
                assert!(matches!(
                    shutdown.as_mut().await,
                    Err(TlsApplicationIoError::Timeout)
                ));
            }
        }
        drop(shutdown);
        let wire = sink.wire();
        let mut records = split_wire_records(&wire);
        assert_eq!(records.len(), 2);
        let update = client_read
            .open_in_place(&mut records[0])
            .expect("update decrypts");
        assert_eq!(update.plaintext(), KEY_UPDATE_RESPONSE);
        client_read.update_traffic_secret().expect("peer updates");
        let alert = client_read
            .open_in_place(&mut records[1])
            .expect("alert decrypts");
        assert_eq!(alert.content_type(), ContentType::Alert);
        assert_eq!(alert.plaintext(), &[1, 0]);
        assert!(writer.write_application(b"retry", TIMEOUT).await.is_err());
        assert!(writer.shutdown(TIMEOUT).await.is_err());
        assert_eq!(sink.wire(), wire);
        let (_transport, records, _pending) = writer.into_handoff_parts();
        assert!(records.into_exported_state().is_err());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn cancellation_before_plaintext_is_sealed_keeps_writer_usable() {
    let (established, _client_write, mut client_read) = key_update_states();
    let sink = PartialWriteSink::new(7, InterruptedWrite::Complete);
    let (_reader, mut writer) = resume_application_halves(
        tokio::io::empty(),
        Vec::new(),
        sink.clone(),
        established,
        false,
    );
    let (_source_peer, mut source) = duplex(128);
    let mut read = Box::pin(writer.write_application_read_from(&mut source, TIMEOUT));
    poll_fn(|context| {
        assert!(read.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(read);
    writer
        .write_application(b"reply", TIMEOUT)
        .await
        .expect("safe retry");
    let mut wire = sink.wire();
    let opened = client_read.open_in_place(&mut wire).expect("peer decrypts");
    assert_eq!(opened.plaintext(), b"reply");
    let (_transport, records, _pending) = writer.into_handoff_parts();
    assert!(records.into_exported_state().is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn pre_seal_failures_preserve_pending_update_and_valid_sequence() {
    let (established, _client_write, mut client_read) = key_update_states();
    let sink = PartialWriteSink::new(7, InterruptedWrite::Complete);
    let (_reader, mut writer) = resume_application_halves(
        tokio::io::empty(),
        Vec::new(),
        sink.clone(),
        established,
        true,
    );
    assert!(matches!(
        writer.write_application(b"reply", Duration::MAX).await,
        Err(TlsApplicationIoError::Timeout)
    ));
    assert!(sink.wire().is_empty());
    assert!(matches!(
        writer
            .write_assembled(
                MAX_PLAINTEXT_LEN + 1,
                |_| panic!("must not assemble"),
                TIMEOUT
            )
            .await,
        Err(TlsApplicationIoError::Record(
            Tls13RecordError::InvalidLength
        ))
    ));
    writer
        .write_application(b"reply", TIMEOUT)
        .await
        .expect("safe retry");
    let mut records = split_wire_records(&sink.wire());
    assert_eq!(records.len(), 2);
    let update = client_read
        .open_in_place(&mut records[0])
        .expect("pending update decrypts");
    assert_eq!(update.plaintext(), KEY_UPDATE_RESPONSE);
    client_read.update_traffic_secret().expect("peer updates");
    let application = client_read
        .open_in_place(&mut records[1])
        .expect("retry decrypts");
    assert_eq!(application.plaintext(), b"reply");
    let (_transport, records, pending) = writer.into_handoff_parts();
    assert!(!pending);
    assert!(records.into_exported_state().is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn traffic_rotation_failure_after_delivered_update_invalidates_writer() {
    let (mut established, _client_write, mut client_read) = key_update_states();
    let suite = CipherSuite::Aes128GcmSha256;
    let schedule = schedule(suite);
    let secrets = schedule
        .application_traffic_secrets(&suite.hash().digest(b"server finished transcript"))
        .expect("application secrets");
    let keys = schedule
        .traffic_keys(secrets.server())
        .expect("application keys");
    // Derived-key-only layers cannot rotate. Exercise the real error after
    // delivery without altering the peer's old-generation decryption keys.
    *established.server_records_mut() = Tls13RecordLayer::new(suite, keys).expect("old key");
    let sink = PartialWriteSink::new(7, InterruptedWrite::Complete);
    let (_reader, mut writer) = resume_application_halves(
        tokio::io::empty(),
        Vec::new(),
        sink.clone(),
        established,
        true,
    );
    assert!(matches!(
        writer.write_application(b"reply", TIMEOUT).await,
        Err(TlsApplicationIoError::Record(
            Tls13RecordError::KeyUpdateUnavailable
        ))
    ));
    let ciphertext = sink.wire();
    let mut wire = ciphertext.clone();
    let update = client_read
        .open_in_place(&mut wire)
        .expect("delivered update decrypts");
    assert_eq!(update.plaintext(), KEY_UPDATE_RESPONSE);
    assert!(matches!(
        writer.write_application(b"retry", TIMEOUT).await,
        Err(TlsApplicationIoError::Record(Tls13RecordError::WriteFailed))
    ));
    assert_eq!(sink.wire(), ciphertext);
    let (_transport, records, _pending) = writer.into_handoff_parts();
    assert!(matches!(
        records.into_exported_state(),
        Err(Tls13RecordError::WriteFailed)
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn requested_update_does_not_block_reader_behind_an_in_flight_record() {
    let (established, mut client_write, mut client_read) = key_update_states();
    let request = [24, 0, 0, 1, KEY_UPDATE_REQUESTED];
    let mut input = seal(&mut client_write, ContentType::Handshake, &request);
    client_write
        .update_traffic_secret()
        .expect("client write secret must update");
    input.extend_from_slice(&seal(
        &mut client_write,
        ContentType::ApplicationData,
        b"request body",
    ));
    let source = CountingTransport {
        input,
        position: 0,
        chunk: usize::MAX,
        reads: Arc::new(AtomicUsize::new(0)),
    };
    let sink = BlockingSink::new();
    let (mut reader, mut writer) =
        resume_application_halves(source, Vec::new(), sink.clone(), established, false);
    let coordination = writer.key_update_coordination.clone();

    let mut first_write = Box::pin(writer.write_application(b"first reply", TIMEOUT));
    poll_fn(|context| {
        assert!(first_write.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    assert!(sink.entered.load(Ordering::Acquire));

    let control = reader
        .read_application(TIMEOUT)
        .await
        .expect("requested KeyUpdate must authenticate while output is blocked");
    assert!(control.is_empty());
    assert!(coordination.response_observed.load(Ordering::Acquire));
    assert!(!coordination.response_pending.load(Ordering::Acquire));
    let request_body = reader
        .read_application(TIMEOUT)
        .await
        .expect("buffered application data must remain readable");
    assert_eq!(request_body.plaintext(), b"request body");

    sink.release();
    first_write
        .as_mut()
        .await
        .expect("the in-flight application record must finish");
    drop(first_write);
    writer
        .write_application(b"second reply", TIMEOUT)
        .await
        .expect("the later application record must follow the KeyUpdate response");
    assert!(!coordination.response_observed.load(Ordering::Acquire));
    assert!(!coordination.response_pending.load(Ordering::Acquire));

    let records = {
        let wire = sink.wire();
        split_wire_records(&wire)
    };
    assert_eq!(records.len(), 3);

    let mut first = records[0].clone();
    let opened = client_read
        .open_in_place(&mut first)
        .expect("in-flight application record must use the old key");
    assert_eq!(opened.content_type(), ContentType::ApplicationData);
    assert_eq!(opened.plaintext(), b"first reply");

    let mut update = records[1].clone();
    let opened = client_read
        .open_in_place(&mut update)
        .expect("KeyUpdate must precede the later application record");
    assert_eq!(opened.content_type(), ContentType::Handshake);
    assert_eq!(opened.plaintext(), KEY_UPDATE_RESPONSE);
    client_read
        .update_traffic_secret()
        .expect("client read secret must update");

    let mut second = records[2].clone();
    let opened = client_read
        .open_in_place(&mut second)
        .expect("later application record must use the next key");
    assert_eq!(opened.content_type(), ContentType::ApplicationData);
    assert_eq!(opened.plaintext(), b"second reply");
}

#[tokio::test(flavor = "current_thread")]
async fn multi_record_write_checks_for_a_request_between_chunks() {
    let (established, _client_write, mut client_read) = key_update_states();
    let sink = RecordingSink::default();
    let application = TlsApplicationIo::new(sink.clone(), established);
    let (_reader, mut writer) = application.into_split();
    sink.request_key_update_after_first_write(writer.key_update_coordination.clone());
    let plaintext = patterned(0x42, 2 * MAX_PLAINTEXT_LEN);

    let stats = writer
        .write_application(&plaintext, TIMEOUT)
        .await
        .expect("multi-record write must succeed");
    assert_eq!(stats.records(), 2);
    let records = {
        let wire = sink.wire();
        split_wire_records(&wire)
    };
    assert_eq!(records.len(), 3);

    let mut first = records[0].clone();
    let opened = client_read
        .open_in_place(&mut first)
        .expect("first application record must use the old key");
    assert_eq!(opened.content_type(), ContentType::ApplicationData);
    assert_eq!(opened.plaintext(), &plaintext[..MAX_PLAINTEXT_LEN]);

    let mut response = records[1].clone();
    let opened = client_read
        .open_in_place(&mut response)
        .expect("KeyUpdate response must follow the first chunk");
    assert_eq!(opened.content_type(), ContentType::Handshake);
    assert_eq!(opened.plaintext(), KEY_UPDATE_RESPONSE);
    client_read
        .update_traffic_secret()
        .expect("client read secret must update");

    let mut second = records[2].clone();
    let opened = client_read
        .open_in_place(&mut second)
        .expect("second application record must use the next key");
    assert_eq!(opened.content_type(), ContentType::ApplicationData);
    assert_eq!(opened.plaintext(), &plaintext[MAX_PLAINTEXT_LEN..]);
}

#[tokio::test(flavor = "current_thread")]
async fn batched_write_uses_the_final_old_key_record_for_key_update() {
    const AES_GCM_RECORD_LIMIT: u64 = 1 << 24;

    let suite = CipherSuite::Aes128GcmSha256;
    let schedule = schedule(suite);
    let transcript = suite.hash().digest(b"server finished transcript");
    let (server_client_secret, server_server_secret) = schedule
        .application_traffic_secrets(&transcript)
        .expect("server application secrets must derive")
        .into_parts();
    let (_client_write_secret, client_read_secret) = schedule
        .application_traffic_secrets(&transcript)
        .expect("client application secrets must derive")
        .into_parts();
    let server_client_records = Tls13RecordLayer::from_traffic_secret(suite, server_client_secret)
        .expect("server read records must initialize");
    let server_server_state =
        ExportedRecordState::from_parts(suite, server_server_secret, AES_GCM_RECORD_LIMIT - 2)
            .expect("server boundary state must initialize");
    let server_server_records = Tls13RecordLayer::from_exported_state(server_server_state)
        .expect("server boundary records must initialize");
    let client_read_state =
        ExportedRecordState::from_parts(suite, client_read_secret, AES_GCM_RECORD_LIMIT - 2)
            .expect("client boundary state must initialize");
    let mut client_read = Tls13RecordLayer::from_exported_state(client_read_state)
        .expect("client boundary records must initialize");
    let established =
        EstablishedTls::from_test_records(suite, server_client_records, server_server_records);
    let sink = RecordingSink::default();
    let application = TlsApplicationIo::new(sink.clone(), established);
    let (_reader, mut writer) = application.into_split();
    grow_batched_record_storage(&mut writer.write_record)
        .expect("batched record storage must grow");
    let plaintext = patterned(0x6a, 2 * MAX_PLAINTEXT_LEN);
    let mut source = ReplaySource::new(plaintext.clone(), usize::MAX);

    let read = writer
        .write_application_read_from_batched(&mut source, TIMEOUT)
        .await
        .expect("boundary batch must be written");
    assert_eq!(read, plaintext.len());
    let records = {
        let wire = sink.wire();
        split_wire_records(&wire)
    };
    assert_eq!(records.len(), 3);

    let mut first = records[0].clone();
    let opened = client_read
        .open_in_place(&mut first)
        .expect("first application record must use the penultimate sequence");
    assert_eq!(opened.content_type(), ContentType::ApplicationData);
    assert_eq!(opened.plaintext(), &plaintext[..MAX_PLAINTEXT_LEN]);

    let mut update = records[1].clone();
    let opened = client_read
        .open_in_place(&mut update)
        .expect("KeyUpdate must use the final safe old-key sequence");
    assert_eq!(opened.content_type(), ContentType::Handshake);
    assert_eq!(opened.plaintext(), KEY_UPDATE_RESPONSE);
    client_read
        .update_traffic_secret()
        .expect("client read secret must update");

    let mut second = records[2].clone();
    let opened = client_read
        .open_in_place(&mut second)
        .expect("remaining batch data must use the next key");
    assert_eq!(opened.content_type(), ContentType::ApplicationData);
    assert_eq!(opened.plaintext(), &plaintext[MAX_PLAINTEXT_LEN..]);
}

#[tokio::test(flavor = "current_thread")]
async fn caller_owned_upload_storage_returns_without_retained_duplicate() {
    let (established, mut client_read) = batched_writer_states();
    let sink = RecordingSink::default();
    let (_reader, mut writer) = TlsApplicationIo::new(sink.clone(), established).into_split();
    let mut storage = writer.take_write_storage();
    storage.resize(2 * RECORD_SLOT_WIRE_CAPACITY, 0);
    let address = storage.as_ptr();
    let capacity = storage.capacity();
    let mut expected = Vec::new();
    for length in [
        1,
        MAX_PLAINTEXT_LEN,
        MAX_PLAINTEXT_LEN + 1,
        2 * MAX_PLAINTEXT_LEN,
    ] {
        storage.fill(0x71);
        writer
            .write_filled_storage(&mut storage, length, TIMEOUT)
            .await
            .unwrap();
        assert_eq!(storage.as_ptr(), address);
        assert_eq!(storage.capacity(), capacity);
        assert_eq!(writer.write_record.capacity(), 0);
        expected.extend(std::iter::repeat_n(0x71, length));
    }
    let wire = sink.wire().clone();
    assert_eq!(
        open_wire_records(&mut client_read, &wire).concat(),
        expected
    );
    for length in [0, 2 * MAX_PLAINTEXT_LEN + 1, usize::MAX] {
        assert!(
            writer
                .write_filled_storage(&mut storage, length, TIMEOUT)
                .await
                .is_err()
        );
        assert_eq!(storage.as_ptr(), address);
    }
    assert_eq!(*sink.wire(), wire);
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_caller_storage_second_record_rejects_every_retry() {
    for prefix in [RECORD_SLOT_WIRE_CAPACITY, RECORD_SLOT_WIRE_CAPACITY + 7] {
        let (established, _client_write, _client_read) = key_update_states();
        let sink = PartialWriteSink::new(prefix, InterruptedWrite::Pending);
        let (_reader, mut writer) = resume_application_halves(
            tokio::io::empty(),
            Vec::new(),
            sink.clone(),
            established,
            false,
        );
        let mut write = Box::pin(write_path(&mut writer, WritePath::FilledStorage));
        poll_fn(|context| {
            assert!(write.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(write);
        assert_eq!(sink.wire().len(), prefix);
        sink.complete();
        for retry in WRITE_PATHS {
            assert!(write_path(&mut writer, retry).await.is_err());
        }
        assert_eq!(sink.wire().len(), prefix);
        assert!(writer.into_handoff_parts().1.into_exported_state().is_err());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn batched_downlink_seals_four_full_records_with_one_read_and_one_write() {
    let (established, mut client_read) = batched_writer_states();
    let sink = RecordingSink::default();
    let application = TlsApplicationIo::new(sink.clone(), established);
    let (_reader, mut writer) = application.into_split();

    // Warm-up: one completely-full record read is the bulk-flow evidence
    // that grows the batched buffer.
    let warm = patterned(0x11, MAX_PLAINTEXT_LEN);
    let mut source = ReplaySource::new(warm.clone(), usize::MAX);
    let read = writer
        .write_application_read_from_batched(&mut source, TIMEOUT)
        .await
        .expect("warm-up record must be relayed");
    assert_eq!(read, MAX_PLAINTEXT_LEN);
    assert_eq!(source.reads, 1);
    assert_eq!(sink.writes(), 1);
    assert!(writer.write_record.capacity() >= BATCHED_WIRE_CAPACITY);

    // The next call must move four maximal records with one readv + one write.
    let batch = patterned(0x77, BATCHED_SLOT_COUNT * MAX_PLAINTEXT_LEN);
    let mut source = ReplaySource::new(batch.clone(), usize::MAX);
    let read = writer
        .write_application_read_from_batched(&mut source, TIMEOUT)
        .await
        .expect("batch must be relayed");
    assert_eq!(read, BATCHED_SLOT_COUNT * MAX_PLAINTEXT_LEN);
    assert_eq!(source.reads, 1, "one readv must fill the whole batch");
    assert_eq!(sink.writes(), 2, "the batch must add exactly one write");
    assert_eq!(
        writer.records.records_used(),
        1 + BATCHED_SLOT_COUNT as u64,
        "the sequence must advance once per sealed record"
    );

    let plaintexts = {
        let wire = sink.wire();
        open_wire_records(&mut client_read, &wire)
    };
    assert_eq!(plaintexts.len(), 1 + BATCHED_SLOT_COUNT);
    assert_eq!(plaintexts[0], warm);
    for record in &plaintexts[1..] {
        assert_eq!(record.len(), MAX_PLAINTEXT_LEN);
    }
    assert_eq!(plaintexts[1..].concat(), batch);
}

#[tokio::test(flavor = "current_thread")]
async fn batched_downlink_seals_a_partial_last_record() {
    let (established, mut client_read) = batched_writer_states();
    let sink = RecordingSink::default();
    let application = TlsApplicationIo::new(sink.clone(), established);
    let (_reader, mut writer) = application.into_split();

    let warm = patterned(0x22, MAX_PLAINTEXT_LEN);
    let mut source = ReplaySource::new(warm, usize::MAX);
    writer
        .write_application_read_from_batched(&mut source, TIMEOUT)
        .await
        .expect("warm-up record must be relayed");

    let batch = patterned(0x55, 2 * MAX_PLAINTEXT_LEN + 100);
    let mut source = ReplaySource::new(batch.clone(), usize::MAX);
    let read = writer
        .write_application_read_from_batched(&mut source, TIMEOUT)
        .await
        .expect("batch must be relayed");
    assert_eq!(read, 2 * MAX_PLAINTEXT_LEN + 100);
    assert_eq!(source.reads, 1);
    assert_eq!(sink.writes(), 2);

    let plaintexts = {
        let wire = sink.wire();
        open_wire_records(&mut client_read, &wire)
    };
    assert_eq!(plaintexts.len(), 4);
    assert_eq!(plaintexts[1].len(), MAX_PLAINTEXT_LEN);
    assert_eq!(plaintexts[2].len(), MAX_PLAINTEXT_LEN);
    assert_eq!(plaintexts[3].len(), 100);
    assert_eq!(plaintexts[1..].concat(), batch);
}

#[tokio::test(flavor = "current_thread")]
async fn short_read_seals_a_one_byte_record_without_growing() {
    let (established, mut client_read) = batched_writer_states();
    let sink = RecordingSink::default();
    let application = TlsApplicationIo::new(sink.clone(), established);
    let (_reader, mut writer) = application.into_split();

    let mut source = ReplaySource::new(vec![0x7e], usize::MAX);
    let read = writer
        .write_application_read_from_batched(&mut source, TIMEOUT)
        .await
        .expect("short read must be relayed");
    assert_eq!(read, 1);
    assert_eq!(sink.writes(), 1);
    assert_eq!(
        writer.write_record.capacity(),
        RECORD_SLOT_WIRE_CAPACITY,
        "a short read must not grow the batched buffer"
    );

    let plaintexts = {
        let wire = sink.wire();
        open_wire_records(&mut client_read, &wire)
    };
    assert_eq!(plaintexts, [vec![0x7e]]);
}

#[tokio::test(flavor = "current_thread")]
async fn eof_before_any_byte_writes_nothing() {
    let (established, _client_read) = batched_writer_states();
    let sink = RecordingSink::default();
    let application = TlsApplicationIo::new(sink.clone(), established);
    let (_reader, mut writer) = application.into_split();

    let mut source = ReplaySource::new(Vec::new(), usize::MAX);
    let read = writer
        .write_application_read_from_batched(&mut source, TIMEOUT)
        .await
        .expect("EOF must be a clean zero");
    assert_eq!(read, 0);
    assert_eq!(sink.writes(), 0, "EOF must not write a record");
    assert!(sink.wire().is_empty());
    assert_eq!(writer.records.records_used(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn eof_after_a_full_record_flushes_then_reports_eof() {
    let (established, mut client_read) = batched_writer_states();
    let sink = RecordingSink::default();
    let application = TlsApplicationIo::new(sink.clone(), established);
    let (_reader, mut writer) = application.into_split();

    let input = patterned(0x99, MAX_PLAINTEXT_LEN + 500);
    let mut source = ReplaySource::new(input.clone(), usize::MAX);

    let read = writer
        .write_application_read_from_batched(&mut source, TIMEOUT)
        .await
        .expect("full record must be relayed");
    assert_eq!(read, MAX_PLAINTEXT_LEN);

    // The batched read now sees the 500-byte tail ahead of the EOF and
    // must seal and write it like today's variable-length path.
    let read = writer
        .write_application_read_from_batched(&mut source, TIMEOUT)
        .await
        .expect("the partial tail must be relayed");
    assert_eq!(read, 500);
    assert_eq!(sink.writes(), 2);

    // Only the following call observes EOF: zero bytes, nothing written.
    let read = writer
        .write_application_read_from_batched(&mut source, TIMEOUT)
        .await
        .expect("EOF must be a clean zero");
    assert_eq!(read, 0);
    assert_eq!(sink.writes(), 2, "EOF must not write a record");
    assert_eq!(writer.records.records_used(), 2);

    let plaintexts = {
        let wire = sink.wire();
        open_wire_records(&mut client_read, &wire)
    };
    assert_eq!(plaintexts.concat(), input);
}

#[tokio::test(flavor = "current_thread")]
async fn batched_buffer_grows_only_after_a_completely_full_read() {
    let (established, _client_read) = batched_writer_states();
    let sink = RecordingSink::default();
    let application = TlsApplicationIo::new(sink.clone(), established);
    let (_reader, mut writer) = application.into_split();

    // Small flows stay on the single-record buffer forever.
    for _ in 0..3 {
        let mut source = ReplaySource::new(patterned(0x33, 100), usize::MAX);
        let read = writer
            .write_application_read_from_batched(&mut source, TIMEOUT)
            .await
            .expect("small read must be relayed");
        assert_eq!(read, 100);
        assert_eq!(
            writer.write_record.capacity(),
            RECORD_SLOT_WIRE_CAPACITY,
            "small flows must not grow the batched buffer"
        );
    }

    // One completely-full record read is the bulk-flow evidence.
    let mut source = ReplaySource::new(patterned(0x44, MAX_PLAINTEXT_LEN), usize::MAX);
    let read = writer
        .write_application_read_from_batched(&mut source, TIMEOUT)
        .await
        .expect("full record must be relayed");
    assert_eq!(read, MAX_PLAINTEXT_LEN);
    assert!(writer.write_record.capacity() >= BATCHED_WIRE_CAPACITY);
    let grown = writer.record_storage_address();

    // The buffer never shrinks back, even for small reads afterwards.
    let mut source = ReplaySource::new(patterned(0x66, 100), usize::MAX);
    let read = writer
        .write_application_read_from_batched(&mut source, TIMEOUT)
        .await
        .expect("small read must be relayed");
    assert_eq!(read, 100);
    assert!(writer.write_record.capacity() >= BATCHED_WIRE_CAPACITY);
    assert_eq!(
        writer.record_storage_address(),
        grown,
        "the grown buffer must not move or shrink"
    );
}
