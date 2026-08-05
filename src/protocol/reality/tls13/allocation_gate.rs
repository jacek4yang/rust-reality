//! Measured proof that the successful framed record path is allocation-free.
//!
//! The specification requires evidence rather than inspection: after connection
//! warm-up, a bounded multi-record successful TLS/Vision framed transfer must
//! perform zero heap allocations per record. These tests drive the real reader,
//! writer, Vision decoder and Vision encoder against an instrumented global
//! allocator and assert the measured delta.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{
    CipherSuite, ContentType, EstablishedTls, Tls13KeySchedule, Tls13RecordLayer, TlsApplicationIo,
};
use crate::protocol::vless::{UserId, VisionCommand, VisionDecoder, VisionEncoder, VisionMode};

/// Builds one single-threaded runtime outside the measured region.
///
/// `allocation-counter` counts per thread, so a current-thread runtime driven
/// from inside the measured closure attributes exactly the work under test and
/// nothing from tests running concurrently in sibling threads.
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime must build")
}

const TIMEOUT: Duration = Duration::from_secs(5);
const USER: UserId = UserId::new([0x42; 16]);
/// Warm-up covers the first record allocation, the ciphertext buffer growth
/// caused by randomized padding, and the runtime timer wheel levels used by the
/// per-read deadline. Everything after warm-up must be free of allocation.
const WARM_UP_RECORDS: usize = 64;
const MEASURED_RECORDS: usize = 64;
const PAYLOAD: &[u8] = &[0xa5; 1024];

/// A transport that replays pre-encrypted bytes without allocating.
///
/// `tokio::io::duplex` is deliberately avoided here: its internal buffer grows
/// while records queue up, which would attribute transport allocations to the
/// record loop under test.
struct ReplayTransport {
    input: Vec<u8>,
    position: usize,
    chunk: usize,
    output: Vec<u8>,
}

impl ReplayTransport {
    fn new(input: Vec<u8>, chunk: usize, output_capacity: usize) -> Self {
        let mut output = Vec::new();
        output
            .try_reserve_exact(output_capacity)
            .expect("test sink must reserve");
        Self {
            input,
            position: 0,
            chunk,
            output,
        }
    }
}

impl AsyncRead for ReplayTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let available = self.input.len().saturating_sub(self.position);
        let length = available.min(buffer.remaining()).min(self.chunk);
        if length == 0 {
            return Poll::Ready(Ok(()));
        }
        let start = self.position;
        let bytes = self
            .input
            .get(start..start + length)
            .expect("replay window must exist");
        buffer.put_slice(bytes);
        self.position += length;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ReplayTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.output.len() + buffer.len() > self.output.capacity() {
            self.output.clear();
        }
        self.output.extend_from_slice(buffer);
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn schedule(suite: CipherSuite) -> Tls13KeySchedule {
    Tls13KeySchedule::new(
        suite,
        &[0x31; 32],
        &suite.hash().digest(b"allocation gate transcript"),
    )
    .expect("test key schedule must derive")
}

struct Peers {
    server: EstablishedTls,
    client_write: Tls13RecordLayer,
    client_read: Tls13RecordLayer,
}

fn peers() -> Peers {
    let suite = CipherSuite::Aes128GcmSha256;
    let schedule = schedule(suite);
    let secrets = schedule
        .application_traffic_secrets(&suite.hash().digest(b"server finished"))
        .expect("application secrets must derive");
    let layer = |secret| {
        Tls13RecordLayer::new(
            suite,
            schedule
                .traffic_keys(secret)
                .expect("traffic keys must derive"),
        )
        .expect("record layer must initialize")
    };
    Peers {
        server: EstablishedTls::from_test_records(
            suite,
            layer(secrets.client()),
            layer(secrets.server()),
        ),
        client_write: layer(secrets.client()),
        client_read: layer(secrets.server()),
    }
}

#[test]
fn framed_read_path_allocates_nothing_per_record_after_warm_up() {
    let runtime = runtime();
    let peers = peers();
    let mut client_write = peers.client_write;

    // Pre-seal every record so the measured region contains only reader work.
    let mut wire = Vec::new();
    let mut stream = Vec::new();
    for _ in 0..WARM_UP_RECORDS + MEASURED_RECORDS {
        client_write
            .seal_into(ContentType::ApplicationData, PAYLOAD, 0, &mut wire)
            .expect("record must seal");
        stream.extend_from_slice(&wire);
    }
    let transport = ReplayTransport::new(stream, 512, 1024);
    let application = TlsApplicationIo::new(transport, peers.server);
    let (mut reader, _writer) = application.into_split();

    runtime.block_on(async {
        for _ in 0..WARM_UP_RECORDS {
            let record = reader
                .read_application(TIMEOUT)
                .await
                .expect("warm-up record must authenticate");
            assert_eq!(record.len(), PAYLOAD.len());
        }
    });
    let storage = reader.record_storage_address();

    let measured = allocation_counter::measure(|| {
        runtime.block_on(async {
            for _ in 0..MEASURED_RECORDS {
                let record = reader
                    .read_application(TIMEOUT)
                    .await
                    .expect("measured record must authenticate");
                assert_eq!(record.len(), PAYLOAD.len());
            }
        });
    });

    assert_eq!(
        measured.count_total, 0,
        "steady-state framed reads must not allocate, saw {measured:?} over {MEASURED_RECORDS} records"
    );
    assert_eq!(
        reader.record_storage_address(),
        storage,
        "record storage must not move between records"
    );
}

#[test]
fn framed_write_path_allocates_nothing_per_record_after_warm_up() {
    let runtime = runtime();
    let peers = peers();
    let transport = ReplayTransport::new(Vec::new(), 512, 64 * 1024);
    let application = TlsApplicationIo::new(transport, peers.server);
    let (_reader, mut writer) = application.into_split();
    let mut encoder = VisionEncoder::with_padding_seed(USER, &[0x11; 44]);

    runtime.block_on(async {
        for _ in 0..WARM_UP_RECORDS {
            let plan = encoder
                .plan(PAYLOAD.len(), VisionCommand::Continue, false)
                .expect("warm-up frame must plan");
            writer
                .write_assembled(
                    plan.wire_len(),
                    |frame| encoder.assemble(&plan, PAYLOAD, frame),
                    TIMEOUT,
                )
                .await
                .expect("warm-up frame must be written");
            encoder.commit(&plan);
        }
    });
    let storage = writer.record_storage_address();

    let measured = allocation_counter::measure(|| {
        runtime.block_on(async {
            for _ in 0..MEASURED_RECORDS {
                let plan = encoder
                    .plan(PAYLOAD.len(), VisionCommand::Continue, false)
                    .expect("measured frame must plan");
                writer
                    .write_assembled(
                        plan.wire_len(),
                        |frame| encoder.assemble(&plan, PAYLOAD, frame),
                        TIMEOUT,
                    )
                    .await
                    .expect("measured frame must be written");
                encoder.commit(&plan);
            }
        });
    });

    assert_eq!(
        measured.count_total, 0,
        "steady-state framed writes must not allocate, saw {measured:?} over {MEASURED_RECORDS} records"
    );
    assert_eq!(
        writer.record_storage_address(),
        storage,
        "ciphertext storage must not move between records"
    );
}

/// Proves the in-place assembled frame is byte-identical to the reference encoder.
#[tokio::test(flavor = "current_thread")]
async fn assembled_frames_match_the_reference_encoder_on_the_wire() {
    let peers = peers();
    let mut client_read = peers.client_read;
    let (mut client, server) = tokio::io::duplex(1 << 20);
    let application = TlsApplicationIo::new(server, peers.server);
    let (_reader, mut writer) = application.into_split();
    let mut assembled = VisionEncoder::with_padding_seed(USER, &[0x33; 44]);
    let mut reference = VisionEncoder::with_padding_seed(USER, &[0x33; 44]);

    let mut expected = Vec::new();
    for _ in 0..8 {
        let plan = assembled
            .plan(PAYLOAD.len(), VisionCommand::Continue, true)
            .expect("frame must plan");
        writer
            .write_assembled(
                plan.wire_len(),
                |frame| assembled.assemble(&plan, PAYLOAD, frame),
                TIMEOUT,
            )
            .await
            .expect("frame must be written");
        assembled.commit(&plan);

        let mut frame = Vec::new();
        reference
            .encode(PAYLOAD, VisionCommand::Continue, true, &mut frame)
            .expect("reference frame must encode");
        expected.push(frame);
    }

    let mut decoder = VisionDecoder::new(USER);
    let mut decoded = Vec::new();
    for frame in &expected {
        let mut record = super::read_tls_record(&mut client, TIMEOUT)
            .await
            .expect("record must be read")
            .into_wire();
        let opened = client_read
            .open_in_place(&mut record)
            .expect("record must authenticate");
        assert_eq!(
            opened.plaintext(),
            frame.as_slice(),
            "in-place assembly must be byte-identical to the reference encoder"
        );
        assert_eq!(
            decoder
                .decode(opened.plaintext(), &mut decoded)
                .expect("frame must decode"),
            VisionMode::Framed
        );
        assert_eq!(decoded.as_slice(), PAYLOAD);
    }
}

#[test]
fn vision_decode_of_borrowed_plaintext_allocates_nothing_per_record() {
    let mut encoder = VisionEncoder::with_padding_seed(USER, &[0x22; 44]);
    let mut frames = Vec::new();
    for _ in 0..WARM_UP_RECORDS + MEASURED_RECORDS {
        let mut frame = Vec::new();
        encoder
            .encode(PAYLOAD, VisionCommand::Continue, false, &mut frame)
            .expect("frame must encode");
        frames.push(frame);
    }

    let mut decoder = VisionDecoder::new(USER);
    let mut decoded = Vec::new();
    decoded
        .try_reserve_exact(crate::protocol::vless::VISION_FRAME_SIZE)
        .expect("decoder output must reserve");
    for frame in frames.iter().take(WARM_UP_RECORDS) {
        decoder.decode(frame, &mut decoded).expect("warm-up decode");
    }

    let measured = allocation_counter::measure(|| {
        for frame in frames.iter().skip(WARM_UP_RECORDS) {
            decoder
                .decode(frame, &mut decoded)
                .expect("measured decode");
        }
    });

    assert_eq!(
        measured.count_total, 0,
        "steady-state Vision decode must not allocate, saw {measured:?}"
    );
}

/// Proves the raw-mode borrowed decode keeps the relay copy- and allocation-free.
#[test]
fn raw_mode_borrowed_decode_allocates_nothing_per_record() {
    let mut encoder = VisionEncoder::with_padding_seed(USER, &[0x22; 44]);
    let mut end_frame = Vec::new();
    encoder
        .encode(b"last", VisionCommand::End, false, &mut end_frame)
        .expect("end frame must encode");

    let mut decoder = VisionDecoder::new(USER);
    let mut staged = Vec::new();
    decoder
        .decode(&end_frame, &mut staged)
        .expect("end frame must decode");
    assert_eq!(decoder.mode(), VisionMode::Raw);

    let record = [0xa5_u8; 4096];
    for _ in 0..WARM_UP_RECORDS {
        let (_, payload) = decoder
            .decode_borrowed(&record, &mut staged)
            .expect("warm-up raw decode must succeed");
        assert_eq!(
            payload,
            crate::protocol::vless::VisionPayload::Borrowed(record.as_slice())
        );
    }

    let measured = allocation_counter::measure(|| {
        for _ in 0..MEASURED_RECORDS {
            let (_, payload) = decoder
                .decode_borrowed(&record, &mut staged)
                .expect("measured raw decode must succeed");
            assert_eq!(
                payload,
                crate::protocol::vless::VisionPayload::Borrowed(record.as_slice())
            );
        }
    });

    assert_eq!(
        measured.count_total, 0,
        "steady-state raw-mode borrowed decode must not allocate, saw {measured:?}"
    );
    assert_eq!(staged, b"last", "the borrowed path never touches staging");
}

/// Proves the outer downlink seals destination reads in place without allocating.
///
/// This is the framed End-path relay loop: one socket read lands directly in
/// the reusable record buffer's plaintext region and is sealed in place, so
/// after warm-up a chunk must perform zero heap allocations.
#[test]
fn outer_downlink_read_into_record_allocates_nothing_per_chunk_after_warm_up() {
    const CHUNK: usize = 4096;

    let runtime = runtime();
    let peers = peers();
    let input = vec![0x5a_u8; (WARM_UP_RECORDS + MEASURED_RECORDS) * CHUNK];
    let mut source = ReplayTransport::new(input, CHUNK, 0);
    let sink = ReplayTransport::new(Vec::new(), 512, 64 * 1024);
    let application = TlsApplicationIo::new(sink, peers.server);
    let (_reader, mut writer) = application.into_split();

    runtime.block_on(async {
        for _ in 0..WARM_UP_RECORDS {
            let read = writer
                .write_application_read_from(&mut source, TIMEOUT)
                .await
                .expect("warm-up chunk must be relayed");
            assert_eq!(read, CHUNK);
        }
    });
    let storage = writer.record_storage_address();

    let measured = allocation_counter::measure(|| {
        runtime.block_on(async {
            for _ in 0..MEASURED_RECORDS {
                let read = writer
                    .write_application_read_from(&mut source, TIMEOUT)
                    .await
                    .expect("measured chunk must be relayed");
                assert_eq!(read, CHUNK);
            }
        });
    });

    assert_eq!(
        measured.count_total, 0,
        "steady-state outer downlink chunks must not allocate, saw {measured:?} over {MEASURED_RECORDS} chunks"
    );
    assert_eq!(
        writer.record_storage_address(),
        storage,
        "ciphertext storage must not move between chunks"
    );
}
