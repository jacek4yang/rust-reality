use super::*;
use crate::protocol::reality::tls13::{
    CipherSuite, ContentType, Tls13KeySchedule, Tls13RecordLayer, read_tls_record,
};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
};

#[test]
fn in_place_upload_matches_assembly_at_every_frame_boundary() {
    for length in [
        1, 2, 8186, 8187, 8188, 16373, 16374, 16375, 24560, 24561, 32747, 32748,
    ] {
        for seed in 0..16_u8 {
            let payload: Vec<u8> = (0..length).map(|i| (i as u8).wrapping_add(seed)).collect();
            fuzz_upload_assembly(&payload);
        }
    }
}

#[tokio::test]
async fn vectored_upload_preserves_payload_and_reserved_wire_bytes() {
    for slots in [1, 2] {
        for length in [1, 8187, 8188, 16374, 16375, 32748] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (local, peer) = tokio::join!(
                TcpStream::connect(listener.local_addr().unwrap()),
                listener.accept()
            );
            let local = local.unwrap();
            let (mut peer, _) = peer.unwrap();
            let payload: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
            peer.write_all(&payload).await.unwrap();
            peer.shutdown().await.unwrap();
            let mut storage = vec![0xa5; slots * RECORD_SLOT_WIRE_CAPACITY];
            let pointer = storage.as_ptr();
            let mut received = Vec::new();
            loop {
                storage.fill(0xa5);
                let count = read_upload(&local, &mut storage).await.unwrap();
                if count == 0 {
                    break;
                }
                let mut remaining = count;
                for record in storage.as_chunks::<RECORD_SLOT_WIRE_CAPACITY>().0 {
                    assert!(record[..TLS_RECORD_HEADER_LEN].iter().all(|b| *b == 0xa5));
                    for frame in 0..2 {
                        let start = TLS_RECORD_HEADER_LEN
                            + frame * crate::protocol::vless::VISION_FRAME_SIZE;
                        assert!(record[start..start + 5].iter().all(|b| *b == 0xa5));
                        let size = remaining.min(UPLOAD_FRAME_PAYLOAD);
                        received.extend_from_slice(&record[start + 5..start + 5 + size]);
                        assert!(
                            record[start + 5 + size..start + 5 + UPLOAD_FRAME_PAYLOAD]
                                .iter()
                                .all(|b| *b == 0xa5)
                        );
                        remaining -= size;
                    }
                    assert!(
                        record[TLS_RECORD_HEADER_LEN + MAX_PLAINTEXT_LEN..]
                            .iter()
                            .all(|b| *b == 0xa5)
                    );
                }
                assert_eq!(remaining, 0);
                assert_eq!(storage.as_ptr(), pointer);
            }
            assert_eq!(received, payload);
        }
    }
}

#[tokio::test]
async fn pending_vectored_upload_can_be_cancelled_without_consuming_input() {
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (local, peer) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    let local = local.unwrap();
    let (mut peer, _) = peer.unwrap();
    let mut storage = vec![0_u8; RECORD_SLOT_WIRE_CAPACITY];
    {
        let mut pending = Box::pin(read_upload(&local, &mut storage));
        assert!(matches!(
            pending
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ));
    }
    peer.write_all(b"a").await.unwrap();
    assert_eq!(read_upload(&local, &mut storage).await.unwrap(), 1);
    assert_eq!(storage[TLS_RECORD_HEADER_LEN + 5], b'a');
    {
        // A successful short read can leave cached readiness. Exhausting it
        // must return Pending and a later write must still wake the reader.
        let mut pending = Box::pin(read_upload(&local, &mut storage));
        assert!(matches!(
            pending
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ));
    }
    peer.write_all(b"b").await.unwrap();
    peer.shutdown().await.unwrap();
    assert_eq!(read_upload(&local, &mut storage).await.unwrap(), 1);
    assert_eq!(storage[TLS_RECORD_HEADER_LEN + 5], b'b');
    assert_eq!(read_upload(&local, &mut storage).await.unwrap(), 0);
}

#[test]
fn vectored_upload_rejects_incomplete_or_oversized_storage() {
    for length in [
        0,
        RECORD_SLOT_WIRE_CAPACITY - 1,
        RECORD_SLOT_WIRE_CAPACITY + 1,
        2 * RECORD_SLOT_WIRE_CAPACITY + 1,
    ] {
        let mut storage = vec![0; length];
        assert!(upload_payload_regions(&mut storage).is_err());
    }
}

fn record_pair() -> (Tls13RecordLayer, Tls13RecordLayer) {
    let suite = CipherSuite::Aes128GcmSha256;
    let schedule = Tls13KeySchedule::new(
        suite,
        &[0x31; 32],
        &suite.hash().digest(b"client record ownership test"),
    )
    .unwrap();
    let transcript = suite.hash().digest(b"server finished");
    let (write, _) = schedule
        .application_traffic_secrets(&transcript)
        .unwrap()
        .into_parts();
    let (read, _) = schedule
        .application_traffic_secrets(&transcript)
        .unwrap()
        .into_parts();
    (
        Tls13RecordLayer::from_traffic_secret(suite, write).unwrap(),
        Tls13RecordLayer::from_traffic_secret(suite, read).unwrap(),
    )
}

#[test]
fn response_addons_and_vision_prefix_survive_every_fragment_boundary() {
    let user = UserId::new([0x11; 16]);
    let mut encoder = VisionEncoder::new(user).unwrap();
    let mut frame = Vec::new();
    encoder
        .encode(b"payload", VisionCommand::End, false, &mut frame)
        .unwrap();
    let mut wire = vec![0, 255];
    wire.extend_from_slice(&[0x55; 255]);
    wire.extend_from_slice(&frame);
    for split in 0..=wire.len() {
        let mut response = Some(Vec::new());
        let mut decoder = VisionDecoder::new(user);
        let mut output = Vec::new();
        decode_downlink(&mut response, &mut decoder, &mut output, &wire[..split]).unwrap();
        decode_downlink(&mut response, &mut decoder, &mut output, &wire[split..]).unwrap();
        assert!(response.is_none());
        assert_eq!(output, b"payload");
        assert_eq!(decoder.mode(), VisionMode::Raw);
    }
}

#[tokio::test]
async fn two_full_buffered_plaintext_records_share_one_delivery() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (client, accepted) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    let (_peer, _) = accepted.unwrap();
    let (reader, writer) = client.unwrap().into_split();
    let (mut downlink, read) = record_pair();
    let (write, _) = record_pair();
    let user = UserId::new([0x11; 16]);
    let mut encoder = VisionEncoder::new(user).unwrap();
    let mut decoder = VisionDecoder::new(user);
    let mut frame = Vec::new();
    encoder
        .encode(&[], VisionCommand::End, false, &mut frame)
        .unwrap();
    decoder.decode_append(&frame, &mut Vec::new()).unwrap();
    let payload = vec![0x42; MAX_PLAINTEXT_LEN];
    let mut pending = Vec::new();
    for _ in 0..2 {
        downlink
            .seal_into(ContentType::ApplicationData, &payload, 0, &mut frame)
            .unwrap();
        pending.extend_from_slice(&frame);
    }
    let (reader, writer) = application_halves(
        reader,
        pending,
        writer,
        read,
        write,
        false,
        crate::protocol::vless::VISION_FRAME_SIZE,
    );
    let mut io = VisionIo {
        reader: ReadDirection::Tls(reader),
        writer,
        response: None,
        encoder: VisionEncoder::new(user).unwrap(),
        decoder,
        readable: Vec::with_capacity(MAX_PLAINTEXT_LEN),
        readable_at: 0,
        activity: Arc::new(crate::io_activity::SessionActivity::default()),
    };
    tokio::time::timeout(Duration::from_secs(1), io.poll_fill_readable())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(io.readable.len(), 2 * MAX_PLAINTEXT_LEN);
    assert!(io.readable.iter().all(|byte| *byte == 0x42));
    assert_eq!(io.readable.capacity(), 2 * MAX_PLAINTEXT_LEN);
}

#[tokio::test]
async fn buffered_downlink_delivers_authenticated_prefix_before_close_notify() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (client, accepted) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    let (_peer, _) = accepted.unwrap();
    let (reader, writer) = client.unwrap().into_split();
    let (mut downlink, read) = record_pair();
    let (write, _) = record_pair();
    let user = UserId::new([0x11; 16]);
    let mut encoder = VisionEncoder::new(user).unwrap();
    let mut pending = Vec::new();
    let mut frame = Vec::new();
    let mut wire = Vec::new();
    for content in [b"first".as_slice(), b"second"] {
        encoder
            .encode(content, VisionCommand::Continue, false, &mut frame)
            .unwrap();
        downlink
            .seal_into(ContentType::ApplicationData, &frame, 0, &mut wire)
            .unwrap();
        pending.extend_from_slice(&wire);
    }
    downlink
        .seal_into(ContentType::Alert, &[1, 0], 0, &mut wire)
        .unwrap();
    pending.extend_from_slice(&wire);
    let (reader, writer) = application_halves(
        reader,
        pending,
        writer,
        read,
        write,
        false,
        crate::protocol::vless::VISION_FRAME_SIZE,
    );
    let mut io = VisionIo {
        reader: ReadDirection::Tls(reader),
        writer,
        response: None,
        encoder: VisionEncoder::new(user).unwrap(),
        decoder: VisionDecoder::new(user),
        readable: Vec::with_capacity(MAX_PLAINTEXT_LEN),
        readable_at: 0,
        activity: Arc::new(crate::io_activity::SessionActivity::default()),
    };
    // The peer sends nothing: buffered records must not trigger a refill
    // or allocate another delivery buffer.
    {
        use std::{
            future::Future,
            task::{Context, Poll, Waker},
        };
        let next = io.poll_fill_readable();
        tokio::pin!(next);
        let allocations = allocation_counter::measure(|| {
            assert!(matches!(
                next.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Ok(()))
            ));
        });
        assert_eq!(allocations.count_total, 0);
    }
    assert_eq!(io.readable, b"firstsecond");
    assert!(matches!(io.reader, ReadDirection::Closed));
    io.readable_at = io.readable.len();
    assert!(matches!(
        io.poll_fill_readable().await,
        Err(VisionTunnelError::Closed)
    ));
}

#[tokio::test]
async fn bulk_upload_packs_two_bounded_frames_in_one_authenticated_record() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (client, accepted) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    let (mut peer, _) = accepted.unwrap();
    let (reader, writer) = client.unwrap().into_split();
    let (_, read) = record_pair();
    let (write, mut uplink) = record_pair();
    let (reader, writer) = application_halves(
        reader,
        Vec::new(),
        writer,
        read,
        write,
        false,
        crate::protocol::vless::VISION_FRAME_SIZE,
    );
    let user = UserId::new([0x11; 16]);
    let mut encoder = VisionEncoder::new(user).unwrap();
    let mut decoder = VisionDecoder::new(user);
    let mut preamble = Vec::new();
    encoder
        .encode(&[], VisionCommand::Continue, true, &mut preamble)
        .unwrap();
    decoder.decode_append(&preamble, &mut Vec::new()).unwrap();
    let mut io = VisionIo {
        reader: ReadDirection::Tls(reader),
        writer,
        response: None,
        encoder,
        decoder,
        readable: Vec::new(),
        readable_at: 0,
        activity: Arc::new(crate::io_activity::SessionActivity::default()),
    };
    let mut received = Vec::new();
    // Exercise full one- and two-record reads, a partial second frame,
    // and the next record's sequence number without splitting a frame.
    for length in [16374_usize, 8190, 1, 32748, 32749, 16374] {
        let payload: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
        if length <= 32748 {
            let mut storage = io.take_upload_storage();
            storage.resize(
                length.div_ceil(UPLOAD_RECORD_PAYLOAD) * RECORD_SLOT_WIRE_CAPACITY,
                0,
            );
            stage_upload_payload(&mut storage, &payload);
            io.write_upload(&mut storage, length).await.unwrap();
            assert!(!storage.is_empty());
        } else {
            io.write_application(&payload).await.unwrap();
        }
        received.clear();
        let mut records = 0;
        while received.len() < payload.len() {
            let mut wire = read_tls_record(&mut peer, Duration::from_secs(1))
                .await
                .unwrap()
                .into_wire();
            let opened = uplink.open_in_place(&mut wire).unwrap();
            assert!(opened.plaintext().len() <= MAX_PLAINTEXT_LEN);
            io.decoder
                .decode_append(opened.plaintext(), &mut received)
                .unwrap();
            records += 1;
        }
        assert_eq!(records, payload.len().div_ceil(16374));
        assert_eq!(received, payload);
        assert_eq!(io.decoder.mode(), VisionMode::Framed);
    }
}

#[tokio::test]
async fn small_read_window_promotes_for_large_records_without_steady_allocations() {
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
    };
    let (mut peer, read) = record_pair();
    let (write, _) = record_pair();
    let payload = vec![0x42; MAX_PLAINTEXT_LEN];
    let mut wire = Vec::new();
    let mut record = Vec::new();
    for _ in 0..2 {
        peer.seal_into(ContentType::ApplicationData, &payload, 0, &mut record)
            .unwrap();
        wire.extend_from_slice(&record);
    }
    let (mut reader, _) = application_halves(
        wire.as_slice(),
        Vec::new(),
        tokio::io::sink(),
        read,
        write,
        false,
        crate::protocol::vless::VISION_FRAME_SIZE,
    );
    assert_eq!(
        reader
            .read_application(Duration::from_secs(1))
            .await
            .unwrap()
            .plaintext(),
        payload
    );
    let next = reader.read_application(Duration::from_secs(1));
    tokio::pin!(next);
    let measured = allocation_counter::measure(|| {
        let Poll::Ready(Ok(record)) = next.as_mut().poll(&mut Context::from_waker(Waker::noop()))
        else {
            panic!("second complete record must already be buffered");
        };
        assert_eq!(record.plaintext(), payload);
    });
    assert_eq!(measured.count_total, 0);
}

#[tokio::test]
async fn cancelled_partial_record_and_direct_read_ahead_preserve_direction_ownership() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let connect = TcpStream::connect(listener.local_addr().unwrap());
    let (client, accepted) = tokio::join!(connect, listener.accept());
    let (mut peer, _) = accepted.unwrap();
    let (reader, writer) = client.unwrap().into_split();
    let (mut downlink, read) = record_pair();
    let (write, mut uplink) = record_pair();
    let (reader, writer) = application_halves(
        reader,
        Vec::new(),
        writer,
        read,
        write,
        false,
        crate::protocol::vless::VISION_FRAME_SIZE,
    );
    let user = UserId::new([0x11; 16]);
    let mut io = VisionIo {
        reader: ReadDirection::Tls(reader),
        writer,
        response: None,
        encoder: VisionEncoder::new(user).unwrap(),
        decoder: VisionDecoder::new(user),
        readable: Vec::with_capacity(MAX_PLAINTEXT_LEN),
        readable_at: 0,
        activity: Arc::new(crate::io_activity::SessionActivity::default()),
    };
    let mut encoder = VisionEncoder::new(user).unwrap();
    let future_bytes = std::mem::size_of_val(&io.read_and_open_record());
    eprintln!("client record-read future bytes: {future_bytes}");
    assert!(
        future_bytes < MAX_PLAINTEXT_LEN,
        "raw scratch must not live in every framed read future"
    );
    let mut plaintext = Vec::new();
    encoder
        .encode(b"boundary", VisionCommand::Direct, false, &mut plaintext)
        .unwrap();
    let mut wire = Vec::new();
    downlink
        .seal_into(ContentType::ApplicationData, &plaintext, 0, &mut wire)
        .unwrap();
    peer.write_all(&wire[..7]).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(10), io.read_and_open_record())
            .await
            .is_err()
    );
    wire.extend_from_slice(b"pipelined raw bytes");
    peer.write_all(&wire[7..]).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), io.read_and_open_record())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(io.reader, ReadDirection::Raw { .. }));
    assert!(
        io.readable.capacity() >= 2 * MAX_PLAINTEXT_LEN,
        "Direct must retain the bounded two-record delivery window"
    );
    let mut received = io.readable.clone();
    io.readable_at = io.readable.len();
    if received.len() < b"boundarypipelined raw bytes".len() {
        io.read_and_open_record().await.unwrap();
        received.extend_from_slice(&io.readable);
        io.readable_at = io.readable.len();
    }
    assert_eq!(received, b"boundarypipelined raw bytes");
    let bulk = vec![0x5a; 2 * MAX_PLAINTEXT_LEN];
    for _ in 0..2 {
        peer.write_all(&bulk).await.unwrap();
        let mut received = Vec::with_capacity(bulk.len());
        while received.len() < bulk.len() {
            let ReadDirection::Raw { reader } = &io.reader else {
                panic!("Direct must keep its authenticated read owner");
            };
            reader.as_ref().readable().await.unwrap();
            let allocations = {
                use std::{
                    future::Future,
                    task::{Context, Poll, Waker},
                };
                let next = io.read_and_open_record();
                tokio::pin!(next);
                allocation_counter::measure(|| {
                    assert!(matches!(
                        next.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                        Poll::Ready(Ok(()))
                    ));
                })
            };
            assert_eq!(allocations.count_total, 0);
            received.extend_from_slice(&io.readable);
            io.readable_at = io.readable.len();
        }
        assert_eq!(received, bulk);
    }
    io.write_application(b"uplink remains framed")
        .await
        .unwrap();
    let mut wire = read_tls_record(&mut peer, Duration::from_secs(1))
        .await
        .unwrap()
        .into_wire();
    let opened = uplink.open_in_place(&mut wire).unwrap();
    let mut decoded = Vec::new();
    assert_eq!(
        VisionDecoder::new(user)
            .decode_append(opened.plaintext(), &mut decoded)
            .unwrap(),
        VisionMode::Framed
    );
    assert_eq!(decoded, b"uplink remains framed");
    peer.shutdown().await.unwrap();
    assert!(matches!(
        io.read_and_open_record().await,
        Err(VisionTunnelError::Closed)
    ));
}
