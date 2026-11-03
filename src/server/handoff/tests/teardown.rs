//! LINE teardown tests where the client resets or half-closes.

use super::*;

#[tokio::test(flavor = "current_thread")]
async fn line_completes_a_clean_session_when_the_client_resets_at_teardown() {
    let rig = handoff_rig().await;
    let destination_port = rig
        .destination_listener
        .local_addr()
        .expect("destination address must exist")
        .port();
    let request = vision_request(destination_port, b"ping");

    let exchange = async {
        let line = rig.line_handler.handle(rig.established);
        let landing = async {
            let (stream, _) = rig.landing_listener.accept().await?;
            rig.landing_handler
                .handle(stream)
                .await
                .map_err(io::Error::other)
        };
        let client_io = async {
            let mut client = rig.client;
            let mut write_records = rig.client_write_records;
            let mut read_records = rig.client_read_records;
            let mut record = Vec::new();
            write_records
                .seal_into(ContentType::ApplicationData, &request, 0, &mut record)
                .map_err(io::Error::other)?;
            client.write_all(&record).await?;
            let mut close_record = Vec::new();
            write_records
                .seal_into(ContentType::Alert, &[1, 0], 0, &mut close_record)
                .map_err(io::Error::other)?;
            client.write_all(&close_record).await?;
            let (mut decoder, mut response) =
                read_response_header_record(&mut client, &mut read_records).await?;
            let response = read_resumed_payload(
                &mut client,
                &mut read_records,
                b"pong",
                &mut decoder,
                &mut response,
            )
            .await?;
            // The payload is complete; the client closes without reading
            // the server's close_notify, so LINE's raw splice observes a
            // reset instead of a FIN. The session was clean and must be
            // accounted as completed, not rejected.
            reset_client_unread(client).await;
            Ok::<_, io::Error>(response)
        };
        let destination_io = async {
            let (mut destination, _) = rig.destination_listener.accept().await?;
            let mut received = Vec::new();
            destination.read_to_end(&mut received).await?;
            destination.write_all(b"pong").await?;
            destination.shutdown().await?;
            Ok::<_, io::Error>(received)
        };
        tokio::join!(line, landing, client_io, destination_io)
    };
    let (line, landing, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
        .await
        .expect("handoff exchange must not time out");

    assert_eq!(client_result.expect("client I/O must succeed"), b"pong");
    assert_eq!(
        destination_result.expect("destination I/O must succeed"),
        b"ping"
    );
    landing.expect("LANDING handler must succeed");
    let line_stats =
        line.expect("a teardown reset must not fail a session that already completed byte-exactly");
    assert!(
        line_stats.downlink_bytes() > 0,
        "LINE must report the spliced downlink ciphertext it moved"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn line_completes_an_upload_dominated_session_when_the_client_resets_at_teardown() {
    let rig = handoff_rig().await;
    let destination_port = rig
        .destination_listener
        .local_addr()
        .expect("destination address must exist")
        .port();
    let request = vision_request(destination_port, b"ping");
    let upload = vec![0x55_u8; 200 * 1024];

    let exchange = async {
        let line = rig.line_handler.handle(rig.established);
        let landing = async {
            let (stream, _) = rig.landing_listener.accept().await?;
            rig.landing_handler
                .handle(stream)
                .await
                .map_err(io::Error::other)
        };
        let client_io = async {
            let mut client = rig.client;
            let mut write_records = rig.client_write_records;
            let mut read_records = rig.client_read_records;
            let mut record = Vec::new();
            write_records
                .seal_into(ContentType::ApplicationData, &request, 0, &mut record)
                .map_err(io::Error::other)?;
            client.write_all(&record).await?;
            // Wait for the first downlink record so the upload provably
            // travels the raw splice rather than the sealed continuation.
            let (mut decoder, mut response) =
                read_response_header_record(&mut client, &mut read_records).await?;
            client
                .write_all(&seal_application_records(&mut write_records, &upload)?)
                .await?;
            let mut close_record = Vec::new();
            write_records
                .seal_into(ContentType::Alert, &[1, 0], 0, &mut close_record)
                .map_err(io::Error::other)?;
            client.write_all(&close_record).await?;
            let response = read_resumed_payload(
                &mut client,
                &mut read_records,
                b"pong",
                &mut decoder,
                &mut response,
            )
            .await?;
            reset_client_unread(client).await;
            Ok::<_, io::Error>(response)
        };
        let destination_io = async {
            let (mut destination, _) = rig.destination_listener.accept().await?;
            let mut received = Vec::new();
            destination.read_to_end(&mut received).await?;
            destination.write_all(b"pong").await?;
            destination.shutdown().await?;
            Ok::<_, io::Error>(received)
        };
        tokio::join!(line, landing, client_io, destination_io)
    };
    let (line, landing, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
        .await
        .expect("upload exchange must not time out");

    assert_eq!(client_result.expect("client I/O must succeed"), b"pong");
    let mut expected_upload = b"ping".to_vec();
    expected_upload.extend_from_slice(&upload);
    assert_eq!(
        destination_result.expect("destination I/O must succeed"),
        expected_upload,
        "the spliced upload must arrive byte-exactly"
    );
    landing.expect("LANDING handler must succeed");
    let line_stats = line.expect("a teardown reset must not fail a completed upload session");
    assert!(
        line_stats.uplink_bytes() > 0,
        "the post-transfer upload must move through the raw splice"
    );
    assert!(line_stats.downlink_bytes() > 0);
}

#[tokio::test(flavor = "current_thread")]
async fn line_completes_when_the_client_half_closes_before_the_downlink() {
    let rig = handoff_rig().await;
    let destination_port = rig
        .destination_listener
        .local_addr()
        .expect("destination address must exist")
        .port();
    let request = vision_request(destination_port, b"ping");

    let exchange = async {
        let line = rig.line_handler.handle(rig.established);
        let landing = async {
            let (stream, _) = rig.landing_listener.accept().await?;
            rig.landing_handler
                .handle(stream)
                .await
                .map_err(io::Error::other)
        };
        let client_io = async {
            let mut client = rig.client;
            let mut write_records = rig.client_write_records;
            let mut read_records = rig.client_read_records;
            let mut burst = Vec::new();
            write_records
                .seal_into(ContentType::ApplicationData, &request, 0, &mut burst)
                .map_err(io::Error::other)?;
            let mut close_record = Vec::new();
            write_records
                .seal_into(ContentType::Alert, &[1, 0], 0, &mut close_record)
                .map_err(io::Error::other)?;
            burst.extend_from_slice(&close_record);
            client.write_all(&burst).await?;
            // The client half-closes its write side before a single
            // downlink byte arrives; the response must still flow.
            client.shutdown().await?;
            let (mut decoder, mut response) =
                read_response_header_record(&mut client, &mut read_records).await?;
            let response = read_resumed_payload(
                &mut client,
                &mut read_records,
                b"pong",
                &mut decoder,
                &mut response,
            )
            .await?;
            Ok::<_, io::Error>(response)
        };
        let destination_io = async {
            let (mut destination, _) = rig.destination_listener.accept().await?;
            let mut received = Vec::new();
            destination.read_to_end(&mut received).await?;
            destination.write_all(b"pong").await?;
            destination.shutdown().await?;
            Ok::<_, io::Error>(received)
        };
        tokio::join!(line, landing, client_io, destination_io)
    };
    let (line, landing, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
        .await
        .expect("half-close exchange must not time out");

    assert_eq!(client_result.expect("client I/O must succeed"), b"pong");
    assert_eq!(
        destination_result.expect("destination I/O must succeed"),
        b"ping"
    );
    landing.expect("LANDING handler must succeed");
    let line_stats = line.expect("a client half-close first must still complete the session");
    assert!(line_stats.downlink_bytes() > 0);
}
