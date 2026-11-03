//! LANDING TLS resume and sequence-continuity tests.

use super::*;

#[test]
fn landing_resume_preserves_sequence_and_key_update_capability() {
    let suite = CipherSuite::ChaCha20Poly1305Sha256;
    let state = test_state_with_server_sequence(
        Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 443),
        1,
    );
    let (exported, ..) = state.into_parts().expect("state must separate");
    let mut resumed = resume_tls(exported).expect("sequence-one state must resume");
    assert_eq!(resumed.client_records_mut().records_used(), 1);
    assert_eq!(resumed.server_records_mut().records_used(), 1);

    let mut wire = Vec::new();
    resumed
        .server_records_mut()
        .seal_into(ContentType::ApplicationData, b"next", 0, &mut wire)
        .expect("resumed server must seal at sequence one");
    assert_eq!(resumed.server_records_mut().records_used(), 2);

    let peer_state = ExportedRecordState::from_parts(
        suite,
        TrafficSecret::from_bytes(suite.hash(), &[0x12; 32]).expect("peer server secret"),
        1,
    )
    .expect("peer state must build");
    let mut peer = Tls13RecordLayer::from_exported_state(peer_state).expect("peer must resume");
    let opened = peer
        .open_in_place(&mut wire)
        .expect("peer must authenticate the next sequence-one record");
    assert_eq!(opened.content_type(), ContentType::ApplicationData);
    assert_eq!(opened.plaintext(), b"next");
    assert_eq!(peer.records_used(), 2);

    resumed
        .server_records_mut()
        .update_traffic_secret()
        .expect("resumed generation must update");
    peer.update_traffic_secret()
        .expect("peer generation must update");
    assert_eq!(resumed.server_records_mut().records_used(), 0);
    assert_eq!(peer.records_used(), 0);
    resumed
        .server_records_mut()
        .seal_into(ContentType::ApplicationData, b"updated", 0, &mut wire)
        .expect("updated resumed server must seal");
    let opened = peer
        .open_in_place(&mut wire)
        .expect("peer must authenticate the updated generation");
    assert_eq!(opened.plaintext(), b"updated");
}

#[tokio::test(flavor = "current_thread")]
async fn sealed_v3_resume_preserves_generations_buffers_response_and_future_updates() {
    for suite in [
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Aes256GcmSha384,
        CipherSuite::ChaCha20Poly1305Sha256,
    ] {
        let layer = |seed| {
            Tls13RecordLayer::from_traffic_secret(
                suite,
                TrafficSecret::from_bytes(suite.hash(), &[seed; 48][..suite.hash().output_len()])
                    .expect("traffic secret"),
            )
            .expect("record layer")
        };
        let mut client_records = layer(0x11);
        let mut server_records = layer(0x12);
        let mut peer_write = layer(0x11);
        let mut peer_read = layer(0x12);
        client_records
            .update_traffic_secret()
            .expect("pre-transfer client update");
        peer_write
            .update_traffic_secret()
            .expect("peer client update");
        let mut wire = Vec::new();
        peer_write
            .seal_into(ContentType::ApplicationData, b"boundary", 0, &mut wire)
            .expect("boundary record");
        client_records
            .open_in_place(&mut wire)
            .expect("boundary authentication");
        server_records
            .seal_into(ContentType::ApplicationData, b"", 0, &mut wire)
            .expect("cover-shaped record");
        peer_read
            .open_in_place(&mut wire)
            .expect("cover-shaped authentication");
        peer_write
            .seal_into(ContentType::ApplicationData, b"read ahead", 0, &mut wire)
            .expect("read-ahead record");
        let (_, client_secret, client_sequence) = client_records
            .into_exported_state()
            .expect("client export")
            .into_parts();
        let (_, server_secret, server_sequence) = server_records
            .into_exported_state()
            .expect("server export")
            .into_parts();
        let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 443);
        let state = ContinuationState::new(
            suite,
            client_secret,
            client_sequence,
            server_secret,
            server_sequence,
            true,
            SessionKind::Tcp,
            *USER.as_bytes(),
            "public-reality",
            destination.clone(),
            std::mem::take(&mut wire),
            b"prefetched Vision bytes".to_vec(),
            HandoffPolicySnapshot::tcp_placeholder(destination),
        )
        .expect("continuation");
        let mut message = Vec::new();
        let timestamp = unix_seconds().expect("clock");
        seal_transfer(
            &state,
            &HandoffPsk::new(PSK),
            &StaticX25519Key::new(&LANDING_SECRET).public_key(),
            [0x44; 32],
            timestamp,
            &mut message,
        )
        .expect("sealed v3 transfer");
        drop(state);
        let handler = test_landing_handler();
        let state = open_transfer(&message, &handler.keys, &handler.replay, timestamp, 30)
            .expect("authenticated v3 transfer")
            .into_state();
        let (exported, user, destination, pending, prefetched, response_pending, kind, tag, policy) =
            state.into_parts().expect("move transferred state");
        assert_eq!(user, *USER.as_bytes());
        assert_eq!(destination.port(), 443);
        assert_eq!(prefetched, b"prefetched Vision bytes");
        assert!(response_pending);
        assert_eq!(kind, SessionKind::Tcp);
        assert_eq!(tag, "public-reality");
        assert_eq!(policy.initial_destination().port(), 443);
        assert!(!policy.allow_destination_rewrites());
        let tls = resume_tls(exported).expect("resume generations");
        let (mut peer, transport) = tokio::io::duplex(4096);
        let (read, write) = tokio::io::split(transport);
        let (mut reader, mut writer) =
            resume_application_halves(read, pending, write, tls, response_pending);
        assert_eq!(
            reader
                .read_application(TEST_TIMEOUT)
                .await
                .expect("pending ciphertext")
                .plaintext(),
            b"read ahead"
        );
        writer
            .write_application(b"after transfer", TEST_TIMEOUT)
            .await
            .expect("resumed write");
        let mut response = read_tls_record(&mut peer, TEST_TIMEOUT)
            .await
            .expect("owed response")
            .into_wire();
        let opened = peer_read
            .open_in_place(&mut response)
            .expect("old-generation response");
        assert_eq!(opened.content_type(), ContentType::Handshake);
        assert_eq!(opened.plaintext(), [24, 0, 0, 1, 0]);
        peer_read
            .update_traffic_secret()
            .expect("response updates peer read");
        let mut application = read_tls_record(&mut peer, TEST_TIMEOUT)
            .await
            .expect("post-response application")
            .into_wire();
        assert_eq!(
            peer_read
                .open_in_place(&mut application)
                .expect("new-generation application")
                .plaintext(),
            b"after transfer"
        );
        peer_write
            .seal_into(ContentType::Handshake, &[24, 0, 0, 1, 1], 0, &mut wire)
            .expect("future requested update");
        peer_write
            .update_traffic_secret()
            .expect("future peer write generation");
        peer.write_all(&wire).await.expect("future update write");
        peer_write
            .seal_into(
                ContentType::ApplicationData,
                b"future client data",
                0,
                &mut wire,
            )
            .expect("future client record");
        peer.write_all(&wire).await.expect("future data write");
        assert!(
            reader
                .read_application(TEST_TIMEOUT)
                .await
                .expect("future update")
                .is_empty()
        );
        assert_eq!(
            reader
                .read_application(TEST_TIMEOUT)
                .await
                .expect("future client data")
                .plaintext(),
            b"future client data"
        );
        writer
            .write_application(b"future server data", TEST_TIMEOUT)
            .await
            .expect("future requested response");
        let mut response = read_tls_record(&mut peer, TEST_TIMEOUT)
            .await
            .expect("future response")
            .into_wire();
        assert_eq!(
            peer_read
                .open_in_place(&mut response)
                .expect("current-generation response")
                .plaintext(),
            [24, 0, 0, 1, 0]
        );
        peer_read
            .update_traffic_secret()
            .expect("future peer read generation");
        let mut application = read_tls_record(&mut peer, TEST_TIMEOUT)
            .await
            .expect("future server application")
            .into_wire();
        assert_eq!(
            peer_read
                .open_in_place(&mut application)
                .expect("future server data")
                .plaintext(),
            b"future server data"
        );
    }
}
