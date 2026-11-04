use std::time::Duration;

use ml_kem::{
    DecapsulationKey768, Seed,
    array::Array as MlKemArray,
    kem::{Decapsulate, KeyExport},
    ml_kem_768::Ciphertext,
};
use tokio::io::{AsyncWriteExt, duplex};
use x25519_dalek::{PublicKey, StaticSecret};

use super::{
    EstablishedTls, ExportedTlsState, RealityHandshakeError, build_server_flight,
    build_server_flight_with_shape, seal_shaped_handshake_record, unpadded_record_wire_len,
};
use crate::protocol::reality::{
    AuthKey, ClientHello, SESSION_ID_LEN, X25519_GROUP, X25519_MLKEM768_GROUP,
    client_hello::fixtures,
    tls13::{
        CertificateIdentity, CipherSuite, ContentType, CoverHandshakePlan,
        CoverHandshakeRecordShape, MAX_TLS_RECORD_WIRE_LEN, ServerHelloTemplate, Tls13KeySchedule,
        Tls13RecordLayer, TrafficKeys, TrafficSecret, change_cipher_spec_record,
        encrypted_extensions, finished_message, read_client_finished,
    },
};

const fn cover_plan(shape: CoverHandshakeRecordShape) -> CoverHandshakePlan {
    CoverHandshakePlan {
        emit_ccs: true,
        shape,
    }
}

#[test]
fn p256_server_agreement_uses_the_advertised_share_and_rejects_invalid_points() {
    let key = crate::crypto::EphemeralP256Key::generate().unwrap();
    let client = client_hello(super::P256_GROUP, &key.public_key());
    let agreed = super::agree_key_share(&client, super::P256_GROUP).unwrap();
    let expected = key.agree(agreed.server_share.as_slice()).unwrap();
    assert_eq!(expected.as_slice(), agreed.shared_secret());
    let target = ServerHelloTemplate::parse(
        &server_hello(super::P256_GROUP, agreed.server_share.as_slice()),
        &client,
    )
    .unwrap();
    assert_eq!(target.key_share_group(), super::P256_GROUP);
    let invalid = client_hello(super::P256_GROUP, &[4; 65]);
    assert!(matches!(
        super::agree_key_share(&invalid, super::P256_GROUP),
        Err(RealityHandshakeError::NonContributoryKey)
    ));
    let unoffered = client_hello(X25519_GROUP, &[3; 32]);
    assert!(
        ServerHelloTemplate::parse(
            &server_hello(super::P256_GROUP, agreed.server_share.as_slice()),
            &unoffered,
        )
        .is_err()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn full_x25519_flight_establishes_only_after_valid_client_finished() {
    let client_secret = StaticSecret::from([0x31; 32]);
    let client_public = PublicKey::from(&client_secret).to_bytes();
    let client = client_hello(X25519_GROUP, &client_public);
    let target = ServerHelloTemplate::parse(&server_hello(X25519_GROUP, &[0x55; 32]), &client)
        .expect("test target must parse");
    let identity = CertificateIdentity::from_seed([0x42; 32]);
    let auth_key = AuthKey::from_test_bytes([0x99; 32]);
    let flight = build_server_flight_with_shape(
        &client,
        &auth_key,
        target,
        &identity,
        Some(b"h2"),
        cover_plan(CoverHandshakeRecordShape::PositionalRecords {
            wire_lens: [37, 838, 286, 58],
            nst_wire_len: Some(139),
        }),
    )
    .expect("server flight must build");
    assert_eq!(
        flight.change_cipher_spec(),
        Some(&change_cipher_spec_record())
    );

    let server_hello = &flight.server_hello_record()[5..];
    let server_public: [u8; 32] = server_hello
        .get(server_hello.len() - 32..)
        .expect("test ServerHello ends with key share")
        .try_into()
        .expect("X25519 server share is fixed");
    let shared = client_secret.diffie_hellman(&PublicKey::from(server_public));
    let mut transcript = client.raw_message().to_vec();
    transcript.extend_from_slice(server_hello);
    let suite = CipherSuite::Aes128GcmSha256;
    let schedule =
        Tls13KeySchedule::new(suite, shared.as_bytes(), &suite.hash().digest(&transcript))
            .expect("client schedule must derive");

    let server_keys = schedule
        .traffic_keys(schedule.server_handshake_secret())
        .expect("server handshake keys must derive");
    let mut server_records =
        Tls13RecordLayer::new(suite, server_keys).expect("server record state must initialize");
    let handshake_wire_len = [37_usize, 838, 286, 58].into_iter().sum();
    let encrypted_records = flight.encrypted_handshake_records();
    let (server_handshake, record_lens, message_types, messages_per_record) =
        open_handshake_records(
            &encrypted_records[..handshake_wire_len],
            &mut server_records,
        );
    assert_eq!(record_lens, [37, 838, 286, 58]);
    assert_eq!(message_types, [8, 11, 15, 20]);
    assert_eq!(messages_per_record, [1, 1, 1, 1]);
    transcript.extend_from_slice(&server_handshake);

    let application = schedule
        .application_traffic_secrets(&suite.hash().digest(&transcript))
        .expect("application secrets must derive");
    let server_application_keys = schedule
        .traffic_keys(application.server())
        .expect("server application keys must derive");
    let mut server_application = Tls13RecordLayer::new(suite, server_application_keys)
        .expect("server application state must initialize");
    let mut ticket = encrypted_records[handshake_wire_len..].to_vec();
    assert_eq!(ticket.len(), 139);
    let opened_ticket = server_application
        .open_in_place(&mut ticket)
        .expect("fake ticket record must use server application keys");
    assert_eq!(opened_ticket.content_type(), ContentType::ApplicationData);
    assert!(opened_ticket.plaintext().is_empty());
    assert_eq!(server_application.records_used(), 1);

    let finished_data = schedule
        .finished_verify_data(
            schedule.client_handshake_secret(),
            &suite.hash().digest(&transcript),
        )
        .expect("client Finished must derive");
    let finished = finished_message(finished_data.as_bytes()).expect("client Finished must encode");
    let client_keys = schedule
        .traffic_keys(schedule.client_handshake_secret())
        .expect("client handshake keys must derive");
    let mut client_records =
        Tls13RecordLayer::new(suite, client_keys).expect("client record state must initialize");
    let mut record = Vec::new();
    client_records
        .seal_into(ContentType::Handshake, &finished, 0, &mut record)
        .expect("client Finished must seal");
    let mut client_wire = change_cipher_spec_record().to_vec();
    client_wire.extend_from_slice(&record);
    let (mut client_io, mut server_io) = duplex(client_wire.len());
    client_io
        .write_all(&client_wire)
        .await
        .expect("client Finished flight must be written");
    let mut established = read_client_finished(&mut server_io, flight, Duration::from_secs(1))
        .await
        .expect("valid ClientFinished must establish TLS");
    assert_eq!(established.suite(), suite);
    assert_eq!(established.client_records_mut().records_used(), 0);
    assert_eq!(established.server_records_mut().records_used(), 1);

    let client_application_keys = schedule
        .traffic_keys(application.client())
        .expect("client application keys must derive");
    let mut client_application = Tls13RecordLayer::new(suite, client_application_keys)
        .expect("client application state must initialize");
    let mut application_record = Vec::new();
    client_application
        .seal_into(
            ContentType::ApplicationData,
            b"VLESS request",
            0,
            &mut application_record,
        )
        .expect("client application record must seal");
    let opened = established
        .client_records_mut()
        .open_in_place(&mut application_record)
        .expect("established server must authenticate application data");
    assert_eq!(opened.plaintext(), b"VLESS request");
}

#[test]
fn fake_ticket_accepts_the_minimum_and_maximum_tls_record_wire_lengths() {
    let client_secret = StaticSecret::from([0x31; 32]);
    let client_public = PublicKey::from(&client_secret).to_bytes();

    for nst_wire_len in [22, MAX_TLS_RECORD_WIRE_LEN] {
        let client = client_hello(X25519_GROUP, &client_public);
        let target = ServerHelloTemplate::parse(&server_hello(X25519_GROUP, &[0x55; 32]), &client)
            .expect("test target must parse");
        let flight = build_server_flight_with_shape(
            &client,
            &AuthKey::from_test_bytes([0x99; 32]),
            target,
            &CertificateIdentity::from_seed([0x42; 32]),
            Some(b"h2"),
            cover_plan(CoverHandshakeRecordShape::PositionalRecords {
                wire_lens: [37, 838, 286, 58],
                nst_wire_len: Some(nst_wire_len),
            }),
        )
        .expect("boundary-sized fake ticket must build");

        let handshake_wire_len = [37_usize, 838, 286, 58].into_iter().sum::<usize>();
        assert_eq!(
            flight.encrypted_handshake_records().len(),
            handshake_wire_len + nst_wire_len
        );
    }
}

#[test]
fn fake_ticket_rejects_wire_lengths_outside_tls_record_bounds() {
    let client_secret = StaticSecret::from([0x31; 32]);
    let client_public = PublicKey::from(&client_secret).to_bytes();

    for nst_wire_len in [21, MAX_TLS_RECORD_WIRE_LEN + 1] {
        let client = client_hello(X25519_GROUP, &client_public);
        let target = ServerHelloTemplate::parse(&server_hello(X25519_GROUP, &[0x55; 32]), &client)
            .expect("test target must parse");
        let result = build_server_flight_with_shape(
            &client,
            &AuthKey::from_test_bytes([0x99; 32]),
            target,
            &CertificateIdentity::from_seed([0x42; 32]),
            Some(b"h2"),
            cover_plan(CoverHandshakeRecordShape::PositionalRecords {
                wire_lens: [37, 838, 286, 58],
                nst_wire_len: Some(nst_wire_len),
            }),
        );
        assert!(matches!(result, Err(RealityHandshakeError::Record)));
    }
}

#[test]
fn large_cover_record_coalesces_and_pads_the_unchanged_handshake_messages() {
    let client_secret = StaticSecret::from([0x31; 32]);
    let client_public = PublicKey::from(&client_secret).to_bytes();
    let client = client_hello(X25519_GROUP, &client_public);
    let target = ServerHelloTemplate::parse(&server_hello(X25519_GROUP, &[0x55; 32]), &client)
        .expect("test target must parse");
    let flight = build_server_flight_with_shape(
        &client,
        &AuthKey::from_test_bytes([0x99; 32]),
        target,
        &CertificateIdentity::from_seed([0x42; 32]),
        Some(b"h2"),
        cover_plan(CoverHandshakeRecordShape::Coalesced { wire_len: 605 }),
    )
    .expect("coalesced cover shape must build");

    let server_hello = &flight.server_hello_record()[5..];
    let server_public: [u8; 32] = server_hello
        .get(server_hello.len() - 32..)
        .expect("test ServerHello ends with key share")
        .try_into()
        .expect("X25519 server share is fixed");
    let shared = client_secret.diffie_hellman(&PublicKey::from(server_public));
    let mut transcript = client.raw_message().to_vec();
    transcript.extend_from_slice(server_hello);
    let suite = CipherSuite::Aes128GcmSha256;
    let schedule =
        Tls13KeySchedule::new(suite, shared.as_bytes(), &suite.hash().digest(&transcript))
            .expect("client schedule must derive");
    let server_keys = schedule
        .traffic_keys(schedule.server_handshake_secret())
        .expect("server handshake keys must derive");
    let mut server_records =
        Tls13RecordLayer::new(suite, server_keys).expect("record state must initialize");

    let (_plaintext, record_lens, message_types, messages_per_record) =
        open_handshake_records(flight.encrypted_handshake_records(), &mut server_records);

    assert_eq!(record_lens, [605]);
    assert_eq!(message_types, [8, 11, 15, 20]);
    assert_eq!(messages_per_record, [4]);
}

#[test]
fn ccs_less_cover_plan_omits_the_compatibility_record() {
    let client_secret = StaticSecret::from([0x31; 32]);
    let client_public = PublicKey::from(&client_secret).to_bytes();
    let client = client_hello(X25519_GROUP, &client_public);
    let target = ServerHelloTemplate::parse(&server_hello(X25519_GROUP, &[0x55; 32]), &client)
        .expect("test target must parse");
    let flight = build_server_flight_with_shape(
        &client,
        &AuthKey::from_test_bytes([0x99; 32]),
        target,
        &CertificateIdentity::from_seed([0x42; 32]),
        Some(b"h2"),
        CoverHandshakePlan {
            emit_ccs: false,
            shape: CoverHandshakeRecordShape::Coalesced { wire_len: 605 },
        },
    )
    .expect("CCS-less cover plan must build");

    assert_eq!(flight.change_cipher_spec(), None);
    assert_eq!(
        flight.wire().len(),
        flight.server_hello_record().len() + flight.encrypted_handshake_records().len()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn coalesced_flight_establishes_only_after_valid_client_finished() {
    let client_secret = StaticSecret::from([0x31; 32]);
    let client_public = PublicKey::from(&client_secret).to_bytes();
    let client = client_hello(X25519_GROUP, &client_public);
    let target = ServerHelloTemplate::parse(&server_hello(X25519_GROUP, &[0x55; 32]), &client)
        .expect("test target must parse");
    let identity = CertificateIdentity::from_seed([0x42; 32]);
    let auth_key = AuthKey::from_test_bytes([0x99; 32]);
    let flight = build_server_flight_with_shape(
        &client,
        &auth_key,
        target,
        &identity,
        Some(b"h2"),
        cover_plan(CoverHandshakeRecordShape::Coalesced { wire_len: 605 }),
    )
    .expect("coalesced server flight must build");
    assert_eq!(
        flight.change_cipher_spec(),
        Some(&change_cipher_spec_record())
    );

    let server_hello = &flight.server_hello_record()[5..];
    let server_public: [u8; 32] = server_hello
        .get(server_hello.len() - 32..)
        .expect("test ServerHello ends with key share")
        .try_into()
        .expect("X25519 server share is fixed");
    let shared = client_secret.diffie_hellman(&PublicKey::from(server_public));
    let mut transcript = client.raw_message().to_vec();
    transcript.extend_from_slice(server_hello);
    let suite = CipherSuite::Aes128GcmSha256;
    let schedule =
        Tls13KeySchedule::new(suite, shared.as_bytes(), &suite.hash().digest(&transcript))
            .expect("client schedule must derive");

    let server_keys = schedule
        .traffic_keys(schedule.server_handshake_secret())
        .expect("server handshake keys must derive");
    let mut server_records =
        Tls13RecordLayer::new(suite, server_keys).expect("server record state must initialize");
    let (server_handshake, record_lens, message_types, messages_per_record) =
        open_handshake_records(flight.encrypted_handshake_records(), &mut server_records);
    assert_eq!(record_lens, [605]);
    assert_eq!(message_types, [8, 11, 15, 20]);
    assert_eq!(messages_per_record, [4]);
    transcript.extend_from_slice(&server_handshake);

    let finished_data = schedule
        .finished_verify_data(
            schedule.client_handshake_secret(),
            &suite.hash().digest(&transcript),
        )
        .expect("client Finished must derive");
    let finished = finished_message(finished_data.as_bytes()).expect("client Finished must encode");
    let client_keys = schedule
        .traffic_keys(schedule.client_handshake_secret())
        .expect("client handshake keys must derive");
    let mut client_records =
        Tls13RecordLayer::new(suite, client_keys).expect("client record state must initialize");
    let mut record = Vec::new();
    client_records
        .seal_into(ContentType::Handshake, &finished, 0, &mut record)
        .expect("client Finished must seal");
    let mut client_wire = change_cipher_spec_record().to_vec();
    client_wire.extend_from_slice(&record);
    let (mut client_io, mut server_io) = duplex(client_wire.len());
    client_io
        .write_all(&client_wire)
        .await
        .expect("client Finished flight must be written");
    let mut established = read_client_finished(&mut server_io, flight, Duration::from_secs(1))
        .await
        .expect("valid ClientFinished must establish TLS");
    assert_eq!(established.suite(), suite);
    assert_eq!(established.client_records_mut().records_used(), 0);
    assert_eq!(established.server_records_mut().records_used(), 0);

    let application = schedule
        .application_traffic_secrets(&suite.hash().digest(&transcript))
        .expect("application secrets must derive");
    let client_application_keys = schedule
        .traffic_keys(application.client())
        .expect("client application keys must derive");
    let mut client_application = Tls13RecordLayer::new(suite, client_application_keys)
        .expect("client application state must initialize");
    let mut application_record = Vec::new();
    client_application
        .seal_into(
            ContentType::ApplicationData,
            b"VLESS request",
            0,
            &mut application_record,
        )
        .expect("client application record must seal");
    let opened = established
        .client_records_mut()
        .open_in_place(&mut application_record)
        .expect("established server must authenticate application data");
    assert_eq!(opened.plaintext(), b"VLESS request");
}

#[test]
fn authenticated_record_partitioning_preserves_exact_handshake_bytes() {
    let messages: [&[u8]; 4] = [
        &[8, 0, 0, 1, 0xa1],
        &[11, 0, 0, 2, 0xb1, 0xb2],
        &[15, 0, 0, 3, 0xc1, 0xc2, 0xc3],
        &[20, 0, 0, 1, 0xd1],
    ];
    let expected = messages.concat();
    let make_layer = || {
        let keys = TrafficKeys::from_raw_parts(&[0x11; 16], [0x22; 12])
            .expect("fixed test traffic keys must be valid");
        Tls13RecordLayer::new(CipherSuite::Aes128GcmSha256, keys)
            .expect("fixed test record layer must initialize")
    };

    let mut compact_writer = make_layer();
    let mut compact_scratch = Vec::new();
    let mut compact_wire = Vec::new();
    seal_shaped_handshake_record(
        &mut compact_writer,
        &expected,
        unpadded_record_wire_len(expected.len()).expect("compact record must fit"),
        &mut compact_scratch,
        &mut compact_wire,
    )
    .expect("compact handshake record must seal");

    let mut shaped_writer = make_layer();
    let mut shaped_scratch = Vec::new();
    let mut shaped_wire = Vec::new();
    for (index, message) in messages.iter().enumerate() {
        let target_wire_len =
            unpadded_record_wire_len(message.len()).expect("positional record must fit") + index;
        seal_shaped_handshake_record(
            &mut shaped_writer,
            message,
            target_wire_len,
            &mut shaped_scratch,
            &mut shaped_wire,
        )
        .expect("positional handshake record must seal");
    }

    let (compact_plaintext, compact_lens, compact_types, compact_counts) =
        open_handshake_records(&compact_wire, &mut make_layer());
    let (shaped_plaintext, shaped_lens, shaped_types, shaped_counts) =
        open_handshake_records(&shaped_wire, &mut make_layer());

    assert_eq!(compact_plaintext, expected);
    assert_eq!(shaped_plaintext, expected);
    assert_eq!(compact_plaintext, shaped_plaintext);
    assert_eq!(compact_lens.len(), 1);
    assert_eq!(shaped_lens.len(), 4);
    assert_eq!(compact_types, [8, 11, 15, 20]);
    assert_eq!(shaped_types, compact_types);
    assert_eq!(compact_counts, [4]);
    assert_eq!(shaped_counts, [1, 1, 1, 1]);
}

#[test]
fn cover_record_shorter_than_the_handshake_fails_before_wire_escape() {
    let client_secret = StaticSecret::from([0x31; 32]);
    let client_public = PublicKey::from(&client_secret).to_bytes();
    let client = client_hello(X25519_GROUP, &client_public);
    let target = ServerHelloTemplate::parse(&server_hello(X25519_GROUP, &[0x55; 32]), &client)
        .expect("test target must parse");

    let result = build_server_flight_with_shape(
        &client,
        &AuthKey::from_test_bytes([0x99; 32]),
        target,
        &CertificateIdentity::from_seed([0x42; 32]),
        Some(b"h2"),
        cover_plan(CoverHandshakeRecordShape::Coalesced { wire_len: 128 }),
    );

    assert!(matches!(result, Err(RealityHandshakeError::Record)));
}

#[test]
fn no_alpn_cover_slot_drops_the_unaffordable_client_alpn() {
    // A no-ALPN cover emits a minimal 28-wire-byte EncryptedExtensions
    // record (6-byte message + inner type + AEAD tag + header); the
    // chrome client's "h2" EE needs 37, so the generated EE must claim
    // no ALPN — exactly what the cover itself emitted.
    let ee = shaped_flight_ee_message(
        &[b"h2", b"http/1.1"],
        Some(b"h2"),
        CoverHandshakeRecordShape::PositionalRecords {
            wire_lens: [28, 838, 286, 58],
            nst_wire_len: None,
        },
    );

    assert_eq!(
        ee,
        encrypted_extensions(None).expect("empty EE must encode")
    );
}

#[test]
fn alpn_less_client_with_no_alpn_cover_stays_alpn_less() {
    let ee = shaped_flight_ee_message(
        &[],
        None,
        CoverHandshakeRecordShape::PositionalRecords {
            wire_lens: [28, 838, 286, 58],
            nst_wire_len: None,
        },
    );

    assert_eq!(
        ee,
        encrypted_extensions(None).expect("empty EE must encode")
    );
}

#[test]
fn alpn_cover_slot_keeps_the_matching_client_alpn() {
    for (slot, protocol) in [(37_usize, b"h2".as_slice()), (43, b"http/1.1")] {
        let ee = shaped_flight_ee_message(
            &[protocol],
            Some(protocol),
            CoverHandshakeRecordShape::PositionalRecords {
                wire_lens: [slot, 838, 286, 58],
                nst_wire_len: None,
            },
        );

        assert_eq!(
            ee,
            encrypted_extensions(Some(protocol)).expect("ALPN EE must encode")
        );
    }
}

#[test]
fn undersized_cover_slot_falls_back_to_the_first_fitting_offered_alpn() {
    // The client prefers http/1.1 (43 wire bytes), but the cover's
    // 37-byte EE slot only fits "h2" — the shorter offered protocol the
    // cover must have selected.
    let ee = shaped_flight_ee_message(
        &[b"http/1.1", b"h2"],
        Some(b"http/1.1"),
        CoverHandshakeRecordShape::PositionalRecords {
            wire_lens: [37, 838, 286, 58],
            nst_wire_len: None,
        },
    );

    assert_eq!(
        ee,
        encrypted_extensions(Some(b"h2")).expect("h2 EE must encode")
    );
}

#[test]
fn coalesced_cover_shape_keeps_the_caller_alpn_selection() {
    let ee = shaped_flight_ee_message(
        &[b"h2"],
        Some(b"h2"),
        CoverHandshakeRecordShape::Coalesced { wire_len: 605 },
    );

    assert_eq!(
        ee,
        encrypted_extensions(Some(b"h2")).expect("h2 EE must encode")
    );
}

#[test]
fn hybrid_share_combines_mlkem_then_x25519_like_xray() {
    let mut seed = Seed::default();
    seed.copy_from_slice(&[0x61; 64]);
    let decapsulation_key = DecapsulationKey768::from_seed(seed);
    let encapsulation_key = decapsulation_key.encapsulation_key().to_bytes();
    let client_secret = StaticSecret::from([0x31; 32]);
    let client_public = PublicKey::from(&client_secret).to_bytes();
    let mut client_share = encapsulation_key.as_slice().to_vec();
    client_share.extend_from_slice(&client_public);
    let client = client_hello(X25519_MLKEM768_GROUP, &client_share);
    let target = ServerHelloTemplate::parse(
        &server_hello(X25519_MLKEM768_GROUP, &[0x55; 1_120]),
        &client,
    )
    .expect("hybrid target must parse");
    let flight = build_server_flight(
        &client,
        &AuthKey::from_test_bytes([0x99; 32]),
        target,
        &CertificateIdentity::from_seed([0x42; 32]),
        Some(b"h2"),
    )
    .expect("hybrid server flight must build");

    let server_hello = &flight.server_hello_record()[5..];
    let server_share = server_hello
        .get(server_hello.len() - 1_120..)
        .expect("hybrid ServerHello ends with its key share");
    let ciphertext: Ciphertext = MlKemArray::try_from(
        server_share
            .get(..1_088)
            .expect("hybrid share contains ML-KEM ciphertext"),
    )
    .expect("ML-KEM ciphertext has fixed size");
    let mlkem_shared = decapsulation_key.decapsulate(&ciphertext);
    let server_public: [u8; 32] = server_share
        .get(1_088..)
        .expect("hybrid share contains X25519 public key")
        .try_into()
        .expect("X25519 public key has fixed size");
    let x25519_shared = client_secret.diffie_hellman(&PublicKey::from(server_public));
    let mut shared = [0_u8; 64];
    shared[..32].copy_from_slice(mlkem_shared.as_ref());
    shared[32..].copy_from_slice(x25519_shared.as_bytes());

    let mut transcript = client.raw_message().to_vec();
    transcript.extend_from_slice(server_hello);
    let suite = CipherSuite::Aes128GcmSha256;
    let schedule = Tls13KeySchedule::new(suite, &shared, &suite.hash().digest(&transcript))
        .expect("hybrid client schedule must derive");
    let keys = schedule
        .traffic_keys(schedule.server_handshake_secret())
        .expect("hybrid server keys must derive");
    let mut records =
        Tls13RecordLayer::new(suite, keys).expect("hybrid record state must initialize");
    let mut encrypted = flight.encrypted_handshake_record().to_vec();
    let opened = records
        .open_in_place(&mut encrypted)
        .expect("hybrid flight must authenticate with combined shared secret");
    assert_eq!(opened.content_type(), ContentType::Handshake);
}

#[test]
fn unoffered_alpn_is_rejected_before_flight() {
    let client_secret = StaticSecret::from([0x31; 32]);
    let client_public = PublicKey::from(&client_secret).to_bytes();
    let client = client_hello(X25519_GROUP, &client_public);
    let target = ServerHelloTemplate::parse(&server_hello(X25519_GROUP, &[0x55; 32]), &client)
        .expect("test target must parse");
    let result = build_server_flight(
        &client,
        &AuthKey::from_test_bytes([0x99; 32]),
        target,
        &CertificateIdentity::from_seed([0x42; 32]),
        Some(b"http/1.1"),
    );
    assert!(matches!(result, Err(RealityHandshakeError::AlpnNotOffered)));
}

#[test]
fn exported_session_state_resumes_interoperation_with_the_client() {
    let suite = CipherSuite::Aes256GcmSha384;
    // `established` plays the server's view; `client_*` plays the remote
    // client holding identical key material for each direction.
    let make_layer = || {
        let secret = TrafficSecret::from_bytes(suite.hash(), &[0x42; 48])
            .expect("test traffic secret must match the suite hash");
        Tls13RecordLayer::from_traffic_secret(suite, secret).expect("test layer must initialize")
    };
    let mut client_writer = make_layer();
    let mut client_reader = make_layer();
    let mut established = EstablishedTls::from_test_records(suite, make_layer(), make_layer());

    // Two client-direction records before the handoff boundary.
    for index in 0..2_u8 {
        let mut record = Vec::new();
        client_writer
            .seal_into(ContentType::ApplicationData, &[index; 32], 0, &mut record)
            .expect("client record must seal");
        established
            .client_records_mut()
            .open_in_place(&mut record)
            .expect("server must open the client record");
    }

    let (client_records, server_records) = established.into_record_layers();
    let client_exported = client_records
        .into_exported_state()
        .expect("application state must export");
    let server_exported = server_records
        .into_exported_state()
        .expect("application state must export");
    assert_eq!(client_exported.sequence(), 2);
    assert_eq!(server_exported.sequence(), 0);
    let exported = ExportedTlsState::from_directions(client_exported, server_exported);
    let rendered = format!("{exported:?}");
    assert!(rendered.contains("[REDACTED]"));

    let mut resumed =
        EstablishedTls::from_exported_state(exported).expect("exported session state must rebuild");
    assert_eq!(resumed.suite(), suite);

    // Uplink continuation: the client's third record opens on the resumed
    // client-direction layer.
    let mut record = Vec::new();
    client_writer
        .seal_into(ContentType::ApplicationData, b"third", 0, &mut record)
        .expect("client continuation must seal");
    let opened = resumed
        .client_records_mut()
        .open_in_place(&mut record)
        .expect("resumed layer must open the client continuation");
    assert_eq!(opened.plaintext(), b"third");
    assert_eq!(resumed.client_records_mut().records_used(), 3);

    // Downlink start: the resumed server-direction layer is at sequence 0
    // and its first record opens on the client's untouched reader.
    let mut downlink = Vec::new();
    resumed
        .server_records_mut()
        .seal_into(ContentType::ApplicationData, b"response", 0, &mut downlink)
        .expect("resumed layer must seal");
    let opened = client_reader
        .open_in_place(&mut downlink)
        .expect("client must open the resumed downlink");
    assert_eq!(opened.plaintext(), b"response");
}

fn client_hello(group: u16, key_exchange: &[u8]) -> ClientHello {
    ClientHello::parse_message(&fixtures::client_hello_with_key_share(
        [0x44; 32],
        &[0x11; SESSION_ID_LEN],
        "www.example.com",
        &[b"h2"],
        group,
        key_exchange,
    ))
    .expect("test ClientHello must parse")
}

/// Builds a cover-shaped flight and returns its generated
/// EncryptedExtensions message as the client would open it.
fn shaped_flight_ee_message(
    offered_alpn: &[&[u8]],
    selected_alpn: Option<&[u8]>,
    shape: CoverHandshakeRecordShape,
) -> Vec<u8> {
    let client_secret = StaticSecret::from([0x31; 32]);
    let client_public = PublicKey::from(&client_secret).to_bytes();
    let client = ClientHello::parse_message(&fixtures::client_hello_with_key_share(
        [0x44; 32],
        &[0x11; SESSION_ID_LEN],
        "www.example.com",
        offered_alpn,
        X25519_GROUP,
        &client_public,
    ))
    .expect("test ClientHello must parse");
    let target = ServerHelloTemplate::parse(&server_hello(X25519_GROUP, &[0x55; 32]), &client)
        .expect("test target must parse");
    let flight = build_server_flight_with_shape(
        &client,
        &AuthKey::from_test_bytes([0x99; 32]),
        target,
        &CertificateIdentity::from_seed([0x42; 32]),
        selected_alpn,
        cover_plan(shape),
    )
    .expect("cover-shaped flight must build");

    let server_hello = &flight.server_hello_record()[5..];
    let server_public: [u8; 32] = server_hello
        .get(server_hello.len() - 32..)
        .expect("test ServerHello ends with key share")
        .try_into()
        .expect("X25519 server share is fixed");
    let shared = client_secret.diffie_hellman(&PublicKey::from(server_public));
    let mut transcript = client.raw_message().to_vec();
    transcript.extend_from_slice(server_hello);
    let suite = CipherSuite::Aes128GcmSha256;
    let schedule =
        Tls13KeySchedule::new(suite, shared.as_bytes(), &suite.hash().digest(&transcript))
            .expect("client schedule must derive");
    let server_keys = schedule
        .traffic_keys(schedule.server_handshake_secret())
        .expect("server handshake keys must derive");
    let mut server_records =
        Tls13RecordLayer::new(suite, server_keys).expect("record state must initialize");

    let wire = flight.encrypted_handshake_records();
    let body_len = usize::from(u16::from_be_bytes(
        wire.get(3..5)
            .expect("first record header must be complete")
            .try_into()
            .expect("record header length is fixed"),
    ));
    let mut first_record = wire
        .get(..5 + body_len)
        .expect("first encrypted record must be complete")
        .to_vec();
    let opened = server_records
        .open_in_place(&mut first_record)
        .expect("first record must authenticate");
    let plaintext = opened.plaintext();
    assert_eq!(plaintext.first(), Some(&8));
    let message_len = (usize::from(plaintext[1]) << 16)
        | (usize::from(plaintext[2]) << 8)
        | usize::from(plaintext[3]);
    plaintext
        .get(..4 + message_len)
        .expect("EE message must be complete")
        .to_vec()
}

fn open_handshake_records(
    wire: &[u8],
    records: &mut Tls13RecordLayer,
) -> (Vec<u8>, Vec<usize>, Vec<u8>, Vec<usize>) {
    let mut offset = 0_usize;
    let mut plaintext = Vec::new();
    let mut record_lens = Vec::new();
    let mut message_types = Vec::new();
    let mut messages_per_record = Vec::new();
    while offset < wire.len() {
        let header = wire
            .get(offset..offset + 5)
            .expect("encrypted record header must be complete");
        assert_eq!(header[0], 23);
        assert_eq!(&header[1..3], &[3, 3]);
        let body_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let record_len = 5 + body_len;
        let record_end = offset + record_len;
        let mut encrypted = wire
            .get(offset..record_end)
            .expect("encrypted record body must be complete")
            .to_vec();
        let opened = records
            .open_in_place(&mut encrypted)
            .expect("encrypted handshake record must authenticate");
        assert_eq!(opened.content_type(), ContentType::Handshake);
        let record_plaintext = opened.plaintext();
        let mut message_offset = 0_usize;
        let mut record_message_count = 0_usize;
        while message_offset < record_plaintext.len() {
            let message_header = record_plaintext
                .get(message_offset..message_offset + 4)
                .expect("handshake message header must be complete");
            let message_len = (usize::from(message_header[1]) << 16)
                | (usize::from(message_header[2]) << 8)
                | usize::from(message_header[3]);
            let message_end = message_offset + 4 + message_len;
            assert!(message_end <= record_plaintext.len());
            message_types.push(message_header[0]);
            record_message_count += 1;
            message_offset = message_end;
        }
        assert_eq!(message_offset, record_plaintext.len());
        plaintext.extend_from_slice(record_plaintext);
        record_lens.push(record_len);
        messages_per_record.push(record_message_count);
        offset = record_end;
    }
    assert_eq!(offset, wire.len());
    (plaintext, record_lens, message_types, messages_per_record)
}

fn server_hello(group: u16, key_exchange: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303_u16.to_be_bytes());
    body.extend_from_slice(&[0x33; 32]);
    body.push(SESSION_ID_LEN as u8);
    body.extend_from_slice(&[0x11; SESSION_ID_LEN]);
    body.extend_from_slice(&0x1301_u16.to_be_bytes());
    body.push(0);
    let mut extensions = Vec::new();
    push_extension(&mut extensions, 0x002b, &0x0304_u16.to_be_bytes());
    let mut share = Vec::new();
    share.extend_from_slice(&group.to_be_bytes());
    share.extend_from_slice(&(key_exchange.len() as u16).to_be_bytes());
    share.extend_from_slice(key_exchange);
    push_extension(&mut extensions, 0x0033, &share);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    let mut message = vec![2];
    let length = body.len() as u32;
    message.extend_from_slice(&length.to_be_bytes()[1..]);
    message.extend_from_slice(&body);
    message
}

fn push_extension(output: &mut Vec<u8>, extension_type: u16, value: &[u8]) {
    output.extend_from_slice(&extension_type.to_be_bytes());
    output.extend_from_slice(&(value.len() as u16).to_be_bytes());
    output.extend_from_slice(value);
}
