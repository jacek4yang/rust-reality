use std::path::Path;

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use x25519_dalek::{PublicKey, StaticSecret};

use super::*;
use crate::config::load_bytes;
use crate::protocol::reality::tls13::{
    CertificateIdentity, ContentType, CoverHandshakePlan, CoverHandshakeRecordShape,
    build_server_flight, build_server_flight_with_shape,
};
use crate::protocol::reality::{
    AuthPlaintext, CLIENT_VERSION, RealityAuthenticator, SESSION_ID_LEN, X25519_GROUP,
    build_client_hello,
};

const NAME: &str = "www.example.com";
const ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const SHORT_ID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const SHORT_ID_HEX: &str = "0102030405060708";
const USER: &str = "11111111-1111-4111-8111-111111111111";

fn plaintext(now: u32) -> AuthPlaintext {
    AuthPlaintext {
        version: CLIENT_VERSION,
        time: now,
        short_id: SHORT_ID,
    }
}

fn authenticator(private: [u8; 32]) -> (RealityAuthenticator, [u8; 32]) {
    let public = PublicKey::from(&StaticSecret::from(private)).to_bytes();
    let json = format!(
        r#"{{
  "role": "entry",
  "listeners": [{{ "port": 443 }}],
  "reality": {{
    "cover": "{name}:443",
    "privateKey": "{private_key}",
    "serverNames": ["{name}"],
    "maxTimeDiffMs": 60000
  }},
  "users": [{{
    "id": "{user}",
    "shortIds": ["{short_id}"],
    "label": "alice"
  }}],
  "routing": {{ "default": "direct" }}
}}"#,
        name = NAME,
        private_key = BASE64_URL_SAFE_NO_PAD.encode(private),
        user = USER,
        short_id = SHORT_ID_HEX,
    );
    let validated = load_bytes(Path::new("client-handshake-entry.json"), json.as_bytes())
        .expect("entry config must load");
    let node = validated.into_node();
    let entry = node.as_entry().expect("role is entry");
    (
        RealityAuthenticator::from_entry(entry).expect("authenticator"),
        public,
    )
}

fn synthetic_server_hello(client: &ClientHello, group: u16, key_exchange: &[u8]) -> Vec<u8> {
    let session = client.session_id().expect("session id");
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303_u16.to_be_bytes());
    body.extend_from_slice(&[0x33; 32]);
    body.push(u8::try_from(session.len()).expect("session len"));
    body.extend_from_slice(session);
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
    let length = u32::try_from(body.len()).expect("body");
    message.extend_from_slice(&length.to_be_bytes()[1..]);
    message.extend_from_slice(&body);
    message
}

fn push_extension(output: &mut Vec<u8>, extension_type: u16, value: &[u8]) {
    output.extend_from_slice(&extension_type.to_be_bytes());
    output.extend_from_slice(&(value.len() as u16).to_be_bytes());
    output.extend_from_slice(value);
}

async fn handshake_pair(suite_wire: u16) -> (ClientSession, EstablishedTls, CipherSuite) {
    let (authenticator, server_public) = authenticator([0x42; 32]);
    let keys = ClientKeyAgreement::generate().expect("keys");
    let now = 1_700_000_000_u32;
    let (record, auth_key) = build_client_hello(NAME, ALPN, &keys, &server_public, plaintext(now))
        .expect("client hello");
    let client = ClientHello::parse_message(record.message()).expect("parse");
    let auth = authenticator
        .authenticate(&client, u64::from(now))
        .expect("authenticate");
    assert_eq!(auth.auth_key().as_bytes(), auth_key.as_bytes());

    let mut target_message = synthetic_server_hello(&client, X25519_GROUP, &[0x55; 32]);
    // Patch suite into the synthetic ServerHello when requested.
    if suite_wire != 0x1301 {
        let session_len = SESSION_ID_LEN;
        let suite_offset = 6 + 32 + 1 + session_len;
        target_message[suite_offset..suite_offset + 2].copy_from_slice(&suite_wire.to_be_bytes());
    }
    let target = ServerHelloTemplate::parse(&target_message, &client).expect("target");
    let identity = CertificateIdentity::from_seed([0x42; 32]);
    let flight = build_server_flight(&client, auth.auth_key(), target, &identity, Some(b"h2"))
        .expect("server flight");

    let (session, established) =
        establish_with_server_flight(&record, keys, &auth_key, ALPN, flight)
            .await
            .expect("handshake");
    let suite = session.negotiated().suite;
    (session, established, suite)
}

#[tokio::test(flavor = "current_thread")]
async fn browser_profiles_authenticate_and_finish_every_offered_group() {
    use super::super::{BrowserFingerprint, P256_GROUP, X25519_MLKEM768_GROUP};
    for profile in [BrowserFingerprint::Chrome, BrowserFingerprint::Firefox] {
        for group in [X25519_GROUP, X25519_MLKEM768_GROUP, P256_GROUP] {
            if profile == BrowserFingerprint::Chrome && group == P256_GROUP {
                continue;
            }
            let (authenticator, server_public) = authenticator([0x42; 32]);
            let keys = ClientKeyAgreement::for_profile(profile).unwrap();
            let now = 1_700_000_000;
            let (record, auth_key) =
                build_client_hello(NAME, ALPN, &keys, &server_public, plaintext(now)).unwrap();
            let client = ClientHello::parse_message(record.message()).unwrap();
            let auth = authenticator.authenticate(&client, u64::from(now)).unwrap();
            let dummy = vec![
                0x55;
                match group {
                    P256_GROUP => 65,
                    X25519_MLKEM768_GROUP => 1120,
                    _ => 32,
                }
            ];
            let target_message = synthetic_server_hello(&client, group, &dummy);
            let target = ServerHelloTemplate::parse(&target_message, &client).unwrap();
            let identity = CertificateIdentity::from_seed([0x42; 32]);
            let flight =
                build_server_flight(&client, auth.auth_key(), target, &identity, Some(b"h2"))
                    .unwrap();
            let (session, _) = establish_with_server_flight(&record, keys, &auth_key, ALPN, flight)
                .await
                .unwrap();
            assert_eq!(session.negotiated().key_share_group, group);
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn in_process_duplex_establishes_and_exchanges_application_data() {
    let (mut client, mut server, suite) = handshake_pair(0x1301).await;
    assert_eq!(suite, CipherSuite::Aes128GcmSha256);
    assert_eq!(client.negotiated().alpn.as_deref(), Some(b"h2".as_slice()));
    assert_eq!(client.negotiated().key_share_group, X25519_GROUP);

    let payload = b"unified-client-pr2";
    let mut record = Vec::new();
    client
        .write_mut()
        .seal_into(ContentType::ApplicationData, payload, 0, &mut record)
        .expect("client seal");
    let opened = server
        .client_records_mut()
        .open_in_place(&mut record)
        .expect("server open");
    assert_eq!(opened.content_type(), ContentType::ApplicationData);
    assert_eq!(opened.plaintext(), payload);

    let mut reply = Vec::new();
    server
        .server_records_mut()
        .seal_into(ContentType::ApplicationData, b"ack", 0, &mut reply)
        .expect("server seal");
    let opened = client
        .read_mut()
        .open_in_place(&mut reply)
        .expect("client open");
    assert_eq!(opened.plaintext(), b"ack");
}

#[tokio::test(flavor = "current_thread")]
async fn key_update_rotates_both_directions() {
    let (mut client, mut server, _) = handshake_pair(0x1301).await;
    client.update_write_secret().expect("client write update");
    server
        .client_records_mut()
        .update_traffic_secret()
        .expect("server read-from-client update");
    client.update_read_secret().expect("client read update");
    server
        .server_records_mut()
        .update_traffic_secret()
        .expect("server write-to-client update");

    let mut record = Vec::new();
    client
        .write_mut()
        .seal_into(ContentType::ApplicationData, b"after-ku", 0, &mut record)
        .expect("seal");
    let opened = server
        .client_records_mut()
        .open_in_place(&mut record)
        .expect("open");
    assert_eq!(opened.plaintext(), b"after-ku");
}

#[tokio::test(flavor = "current_thread")]
async fn establishes_for_each_offered_aead_suite() {
    for (wire, expected) in [
        (0x1301_u16, CipherSuite::Aes128GcmSha256),
        (0x1302, CipherSuite::Aes256GcmSha384),
        (0x1303, CipherSuite::ChaCha20Poly1305Sha256),
    ] {
        let (session, _, suite) = handshake_pair(wire).await;
        assert_eq!(suite, expected, "suite wire {wire:#06x}");
        assert_eq!(session.negotiated().suite, expected);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn rejects_certificate_bound_to_a_different_auth_key() {
    let (authenticator, server_public) = authenticator([0x42; 32]);
    let keys = ClientKeyAgreement::generate().expect("keys");
    let now = 1_700_000_000_u32;
    let (record, auth_key) =
        build_client_hello(NAME, ALPN, &keys, &server_public, plaintext(now)).expect("hello");
    let client = ClientHello::parse_message(record.message()).expect("parse");
    let _ = authenticator
        .authenticate(&client, u64::from(now))
        .expect("authenticate");
    let target = ServerHelloTemplate::parse(
        &synthetic_server_hello(&client, X25519_GROUP, &[0x55; 32]),
        &client,
    )
    .expect("target");
    let identity = CertificateIdentity::from_seed([0x42; 32]);
    let wrong_key = AuthKey::from_test_bytes([0x11; 32]);
    let flight =
        build_server_flight(&client, &wrong_key, target, &identity, Some(b"h2")).expect("flight");
    let error = establish_with_server_flight(&record, keys, &auth_key, ALPN, flight)
        .await
        .expect_err("binding must fail");
    assert!(matches!(
        error,
        ClientHandshakeError::Certificate(CertificateError::Binding)
    ));
}

#[test]
fn rejects_unknown_short_id_at_authenticator() {
    let (authenticator, server_public) = authenticator([0x42; 32]);
    let keys = ClientKeyAgreement::generate().expect("keys");
    let mut auth = plaintext(1_700_000_000);
    auth.short_id = [0xff; 8];
    let (record, _) = build_client_hello(NAME, ALPN, &keys, &server_public, auth).expect("hello");
    let client = ClientHello::parse_message(record.message()).expect("parse");
    assert!(
        authenticator.authenticate(&client, 1_700_000_000).is_err(),
        "unknown shortId must not authenticate"
    );
}

#[test]
fn rejects_wrong_server_public_key_at_authenticator() {
    let (authenticator, _server_public) = authenticator([0x42; 32]);
    let keys = ClientKeyAgreement::generate().expect("keys");
    let wrong_public = PublicKey::from(&StaticSecret::from([0x77; 32])).to_bytes();
    let (record, _) =
        build_client_hello(NAME, ALPN, &keys, &wrong_public, plaintext(1_700_000_000))
            .expect("hello");
    let client = ClientHello::parse_message(record.message()).expect("parse");
    assert!(
        authenticator.authenticate(&client, 1_700_000_000).is_err(),
        "wrong server public key must not authenticate"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn positional_flight_shape_still_establishes() {
    let (authenticator, server_public) = authenticator([0x42; 32]);
    let keys = ClientKeyAgreement::generate().expect("keys");
    let now = 1_700_000_000_u32;
    let (record, auth_key) =
        build_client_hello(NAME, ALPN, &keys, &server_public, plaintext(now)).expect("hello");
    let client = ClientHello::parse_message(record.message()).expect("parse");
    let auth = authenticator
        .authenticate(&client, u64::from(now))
        .expect("authenticate");
    let target = ServerHelloTemplate::parse(
        &synthetic_server_hello(&client, X25519_GROUP, &[0x55; 32]),
        &client,
    )
    .expect("target");
    let identity = CertificateIdentity::from_seed([0x42; 32]);
    let flight = build_server_flight_with_shape(
        &client,
        auth.auth_key(),
        target,
        &identity,
        Some(b"h2"),
        CoverHandshakePlan {
            emit_ccs: true,
            shape: CoverHandshakeRecordShape::PositionalRecords {
                wire_lens: [37, 838, 286, 58],
                nst_wire_len: None,
            },
        },
    )
    .expect("flight");
    let (mut session, mut established) =
        establish_with_server_flight(&record, keys, &auth_key, ALPN, flight)
            .await
            .expect("handshake");
    let mut record = Vec::new();
    session
        .write_mut()
        .seal_into(ContentType::ApplicationData, b"pos", 0, &mut record)
        .expect("seal");
    let opened = established
        .client_records_mut()
        .open_in_place(&mut record)
        .expect("open");
    assert_eq!(opened.plaintext(), b"pos");
}

#[tokio::test(flavor = "current_thread")]
async fn tcp_loopback_establishes_against_build_server_flight() {
    use tokio::net::{TcpListener, TcpStream};

    let (authenticator, server_public) = authenticator([0x42; 32]);
    let keys = ClientKeyAgreement::generate().expect("keys");
    let now = 1_700_000_000_u32;
    let (record, auth_key) =
        build_client_hello(NAME, ALPN, &keys, &server_public, plaintext(now)).expect("hello");
    let client = ClientHello::parse_message(record.message()).expect("parse");
    let auth = authenticator
        .authenticate(&client, u64::from(now))
        .expect("authenticate");
    let target = ServerHelloTemplate::parse(
        &synthetic_server_hello(&client, X25519_GROUP, &[0x55; 32]),
        &client,
    )
    .expect("target");
    let identity = CertificateIdentity::from_seed([0x42; 32]);
    let flight = build_server_flight(&client, auth.auth_key(), target, &identity, Some(b"h2"))
        .expect("flight");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        socket.write_all(flight.wire()).await.expect("write flight");
        let mut header = [0_u8; RECORD_HEADER_LEN];
        loop {
            socket.read_exact(&mut header).await.expect("header");
            let body_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
            let mut body = vec![0_u8; body_len];
            socket.read_exact(&mut body).await.expect("body");
            if header[0] == OUTER_CHANGE_CIPHER_SPEC {
                continue;
            }
            let mut finished = Vec::with_capacity(RECORD_HEADER_LEN + body_len);
            finished.extend_from_slice(&header);
            finished.extend_from_slice(&body);
            let mut established = flight
                .verify_client_finished(&mut finished)
                .expect("client finished");
            let mut reply = Vec::new();
            established
                .server_records_mut()
                .seal_into(ContentType::ApplicationData, b"tcp-ok", 0, &mut reply)
                .expect("server seal");
            socket.write_all(&reply).await.expect("write reply");
            break;
        }
    });

    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let mut session = complete(&mut stream, &record, keys, &auth_key, ALPN)
        .await
        .expect("client handshake over tcp");
    assert_eq!(session.negotiated().alpn.as_deref(), Some(b"h2".as_slice()));

    let mut header = [0_u8; RECORD_HEADER_LEN];
    stream.read_exact(&mut header).await.expect("reply header");
    let body_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    let mut body = vec![0_u8; body_len];
    stream.read_exact(&mut body).await.expect("reply body");
    let mut reply = Vec::with_capacity(RECORD_HEADER_LEN + body_len);
    reply.extend_from_slice(&header);
    reply.extend_from_slice(&body);
    let opened = session
        .read_mut()
        .open_in_place(&mut reply)
        .expect("open reply");
    assert_eq!(opened.plaintext(), b"tcp-ok");
    server.await.expect("server task");
}

#[test]
fn debug_redacts_session_secrets() {
    let text = format!("{:?}", ClientHandshakeError::KeyAgreement);
    assert!(!text.contains("secret"));
    assert!(verify_data_eq(&[1, 2], &[1, 2]));
    assert!(!verify_data_eq(&[1, 2], &[1, 3]));
}
