use super::{
    ClientHello, ClientHelloClassError, ClientHelloError, EXT_ENCRYPTED_CLIENT_HELLO,
    EXT_PRE_SHARED_KEY, MAX_CLIENT_HELLO_BYTES, SESSION_ID_LEN, SESSION_ID_OFFSET, X25519_GROUP,
    X25519_MLKEM768_GROUP, X25519_MLKEM768_SHARE_LEN, extension_segments,
    fixtures::{client_hello, client_hello_with_key_share, record},
};

#[test]
fn p256_cover_probe_retains_class_and_consumes_valid_private_state() {
    let key = crate::crypto::EphemeralP256Key::generate().unwrap();
    let hello = ClientHello::parse_message(&client_hello_with_key_share(
        [7; 32],
        &[9; 32],
        "www.example.com",
        &[b"h2"],
        super::P256_GROUP,
        &key.public_key(),
    ))
    .unwrap();
    let class = hello.normalized_profile_class().unwrap();
    let template = hello.controlled_cover_probe_template().unwrap();
    let mut probe = template.generate(3).unwrap();
    assert_eq!(probe.hello().normalized_profile_class().unwrap(), class);
    let share = probe
        .hello()
        .key_shares()
        .find(|s| s.group() == super::P256_GROUP)
        .unwrap()
        .data()
        .to_vec();
    assert_ne!(share, key.public_key());
    let peer = crate::crypto::EphemeralP256Key::generate().unwrap();
    let public = peer.public_key();
    let expected = peer.agree(&share).unwrap();
    let actual = probe.shared_secret(super::P256_GROUP, &public).unwrap();
    assert_eq!(actual.as_bytes(), expected.as_slice());
    assert!(probe.shared_secret(super::P256_GROUP, &public).is_err());
    let malformed = ClientHello::parse_message(&client_hello_with_key_share(
        [7; 32],
        &[9; 32],
        "www.example.com",
        &[b"h2"],
        super::P256_GROUP,
        &[4; 64],
    ))
    .unwrap();
    assert!(malformed.normalized_profile_class().is_err());
}

#[test]
fn a_controlled_probe_consumes_its_ephemeral_agreement() {
    let hello = ClientHello::parse_message(&client_hello(
        [0x11; 32],
        &[0x22; 32],
        "www.example.com",
        &[b"h2"],
    ))
    .expect("fixture hello");
    let template = hello.controlled_cover_probe_template().expect("template");
    let peer = crate::crypto::StaticX25519Key::new(&[0x33; 32]);
    let mut probe = template.generate(0).expect("probe");
    let share = probe.hello().peer_x25519().expect("probe share");
    let expected = peer.agree(&share).expect("peer agreement");
    let agreed = probe
        .shared_secret(X25519_GROUP, &peer.public_key())
        .expect("agreement");
    assert_eq!(agreed.as_bytes(), expected.as_slice());
    assert!(matches!(
        probe.shared_secret(X25519_GROUP, &peer.public_key()),
        Err(super::CoverProbeError::Malformed)
    ));

    let mut rejected = template.generate(1).expect("fresh probe");
    assert!(matches!(
        rejected.shared_secret(X25519_GROUP, &[0; 32]),
        Err(super::CoverProbeError::NonContributoryKey)
    ));
    assert!(matches!(
        rejected.shared_secret(X25519_GROUP, &peer.public_key()),
        Err(super::CoverProbeError::Malformed)
    ));
}

#[test]
fn parses_fields_without_copying_variable_payloads() {
    let random = [7; 32];
    let session_id = [0xcd; SESSION_ID_LEN];
    let message = client_hello(
        random,
        &session_id,
        "www.example.com",
        &[b"h2", b"http/1.1"],
    );
    let hello = ClientHello::parse_message(&message).expect("ClientHello must parse");

    assert_eq!(hello.raw_message(), message);
    assert_eq!(hello.random(), &random);
    assert_eq!(hello.server_name(), Some("www.example.com"));
    assert_eq!(hello.session_ciphertext(), Some(&session_id));
    assert_eq!(
        hello.alpn_protocols().collect::<Vec<_>>(),
        vec![b"h2".as_slice(), b"http/1.1".as_slice()]
    );
    assert!(hello.offers_tls13());
    assert_eq!(hello.peer_x25519(), Some([0x42; 32]));
    assert!(hello.cipher_offered(0x1301));
    assert!(hello.key_share_group_offered(X25519_GROUP));
}

#[test]
fn profile_class_excludes_only_fresh_session_fields() {
    let first = ClientHello::parse_message(&client_hello_with_key_share(
        [0x11; 32],
        &[0x21; 32],
        "www.example.com",
        &[b"h2", b"http/1.1"],
        X25519_GROUP,
        &[0x31; 32],
    ))
    .expect("first ClientHello must parse");
    let second = ClientHello::parse_message(&client_hello_with_key_share(
        [0x12; 32],
        &[0x22; 32],
        "www.example.com",
        &[b"h2", b"http/1.1"],
        X25519_GROUP,
        &[0x32; 32],
    ))
    .expect("second ClientHello must parse");

    assert_eq!(
        first
            .normalized_profile_class()
            .expect("first class must normalize"),
        second
            .normalized_profile_class()
            .expect("second class must normalize")
    );
    assert_eq!(
        format!(
            "{:?}",
            first
                .normalized_profile_class()
                .expect("class must normalize")
        ),
        "NormalizedClientHelloClass([REDACTED])"
    );
}

#[test]
fn profile_class_separates_behavioral_offers() {
    let h2 = ClientHello::parse_message(&client_hello(
        [0; 32],
        &[1; 32],
        "www.example.com",
        &[b"h2", b"http/1.1"],
    ))
    .expect("h2 ClientHello must parse");
    let http1 = ClientHello::parse_message(&client_hello(
        [0; 32],
        &[1; 32],
        "www.example.com",
        &[b"http/1.1"],
    ))
    .expect("http/1.1 ClientHello must parse");
    let other_sni = ClientHello::parse_message(&client_hello(
        [0; 32],
        &[1; 32],
        "other.example.com",
        &[b"h2", b"http/1.1"],
    ))
    .expect("other-SNI ClientHello must parse");
    let hybrid = ClientHello::parse_message(&client_hello_with_key_share(
        [0; 32],
        &[1; 32],
        "www.example.com",
        &[b"h2", b"http/1.1"],
        X25519_MLKEM768_GROUP,
        &[0x44; X25519_MLKEM768_SHARE_LEN],
    ))
    .expect("hybrid ClientHello must parse");

    let base = h2
        .normalized_profile_class()
        .expect("base class must normalize");
    assert_ne!(
        base,
        http1
            .normalized_profile_class()
            .expect("ALPN class must normalize")
    );
    assert_ne!(
        base,
        other_sni
            .normalized_profile_class()
            .expect("SNI class must normalize")
    );
    assert_ne!(
        base,
        hybrid
            .normalized_profile_class()
            .expect("hybrid class must normalize")
    );
}

#[test]
fn profile_class_rejects_unsupported_key_share() {
    let hello = ClientHello::parse_message(&client_hello_with_key_share(
        [0; 32],
        &[1; 32],
        "www.example.com",
        &[b"h2"],
        0x0018,
        &[0x04; 97],
    ))
    .expect("P-384 offer remains a structurally valid ClientHello");
    assert_eq!(
        hello.normalized_profile_class(),
        Err(ClientHelloClassError::UnsupportedKeyShare)
    );
}

#[test]
fn controlled_probes_refresh_session_fields_and_preserve_the_class() {
    let hello = ClientHello::parse_message(&client_hello(
        [0x10; 32],
        &[0x20; 32],
        "www.example.com",
        &[b"h2", b"http/1.1"],
    ))
    .expect("source ClientHello must parse");
    let template = hello
        .controlled_cover_probe_template()
        .expect("eligible authenticated shape must sanitize");
    let first = template.generate(0).expect("first probe must generate");
    let second = template.generate(1).expect("second probe must generate");

    assert_eq!(
        first
            .hello()
            .normalized_profile_class()
            .expect("first probe class must normalize"),
        template.class()
    );
    assert_eq!(
        second
            .hello()
            .normalized_profile_class()
            .expect("second probe class must normalize"),
        template.class()
    );
    assert_ne!(first.hello().random(), second.hello().random());
    assert_ne!(first.hello().session_id(), second.hello().session_id());
    assert_ne!(first.hello().raw_message(), second.hello().raw_message());
}

#[test]
fn grease_values_and_extension_order_normalize_only_when_shape_matches() {
    let base = client_hello(
        [0x10; 32],
        &[0x20; 32],
        "www.example.com",
        &[b"h2", b"http/1.1"],
    );
    let grease_a = append_extension(base.clone(), 0x0a0a, &[]);
    let grease_b = append_extension(base, 0x1a1a, &[]);
    let reversed = reverse_extensions(&grease_a);
    let classes = [&grease_a, &grease_b, &reversed].map(|message| {
        ClientHello::parse_message(message)
            .expect("GREASE ClientHello must parse")
            .normalized_profile_class()
            .expect("GREASE class must normalize")
    });
    assert_eq!(classes[0], classes[1]);
    assert_eq!(classes[0], classes[2]);

    let source = ClientHello::parse_message(&grease_a).expect("GREASE source must parse");
    let template = source
        .controlled_cover_probe_template()
        .expect("GREASE template must sanitize");
    let first = template.generate(0).expect("first GREASE probe must build");
    let second = template
        .generate(1)
        .expect("second GREASE probe must build");
    let first_types: Vec<u16> = extension_segments(first.hello().raw_message())
        .expect("first probe extensions must parse")
        .into_iter()
        .map(|segment| segment.extension_type)
        .filter(|extension_type| super::is_grease(*extension_type))
        .collect();
    let second_types: Vec<u16> = extension_segments(second.hello().raw_message())
        .expect("second probe extensions must parse")
        .into_iter()
        .map(|segment| segment.extension_type)
        .filter(|extension_type| super::is_grease(*extension_type))
        .collect();
    assert_ne!(first_types, second_types);
    assert_eq!(
        first.hello().normalized_profile_class(),
        second.hello().normalized_profile_class()
    );
}

/// A minimal ClientHello with an explicit cipher list, mirroring the
/// fixture skeleton so GREASE placement can be varied exactly the way the
/// captured uTLS Chrome hellos vary it.
fn hello_with_ciphers_and_groups(ciphers: &[u16], groups: Option<&[u16]>) -> Vec<u8> {
    let base = client_hello([0x10; 32], &[0x20; 32], "www.example.com", &[b"h2"]);
    // Replace the single fixture cipher with the requested list.
    // header(4) + legacy version(2) + random(32) + session-id length(1)
    // + session-id(32)
    let cipher_len_offset = 4 + 2 + 32 + 1 + 32;
    let old_len = usize::from(u16::from_be_bytes([
        base[cipher_len_offset],
        base[cipher_len_offset + 1],
    ]));
    let mut out = Vec::with_capacity(base.len() + ciphers.len() * 2);
    out.extend_from_slice(&base[..cipher_len_offset]);
    out.extend_from_slice(
        &u16::try_from(ciphers.len() * 2)
            .expect("test ciphers fit")
            .to_be_bytes(),
    );
    for cipher in ciphers {
        out.extend_from_slice(&cipher.to_be_bytes());
    }
    out.extend_from_slice(&base[cipher_len_offset + 2 + old_len..]);
    // The cipher list grew or shrank; the handshake length must follow.
    let body_len = out.len() - 4;
    out[1..4].copy_from_slice(&u32::try_from(body_len).expect("length fits").to_be_bytes()[1..]);

    let Some(groups) = groups else {
        return out;
    };
    // Replace the fixture supported_versions extension with a
    // supported_groups one carrying the requested values.
    let segments = extension_segments(&out).expect("base extensions must parse");
    let version = segments
        .iter()
        .find(|segment| segment.extension_type == 0x002b)
        .expect("fixture carries supported_versions");
    let mut rebuilt: Vec<u8> = Vec::with_capacity(out.len());
    rebuilt.extend_from_slice(&out[..version.wire.start]);
    let mut body = Vec::new();
    body.extend_from_slice(
        &u16::try_from(groups.len() * 2)
            .expect("groups fit")
            .to_be_bytes(),
    );
    for group in groups {
        body.extend_from_slice(&group.to_be_bytes());
    }
    rebuilt.extend_from_slice(&0x000a_u16.to_be_bytes());
    rebuilt.extend_from_slice(
        &u16::try_from(body.len())
            .expect("groups body")
            .to_be_bytes(),
    );
    rebuilt.extend_from_slice(&body);
    rebuilt.extend_from_slice(&out[version.wire.end..]);
    // The extension vector and handshake lengths grow by the delta.
    // The extension-vector length field precedes the FIRST extension;
    // supported_versions is not necessarily first.
    let vector_len_offset = segments[0].wire.start - 2;
    let declared = usize::from(u16::from_be_bytes([
        rebuilt[vector_len_offset],
        rebuilt[vector_len_offset + 1],
    ]));
    let delta = 4 + body.len() - (version.wire.end - version.wire.start);
    rebuilt[vector_len_offset..vector_len_offset + 2].copy_from_slice(
        &u16::try_from(declared + delta)
            .expect("new length fits")
            .to_be_bytes(),
    );
    let body_len = rebuilt.len() - 4;
    rebuilt[1..4]
        .copy_from_slice(&u32::try_from(body_len).expect("length fits").to_be_bytes()[1..]);
    rebuilt
}

#[test]
fn grease_cipher_position_and_order_do_not_split_the_class() {
    let plain = [0x1301_u16, 0x1302, 0x1303];
    let grease_first = [0x1a1a_u16, 0x1301, 0x1302, 0x1303];
    let grease_last = [0x1301_u16, 0x1302, 0x1303, 0x0a0a];
    let reordered = [0x1303_u16, 0x1302, 0x1301];
    let class = |ciphers: &[u16]| {
        ClientHello::parse_message(&hello_with_ciphers_and_groups(ciphers, None))
            .expect("cipher-list ClientHello must parse")
            .normalized_profile_class()
            .expect("class must normalize")
    };
    let base = class(&plain);
    assert_eq!(base, class(&grease_first), "GREASE cipher at the front");
    assert_eq!(base, class(&grease_last), "GREASE cipher at the back");
    assert_eq!(
        base,
        class(&reordered),
        "preference order is not a capability"
    );
    let different = class(&[0x1302_u16]);
    assert_ne!(
        base, different,
        "a different suite set is a different class"
    );
}

#[test]
fn grease_group_positions_normalize_but_a_real_group_change_does_not() {
    let plain = [X25519_GROUP];
    let shuffled = [0x3a3a_u16, X25519_GROUP, 0x2a2a];
    let hybrid = [0x2a2a_u16, X25519_MLKEM768_GROUP, X25519_GROUP];
    let class = |groups: &[u16]| {
        ClientHello::parse_message(&hello_with_ciphers_and_groups(&[0x1301_u16], Some(groups)))
            .expect("group-list ClientHello must parse")
            .normalized_profile_class()
            .expect("class must normalize")
    };
    let base = class(&plain);
    assert_eq!(
        base,
        class(&shuffled),
        "GREASE groups at shuffled positions"
    );
    assert_ne!(
        base,
        class(&hybrid),
        "adding a real group is a capability change"
    );
}

#[test]
fn a_grease_extension_coming_and_going_does_not_split_the_class() {
    let bare = client_hello([0x10; 32], &[0x20; 32], "www.example.com", &[b"h2"]);
    let with_grease = append_extension(bare.clone(), 0xaaaa, &[0x0a]);
    let with_other_grease = append_extension(bare.clone(), 0x4a4a, &[]);
    let class = |message: &Vec<u8>| {
        ClientHello::parse_message(message)
            .expect("ClientHello must parse")
            .normalized_profile_class()
            .expect("class must normalize")
    };
    let base = class(&bare);
    assert_eq!(base, class(&with_grease));
    assert_eq!(base, class(&with_other_grease));
    // A real extension still splits the class: presence is semantic.
    let with_session_ticket = append_extension(bare, 0x0023, &[1, 2, 3]);
    assert_ne!(base, class(&with_session_ticket));
}

#[test]
fn the_classifier_counts_grease_towards_the_wire_extension_bound() {
    let base = client_hello([0x10; 32], &[0x20; 32], "www.example.com", &[b"h2"]);
    let mut message = append_extension(base, 0xaaaa, &[]);
    let existing = extension_segments(&message)
        .expect("fixture segments")
        .len();
    for index in existing..super::MAX_EXTENSIONS {
        message = append_extension(message, 0x4000 + u16::try_from(index).unwrap(), &[]);
    }
    assert!(super::classify_profile_message(&message).is_ok());
    let oversized = append_extension(message, 0x4a4a, &[]);
    assert_eq!(
        super::classify_profile_message(&oversized),
        Err(ClientHelloClassError::Malformed)
    );
    assert!(ClientHello::parse_message(&oversized).is_err());
}

#[test]
fn repeated_cipher_capabilities_do_not_split_the_class() {
    let class = |ciphers: &[u16]| {
        ClientHello::parse_message(&hello_with_ciphers_and_groups(ciphers, None))
            .expect("fixture hello")
            .normalized_profile_class()
            .expect("fixture class")
    };
    assert_eq!(class(&[0x1301, 0x1302]), class(&[0x1302, 0x1301, 0x1301]));
}

#[test]
fn grease_ech_content_and_length_do_not_split_the_class() {
    let base = client_hello([0x10; 32], &[0x20; 32], "www.example.com", &[b"h2"]);
    let ech = |fill: u8, payload_len: usize| {
        let mut body = vec![0, 0, 1, 0, 1, fill, 0, 32];
        body.extend(std::iter::repeat_n(fill, 32));
        body.extend_from_slice(
            &u16::try_from(payload_len)
                .expect("test ECH payload must fit")
                .to_be_bytes(),
        );
        body.extend(std::iter::repeat_n(fill, payload_len));
        append_extension(base.clone(), EXT_ENCRYPTED_CLIENT_HELLO, &body)
    };
    let first = ClientHello::parse_message(&ech(0x11, 144)).expect("ECH must parse");
    let second = ClientHello::parse_message(&ech(0x22, 144)).expect("ECH must parse");
    let longer = ClientHello::parse_message(&ech(0x33, 176)).expect("ECH must parse");
    assert_eq!(
        first.normalized_profile_class(),
        second.normalized_profile_class()
    );
    assert_eq!(
        first.normalized_profile_class(),
        longer.normalized_profile_class(),
        "the GREASE ECH payload length is variance, not capability"
    );
}

#[test]
fn profile_class_rejects_valid_tls13_psk_offers() {
    let mut psk = Vec::new();
    psk.extend_from_slice(&7_u16.to_be_bytes());
    psk.extend_from_slice(&1_u16.to_be_bytes());
    psk.push(0x42);
    psk.extend_from_slice(&0_u32.to_be_bytes());
    psk.extend_from_slice(&33_u16.to_be_bytes());
    psk.push(32);
    psk.extend_from_slice(&[0x55; 32]);
    let message = append_extension(
        client_hello([0; 32], &[1; 32], "www.example.com", &[b"h2"]),
        EXT_PRE_SHARED_KEY,
        &psk,
    );
    let hello = ClientHello::parse_message(&message).expect("PSK offer must parse strictly");
    assert_eq!(
        hello.normalized_profile_class(),
        Err(ClientHelloClassError::PreSharedKey)
    );
}

fn append_extension(mut message: Vec<u8>, extension_type: u16, body: &[u8]) -> Vec<u8> {
    let segments = extension_segments(&message).expect("base extensions must parse");
    let extensions_start = segments.first().expect("fixture has extensions").wire.start;
    let length_offset = extensions_start - 2;
    let old_extensions_len = usize::from(u16::from_be_bytes([
        message[length_offset],
        message[length_offset + 1],
    ]));
    message.extend_from_slice(&extension_type.to_be_bytes());
    message.extend_from_slice(
        &u16::try_from(body.len())
            .expect("test extension body must fit")
            .to_be_bytes(),
    );
    message.extend_from_slice(body);
    let new_extensions_len = old_extensions_len + 4 + body.len();
    message[length_offset..length_offset + 2].copy_from_slice(
        &u16::try_from(new_extensions_len)
            .expect("test extension vector must fit")
            .to_be_bytes(),
    );
    let body_len = message.len() - 4;
    message[1..4].copy_from_slice(
        &u32::try_from(body_len)
            .expect("test message must fit")
            .to_be_bytes()[1..],
    );
    message
}

fn reverse_extensions(message: &[u8]) -> Vec<u8> {
    let segments = extension_segments(message).expect("extensions must parse");
    let first = segments.first().expect("fixture has extensions");
    let last = segments.last().expect("fixture has extensions");
    let mut output = message[..first.wire.start].to_vec();
    for segment in segments.iter().rev() {
        output.extend_from_slice(&message[segment.wire.clone()]);
    }
    output.extend_from_slice(&message[last.wire.end..]);
    output
}

#[test]
fn builds_exact_reality_aad_and_nonce() {
    let random = [9; 32];
    let session_id = [0xab; SESSION_ID_LEN];
    let message = client_hello(random, &session_id, "a.example", &[]);
    let hello = ClientHello::parse_message(&message).expect("ClientHello must parse");
    let aad = hello
        .reality_aad()
        .expect("32-byte session ID must make AAD");

    assert_eq!(
        aad.get(SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN),
        Some([0_u8; SESSION_ID_LEN].as_slice())
    );
    assert_eq!(hello.aead_nonce(), [9; 12]);
}

#[test]
fn extracts_hybrid_x25519_and_mlkem_parts() {
    let mut hybrid = vec![0x7a; X25519_MLKEM768_SHARE_LEN];
    hybrid
        .get_mut(X25519_MLKEM768_SHARE_LEN - 32..)
        .expect("test hybrid tail must exist")
        .fill(0x99);
    let message = client_hello_with_key_share(
        [0; 32],
        &[1; 32],
        "a.example",
        &[],
        X25519_MLKEM768_GROUP,
        &hybrid,
    );
    let hello = ClientHello::parse_message(&message).expect("hybrid ClientHello must parse");

    assert_eq!(hello.peer_x25519(), Some([0x99; 32]));
    assert_eq!(
        hello.peer_mlkem768_encapsulation_key(),
        hybrid.get(..X25519_MLKEM768_SHARE_LEN - 32)
    );
}

#[test]
fn parses_exact_record_and_rejects_trailing_bytes() {
    let message = client_hello([0; 32], &[1; 32], "a.example", &[]);
    let mut record = record(&message);
    assert!(ClientHello::parse_record(&record).is_ok());

    record.push(0);
    assert!(matches!(
        ClientHello::parse_record(&record),
        Err(ClientHelloError::LengthMismatch)
    ));
}

#[test]
fn rejects_odd_cipher_suite_vector() {
    let mut message = client_hello([0; 32], &[1; 32], "a.example", &[]);
    let cipher_length_offset = SESSION_ID_OFFSET + SESSION_ID_LEN;
    message[cipher_length_offset] = 0;
    message[cipher_length_offset + 1] = 1;

    assert!(matches!(
        ClientHello::parse_message(&message),
        Err(ClientHelloError::Malformed("cipher suites"))
    ));
}

#[test]
fn rejects_oversized_input_before_parsing() {
    let oversized = vec![0; MAX_CLIENT_HELLO_BYTES + 1];

    assert!(matches!(
        ClientHello::parse_message(&oversized),
        Err(ClientHelloError::TooLarge)
    ));
}

#[test]
fn arbitrary_bytes_never_panic() {
    let mut state = 0x1234_5678_u32;
    for length in 0..2_048 {
        let mut input = Vec::with_capacity(length);
        for _ in 0..length {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            input.push(state.to_be_bytes()[1]);
        }
        let _result = ClientHello::parse_message(&input);
    }
}
