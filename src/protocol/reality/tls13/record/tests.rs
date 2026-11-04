use super::{ContentType, Tls13RecordError, Tls13RecordLayer};
use crate::protocol::reality::tls13::{
    CipherSuite, HashAlgorithm, Tls13KeySchedule, Tls13KeyScheduleError, TrafficKeys,
    TrafficSecret, TranscriptHash,
};

#[test]
fn rfc8448_client_finished_record_matches_byte_for_byte() {
    let schedule = rfc8448_schedule();
    let keys = schedule
        .traffic_keys(schedule.client_handshake_secret())
        .expect("RFC 8448 traffic keys must derive");
    let mut records = Tls13RecordLayer::new(CipherSuite::Aes128GcmSha256, keys)
        .expect("RFC 8448 record state must initialize");
    let plaintext =
        hex_vec("14000020a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61");
    let mut record = Vec::new();
    records
        .seal_into(ContentType::Handshake, &plaintext, 0, &mut record)
        .expect("RFC 8448 Finished must seal");

    assert_eq!(
        record,
        hex_vec(
            "170303003575ec4dc238cce60b298044a71e219c56cc77b0517fe9b93c7a4bfc44\
                 d87f38f80338ac98fc46deb384bd1caeacab6867d726c40546"
        )
    );
}

#[test]
fn rfc8448_client_finished_record_opens_in_place() {
    let schedule = rfc8448_schedule();
    let keys = schedule
        .traffic_keys(schedule.client_handshake_secret())
        .expect("RFC 8448 traffic keys must derive");
    let mut records = Tls13RecordLayer::new(CipherSuite::Aes128GcmSha256, keys)
        .expect("RFC 8448 record state must initialize");
    let mut record = hex_vec(
        "170303003575ec4dc238cce60b298044a71e219c56cc77b0517fe9b93c7a4bfc44\
             d87f38f80338ac98fc46deb384bd1caeacab6867d726c40546",
    );
    let opened = records
        .open_in_place(&mut record)
        .expect("RFC 8448 Finished must authenticate");

    assert_eq!(opened.content_type(), ContentType::Handshake);
    assert_eq!(
        opened.plaintext(),
        hex_vec("14000020a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61")
    );
}

#[test]
fn round_trips_all_supported_suites_with_padding_and_sequence() {
    for suite in [
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Aes256GcmSha384,
        CipherSuite::ChaCha20Poly1305Sha256,
    ] {
        let (mut writer, mut reader) = paired_layers(suite);
        for plaintext in [b"".as_slice(), b"interactive", &[0x42; 16_384]] {
            let padding = usize::from(plaintext.len() < 128) * 31;
            let mut record = Vec::new();
            writer
                .seal_into(
                    ContentType::ApplicationData,
                    plaintext,
                    padding,
                    &mut record,
                )
                .expect("bounded test record must seal");
            let opened = reader
                .open_in_place(&mut record)
                .expect("matching direction must authenticate");
            assert_eq!(opened.content_type(), ContentType::ApplicationData);
            assert_eq!(opened.plaintext(), plaintext);
        }
        assert_eq!(writer.records_used(), 3);
        assert_eq!(reader.records_used(), 3);
    }
}

#[test]
fn rejects_tamper_reordering_trailing_bytes_and_oversize() {
    let (mut writer, mut reader) = paired_layers(CipherSuite::Aes128GcmSha256);
    let mut first = Vec::new();
    writer
        .seal_into(ContentType::Handshake, b"first", 0, &mut first)
        .expect("first record must seal");
    let mut second = Vec::new();
    writer
        .seal_into(ContentType::Handshake, b"second", 0, &mut second)
        .expect("second record must seal");

    assert_eq!(
        reader.open_in_place(&mut second),
        Err(Tls13RecordError::AuthenticationFailed)
    );
    let mut tampered = first.clone();
    if let Some(last) = tampered.last_mut() {
        *last ^= 1;
    }
    assert_eq!(
        reader.open_in_place(&mut tampered),
        Err(Tls13RecordError::AuthenticationFailed)
    );
    first.push(0);
    assert_eq!(
        reader.open_in_place(&mut first),
        Err(Tls13RecordError::InvalidLength)
    );

    let mut output = Vec::new();
    assert_eq!(
        writer.seal_into(
            ContentType::ApplicationData,
            &[0; super::MAX_PLAINTEXT_LEN + 1],
            0,
            &mut output,
        ),
        Err(Tls13RecordError::InvalidLength)
    );
}

#[test]
fn debug_never_exposes_key_or_iv() {
    let (writer, _) = paired_layers(CipherSuite::Aes128GcmSha256);
    let rendered = format!("{writer:?}");
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains("dbfa"));
    assert!(!rendered.contains("5bd3"));
}

#[test]
fn exported_layer_continues_interoperation_both_ways() {
    for suite in [
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Aes256GcmSha384,
        CipherSuite::ChaCha20Poly1305Sha256,
    ] {
        // Two directions, each a writer/reader pair over shared keys.
        let (mut up_writer, mut up_reader) = paired_layers(suite);
        let (mut down_writer, mut down_reader) = paired_layers(suite);
        for index in 0..3_u8 {
            let mut record = Vec::new();
            up_writer
                .seal_into(ContentType::ApplicationData, &[index; 64], 0, &mut record)
                .expect("pre-export record must seal");
            up_reader
                .open_in_place(&mut record)
                .expect("pre-export record must open");
            let mut downlink = Vec::new();
            down_writer
                .seal_into(ContentType::ApplicationData, &[index; 16], 0, &mut downlink)
                .expect("pre-export downlink must seal");
            down_reader
                .open_in_place(&mut downlink)
                .expect("pre-export downlink must open");
        }

        // Export after three records: the imported opener must authenticate
        // the original writer's fourth record.
        let exported_reader = up_reader
            .into_exported_state()
            .expect("application reader state must export");
        assert_eq!(exported_reader.suite(), suite);
        assert_eq!(exported_reader.sequence(), 3);
        let mut imported_reader = Tls13RecordLayer::from_exported_state(exported_reader)
            .expect("exported reader state must rebuild");
        let mut fourth = Vec::new();
        up_writer
            .seal_into(
                ContentType::ApplicationData,
                b"after-export",
                0,
                &mut fourth,
            )
            .expect("continuation record must seal");
        let opened = imported_reader
            .open_in_place(&mut fourth)
            .expect("imported layer must open the original's continuation");
        assert_eq!(opened.plaintext(), b"after-export");
        assert_eq!(imported_reader.records_used(), 4);

        // And vice versa: a record sealed by the imported writer must
        // authenticate on the original reader.
        let exported_writer = down_writer
            .into_exported_state()
            .expect("application writer state must export");
        let mut imported_writer = Tls13RecordLayer::from_exported_state(exported_writer)
            .expect("exported writer state must rebuild");
        let mut reply = Vec::new();
        imported_writer
            .seal_into(
                ContentType::ApplicationData,
                b"reply-after-export",
                7,
                &mut reply,
            )
            .expect("imported layer must seal the continuation");
        let opened = down_reader
            .open_in_place(&mut reply)
            .expect("original layer must open the imported continuation");
        assert_eq!(opened.plaintext(), b"reply-after-export");
        assert_eq!(down_reader.records_used(), 4);
    }
}

#[test]
fn exported_state_preserves_generation_secret_and_redacts_debug() {
    let suite = CipherSuite::ChaCha20Poly1305Sha256;
    let (writer, mut reader) = paired_layers(suite);
    let exported = writer
        .into_exported_state()
        .expect("application state must export");
    let secret = exported.traffic_secret().as_bytes().to_vec();
    assert_eq!(secret.len(), suite.hash().output_len());

    let rebuilt_secret =
        TrafficSecret::from_bytes(suite.hash(), &secret).expect("raw secret must rebuild");
    let mut reference = Tls13RecordLayer::from_traffic_secret(suite, rebuilt_secret)
        .expect("reference layer must initialize");
    let mut imported =
        Tls13RecordLayer::from_exported_state(exported).expect("exported state must rebuild");
    let mut record = Vec::new();
    imported
        .seal_into(ContentType::ApplicationData, b"same-secret", 0, &mut record)
        .expect("imported layer must seal");
    let mut peer_copy = record.clone();
    let opened = reader
        .open_in_place(&mut peer_copy)
        .expect("original peer must open");
    assert_eq!(opened.plaintext(), b"same-secret");
    let opened = reference
        .open_in_place(&mut record)
        .expect("raw-secret layer must agree on the first record");
    assert_eq!(opened.plaintext(), b"same-secret");

    let rendered = format!("{imported:?}");
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains("42424242"));
}

#[test]
fn traffic_update_rekeys_both_peers_and_resets_sequence() {
    for suite in [
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Aes256GcmSha384,
        CipherSuite::ChaCha20Poly1305Sha256,
    ] {
        let (mut writer, mut reader) = paired_layers(suite);
        let mut before = Vec::new();
        writer
            .seal_into(ContentType::ApplicationData, b"before", 0, &mut before)
            .expect("old generation must seal");
        reader
            .open_in_place(&mut before)
            .expect("old generation must open");
        assert_eq!(writer.records_used(), 1);
        assert_eq!(reader.records_used(), 1);

        writer
            .update_traffic_secret()
            .expect("writer secret must update");
        reader
            .update_traffic_secret()
            .expect("reader secret must update");
        assert_eq!(writer.records_used(), 0);
        assert_eq!(reader.records_used(), 0);

        let mut after = Vec::new();
        writer
            .seal_into(ContentType::ApplicationData, b"after", 0, &mut after)
            .expect("new generation must seal");
        let opened = reader
            .open_in_place(&mut after)
            .expect("new generation must open");
        assert_eq!(opened.plaintext(), b"after");
        assert_eq!(writer.records_used(), 1);
        assert_eq!(reader.records_used(), 1);
    }
}

#[test]
fn handshake_layer_rejects_update_without_changing_sequence() {
    let schedule = rfc8448_schedule();
    let keys = schedule
        .traffic_keys(schedule.client_handshake_secret())
        .expect("handshake keys must derive");
    let mut records = Tls13RecordLayer::new(CipherSuite::Aes128GcmSha256, keys)
        .expect("handshake record layer must initialize");
    let mut wire = Vec::new();
    records
        .seal_into(ContentType::Handshake, b"one", 0, &mut wire)
        .expect("handshake record must seal");
    assert_eq!(
        records.update_traffic_secret(),
        Err(Tls13RecordError::KeyUpdateUnavailable)
    );
    assert_eq!(records.records_used(), 1);
}

#[test]
fn proactive_update_threshold_leaves_one_safe_record() {
    for (suite, limit) in [
        (CipherSuite::Aes128GcmSha256, super::AES_GCM_RECORD_LIMIT),
        (CipherSuite::Aes256GcmSha384, super::AES_GCM_RECORD_LIMIT),
        (
            CipherSuite::ChaCha20Poly1305Sha256,
            super::CHACHA20_POLY1305_RECORD_LIMIT,
        ),
    ] {
        let (mut records, _) = paired_layers(suite);
        records.sequence = limit - 2;
        assert!(!records.needs_key_update());
        records.sequence = limit - 1;
        assert!(records.needs_key_update());
        assert!(records.ensure_key_available().is_ok());
        records.sequence = limit;
        assert_eq!(
            records.ensure_key_available(),
            Err(Tls13RecordError::KeyUsageExhausted)
        );
    }
}

#[test]
fn raw_parts_reject_unsupported_key_lengths() {
    for length in [0_usize, 8, 15, 17, 31, 33, 48] {
        assert_eq!(
            TrafficKeys::from_raw_parts(&vec![0x55; length], [0; 12]).unwrap_err(),
            Tls13KeyScheduleError::InvalidLength
        );
    }
    assert!(TrafficKeys::from_raw_parts(&[0x55; 16], [0; 12]).is_ok());
    assert!(TrafficKeys::from_raw_parts(&[0x55; 32], [0; 12]).is_ok());
}

/// D9 cross-provider equivalence: the RustCrypto AES-128-GCM primitive and
/// ring must produce byte-identical output for identical
/// key/nonce/AAD/plaintext, using the record layer's exact nonce
/// derivation (`iv XOR sequence`). Together with the RFC 8448 byte-exact
/// tests above — which pass under both feature configurations — this
/// proves the ring backend is wire-identical to the RustCrypto one.
#[test]
fn aes128_gcm_rustcrypto_and_ring_are_byte_identical() {
    use aes_gcm::{
        Aes128Gcm as RustCryptoAes128,
        aead::{AeadInOut, KeyInit as _, Nonce as RustCryptoNonce, array::Array},
    };

    let key = [0x42_u8; 16];
    let iv = [0x24_u8; 12];
    let aad = [23, 3, 3, 0x40, 0x11];
    let rustcrypto = RustCryptoAes128::new(&Array(key));
    let ring_key = ring::aead::LessSafeKey::new(
        ring::aead::UnboundKey::new(&ring::aead::AES_128_GCM, &key).expect("ring key"),
    );
    let derive_nonce = |sequence: u64| {
        let mut nonce = iv;
        for (nonce_byte, sequence_byte) in nonce[4..].iter_mut().zip(sequence.to_be_bytes()) {
            *nonce_byte ^= sequence_byte;
        }
        nonce
    };
    let rc_open = |body: &mut [u8], plaintext_len: usize, nonce: [u8; 12], aad: &[u8]| {
        let (ciphertext, tag) = body.split_at_mut(plaintext_len);
        let nonce: RustCryptoNonce<RustCryptoAes128> = Array(nonce);
        let tag: aes_gcm::aead::Tag<RustCryptoAes128> =
            Array(*tag.first_chunk::<16>().expect("tag length"));
        rustcrypto.decrypt_inout_detached(&nonce, aad, ciphertext.into(), &tag)
    };
    let ring_open = |body: &mut [u8], nonce: [u8; 12], aad: &[u8]| {
        ring_key
            .open_in_place(
                ring::aead::Nonce::assume_unique_for_key(nonce),
                ring::aead::Aad::from(aad),
                body,
            )
            .map(|_| ())
    };

    for plaintext_len in [0_usize, 1, 64, 1024, 4096, 16_384] {
        let plaintext: Vec<u8> = (0..plaintext_len)
            .map(|index| (index * 31 + 7) as u8)
            .collect();
        for sequence in [0_u64, 1, 255, 65_536, (1 << 24) - 1] {
            let nonce = derive_nonce(sequence);

            let mut rc_body = plaintext.clone();
            let rc_nonce: RustCryptoNonce<RustCryptoAes128> = Array(nonce);
            let rc_tag = rustcrypto
                .encrypt_inout_detached(&rc_nonce, &aad, rc_body.as_mut_slice().into())
                .expect("RustCrypto seal");

            let mut ring_body = plaintext.clone();
            let ring_tag = ring_key
                .seal_in_place_separate_tag(
                    ring::aead::Nonce::assume_unique_for_key(nonce),
                    ring::aead::Aad::from(&aad),
                    &mut ring_body,
                )
                .expect("ring seal");

            assert_eq!(
                rc_body, ring_body,
                "ciphertext mismatch at len {plaintext_len} seq {sequence}"
            );
            assert_eq!(
                rc_tag.as_slice(),
                ring_tag.as_ref(),
                "tag mismatch at len {plaintext_len} seq {sequence}"
            );

            // Cross-open: each provider authenticates the other's record.
            let mut wire = ring_body.clone();
            wire.extend_from_slice(ring_tag.as_ref());
            ring_open(&mut wire.clone(), nonce, &aad).expect("ring opens its own record");
            let mut rc_wire = wire.clone();
            rc_open(&mut rc_wire, plaintext_len, nonce, &aad)
                .expect("RustCrypto opens the ring record");
            assert_eq!(&rc_wire[..plaintext_len], plaintext.as_slice());

            // Corrupted tag, corrupted ciphertext, wrong AAD, and wrong
            // nonce must be rejected by both providers.
            let mut bad_tag = wire.clone();
            let tag_byte = bad_tag.len() - 1;
            bad_tag[tag_byte] ^= 1;
            assert!(ring_open(&mut bad_tag.clone(), nonce, &aad).is_err());
            assert!(rc_open(&mut bad_tag, plaintext_len, nonce, &aad).is_err());

            if plaintext_len > 0 {
                let mut bad_ciphertext = wire.clone();
                bad_ciphertext[0] ^= 1;
                assert!(ring_open(&mut bad_ciphertext.clone(), nonce, &aad).is_err());
                assert!(rc_open(&mut bad_ciphertext, plaintext_len, nonce, &aad).is_err());
            }

            let bad_aad = [23, 3, 3, 0x40, 0x12];
            assert!(ring_open(&mut wire.clone(), nonce, &bad_aad).is_err());
            assert!(rc_open(&mut wire.clone(), plaintext_len, nonce, &bad_aad).is_err());

            let wrong_nonce = derive_nonce(sequence.wrapping_add(1));
            assert!(ring_open(&mut wire.clone(), wrong_nonce, &aad).is_err());
            assert!(rc_open(&mut wire.clone(), plaintext_len, wrong_nonce, &aad).is_err());
        }
    }
}

/// The same cross-provider equivalence the AES-128-GCM test proves, for the
/// two suites that moved from RustCrypto to ring.
///
/// Both providers are compared as primitives rather than through
/// `Tls13RecordLayer`, because the layer compiles against exactly one
/// backend at a time; the layer's own nonce derivation (`iv XOR sequence`),
/// record sizes and sequence numbers are reproduced here so the comparison
/// is the production shape and not an abstract one.
///
/// Equality of the sealed bytes is the protocol-compatibility claim.
/// Rejection parity is the security claim: a record either provider refuses
/// must be refused by the other, or swapping them would change which peer
/// is accepted.
#[test]
fn the_alternate_suites_are_byte_identical_between_rustcrypto_and_ring() {
    use aes_gcm::{
        Aes256Gcm as RustCryptoAes256,
        aead::{AeadInOut, KeyInit as _, array::Array},
    };
    use chacha20poly1305::ChaCha20Poly1305 as RustCryptoChaCha;

    let key = [0x42_u8; 32];
    let iv = [0x24_u8; 12];
    let aad = [23, 3, 3, 0x40, 0x11];
    let derive_nonce = |sequence: u64| {
        let mut nonce = iv;
        for (nonce_byte, sequence_byte) in nonce[4..].iter_mut().zip(sequence.to_be_bytes()) {
            *nonce_byte ^= sequence_byte;
        }
        nonce
    };

    let aes = RustCryptoAes256::new(&Array(key));
    let chacha = RustCryptoChaCha::new(&Array(key));

    for (label, algorithm) in [
        ("AES-256-GCM", &ring::aead::AES_256_GCM),
        ("ChaCha20-Poly1305", &ring::aead::CHACHA20_POLY1305),
    ] {
        let ring_key = ring::aead::LessSafeKey::new(
            ring::aead::UnboundKey::new(algorithm, &key).expect("ring key"),
        );
        let is_aes = label == "AES-256-GCM";

        for plaintext_len in [0_usize, 1, 64, 1024, 4096, 16_384] {
            let plaintext: Vec<u8> = (0..plaintext_len)
                .map(|index| (index * 31 + 7) as u8)
                .collect();
            for sequence in [0_u64, 1, 255, 65_536, (1 << 24) - 1] {
                let nonce = derive_nonce(sequence);

                let mut rc_body = plaintext.clone();
                let rc_tag = if is_aes {
                    aes.encrypt_inout_detached(&Array(nonce), &aad, rc_body.as_mut_slice().into())
                        .expect("RustCrypto seal")
                        .to_vec()
                } else {
                    chacha
                        .encrypt_inout_detached(&Array(nonce), &aad, rc_body.as_mut_slice().into())
                        .expect("RustCrypto seal")
                        .to_vec()
                };

                let mut ring_body = plaintext.clone();
                let ring_tag = ring_key
                    .seal_in_place_separate_tag(
                        ring::aead::Nonce::assume_unique_for_key(nonce),
                        ring::aead::Aad::from(&aad),
                        &mut ring_body,
                    )
                    .expect("ring seal");

                assert_eq!(
                    rc_body, ring_body,
                    "{label} ciphertext differs at len {plaintext_len} sequence {sequence}"
                );
                assert_eq!(
                    rc_tag,
                    ring_tag.as_ref(),
                    "{label} tag differs at len {plaintext_len} sequence {sequence}"
                );

                // Rejection parity: ring opens the contiguous body, so build
                // the wire form once and tamper with it.
                let mut wire = ring_body.clone();
                wire.extend_from_slice(ring_tag.as_ref());
                let ring_open = |body: &mut Vec<u8>, nonce: [u8; 12], aad: &[u8]| {
                    ring_key
                        .open_in_place(
                            ring::aead::Nonce::assume_unique_for_key(nonce),
                            ring::aead::Aad::from(aad),
                            body.as_mut_slice(),
                        )
                        .map(|_| ())
                };
                let rc_open = |body: &mut Vec<u8>, nonce: [u8; 12], aad: &[u8]| {
                    let (ciphertext, tag) = body.split_at_mut(plaintext_len);
                    let tag = *tag.first_chunk::<16>().expect("tag length");
                    if is_aes {
                        aes.decrypt_inout_detached(
                            &Array(nonce),
                            aad,
                            ciphertext.into(),
                            &Array(tag),
                        )
                    } else {
                        chacha.decrypt_inout_detached(
                            &Array(nonce),
                            aad,
                            ciphertext.into(),
                            &Array(tag),
                        )
                    }
                };

                assert!(ring_open(&mut wire.clone(), nonce, &aad).is_ok(), "{label}");
                assert!(rc_open(&mut wire.clone(), nonce, &aad).is_ok(), "{label}");

                let mut bad_tag = wire.clone();
                let last = bad_tag.len() - 1;
                bad_tag[last] ^= 1;
                assert!(
                    ring_open(&mut bad_tag.clone(), nonce, &aad).is_err(),
                    "{label}"
                );
                assert!(rc_open(&mut bad_tag, nonce, &aad).is_err(), "{label}");

                if plaintext_len > 0 {
                    let mut bad_ciphertext = wire.clone();
                    bad_ciphertext[0] ^= 1;
                    assert!(
                        ring_open(&mut bad_ciphertext.clone(), nonce, &aad).is_err(),
                        "{label}"
                    );
                    assert!(
                        rc_open(&mut bad_ciphertext, nonce, &aad).is_err(),
                        "{label}"
                    );
                }

                let bad_aad = [23, 3, 3, 0x40, 0x12];
                assert!(
                    ring_open(&mut wire.clone(), nonce, &bad_aad).is_err(),
                    "{label}"
                );
                assert!(
                    rc_open(&mut wire.clone(), nonce, &bad_aad).is_err(),
                    "{label}"
                );

                let wrong_nonce = derive_nonce(sequence.wrapping_add(1));
                assert!(
                    ring_open(&mut wire.clone(), wrong_nonce, &aad).is_err(),
                    "{label}"
                );
                assert!(
                    rc_open(&mut wire.clone(), wrong_nonce, &aad).is_err(),
                    "{label}"
                );
            }
        }
    }
}

fn paired_layers(suite: CipherSuite) -> (Tls13RecordLayer, Tls13RecordLayer) {
    let secret_len = suite.hash().output_len();
    let writer_secret = TrafficSecret::from_bytes(suite.hash(), &[0x42; 48][..secret_len])
        .expect("test write secret must match suite");
    let reader_secret = TrafficSecret::from_bytes(suite.hash(), &[0x42; 48][..secret_len])
        .expect("test read secret must match suite");
    (
        Tls13RecordLayer::from_traffic_secret(suite, writer_secret)
            .expect("test writer must initialize"),
        Tls13RecordLayer::from_traffic_secret(suite, reader_secret)
            .expect("test reader must initialize"),
    )
}

fn rfc8448_schedule() -> Tls13KeySchedule {
    let shared_secret = hex_vec("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    let transcript = TranscriptHash::from_bytes(
        HashAlgorithm::Sha256,
        &hex_vec("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"),
    )
    .expect("RFC 8448 transcript must import");
    Tls13KeySchedule::new(CipherSuite::Aes128GcmSha256, &shared_secret, &transcript)
        .expect("RFC 8448 schedule must derive")
}

fn hex_vec(encoded: &str) -> Vec<u8> {
    let bytes: Vec<u8> = encoded
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    let (pairs, _) = bytes.as_chunks::<2>();
    pairs
        .iter()
        .map(|pair| {
            let decode = |byte| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("test hex must be lowercase"),
            };
            (decode(pair[0]) << 4) | decode(pair[1])
        })
        .collect()
}
