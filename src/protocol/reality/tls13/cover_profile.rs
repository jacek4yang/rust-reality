use std::{error::Error, fmt};

use crate::protocol::reality::{ClientHello, CoverProbe, NormalizedClientHelloClass};

use super::{
    ContentType, CoverHandshakePlan, ServerHelloProfileTemplate, ServerHelloTemplate,
    Tls13KeySchedule, Tls13RecordLayer,
};

const HANDSHAKE_ENCRYPTED_EXTENSIONS: u8 = 8;
const EXTENSION_ALPN: u16 = 0x0010;
const EXTENSION_EARLY_DATA: u16 = 0x002a;
const MAX_ENCRYPTED_EXTENSIONS: usize = 64;

/// A controlled cover observation cannot safely become a reusable profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoverProfileError {
    KeyAgreement,
    KeySchedule,
    Record,
    MalformedEncryptedExtensions,
    /// The cover answered with an extension whose semantics bind to negotiated
    /// state a reusable profile cannot reconstruct. Structurally valid, so it
    /// is not a parse failure; the class simply stays live-only.
    UnsupportedEncryptedExtension,
    AlpnNotOffered,
    ProfileClassMismatch,
    ServerHello,
}

impl fmt::Display for CoverProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("cover TLS observation is not profile-compatible")
    }
}

impl Error for CoverProfileError {}

/// Immutable stable cover semantics with no reusable TLS session material.
///
/// Server random, session ID and key exchange are erased in `server_hello`.
/// The ALPN value was decrypted from a controlled cover response and the
/// record plan was observed by the strict live-cover reader.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct CoverProfile {
    class: NormalizedClientHelloClass,
    server_hello: ServerHelloProfileTemplate,
    plan: CoverHandshakePlan,
    selected_alpn: Option<Vec<u8>>,
}

impl CoverProfile {
    /// Validates one controlled response and erases every per-session field.
    pub(crate) fn from_controlled_observation(
        class: NormalizedClientHelloClass,
        probe: &CoverProbe,
        target: ServerHelloTemplate,
        plan: CoverHandshakePlan,
        first_encrypted_record: &[u8],
    ) -> Result<Self, CoverProfileError> {
        if probe
            .hello()
            .normalized_profile_class()
            .map_err(|_| CoverProfileError::ProfileClassMismatch)?
            != class
        {
            return Err(CoverProfileError::ProfileClassMismatch);
        }
        let shared = probe
            .shared_secret(
                target.key_share_group(),
                target
                    .observed_key_exchange()
                    .ok_or(CoverProfileError::ServerHello)?,
            )
            .map_err(|_| CoverProfileError::KeyAgreement)?;
        let mut transcript = Vec::new();
        transcript
            .try_reserve_exact(
                probe
                    .hello()
                    .raw_message()
                    .len()
                    .saturating_add(target.raw_message().len()),
            )
            .map_err(|_| CoverProfileError::KeySchedule)?;
        transcript.extend_from_slice(probe.hello().raw_message());
        transcript.extend_from_slice(target.raw_message());
        let suite = target.suite();
        let schedule =
            Tls13KeySchedule::new(suite, shared.as_bytes(), &suite.hash().digest(&transcript))
                .map_err(|_| CoverProfileError::KeySchedule)?;
        let keys = schedule
            .traffic_keys(schedule.server_handshake_secret())
            .map_err(|_| CoverProfileError::KeySchedule)?;
        let mut records =
            Tls13RecordLayer::new(suite, keys).map_err(|_| CoverProfileError::Record)?;
        let mut encrypted = first_encrypted_record.to_vec();
        let opened = records
            .open_in_place(&mut encrypted)
            .map_err(|_| CoverProfileError::Record)?;
        if opened.content_type() != ContentType::Handshake {
            return Err(CoverProfileError::MalformedEncryptedExtensions);
        }
        let selected_alpn = classify_encrypted_extensions(opened.plaintext())?;
        if let Some(protocol) = selected_alpn.as_deref()
            && !probe
                .hello()
                .alpn_protocols()
                .any(|offered| offered == protocol)
        {
            return Err(CoverProfileError::AlpnNotOffered);
        }
        let server_hello = target
            .into_profile_template()
            .map_err(|_| CoverProfileError::ServerHello)?;
        Ok(Self {
            class,
            server_hello,
            plan,
            selected_alpn,
        })
    }

    /// Materializes only an exact conservative class match.
    pub(crate) fn materialize(
        &self,
        client: &ClientHello,
        server_random: [u8; 32],
    ) -> Result<CoverProfileMaterialized, CoverProfileError> {
        if client
            .normalized_profile_class()
            .map_err(|_| CoverProfileError::ProfileClassMismatch)?
            != self.class
        {
            return Err(CoverProfileError::ProfileClassMismatch);
        }
        let server_hello = self
            .server_hello
            .materialize(client, server_random)
            .map_err(|_| CoverProfileError::ServerHello)?;
        Ok(CoverProfileMaterialized {
            server_hello,
            plan: self.plan,
            selected_alpn: self.selected_alpn.clone(),
        })
    }
}

impl fmt::Debug for CoverProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoverProfile")
            .field("class", &self.class)
            .field("server_hello", &self.server_hello)
            .field("plan", &self.plan)
            .field("has_alpn", &self.selected_alpn.is_some())
            .finish_non_exhaustive()
    }
}

pub(crate) struct CoverProfileMaterialized {
    pub(crate) server_hello: ServerHelloTemplate,
    pub(crate) plan: CoverHandshakePlan,
    pub(crate) selected_alpn: Option<Vec<u8>>,
}

/// Classifies one decrypted cover `EncryptedExtensions` and returns the ALPN
/// protocol the cover selected, if any.
///
/// # Why most extensions are discarded rather than rejected
///
/// The profile needs exactly one value out of this message. Both the live and
/// the prebuilt path build their own `EncryptedExtensions` from the selected
/// ALPN and nothing else, then pad that record to the cover's observed wire
/// length. Neither path ever re-emits the cover's extension bytes. So an
/// extension discarded here is one the emitted server flight would have omitted
/// on either path, and rejecting the observation does not make the flight more
/// faithful — it only forces this class onto the live path, where the *same*
/// flight is built after paying a cover round trip.
///
/// The previous rule rejected every non-ALPN extension. Measurement showed that
/// excluded ordinary TLS 1.3 covers: an empty `server_name` acknowledgement
/// (RFC 8446 section 4.2, what most servers send) and `application_settings`
/// both made a cover permanently unprofilable, so tier-3 reuse never activated
/// and every authenticated handshake paid the cover round trip.
///
/// # Classification
///
/// - **Reproduced**: ALPN. It is the one value the local flight emits, and it
///   must have been offered by the probe.
/// - **Discarded**: every other structurally valid extension. Declining an
///   offered extension is always legal for a TLS 1.3 server, and the live path
///   already declines all of them.
/// - **Unsupported**: `early_data`, which asserts an accepted 0-RTT/PSK
///   negotiation. [`normalized_profile_class`] refuses to classify a PSK
///   ClientHello at all, so observing it means the cover negotiated state this
///   mechanism does not model. That class stays live-only.
///
/// Structural strictness is unchanged: framing errors, duplicate extensions,
/// an over-long extension vector and malformed ALPN all still reject.
///
/// [`normalized_profile_class`]: crate::protocol::reality::ClientHello::normalized_profile_class
fn classify_encrypted_extensions(input: &[u8]) -> Result<Option<Vec<u8>>, CoverProfileError> {
    let mut reader = Reader::new(input);
    if reader.read_u8()? != HANDSHAKE_ENCRYPTED_EXTENSIONS {
        return Err(CoverProfileError::MalformedEncryptedExtensions);
    }
    let message_len = reader.read_u24()?;
    if message_len > reader.remaining() {
        return Err(CoverProfileError::MalformedEncryptedExtensions);
    }
    let mut message = reader.subreader(message_len)?;
    let extensions_len = usize::from(message.read_u16()?);
    let mut extensions = message.subreader(extensions_len)?;
    if !message.is_empty() {
        return Err(CoverProfileError::MalformedEncryptedExtensions);
    }
    let mut selected_alpn = None;
    // RFC 8446 section 4.2 forbids a repeated extension type in one block. The
    // fixed array is both the duplicate set and the count bound, so a cover
    // cannot make this loop allocate or run long.
    let mut seen = [0_u16; MAX_ENCRYPTED_EXTENSIONS];
    let mut count = 0_usize;
    while !extensions.is_empty() {
        let extension_type = extensions.read_u16()?;
        let extension_len = usize::from(extensions.read_u16()?);
        let mut extension = extensions.subreader(extension_len)?;
        if seen
            .get(..count)
            .is_some_and(|already| already.contains(&extension_type))
        {
            return Err(CoverProfileError::MalformedEncryptedExtensions);
        }
        let Some(slot) = seen.get_mut(count) else {
            return Err(CoverProfileError::MalformedEncryptedExtensions);
        };
        *slot = extension_type;
        count = count.saturating_add(1);
        match extension_type {
            EXTENSION_ALPN => {
                let list_len = usize::from(extension.read_u16()?);
                let mut protocols = extension.subreader(list_len)?;
                let protocol_len = usize::from(protocols.read_u8()?);
                if protocol_len == 0 {
                    return Err(CoverProfileError::MalformedEncryptedExtensions);
                }
                let protocol = protocols.read_bytes(protocol_len)?.to_vec();
                if !protocols.is_empty() || !extension.is_empty() {
                    return Err(CoverProfileError::MalformedEncryptedExtensions);
                }
                selected_alpn = Some(protocol);
            }
            EXTENSION_EARLY_DATA => {
                return Err(CoverProfileError::UnsupportedEncryptedExtension);
            }
            // Discarded: the body is framed by `subreader` above and then goes
            // unread, because nothing downstream of a profile consumes it.
            _ => {}
        }
    }
    Ok(selected_alpn)
}

/// Exercises strict profile EncryptedExtensions classification with arbitrary
/// attacker-influenced decrypted bytes in the dedicated libFuzzer build.
///
/// A returned ALPN is re-derived from the same input so the fuzzer also covers
/// the invariant the caller depends on: an accepted selection is a single
/// protocol that the message really contained, never a slice of neighbouring
/// extension bytes.
#[cfg(feature = "fuzzing")]
pub fn fuzz_cover_profile_extensions(input: &[u8]) {
    if let Ok(Some(protocol)) = classify_encrypted_extensions(input) {
        assert!(
            !protocol.is_empty(),
            "an accepted ALPN selection is never empty"
        );
        assert!(
            input
                .windows(protocol.len())
                .any(|window| window == protocol),
            "an accepted ALPN selection is a substring of the observed message"
        );
    }
}

struct Reader<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.position)
    }

    fn is_empty(&self) -> bool {
        self.position == self.input.len()
    }

    fn read_u8(&mut self) -> Result<u8, CoverProfileError> {
        let value = *self
            .input
            .get(self.position)
            .ok_or(CoverProfileError::MalformedEncryptedExtensions)?;
        self.position += 1;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, CoverProfileError> {
        let bytes: [u8; 2] = self
            .read_bytes(2)?
            .try_into()
            .map_err(|_| CoverProfileError::MalformedEncryptedExtensions)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u24(&mut self) -> Result<usize, CoverProfileError> {
        let bytes = self.read_bytes(3)?;
        Ok((usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2]))
    }

    fn read_bytes(&mut self, length: usize) -> Result<&'a [u8], CoverProfileError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(CoverProfileError::MalformedEncryptedExtensions)?;
        let output = self
            .input
            .get(self.position..end)
            .ok_or(CoverProfileError::MalformedEncryptedExtensions)?;
        self.position = end;
        Ok(output)
    }

    fn subreader(&mut self, length: usize) -> Result<Self, CoverProfileError> {
        Ok(Self::new(self.read_bytes(length)?))
    }
}

#[cfg(test)]
mod equivalence {
    //! The proof obligation behind discarding observed extensions.
    //!
    //! Broadening what a cover observation may contain is only safe if the
    //! flight a materialized profile produces is the flight the live path would
    //! have produced for the same ClientHello and the same cover. These tests
    //! build both and compare what the client actually receives.

    use rr_crypto::StaticSecret;

    use super::{CoverProfile, classify_encrypted_extensions};
    use crate::protocol::reality::{
        AuthKey, ClientHello,
        client_hello::fixtures,
        tls13::{
            CipherSuite, ContentType, CoverHandshakePlan, CoverHandshakeRecordShape, ServerFlight,
            ServerHelloTemplate, Tls13KeySchedule, Tls13RecordLayer,
            handshake::build_server_flight_with_shape, messages::CertificateIdentity,
        },
    };

    const X25519_GROUP: u16 = 0x001d;
    const SESSION_ID: [u8; 32] = [0x11; 32];
    const CLIENT_SECRET: [u8; 32] = [0x31; 32];
    const COVER_SECRET: [u8; 32] = [0x71; 32];
    const OFFERED_ALPN: [&[u8]; 2] = [b"h2", b"http/1.1"];

    /// The client whose class both paths serve.
    fn client() -> ClientHello {
        let public = StaticSecret::from_bytes(CLIENT_SECRET).public_key();
        ClientHello::parse_message(&fixtures::client_hello_with_key_share(
            [0x44; 32],
            &SESSION_ID,
            "cover.example",
            &OFFERED_ALPN,
            X25519_GROUP,
            &public,
        ))
        .expect("the fixture ClientHello must parse")
    }

    /// A cover ServerHello echoing `session_id`, carrying the cover's share.
    fn cover_server_hello(session_id: &[u8], key_exchange: &[u8; 32]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303_u16.to_be_bytes());
        body.extend_from_slice(&[0x33; 32]);
        body.push(u8::try_from(session_id.len()).expect("a session ID fits one byte"));
        body.extend_from_slice(session_id);
        body.extend_from_slice(&0x1301_u16.to_be_bytes());
        body.push(0);
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0x002b_u16.to_be_bytes());
        extensions.extend_from_slice(&2_u16.to_be_bytes());
        extensions.extend_from_slice(&0x0304_u16.to_be_bytes());
        let mut share = Vec::new();
        share.extend_from_slice(&X25519_GROUP.to_be_bytes());
        share.extend_from_slice(&32_u16.to_be_bytes());
        share.extend_from_slice(key_exchange);
        extensions.extend_from_slice(&0x0033_u16.to_be_bytes());
        extensions.extend_from_slice(
            &u16::try_from(share.len())
                .expect("a key share fits")
                .to_be_bytes(),
        );
        extensions.extend_from_slice(&share);
        body.extend_from_slice(
            &u16::try_from(extensions.len())
                .expect("the extension vector fits")
                .to_be_bytes(),
        );
        body.extend_from_slice(&extensions);
        let mut message = vec![2];
        message.extend_from_slice(
            &u32::try_from(body.len())
                .expect("a ServerHello fits u24")
                .to_be_bytes()[1..],
        );
        message.extend_from_slice(&body);
        message
    }

    /// Server handshake keys for one `(client share, cover secret)` pair.
    fn cover_records(
        client_hello: &ClientHello,
        server_hello: &[u8],
        shared: &[u8],
    ) -> Tls13RecordLayer {
        let mut transcript = client_hello.raw_message().to_vec();
        transcript.extend_from_slice(server_hello);
        let suite = CipherSuite::Aes128GcmSha256;
        let schedule = Tls13KeySchedule::new(suite, shared, &suite.hash().digest(&transcript))
            .expect("the cover key schedule must derive");
        let keys = schedule
            .traffic_keys(schedule.server_handshake_secret())
            .expect("cover handshake keys must derive");
        Tls13RecordLayer::new(suite, keys).expect("the cover record state must initialize")
    }

    /// One sealed cover EncryptedExtensions record, as the collector reads it.
    fn sealed_cover_flight(
        records: &mut Tls13RecordLayer,
        extensions: &[(u16, Vec<u8>)],
    ) -> Vec<u8> {
        let mut output = Vec::new();
        records
            .seal_into(
                ContentType::Handshake,
                &super::tests::message(extensions),
                0,
                &mut output,
            )
            .expect("the cover record must seal");
        output
    }

    /// The EncryptedExtensions message a built flight actually emits.
    fn emitted_encrypted_extensions(flight: &ServerFlight, client_hello: &ClientHello) -> Vec<u8> {
        let server_hello = flight
            .server_hello_record()
            .get(5..)
            .expect("a ServerHello record has a header");
        let server_public: [u8; 32] = server_hello
            .get(server_hello.len() - 32..)
            .expect("the ServerHello ends with the key share")
            .try_into()
            .expect("an X25519 share is 32 bytes");
        let shared = StaticSecret::from_bytes(CLIENT_SECRET)
            .agree(&server_public)
            .expect("the emitted ServerHello carries a contributory share");
        let mut records = cover_records(client_hello, server_hello, shared.as_bytes());

        let wire = flight.encrypted_handshake_records();
        let body_len = usize::from(u16::from_be_bytes(
            wire.get(3..5)
                .expect("the first record header is complete")
                .try_into()
                .expect("a record length is two bytes"),
        ));
        let mut first = wire
            .get(..5 + body_len)
            .expect("the first record is complete")
            .to_vec();
        let opened = records
            .open_in_place(&mut first)
            .expect("the emitted flight must authenticate under the client's keys");
        let plaintext = opened.plaintext();
        let message_len = plaintext
            .get(1..4)
            .map(|bytes| {
                (usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2])
            })
            .expect("the flight starts with a handshake header");
        plaintext
            .get(..4 + message_len)
            .expect("the EncryptedExtensions message is complete")
            .to_vec()
    }

    /// Builds the flight for `client` from a cover observation containing
    /// `extensions`, once through a materialized profile and once live.
    fn both_paths(extensions: &[(u16, Vec<u8>)]) -> (Vec<u8>, Vec<u8>) {
        let client = client();
        let class = client
            .normalized_profile_class()
            .expect("the fixture client must classify");
        let probe = client
            .controlled_cover_probe_template()
            .expect("a probe template must derive")
            .generate(0)
            .expect("a controlled probe must generate");

        let cover_secret = StaticSecret::from_bytes(COVER_SECRET);
        let cover_public = cover_secret.public_key();
        let probe_share: [u8; 32] = probe
            .hello()
            .key_shares()
            .find(|share| share.group() == X25519_GROUP)
            .expect("the probe offers X25519")
            .data()
            .try_into()
            .expect("an X25519 share is 32 bytes");
        let probe_session = probe
            .hello()
            .session_id()
            .expect("the probe carries a session ID")
            .to_vec();

        let observed_hello = cover_server_hello(&probe_session, &cover_public);
        let target = ServerHelloTemplate::parse(&observed_hello, probe.hello())
            .expect("the cover ServerHello must parse against the probe");
        let shared = cover_secret
            .agree(&probe_share)
            .expect("the probe offers a contributory share");
        let mut records = cover_records(probe.hello(), &observed_hello, shared.as_bytes());
        let sealed = sealed_cover_flight(&mut records, extensions);

        let plan = CoverHandshakePlan {
            emit_ccs: true,
            shape: CoverHandshakeRecordShape::Coalesced { wire_len: 4_096 },
        };
        let profile =
            CoverProfile::from_controlled_observation(class, &probe, target, plan, &sealed)
                .expect("the cover observation must become a profile");
        let materialized = profile
            .materialize(&client, [0x5a; 32])
            .expect("the profile must materialize for its own class");

        let auth_key = AuthKey::from_test_bytes([0x99; 32]);
        let identity = CertificateIdentity::from_seed([0x42; 32]);
        let from_profile = build_server_flight_with_shape(
            &client,
            &auth_key,
            materialized.server_hello,
            &identity,
            materialized.selected_alpn.as_deref(),
            materialized.plan,
        )
        .expect("the profile flight must build");

        // The live path: a fresh cover observation for this same client, whose
        // ALPN comes from the client's offer rather than the cover's answer.
        let live_hello = cover_server_hello(&SESSION_ID, &cover_public);
        let live_target = ServerHelloTemplate::parse(&live_hello, &client)
            .expect("the cover ServerHello must parse against the client");
        let live = build_server_flight_with_shape(
            &client,
            &auth_key,
            live_target,
            &identity,
            client.alpn_protocols().next(),
            plan,
        )
        .expect("the live flight must build");

        (
            emitted_encrypted_extensions(&from_profile, &client),
            emitted_encrypted_extensions(&live, &client),
        )
    }

    #[test]
    fn discarded_cover_extensions_do_not_change_what_the_client_receives() {
        let alpn = super::tests::alpn(b"h2");
        let plain = both_paths(&[(0x0010, alpn.clone())]);
        let decorated = both_paths(&[
            (0x0000, Vec::new()),
            (0x0010, alpn),
            (0x44cd, vec![0x00, 0x03, b'a', b'b', b'c']),
        ]);

        assert_eq!(
            plain.0, plain.1,
            "a profile built from an ALPN-only cover must match the live flight"
        );
        assert_eq!(
            decorated.0, decorated.1,
            "a profile built from a cover carrying discarded extensions must match the live flight"
        );
        assert_eq!(
            plain.0, decorated.0,
            "the discarded extensions must not reach the emitted flight at all"
        );
    }

    #[test]
    fn a_cover_that_selects_no_alpn_still_matches_the_live_path() {
        // The live path emits the client's first offered protocol, so this is
        // the one place the two paths may legitimately differ: the profile
        // remembers that the cover declined. Assert the difference is exactly
        // that, and that both remain protocols the client offered.
        let (from_profile, live) = both_paths(&[(0x0000, Vec::new())]);
        assert!(
            classify_encrypted_extensions(&from_profile)
                .expect("the emitted flight is well formed")
                .is_none(),
            "declining ALPN is what the cover did, so the profile declines too"
        );
        assert_eq!(
            classify_encrypted_extensions(&live)
                .expect("the emitted flight is well formed")
                .as_deref(),
            Some(OFFERED_ALPN[0]),
            "the live path selects the client's first offer"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{CoverProfileError, classify_encrypted_extensions};

    /// Frames one `EncryptedExtensions` handshake message.
    pub(super) fn message(extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut vector = Vec::new();
        for (extension_type, body) in extensions {
            vector.extend_from_slice(&extension_type.to_be_bytes());
            vector.extend_from_slice(&length(body.len()).to_be_bytes());
            vector.extend_from_slice(body);
        }
        let mut payload = length(vector.len()).to_be_bytes().to_vec();
        payload.extend_from_slice(&vector);
        let mut framed = vec![super::HANDSHAKE_ENCRYPTED_EXTENSIONS];
        framed.extend_from_slice(&u32::from(length(payload.len())).to_be_bytes()[1..]);
        framed.extend_from_slice(&payload);
        framed
    }

    fn length(value: usize) -> u16 {
        u16::try_from(value).expect("test fixtures stay inside a TLS vector")
    }

    /// One server-selected ALPN protocol, as the extension body.
    pub(super) fn alpn(protocol: &[u8]) -> Vec<u8> {
        let mut list = vec![u8::try_from(protocol.len()).expect("test protocol")];
        list.extend_from_slice(protocol);
        let mut body = length(list.len()).to_be_bytes().to_vec();
        body.extend_from_slice(&list);
        body
    }

    #[test]
    fn parses_only_one_exact_server_alpn_selection() {
        assert_eq!(
            classify_encrypted_extensions(&message(&[(0x0010, alpn(b"h2"))])),
            Ok(Some(b"h2".to_vec()))
        );
        assert_eq!(classify_encrypted_extensions(&message(&[])), Ok(None));
    }

    #[test]
    fn rejects_truncated_or_multi_protocol_alpn() {
        let mut two_protocols = alpn(b"h2");
        two_protocols.extend_from_slice(&[2, b'h', b'3']);
        let list_len = length(two_protocols.len() - 2).to_be_bytes();
        two_protocols
            .get_mut(..2)
            .expect("the body starts with its list length")
            .copy_from_slice(&list_len);
        assert_eq!(
            classify_encrypted_extensions(&message(&[(0x0010, two_protocols)])),
            Err(CoverProfileError::MalformedEncryptedExtensions)
        );
        assert_eq!(
            classify_encrypted_extensions(&message(&[(0x0010, vec![0, 1, 0])])),
            Err(CoverProfileError::MalformedEncryptedExtensions)
        );
    }

    /// The rule under test is semantic, not a list of known covers: a
    /// structurally valid extension the emitted flight would not have carried
    /// anyway must not cost the class its profile.
    #[test]
    fn discards_structurally_valid_extensions_the_flight_never_emits() {
        // An empty `server_name` acknowledgement (RFC 8446 section 4.2) and an
        // opaque extension carrying a body, before and after the ALPN, in one
        // message and alone.
        let opaque = vec![0x00, 0x03, b'a', b'b', b'c'];
        assert_eq!(
            classify_encrypted_extensions(&message(&[
                (0x0000, Vec::new()),
                (0x0010, alpn(b"h2")),
                (0x44cd, opaque.clone()),
            ])),
            Ok(Some(b"h2".to_vec()))
        );
        assert_eq!(
            classify_encrypted_extensions(&message(&[(0x44cd, opaque), (0x0000, Vec::new()),])),
            Ok(None),
            "a cover that selects no ALPN is still profilable"
        );
    }

    /// `early_data` asserts an accepted 0-RTT negotiation, and a PSK
    /// ClientHello never reaches classification at all. Observing it means the
    /// cover negotiated state this mechanism does not model.
    #[test]
    fn rejects_an_extension_bound_to_state_a_profile_cannot_reconstruct() {
        assert_eq!(
            classify_encrypted_extensions(&message(&[(0x002a, Vec::new())])),
            Err(CoverProfileError::UnsupportedEncryptedExtension)
        );
        assert_eq!(
            classify_encrypted_extensions(&message(
                &[(0x0010, alpn(b"h2")), (0x002a, Vec::new()),]
            )),
            Err(CoverProfileError::UnsupportedEncryptedExtension),
            "a usable ALPN does not excuse an unmodellable negotiation"
        );
    }

    #[test]
    fn rejects_a_repeated_extension_type() {
        for repeated in [
            message(&[(0x0000, Vec::new()), (0x0000, Vec::new())]),
            message(&[(0x0010, alpn(b"h2")), (0x0010, alpn(b"h2"))]),
            message(&[
                (0x0010, alpn(b"h2")),
                (0x0000, Vec::new()),
                (0x0010, alpn(b"http/1.1")),
            ]),
        ] {
            assert_eq!(
                classify_encrypted_extensions(&repeated),
                Err(CoverProfileError::MalformedEncryptedExtensions)
            );
        }
    }

    #[test]
    fn rejects_malformed_framing_around_a_discarded_extension() {
        // An extension whose declared length overruns the vector.
        let mut truncated = message(&[(0x44cd, vec![1, 2, 3, 4])]);
        truncated
            .get_mut(9)
            .map(|byte| *byte = 0x40)
            .expect("the fixture carries an extension length");
        assert_eq!(
            classify_encrypted_extensions(&truncated),
            Err(CoverProfileError::MalformedEncryptedExtensions)
        );
        // A handshake header claiming more than the record holds.
        let mut overrun = message(&[(0x0000, Vec::new())]);
        overrun
            .get_mut(3)
            .map(|byte| *byte = 0xff)
            .expect("the fixture carries a handshake length");
        assert_eq!(
            classify_encrypted_extensions(&overrun),
            Err(CoverProfileError::MalformedEncryptedExtensions)
        );
        // Not an EncryptedExtensions message at all.
        let mut wrong_type = message(&[(0x0010, alpn(b"h2"))]);
        wrong_type
            .get_mut(0)
            .map(|byte| *byte = 11)
            .expect("the fixture carries a handshake type");
        assert_eq!(
            classify_encrypted_extensions(&wrong_type),
            Err(CoverProfileError::MalformedEncryptedExtensions)
        );
    }

    /// A cover that coalesces its whole flight into one record hands this
    /// function EncryptedExtensions followed by Certificate, CertificateVerify
    /// and Finished. Only the first message is classified, and the remainder is
    /// left alone — reading past the framed message would reject exactly the
    /// covers the coalesced record shape exists to reproduce.
    #[test]
    fn classifies_the_first_message_of_a_coalesced_flight() {
        let mut coalesced = message(&[(0x0010, alpn(b"h2"))]);
        coalesced.extend_from_slice(&[11, 0, 0, 4, 0, 0, 0, 0]);
        assert_eq!(
            classify_encrypted_extensions(&coalesced),
            Ok(Some(b"h2".to_vec()))
        );
    }

    #[test]
    fn rejects_more_extensions_than_the_bound_allows() {
        let bounded: Vec<(u16, Vec<u8>)> = (0..u16::try_from(super::MAX_ENCRYPTED_EXTENSIONS)
            .expect("the bound fits a u16"))
            .map(|extension_type| (extension_type.wrapping_add(0x0100), Vec::new()))
            .collect();
        assert_eq!(classify_encrypted_extensions(&message(&bounded)), Ok(None));

        let mut excessive = bounded;
        excessive.push((0x0f00, Vec::new()));
        assert_eq!(
            classify_encrypted_extensions(&message(&excessive)),
            Err(CoverProfileError::MalformedEncryptedExtensions)
        );
    }
}
