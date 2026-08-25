use std::{error::Error, fmt, ops::Range};

use crate::protocol::reality::{ClientHello, X25519_GROUP, X25519_MLKEM768_GROUP};

use super::CipherSuite;

const HANDSHAKE_SERVER_HELLO: u8 = 2;
const LEGACY_TLS12_VERSION: u16 = 0x0303;
const TLS13_VERSION: u16 = 0x0304;
const EXTENSION_PRE_SHARED_KEY: u16 = 0x0029;
const EXTENSION_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXTENSION_KEY_SHARE: u16 = 0x0033;
const MAX_SERVER_HELLO_LEN: usize = 8 * 1024;
const MAX_EXTENSIONS: usize = 64;
const X25519_KEY_EXCHANGE_LEN: usize = 32;
const MLKEM768_CIPHERTEXT_LEN: usize = 1_088;
const X25519_MLKEM768_SERVER_SHARE_LEN: usize = MLKEM768_CIPHERTEXT_LEN + 32;
const SERVER_RANDOM_START: usize = 6;
const SERVER_RANDOM_END: usize = SERVER_RANDOM_START + 32;
const SESSION_ID_LENGTH_OFFSET: usize = SERVER_RANDOM_END;
const SESSION_ID_START: usize = SESSION_ID_LENGTH_OFFSET + 1;

/// A target ServerHello cannot safely seed the dedicated REALITY handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerHelloError {
    /// The declared handshake or vector bytes are truncated.
    Truncated,
    /// Input exceeds the repository's fixed ServerHello bound.
    TooLarge,
    /// The message is not a structurally exact TLS ServerHello.
    Malformed,
    /// The target did not negotiate TLS 1.3.
    UnsupportedVersion,
    /// The selected cipher is unsupported or was not offered by the client.
    UnsupportedCipherSuite,
    /// The selected key-share group is unsupported or was not offered.
    UnsupportedKeyShare,
    /// The target selected PSK resumption, which this server does not mirror.
    PreSharedKeySelected,
    /// The target did not echo the client's exact legacy session ID.
    SessionIdMismatch,
    /// A replacement key share does not have the target's exact encoded length.
    ReplacementLength,
    /// A plaintext TLS record length cannot be represented on the wire.
    RecordLength,
    /// Reserving a bounded output buffer failed.
    BufferAllocation,
}

impl fmt::Display for ServerHelloError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("target TLS ServerHello is not REALITY-compatible")
    }
}

impl Error for ServerHelloError {}

/// Validated target presentation bytes with a replaceable server key share.
pub struct ServerHelloTemplate {
    message: Vec<u8>,
    suite: CipherSuite,
    key_share_group: u16,
    key_exchange: Range<usize>,
}

/// Stable cover-derived ServerHello bytes with every session field erased.
///
/// The skeleton retains target extension structure/order and negotiation, but
/// stores zeroes in the server-random, echoed-session-ID, and key-exchange
/// ranges. Materialization copies the bounded skeleton and supplies a fresh
/// random plus the exact current client session ID. The handshake builder then
/// supplies a fresh ephemeral server share as it does on the live-cover path.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ServerHelloProfileTemplate {
    message: Vec<u8>,
    suite: CipherSuite,
    key_share_group: u16,
    key_exchange: Range<usize>,
}

impl ServerHelloTemplate {
    /// Parses a target ServerHello against the exact REALITY ClientHello offer.
    ///
    /// # Errors
    ///
    /// Rejects malformed messages, unoffered negotiation, unsupported
    /// suites/groups, PSK selection, and session-ID mismatch.
    pub fn parse(message: &[u8], client: &ClientHello) -> Result<Self, ServerHelloError> {
        if message.len() > MAX_SERVER_HELLO_LEN {
            return Err(ServerHelloError::TooLarge);
        }
        let mut reader = Reader::new(message);
        if reader.read_u8()? != HANDSHAKE_SERVER_HELLO {
            return Err(ServerHelloError::Malformed);
        }
        let declared = reader.read_u24()?;
        if declared != reader.remaining() {
            return Err(ServerHelloError::Malformed);
        }
        if reader.read_u16()? != LEGACY_TLS12_VERSION {
            return Err(ServerHelloError::Malformed);
        }
        reader.read_bytes(32)?;
        let session_id_len = usize::from(reader.read_u8()?);
        if session_id_len > 32 {
            return Err(ServerHelloError::Malformed);
        }
        let session_id = reader.read_bytes(session_id_len)?;
        if client.session_id() != Some(session_id) {
            return Err(ServerHelloError::SessionIdMismatch);
        }

        let suite_wire = reader.read_u16()?;
        let suite = CipherSuite::from_wire(suite_wire)
            .filter(|_| client.cipher_offered(suite_wire))
            .ok_or(ServerHelloError::UnsupportedCipherSuite)?;
        if reader.read_u8()? != 0 {
            return Err(ServerHelloError::Malformed);
        }

        let extensions_len = usize::from(reader.read_u16()?);
        let mut extensions = reader.subreader(extensions_len)?;
        if !reader.is_empty() {
            return Err(ServerHelloError::Malformed);
        }
        let mut seen = Vec::new();
        let mut negotiated_tls13 = false;
        let mut key_share = None;
        while !extensions.is_empty() {
            if seen.len() >= MAX_EXTENSIONS {
                return Err(ServerHelloError::Malformed);
            }
            let extension_type = extensions.read_u16()?;
            if seen.contains(&extension_type) {
                return Err(ServerHelloError::Malformed);
            }
            seen.push(extension_type);
            let extension_len = usize::from(extensions.read_u16()?);
            let mut extension = extensions.subreader(extension_len)?;
            match extension_type {
                EXTENSION_SUPPORTED_VERSIONS => {
                    negotiated_tls13 = extension.read_u16()? == TLS13_VERSION;
                }
                EXTENSION_KEY_SHARE => {
                    let group = extension.read_u16()?;
                    let exchange_len = usize::from(extension.read_u16()?);
                    let exchange = extension.read_range(exchange_len)?;
                    validate_key_share(group, exchange_len, client)?;
                    key_share = Some((group, exchange));
                }
                EXTENSION_PRE_SHARED_KEY => {
                    return Err(ServerHelloError::PreSharedKeySelected);
                }
                _ => extension.skip_remaining(),
            }
            if !extension.is_empty() {
                return Err(ServerHelloError::Malformed);
            }
        }
        if !negotiated_tls13 {
            return Err(ServerHelloError::UnsupportedVersion);
        }
        let (key_share_group, key_exchange) =
            key_share.ok_or(ServerHelloError::UnsupportedKeyShare)?;
        Ok(Self {
            message: message.to_vec(),
            suite,
            key_share_group,
            key_exchange,
        })
    }

    /// Returns the target-selected TLS 1.3 cipher suite.
    #[must_use]
    pub const fn suite(&self) -> CipherSuite {
        self.suite
    }

    /// Returns the target-selected key-share group.
    #[must_use]
    pub const fn key_share_group(&self) -> u16 {
        self.key_share_group
    }

    /// Returns the exact target handshake bytes before key-share replacement.
    #[must_use]
    pub fn raw_message(&self) -> &[u8] {
        &self.message
    }

    /// Returns the observed cover key exchange for a controlled collector.
    ///
    /// User handshakes never expose or persist this value. The collector needs
    /// it only to derive the cover handshake read keys before erasing it from
    /// the immutable profile skeleton.
    pub(crate) fn observed_key_exchange(&self) -> Option<&[u8]> {
        self.message.get(self.key_exchange.clone())
    }

    /// Erases all per-session target values and returns a stable profile skeleton.
    pub(crate) fn into_profile_template(
        mut self,
    ) -> Result<ServerHelloProfileTemplate, ServerHelloError> {
        let session_len = usize::from(
            *self
                .message
                .get(SESSION_ID_LENGTH_OFFSET)
                .ok_or(ServerHelloError::Malformed)?,
        );
        let session_end = SESSION_ID_START
            .checked_add(session_len)
            .ok_or(ServerHelloError::TooLarge)?;
        self.message
            .get_mut(SERVER_RANDOM_START..SERVER_RANDOM_END)
            .ok_or(ServerHelloError::Malformed)?
            .fill(0);
        self.message
            .get_mut(SESSION_ID_START..session_end)
            .ok_or(ServerHelloError::Malformed)?
            .fill(0);
        self.message
            .get_mut(self.key_exchange.clone())
            .ok_or(ServerHelloError::Malformed)?
            .fill(0);
        Ok(ServerHelloProfileTemplate {
            message: self.message,
            suite: self.suite,
            key_share_group: self.key_share_group,
            key_exchange: self.key_exchange,
        })
    }

    /// Consumes the template and replaces only the key-exchange bytes.
    ///
    /// # Errors
    ///
    /// Rejects a replacement whose length differs from the validated field.
    pub fn into_patched_message(mut self, replacement: &[u8]) -> Result<Vec<u8>, ServerHelloError> {
        if replacement.len() != self.key_exchange.len() {
            return Err(ServerHelloError::ReplacementLength);
        }
        self.message
            .get_mut(self.key_exchange)
            .ok_or(ServerHelloError::Malformed)?
            .copy_from_slice(replacement);
        Ok(self.message)
    }
}

impl ServerHelloProfileTemplate {
    /// Creates one session template from stable profile bytes.
    ///
    /// # Errors
    ///
    /// Rejects a changed offer, mismatched session-ID length, malformed
    /// skeleton, or bounded allocation failure. These failures select the
    /// live cover rather than guessing.
    pub(crate) fn materialize(
        &self,
        client: &ClientHello,
        server_random: [u8; 32],
    ) -> Result<ServerHelloTemplate, ServerHelloError> {
        if !client.cipher_offered(self.suite.wire_value()) {
            return Err(ServerHelloError::UnsupportedCipherSuite);
        }
        validate_key_share(self.key_share_group, self.key_exchange.len(), client)?;
        let session_id = client
            .session_id()
            .ok_or(ServerHelloError::SessionIdMismatch)?;
        let stored_session_len = usize::from(
            *self
                .message
                .get(SESSION_ID_LENGTH_OFFSET)
                .ok_or(ServerHelloError::Malformed)?,
        );
        if session_id.len() != stored_session_len {
            return Err(ServerHelloError::SessionIdMismatch);
        }
        let session_end = SESSION_ID_START
            .checked_add(stored_session_len)
            .ok_or(ServerHelloError::TooLarge)?;
        let mut message = Vec::new();
        message
            .try_reserve_exact(self.message.len())
            .map_err(|_| ServerHelloError::BufferAllocation)?;
        message.extend_from_slice(&self.message);
        message
            .get_mut(SERVER_RANDOM_START..SERVER_RANDOM_END)
            .ok_or(ServerHelloError::Malformed)?
            .copy_from_slice(&server_random);
        message
            .get_mut(SESSION_ID_START..session_end)
            .ok_or(ServerHelloError::Malformed)?
            .copy_from_slice(session_id);
        Ok(ServerHelloTemplate {
            message,
            suite: self.suite,
            key_share_group: self.key_share_group,
            key_exchange: self.key_exchange.clone(),
        })
    }

    #[cfg(test)]
    fn raw_message(&self) -> &[u8] {
        &self.message
    }
}

impl fmt::Debug for ServerHelloTemplate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerHelloTemplate")
            .field("suite", &self.suite)
            .field("key_share_group", &self.key_share_group)
            .field("message_len", &self.message.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for ServerHelloProfileTemplate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerHelloProfileTemplate")
            .field("suite", &self.suite)
            .field("key_share_group", &self.key_share_group)
            .field("message_len", &self.message.len())
            .finish_non_exhaustive()
    }
}

/// Wraps one bounded handshake message in a plaintext TLS record.
///
/// # Errors
///
/// Rejects messages whose size cannot fit the 16-bit TLS record length.
pub fn plaintext_handshake_record(message: &[u8]) -> Result<Vec<u8>, ServerHelloError> {
    let encoded_len = u16::try_from(message.len()).map_err(|_| ServerHelloError::RecordLength)?;
    let capacity = 5_usize
        .checked_add(message.len())
        .ok_or(ServerHelloError::RecordLength)?;
    let mut record = Vec::new();
    record
        .try_reserve_exact(capacity)
        .map_err(|_| ServerHelloError::BufferAllocation)?;
    record.extend_from_slice(&[22, 3, 3]);
    record.extend_from_slice(&encoded_len.to_be_bytes());
    record.extend_from_slice(message);
    Ok(record)
}

/// Returns the fixed TLS 1.3 middlebox-compatibility ChangeCipherSpec record.
#[must_use]
pub const fn change_cipher_spec_record() -> [u8; 6] {
    [20, 3, 3, 0, 1, 1]
}

fn validate_key_share(
    group: u16,
    exchange_len: usize,
    client: &ClientHello,
) -> Result<(), ServerHelloError> {
    let expected_len = match group {
        X25519_GROUP => X25519_KEY_EXCHANGE_LEN,
        X25519_MLKEM768_GROUP => X25519_MLKEM768_SERVER_SHARE_LEN,
        _ => return Err(ServerHelloError::UnsupportedKeyShare),
    };
    if exchange_len != expected_len || !client.key_share_group_offered(group) {
        return Err(ServerHelloError::UnsupportedKeyShare);
    }
    Ok(())
}

struct Reader<'a> {
    input: &'a [u8],
    position: usize,
    base: usize,
}

impl<'a> Reader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            position: 0,
            base: 0,
        }
    }

    fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.position)
    }

    fn is_empty(&self) -> bool {
        self.position == self.input.len()
    }

    fn read_u8(&mut self) -> Result<u8, ServerHelloError> {
        let value = *self
            .input
            .get(self.position)
            .ok_or(ServerHelloError::Truncated)?;
        self.position += 1;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, ServerHelloError> {
        let bytes: [u8; 2] = self
            .read_bytes(2)?
            .try_into()
            .map_err(|_| ServerHelloError::Truncated)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u24(&mut self) -> Result<usize, ServerHelloError> {
        let bytes = self.read_bytes(3)?;
        Ok((usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2]))
    }

    fn read_bytes(&mut self, length: usize) -> Result<&'a [u8], ServerHelloError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ServerHelloError::TooLarge)?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(ServerHelloError::Truncated)?;
        self.position = end;
        Ok(bytes)
    }

    fn read_range(&mut self, length: usize) -> Result<Range<usize>, ServerHelloError> {
        let start = self
            .base
            .checked_add(self.position)
            .ok_or(ServerHelloError::TooLarge)?;
        self.read_bytes(length)?;
        let end = self
            .base
            .checked_add(self.position)
            .ok_or(ServerHelloError::TooLarge)?;
        Ok(start..end)
    }

    fn subreader(&mut self, length: usize) -> Result<Self, ServerHelloError> {
        let base = self
            .base
            .checked_add(self.position)
            .ok_or(ServerHelloError::TooLarge)?;
        Ok(Self {
            input: self.read_bytes(length)?,
            position: 0,
            base,
        })
    }

    fn skip_remaining(&mut self) {
        self.position = self.input.len();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EXTENSION_KEY_SHARE, EXTENSION_PRE_SHARED_KEY, EXTENSION_SUPPORTED_VERSIONS,
        HANDSHAKE_SERVER_HELLO, LEGACY_TLS12_VERSION, ServerHelloError, ServerHelloTemplate,
        TLS13_VERSION, change_cipher_spec_record, plaintext_handshake_record,
    };
    use crate::protocol::reality::{
        ClientHello, SESSION_ID_LEN, X25519_GROUP, client_hello::fixtures,
    };

    #[test]
    fn parses_target_and_replaces_only_x25519_key_exchange() {
        let client = client(X25519_GROUP, &[0x22; 32]);
        let message = server_hello(
            &[0x11; SESSION_ID_LEN],
            0x1301,
            X25519_GROUP,
            &[0x55; 32],
            &[],
        );
        let template = ServerHelloTemplate::parse(&message, &client)
            .expect("matching target ServerHello must parse");

        assert_eq!(template.suite().wire_value(), 0x1301);
        assert_eq!(template.key_share_group(), X25519_GROUP);
        assert_eq!(template.raw_message(), message);
        let patched = template
            .into_patched_message(&[0x77; 32])
            .expect("same-length share must patch");
        assert_eq!(patched.len(), message.len());
        assert_eq!(patched.iter().filter(|byte| **byte == 0x77).count(), 32);
        assert_eq!(message.iter().filter(|byte| **byte == 0x55).count(), 32);
        assert_eq!(patched.iter().filter(|byte| **byte == 0x55).count(), 0);
    }

    #[test]
    fn profile_erases_and_regenerates_every_server_hello_session_field() {
        let observed_client = client(X25519_GROUP, &[0x22; 32]);
        let observed = server_hello(
            &[0x11; SESSION_ID_LEN],
            0x1301,
            X25519_GROUP,
            &[0x55; 32],
            &[],
        );
        let profile = ServerHelloTemplate::parse(&observed, &observed_client)
            .expect("observed target ServerHello must parse")
            .into_profile_template()
            .expect("per-session fields must erase");

        assert_eq!(&profile.raw_message()[6..38], &[0; 32]);
        assert_eq!(&profile.raw_message()[39..71], &[0; SESSION_ID_LEN]);
        assert_eq!(
            &profile.raw_message()[profile.raw_message().len() - 32..],
            &[0; 32]
        );

        let current = ClientHello::parse_message(&fixtures::client_hello_with_key_share(
            [0x33; 32],
            &[0x44; SESSION_ID_LEN],
            "www.example.com",
            &[b"h2"],
            X25519_GROUP,
            &[0x66; 32],
        ))
        .expect("current ClientHello must parse");
        let materialized = profile
            .materialize(&current, [0x77; 32])
            .expect("matching current offer must materialize")
            .into_patched_message(&[0x88; 32])
            .expect("fresh server share must patch");

        assert_eq!(&materialized[6..38], &[0x77; 32]);
        assert_eq!(&materialized[39..71], &[0x44; SESSION_ID_LEN]);
        assert_eq!(&materialized[materialized.len() - 32..], &[0x88; 32]);
        assert_ne!(&materialized[6..38], &observed[6..38]);
    }

    #[test]
    fn rejects_negotiation_not_offered_by_client() {
        let client = client(X25519_GROUP, &[0x22; 32]);
        let wrong_suite = server_hello(
            &[0x11; SESSION_ID_LEN],
            0x1302,
            X25519_GROUP,
            &[0x55; 32],
            &[],
        );
        assert!(matches!(
            ServerHelloTemplate::parse(&wrong_suite, &client),
            Err(ServerHelloError::UnsupportedCipherSuite)
        ));

        let wrong_session = server_hello(
            &[0x12; SESSION_ID_LEN],
            0x1301,
            X25519_GROUP,
            &[0x55; 32],
            &[],
        );
        assert!(matches!(
            ServerHelloTemplate::parse(&wrong_session, &client),
            Err(ServerHelloError::SessionIdMismatch)
        ));
    }

    #[test]
    fn rejects_target_psk_selection_and_bad_key_length() {
        let client = client(X25519_GROUP, &[0x22; 32]);
        let psk = server_hello(
            &[0x11; SESSION_ID_LEN],
            0x1301,
            X25519_GROUP,
            &[0x55; 32],
            &[(EXTENSION_PRE_SHARED_KEY, &[0, 0])],
        );
        assert!(matches!(
            ServerHelloTemplate::parse(&psk, &client),
            Err(ServerHelloError::PreSharedKeySelected)
        ));

        let short_key = server_hello(
            &[0x11; SESSION_ID_LEN],
            0x1301,
            X25519_GROUP,
            &[0x55; 31],
            &[],
        );
        assert!(matches!(
            ServerHelloTemplate::parse(&short_key, &client),
            Err(ServerHelloError::UnsupportedKeyShare)
        ));
    }

    #[test]
    fn wraps_plaintext_record_and_emits_fixed_ccs() {
        let record =
            plaintext_handshake_record(&[2, 0, 0, 0]).expect("small handshake must fit a record");
        assert_eq!(record, [22, 3, 3, 0, 4, 2, 0, 0, 0]);
        assert_eq!(change_cipher_spec_record(), [20, 3, 3, 0, 1, 1]);
    }

    #[test]
    fn arbitrary_target_bytes_never_panic() {
        let client = client(X25519_GROUP, &[0x22; 32]);
        let mut state = 0x51a7_d31b_u32;
        for length in 0..2_048 {
            let mut input = vec![0_u8; length];
            for byte in &mut input {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                *byte = state.to_le_bytes()[0];
            }
            let _ = ServerHelloTemplate::parse(&input, &client);
        }
    }

    fn client(group: u16, key_exchange: &[u8]) -> ClientHello {
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

    fn server_hello(
        session_id: &[u8],
        suite: u16,
        group: u16,
        key_exchange: &[u8],
        extra_extensions: &[(u16, &[u8])],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&LEGACY_TLS12_VERSION.to_be_bytes());
        body.extend_from_slice(&[0x33; 32]);
        body.push(u8::try_from(session_id.len()).expect("test session ID must fit"));
        body.extend_from_slice(session_id);
        body.extend_from_slice(&suite.to_be_bytes());
        body.push(0);

        let mut extensions = Vec::new();
        push_extension(
            &mut extensions,
            EXTENSION_SUPPORTED_VERSIONS,
            &TLS13_VERSION.to_be_bytes(),
        );
        let mut share = Vec::new();
        share.extend_from_slice(&group.to_be_bytes());
        share.extend_from_slice(
            &u16::try_from(key_exchange.len())
                .expect("test key share must fit")
                .to_be_bytes(),
        );
        share.extend_from_slice(key_exchange);
        push_extension(&mut extensions, EXTENSION_KEY_SHARE, &share);
        for (extension_type, value) in extra_extensions {
            push_extension(&mut extensions, *extension_type, value);
        }
        body.extend_from_slice(
            &u16::try_from(extensions.len())
                .expect("test extensions must fit")
                .to_be_bytes(),
        );
        body.extend_from_slice(&extensions);

        let mut message = Vec::new();
        message.push(HANDSHAKE_SERVER_HELLO);
        let length = u32::try_from(body.len()).expect("test body must fit");
        message.extend_from_slice(&length.to_be_bytes()[1..]);
        message.extend_from_slice(&body);
        message
    }

    fn push_extension(output: &mut Vec<u8>, extension_type: u16, value: &[u8]) {
        output.extend_from_slice(&extension_type.to_be_bytes());
        output.extend_from_slice(
            &u16::try_from(value.len())
                .expect("test extension must fit")
                .to_be_bytes(),
        );
        output.extend_from_slice(value);
    }
}
