use std::{error::Error, fmt, ops::Range, sync::Arc};

/// Maximum accepted ClientHello handshake message, including its four-byte header.
pub const MAX_CLIENT_HELLO_BYTES: usize = 64 * 1024;
/// Offset of the session ID bytes when the session ID has the REALITY length.
pub const SESSION_ID_OFFSET: usize = 39;
/// REALITY authentication ciphertext length.
pub const SESSION_ID_LEN: usize = 32;
/// TLS NamedGroup identifier for X25519.
pub const X25519_GROUP: u16 = 0x001d;
/// Xray-compatible NamedGroup identifier for X25519MLKEM768.
pub const X25519_MLKEM768_GROUP: u16 = 0x11ec;
/// ML-KEM-768 encapsulation key bytes in the hybrid client share.
pub const MLKEM768_ENCAP_KEY_LEN: usize = 1_184;
/// Complete X25519MLKEM768 client share length.
pub const X25519_MLKEM768_SHARE_LEN: usize = MLKEM768_ENCAP_KEY_LEN + 32;

const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const TLS13_VERSION: u16 = 0x0304;

const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_ALPN: u16 = 0x0010;
const EXT_PRE_SHARED_KEY: u16 = 0x0029;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;

const MAX_EXTENSIONS: usize = 256;
const MAX_KEY_SHARES: usize = 16;
const MAX_ALPN_PROTOCOLS: usize = 32;
const MAX_PSK_IDENTITIES: usize = 16;
const MAX_PSK_BINDERS: usize = 16;

/// A strict ClientHello parsing failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientHelloError {
    /// The declared bytes have not all arrived.
    Truncated,
    /// Input exceeds the server's hard ClientHello allocation limit.
    TooLarge,
    /// A TLS record does not carry a handshake.
    NotHandshakeRecord,
    /// The handshake is not a ClientHello.
    NotClientHello,
    /// An outer declared length does not exactly match the supplied input.
    LengthMismatch,
    /// A bounded TLS vector or extension violates its structural invariant.
    Malformed(&'static str),
}

impl fmt::Display for ClientHelloError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => formatter.write_str("truncated TLS ClientHello"),
            Self::TooLarge => formatter.write_str("TLS ClientHello exceeds the hard size limit"),
            Self::NotHandshakeRecord => formatter.write_str("TLS record is not a handshake record"),
            Self::NotClientHello => formatter.write_str("TLS handshake is not a ClientHello"),
            Self::LengthMismatch => {
                formatter.write_str("TLS ClientHello length does not match input")
            }
            Self::Malformed(field) => write!(formatter, "malformed TLS ClientHello {field}"),
        }
    }
}

impl Error for ClientHelloError {}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KeyShareRange {
    group: u16,
    data: Range<usize>,
}

/// A borrowed key share whose bytes remain owned by [`ClientHello`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyShare<'hello> {
    group: u16,
    data: &'hello [u8],
}

impl<'hello> KeyShare<'hello> {
    /// Returns the TLS NamedGroup identifier.
    #[must_use]
    pub const fn group(self) -> u16 {
        self.group
    }

    /// Returns the exact key exchange bytes.
    #[must_use]
    pub const fn data(self) -> &'hello [u8] {
        self.data
    }
}

/// Strictly parsed fields needed by REALITY authentication and presentation.
///
/// The original handshake message is stored once. Variable-sized fields retain
/// checked byte ranges into that immutable allocation instead of owning copies.
#[derive(Clone, Debug)]
pub struct ClientHello {
    raw_message: Arc<[u8]>,
    random: [u8; 32],
    session_id: Range<usize>,
    server_name: Option<Range<usize>>,
    alpn: Vec<Range<usize>>,
    key_shares: Vec<KeyShareRange>,
    cipher_suites: Vec<u16>,
    offers_tls13: bool,
    offers_psk: bool,
}

impl ClientHello {
    /// Parses one complete TLS handshake message without a record header.
    ///
    /// # Errors
    ///
    /// Rejects truncated, oversized, non-ClientHello, duplicate-extension, and
    /// structurally malformed input. Every attacker-controlled vector is bounded.
    pub fn parse_message(message: &[u8]) -> Result<Self, ClientHelloError> {
        if message.len() > MAX_CLIENT_HELLO_BYTES {
            return Err(ClientHelloError::TooLarge);
        }
        let mut reader = Reader::new(message);
        if reader.read_u8()? != HANDSHAKE_TYPE_CLIENT_HELLO {
            return Err(ClientHelloError::NotClientHello);
        }
        let declared =
            usize::try_from(reader.read_u24()?).map_err(|_| ClientHelloError::TooLarge)?;
        if declared != reader.remaining() {
            return Err(ClientHelloError::LengthMismatch);
        }

        let _legacy_version = reader.read_u16()?;
        let random: [u8; 32] = reader
            .read_bytes(32)?
            .try_into()
            .map_err(|_| ClientHelloError::Truncated)?;
        let session_id_len = usize::from(reader.read_u8()?);
        if session_id_len > SESSION_ID_LEN {
            return Err(ClientHelloError::Malformed("session ID"));
        }
        let session_id = reader.read_range(session_id_len)?;

        let cipher_bytes_len = usize::from(reader.read_u16()?);
        if cipher_bytes_len < 2 || cipher_bytes_len % 2 != 0 {
            return Err(ClientHelloError::Malformed("cipher suites"));
        }
        let cipher_bytes = reader.read_bytes(cipher_bytes_len)?;
        let cipher_suites = cipher_bytes
            .chunks_exact(2)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
            .collect();

        let compression_len = usize::from(reader.read_u8()?);
        if compression_len == 0 {
            return Err(ClientHelloError::Malformed("compression methods"));
        }
        reader.read_bytes(compression_len)?;

        let mut state = ExtensionState::default();
        if !reader.is_empty() {
            let extensions_len = usize::from(reader.read_u16()?);
            let mut extensions = reader.read_subreader(extensions_len)?;
            if !reader.is_empty() {
                return Err(ClientHelloError::LengthMismatch);
            }
            parse_extensions(&mut extensions, &mut state)?;
        }

        Ok(Self {
            raw_message: Arc::from(message),
            random,
            session_id,
            server_name: state.server_name,
            alpn: state.alpn,
            key_shares: state.key_shares,
            cipher_suites,
            offers_tls13: state.offers_tls13,
            offers_psk: state.offers_psk,
        })
    }

    /// Parses one complete TLS handshake record containing only a ClientHello.
    ///
    /// Fragmented records are handled by the incremental reader layer rather than
    /// this exact-record convenience function.
    ///
    /// # Errors
    ///
    /// Rejects non-handshake, truncated, trailing, or malformed records.
    pub fn parse_record(record: &[u8]) -> Result<Self, ClientHelloError> {
        if record.len() < TLS_RECORD_HEADER_LEN {
            return Err(ClientHelloError::Truncated);
        }
        if record[0] != TLS_CONTENT_TYPE_HANDSHAKE {
            return Err(ClientHelloError::NotHandshakeRecord);
        }
        let body_len = usize::from(u16::from_be_bytes([record[3], record[4]]));
        let record_len = TLS_RECORD_HEADER_LEN
            .checked_add(body_len)
            .ok_or(ClientHelloError::TooLarge)?;
        if record.len() < record_len {
            return Err(ClientHelloError::Truncated);
        }
        if record.len() != record_len {
            return Err(ClientHelloError::LengthMismatch);
        }
        let body = record
            .get(TLS_RECORD_HEADER_LEN..record_len)
            .ok_or(ClientHelloError::Truncated)?;
        Self::parse_message(body)
    }

    /// Returns the exact ClientHello handshake bytes for the TLS transcript.
    #[must_use]
    pub fn raw_message(&self) -> &[u8] {
        &self.raw_message
    }

    /// Returns the 32-byte ClientHello random.
    #[must_use]
    pub const fn random(&self) -> &[u8; 32] {
        &self.random
    }

    /// Returns the validated SNI host name when present.
    #[must_use]
    pub fn server_name(&self) -> Option<&str> {
        let bytes = self.raw_message.get(self.server_name.clone()?)?;
        std::str::from_utf8(bytes).ok()
    }

    /// Returns the exact session ID bytes.
    #[must_use]
    pub fn session_id(&self) -> Option<&[u8]> {
        self.raw_message.get(self.session_id.clone())
    }

    /// Returns the fixed-size REALITY ciphertext only for a 32-byte session ID.
    #[must_use]
    pub fn session_ciphertext(&self) -> Option<&[u8; SESSION_ID_LEN]> {
        self.session_id()?.try_into().ok()
    }

    /// Builds the REALITY AEAD additional data with the session ID bytes zeroed.
    #[must_use]
    pub fn reality_aad(&self) -> Option<Vec<u8>> {
        self.session_ciphertext()?;
        let mut aad = self.raw_message.to_vec();
        aad.get_mut(self.session_id.clone())?.fill(0);
        Some(aad)
    }

    /// Returns the 12-byte REALITY AEAD nonce derived from random bytes 20 through 31.
    #[must_use]
    pub const fn aead_nonce(&self) -> [u8; 12] {
        [
            self.random[20],
            self.random[21],
            self.random[22],
            self.random[23],
            self.random[24],
            self.random[25],
            self.random[26],
            self.random[27],
            self.random[28],
            self.random[29],
            self.random[30],
            self.random[31],
        ]
    }

    /// Returns whether the supported-versions extension offers TLS 1.3.
    #[must_use]
    pub const fn offers_tls13(&self) -> bool {
        self.offers_tls13
    }

    /// Returns whether a structurally valid, bounded PSK offer was present.
    ///
    /// The REALITY server still performs a full handshake and never selects this PSK.
    #[must_use]
    pub const fn offers_psk(&self) -> bool {
        self.offers_psk
    }

    /// Iterates ALPN protocol bytes in client preference order.
    pub fn alpn_protocols(&self) -> impl Iterator<Item = &[u8]> {
        self.alpn
            .iter()
            .filter_map(|range| self.raw_message.get(range.clone()))
    }

    /// Iterates borrowed key shares without copying their attacker-controlled bytes.
    pub fn key_shares(&self) -> impl Iterator<Item = KeyShare<'_>> {
        self.key_shares.iter().filter_map(|share| {
            self.raw_message
                .get(share.data.clone())
                .map(|data| KeyShare {
                    group: share.group,
                    data,
                })
        })
    }

    /// Returns the offered standalone X25519 key, or the hybrid share's X25519 tail.
    #[must_use]
    pub fn peer_x25519(&self) -> Option<[u8; 32]> {
        if let Some(share) = self
            .key_shares()
            .find(|share| share.group == X25519_GROUP && share.data.len() == 32)
        {
            return share.data.try_into().ok();
        }
        let hybrid = self.key_shares().find(|share| {
            share.group == X25519_MLKEM768_GROUP && share.data.len() == X25519_MLKEM768_SHARE_LEN
        })?;
        hybrid
            .data
            .get(MLKEM768_ENCAP_KEY_LEN..X25519_MLKEM768_SHARE_LEN)?
            .try_into()
            .ok()
    }

    /// Returns the ML-KEM-768 encapsulation key from a valid hybrid share.
    #[must_use]
    pub fn peer_mlkem768_encapsulation_key(&self) -> Option<&[u8]> {
        let share = self.key_shares().find(|share| {
            share.group == X25519_MLKEM768_GROUP && share.data.len() == X25519_MLKEM768_SHARE_LEN
        })?;
        share.data.get(..MLKEM768_ENCAP_KEY_LEN)
    }

    /// Returns whether the client offered a cipher suite.
    #[must_use]
    pub fn cipher_offered(&self, cipher_suite: u16) -> bool {
        self.cipher_suites.contains(&cipher_suite)
    }

    /// Returns whether a non-GREASE share exists for the selected group.
    #[must_use]
    pub fn key_share_group_offered(&self, group: u16) -> bool {
        !is_grease(group) && self.key_shares.iter().any(|share| share.group == group)
    }
}

#[derive(Default)]
struct ExtensionState {
    seen: Vec<u16>,
    server_name: Option<Range<usize>>,
    alpn: Vec<Range<usize>>,
    key_shares: Vec<KeyShareRange>,
    offers_tls13: bool,
    offers_psk: bool,
}

fn parse_extensions(
    reader: &mut Reader<'_>,
    state: &mut ExtensionState,
) -> Result<(), ClientHelloError> {
    while !reader.is_empty() {
        if state.seen.len() >= MAX_EXTENSIONS {
            return Err(ClientHelloError::Malformed("extension count"));
        }
        let extension_type = reader.read_u16()?;
        if state.seen.contains(&extension_type) {
            return Err(ClientHelloError::Malformed("duplicate extension"));
        }
        state.seen.push(extension_type);
        let extension_len = usize::from(reader.read_u16()?);
        let mut extension = reader.read_subreader(extension_len)?;
        match extension_type {
            EXT_SERVER_NAME => state.server_name = parse_server_name(&mut extension)?,
            EXT_SUPPORTED_VERSIONS => {
                state.offers_tls13 = parse_supported_versions(&mut extension)?;
            }
            EXT_KEY_SHARE => state.key_shares = parse_key_shares(&mut extension)?,
            EXT_ALPN => state.alpn = parse_alpn(&mut extension)?,
            EXT_PRE_SHARED_KEY => {
                if !reader.is_empty() {
                    return Err(ClientHelloError::Malformed("pre-shared key ordering"));
                }
                parse_pre_shared_key(&mut extension)?;
                state.offers_psk = true;
            }
            _ => extension.skip_remaining(),
        }
        if !extension.is_empty() {
            return Err(ClientHelloError::Malformed("extension length"));
        }
    }
    Ok(())
}

fn parse_server_name(reader: &mut Reader<'_>) -> Result<Option<Range<usize>>, ClientHelloError> {
    let list_len = usize::from(reader.read_u16()?);
    let mut names = reader.read_subreader(list_len)?;
    if !reader.is_empty() || names.is_empty() {
        return Err(ClientHelloError::Malformed("server name"));
    }
    let mut host_name = None;
    while !names.is_empty() {
        let name_type = names.read_u8()?;
        let name_len = usize::from(names.read_u16()?);
        let range = names.read_range(name_len)?;
        if name_type == 0 {
            if host_name.is_some() {
                return Err(ClientHelloError::Malformed("duplicate host name"));
            }
            let bytes = names.bytes(&range)?;
            if bytes.is_empty() || bytes.len() > 253 || !bytes.is_ascii() || bytes.contains(&0) {
                return Err(ClientHelloError::Malformed("server name"));
            }
            host_name = Some(range);
        }
    }
    Ok(host_name)
}

fn parse_supported_versions(reader: &mut Reader<'_>) -> Result<bool, ClientHelloError> {
    let list_len = usize::from(reader.read_u8()?);
    if list_len < 2 || list_len % 2 != 0 {
        return Err(ClientHelloError::Malformed("supported versions"));
    }
    let mut versions = reader.read_subreader(list_len)?;
    if !reader.is_empty() {
        return Err(ClientHelloError::Malformed("supported versions"));
    }
    let mut offers_tls13 = false;
    while !versions.is_empty() {
        offers_tls13 |= versions.read_u16()? == TLS13_VERSION;
    }
    Ok(offers_tls13)
}

fn parse_key_shares(reader: &mut Reader<'_>) -> Result<Vec<KeyShareRange>, ClientHelloError> {
    let list_len = usize::from(reader.read_u16()?);
    let mut shares = reader.read_subreader(list_len)?;
    if !reader.is_empty() || shares.is_empty() {
        return Err(ClientHelloError::Malformed("key shares"));
    }
    let mut output = Vec::new();
    while !shares.is_empty() {
        if output.len() >= MAX_KEY_SHARES {
            return Err(ClientHelloError::Malformed("key share count"));
        }
        let group = shares.read_u16()?;
        let data_len = usize::from(shares.read_u16()?);
        if data_len == 0 {
            return Err(ClientHelloError::Malformed("empty key share"));
        }
        output.push(KeyShareRange {
            group,
            data: shares.read_range(data_len)?,
        });
    }
    Ok(output)
}

fn parse_alpn(reader: &mut Reader<'_>) -> Result<Vec<Range<usize>>, ClientHelloError> {
    let list_len = usize::from(reader.read_u16()?);
    let mut protocols = reader.read_subreader(list_len)?;
    if !reader.is_empty() || protocols.is_empty() {
        return Err(ClientHelloError::Malformed("ALPN"));
    }
    let mut output = Vec::new();
    while !protocols.is_empty() {
        if output.len() >= MAX_ALPN_PROTOCOLS {
            return Err(ClientHelloError::Malformed("ALPN protocol count"));
        }
        let protocol_len = usize::from(protocols.read_u8()?);
        if protocol_len == 0 {
            return Err(ClientHelloError::Malformed("empty ALPN protocol"));
        }
        output.push(protocols.read_range(protocol_len)?);
    }
    Ok(output)
}

fn parse_pre_shared_key(reader: &mut Reader<'_>) -> Result<(), ClientHelloError> {
    let identities_len = usize::from(reader.read_u16()?);
    let mut identities = reader.read_subreader(identities_len)?;
    let mut identity_count = 0;
    while !identities.is_empty() {
        if identity_count >= MAX_PSK_IDENTITIES {
            return Err(ClientHelloError::Malformed("PSK identity count"));
        }
        let identity_len = usize::from(identities.read_u16()?);
        if identity_len == 0 {
            return Err(ClientHelloError::Malformed("empty PSK identity"));
        }
        identities.read_bytes(identity_len)?;
        identities.read_bytes(4)?;
        identity_count += 1;
    }

    let binders_len = usize::from(reader.read_u16()?);
    let mut binders = reader.read_subreader(binders_len)?;
    if !reader.is_empty() {
        return Err(ClientHelloError::Malformed("PSK"));
    }
    let mut binder_count = 0;
    while !binders.is_empty() {
        if binder_count >= MAX_PSK_BINDERS {
            return Err(ClientHelloError::Malformed("PSK binder count"));
        }
        let binder_len = usize::from(binders.read_u8()?);
        if binder_len < 32 {
            return Err(ClientHelloError::Malformed("PSK binder"));
        }
        binders.read_bytes(binder_len)?;
        binder_count += 1;
    }
    if identity_count == 0 || identity_count != binder_count {
        return Err(ClientHelloError::Malformed("PSK identity and binder count"));
    }
    Ok(())
}

/// RFC 8701 GREASE value test.
const fn is_grease(value: u16) -> bool {
    (value & 0x0f0f) == 0x0a0a && (value >> 8) == (value & 0x00ff)
}

struct Reader<'input> {
    input: &'input [u8],
    position: usize,
    end: usize,
}

impl<'input> Reader<'input> {
    const fn new(input: &'input [u8]) -> Self {
        Self {
            input,
            position: 0,
            end: input.len(),
        }
    }

    const fn is_empty(&self) -> bool {
        self.position == self.end
    }

    const fn remaining(&self) -> usize {
        self.end.saturating_sub(self.position)
    }

    fn read_range(&mut self, length: usize) -> Result<Range<usize>, ClientHelloError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ClientHelloError::TooLarge)?;
        if end > self.end {
            return Err(ClientHelloError::Truncated);
        }
        let range = self.position..end;
        self.position = end;
        Ok(range)
    }

    fn read_bytes(&mut self, length: usize) -> Result<&'input [u8], ClientHelloError> {
        let range = self.read_range(length)?;
        self.bytes(&range)
    }

    fn bytes(&self, range: &Range<usize>) -> Result<&'input [u8], ClientHelloError> {
        self.input
            .get(range.clone())
            .ok_or(ClientHelloError::Truncated)
    }

    fn read_subreader(&mut self, length: usize) -> Result<Self, ClientHelloError> {
        let range = self.read_range(length)?;
        Ok(Self {
            input: self.input,
            position: range.start,
            end: range.end,
        })
    }

    fn read_u8(&mut self) -> Result<u8, ClientHelloError> {
        self.read_bytes(1)?
            .first()
            .copied()
            .ok_or(ClientHelloError::Truncated)
    }

    fn read_u16(&mut self) -> Result<u16, ClientHelloError> {
        let bytes: [u8; 2] = self
            .read_bytes(2)?
            .try_into()
            .map_err(|_| ClientHelloError::Truncated)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u24(&mut self) -> Result<u32, ClientHelloError> {
        let bytes: [u8; 3] = self
            .read_bytes(3)?
            .try_into()
            .map_err(|_| ClientHelloError::Truncated)?;
        Ok(u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]))
    }

    fn skip_remaining(&mut self) {
        self.position = self.end;
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::{
        EXT_ALPN, EXT_KEY_SHARE, EXT_SERVER_NAME, EXT_SUPPORTED_VERSIONS,
        HANDSHAKE_TYPE_CLIENT_HELLO, X25519_GROUP,
    };

    pub(crate) fn client_hello(
        random: [u8; 32],
        session_id: &[u8],
        server_name: &str,
        alpn: &[&[u8]],
    ) -> Vec<u8> {
        client_hello_with_key_share(
            random,
            session_id,
            server_name,
            alpn,
            X25519_GROUP,
            &[0x42; 32],
        )
    }

    pub(crate) fn client_hello_with_key_share(
        random: [u8; 32],
        session_id: &[u8],
        server_name: &str,
        alpn: &[&[u8]],
        key_share_group: u16,
        key_share_data: &[u8],
    ) -> Vec<u8> {
        let mut extensions = Vec::new();
        let mut names = vec![0];
        push_u16_length(&mut names, server_name.as_bytes());
        let mut server_name_body = Vec::new();
        push_u16_length(&mut server_name_body, &names);
        push_extension(&mut extensions, EXT_SERVER_NAME, &server_name_body);
        push_extension(&mut extensions, EXT_SUPPORTED_VERSIONS, &[2, 0x03, 0x04]);

        let mut share_entries = Vec::new();
        share_entries.extend_from_slice(&key_share_group.to_be_bytes());
        push_u16_length(&mut share_entries, key_share_data);
        let mut shares = Vec::new();
        push_u16_length(&mut shares, &share_entries);
        push_extension(&mut extensions, EXT_KEY_SHARE, &shares);

        if !alpn.is_empty() {
            let mut protocols = Vec::new();
            for protocol in alpn {
                protocols.push(u8::try_from(protocol.len()).expect("test ALPN must fit u8"));
                protocols.extend_from_slice(protocol);
            }
            let mut alpn_body = Vec::new();
            push_u16_length(&mut alpn_body, &protocols);
            push_extension(&mut extensions, EXT_ALPN, &alpn_body);
        }

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303_u16.to_be_bytes());
        body.extend_from_slice(&random);
        body.push(u8::try_from(session_id.len()).expect("test session ID must fit u8"));
        body.extend_from_slice(session_id);
        push_u16_length(&mut body, &0x1301_u16.to_be_bytes());
        body.extend_from_slice(&[1, 0]);
        push_u16_length(&mut body, &extensions);

        let mut message = vec![HANDSHAKE_TYPE_CLIENT_HELLO];
        let length = u32::try_from(body.len()).expect("test ClientHello must fit u24");
        message.extend_from_slice(&length.to_be_bytes()[1..]);
        message.extend_from_slice(&body);
        message
    }

    pub(crate) fn record(message: &[u8]) -> Vec<u8> {
        let mut output = vec![0x16, 0x03, 0x01];
        push_u16_length(&mut output, message);
        output
    }

    pub(crate) fn push_extension(output: &mut Vec<u8>, extension_type: u16, body: &[u8]) {
        output.extend_from_slice(&extension_type.to_be_bytes());
        push_u16_length(output, body);
    }

    fn push_u16_length(output: &mut Vec<u8>, bytes: &[u8]) {
        output.extend_from_slice(
            &u16::try_from(bytes.len())
                .expect("test vector length must fit u16")
                .to_be_bytes(),
        );
        output.extend_from_slice(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ClientHello, ClientHelloError, MAX_CLIENT_HELLO_BYTES, SESSION_ID_LEN, SESSION_ID_OFFSET,
        X25519_GROUP, X25519_MLKEM768_GROUP, X25519_MLKEM768_SHARE_LEN,
        fixtures::{client_hello, client_hello_with_key_share, record},
    };

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
}
