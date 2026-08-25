use std::{error::Error, fmt};

use crate::protocol::reality::{ClientHello, CoverProbe, NormalizedClientHelloClass};

use super::{
    ContentType, CoverHandshakePlan, ServerHelloProfileTemplate, ServerHelloTemplate,
    Tls13KeySchedule, Tls13RecordLayer,
};

const HANDSHAKE_ENCRYPTED_EXTENSIONS: u8 = 8;
const EXTENSION_ALPN: u16 = 0x0010;
const MAX_ENCRYPTED_EXTENSIONS: usize = 64;

/// A controlled cover observation cannot safely become a reusable profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoverProfileError {
    KeyAgreement,
    KeySchedule,
    Record,
    MalformedEncryptedExtensions,
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
        let selected_alpn = parse_encrypted_extensions_alpn(opened.plaintext())?;
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

fn parse_encrypted_extensions_alpn(input: &[u8]) -> Result<Option<Vec<u8>>, CoverProfileError> {
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
    let mut count = 0_usize;
    while !extensions.is_empty() {
        count = count.saturating_add(1);
        if count > MAX_ENCRYPTED_EXTENSIONS {
            return Err(CoverProfileError::MalformedEncryptedExtensions);
        }
        let extension_type = extensions.read_u16()?;
        let extension_len = usize::from(extensions.read_u16()?);
        let mut extension = extensions.subreader(extension_len)?;
        if extension_type == EXTENSION_ALPN {
            if selected_alpn.is_some() {
                return Err(CoverProfileError::MalformedEncryptedExtensions);
            }
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
        } else {
            extension.skip_remaining();
        }
    }
    Ok(selected_alpn)
}

/// Exercises strict profile EncryptedExtensions classification with arbitrary
/// attacker-influenced decrypted bytes in the dedicated libFuzzer build.
#[cfg(feature = "fuzzing")]
pub fn fuzz_cover_profile_extensions(input: &[u8]) {
    let _ = parse_encrypted_extensions_alpn(input);
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

    fn skip_remaining(&mut self) {
        self.position = self.input.len();
    }
}

#[cfg(test)]
mod tests {
    use super::{CoverProfileError, parse_encrypted_extensions_alpn};

    #[test]
    fn parses_only_one_exact_server_alpn_selection() {
        assert_eq!(
            parse_encrypted_extensions_alpn(
                &[8, 0, 0, 11, 0, 9, 0, 16, 0, 5, 0, 3, 2, b'h', b'2',]
            ),
            Ok(Some(b"h2".to_vec()))
        );
        assert_eq!(
            parse_encrypted_extensions_alpn(&[8, 0, 0, 2, 0, 0]),
            Ok(None)
        );
    }

    #[test]
    fn rejects_truncated_or_multi_protocol_alpn() {
        assert_eq!(
            parse_encrypted_extensions_alpn(&[
                8, 0, 0, 14, 0, 12, 0, 16, 0, 8, 0, 6, 2, b'h', b'2', 2, b'h', b'3',
            ]),
            Err(CoverProfileError::MalformedEncryptedExtensions)
        );
    }
}
