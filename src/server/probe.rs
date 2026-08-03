use std::{error::Error, fmt, io, time::Duration};

use serde::Serialize;
use tokio::{
    io::AsyncWriteExt,
    net::TcpStream,
    time::{self, Instant},
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{
    protocol::reality::{
        ClientHello, ClientHelloError, SESSION_ID_LEN, X25519_GROUP,
        tls13::{CipherSuite, TargetServerHelloReadError, read_target_server_hello},
    },
    server_name::concrete_probe_name,
};

const TLS_RECORD_HANDSHAKE: u8 = 22;
const TLS_LEGACY_RECORD_VERSION: [u8; 2] = [3, 1];
const TLS_LEGACY_HANDSHAKE_VERSION: u16 = 0x0303;
const TLS13_VERSION: u16 = 0x0304;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const EXT_SERVER_NAME: u16 = 0;
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_ALPN: u16 = 16;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const EXT_KEY_SHARE: u16 = 51;

/// Machine-readable result of a live REALITY cover-target compatibility probe.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DestinationProbeReport {
    target: String,
    server_name: String,
    compatible: bool,
    cipher_suite: &'static str,
    key_exchange_group: &'static str,
    connect_millis: u64,
    server_hello_millis: u64,
    total_millis: u64,
}

impl DestinationProbeReport {
    /// Returns whether the target passed strict REALITY presentation checks.
    #[must_use]
    pub const fn compatible(&self) -> bool {
        self.compatible
    }

    /// Returns the target-selected TLS 1.3 cipher suite name.
    #[must_use]
    pub const fn cipher_suite(&self) -> &'static str {
        self.cipher_suite
    }

    /// Returns the target-selected key exchange group name.
    #[must_use]
    pub const fn key_exchange_group(&self) -> &'static str {
        self.key_exchange_group
    }
}

/// A live cover-target probe could not prove REALITY compatibility.
#[derive(Debug)]
pub enum DestinationProbeError {
    /// SNI was not a bounded ASCII DNS name.
    InvalidServerName,
    /// A wildcard pattern had no matching concrete hostname in the target.
    WildcardServerNameTargetMismatch,
    /// Operating-system entropy was unavailable.
    Random,
    /// The internally generated ClientHello failed strict self-validation.
    ClientHello(ClientHelloError),
    /// A bounded TLS vector could not be represented on the wire.
    Encoding,
    /// The overall probe deadline elapsed during connection setup.
    ConnectTimeout,
    /// DNS resolution or TCP setup failed.
    Connect(io::Error),
    /// Writing the generated ClientHello exceeded the probe deadline.
    WriteTimeout,
    /// Writing the generated ClientHello failed.
    Write(io::Error),
    /// The target response was incomplete or incompatible.
    ServerHello(TargetServerHelloReadError),
}

impl fmt::Display for DestinationProbeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidServerName => formatter.write_str("probe SNI is not a valid DNS name"),
            Self::WildcardServerNameTargetMismatch => formatter.write_str(
                "wildcard REALITY server name requires a matching concrete DNS hostname in target",
            ),
            Self::Random => formatter.write_str("operating-system random generation failed"),
            Self::ClientHello(_) => formatter.write_str("failed to build probe ClientHello"),
            Self::Encoding => formatter.write_str("probe ClientHello vector is too large"),
            Self::ConnectTimeout => formatter.write_str("REALITY target connection timed out"),
            Self::Connect(_) => formatter.write_str("failed to connect to REALITY target"),
            Self::WriteTimeout => formatter.write_str("REALITY target ClientHello write timed out"),
            Self::Write(_) => formatter.write_str("failed to write REALITY target ClientHello"),
            Self::ServerHello(source) => source.fmt(formatter),
        }
    }
}

impl Error for DestinationProbeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ClientHello(source) => Some(source),
            Self::Connect(source) | Self::Write(source) => Some(source),
            Self::ServerHello(source) => Some(source),
            Self::InvalidServerName
            | Self::WildcardServerNameTargetMismatch
            | Self::Random
            | Self::Encoding
            | Self::ConnectTimeout
            | Self::WriteTimeout => None,
        }
    }
}

/// Probes one configured exact name or wildcard pattern against its target.
///
/// A TLS ClientHello cannot carry a wildcard SNI. For a wildcard configuration,
/// the target hostname is used only when it is a matching concrete one-label
/// expansion of the pattern.
///
/// # Errors
///
/// Returns [`DestinationProbeError::WildcardServerNameTargetMismatch`] when a
/// wildcard cannot be converted to a concrete SNI from the target.
pub async fn probe_destination_pattern(
    target: &str,
    server_name_pattern: &str,
    timeout: Duration,
) -> Result<DestinationProbeReport, DestinationProbeError> {
    let server_name = concrete_probe_name(target, server_name_pattern)
        .ok_or(DestinationProbeError::WildcardServerNameTargetMismatch)?;
    probe_destination(target, server_name, timeout).await
}

/// Connects to a real target and verifies its first TLS 1.3 negotiation response.
///
/// The probe uses an ephemeral X25519 ClientHello, advertises every cipher suite
/// implemented by the REALITY record layer, and validates the response against
/// the exact offer. It does not transmit configuration, UUIDs, or REALITY keys.
///
/// # Errors
///
/// Returns a bounded validation, entropy, deadline, DNS, TCP, or TLS response error.
pub async fn probe_destination(
    target: &str,
    server_name: &str,
    timeout: Duration,
) -> Result<DestinationProbeReport, DestinationProbeError> {
    let probe = ProbeClientHello::build(server_name)?;
    let started = Instant::now();
    let deadline = started
        .checked_add(timeout)
        .ok_or(DestinationProbeError::ConnectTimeout)?;
    let mut stream = time::timeout_at(deadline, TcpStream::connect(target))
        .await
        .map_err(|_| DestinationProbeError::ConnectTimeout)?
        .map_err(DestinationProbeError::Connect)?;
    let connected = Instant::now();
    stream
        .set_nodelay(true)
        .map_err(DestinationProbeError::Connect)?;
    time::timeout_at(deadline, stream.write_all(&probe.record))
        .await
        .map_err(|_| DestinationProbeError::WriteTimeout)?
        .map_err(DestinationProbeError::Write)?;
    let target_hello = read_target_server_hello(
        &mut stream,
        &probe.hello,
        deadline.saturating_duration_since(Instant::now()),
    )
    .await
    .map_err(DestinationProbeError::ServerHello)?;
    let completed = Instant::now();
    let suite = target_hello.template().suite();
    let group = target_hello.template().key_share_group();

    Ok(DestinationProbeReport {
        target: target.to_owned(),
        server_name: server_name.to_owned(),
        compatible: true,
        cipher_suite: cipher_suite_name(suite),
        key_exchange_group: key_exchange_group_name(group),
        connect_millis: duration_millis(connected.saturating_duration_since(started)),
        server_hello_millis: duration_millis(completed.saturating_duration_since(connected)),
        total_millis: duration_millis(completed.saturating_duration_since(started)),
    })
}

struct ProbeClientHello {
    hello: ClientHello,
    record: Vec<u8>,
}

impl ProbeClientHello {
    fn build(server_name: &str) -> Result<Self, DestinationProbeError> {
        validate_server_name(server_name)?;
        let mut random = [0_u8; 32];
        let mut session_id = [0_u8; SESSION_ID_LEN];
        let mut private_bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut random).map_err(|_| DestinationProbeError::Random)?;
        getrandom::fill(&mut session_id).map_err(|_| DestinationProbeError::Random)?;
        getrandom::fill(private_bytes.as_mut()).map_err(|_| DestinationProbeError::Random)?;
        let private = StaticSecret::from(*private_bytes);
        let public = PublicKey::from(&private).to_bytes();

        let mut extensions = Vec::with_capacity(256);
        let mut names = vec![0];
        push_u16_vector(&mut names, server_name.as_bytes())?;
        let mut server_names = Vec::new();
        push_u16_vector(&mut server_names, &names)?;
        push_extension(&mut extensions, EXT_SERVER_NAME, &server_names)?;

        let mut groups = Vec::new();
        push_u16_vector(&mut groups, &X25519_GROUP.to_be_bytes())?;
        push_extension(&mut extensions, EXT_SUPPORTED_GROUPS, &groups)?;

        let signatures = [0x08, 0x07, 0x08, 0x04, 0x04, 0x03, 0x08, 0x05, 0x08, 0x06];
        let mut signature_algorithms = Vec::new();
        push_u16_vector(&mut signature_algorithms, &signatures)?;
        push_extension(
            &mut extensions,
            EXT_SIGNATURE_ALGORITHMS,
            &signature_algorithms,
        )?;

        let protocols = [
            2, b'h', b'2', 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
        ];
        let mut alpn = Vec::new();
        push_u16_vector(&mut alpn, &protocols)?;
        push_extension(&mut extensions, EXT_ALPN, &alpn)?;
        push_extension(
            &mut extensions,
            EXT_SUPPORTED_VERSIONS,
            &[
                2,
                TLS13_VERSION.to_be_bytes()[0],
                TLS13_VERSION.to_be_bytes()[1],
            ],
        )?;

        let mut key_share_entry = Vec::new();
        key_share_entry.extend_from_slice(&X25519_GROUP.to_be_bytes());
        push_u16_vector(&mut key_share_entry, &public)?;
        let mut key_shares = Vec::new();
        push_u16_vector(&mut key_shares, &key_share_entry)?;
        push_extension(&mut extensions, EXT_KEY_SHARE, &key_shares)?;

        let mut body = Vec::with_capacity(512);
        body.extend_from_slice(&TLS_LEGACY_HANDSHAKE_VERSION.to_be_bytes());
        body.extend_from_slice(&random);
        body.push(u8::try_from(session_id.len()).map_err(|_| DestinationProbeError::Encoding)?);
        body.extend_from_slice(&session_id);
        let cipher_suites = [0x13, 0x01, 0x13, 0x02, 0x13, 0x03];
        push_u16_vector(&mut body, &cipher_suites)?;
        body.extend_from_slice(&[1, 0]);
        push_u16_vector(&mut body, &extensions)?;

        let mut message = vec![HANDSHAKE_CLIENT_HELLO];
        let body_len = u32::try_from(body.len()).map_err(|_| DestinationProbeError::Encoding)?;
        message.extend_from_slice(&body_len.to_be_bytes()[1..]);
        message.extend_from_slice(&body);
        let hello =
            ClientHello::parse_message(&message).map_err(DestinationProbeError::ClientHello)?;

        let mut record = vec![TLS_RECORD_HANDSHAKE];
        record.extend_from_slice(&TLS_LEGACY_RECORD_VERSION);
        push_u16_vector(&mut record, &message)?;
        Ok(Self { hello, record })
    }
}

fn validate_server_name(server_name: &str) -> Result<(), DestinationProbeError> {
    if server_name.is_empty()
        || server_name.len() > 253
        || !server_name.is_ascii()
        || server_name.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(DestinationProbeError::InvalidServerName);
    }
    Ok(())
}

fn push_extension(
    output: &mut Vec<u8>,
    extension_type: u16,
    body: &[u8],
) -> Result<(), DestinationProbeError> {
    output.extend_from_slice(&extension_type.to_be_bytes());
    push_u16_vector(output, body)
}

fn push_u16_vector(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), DestinationProbeError> {
    let length = u16::try_from(bytes.len()).map_err(|_| DestinationProbeError::Encoding)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

const fn cipher_suite_name(suite: CipherSuite) -> &'static str {
    match suite {
        CipherSuite::Aes128GcmSha256 => "TLS_AES_128_GCM_SHA256",
        CipherSuite::Aes256GcmSha384 => "TLS_AES_256_GCM_SHA384",
        CipherSuite::ChaCha20Poly1305Sha256 => "TLS_CHACHA20_POLY1305_SHA256",
    }
}

const fn key_exchange_group_name(group: u16) -> &'static str {
    if group == X25519_GROUP {
        "X25519"
    } else {
        "unsupported"
    }
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, time::Duration};

    use tokio::{io::AsyncWriteExt, net::TcpListener};

    use super::{
        DestinationProbeError, ProbeClientHello, probe_destination, probe_destination_pattern,
    };
    use crate::protocol::reality::{SESSION_ID_LEN, X25519_GROUP, read_client_hello};

    #[test]
    fn generated_probe_client_hello_passes_strict_parser() {
        let probe = ProbeClientHello::build("www.example.com")
            .expect("valid SNI must build a probe ClientHello");

        assert_eq!(probe.hello.server_name(), Some("www.example.com"));
        assert!(probe.hello.cipher_offered(0x1301));
        assert!(probe.hello.cipher_offered(0x1302));
        assert!(probe.hello.cipher_offered(0x1303));
        assert!(probe.hello.key_share_group_offered(X25519_GROUP));
        assert_eq!(probe.record.get(..3), Some([22, 3, 1].as_slice()));
    }

    #[test]
    fn rejects_unbounded_or_non_dns_sni() {
        assert!(matches!(
            ProbeClientHello::build("-invalid.example"),
            Err(DestinationProbeError::InvalidServerName)
        ));
        assert!(matches!(
            ProbeClientHello::build(""),
            Err(DestinationProbeError::InvalidServerName)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wildcard_probe_requires_matching_concrete_target_hostname() {
        assert!(matches!(
            probe_destination_pattern("other.example:443", "*.lmu.edu", Duration::from_millis(1))
                .await,
            Err(DestinationProbeError::WildcardServerNameTargetMismatch)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn probes_live_loopback_target_and_reports_negotiation() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("probe target must bind");
        let target = listener
            .local_addr()
            .expect("probe target address must exist")
            .to_string();
        let target_task = async {
            let (mut stream, _) = listener.accept().await.expect("probe must connect");
            let read = read_client_hello(&mut stream, Duration::from_secs(1))
                .await
                .expect("probe ClientHello must arrive");
            let record = target_server_hello_record(
                read.hello()
                    .session_id()
                    .expect("probe must include session ID"),
            );
            stream
                .write_all(&record)
                .await
                .expect("target ServerHello must be written");
        };
        let probe_task = probe_destination(&target, "www.example.com", Duration::from_secs(1));
        let ((), report) = tokio::join!(target_task, probe_task);
        let report = report.expect("loopback target must be compatible");

        assert!(report.compatible());
        assert_eq!(report.cipher_suite(), "TLS_AES_128_GCM_SHA256");
        assert_eq!(report.key_exchange_group(), "X25519");
    }

    fn target_server_hello_record(session_id: &[u8]) -> Vec<u8> {
        assert_eq!(session_id.len(), SESSION_ID_LEN);
        let mut extensions = Vec::new();
        push_test_extension(&mut extensions, 0x002b, &0x0304_u16.to_be_bytes());
        let mut key_share = Vec::new();
        key_share.extend_from_slice(&X25519_GROUP.to_be_bytes());
        key_share.extend_from_slice(&32_u16.to_be_bytes());
        key_share.extend_from_slice(&[0x55; 32]);
        push_test_extension(&mut extensions, 0x0033, &key_share);

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303_u16.to_be_bytes());
        body.extend_from_slice(&[0x33; 32]);
        body.push(u8::try_from(session_id.len()).expect("test session ID must fit"));
        body.extend_from_slice(session_id);
        body.extend_from_slice(&0x1301_u16.to_be_bytes());
        body.push(0);
        body.extend_from_slice(
            &u16::try_from(extensions.len())
                .expect("test extensions must fit")
                .to_be_bytes(),
        );
        body.extend_from_slice(&extensions);

        let mut message = vec![2];
        let message_len = u32::try_from(body.len()).expect("test message must fit");
        message.extend_from_slice(&message_len.to_be_bytes()[1..]);
        message.extend_from_slice(&body);
        let mut record = vec![22, 3, 3];
        record.extend_from_slice(
            &u16::try_from(message.len())
                .expect("test record must fit")
                .to_be_bytes(),
        );
        record.extend_from_slice(&message);
        record
    }

    fn push_test_extension(output: &mut Vec<u8>, extension_type: u16, body: &[u8]) {
        output.extend_from_slice(&extension_type.to_be_bytes());
        output.extend_from_slice(
            &u16::try_from(body.len())
                .expect("test extension must fit")
                .to_be_bytes(),
        );
        output.extend_from_slice(body);
    }
}
