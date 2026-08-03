use std::{error::Error, fmt, io, ops::Range, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    time::{self, Instant},
};

use super::{
    ContentType, EstablishedTls, MAX_PLAINTEXT_LEN, Tls13RecordError, TlsRecordReadError,
    read_tls_record,
};

const TLS_RECORD_HEADER_LEN: usize = 5;
const ALERT_LEVEL_WARNING: u8 = 1;
const ALERT_CLOSE_NOTIFY: u8 = 0;

/// One authenticated application record retaining its in-place decrypted storage.
pub struct ApplicationRecord {
    wire: Vec<u8>,
    plaintext: Range<usize>,
}

impl ApplicationRecord {
    /// Returns authenticated application bytes without copying them from the record.
    #[must_use]
    pub fn plaintext(&self) -> &[u8] {
        self.wire.get(self.plaintext.clone()).unwrap_or_default()
    }

    /// Returns the plaintext length available to the application.
    #[must_use]
    pub fn len(&self) -> usize {
        self.plaintext.len()
    }

    /// Returns whether this authenticated application fragment is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.plaintext.is_empty()
    }
}

impl fmt::Debug for ApplicationRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApplicationRecord")
            .field("plaintext_len", &self.plaintext.len())
            .finish_non_exhaustive()
    }
}

/// Counts produced while encrypting one application write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationWriteStats {
    plaintext_bytes: u64,
    records: u64,
}

impl ApplicationWriteStats {
    /// Returns application bytes accepted for encryption.
    #[must_use]
    pub const fn plaintext_bytes(self) -> u64 {
        self.plaintext_bytes
    }

    /// Returns TLS records emitted for this write.
    #[must_use]
    pub const fn records(self) -> u64 {
        self.records
    }
}

/// Established TLS application I/O failed or received unsupported control traffic.
#[derive(Debug)]
pub enum TlsApplicationIoError {
    /// The requested absolute operation deadline could not be represented or elapsed.
    Timeout,
    /// Reading one exact encrypted record failed.
    Read(TlsRecordReadError),
    /// Record authentication, framing, or encryption failed.
    Record(Tls13RecordError),
    /// An authenticated post-handshake message is not supported by this state machine.
    UnexpectedContentType(ContentType),
    /// The peer sent a malformed authenticated TLS alert.
    InvalidAlert,
    /// The peer sent an authenticated two-byte TLS alert.
    PeerAlert { level: u8, description: u8 },
    /// Writing ciphertext or shutting down the transport failed.
    Io(io::Error),
}

impl fmt::Display for TlsApplicationIoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => formatter.write_str("TLS application I/O timed out"),
            Self::Read(source) => source.fmt(formatter),
            Self::Record(source) => source.fmt(formatter),
            Self::UnexpectedContentType(_) => {
                formatter.write_str("unexpected authenticated TLS content type")
            }
            Self::InvalidAlert => formatter.write_str("invalid authenticated TLS alert"),
            Self::PeerAlert { .. } => formatter.write_str("peer closed TLS with an alert"),
            Self::Io(_) => formatter.write_str("TLS application socket I/O failed"),
        }
    }
}

impl Error for TlsApplicationIoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Read(source) => Some(source),
            Self::Record(source) => Some(source),
            Self::Io(source) => Some(source),
            Self::Timeout
            | Self::UnexpectedContentType(_)
            | Self::InvalidAlert
            | Self::PeerAlert { .. } => None,
        }
    }
}

/// One transport plus non-clonable TLS 1.3 application traffic state.
pub struct TlsApplicationIo<S> {
    io: S,
    tls: EstablishedTls,
    write_record: Vec<u8>,
}

impl<S> TlsApplicationIo<S> {
    /// Binds an authenticated transport to the traffic state unlocked by ClientFinished.
    #[must_use]
    pub const fn new(io: S, tls: EstablishedTls) -> Self {
        Self {
            io,
            tls,
            write_record: Vec::new(),
        }
    }

    /// Consumes TLS state and returns the underlying transport.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.io
    }
}

impl<S> TlsApplicationIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Reads and authenticates one application record under an absolute deadline.
    ///
    /// Decryption occurs in place. The returned value owns the record buffer and
    /// exposes the plaintext as a range, avoiding a second plaintext allocation.
    ///
    /// # Errors
    ///
    /// Returns a bounded record read, AEAD, alert, content-type, or deadline error.
    pub async fn read_application(
        &mut self,
        timeout: Duration,
    ) -> Result<ApplicationRecord, TlsApplicationIoError> {
        let record = read_tls_record(&mut self.io, timeout)
            .await
            .map_err(TlsApplicationIoError::Read)?;
        let mut wire = record.into_wire();
        let (content_type, plaintext_len, alert) = {
            let opened = self
                .tls
                .client_records_mut()
                .open_in_place(&mut wire)
                .map_err(TlsApplicationIoError::Record)?;
            let alert = if opened.content_type() == ContentType::Alert {
                opened.plaintext().try_into().ok()
            } else {
                None
            };
            (opened.content_type(), opened.plaintext().len(), alert)
        };
        match content_type {
            ContentType::ApplicationData => {
                let end = TLS_RECORD_HEADER_LEN.checked_add(plaintext_len).ok_or(
                    TlsApplicationIoError::Record(Tls13RecordError::InvalidLength),
                )?;
                Ok(ApplicationRecord {
                    wire,
                    plaintext: TLS_RECORD_HEADER_LEN..end,
                })
            }
            ContentType::Alert => {
                let [level, description] = alert.ok_or(TlsApplicationIoError::InvalidAlert)?;
                Err(TlsApplicationIoError::PeerAlert { level, description })
            }
            ContentType::ChangeCipherSpec | ContentType::Handshake => {
                Err(TlsApplicationIoError::UnexpectedContentType(content_type))
            }
        }
    }

    /// Encrypts application bytes into bounded records and writes every ciphertext byte.
    ///
    /// The reusable ciphertext buffer is retained by the connection. Empty writes
    /// produce no record, and all chunks share one absolute deadline.
    ///
    /// # Errors
    ///
    /// Returns a record-protection, allocation, socket, or deadline error.
    pub async fn write_application(
        &mut self,
        plaintext: &[u8],
        timeout: Duration,
    ) -> Result<ApplicationWriteStats, TlsApplicationIoError> {
        let deadline = operation_deadline(timeout)?;
        let mut records = 0_u64;
        for chunk in plaintext.chunks(MAX_PLAINTEXT_LEN) {
            self.write_content(ContentType::ApplicationData, chunk, deadline)
                .await?;
            records = records.saturating_add(1);
        }
        Ok(ApplicationWriteStats {
            plaintext_bytes: u64::try_from(plaintext.len()).unwrap_or(u64::MAX),
            records,
        })
    }

    /// Sends an encrypted `close_notify` and shuts down the transport writer.
    ///
    /// # Errors
    ///
    /// Returns a record-protection, socket, or absolute deadline error.
    pub async fn shutdown(&mut self, timeout: Duration) -> Result<(), TlsApplicationIoError> {
        let deadline = operation_deadline(timeout)?;
        self.write_content(
            ContentType::Alert,
            &[ALERT_LEVEL_WARNING, ALERT_CLOSE_NOTIFY],
            deadline,
        )
        .await?;
        time::timeout_at(deadline, self.io.shutdown())
            .await
            .map_err(|_| TlsApplicationIoError::Timeout)?
            .map_err(TlsApplicationIoError::Io)
    }

    async fn write_content(
        &mut self,
        content_type: ContentType,
        plaintext: &[u8],
        deadline: Instant,
    ) -> Result<(), TlsApplicationIoError> {
        self.tls
            .server_records_mut()
            .seal_into(content_type, plaintext, 0, &mut self.write_record)
            .map_err(TlsApplicationIoError::Record)?;
        time::timeout_at(deadline, self.io.write_all(&self.write_record))
            .await
            .map_err(|_| TlsApplicationIoError::Timeout)?
            .map_err(TlsApplicationIoError::Io)
    }
}

impl<S> fmt::Debug for TlsApplicationIo<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsApplicationIo")
            .field("tls", &self.tls)
            .field("write_buffer_capacity", &self.write_record.capacity())
            .field("transport", &"[BOUND]")
            .finish_non_exhaustive()
    }
}

fn operation_deadline(timeout: Duration) -> Result<Instant, TlsApplicationIoError> {
    Instant::now()
        .checked_add(timeout)
        .ok_or(TlsApplicationIoError::Timeout)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncWriteExt, duplex};

    use super::{TlsApplicationIo, TlsApplicationIoError};
    use crate::protocol::reality::tls13::{
        CipherSuite, ContentType, EstablishedTls, Tls13KeySchedule, Tls13RecordLayer,
        read_tls_record,
    };

    const TIMEOUT: Duration = Duration::from_secs(1);

    #[tokio::test(flavor = "current_thread")]
    async fn decrypts_and_encrypts_application_records_without_plaintext_copy() {
        let suite = CipherSuite::Aes128GcmSha256;
        let schedule = schedule(suite);
        let application = schedule
            .application_traffic_secrets(&suite.hash().digest(b"server finished transcript"))
            .expect("application secrets must derive");
        let server_client_records = Tls13RecordLayer::new(
            suite,
            schedule
                .traffic_keys(application.client())
                .expect("server client keys must derive"),
        )
        .expect("server client records must initialize");
        let server_server_records = Tls13RecordLayer::new(
            suite,
            schedule
                .traffic_keys(application.server())
                .expect("server write keys must derive"),
        )
        .expect("server write records must initialize");
        let mut client_write_records = Tls13RecordLayer::new(
            suite,
            schedule
                .traffic_keys(application.client())
                .expect("client write keys must derive"),
        )
        .expect("client write records must initialize");
        let mut client_read_records = Tls13RecordLayer::new(
            suite,
            schedule
                .traffic_keys(application.server())
                .expect("client read keys must derive"),
        )
        .expect("client read records must initialize");
        let established =
            EstablishedTls::from_test_records(suite, server_client_records, server_server_records);
        let (mut client, server) = duplex(64 * 1024);
        let mut application = TlsApplicationIo::new(server, established);

        let mut request_record = Vec::new();
        client_write_records
            .seal_into(
                ContentType::ApplicationData,
                b"VLESS request",
                0,
                &mut request_record,
            )
            .expect("request must seal");
        client
            .write_all(&request_record)
            .await
            .expect("request record must be written");
        let request = application
            .read_application(TIMEOUT)
            .await
            .expect("request record must authenticate");
        assert_eq!(request.plaintext(), b"VLESS request");
        assert_eq!(request.len(), b"VLESS request".len());

        let stats = application
            .write_application(b"VLESS response", TIMEOUT)
            .await
            .expect("response must encrypt");
        assert_eq!(stats.plaintext_bytes(), b"VLESS response".len() as u64);
        assert_eq!(stats.records(), 1);
        let mut response_record = read_tls_record(&mut client, TIMEOUT)
            .await
            .expect("response record must be read")
            .into_wire();
        let response = client_read_records
            .open_in_place(&mut response_record)
            .expect("response record must authenticate");
        assert_eq!(response.content_type(), ContentType::ApplicationData);
        assert_eq!(response.plaintext(), b"VLESS response");

        application
            .shutdown(TIMEOUT)
            .await
            .expect("close notify must be sent");
        let mut close_record = read_tls_record(&mut client, TIMEOUT)
            .await
            .expect("close notify record must be read")
            .into_wire();
        let close = client_read_records
            .open_in_place(&mut close_record)
            .expect("close notify must authenticate");
        assert_eq!(close.content_type(), ContentType::Alert);
        assert_eq!(close.plaintext(), [1, 0]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn authenticated_peer_alert_is_not_application_eof() {
        let suite = CipherSuite::Aes128GcmSha256;
        let schedule = schedule(suite);
        let application_secrets = schedule
            .application_traffic_secrets(&suite.hash().digest(b"server finished transcript"))
            .expect("application secrets must derive");
        let server_client_records = Tls13RecordLayer::new(
            suite,
            schedule
                .traffic_keys(application_secrets.client())
                .expect("server client keys must derive"),
        )
        .expect("server client records must initialize");
        let server_server_records = Tls13RecordLayer::new(
            suite,
            schedule
                .traffic_keys(application_secrets.server())
                .expect("server write keys must derive"),
        )
        .expect("server write records must initialize");
        let mut client_records = Tls13RecordLayer::new(
            suite,
            schedule
                .traffic_keys(application_secrets.client())
                .expect("client keys must derive"),
        )
        .expect("client records must initialize");
        let established =
            EstablishedTls::from_test_records(suite, server_client_records, server_server_records);
        let (mut client, server) = duplex(1024);
        let mut application = TlsApplicationIo::new(server, established);
        let mut alert = Vec::new();
        client_records
            .seal_into(ContentType::Alert, &[2, 40], 0, &mut alert)
            .expect("fatal handshake alert must seal");
        client
            .write_all(&alert)
            .await
            .expect("alert record must be written");

        assert!(matches!(
            application.read_application(TIMEOUT).await,
            Err(TlsApplicationIoError::PeerAlert {
                level: 2,
                description: 40
            })
        ));
    }

    fn schedule(suite: CipherSuite) -> Tls13KeySchedule {
        Tls13KeySchedule::new(
            suite,
            &[0x31; 32],
            &suite.hash().digest(b"server hello transcript"),
        )
        .expect("test key schedule must derive")
    }
}
