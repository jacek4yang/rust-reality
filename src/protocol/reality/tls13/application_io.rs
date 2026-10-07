use std::{
    error::Error,
    fmt, io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf, split};

use super::{
    ContentType, EstablishedTls, IdleDeadline, IdleError, MAX_PLAINTEXT_LEN,
    MAX_TLS_RECORD_WIRE_LEN, MAX_TLS13_CIPHERTEXT_LEN, TLS_RECORD_HEADER_LEN, Tls13RecordError,
    TlsRecordReadError, TlsRecordReadErrorKind, buffered_failure, read_tls_record_into,
    record_storage,
};

const ALERT_LEVEL_WARNING: u8 = 1;
const ALERT_CLOSE_NOTIFY: u8 = 0;

const KEY_UPDATE_HANDSHAKE_TYPE: u8 = 24;
const KEY_UPDATE_NOT_REQUESTED: u8 = 0;
const KEY_UPDATE_REQUESTED: u8 = 1;
const KEY_UPDATE_MESSAGE_LEN: usize = 5;
const KEY_UPDATE_HEADER: [u8; 4] = [KEY_UPDATE_HANDSHAKE_TYPE, 0, 0, 1];
const KEY_UPDATE_RESPONSE: [u8; KEY_UPDATE_MESSAGE_LEN] =
    [KEY_UPDATE_HANDSHAKE_TYPE, 0, 0, 1, KEY_UPDATE_NOT_REQUESTED];
const KEY_UPDATE_RECORD_WIRE_LEN: usize = TLS_RECORD_HEADER_LEN + KEY_UPDATE_MESSAGE_LEN + 1 + 16;

/// Capacity of the connection-owned socket buffer behind a split reader.
///
/// One refill moves up to this many bytes per socket read — four maximum-sized
/// records, matching the 64 KiB read window of the reference implementation —
/// so a pipelined peer costs one syscall per refill instead of one header read
/// plus one body read per record. The buffer is allocated and zero-filled once
/// and then treated as fully initialized storage; only the start/end cursors
/// move afterwards.
const SOCKET_BUFFER_CAPACITY: usize = 4 * MAX_TLS_RECORD_WIRE_LEN;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyUpdateRequest {
    NotRequested,
    Requested,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenedRecordOutcome {
    ApplicationData(usize),
    Control { key_update_requested: bool },
}

struct KeyUpdateCoordination {
    /// A response restored after a canceled write or transferred through Handoff.
    response_pending: AtomicBool,
    /// A requested update authenticated by the reader for the next output record.
    response_observed: AtomicBool,
}

impl KeyUpdateCoordination {
    const fn new(response_pending: bool) -> Self {
        Self {
            response_pending: AtomicBool::new(response_pending),
            response_observed: AtomicBool::new(false),
        }
    }
}

#[derive(Default)]
struct KeyUpdateReassembly {
    message: [u8; KEY_UPDATE_MESSAGE_LEN],
    length: usize,
}

impl KeyUpdateReassembly {
    const fn new() -> Self {
        Self {
            message: [0; KEY_UPDATE_MESSAGE_LEN],
            length: 0,
        }
    }

    const fn is_empty(&self) -> bool {
        self.length == 0
    }

    fn push_record(
        &mut self,
        fragment: &[u8],
    ) -> Result<Option<KeyUpdateRequest>, TlsApplicationIoError> {
        if fragment.is_empty() {
            return Err(TlsApplicationIoError::InvalidKeyUpdate);
        }
        // A call contains exactly one authenticated record's Handshake
        // plaintext. Capping the cumulative length at the fixed message size
        // therefore rejects coalesced/trailing bytes and makes the key change
        // land exactly on a record boundary.
        let end = self
            .length
            .checked_add(fragment.len())
            .filter(|end| *end <= KEY_UPDATE_MESSAGE_LEN)
            .ok_or(TlsApplicationIoError::InvalidKeyUpdate)?;
        self.message
            .get_mut(self.length..end)
            .ok_or(TlsApplicationIoError::InvalidKeyUpdate)?
            .copy_from_slice(fragment);
        self.length = end;

        let header_len = self.length.min(KEY_UPDATE_HEADER.len());
        if self.message.get(..header_len) != KEY_UPDATE_HEADER.get(..header_len) {
            return Err(TlsApplicationIoError::InvalidKeyUpdate);
        }
        if self.length < KEY_UPDATE_MESSAGE_LEN {
            return Ok(None);
        }

        self.length = 0;
        match self.message[4] {
            KEY_UPDATE_NOT_REQUESTED => Ok(Some(KeyUpdateRequest::NotRequested)),
            KEY_UPDATE_REQUESTED => Ok(Some(KeyUpdateRequest::Requested)),
            _ => Err(TlsApplicationIoError::InvalidKeyUpdate),
        }
    }
}

struct PendingKeyUpdateResponse<'state> {
    state: Option<&'state AtomicBool>,
}

impl<'state> PendingKeyUpdateResponse<'state> {
    fn take(coordination: &'state KeyUpdateCoordination) -> Self {
        let pending = &coordination.response_pending;
        let pending_request =
            pending.load(Ordering::Acquire) && pending.swap(false, Ordering::AcqRel);
        let observed = &coordination.response_observed;
        let observed_request =
            observed.load(Ordering::Acquire) && observed.swap(false, Ordering::AcqRel);
        Self {
            state: (pending_request | observed_request).then_some(pending),
        }
    }

    const fn was_requested(&self) -> bool {
        self.state.is_some()
    }

    fn complete(&mut self) {
        self.state = None;
    }
}

impl Drop for PendingKeyUpdateResponse<'_> {
    fn drop(&mut self) {
        if let Some(state) = self.state {
            state.store(true, Ordering::Release);
        }
    }
}

#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_key_update_fragments(fragments: &[&[u8]]) {
    let mut reassembly = KeyUpdateReassembly::default();
    for fragment in fragments {
        if reassembly.push_record(fragment).is_err() {
            return;
        }
    }
}

/// One authenticated application record borrowed from the connection's buffer.
///
/// The borrow keeps the connection's socket buffer immutable until the caller
/// finishes with the plaintext, which is what makes the successful record loop
/// allocation-free: no owned `Vec` is produced per record.
pub struct ApplicationRecord<'record> {
    plaintext: &'record [u8],
}

impl<'record> ApplicationRecord<'record> {
    /// Returns authenticated application bytes without copying them from the record.
    #[must_use]
    pub const fn plaintext(&self) -> &'record [u8] {
        self.plaintext
    }

    /// Returns the plaintext length available to the application.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.plaintext.len()
    }

    /// Returns whether this authenticated application fragment is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.plaintext.is_empty()
    }
}

impl fmt::Debug for ApplicationRecord<'_> {
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

/// A transport whose read side can fill several buffers in one operation.
///
/// The generic [`AsyncRead`] surface exposes only a single-buffer poll, while
/// the batched downlink relay (experiment D11) needs one vectored read that
/// lands in the disjoint plaintext regions of several record slots at once.
/// Implementations perform one socket `readv` when possible; an
/// implementation with buffered bytes may fill only the first non-empty
/// buffer, which is correct but simply batches less for that one call.
pub(crate) trait VectoredRead: AsyncRead + Unpin {
    /// Reads into the given buffers in order, returning the total byte count.
    ///
    /// A return of `0` means end of stream, exactly like [`AsyncRead`]: every
    /// buffer the batched relay passes is non-empty.
    fn read_vectored<'buf>(
        &'buf mut self,
        buffers: &'buf mut [io::IoSliceMut<'buf>],
    ) -> impl std::future::Future<Output = io::Result<usize>> + Send + 'buf;
}

/// Established TLS application I/O failed or received unsupported control traffic.
#[derive(Debug)]
pub enum TlsApplicationIoError {
    /// The requested idle window could not be represented or elapsed.
    Timeout,
    /// Reading one exact encrypted record failed.
    Read(TlsRecordReadError),
    /// Record authentication, framing, or encryption failed.
    Record(Tls13RecordError),
    /// An authenticated post-handshake message is not supported by this state machine.
    UnexpectedContentType(ContentType),
    /// The peer sent a malformed or interleaved TLS 1.3 KeyUpdate message.
    InvalidKeyUpdate,
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
            Self::InvalidKeyUpdate => {
                formatter.write_str("invalid authenticated TLS KeyUpdate message")
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
            | Self::InvalidKeyUpdate
            | Self::InvalidAlert
            | Self::PeerAlert { .. } => None,
        }
    }
}

/// One transport plus non-clonable TLS 1.3 application traffic state.
pub struct TlsApplicationIo<S> {
    io: S,
    tls: EstablishedTls,
    read_record: Vec<u8>,
    write_record: Vec<u8>,
    idle: IdleDeadline,
    key_update: KeyUpdateReassembly,
    key_update_coordination: KeyUpdateCoordination,
}

/// Authenticated client-to-server TLS application records.
///
/// The reader owns one grow-only socket buffer and one idle deadline for the
/// whole connection. Each refill reads available socket bytes into the buffer
/// once, complete records are parsed out of the buffered range and opened in
/// place, and the plaintext is exposed as a borrowed slice. The steady-state
/// path therefore performs no allocation and one socket read per refill, and
/// bytes already buffered survive a dropped future untouched.
pub struct TlsApplicationReader<R> {
    io: R,
    records: super::Tls13RecordLayer,
    socket_buffer: Vec<u8>,
    buffered_start: usize,
    buffered_end: usize,
    idle: IdleDeadline,
    key_update: KeyUpdateReassembly,
    key_update_coordination: Arc<KeyUpdateCoordination>,
}

/// Server-to-client TLS application records with one reusable ciphertext buffer.
pub struct TlsApplicationWriter<W> {
    io: W,
    records: super::Tls13RecordLayer,
    write_record: Vec<u8>,
    idle: IdleDeadline,
    key_update_coordination: Arc<KeyUpdateCoordination>,
}

impl<R> TlsApplicationReader<R> {
    /// Switches authenticated data reads to connection-wide activity.
    pub(crate) fn set_activity(
        &mut self,
        activity: std::sync::Arc<crate::io_activity::SessionActivity>,
    ) {
        self.idle.set_activity(activity);
    }

    /// Consumes record state and returns unparsed buffered bytes plus the transport.
    ///
    /// This is only appropriate after an authenticated higher-level protocol has
    /// explicitly negotiated a transition away from the outer TLS record layer.
    /// The boundary record is the last outer record the peer sends, so every
    /// byte still in the socket buffer is post-boundary raw bytes the peer
    /// pipelined behind it; the caller must deliver them, in order, ahead of
    /// every byte any raw relay moves.
    #[must_use]
    pub fn into_inner_with_pending(self) -> (Vec<u8>, R) {
        let pending = self
            .socket_buffer
            .get(self.buffered_start..self.buffered_end)
            .unwrap_or_default()
            .to_vec();
        (pending, self.io)
    }

    /// Consumes the reader at a session-handoff boundary.
    ///
    /// Returns the undecrypted ciphertext already read ahead from the
    /// transport, the transport itself, and the client-direction record layer.
    /// The pending bytes precede every byte the transport still holds, so the
    /// receiver of the handoff must feed them to the resumed record layer
    /// first; the record layer carries the exact sequence the peer's next
    /// record must authenticate against.
    #[must_use]
    pub fn into_handoff_parts(self) -> (Vec<u8>, R, super::Tls13RecordLayer) {
        let pending = self
            .socket_buffer
            .get(self.buffered_start..self.buffered_end)
            .unwrap_or_default()
            .to_vec();
        (pending, self.io, self.records)
    }
}

impl<W> TlsApplicationWriter<W> {
    /// Attaches the same activity state as the peer read direction.
    pub(crate) fn set_activity(
        &mut self,
        activity: std::sync::Arc<crate::io_activity::SessionActivity>,
    ) {
        self.idle.set_activity(activity);
    }

    /// Consumes the writer at a session-handoff boundary.
    ///
    /// Writes are record-synchronous, so the writer is always at a record
    /// boundary between awaited calls; the returned record layer carries the
    /// exact server-direction sequence. The final flag preserves an outstanding
    /// peer request for a server KeyUpdate across the ownership transfer.
    #[must_use]
    pub fn into_handoff_parts(self) -> (W, super::Tls13RecordLayer, bool) {
        let key_update_response_pending = self
            .key_update_coordination
            .response_pending
            .load(Ordering::Acquire)
            || self
                .key_update_coordination
                .response_observed
                .load(Ordering::Acquire);
        (self.io, self.records, key_update_response_pending)
    }
}

impl<W> TlsApplicationWriter<W> {
    /// Consumes record state and returns the transport writer at a record boundary.
    ///
    /// Callers must finish writing the authenticated transition record before
    /// invoking this method.
    #[must_use]
    pub fn into_inner(self) -> W {
        self.io
    }
}

/// Binds transport halves to resumed TLS directions after a session handoff.
///
/// This is the receiving counterpart of the `into_handoff_parts` extraction:
/// `pending_ciphertext` is the read-ahead the previous owner had already
/// pulled out of its kernel buffer, so it is preloaded into the reader's
/// socket buffer and is therefore opened ahead of every byte the new
/// transport delivers. The record layers inside `tls` carry the exact
/// sequences at the boundary, and `key_update_response_pending` carries the
/// outstanding post-handshake response obligation.
#[must_use]
pub fn resume_application_halves<R, W>(
    reader: R,
    pending_ciphertext: Vec<u8>,
    writer: W,
    tls: EstablishedTls,
    key_update_response_pending: bool,
) -> (TlsApplicationReader<R>, TlsApplicationWriter<W>) {
    let (client_records, server_records) = tls.into_record_layers();
    let buffered_end = pending_ciphertext.len();
    let mut socket_buffer = pending_ciphertext;
    // Best-effort headroom for the first refill; the grow-on-demand refill
    // policy stays correct even when this reservation fails.
    let _ignored = socket_buffer.try_reserve(SOCKET_BUFFER_CAPACITY);
    let key_update_coordination = Arc::new(KeyUpdateCoordination::new(key_update_response_pending));
    (
        TlsApplicationReader {
            io: reader,
            records: client_records,
            socket_buffer,
            buffered_start: 0,
            buffered_end,
            idle: IdleDeadline::new(),
            key_update: KeyUpdateReassembly::new(),
            key_update_coordination: key_update_coordination.clone(),
        },
        TlsApplicationWriter {
            io: writer,
            records: server_records,
            write_record: Vec::new(),
            idle: IdleDeadline::new(),
            key_update_coordination,
        },
    )
}

impl<S> TlsApplicationIo<S> {
    /// Binds an authenticated transport to the traffic state unlocked by ClientFinished.
    #[must_use]
    pub const fn new(io: S, tls: EstablishedTls) -> Self {
        Self {
            io,
            tls,
            read_record: Vec::new(),
            write_record: Vec::new(),
            idle: IdleDeadline::new(),
            key_update: KeyUpdateReassembly::new(),
            key_update_coordination: KeyUpdateCoordination::new(false),
        }
    }

    /// Consumes TLS state and returns the underlying transport.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.io
    }
}

impl TlsApplicationIo<tokio::net::TcpStream> {
    /// Splits the socket into owned halves that can later be reunited.
    ///
    /// `tokio::io::split` produces halves that can never reconstruct the
    /// original socket, which permanently prevents handing a complete
    /// descriptor to a kernel relay backend. `TcpStream::into_split` keeps that
    /// option open: `OwnedReadHalf::reunite` restores the exact socket and fails
    /// closed if the halves do not belong together.
    #[must_use]
    pub fn into_owned_split(
        self,
    ) -> (
        TlsApplicationReader<tokio::net::tcp::OwnedReadHalf>,
        TlsApplicationWriter<tokio::net::tcp::OwnedWriteHalf>,
    ) {
        let (reader, writer) = self.io.into_split();
        let (client_records, server_records) = self.tls.into_record_layers();
        let key_update_coordination = Arc::new(self.key_update_coordination);
        (
            TlsApplicationReader {
                io: reader,
                records: client_records,
                socket_buffer: Vec::new(),
                buffered_start: 0,
                buffered_end: 0,
                idle: IdleDeadline::new(),
                key_update: self.key_update,
                key_update_coordination: key_update_coordination.clone(),
            },
            TlsApplicationWriter {
                io: writer,
                records: server_records,
                write_record: self.write_record,
                idle: IdleDeadline::new(),
                key_update_coordination,
            },
        )
    }
}

impl<S> TlsApplicationIo<S>
where
    S: AsyncRead + AsyncWrite,
{
    /// Splits a generic transport and transfers each non-clonable record direction.
    #[must_use]
    pub fn into_split(
        self,
    ) -> (
        TlsApplicationReader<ReadHalf<S>>,
        TlsApplicationWriter<WriteHalf<S>>,
    ) {
        let (reader, writer) = split(self.io);
        let (client_records, server_records) = self.tls.into_record_layers();
        let key_update_coordination = Arc::new(self.key_update_coordination);
        (
            TlsApplicationReader {
                io: reader,
                records: client_records,
                socket_buffer: Vec::new(),
                buffered_start: 0,
                buffered_end: 0,
                idle: IdleDeadline::new(),
                key_update: self.key_update,
                key_update_coordination: key_update_coordination.clone(),
            },
            TlsApplicationWriter {
                io: writer,
                records: server_records,
                write_record: self.write_record,
                idle: IdleDeadline::new(),
                key_update_coordination,
            },
        )
    }
}

impl<S> TlsApplicationIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Reads and authenticates one application record under one idle window.
    ///
    /// Decryption occurs in place. The returned value owns the record buffer and
    /// exposes the plaintext as a range, avoiding a second plaintext allocation.
    /// An authenticated post-handshake control record returns an empty value so
    /// the caller retains control of flushing and absolute deadlines.
    ///
    /// # Errors
    ///
    /// Returns a bounded record read, AEAD, alert, content-type, or deadline error.
    pub async fn read_application(
        &mut self,
        timeout: Duration,
    ) -> Result<ApplicationRecord<'_>, TlsApplicationIoError> {
        self.idle
            .reset(timeout)
            .map_err(|_| TlsApplicationIoError::Timeout)?;
        read_application_record(
            &mut self.io,
            self.tls.client_records_mut(),
            &mut self.read_record,
            &mut self.idle,
            &mut self.key_update,
            &self.key_update_coordination,
        )
        .await
    }

    /// Encrypts application bytes into bounded records and writes every ciphertext byte.
    ///
    /// The reusable ciphertext buffer is retained by the connection. Empty writes
    /// produce no record, and each record gets its own idle window.
    ///
    /// # Errors
    ///
    /// Returns a record-protection, allocation, socket, or deadline error.
    pub async fn write_application(
        &mut self,
        plaintext: &[u8],
        timeout: Duration,
    ) -> Result<ApplicationWriteStats, TlsApplicationIoError> {
        write_application_data(
            &mut self.io,
            self.tls.server_records_mut(),
            &mut self.write_record,
            &mut self.idle,
            &self.key_update_coordination,
            plaintext,
            timeout,
        )
        .await
    }

    /// Sends an encrypted `close_notify` and shuts down the transport writer.
    ///
    /// # Errors
    ///
    /// Returns a record-protection, socket, or absolute deadline error.
    pub async fn shutdown(&mut self, timeout: Duration) -> Result<(), TlsApplicationIoError> {
        shutdown_tls_writer(
            &mut self.io,
            self.tls.server_records_mut(),
            &mut self.write_record,
            &mut self.idle,
            timeout,
        )
        .await
    }
}

impl TlsApplicationReader<tokio::net::tcp::OwnedReadHalf> {
    /// Borrows the client descriptor for abort-path socket options.
    ///
    /// The borrow is lifetime-bound to this reader, so an abort guard has to
    /// capture what it needs while the socket is provably live.
    #[must_use]
    pub fn fd(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd as _;
        self.io.as_ref().as_fd()
    }
}

impl<R> TlsApplicationReader<R>
where
    R: AsyncRead + Unpin,
{
    /// Reads and authenticates one client application record.
    ///
    /// Complete records are parsed out of the connection-owned socket buffer;
    /// a refill moves available socket bytes into that buffer with a single
    /// read, so a pipelined peer costs one syscall per refill rather than two
    /// per record. The record is opened in place inside the buffer and the
    /// plaintext is exposed as a borrowed slice, exactly like the record-exact
    /// path: no owned `Vec` is produced per record.
    /// An authenticated post-handshake control record returns an empty value so
    /// the caller retains control of flushing and absolute deadlines.
    ///
    /// # Errors
    ///
    /// Returns a bounded record, AEAD, alert, content-type, or deadline error.
    /// The kinds and consumed-byte prefixes are identical to the record-exact
    /// read: EOF at a record boundary is an [`TlsRecordReadErrorKind::UnexpectedEof`]
    /// with an empty prefix, EOF or timeout mid-record carries exactly the
    /// partial record bytes buffered so far, and an invalid declared length is
    /// [`TlsRecordReadErrorKind::RecordTooLarge`] with the five-byte header.
    pub async fn read_application(
        &mut self,
        timeout: Duration,
    ) -> Result<ApplicationRecord<'_>, TlsApplicationIoError> {
        while self.buffered_end - self.buffered_start < TLS_RECORD_HEADER_LEN {
            self.refill(timeout).await?;
        }
        let header_end = self.buffered_start + TLS_RECORD_HEADER_LEN;
        let header = self
            .socket_buffer
            .get(self.buffered_start..header_end)
            .ok_or(TlsApplicationIoError::Record(
                Tls13RecordError::InvalidLength,
            ))?;
        let body_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if body_len == 0 || body_len > MAX_TLS13_CIPHERTEXT_LEN {
            return Err(TlsApplicationIoError::Read(buffered_failure(
                TlsRecordReadErrorKind::RecordTooLarge,
                header,
            )));
        }
        let record_len = TLS_RECORD_HEADER_LEN + body_len;
        while self.buffered_end - self.buffered_start < record_len {
            self.refill(timeout).await?;
        }
        // Advance the cursor past the record before borrowing the buffer for
        // the in-place open: the AEAD then mutates only the record slice while
        // any bytes of later records stay untouched behind the cursor.
        let record_start = self.buffered_start;
        let record_end = record_start + record_len;
        self.buffered_start = record_end;
        let outcome = {
            let record = self.socket_buffer.get_mut(record_start..record_end).ok_or(
                TlsApplicationIoError::Record(Tls13RecordError::InvalidLength),
            )?;
            let opened = self
                .records
                .open_in_place(record)
                .map_err(TlsApplicationIoError::Record)?;
            process_opened_record(
                &mut self.records,
                &mut self.key_update,
                opened.content_type(),
                opened.plaintext(),
            )?
        };
        let plaintext_len = match outcome {
            OpenedRecordOutcome::ApplicationData(plaintext_len) => plaintext_len,
            OpenedRecordOutcome::Control {
                key_update_requested,
            } => {
                if key_update_requested {
                    self.key_update_coordination
                        .response_observed
                        .store(true, Ordering::Release);
                }
                return Ok(ApplicationRecord { plaintext: &[] });
            }
        };
        let plaintext_start = record_start.checked_add(TLS_RECORD_HEADER_LEN).ok_or(
            TlsApplicationIoError::Record(Tls13RecordError::InvalidLength),
        )?;
        let plaintext_end =
            plaintext_start
                .checked_add(plaintext_len)
                .ok_or(TlsApplicationIoError::Record(
                    Tls13RecordError::InvalidLength,
                ))?;
        let plaintext = self
            .socket_buffer
            .get(plaintext_start..plaintext_end)
            .ok_or(TlsApplicationIoError::Record(
                Tls13RecordError::InvalidLength,
            ))?;
        Ok(ApplicationRecord { plaintext })
    }

    /// Moves available socket bytes into the buffer under one idle window.
    ///
    /// The buffer is compacted only when the free tail can no longer hold one
    /// maximum-sized record, so the steady-state path neither copies nor
    /// allocates. One refill is one idle window: steady progress resets the
    /// deadline, never a session cap.
    async fn refill(&mut self, timeout: Duration) -> Result<(), TlsApplicationIoError> {
        self.ensure_socket_buffer()?;
        if self.buffered_start == self.buffered_end {
            self.buffered_start = 0;
            self.buffered_end = 0;
        } else if self.socket_buffer.len() - self.buffered_end < MAX_TLS_RECORD_WIRE_LEN {
            let buffered = self.buffered_end - self.buffered_start;
            self.socket_buffer
                .copy_within(self.buffered_start..self.buffered_end, 0);
            self.buffered_start = 0;
            self.buffered_end = buffered;
        }
        if self.buffered_end == self.socket_buffer.len() {
            // Unreachable for validated record lengths (one record never
            // exceeds a quarter of the buffer): a single record larger than
            // the whole buffer grows the storage once, following the same
            // reserve-then-zero-fill pattern as the initial allocation.
            self.socket_buffer
                .try_reserve_exact(SOCKET_BUFFER_CAPACITY)
                .map_err(|_| TlsApplicationIoError::Record(Tls13RecordError::BufferAllocation))?;
            self.socket_buffer
                .resize(self.socket_buffer.len() + SOCKET_BUFFER_CAPACITY, 0);
        }
        self.idle
            .reset(timeout)
            .map_err(|_| TlsApplicationIoError::Timeout)?;
        let end = self.buffered_end;
        let destination =
            self.socket_buffer
                .get_mut(end..)
                .ok_or(TlsApplicationIoError::Record(
                    Tls13RecordError::InvalidLength,
                ))?;
        let kind = match self.idle.read(&mut self.io, destination).await {
            Ok(0) => TlsRecordReadErrorKind::UnexpectedEof,
            Ok(read) => {
                self.buffered_end += read;
                return Ok(());
            }
            Err(IdleError::Timeout) => TlsRecordReadErrorKind::Timeout,
            Err(IdleError::Io(source)) => TlsRecordReadErrorKind::Io(source),
        };
        Err(self.refill_failure(kind))
    }

    /// Maps a failed refill to the record-exact read error shape.
    ///
    /// The unconsumed buffered bytes are exactly the partial record a
    /// record-exact read would have consumed when the failure hit, so the
    /// error kind and prefix match `read_tls_record_into` one to one —
    /// including the clean-EOF case, where nothing is buffered and the prefix
    /// is empty.
    fn refill_failure(&self, kind: TlsRecordReadErrorKind) -> TlsApplicationIoError {
        let buffered = self
            .socket_buffer
            .get(self.buffered_start..self.buffered_end)
            .unwrap_or_default();
        TlsApplicationIoError::Read(buffered_failure(kind, buffered))
    }

    /// Allocates and zero-fills the connection's socket buffer exactly once.
    fn ensure_socket_buffer(&mut self) -> Result<(), TlsApplicationIoError> {
        if self.socket_buffer.capacity() == 0 {
            let mut buffer = Vec::new();
            buffer
                .try_reserve_exact(SOCKET_BUFFER_CAPACITY)
                .map_err(|_| TlsApplicationIoError::Record(Tls13RecordError::BufferAllocation))?;
            buffer.resize(SOCKET_BUFFER_CAPACITY, 0);
            self.socket_buffer = buffer;
        }
        Ok(())
    }

    /// Returns whether the socket buffer already holds one complete record.
    ///
    /// A relay that batches several decoded records into one destination
    /// write uses this to flush exactly when the next [`Self::read_application`]
    /// would block on the socket: while a complete record is buffered the
    /// loop keeps decoding into the batch, and the first record that would
    /// require a refill flushes the batch first, so batching never adds
    /// latency to a sparse flow. The check peeks only at the declared length;
    /// the record itself is still validated and authenticated by the read.
    #[must_use]
    pub(crate) fn has_buffered_record(&self) -> bool {
        let buffered = self.buffered_end - self.buffered_start;
        if buffered < TLS_RECORD_HEADER_LEN {
            return false;
        }
        let Some(header) = self
            .socket_buffer
            .get(self.buffered_start..self.buffered_start + TLS_RECORD_HEADER_LEN)
        else {
            return false;
        };
        let body_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        buffered >= TLS_RECORD_HEADER_LEN + body_len
    }

    /// Returns the address of the reusable record storage for allocation tests.
    ///
    /// The socket buffer is allocated on the first read and never moves
    /// afterwards, so a warm connection reports one stable address.
    #[must_use]
    pub fn record_storage_address(&self) -> usize {
        self.socket_buffer.as_ptr() as usize
    }
}

impl TlsApplicationWriter<tokio::net::tcp::OwnedWriteHalf> {
    /// Borrows the client descriptor for abort-path socket options.
    ///
    /// The borrow is lifetime-bound to this writer, so an abort guard has to
    /// capture what it needs while the socket is provably live.
    #[must_use]
    pub fn fd(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd as _;
        self.io.as_ref().as_fd()
    }
}

impl<W> TlsApplicationWriter<W>
where
    W: AsyncWrite + Unpin,
{
    /// Encrypts and writes bounded server application records.
    ///
    /// # Errors
    ///
    /// Returns a record-protection, allocation, socket, or deadline error.
    pub async fn write_application(
        &mut self,
        plaintext: &[u8],
        timeout: Duration,
    ) -> Result<ApplicationWriteStats, TlsApplicationIoError> {
        write_application_data(
            &mut self.io,
            &mut self.records,
            &mut self.write_record,
            &mut self.idle,
            &self.key_update_coordination,
            plaintext,
            timeout,
        )
        .await
    }

    /// Reads transport bytes straight into AEAD plaintext storage and seals in place.
    ///
    /// This is the relay shape of [`TlsApplicationWriter::write_assembled`]:
    /// instead of assembling a framed payload, the plaintext region of the
    /// connection's reusable record buffer is the destination of one socket
    /// read, and exactly the bytes read are sealed. The scratch buffer and its
    /// per-chunk copy are gone; the only copy left is the socket read itself.
    /// One idle window covers the read and the write, so a relay chunk costs
    /// one timer registration.
    ///
    /// Returns the number of plaintext bytes sealed; `0` means the peer
    /// reached EOF and no record was written.
    ///
    /// # Errors
    ///
    /// Returns a record-protection, allocation, socket, or deadline error.
    pub async fn write_application_read_from<R>(
        &mut self,
        reader: &mut R,
        timeout: Duration,
    ) -> Result<usize, TlsApplicationIoError>
    where
        R: AsyncRead + Unpin,
    {
        self.idle
            .reset(timeout)
            .map_err(|_| TlsApplicationIoError::Timeout)?;
        let read = {
            let region = super::record::application_plaintext_region(&mut self.write_record)
                .map_err(TlsApplicationIoError::Record)?;
            self.idle.read(reader, region).await.map_err(idle_failure)?
        };
        if read == 0 {
            return Ok(0);
        }
        let key_update_written = write_key_update_if_needed(
            &mut self.io,
            &mut self.records,
            &mut self.idle,
            self.key_update_coordination.as_ref(),
            timeout,
        )
        .await?;
        if key_update_written {
            self.idle
                .reset(timeout)
                .map_err(|_| TlsApplicationIoError::Timeout)?;
        }
        let record_len = self
            .records
            .seal_filled(ContentType::ApplicationData, read, &mut self.write_record)
            .map_err(TlsApplicationIoError::Record)?;
        let record = self
            .write_record
            .get(..record_len)
            .ok_or(TlsApplicationIoError::Record(
                Tls13RecordError::InvalidLength,
            ))?;
        self.idle
            .write_all(&mut self.io, record)
            .await
            .map_err(idle_failure)?;
        Ok(read)
    }

    /// Batched variant of [`TlsApplicationWriter::write_application_read_from`]
    /// (experiment D11): one vectored destination read fills up to
    /// [`super::record::BATCHED_SLOT_COUNT`] record slots, each filled slot is
    /// sealed in place with the shared [`Tls13RecordLayer::seal_filled`] logic
    /// — one sequence increment per record, unchanged nonce/AAD semantics —
    /// and the contiguous sealed prefix goes out in a single write. A full
    /// batch therefore costs one read plus one write syscall for four records
    /// instead of one of each per record. Wire format is unchanged: maximal
    /// 16 KiB records except possibly the last, exactly today's
    /// variable-length behavior, so record boundaries on the wire stay legal
    /// TLS either way.
    ///
    /// Lazy growth bounds idle-connection memory: the connection starts on the
    /// single-record buffer and only a completely-full record read — evidence
    /// of a bulk flow — grows the buffer to the batched layout (once, via the
    /// reserve-then-zero-fill discipline of the single-record path). The
    /// buffer never shrinks back, and idle or small-flow connections never pay
    /// the extra slots.
    ///
    /// Returns the number of plaintext bytes sealed; `0` means the peer
    /// reached EOF and nothing was written. A short read mid-batch seals and
    /// writes whatever was already filled, so an EOF that follows behaves
    /// exactly like today's EOF path. One idle window covers the read and the
    /// write, as in the single-record variant.
    ///
    /// # Errors
    ///
    /// Returns a record-protection, allocation, socket, or deadline error.
    pub(crate) async fn write_application_read_from_batched<R>(
        &mut self,
        reader: &mut R,
        timeout: Duration,
    ) -> Result<usize, TlsApplicationIoError>
    where
        R: VectoredRead,
    {
        // Mode selection keys on capacity, not length: `seal_into` and
        // `seal_assembled` clear the shared buffer, so a reduced length does
        // not mean the batched layout was never allocated.
        if self.write_record.capacity() < super::record::BATCHED_WIRE_CAPACITY {
            let read = self.write_application_read_from(reader, timeout).await?;
            if read == MAX_PLAINTEXT_LEN {
                super::record::grow_batched_record_storage(&mut self.write_record)
                    .map_err(TlsApplicationIoError::Record)?;
            }
            return Ok(read);
        }
        // A no-op in the steady state; restores the full batched length if an
        // interleaved framed write cleared the buffer.
        super::record::grow_batched_record_storage(&mut self.write_record)
            .map_err(TlsApplicationIoError::Record)?;
        self.idle
            .reset(timeout)
            .map_err(|_| TlsApplicationIoError::Timeout)?;
        let read = {
            let [first, second, third, fourth] =
                super::record::batched_plaintext_regions(&mut self.write_record)
                    .map_err(TlsApplicationIoError::Record)?;
            let mut buffers = [
                io::IoSliceMut::new(first),
                io::IoSliceMut::new(second),
                io::IoSliceMut::new(third),
                io::IoSliceMut::new(fourth),
            ];
            self.idle
                .read_operation(reader.read_vectored(&mut buffers))
                .await
                .map_err(idle_failure)?
        };
        if read == 0 {
            return Ok(0);
        }
        let mut sealed_len = 0_usize;
        let mut wire_start = 0_usize;
        let mut remaining = read;
        for slot in 0..super::record::BATCHED_SLOT_COUNT {
            if remaining == 0 {
                break;
            }
            if self
                .key_update_coordination
                .response_pending
                .load(Ordering::Acquire)
                || self
                    .key_update_coordination
                    .response_observed
                    .load(Ordering::Acquire)
                || self.records.needs_key_update()
            {
                if wire_start < sealed_len {
                    let wire = self.write_record.get(wire_start..sealed_len).ok_or(
                        TlsApplicationIoError::Record(Tls13RecordError::InvalidLength),
                    )?;
                    self.idle
                        .write_all(&mut self.io, wire)
                        .await
                        .map_err(idle_failure)?;
                    wire_start = sealed_len;
                }
                if write_key_update_if_needed(
                    &mut self.io,
                    &mut self.records,
                    &mut self.idle,
                    self.key_update_coordination.as_ref(),
                    timeout,
                )
                .await?
                {
                    self.idle
                        .reset(timeout)
                        .map_err(|_| TlsApplicationIoError::Timeout)?;
                }
            }
            let filled = remaining.min(MAX_PLAINTEXT_LEN);
            let start = slot * super::record::RECORD_SLOT_WIRE_CAPACITY;
            let slot_slice = self
                .write_record
                .get_mut(start..start + super::record::RECORD_SLOT_WIRE_CAPACITY)
                .ok_or(TlsApplicationIoError::Record(
                    Tls13RecordError::InvalidLength,
                ))?;
            let record_len = self
                .records
                .seal_filled(ContentType::ApplicationData, filled, slot_slice)
                .map_err(TlsApplicationIoError::Record)?;
            sealed_len += record_len;
            remaining -= filled;
        }
        let wire =
            self.write_record
                .get(wire_start..sealed_len)
                .ok_or(TlsApplicationIoError::Record(
                    Tls13RecordError::InvalidLength,
                ))?;
        self.idle
            .write_all(&mut self.io, wire)
            .await
            .map_err(idle_failure)?;
        Ok(read)
    }

    /// Encrypts one record whose plaintext is assembled in final AEAD storage.
    ///
    /// `assemble` receives exactly `plaintext_len` bytes inside the connection's
    /// reusable ciphertext buffer. Callers that build a framed payload therefore
    /// never allocate or copy a complete intermediate frame.
    ///
    /// # Errors
    ///
    /// Returns a record-protection, allocation, socket, or deadline error.
    pub async fn write_assembled<Assemble>(
        &mut self,
        plaintext_len: usize,
        assemble: Assemble,
        timeout: Duration,
    ) -> Result<(), TlsApplicationIoError>
    where
        Assemble: FnOnce(&mut [u8]),
    {
        write_key_update_if_needed(
            &mut self.io,
            &mut self.records,
            &mut self.idle,
            self.key_update_coordination.as_ref(),
            timeout,
        )
        .await?;
        self.idle
            .reset(timeout)
            .map_err(|_| TlsApplicationIoError::Timeout)?;
        self.records
            .seal_assembled(
                ContentType::ApplicationData,
                plaintext_len,
                0,
                &mut self.write_record,
                assemble,
            )
            .map_err(TlsApplicationIoError::Record)?;
        let record = self.write_record.as_slice();
        self.idle
            .write_all(&mut self.io, record)
            .await
            .map_err(idle_failure)
    }

    /// Sends an authenticated `close_notify` and shuts down the transport writer.
    ///
    /// # Errors
    ///
    /// Returns a record-protection, socket, or absolute deadline error.
    pub async fn shutdown(&mut self, timeout: Duration) -> Result<(), TlsApplicationIoError> {
        shutdown_tls_writer(
            &mut self.io,
            &mut self.records,
            &mut self.write_record,
            &mut self.idle,
            timeout,
        )
        .await
    }

    /// Returns the address of the reusable ciphertext storage for allocation tests.
    #[must_use]
    pub fn record_storage_address(&self) -> usize {
        self.write_record.as_ptr() as usize
    }
}

async fn read_application_record<'record, R>(
    io: &mut R,
    records: &mut super::Tls13RecordLayer,
    wire: &'record mut Vec<u8>,
    idle: &mut IdleDeadline,
    key_update: &mut KeyUpdateReassembly,
    key_update_coordination: &KeyUpdateCoordination,
) -> Result<ApplicationRecord<'record>, TlsApplicationIoError>
where
    R: AsyncRead + Unpin,
{
    ensure_record_storage(wire)?;
    let length = read_tls_record_into(io, wire, idle)
        .await
        .map_err(TlsApplicationIoError::Read)?;
    let outcome = {
        let record = wire.get_mut(..length).ok_or(TlsApplicationIoError::Record(
            Tls13RecordError::InvalidLength,
        ))?;
        let opened = records
            .open_in_place(record)
            .map_err(TlsApplicationIoError::Record)?;
        process_opened_record(
            records,
            key_update,
            opened.content_type(),
            opened.plaintext(),
        )?
    };
    let plaintext_len = match outcome {
        OpenedRecordOutcome::ApplicationData(plaintext_len) => plaintext_len,
        OpenedRecordOutcome::Control {
            key_update_requested,
        } => {
            if key_update_requested {
                key_update_coordination
                    .response_observed
                    .store(true, Ordering::Release);
            }
            return Ok(ApplicationRecord { plaintext: &[] });
        }
    };
    let plaintext_end =
        TLS_RECORD_HEADER_LEN
            .checked_add(plaintext_len)
            .ok_or(TlsApplicationIoError::Record(
                Tls13RecordError::InvalidLength,
            ))?;
    let plaintext =
        wire.get(TLS_RECORD_HEADER_LEN..plaintext_end)
            .ok_or(TlsApplicationIoError::Record(
                Tls13RecordError::InvalidLength,
            ))?;
    Ok(ApplicationRecord { plaintext })
}

fn process_opened_record(
    records: &mut super::Tls13RecordLayer,
    key_update: &mut KeyUpdateReassembly,
    content_type: ContentType,
    plaintext: &[u8],
) -> Result<OpenedRecordOutcome, TlsApplicationIoError> {
    match content_type {
        ContentType::ApplicationData => {
            if !key_update.is_empty() {
                return Err(TlsApplicationIoError::InvalidKeyUpdate);
            }
            Ok(OpenedRecordOutcome::ApplicationData(plaintext.len()))
        }
        ContentType::Alert => {
            if !key_update.is_empty() {
                return Err(TlsApplicationIoError::InvalidKeyUpdate);
            }
            let [level, description] =
                <[u8; 2]>::try_from(plaintext).map_err(|_| TlsApplicationIoError::InvalidAlert)?;
            Err(TlsApplicationIoError::PeerAlert { level, description })
        }
        ContentType::Handshake => {
            let request = process_key_update_record(records, key_update, plaintext)?;
            Ok(OpenedRecordOutcome::Control {
                key_update_requested: request == Some(KeyUpdateRequest::Requested),
            })
        }
        ContentType::ChangeCipherSpec => Err(if key_update.is_empty() {
            TlsApplicationIoError::UnexpectedContentType(content_type)
        } else {
            TlsApplicationIoError::InvalidKeyUpdate
        }),
    }
}

fn process_key_update_record(
    records: &mut super::Tls13RecordLayer,
    key_update: &mut KeyUpdateReassembly,
    fragment: &[u8],
) -> Result<Option<KeyUpdateRequest>, TlsApplicationIoError> {
    let request = key_update.push_record(fragment)?;
    if request.is_some() {
        records
            .update_traffic_secret()
            .map_err(TlsApplicationIoError::Record)?;
    }
    Ok(request)
}

/// Reserves the connection's single record buffer exactly once.
fn ensure_record_storage(wire: &mut Vec<u8>) -> Result<(), TlsApplicationIoError> {
    if wire.capacity() == 0 {
        *wire = record_storage()
            .map_err(|_| TlsApplicationIoError::Record(Tls13RecordError::BufferAllocation))?;
    }
    Ok(())
}

async fn write_key_update_if_needed<W>(
    io: &mut W,
    records: &mut super::Tls13RecordLayer,
    idle: &mut IdleDeadline,
    key_update_coordination: &KeyUpdateCoordination,
    timeout: Duration,
) -> Result<bool, TlsApplicationIoError>
where
    W: AsyncWrite + Unpin,
{
    let mut pending_response = PendingKeyUpdateResponse::take(key_update_coordination);
    if !pending_response.was_requested() && !records.needs_key_update() {
        return Ok(false);
    }

    idle.reset(timeout)
        .map_err(|_| TlsApplicationIoError::Timeout)?;
    let mut response = [0_u8; KEY_UPDATE_RECORD_WIRE_LEN];
    response
        .get_mut(TLS_RECORD_HEADER_LEN..TLS_RECORD_HEADER_LEN + KEY_UPDATE_MESSAGE_LEN)
        .ok_or(TlsApplicationIoError::Record(
            Tls13RecordError::InvalidLength,
        ))?
        .copy_from_slice(&KEY_UPDATE_RESPONSE);
    let record_len = records
        .seal_filled(
            ContentType::Handshake,
            KEY_UPDATE_MESSAGE_LEN,
            &mut response,
        )
        .map_err(TlsApplicationIoError::Record)?;
    let record = response
        .get(..record_len)
        .ok_or(TlsApplicationIoError::Record(
            Tls13RecordError::InvalidLength,
        ))?;
    idle.write_all(io, record).await.map_err(idle_failure)?;
    records
        .update_traffic_secret()
        .map_err(TlsApplicationIoError::Record)?;
    pending_response.complete();
    Ok(true)
}

async fn write_application_data<W>(
    io: &mut W,
    records: &mut super::Tls13RecordLayer,
    write_record: &mut Vec<u8>,
    idle: &mut IdleDeadline,
    key_update_coordination: &KeyUpdateCoordination,
    plaintext: &[u8],
    timeout: Duration,
) -> Result<ApplicationWriteStats, TlsApplicationIoError>
where
    W: AsyncWrite + Unpin,
{
    let mut record_count = 0_u64;
    for chunk in plaintext.chunks(MAX_PLAINTEXT_LEN) {
        write_key_update_if_needed(io, records, idle, key_update_coordination, timeout).await?;
        // One idle window per record: steady progress can never time out,
        // while a stalled peer is still bounded per record.
        idle.reset(timeout)
            .map_err(|_| TlsApplicationIoError::Timeout)?;
        write_content(
            io,
            records,
            write_record,
            idle,
            ContentType::ApplicationData,
            chunk,
        )
        .await?;
        record_count = record_count.saturating_add(1);
    }
    Ok(ApplicationWriteStats {
        plaintext_bytes: u64::try_from(plaintext.len()).unwrap_or(u64::MAX),
        records: record_count,
    })
}

async fn shutdown_tls_writer<W>(
    io: &mut W,
    records: &mut super::Tls13RecordLayer,
    write_record: &mut Vec<u8>,
    idle: &mut IdleDeadline,
    timeout: Duration,
) -> Result<(), TlsApplicationIoError>
where
    W: AsyncWrite + Unpin,
{
    idle.reset(timeout)
        .map_err(|_| TlsApplicationIoError::Timeout)?;
    write_content(
        io,
        records,
        write_record,
        idle,
        ContentType::Alert,
        &[ALERT_LEVEL_WARNING, ALERT_CLOSE_NOTIFY],
    )
    .await?;
    idle.shutdown(io).await.map_err(idle_failure)
}

async fn write_content<W>(
    io: &mut W,
    records: &mut super::Tls13RecordLayer,
    write_record: &mut Vec<u8>,
    idle: &mut IdleDeadline,
    content_type: ContentType,
    plaintext: &[u8],
) -> Result<(), TlsApplicationIoError>
where
    W: AsyncWrite + Unpin,
{
    records
        .seal_into(content_type, plaintext, 0, write_record)
        .map_err(TlsApplicationIoError::Record)?;
    idle.write_all(io, write_record).await.map_err(idle_failure)
}

/// Maps an idle-guarded operation failure to the application I/O error.
fn idle_failure(error: IdleError) -> TlsApplicationIoError {
    match error {
        IdleError::Timeout => TlsApplicationIoError::Timeout,
        IdleError::Io(source) => TlsApplicationIoError::Io(source),
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

impl<R> fmt::Debug for TlsApplicationReader<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsApplicationReader")
            .field("records", &self.records)
            .field("transport", &"[BOUND]")
            .finish_non_exhaustive()
    }
}

impl<W> fmt::Debug for TlsApplicationWriter<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsApplicationWriter")
            .field("records", &self.records)
            .field("write_buffer_capacity", &self.write_record.capacity())
            .field("transport", &"[BOUND]")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::{Future, poll_fn},
        io,
        pin::Pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        task::{Context, Poll},
        time::Duration,
    };

    use futures_util::task::AtomicWaker;

    use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf, duplex};

    use super::{
        KEY_UPDATE_REQUESTED, KEY_UPDATE_RESPONSE, KeyUpdateCoordination, PendingKeyUpdateResponse,
        TlsApplicationIo, TlsApplicationIoError, VectoredRead, resume_application_halves,
    };
    use crate::protocol::reality::tls13::record::{
        BATCHED_SLOT_COUNT, BATCHED_WIRE_CAPACITY, RECORD_SLOT_WIRE_CAPACITY,
        grow_batched_record_storage,
    };
    use crate::protocol::reality::tls13::{
        CipherSuite, ContentType, EstablishedTls, ExportedRecordState, MAX_PLAINTEXT_LEN,
        Tls13KeySchedule, Tls13RecordError, Tls13RecordLayer, TlsRecordReadErrorKind,
        read_tls_record,
    };

    const TIMEOUT: Duration = Duration::from_secs(1);

    #[tokio::test(flavor = "current_thread")]
    async fn decrypts_and_encrypts_application_records_without_plaintext_copy() {
        let (established, mut client_write_records, mut client_read_records) = key_update_states();
        let (mut client, server) = duplex(64 * 1024);
        let application = TlsApplicationIo::new(server, established);
        let (mut application_reader, mut application_writer) = application.into_split();

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
        let request = application_reader
            .read_application(TIMEOUT)
            .await
            .expect("request record must authenticate");
        assert_eq!(request.plaintext(), b"VLESS request");
        assert_eq!(request.len(), b"VLESS request".len());

        let stats = application_writer
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

        application_writer
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
        let (established, mut client_records, _client_read_records) = key_update_states();
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

    fn key_update_states() -> (EstablishedTls, Tls13RecordLayer, Tls13RecordLayer) {
        let suite = CipherSuite::Aes128GcmSha256;
        let schedule = schedule(suite);
        let transcript = suite.hash().digest(b"server finished transcript");
        let (server_client_secret, server_server_secret) = schedule
            .application_traffic_secrets(&transcript)
            .expect("server application secrets must derive")
            .into_parts();
        let (client_write_secret, client_read_secret) = schedule
            .application_traffic_secrets(&transcript)
            .expect("client application secrets must derive")
            .into_parts();
        let server_client_records =
            Tls13RecordLayer::from_traffic_secret(suite, server_client_secret)
                .expect("server read records must initialize");
        let server_server_records =
            Tls13RecordLayer::from_traffic_secret(suite, server_server_secret)
                .expect("server write records must initialize");
        (
            EstablishedTls::from_test_records(suite, server_client_records, server_server_records),
            Tls13RecordLayer::from_traffic_secret(suite, client_write_secret)
                .expect("client write records must initialize"),
            Tls13RecordLayer::from_traffic_secret(suite, client_read_secret)
                .expect("client read records must initialize"),
        )
    }

    fn seal(
        records: &mut Tls13RecordLayer,
        content_type: ContentType,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let mut record = Vec::new();
        records
            .seal_into(content_type, plaintext, 0, &mut record)
            .expect("test record must seal");
        record
    }

    #[test]
    fn cancelled_key_update_write_restores_the_pending_response() {
        let coordination = KeyUpdateCoordination::new(false);
        coordination
            .response_observed
            .store(true, Ordering::Release);
        {
            let response = PendingKeyUpdateResponse::take(&coordination);
            assert!(response.was_requested());
            assert!(!coordination.response_observed.load(Ordering::Acquire));
            assert!(!coordination.response_pending.load(Ordering::Acquire));
        }
        assert!(coordination.response_pending.load(Ordering::Acquire));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn split_reader_reassembles_unrequested_key_update_before_application_data() {
        let (established, mut client_write, _client_read) = key_update_states();
        let (mut client, server) = duplex(4096);
        let application = TlsApplicationIo::new(server, established);
        let (mut reader, writer) = application.into_split();

        let mut wire = seal(
            &mut client_write,
            ContentType::Handshake,
            &KEY_UPDATE_RESPONSE[..2],
        );
        wire.extend_from_slice(&seal(
            &mut client_write,
            ContentType::Handshake,
            &KEY_UPDATE_RESPONSE[2..],
        ));
        client_write
            .update_traffic_secret()
            .expect("client write secret must update");
        wire.extend_from_slice(&seal(
            &mut client_write,
            ContentType::ApplicationData,
            b"after update",
        ));
        client
            .write_all(&wire)
            .await
            .expect("fragmented KeyUpdate and application record must be written");

        for _ in 0..2 {
            let control = reader
                .read_application(TIMEOUT)
                .await
                .expect("KeyUpdate fragment must authenticate");
            assert!(control.is_empty());
        }
        let application = reader
            .read_application(TIMEOUT)
            .await
            .expect("next application record must authenticate");
        assert_eq!(application.plaintext(), b"after update");
        assert!(
            !writer.into_handoff_parts().2,
            "update_not_requested must not schedule a response"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn key_update_returns_without_waiting_for_application_data() {
        let (established, mut client_write, _client_read) = key_update_states();
        let (mut client, server) = duplex(4096);
        let application = TlsApplicationIo::new(server, established);
        let (mut reader, writer) = application.into_split();
        let wire = seal(
            &mut client_write,
            ContentType::Handshake,
            &KEY_UPDATE_RESPONSE,
        );
        client_write
            .update_traffic_secret()
            .expect("client write secret must update");
        client
            .write_all(&wire)
            .await
            .expect("KeyUpdate must be written");

        let control = reader
            .read_application(TIMEOUT)
            .await
            .expect("KeyUpdate must return at its record boundary");
        assert!(control.is_empty());
        assert!(!writer.into_handoff_parts().2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn requested_key_update_response_precedes_next_generation_application_data() {
        let (established, mut client_write, mut client_read) = key_update_states();
        let (_, _, mut stale_client_read) = key_update_states();
        let (mut client, server) = duplex(4096);
        let application = TlsApplicationIo::new(server, established);
        let (mut reader, mut writer) = application.into_split();

        let request = [
            KEY_UPDATE_RESPONSE[0],
            KEY_UPDATE_RESPONSE[1],
            KEY_UPDATE_RESPONSE[2],
            KEY_UPDATE_RESPONSE[3],
            KEY_UPDATE_REQUESTED,
        ];
        let mut wire = seal(&mut client_write, ContentType::Handshake, &request);
        client_write
            .update_traffic_secret()
            .expect("client write secret must update");
        wire.extend_from_slice(&seal(
            &mut client_write,
            ContentType::ApplicationData,
            b"request body",
        ));
        client
            .write_all(&wire)
            .await
            .expect("requested KeyUpdate and application record must be written");

        let control = reader
            .read_application(TIMEOUT)
            .await
            .expect("requested KeyUpdate must authenticate");
        assert!(control.is_empty());
        let request_body = reader
            .read_application(TIMEOUT)
            .await
            .expect("next application record must authenticate");
        assert_eq!(request_body.plaintext(), b"request body");
        writer
            .write_assembled(
                b"reply".len(),
                |plaintext| plaintext.copy_from_slice(b"reply"),
                TIMEOUT,
            )
            .await
            .expect("response and application record must be written");

        let mut response_wire = read_tls_record(&mut client, TIMEOUT)
            .await
            .expect("KeyUpdate response must be first")
            .into_wire();
        let mut application_wire = read_tls_record(&mut client, TIMEOUT)
            .await
            .expect("application record must follow")
            .into_wire();
        let mut stale_response_wire = response_wire.clone();
        let response = stale_client_read
            .open_in_place(&mut stale_response_wire)
            .expect("response must use the old write key");
        assert_eq!(response.content_type(), ContentType::Handshake);
        assert_eq!(response.plaintext(), KEY_UPDATE_RESPONSE);
        let mut stale_application_wire = application_wire.clone();
        assert!(matches!(
            stale_client_read.open_in_place(&mut stale_application_wire),
            Err(Tls13RecordError::AuthenticationFailed)
        ));

        let response = client_read
            .open_in_place(&mut response_wire)
            .expect("response must authenticate under the old key");
        assert_eq!(response.content_type(), ContentType::Handshake);
        assert_eq!(response.plaintext(), KEY_UPDATE_RESPONSE);
        client_read
            .update_traffic_secret()
            .expect("client read secret must update");
        let application = client_read
            .open_in_place(&mut application_wire)
            .expect("application data must use the next write key");
        assert_eq!(application.content_type(), ContentType::ApplicationData);
        assert_eq!(application.plaintext(), b"reply");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unsplit_io_processes_requested_key_update_transparently() {
        let (established, mut client_write, mut client_read) = key_update_states();
        let (mut client, server) = duplex(4096);
        let mut application = TlsApplicationIo::new(server, established);
        let request = [24, 0, 0, 1, KEY_UPDATE_REQUESTED];
        let mut wire = seal(&mut client_write, ContentType::Handshake, &request);
        client_write
            .update_traffic_secret()
            .expect("client write secret must update");
        wire.extend_from_slice(&seal(
            &mut client_write,
            ContentType::ApplicationData,
            b"unsplit request",
        ));
        client
            .write_all(&wire)
            .await
            .expect("unsplit request must be written");

        let control = application
            .read_application(TIMEOUT)
            .await
            .expect("unsplit KeyUpdate must authenticate");
        assert!(control.is_empty());
        let request = application
            .read_application(TIMEOUT)
            .await
            .expect("unsplit application record must authenticate");
        assert_eq!(request.plaintext(), b"unsplit request");
        application
            .write_application(b"unsplit reply", TIMEOUT)
            .await
            .expect("unsplit response must be written");

        let mut response_wire = read_tls_record(&mut client, TIMEOUT)
            .await
            .expect("unsplit KeyUpdate response must be written first")
            .into_wire();
        let response = client_read
            .open_in_place(&mut response_wire)
            .expect("unsplit response must use the old key");
        assert_eq!(response.content_type(), ContentType::Handshake);
        assert_eq!(response.plaintext(), KEY_UPDATE_RESPONSE);
        client_read
            .update_traffic_secret()
            .expect("client read secret must update");
        let mut application_wire = read_tls_record(&mut client, TIMEOUT)
            .await
            .expect("unsplit application response must follow")
            .into_wire();
        let response = client_read
            .open_in_place(&mut application_wire)
            .expect("unsplit application response must use the next key");
        assert_eq!(response.content_type(), ContentType::ApplicationData);
        assert_eq!(response.plaintext(), b"unsplit reply");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn application_data_after_key_update_rejects_the_old_read_key() {
        let (established, mut client_write, _client_read) = key_update_states();
        let (mut client, server) = duplex(4096);
        let mut application = TlsApplicationIo::new(server, established);
        let mut wire = seal(
            &mut client_write,
            ContentType::Handshake,
            &KEY_UPDATE_RESPONSE,
        );
        wire.extend_from_slice(&seal(
            &mut client_write,
            ContentType::ApplicationData,
            b"stale generation",
        ));
        client
            .write_all(&wire)
            .await
            .expect("stale-generation test records must be written");

        let control = application
            .read_application(TIMEOUT)
            .await
            .expect("KeyUpdate must authenticate");
        assert!(control.is_empty());
        assert!(matches!(
            application.read_application(TIMEOUT).await,
            Err(TlsApplicationIoError::Record(
                Tls13RecordError::AuthenticationFailed
            ))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unsplit_reader_rejects_malformed_and_interleaved_key_updates() {
        let malformed = [
            vec![(ContentType::Handshake, Vec::new())],
            vec![(ContentType::Handshake, vec![25, 0, 0, 1, 0])],
            vec![(ContentType::Handshake, vec![24, 0, 0, 2, 0])],
            vec![(ContentType::Handshake, vec![24, 0, 0, 1, 2])],
            vec![(ContentType::Handshake, vec![24, 0, 0, 1, 0, 7])],
            vec![(
                ContentType::Handshake,
                [
                    KEY_UPDATE_RESPONSE.as_slice(),
                    KEY_UPDATE_RESPONSE.as_slice(),
                ]
                .concat(),
            )],
            vec![
                (ContentType::Handshake, vec![24, 0]),
                (ContentType::ApplicationData, b"interleaved".to_vec()),
            ],
            vec![
                (ContentType::Handshake, vec![24, 0]),
                (ContentType::Alert, vec![2, 40]),
            ],
        ];

        for records in malformed {
            let (established, mut client_write, _client_read) = key_update_states();
            let (mut client, server) = duplex(4096);
            let mut application = TlsApplicationIo::new(server, established);
            let record_count = records.len();
            let mut wire = Vec::new();
            for (content_type, plaintext) in records {
                wire.extend_from_slice(&seal(&mut client_write, content_type, &plaintext));
            }
            client
                .write_all(&wire)
                .await
                .expect("malformed test records must be written");

            let mut rejected = false;
            for _ in 0..record_count {
                match application.read_application(TIMEOUT).await {
                    Ok(control) if control.is_empty() => {}
                    Err(TlsApplicationIoError::InvalidKeyUpdate) => {
                        rejected = true;
                        break;
                    }
                    result => panic!("unexpected malformed KeyUpdate result: {result:?}"),
                }
            }
            assert!(rejected);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handoff_resume_preserves_requested_key_update_response() {
        let (established, mut client_write, mut client_read) = key_update_states();
        let (mut client, server) = duplex(4096);
        let application = TlsApplicationIo::new(server, established);
        let (mut reader, writer) = application.into_split();
        let request = [24, 0, 0, 1, KEY_UPDATE_REQUESTED];
        let mut wire = seal(&mut client_write, ContentType::Handshake, &request);
        client_write
            .update_traffic_secret()
            .expect("client write secret must update");
        wire.extend_from_slice(&seal(
            &mut client_write,
            ContentType::ApplicationData,
            b"handoff boundary",
        ));
        client
            .write_all(&wire)
            .await
            .expect("handoff input must be written");
        let control = reader
            .read_application(TIMEOUT)
            .await
            .expect("handoff KeyUpdate must authenticate");
        assert!(control.is_empty());
        let boundary = reader
            .read_application(TIMEOUT)
            .await
            .expect("handoff boundary must authenticate");
        assert_eq!(boundary.plaintext(), b"handoff boundary");

        let (writer_half, server_records, key_update_response_pending) =
            writer.into_handoff_parts();
        assert!(key_update_response_pending);
        let (pending_ciphertext, reader_half, client_records) = reader.into_handoff_parts();
        let tls = EstablishedTls::from_test_records(
            CipherSuite::Aes128GcmSha256,
            client_records,
            server_records,
        );
        let (_reader, mut writer) = resume_application_halves(
            reader_half,
            pending_ciphertext,
            writer_half,
            tls,
            key_update_response_pending,
        );
        writer
            .write_application(b"after handoff", TIMEOUT)
            .await
            .expect("resumed writer must answer before application data");

        let mut response_wire = read_tls_record(&mut client, TIMEOUT)
            .await
            .expect("resumed response must be written")
            .into_wire();
        let response = client_read
            .open_in_place(&mut response_wire)
            .expect("resumed response must use the old write key");
        assert_eq!(response.content_type(), ContentType::Handshake);
        assert_eq!(response.plaintext(), KEY_UPDATE_RESPONSE);
        client_read
            .update_traffic_secret()
            .expect("client read secret must update");
        let mut application_wire = read_tls_record(&mut client, TIMEOUT)
            .await
            .expect("resumed application data must be written")
            .into_wire();
        let application = client_read
            .open_in_place(&mut application_wire)
            .expect("resumed application data must use the next write key");
        assert_eq!(application.plaintext(), b"after handoff");
    }

    /// Server-side TLS state plus the client's write record layer.
    fn buffered_reader_states() -> (EstablishedTls, Tls13RecordLayer) {
        let (established, client_write, _client_read) = key_update_states();
        (established, client_write)
    }

    /// A transport replaying input in bounded chunks and counting socket reads.
    struct CountingTransport {
        input: Vec<u8>,
        position: usize,
        chunk: usize,
        reads: Arc<AtomicUsize>,
    }

    impl AsyncRead for CountingTransport {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            let available = self.input.len().saturating_sub(self.position);
            let length = available.min(output.remaining()).min(self.chunk);
            if length == 0 {
                return Poll::Ready(Ok(()));
            }
            let start = self.position;
            output.put_slice(
                self.input
                    .get(start..start + length)
                    .expect("replay window must exist"),
            );
            self.position += length;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for CountingTransport {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buffer.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn sealed_records(records: &mut Tls13RecordLayer, plaintexts: &[&[u8]]) -> Vec<u8> {
        let mut stream = Vec::new();
        for plaintext in plaintexts {
            let mut record = Vec::new();
            records
                .seal_into(ContentType::ApplicationData, plaintext, 0, &mut record)
                .expect("record must seal");
            stream.extend_from_slice(&record);
        }
        stream
    }

    #[tokio::test(flavor = "current_thread")]
    async fn two_records_in_one_burst_cost_one_socket_read() {
        let (established, mut client_write) = buffered_reader_states();
        let stream = sealed_records(&mut client_write, &[b"first", b"second"]);
        let reads = Arc::new(AtomicUsize::new(0));
        let transport = CountingTransport {
            input: stream,
            position: 0,
            chunk: usize::MAX,
            reads: reads.clone(),
        };
        let application = TlsApplicationIo::new(transport, established);
        let (mut reader, _writer) = application.into_split();

        {
            let first = reader
                .read_application(TIMEOUT)
                .await
                .expect("first record must authenticate");
            assert_eq!(first.plaintext(), b"first");
            assert_eq!(reads.load(Ordering::Relaxed), 1);
        }

        let second = reader
            .read_application(TIMEOUT)
            .await
            .expect("second record must come from the buffer");
        assert_eq!(second.plaintext(), b"second");
        assert_eq!(
            reads.load(Ordering::Relaxed),
            1,
            "the buffered second record must not touch the socket"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn has_buffered_record_peeks_complete_records_only() {
        let (established, mut client_write) = buffered_reader_states();
        let stream = sealed_records(&mut client_write, &[b"first", b"second"]);
        // Keep the complete first record plus a partial second record: the
        // peek must not mistake the partial tail for a buffered record.
        let first_wire_len = 5 + b"first".len() + 1 + 16;
        let transport = CountingTransport {
            input: stream[..first_wire_len + 7].to_vec(),
            position: 0,
            chunk: usize::MAX,
            reads: Arc::new(AtomicUsize::new(0)),
        };
        let application = TlsApplicationIo::new(transport, established);
        let (mut reader, _writer) = application.into_split();

        assert!(
            !reader.has_buffered_record(),
            "an empty socket buffer holds no record"
        );
        {
            let first = reader
                .read_application(TIMEOUT)
                .await
                .expect("first record must authenticate");
            assert_eq!(first.plaintext(), b"first");
        }
        assert!(
            !reader.has_buffered_record(),
            "a partial record tail is not a complete buffered record"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fragmented_record_is_reassembled_across_refills() {
        let (established, mut client_write) = buffered_reader_states();
        let stream = sealed_records(&mut client_write, &[b"fragmented plaintext"]);
        let reads = Arc::new(AtomicUsize::new(0));
        let transport = CountingTransport {
            input: stream,
            position: 0,
            chunk: 7,
            reads: reads.clone(),
        };
        let application = TlsApplicationIo::new(transport, established);
        let (mut reader, _writer) = application.into_split();

        let record = reader
            .read_application(TIMEOUT)
            .await
            .expect("fragmented record must authenticate");
        assert_eq!(record.plaintext(), b"fragmented plaintext");
        assert!(
            reads.load(Ordering::Relaxed) > 1,
            "a fragmented record must span multiple refills"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn clean_eof_at_a_record_boundary_keeps_the_exact_error_shape() {
        let (established, mut client_write) = buffered_reader_states();
        let stream = sealed_records(&mut client_write, &[b"only record"]);
        let transport = CountingTransport {
            input: stream,
            position: 0,
            chunk: usize::MAX,
            reads: Arc::new(AtomicUsize::new(0)),
        };
        let application = TlsApplicationIo::new(transport, established);
        let (mut reader, _writer) = application.into_split();

        {
            let record = reader
                .read_application(TIMEOUT)
                .await
                .expect("record must authenticate");
            assert_eq!(record.plaintext(), b"only record");
        }

        let error = reader
            .read_application(TIMEOUT)
            .await
            .expect_err("EOF at the boundary must fail the next read");
        let TlsApplicationIoError::Read(read) = error else {
            panic!("boundary EOF must surface as a record read error");
        };
        assert!(matches!(read.kind(), TlsRecordReadErrorKind::UnexpectedEof));
        assert_eq!(read.wire_prefix(), b"");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn eof_mid_record_reports_exactly_the_buffered_partial_bytes() {
        let (established, mut client_write) = buffered_reader_states();
        let stream = sealed_records(&mut client_write, &[b"truncated record body"]);
        let partial = stream[..stream.len() / 2].to_vec();
        let transport = CountingTransport {
            input: partial.clone(),
            position: 0,
            chunk: usize::MAX,
            reads: Arc::new(AtomicUsize::new(0)),
        };
        let application = TlsApplicationIo::new(transport, established);
        let (mut reader, _writer) = application.into_split();

        let error = reader
            .read_application(TIMEOUT)
            .await
            .expect_err("a truncated record must fail");
        let TlsApplicationIoError::Read(read) = error else {
            panic!("mid-record EOF must surface as a record read error");
        };
        assert!(matches!(read.kind(), TlsRecordReadErrorKind::UnexpectedEof));
        assert_eq!(read.wire_prefix(), partial.as_slice());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn alert_is_read_out_of_a_multi_record_burst() {
        let (established, mut client_write) = buffered_reader_states();
        let mut stream = Vec::new();
        client_write
            .seal_into(ContentType::Alert, &[2, 40], 0, &mut stream)
            .expect("alert must seal");
        stream.extend_from_slice(&sealed_records(&mut client_write, &[b"after alert"]));
        let transport = CountingTransport {
            input: stream,
            position: 0,
            chunk: usize::MAX,
            reads: Arc::new(AtomicUsize::new(0)),
        };
        let application = TlsApplicationIo::new(transport, established);
        let (mut reader, _writer) = application.into_split();

        assert!(matches!(
            reader.read_application(TIMEOUT).await,
            Err(TlsApplicationIoError::PeerAlert {
                level: 2,
                description: 40
            })
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pending_drain_returns_exactly_the_pipelined_raw_bytes() {
        let (established, mut client_write) = buffered_reader_states();
        let mut stream = sealed_records(&mut client_write, &[b"boundary record"]);
        stream.extend_from_slice(b"raw-after-boundary");
        let transport = CountingTransport {
            input: stream,
            position: 0,
            chunk: usize::MAX,
            reads: Arc::new(AtomicUsize::new(0)),
        };
        let application = TlsApplicationIo::new(transport, established);
        let (mut reader, _writer) = application.into_split();

        {
            let record = reader
                .read_application(TIMEOUT)
                .await
                .expect("boundary record must authenticate");
            assert_eq!(record.plaintext(), b"boundary record");
        }

        let (pending, _transport) = reader.into_inner_with_pending();
        assert_eq!(pending, b"raw-after-boundary");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn oversized_declared_length_fails_with_the_five_byte_header() {
        let (established, _client_write) = buffered_reader_states();
        let header = [23, 3, 3, 0xff, 0xff];
        let transport = CountingTransport {
            input: header.to_vec(),
            position: 0,
            chunk: usize::MAX,
            reads: Arc::new(AtomicUsize::new(0)),
        };
        let application = TlsApplicationIo::new(transport, established);
        let (mut reader, _writer) = application.into_split();

        let error = reader
            .read_application(TIMEOUT)
            .await
            .expect_err("an oversized declared length must fail at its header");
        let TlsApplicationIoError::Read(read) = error else {
            panic!("an invalid length must surface as a record read error");
        };
        assert!(matches!(
            read.kind(),
            TlsRecordReadErrorKind::RecordTooLarge
        ));
        assert_eq!(read.wire_prefix(), header);
    }

    /// Server-side TLS state plus the client layer that opens server records.
    fn batched_writer_states() -> (EstablishedTls, Tls13RecordLayer) {
        let (established, _client_write, client_read) = key_update_states();
        (established, client_read)
    }

    /// Opens every record on the wire and returns the plaintexts in order.
    fn open_wire_records(records: &mut Tls13RecordLayer, wire: &[u8]) -> Vec<Vec<u8>> {
        let mut plaintexts = Vec::new();
        let mut rest = wire;
        while !rest.is_empty() {
            let body_len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
            let record_len = 5 + body_len;
            let mut record = rest
                .get(..record_len)
                .expect("wire bytes must hold a whole record")
                .to_vec();
            let opened = records
                .open_in_place(&mut record)
                .expect("record must authenticate");
            assert_eq!(opened.content_type(), ContentType::ApplicationData);
            plaintexts.push(opened.plaintext().to_vec());
            rest = &rest[record_len..];
        }
        plaintexts
    }

    fn split_wire_records(wire: &[u8]) -> Vec<Vec<u8>> {
        let mut records = Vec::new();
        let mut rest = wire;
        while !rest.is_empty() {
            let body_len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
            let record_len = 5 + body_len;
            records.push(
                rest.get(..record_len)
                    .expect("wire bytes must hold a whole record")
                    .to_vec(),
            );
            rest = &rest[record_len..];
        }
        records
    }
    /// A deterministic byte pattern that differs between test inputs.
    fn patterned(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|index| seed.wrapping_add((index % 251) as u8))
            .collect()
    }

    /// A destination replaying input through bounded reads, counting read calls.
    struct ReplaySource {
        input: Vec<u8>,
        position: usize,
        chunk: usize,
        reads: usize,
    }

    impl ReplaySource {
        fn new(input: Vec<u8>, chunk: usize) -> Self {
            Self {
                input,
                position: 0,
                chunk,
                reads: 0,
            }
        }
    }

    impl AsyncRead for ReplaySource {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.reads += 1;
            let available = self.input.len().saturating_sub(self.position);
            let length = available.min(output.remaining()).min(self.chunk);
            output.put_slice(
                self.input
                    .get(self.position..self.position + length)
                    .expect("replay window must exist"),
            );
            self.position += length;
            Poll::Ready(Ok(()))
        }
    }

    impl VectoredRead for ReplaySource {
        /// Fills the buffers in order, bounded by one chunk like a socket read.
        async fn read_vectored<'buf>(
            &'buf mut self,
            buffers: &'buf mut [io::IoSliceMut<'buf>],
        ) -> io::Result<usize> {
            self.reads += 1;
            let mut budget = self.chunk;
            let mut total = 0;
            for buffer in buffers.iter_mut() {
                let available = self.input.len().saturating_sub(self.position);
                let length = available.min(buffer.len()).min(budget);
                if length > 0 {
                    buffer[..length].copy_from_slice(
                        self.input
                            .get(self.position..self.position + length)
                            .expect("replay window must exist"),
                    );
                    self.position += length;
                    budget -= length;
                    total += length;
                }
                if length < buffer.len() {
                    break;
                }
            }
            Ok(total)
        }
    }

    /// A client-side sink capturing wire bytes and counting write calls.
    #[derive(Clone, Default)]
    struct RecordingSink {
        output: Arc<Mutex<Vec<u8>>>,
        writes: Arc<AtomicUsize>,
        request_after_first_write: Arc<Mutex<Option<Arc<KeyUpdateCoordination>>>>,
    }

    impl RecordingSink {
        fn wire(&self) -> std::sync::MutexGuard<'_, Vec<u8>> {
            self.output
                .lock()
                .expect("sink output must not be poisoned")
        }

        fn writes(&self) -> usize {
            self.writes.load(Ordering::Relaxed)
        }

        fn request_key_update_after_first_write(&self, coordination: Arc<KeyUpdateCoordination>) {
            *self
                .request_after_first_write
                .lock()
                .expect("request trigger must not be poisoned") = Some(coordination);
        }
    }

    impl AsyncRead for RecordingSink {
        fn poll_read(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for RecordingSink {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            let write_index = self.writes.fetch_add(1, Ordering::Relaxed);
            self.output
                .lock()
                .expect("sink output must not be poisoned")
                .extend_from_slice(buffer);
            if write_index == 0
                && let Some(coordination) = self
                    .request_after_first_write
                    .lock()
                    .expect("request trigger must not be poisoned")
                    .take()
            {
                coordination
                    .response_observed
                    .store(true, Ordering::Release);
            }
            Poll::Ready(Ok(buffer.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Clone)]
    struct BlockingSink {
        output: Arc<Mutex<Vec<u8>>>,
        entered: Arc<AtomicBool>,
        released: Arc<AtomicBool>,
        waker: Arc<AtomicWaker>,
    }

    impl BlockingSink {
        fn new() -> Self {
            Self {
                output: Arc::new(Mutex::new(Vec::new())),
                entered: Arc::new(AtomicBool::new(false)),
                released: Arc::new(AtomicBool::new(false)),
                waker: Arc::new(AtomicWaker::new()),
            }
        }

        fn release(&self) {
            self.released.store(true, Ordering::Release);
            self.waker.wake();
        }

        fn wire(&self) -> std::sync::MutexGuard<'_, Vec<u8>> {
            self.output
                .lock()
                .expect("blocking sink output must not be poisoned")
        }
    }

    impl AsyncWrite for BlockingSink {
        fn poll_write(
            self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.entered.store(true, Ordering::Release);
            if !self.released.load(Ordering::Acquire) {
                self.waker.register(context.waker());
                if !self.released.load(Ordering::Acquire) {
                    return Poll::Pending;
                }
            }
            self.output
                .lock()
                .expect("blocking sink output must not be poisoned")
                .extend_from_slice(buffer);
            Poll::Ready(Ok(buffer.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn requested_update_does_not_block_reader_behind_an_in_flight_record() {
        let (established, mut client_write, mut client_read) = key_update_states();
        let request = [24, 0, 0, 1, KEY_UPDATE_REQUESTED];
        let mut input = seal(&mut client_write, ContentType::Handshake, &request);
        client_write
            .update_traffic_secret()
            .expect("client write secret must update");
        input.extend_from_slice(&seal(
            &mut client_write,
            ContentType::ApplicationData,
            b"request body",
        ));
        let source = CountingTransport {
            input,
            position: 0,
            chunk: usize::MAX,
            reads: Arc::new(AtomicUsize::new(0)),
        };
        let sink = BlockingSink::new();
        let (mut reader, mut writer) =
            resume_application_halves(source, Vec::new(), sink.clone(), established, false);
        let coordination = writer.key_update_coordination.clone();

        let mut first_write = Box::pin(writer.write_application(b"first reply", TIMEOUT));
        poll_fn(|context| {
            assert!(first_write.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
        assert!(sink.entered.load(Ordering::Acquire));

        let control = reader
            .read_application(TIMEOUT)
            .await
            .expect("requested KeyUpdate must authenticate while output is blocked");
        assert!(control.is_empty());
        assert!(coordination.response_observed.load(Ordering::Acquire));
        assert!(!coordination.response_pending.load(Ordering::Acquire));
        let request_body = reader
            .read_application(TIMEOUT)
            .await
            .expect("buffered application data must remain readable");
        assert_eq!(request_body.plaintext(), b"request body");

        sink.release();
        first_write
            .as_mut()
            .await
            .expect("the in-flight application record must finish");
        drop(first_write);
        writer
            .write_application(b"second reply", TIMEOUT)
            .await
            .expect("the later application record must follow the KeyUpdate response");
        assert!(!coordination.response_observed.load(Ordering::Acquire));
        assert!(!coordination.response_pending.load(Ordering::Acquire));

        let records = {
            let wire = sink.wire();
            split_wire_records(&wire)
        };
        assert_eq!(records.len(), 3);

        let mut first = records[0].clone();
        let opened = client_read
            .open_in_place(&mut first)
            .expect("in-flight application record must use the old key");
        assert_eq!(opened.content_type(), ContentType::ApplicationData);
        assert_eq!(opened.plaintext(), b"first reply");

        let mut update = records[1].clone();
        let opened = client_read
            .open_in_place(&mut update)
            .expect("KeyUpdate must precede the later application record");
        assert_eq!(opened.content_type(), ContentType::Handshake);
        assert_eq!(opened.plaintext(), KEY_UPDATE_RESPONSE);
        client_read
            .update_traffic_secret()
            .expect("client read secret must update");

        let mut second = records[2].clone();
        let opened = client_read
            .open_in_place(&mut second)
            .expect("later application record must use the next key");
        assert_eq!(opened.content_type(), ContentType::ApplicationData);
        assert_eq!(opened.plaintext(), b"second reply");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn multi_record_write_checks_for_a_request_between_chunks() {
        let (established, _client_write, mut client_read) = key_update_states();
        let sink = RecordingSink::default();
        let application = TlsApplicationIo::new(sink.clone(), established);
        let (_reader, mut writer) = application.into_split();
        sink.request_key_update_after_first_write(writer.key_update_coordination.clone());
        let plaintext = patterned(0x42, 2 * MAX_PLAINTEXT_LEN);

        let stats = writer
            .write_application(&plaintext, TIMEOUT)
            .await
            .expect("multi-record write must succeed");
        assert_eq!(stats.records(), 2);
        let records = {
            let wire = sink.wire();
            split_wire_records(&wire)
        };
        assert_eq!(records.len(), 3);

        let mut first = records[0].clone();
        let opened = client_read
            .open_in_place(&mut first)
            .expect("first application record must use the old key");
        assert_eq!(opened.content_type(), ContentType::ApplicationData);
        assert_eq!(opened.plaintext(), &plaintext[..MAX_PLAINTEXT_LEN]);

        let mut response = records[1].clone();
        let opened = client_read
            .open_in_place(&mut response)
            .expect("KeyUpdate response must follow the first chunk");
        assert_eq!(opened.content_type(), ContentType::Handshake);
        assert_eq!(opened.plaintext(), KEY_UPDATE_RESPONSE);
        client_read
            .update_traffic_secret()
            .expect("client read secret must update");

        let mut second = records[2].clone();
        let opened = client_read
            .open_in_place(&mut second)
            .expect("second application record must use the next key");
        assert_eq!(opened.content_type(), ContentType::ApplicationData);
        assert_eq!(opened.plaintext(), &plaintext[MAX_PLAINTEXT_LEN..]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn batched_write_uses_the_final_old_key_record_for_key_update() {
        const AES_GCM_RECORD_LIMIT: u64 = 1 << 24;

        let suite = CipherSuite::Aes128GcmSha256;
        let schedule = schedule(suite);
        let transcript = suite.hash().digest(b"server finished transcript");
        let (server_client_secret, server_server_secret) = schedule
            .application_traffic_secrets(&transcript)
            .expect("server application secrets must derive")
            .into_parts();
        let (_client_write_secret, client_read_secret) = schedule
            .application_traffic_secrets(&transcript)
            .expect("client application secrets must derive")
            .into_parts();
        let server_client_records =
            Tls13RecordLayer::from_traffic_secret(suite, server_client_secret)
                .expect("server read records must initialize");
        let server_server_state =
            ExportedRecordState::from_parts(suite, server_server_secret, AES_GCM_RECORD_LIMIT - 2)
                .expect("server boundary state must initialize");
        let server_server_records = Tls13RecordLayer::from_exported_state(server_server_state)
            .expect("server boundary records must initialize");
        let client_read_state =
            ExportedRecordState::from_parts(suite, client_read_secret, AES_GCM_RECORD_LIMIT - 2)
                .expect("client boundary state must initialize");
        let mut client_read = Tls13RecordLayer::from_exported_state(client_read_state)
            .expect("client boundary records must initialize");
        let established =
            EstablishedTls::from_test_records(suite, server_client_records, server_server_records);
        let sink = RecordingSink::default();
        let application = TlsApplicationIo::new(sink.clone(), established);
        let (_reader, mut writer) = application.into_split();
        grow_batched_record_storage(&mut writer.write_record)
            .expect("batched record storage must grow");
        let plaintext = patterned(0x6a, 2 * MAX_PLAINTEXT_LEN);
        let mut source = ReplaySource::new(plaintext.clone(), usize::MAX);

        let read = writer
            .write_application_read_from_batched(&mut source, TIMEOUT)
            .await
            .expect("boundary batch must be written");
        assert_eq!(read, plaintext.len());
        let records = {
            let wire = sink.wire();
            split_wire_records(&wire)
        };
        assert_eq!(records.len(), 3);

        let mut first = records[0].clone();
        let opened = client_read
            .open_in_place(&mut first)
            .expect("first application record must use the penultimate sequence");
        assert_eq!(opened.content_type(), ContentType::ApplicationData);
        assert_eq!(opened.plaintext(), &plaintext[..MAX_PLAINTEXT_LEN]);

        let mut update = records[1].clone();
        let opened = client_read
            .open_in_place(&mut update)
            .expect("KeyUpdate must use the final safe old-key sequence");
        assert_eq!(opened.content_type(), ContentType::Handshake);
        assert_eq!(opened.plaintext(), KEY_UPDATE_RESPONSE);
        client_read
            .update_traffic_secret()
            .expect("client read secret must update");

        let mut second = records[2].clone();
        let opened = client_read
            .open_in_place(&mut second)
            .expect("remaining batch data must use the next key");
        assert_eq!(opened.content_type(), ContentType::ApplicationData);
        assert_eq!(opened.plaintext(), &plaintext[MAX_PLAINTEXT_LEN..]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn batched_downlink_seals_four_full_records_with_one_read_and_one_write() {
        let (established, mut client_read) = batched_writer_states();
        let sink = RecordingSink::default();
        let application = TlsApplicationIo::new(sink.clone(), established);
        let (_reader, mut writer) = application.into_split();

        // Warm-up: one completely-full record read is the bulk-flow evidence
        // that grows the batched buffer.
        let warm = patterned(0x11, MAX_PLAINTEXT_LEN);
        let mut source = ReplaySource::new(warm.clone(), usize::MAX);
        let read = writer
            .write_application_read_from_batched(&mut source, TIMEOUT)
            .await
            .expect("warm-up record must be relayed");
        assert_eq!(read, MAX_PLAINTEXT_LEN);
        assert_eq!(source.reads, 1);
        assert_eq!(sink.writes(), 1);
        assert!(writer.write_record.capacity() >= BATCHED_WIRE_CAPACITY);

        // The next call must move four maximal records with one readv + one write.
        let batch = patterned(0x77, BATCHED_SLOT_COUNT * MAX_PLAINTEXT_LEN);
        let mut source = ReplaySource::new(batch.clone(), usize::MAX);
        let read = writer
            .write_application_read_from_batched(&mut source, TIMEOUT)
            .await
            .expect("batch must be relayed");
        assert_eq!(read, BATCHED_SLOT_COUNT * MAX_PLAINTEXT_LEN);
        assert_eq!(source.reads, 1, "one readv must fill the whole batch");
        assert_eq!(sink.writes(), 2, "the batch must add exactly one write");
        assert_eq!(
            writer.records.records_used(),
            1 + BATCHED_SLOT_COUNT as u64,
            "the sequence must advance once per sealed record"
        );

        let plaintexts = {
            let wire = sink.wire();
            open_wire_records(&mut client_read, &wire)
        };
        assert_eq!(plaintexts.len(), 1 + BATCHED_SLOT_COUNT);
        assert_eq!(plaintexts[0], warm);
        for record in &plaintexts[1..] {
            assert_eq!(record.len(), MAX_PLAINTEXT_LEN);
        }
        assert_eq!(plaintexts[1..].concat(), batch);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn batched_downlink_seals_a_partial_last_record() {
        let (established, mut client_read) = batched_writer_states();
        let sink = RecordingSink::default();
        let application = TlsApplicationIo::new(sink.clone(), established);
        let (_reader, mut writer) = application.into_split();

        let warm = patterned(0x22, MAX_PLAINTEXT_LEN);
        let mut source = ReplaySource::new(warm, usize::MAX);
        writer
            .write_application_read_from_batched(&mut source, TIMEOUT)
            .await
            .expect("warm-up record must be relayed");

        let batch = patterned(0x55, 2 * MAX_PLAINTEXT_LEN + 100);
        let mut source = ReplaySource::new(batch.clone(), usize::MAX);
        let read = writer
            .write_application_read_from_batched(&mut source, TIMEOUT)
            .await
            .expect("batch must be relayed");
        assert_eq!(read, 2 * MAX_PLAINTEXT_LEN + 100);
        assert_eq!(source.reads, 1);
        assert_eq!(sink.writes(), 2);

        let plaintexts = {
            let wire = sink.wire();
            open_wire_records(&mut client_read, &wire)
        };
        assert_eq!(plaintexts.len(), 4);
        assert_eq!(plaintexts[1].len(), MAX_PLAINTEXT_LEN);
        assert_eq!(plaintexts[2].len(), MAX_PLAINTEXT_LEN);
        assert_eq!(plaintexts[3].len(), 100);
        assert_eq!(plaintexts[1..].concat(), batch);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn short_read_seals_a_one_byte_record_without_growing() {
        let (established, mut client_read) = batched_writer_states();
        let sink = RecordingSink::default();
        let application = TlsApplicationIo::new(sink.clone(), established);
        let (_reader, mut writer) = application.into_split();

        let mut source = ReplaySource::new(vec![0x7e], usize::MAX);
        let read = writer
            .write_application_read_from_batched(&mut source, TIMEOUT)
            .await
            .expect("short read must be relayed");
        assert_eq!(read, 1);
        assert_eq!(sink.writes(), 1);
        assert_eq!(
            writer.write_record.capacity(),
            RECORD_SLOT_WIRE_CAPACITY,
            "a short read must not grow the batched buffer"
        );

        let plaintexts = {
            let wire = sink.wire();
            open_wire_records(&mut client_read, &wire)
        };
        assert_eq!(plaintexts, [vec![0x7e]]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn eof_before_any_byte_writes_nothing() {
        let (established, _client_read) = batched_writer_states();
        let sink = RecordingSink::default();
        let application = TlsApplicationIo::new(sink.clone(), established);
        let (_reader, mut writer) = application.into_split();

        let mut source = ReplaySource::new(Vec::new(), usize::MAX);
        let read = writer
            .write_application_read_from_batched(&mut source, TIMEOUT)
            .await
            .expect("EOF must be a clean zero");
        assert_eq!(read, 0);
        assert_eq!(sink.writes(), 0, "EOF must not write a record");
        assert!(sink.wire().is_empty());
        assert_eq!(writer.records.records_used(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn eof_after_a_full_record_flushes_then_reports_eof() {
        let (established, mut client_read) = batched_writer_states();
        let sink = RecordingSink::default();
        let application = TlsApplicationIo::new(sink.clone(), established);
        let (_reader, mut writer) = application.into_split();

        let input = patterned(0x99, MAX_PLAINTEXT_LEN + 500);
        let mut source = ReplaySource::new(input.clone(), usize::MAX);

        let read = writer
            .write_application_read_from_batched(&mut source, TIMEOUT)
            .await
            .expect("full record must be relayed");
        assert_eq!(read, MAX_PLAINTEXT_LEN);

        // The batched read now sees the 500-byte tail ahead of the EOF and
        // must seal and write it like today's variable-length path.
        let read = writer
            .write_application_read_from_batched(&mut source, TIMEOUT)
            .await
            .expect("the partial tail must be relayed");
        assert_eq!(read, 500);
        assert_eq!(sink.writes(), 2);

        // Only the following call observes EOF: zero bytes, nothing written.
        let read = writer
            .write_application_read_from_batched(&mut source, TIMEOUT)
            .await
            .expect("EOF must be a clean zero");
        assert_eq!(read, 0);
        assert_eq!(sink.writes(), 2, "EOF must not write a record");
        assert_eq!(writer.records.records_used(), 2);

        let plaintexts = {
            let wire = sink.wire();
            open_wire_records(&mut client_read, &wire)
        };
        assert_eq!(plaintexts.concat(), input);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn batched_buffer_grows_only_after_a_completely_full_read() {
        let (established, _client_read) = batched_writer_states();
        let sink = RecordingSink::default();
        let application = TlsApplicationIo::new(sink.clone(), established);
        let (_reader, mut writer) = application.into_split();

        // Small flows stay on the single-record buffer forever.
        for _ in 0..3 {
            let mut source = ReplaySource::new(patterned(0x33, 100), usize::MAX);
            let read = writer
                .write_application_read_from_batched(&mut source, TIMEOUT)
                .await
                .expect("small read must be relayed");
            assert_eq!(read, 100);
            assert_eq!(
                writer.write_record.capacity(),
                RECORD_SLOT_WIRE_CAPACITY,
                "small flows must not grow the batched buffer"
            );
        }

        // One completely-full record read is the bulk-flow evidence.
        let mut source = ReplaySource::new(patterned(0x44, MAX_PLAINTEXT_LEN), usize::MAX);
        let read = writer
            .write_application_read_from_batched(&mut source, TIMEOUT)
            .await
            .expect("full record must be relayed");
        assert_eq!(read, MAX_PLAINTEXT_LEN);
        assert!(writer.write_record.capacity() >= BATCHED_WIRE_CAPACITY);
        let grown = writer.record_storage_address();

        // The buffer never shrinks back, even for small reads afterwards.
        let mut source = ReplaySource::new(patterned(0x66, 100), usize::MAX);
        let read = writer
            .write_application_read_from_batched(&mut source, TIMEOUT)
            .await
            .expect("small read must be relayed");
        assert_eq!(read, 100);
        assert!(writer.write_record.capacity() >= BATCHED_WIRE_CAPACITY);
        assert_eq!(
            writer.record_storage_address(),
            grown,
            "the grown buffer must not move or shrink"
        );
    }
}
