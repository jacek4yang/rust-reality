//! Application-data TLS I/O over an established REALITY session.
//!
//! [`TlsApplicationIo`] splits into reader/writer halves, handles close_notify
//! and KeyUpdate, and exposes the byte-oriented API Vision relays consume.
//! No handshake cryptography lives here; it only drives the record layer.

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
    /// A response obligation transferred through Handoff.
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

    fn take_response(&self) -> bool {
        let pending = self.response_pending.load(Ordering::Acquire)
            && self.response_pending.swap(false, Ordering::AcqRel);
        let observed = self.response_observed.load(Ordering::Acquire)
            && self.response_observed.swap(false, Ordering::AcqRel);
        pending | observed
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

/// Sealing consumes a nonce before socket I/O. Only a complete write may leave
/// the direction usable, including when a future is dropped without an error.
struct SealedWrite<'records> {
    records: &'records mut super::Tls13RecordLayer,
    armed: bool,
}

impl<'records> SealedWrite<'records> {
    fn new(records: &'records mut super::Tls13RecordLayer) -> Result<Self, TlsApplicationIoError> {
        records
            .ensure_write_ready()
            .map_err(TlsApplicationIoError::Record)?;
        Ok(Self {
            records,
            armed: false,
        })
    }

    fn arm(&mut self) {
        self.armed = true;
    }

    fn complete(mut self) {
        self.armed = false;
    }
}

impl Drop for SealedWrite<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.records.fail_write();
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
///
/// Once sealing begins, cancellation, partial-write failure, or timeout
/// permanently invalidates this direction. Later writes and Handoff record
/// exports fail without emitting additional ciphertext.
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
    /// Successful writes leave an exact record boundary. An interrupted sealed
    /// write permanently invalidates the returned record layer, so its export
    /// and subsequent use fail closed. The final flag preserves an outstanding
    /// peer request for a server KeyUpdate across a valid ownership transfer.
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
    application_halves(
        reader,
        pending_ciphertext,
        writer,
        client_records,
        server_records,
        key_update_response_pending,
        SOCKET_BUFFER_CAPACITY,
    )
}

/// Attaches owned traffic directions without assuming which peer is the server.
pub(crate) fn application_halves<R, W>(
    reader: R,
    pending_ciphertext: Vec<u8>,
    writer: W,
    read_records: super::Tls13RecordLayer,
    write_records: super::Tls13RecordLayer,
    key_update_response_pending: bool,
    initial_read_capacity: usize,
) -> (TlsApplicationReader<R>, TlsApplicationWriter<W>) {
    let buffered_end = pending_ciphertext.len();
    let mut socket_buffer = pending_ciphertext;
    // Best-effort headroom for the first refill; the grow-on-demand refill
    // policy stays correct even when this reservation fails.
    let _ignored = socket_buffer.try_reserve(initial_read_capacity);
    let key_update_coordination = Arc::new(KeyUpdateCoordination::new(key_update_response_pending));
    (
        TlsApplicationReader {
            io: reader,
            records: read_records,
            socket_buffer,
            buffered_start: 0,
            buffered_end,
            idle: IdleDeadline::new(),
            key_update: KeyUpdateReassembly::new(),
            key_update_coordination: key_update_coordination.clone(),
        },
        TlsApplicationWriter {
            io: writer,
            records: write_records,
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
    /// An interrupted sealed write permanently invalidates the write direction,
    /// including when its future is canceled. Subsequent writes fail closed.
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
            &self.key_update_coordination,
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
            // A client starts with a smaller idle-session window. Its first
            // large record promotes storage to the normal batching capacity.
            // Server readers already have that capacity; validated records
            // never require growth beyond it.
            let growth = SOCKET_BUFFER_CAPACITY.saturating_sub(self.socket_buffer.len());
            if growth == 0 {
                return Err(TlsApplicationIoError::Record(
                    Tls13RecordError::InvalidLength,
                ));
            }
            self.socket_buffer
                .try_reserve_exact(growth)
                .map_err(|_| TlsApplicationIoError::Record(Tls13RecordError::BufferAllocation))?;
            self.socket_buffer.resize(SOCKET_BUFFER_CAPACITY, 0);
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
        } else if self.socket_buffer.is_empty() {
            self.socket_buffer.resize(self.socket_buffer.capacity(), 0);
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
        self.records
            .ensure_write_ready()
            .map_err(TlsApplicationIoError::Record)?;
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
        let mut write = SealedWrite::new(&mut self.records)?;
        let record_len = write
            .records
            .seal_filled(ContentType::ApplicationData, read, &mut self.write_record)
            .map_err(TlsApplicationIoError::Record)?;
        write.arm();
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
        write.complete();
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
        self.records
            .ensure_write_ready()
            .map_err(TlsApplicationIoError::Record)?;
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
        self.write_filled_batch(read, timeout).await?;
        Ok(read)
    }

    /// Seals the filled prefix of the existing record-slot layout, preserving
    /// record boundaries and flushing before any intervening KeyUpdate.
    async fn write_filled_batch(
        &mut self,
        read: usize,
        timeout: Duration,
    ) -> Result<(), TlsApplicationIoError> {
        let mut write = SealedWrite::new(&mut self.records)?;
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
                || write.records.needs_key_update()
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
                    write.records,
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
            let record_len = write
                .records
                .seal_filled(ContentType::ApplicationData, filled, slot_slice)
                .map_err(TlsApplicationIoError::Record)?;
            write.arm();
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
        write.complete();
        Ok(())
    }

    /// Transfers idle write storage to the connection's upload reader.
    /// The caller returns it for sealing through `write_filled_storage`.
    pub(crate) fn take_write_storage(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.write_record)
    }

    /// Seals one or two already assembled record slots in caller-owned storage.
    /// Swapping ownership avoids retaining a second plaintext/ciphertext buffer.
    /// Cancellation retains storage in this writer and the canonical sealed-write
    /// guard invalidates the write direction. Successful completion returns it.
    pub(crate) async fn write_filled_storage(
        &mut self,
        storage: &mut Vec<u8>,
        plaintext_len: usize,
        timeout: Duration,
    ) -> Result<(), TlsApplicationIoError> {
        let slots = plaintext_len.div_ceil(MAX_PLAINTEXT_LEN);
        if slots == 0
            || slots > 2
            || storage.len() < slots * super::record::RECORD_SLOT_WIRE_CAPACITY
        {
            return Err(TlsApplicationIoError::Record(
                Tls13RecordError::InvalidLength,
            ));
        }
        self.records
            .ensure_write_ready()
            .map_err(TlsApplicationIoError::Record)?;
        self.idle
            .reset(timeout)
            .map_err(|_| TlsApplicationIoError::Timeout)?;
        std::mem::swap(storage, &mut self.write_record);
        let result = self.write_filled_batch(plaintext_len, timeout).await;
        std::mem::swap(storage, &mut self.write_record);
        result
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
        let mut write = SealedWrite::new(&mut self.records)?;
        write
            .records
            .seal_assembled(
                ContentType::ApplicationData,
                plaintext_len,
                0,
                &mut self.write_record,
                assemble,
            )
            .map_err(TlsApplicationIoError::Record)?;
        write.arm();
        let record = self.write_record.as_slice();
        self.idle
            .write_all(&mut self.io, record)
            .await
            .map_err(idle_failure)?;
        write.complete();
        Ok(())
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
            self.key_update_coordination.as_ref(),
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
    records
        .ensure_write_ready()
        .map_err(TlsApplicationIoError::Record)?;
    let requested = key_update_coordination
        .response_pending
        .load(Ordering::Acquire)
        || key_update_coordination
            .response_observed
            .load(Ordering::Acquire);
    if !requested && !records.needs_key_update() {
        return Ok(false);
    }
    let mut write = SealedWrite::new(records)?;

    idle.reset(timeout)
        .map_err(|_| TlsApplicationIoError::Timeout)?;
    let mut response = [0_u8; KEY_UPDATE_RECORD_WIRE_LEN];
    response
        .get_mut(TLS_RECORD_HEADER_LEN..TLS_RECORD_HEADER_LEN + KEY_UPDATE_MESSAGE_LEN)
        .ok_or(TlsApplicationIoError::Record(
            Tls13RecordError::InvalidLength,
        ))?
        .copy_from_slice(&KEY_UPDATE_RESPONSE);
    let record_len = write
        .records
        .seal_filled(
            ContentType::Handshake,
            KEY_UPDATE_MESSAGE_LEN,
            &mut response,
        )
        .map_err(TlsApplicationIoError::Record)?;
    write.arm();
    key_update_coordination.take_response();
    let record = response
        .get(..record_len)
        .ok_or(TlsApplicationIoError::Record(
            Tls13RecordError::InvalidLength,
        ))?;
    idle.write_all(io, record).await.map_err(idle_failure)?;
    write
        .records
        .update_traffic_secret()
        .map_err(TlsApplicationIoError::Record)?;
    write.complete();
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
    records
        .ensure_write_ready()
        .map_err(TlsApplicationIoError::Record)?;
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
    key_update_coordination: &KeyUpdateCoordination,
    timeout: Duration,
) -> Result<(), TlsApplicationIoError>
where
    W: AsyncWrite + Unpin,
{
    write_key_update_if_needed(io, records, idle, key_update_coordination, timeout).await?;
    let mut write = SealedWrite::new(records)?;
    idle.reset(timeout)
        .map_err(|_| TlsApplicationIoError::Timeout)?;
    write_content(
        io,
        write.records,
        write_record,
        idle,
        ContentType::Alert,
        &[ALERT_LEVEL_WARNING, ALERT_CLOSE_NOTIFY],
    )
    .await?;
    write.arm();
    idle.shutdown(io).await.map_err(idle_failure)?;
    write.complete();
    Ok(())
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
    let mut write = SealedWrite::new(records)?;
    write
        .records
        .seal_into(content_type, plaintext, 0, write_record)
        .map_err(TlsApplicationIoError::Record)?;
    write.arm();
    idle.write_all(io, write_record)
        .await
        .map_err(idle_failure)?;
    write.complete();
    Ok(())
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
mod tests;
