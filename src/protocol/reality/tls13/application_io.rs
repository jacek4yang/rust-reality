use std::{error::Error, fmt, io, time::Duration};

use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf, split};

use super::{
    ContentType, EstablishedTls, IdleDeadline, IdleError, MAX_PLAINTEXT_LEN,
    MAX_TLS_RECORD_WIRE_LEN, MAX_TLS13_CIPHERTEXT_LEN, TLS_RECORD_HEADER_LEN, Tls13RecordError,
    TlsRecordReadError, TlsRecordReadErrorKind, buffered_failure, read_tls_record_into,
    record_storage,
};

const ALERT_LEVEL_WARNING: u8 = 1;
const ALERT_CLOSE_NOTIFY: u8 = 0;

/// Capacity of the connection-owned socket buffer behind a split reader.
///
/// One refill moves up to this many bytes per socket read — four maximum-sized
/// records, matching the 64 KiB read window of the reference implementation —
/// so a pipelined peer costs one syscall per refill instead of one header read
/// plus one body read per record. The buffer is allocated and zero-filled once
/// and then treated as fully initialized storage; only the start/end cursors
/// move afterwards.
const SOCKET_BUFFER_CAPACITY: usize = 4 * MAX_TLS_RECORD_WIRE_LEN;

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
    read_record: Vec<u8>,
    write_record: Vec<u8>,
    idle: IdleDeadline,
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
}

/// Server-to-client TLS application records with one reusable ciphertext buffer.
pub struct TlsApplicationWriter<W> {
    io: W,
    records: super::Tls13RecordLayer,
    write_record: Vec<u8>,
    idle: IdleDeadline,
}

impl<R> TlsApplicationReader<R> {
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
    /// Consumes the writer at a session-handoff boundary.
    ///
    /// Writes are record-synchronous, so the writer is always at a record
    /// boundary between awaited calls; the returned record layer carries the
    /// exact server-direction sequence.
    #[must_use]
    pub fn into_handoff_parts(self) -> (W, super::Tls13RecordLayer) {
        (self.io, self.records)
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
/// sequences at the boundary.
#[must_use]
pub fn resume_application_halves<R, W>(
    reader: R,
    pending_ciphertext: Vec<u8>,
    writer: W,
    tls: EstablishedTls,
) -> (TlsApplicationReader<R>, TlsApplicationWriter<W>) {
    let (client_records, server_records) = tls.into_record_layers();
    let buffered_end = pending_ciphertext.len();
    let mut socket_buffer = pending_ciphertext;
    // Best-effort headroom for the first refill; the grow-on-demand refill
    // policy stays correct even when this reservation fails.
    let _ignored = socket_buffer.try_reserve(SOCKET_BUFFER_CAPACITY);
    (
        TlsApplicationReader {
            io: reader,
            records: client_records,
            socket_buffer,
            buffered_start: 0,
            buffered_end,
            idle: IdleDeadline::new(),
        },
        TlsApplicationWriter {
            io: writer,
            records: server_records,
            write_record: Vec::new(),
            idle: IdleDeadline::new(),
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
        (
            TlsApplicationReader {
                io: reader,
                records: client_records,
                socket_buffer: Vec::new(),
                buffered_start: 0,
                buffered_end: 0,
                idle: IdleDeadline::new(),
            },
            TlsApplicationWriter {
                io: writer,
                records: server_records,
                write_record: self.write_record,
                idle: IdleDeadline::new(),
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
        (
            TlsApplicationReader {
                io: reader,
                records: client_records,
                socket_buffer: Vec::new(),
                buffered_start: 0,
                buffered_end: 0,
                idle: IdleDeadline::new(),
            },
            TlsApplicationWriter {
                io: writer,
                records: server_records,
                write_record: self.write_record,
                idle: IdleDeadline::new(),
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
    /// Returns the raw client descriptor for abort-path socket options.
    #[must_use]
    pub fn fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd as _;
        self.io.as_ref().as_raw_fd()
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
        let record = self.socket_buffer.get_mut(record_start..record_end).ok_or(
            TlsApplicationIoError::Record(Tls13RecordError::InvalidLength),
        )?;
        let opened = self
            .records
            .open_in_place(record)
            .map_err(TlsApplicationIoError::Record)?;
        let content_type = opened.content_type();
        match content_type {
            ContentType::ApplicationData => Ok(ApplicationRecord {
                plaintext: opened.plaintext(),
            }),
            ContentType::Alert => {
                let [level, description] = <[u8; 2]>::try_from(opened.plaintext())
                    .map_err(|_| TlsApplicationIoError::InvalidAlert)?;
                Err(TlsApplicationIoError::PeerAlert { level, description })
            }
            ContentType::ChangeCipherSpec | ContentType::Handshake => {
                Err(TlsApplicationIoError::UnexpectedContentType(content_type))
            }
        }
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
    /// Returns the raw client descriptor for abort-path socket options.
    #[must_use]
    pub fn fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd as _;
        self.io.as_ref().as_raw_fd()
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
                .guard(reader.read_vectored(&mut buffers))
                .await
                .map_err(idle_failure)?
        };
        if read == 0 {
            return Ok(0);
        }
        let mut sealed_len = 0_usize;
        let mut remaining = read;
        for slot in 0..super::record::BATCHED_SLOT_COUNT {
            if remaining == 0 {
                break;
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
        let wire = self
            .write_record
            .get(..sealed_len)
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
) -> Result<ApplicationRecord<'record>, TlsApplicationIoError>
where
    R: AsyncRead + Unpin,
{
    ensure_record_storage(wire)?;
    let length = read_tls_record_into(io, wire, idle)
        .await
        .map_err(TlsApplicationIoError::Read)?;
    let record = wire.get_mut(..length).ok_or(TlsApplicationIoError::Record(
        Tls13RecordError::InvalidLength,
    ))?;
    let opened = records
        .open_in_place(record)
        .map_err(TlsApplicationIoError::Record)?;
    let content_type = opened.content_type();
    match content_type {
        ContentType::ApplicationData => Ok(ApplicationRecord {
            plaintext: opened.plaintext(),
        }),
        ContentType::Alert => {
            let [level, description] = <[u8; 2]>::try_from(opened.plaintext())
                .map_err(|_| TlsApplicationIoError::InvalidAlert)?;
            Err(TlsApplicationIoError::PeerAlert { level, description })
        }
        ContentType::ChangeCipherSpec | ContentType::Handshake => {
            Err(TlsApplicationIoError::UnexpectedContentType(content_type))
        }
    }
}

/// Reserves the connection's single record buffer exactly once.
fn ensure_record_storage(wire: &mut Vec<u8>) -> Result<(), TlsApplicationIoError> {
    if wire.capacity() == 0 {
        *wire = record_storage()
            .map_err(|_| TlsApplicationIoError::Record(Tls13RecordError::BufferAllocation))?;
    }
    Ok(())
}

async fn write_application_data<W>(
    io: &mut W,
    records: &mut super::Tls13RecordLayer,
    write_record: &mut Vec<u8>,
    idle: &mut IdleDeadline,
    plaintext: &[u8],
    timeout: Duration,
) -> Result<ApplicationWriteStats, TlsApplicationIoError>
where
    W: AsyncWrite + Unpin,
{
    let mut record_count = 0_u64;
    for chunk in plaintext.chunks(MAX_PLAINTEXT_LEN) {
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
        io,
        pin::Pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
        time::Duration,
    };

    use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf, duplex};

    use super::{TlsApplicationIo, TlsApplicationIoError, VectoredRead};
    use crate::protocol::reality::tls13::record::{
        BATCHED_SLOT_COUNT, BATCHED_WIRE_CAPACITY, RECORD_SLOT_WIRE_CAPACITY,
    };
    use crate::protocol::reality::tls13::{
        CipherSuite, ContentType, EstablishedTls, MAX_PLAINTEXT_LEN, Tls13KeySchedule,
        Tls13RecordLayer, TlsRecordReadErrorKind, read_tls_record,
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

    /// Server-side TLS state plus the client's write record layer.
    fn buffered_reader_states() -> (EstablishedTls, Tls13RecordLayer) {
        let suite = CipherSuite::Aes128GcmSha256;
        let schedule = schedule(suite);
        let secrets = schedule
            .application_traffic_secrets(&suite.hash().digest(b"server finished transcript"))
            .expect("application secrets must derive");
        let layer = |secret| {
            Tls13RecordLayer::new(
                suite,
                schedule
                    .traffic_keys(secret)
                    .expect("traffic keys must derive"),
            )
            .expect("record layer must initialize")
        };
        (
            EstablishedTls::from_test_records(
                suite,
                layer(secrets.client()),
                layer(secrets.server()),
            ),
            layer(secrets.client()),
        )
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
        let suite = CipherSuite::Aes128GcmSha256;
        let schedule = schedule(suite);
        let secrets = schedule
            .application_traffic_secrets(&suite.hash().digest(b"server finished transcript"))
            .expect("application secrets must derive");
        let layer = |secret| {
            Tls13RecordLayer::new(
                suite,
                schedule
                    .traffic_keys(secret)
                    .expect("traffic keys must derive"),
            )
            .expect("record layer must initialize")
        };
        (
            EstablishedTls::from_test_records(
                suite,
                layer(secrets.client()),
                layer(secrets.server()),
            ),
            layer(secrets.server()),
        )
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
            self.writes.fetch_add(1, Ordering::Relaxed);
            self.output
                .lock()
                .expect("sink output must not be poisoned")
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
