//! Bounded reads of a cover target's ServerHello and full server flight.
//!
//! Captures the retained cover prefix and record-shape plan used to mirror
//! the target when building a REALITY flight. Prefix size is hard-capped so
//! fallback relay storage stays bounded.

use std::{error::Error, fmt, io, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt},
    net::TcpStream,
    time::{self, Instant},
};

use crate::protocol::reality::ClientHello;

use super::{MAX_TLS13_CIPHERTEXT_LEN, ServerHelloError, ServerHelloTemplate};

const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 20;
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 22;
const TLS_CONTENT_TYPE_APPLICATION_DATA: u8 = 23;
const TLS_LEGACY_RECORD_VERSION: [u8; 2] = [3, 3];
const MAX_TLS_PLAINTEXT_BYTES: usize = 16 * 1024;
const READ_SCRATCH_BYTES: usize = 4 * 1024;
const COALESCED_COVER_RECORD_THRESHOLD: usize = 512;
const NST_PROBE_SCRATCH_BYTES: usize = 512;

/// Upper bound on the retained cover prefix, in bytes.
///
/// Derivation: maximum ServerHello record (5 + [`MAX_TLS_PLAINTEXT_BYTES`]) +
/// compatibility CCS (6) + first positional record (at most
/// [`COALESCED_COVER_RECORD_THRESHOLD`]) + three maximum encrypted records
/// (3 × (5 + [`MAX_TLS13_CIPHERTEXT_LEN`])) + one buffered-refill over-read
/// (at most [`TLS_RECORD_HEADER_LEN`]) + one non-blocking NewSessionTicket
/// probe (at most [`NST_PROBE_SCRATCH_BYTES`]).
pub(crate) const MAX_RETAINED_COVER_PREFIX_LEN: usize = 66_642;

/// Socket operations needed by the cover-flight reader.
///
/// The fifth-record probe must be non-blocking. Keeping that operation on a
/// small internal trait makes the production path use `TcpStream::try_read`
/// while deterministic test readers can model buffered and delayed arrivals.
pub(crate) trait CoverFlightIo: AsyncRead + Unpin {
    fn try_read_now(&mut self, output: &mut [u8]) -> io::Result<usize>;
}

impl CoverFlightIo for TcpStream {
    fn try_read_now(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.try_read(output)
    }
}

/// Bounded cover-derived policy for the encrypted server handshake records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoverHandshakeRecordShape {
    /// The four generated messages share one record padded to the cover's wire length.
    Coalesced { wire_len: usize },
    /// The four generated messages use the cover's four positional outer lengths.
    ///
    /// Cover ciphertext does not reveal its inner message boundaries; the
    /// positional association is an intentionally bounded policy inference.
    PositionalRecords {
        wire_lens: [usize; 4],
        /// Wire length of a fifth NewSessionTicket record whose header the
        /// non-blocking probe observed; its body is never awaited.
        nst_wire_len: Option<usize>,
    },
}

/// Bounded cover-derived plan for the generated post-ServerHello flight.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CoverHandshakePlan {
    /// Emit the compatibility CCS only when the cover emitted a valid one.
    pub(crate) emit_ccs: bool,
    /// Cover-derived encrypted record shape.
    pub(crate) shape: CoverHandshakeRecordShape,
}

/// A validated target ServerHello and its exact plaintext TLS record.
#[derive(Debug)]
pub struct TargetServerHelloRead {
    template: ServerHelloTemplate,
    wire_record: Vec<u8>,
}

impl TargetServerHelloRead {
    /// Returns the validated target presentation template.
    #[must_use]
    pub const fn template(&self) -> &ServerHelloTemplate {
        &self.template
    }

    /// Returns the exact target bytes consumed from the cover connection.
    #[must_use]
    pub fn wire_record(&self) -> &[u8] {
        &self.wire_record
    }

    /// Separates validated target state from the exact consumed record.
    #[must_use]
    pub fn into_parts(self) -> (ServerHelloTemplate, Vec<u8>) {
        (self.template, self.wire_record)
    }
}

/// Validated target presentation plus its bounded post-ServerHello flight plan.
#[derive(Debug)]
pub(crate) struct TargetServerFlightRead {
    template: ServerHelloTemplate,
    plan: CoverHandshakePlan,
    wire_prefix: Vec<u8>,
}

impl TargetServerFlightRead {
    /// Separates the template, cover-derived plan, and exact consumed bytes.
    pub(crate) fn into_parts(self) -> (ServerHelloTemplate, CoverHandshakePlan, Vec<u8>) {
        (self.template, self.plan, self.wire_prefix)
    }
}

/// Category of a bounded target TLS server-flight read failure.
#[derive(Debug)]
pub enum TargetServerHelloReadErrorKind {
    /// The absolute read deadline elapsed.
    Timeout,
    /// The target closed before a complete record arrived.
    UnexpectedEof,
    /// Socket input failed.
    Io(io::Error),
    /// A declared record exceeded the applicable TLS limit or was empty.
    RecordTooLarge,
    /// The first target record was not a TLS 1.3 ServerHello record.
    UnexpectedRecord,
    /// The complete ServerHello was not compatible with the client offer.
    Invalid(ServerHelloError),
}

impl fmt::Display for TargetServerHelloReadErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => formatter.write_str("target TLS server-flight read timed out"),
            Self::UnexpectedEof => formatter.write_str("target closed during TLS server flight"),
            Self::Io(_) => formatter.write_str("target TLS server-flight socket read failed"),
            Self::RecordTooLarge => {
                formatter.write_str("target TLS server-flight record length is invalid")
            }
            Self::UnexpectedRecord => {
                formatter.write_str("target TLS server-flight record sequence is invalid")
            }
            Self::Invalid(source) => source.fmt(formatter),
        }
    }
}

impl Error for TargetServerHelloReadErrorKind {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(source) => Some(source),
            Self::Invalid(source) => Some(source),
            Self::Timeout | Self::UnexpectedEof | Self::RecordTooLarge | Self::UnexpectedRecord => {
                None
            }
        }
    }
}

/// A target read failure retaining every byte required for exact fallback.
#[derive(Debug)]
pub struct TargetServerHelloReadError {
    kind: TargetServerHelloReadErrorKind,
    wire_prefix: Vec<u8>,
}

impl TargetServerHelloReadError {
    /// Returns the failure category.
    #[must_use]
    pub const fn kind(&self) -> &TargetServerHelloReadErrorKind {
        &self.kind
    }

    /// Returns exactly the bytes already consumed from the target.
    #[must_use]
    pub fn fallback_prefix(&self) -> &[u8] {
        &self.wire_prefix
    }

    /// Separates the failure category and its exact consumed target prefix.
    #[must_use]
    pub fn into_parts(self) -> (TargetServerHelloReadErrorKind, Vec<u8>) {
        (self.kind, self.wire_prefix)
    }
}

impl fmt::Display for TargetServerHelloReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(formatter)
    }
}

impl Error for TargetServerHelloReadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.kind.source()
    }
}

/// Reads exactly one target ServerHello record under an absolute deadline.
///
/// The reader stops at the first record boundary. Both success and failure retain
/// the exact bytes consumed so an incompatible target can continue as byte-exact
/// fallback without reconnecting or discarding its response.
///
/// # Errors
///
/// Returns a byte-owning error for timeout, EOF, I/O, record framing, or strict
/// ServerHello compatibility failures.
pub async fn read_target_server_hello<R>(
    reader: &mut R,
    client: &ClientHello,
    timeout: Duration,
) -> Result<TargetServerHelloRead, TargetServerHelloReadError>
where
    R: AsyncRead + Unpin,
{
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return Err(failure(TargetServerHelloReadErrorKind::Timeout, Vec::new()));
    };
    read_target_server_hello_until(reader, client, deadline).await
}

async fn read_target_server_hello_until<R>(
    reader: &mut R,
    client: &ClientHello,
    deadline: Instant,
) -> Result<TargetServerHelloRead, TargetServerHelloReadError>
where
    R: AsyncRead + Unpin,
{
    let mut wire_record = Vec::with_capacity(512);
    if let Err(kind) =
        read_exact_to(reader, &mut wire_record, TLS_RECORD_HEADER_LEN, deadline).await
    {
        return Err(failure(kind, wire_record));
    }

    let Some(header) = wire_record.get(..TLS_RECORD_HEADER_LEN) else {
        return Err(failure(
            TargetServerHelloReadErrorKind::UnexpectedEof,
            wire_record,
        ));
    };
    if header[0] != TLS_CONTENT_TYPE_HANDSHAKE || header[1..3] != TLS_LEGACY_RECORD_VERSION {
        return Err(failure(
            TargetServerHelloReadErrorKind::UnexpectedRecord,
            wire_record,
        ));
    }
    let record_body_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if record_body_len == 0 || record_body_len > MAX_TLS_PLAINTEXT_BYTES {
        return Err(failure(
            TargetServerHelloReadErrorKind::RecordTooLarge,
            wire_record,
        ));
    }
    let Some(record_end) = TLS_RECORD_HEADER_LEN.checked_add(record_body_len) else {
        return Err(failure(
            TargetServerHelloReadErrorKind::RecordTooLarge,
            wire_record,
        ));
    };
    if let Err(kind) = read_exact_to(reader, &mut wire_record, record_end, deadline).await {
        return Err(failure(kind, wire_record));
    }
    let Some(message) = wire_record.get(TLS_RECORD_HEADER_LEN..record_end) else {
        return Err(failure(
            TargetServerHelloReadErrorKind::UnexpectedEof,
            wire_record,
        ));
    };
    let template = match ServerHelloTemplate::parse(message, client) {
        Ok(template) => template,
        Err(source) => {
            return Err(failure(
                TargetServerHelloReadErrorKind::Invalid(source),
                wire_record,
            ));
        }
    };

    Ok(TargetServerHelloRead {
        template,
        wire_record,
    })
}

/// Reads the cover-derived encrypted-handshake record plan under one deadline.
///
/// This follows stock Xray's measured 512-wire-byte adaptive branch policy,
/// extended by the observed cover flight itself. A compatibility CCS after the
/// ServerHello is consumed when present and tolerated when absent; the
/// generated flight emits its own CCS only in the first case. A larger first
/// encrypted record selects one coalesced generated record; its header and
/// first body byte are consumed before accepting the shape. Otherwise exactly
/// four positional encrypted records are consumed, followed by one
/// non-blocking probe for a fifth NewSessionTicket record header whose body is
/// never awaited. Socket bytes are fetched through a lazily refilled buffer
/// (one read per refill, sized to finish the current record plus one header),
/// and every byte read — consumed or still buffered — is retained in order in
/// the returned prefix for byte-exact fallback, bounded by
/// [`MAX_RETAINED_COVER_PREFIX_LEN`]. Rust's existing TLS 1.3 record limit
/// remains authoritative rather than copying Xray's internal
/// observation-buffer size.
pub(crate) async fn read_target_server_flight<R>(
    reader: &mut R,
    client: &ClientHello,
    timeout: Duration,
) -> Result<TargetServerFlightRead, TargetServerHelloReadError>
where
    R: CoverFlightIo,
{
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return Err(failure(TargetServerHelloReadErrorKind::Timeout, Vec::new()));
    };
    let hello = read_target_server_hello_until(reader, client, deadline).await?;
    let (template, wire_prefix) = hello.into_parts();
    let mut flight = BufferedFlightReader {
        consumed: wire_prefix.len(),
        buffer: wire_prefix,
        reader,
        deadline,
    };

    let emit_ccs = match flight.change_cipher_spec().await {
        Ok(emit_ccs) => emit_ccs,
        Err(kind) => return Err(failure(kind, flight.into_prefix())),
    };

    let first_wire_len = match flight.encrypted_header().await {
        Ok(wire_len) => wire_len,
        Err(kind) => return Err(failure(kind, flight.into_prefix())),
    };
    if first_wire_len > COALESCED_COVER_RECORD_THRESHOLD {
        // Xray does not classify a header-only response as a usable cover
        // flight: at least one declared ciphertext byte must have arrived.
        // Stop immediately after that byte so fallback can replay this exact
        // prefix and relay the unread body without buffering the large record.
        if let Err(kind) = flight.fill(TLS_RECORD_HEADER_LEN + 1).await {
            return Err(failure(kind, flight.into_prefix()));
        }
        flight.consume(TLS_RECORD_HEADER_LEN + 1);
        return Ok(TargetServerFlightRead {
            template,
            plan: CoverHandshakePlan {
                emit_ccs,
                shape: CoverHandshakeRecordShape::Coalesced {
                    wire_len: first_wire_len,
                },
            },
            wire_prefix: flight.into_prefix(),
        });
    }

    let mut wire_lens = [first_wire_len, 0, 0, 0];
    for (index, wire_len) in wire_lens.iter_mut().enumerate() {
        if index > 0 {
            *wire_len = match flight.encrypted_header().await {
                Ok(wire_len) => wire_len,
                Err(kind) => return Err(failure(kind, flight.into_prefix())),
            };
        }
        if let Err(kind) = flight.fill(*wire_len).await {
            return Err(failure(kind, flight.into_prefix()));
        }
        flight.consume(*wire_len);
    }

    let nst_wire_len = match flight.probe_session_ticket().await {
        Ok(nst_wire_len) => nst_wire_len,
        Err(kind) => return Err(failure(kind, flight.into_prefix())),
    };

    Ok(TargetServerFlightRead {
        template,
        plan: CoverHandshakePlan {
            emit_ccs,
            shape: CoverHandshakeRecordShape::PositionalRecords {
                wire_lens,
                nst_wire_len,
            },
        },
        wire_prefix: flight.into_prefix(),
    })
}

/// Lazily refilled cover-flight parser retaining every socket byte in order.
///
/// `buffer` owns every byte read from the cover — consumed and still
/// unconsumed — so the success prefix and every error prefix stay byte-exact
/// for fallback without a second copy. Refills happen only when the parser
/// lacks bytes for the next header or body, so one delivered flight typically
/// costs one read call per kernel delivery instead of two per record.
struct BufferedFlightReader<'a, R> {
    reader: &'a mut R,
    deadline: Instant,
    buffer: Vec<u8>,
    consumed: usize,
}

impl<R> BufferedFlightReader<'_, R>
where
    R: CoverFlightIo,
{
    /// Ensures at least `len` unconsumed bytes, refilling once per read call.
    ///
    /// Each refill asks for the bytes needed to finish the current record plus
    /// one next-header length, so a flight delivered in one burst is parsed
    /// with few reads; the socket decides how much actually arrives and every
    /// returned byte is appended to the retained prefix. Every blocking read
    /// runs under the same absolute deadline.
    async fn fill(&mut self, len: usize) -> Result<(), TargetServerHelloReadErrorKind> {
        let target = self
            .consumed
            .checked_add(len)
            .ok_or(TargetServerHelloReadErrorKind::RecordTooLarge)?;
        if target > MAX_RETAINED_COVER_PREFIX_LEN
            || self.buffer.len() > MAX_RETAINED_COVER_PREFIX_LEN
        {
            return Err(TargetServerHelloReadErrorKind::RecordTooLarge);
        }
        if self.buffer.len() >= target {
            return Ok(());
        }
        let reserve = target
            .checked_add(TLS_RECORD_HEADER_LEN)
            .ok_or(TargetServerHelloReadErrorKind::RecordTooLarge)?
            .saturating_sub(self.buffer.len());
        self.buffer
            .try_reserve_exact(reserve)
            .map_err(|_| TargetServerHelloReadErrorKind::RecordTooLarge)?;
        let mut scratch = [0_u8; READ_SCRATCH_BYTES];
        while self.buffer.len() < target {
            let needed = target.saturating_sub(self.buffer.len());
            let read_len = needed
                .checked_add(TLS_RECORD_HEADER_LEN)
                .map(|request| {
                    request
                        .min(scratch.len())
                        .min(MAX_RETAINED_COVER_PREFIX_LEN - self.buffer.len())
                })
                .ok_or(TargetServerHelloReadErrorKind::RecordTooLarge)?;
            if read_len == 0 {
                return Err(TargetServerHelloReadErrorKind::RecordTooLarge);
            }
            let request = scratch
                .get_mut(..read_len)
                .ok_or(TargetServerHelloReadErrorKind::UnexpectedEof)?;
            let read = match time::timeout_at(self.deadline, self.reader.read(request)).await {
                Ok(Ok(0)) => return Err(TargetServerHelloReadErrorKind::UnexpectedEof),
                Ok(Ok(read)) => read,
                Ok(Err(source)) => return Err(TargetServerHelloReadErrorKind::Io(source)),
                Err(_) => return Err(TargetServerHelloReadErrorKind::Timeout),
            };
            let bytes = request
                .get(..read)
                .ok_or(TargetServerHelloReadErrorKind::UnexpectedEof)?;
            self.buffer.extend_from_slice(bytes);
        }
        Ok(())
    }

    /// Marks `len` parsed bytes as consumed; [`Self::fill`] proved them present.
    fn consume(&mut self, len: usize) {
        self.consumed += len;
    }

    /// Parses the record header at the consumed position.
    ///
    /// [`Self::fill`] must already have provided the five header bytes.
    fn header(&self) -> Result<(u8, usize), TargetServerHelloReadErrorKind> {
        let header = self
            .buffer
            .get(self.consumed..self.consumed + TLS_RECORD_HEADER_LEN)
            .ok_or(TargetServerHelloReadErrorKind::UnexpectedEof)?;
        if header[1..3] != TLS_LEGACY_RECORD_VERSION {
            return Err(TargetServerHelloReadErrorKind::UnexpectedRecord);
        }
        let body_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if body_len == 0 || body_len > MAX_TLS13_CIPHERTEXT_LEN {
            return Err(TargetServerHelloReadErrorKind::RecordTooLarge);
        }
        let wire_len = TLS_RECORD_HEADER_LEN
            .checked_add(body_len)
            .ok_or(TargetServerHelloReadErrorKind::RecordTooLarge)?;
        Ok((header[0], wire_len))
    }

    /// Consumes a valid compatibility CCS, or peers at the first encrypted
    /// record header without consuming it when the cover omits the CCS.
    ///
    /// Invalid CCS variants (wrong version, wrong length, wrong payload) and
    /// any other record type remain hard failures with the exact prefix.
    async fn change_cipher_spec(&mut self) -> Result<bool, TargetServerHelloReadErrorKind> {
        self.fill(TLS_RECORD_HEADER_LEN).await?;
        let (outer_type, wire_len) = self.header()?;
        match outer_type {
            TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC => {
                if wire_len != TLS_RECORD_HEADER_LEN + 1 {
                    return Err(TargetServerHelloReadErrorKind::UnexpectedRecord);
                }
                self.fill(wire_len).await?;
                if self.buffer.get(self.consumed + TLS_RECORD_HEADER_LEN) != Some(&1) {
                    return Err(TargetServerHelloReadErrorKind::UnexpectedRecord);
                }
                self.consume(wire_len);
                Ok(true)
            }
            TLS_CONTENT_TYPE_APPLICATION_DATA => Ok(false),
            _ => Err(TargetServerHelloReadErrorKind::UnexpectedRecord),
        }
    }

    /// Parses the next encrypted record header without consuming its body.
    async fn encrypted_header(&mut self) -> Result<usize, TargetServerHelloReadErrorKind> {
        self.fill(TLS_RECORD_HEADER_LEN).await?;
        let (outer_type, wire_len) = self.header()?;
        if outer_type != TLS_CONTENT_TYPE_APPLICATION_DATA {
            return Err(TargetServerHelloReadErrorKind::UnexpectedRecord);
        }
        Ok(wire_len)
    }

    /// Non-blocking probe for a fifth (NewSessionTicket) record header.
    ///
    /// Whatever the single `try_read` returns joins the retained prefix; an
    /// empty, short, or failed probe simply means no ticket slot was observed,
    /// so arrival timing can never turn the probe into an error. A declared
    /// empty body stays the hard framing failure every other record applies;
    /// a body too small to hold the AEAD tag is still reported and left for
    /// the flight builder to reject, matching undersized positional slots.
    async fn probe_session_ticket(
        &mut self,
    ) -> Result<Option<usize>, TargetServerHelloReadErrorKind> {
        let buffered = self.buffer.len().saturating_sub(self.consumed);
        if buffered < TLS_RECORD_HEADER_LEN {
            let remaining_capacity = MAX_RETAINED_COVER_PREFIX_LEN
                .checked_sub(self.buffer.len())
                .ok_or(TargetServerHelloReadErrorKind::RecordTooLarge)?;
            if remaining_capacity == 0 {
                return Err(TargetServerHelloReadErrorKind::RecordTooLarge);
            }
            let mut scratch = [0_u8; NST_PROBE_SCRATCH_BYTES];
            let request_len = scratch.len().min(remaining_capacity);
            if let Ok(read @ 1..) = self.reader.try_read_now(&mut scratch[..request_len]) {
                self.buffer
                    .try_reserve_exact(read)
                    .map_err(|_| TargetServerHelloReadErrorKind::RecordTooLarge)?;
                let bytes = scratch
                    .get(..read)
                    .ok_or(TargetServerHelloReadErrorKind::UnexpectedEof)?;
                self.buffer.extend_from_slice(bytes);
            }
        }
        let Some(header) = self
            .buffer
            .get(self.consumed..self.consumed + TLS_RECORD_HEADER_LEN)
        else {
            return Ok(None);
        };
        if header[0] != TLS_CONTENT_TYPE_APPLICATION_DATA
            || header[1..3] != TLS_LEGACY_RECORD_VERSION
        {
            return Ok(None);
        }
        let body_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if body_len == 0 || body_len > MAX_TLS13_CIPHERTEXT_LEN {
            return Err(TargetServerHelloReadErrorKind::RecordTooLarge);
        }
        TLS_RECORD_HEADER_LEN
            .checked_add(body_len)
            .map(Some)
            .ok_or(TargetServerHelloReadErrorKind::RecordTooLarge)
    }

    /// Returns every byte read from the cover, consumed or not, in order.
    fn into_prefix(self) -> Vec<u8> {
        self.buffer
    }
}

async fn read_exact_to<R>(
    reader: &mut R,
    output: &mut Vec<u8>,
    target_len: usize,
    deadline: Instant,
) -> Result<(), TargetServerHelloReadErrorKind>
where
    R: AsyncRead + Unpin,
{
    let mut scratch = [0_u8; READ_SCRATCH_BYTES];
    if output.capacity() < target_len {
        output
            .try_reserve_exact(target_len.saturating_sub(output.len()))
            .map_err(|_| TargetServerHelloReadErrorKind::RecordTooLarge)?;
    }
    while output.len() < target_len {
        let remaining = target_len.saturating_sub(output.len());
        let read_len = remaining.min(scratch.len());
        let buffer = scratch
            .get_mut(..read_len)
            .ok_or(TargetServerHelloReadErrorKind::UnexpectedEof)?;
        let read = match time::timeout_at(deadline, reader.read(buffer)).await {
            Ok(Ok(0)) => return Err(TargetServerHelloReadErrorKind::UnexpectedEof),
            Ok(Ok(read)) => read,
            Ok(Err(source)) => return Err(TargetServerHelloReadErrorKind::Io(source)),
            Err(_) => return Err(TargetServerHelloReadErrorKind::Timeout),
        };
        let bytes = buffer
            .get(..read)
            .ok_or(TargetServerHelloReadErrorKind::UnexpectedEof)?;
        output.extend_from_slice(bytes);
    }
    Ok(())
}

const fn failure(
    kind: TargetServerHelloReadErrorKind,
    wire_prefix: Vec<u8>,
) -> TargetServerHelloReadError {
    TargetServerHelloReadError { kind, wire_prefix }
}

/// Exercises the complete bounded cover-flight reader with arbitrary bytes.
///
/// This entry point only exists for the dedicated libFuzzer build. A fixed,
/// valid ClientHello keeps mutations focused on the server flight, while the
/// first input byte selects raw or valid-prefix mode, fragmentation, and
/// non-blocking NST visibility.
#[cfg(feature = "fuzzing")]
pub fn fuzz_cover_flight(input: &[u8]) {
    use std::sync::OnceLock;

    use crate::protocol::reality::{SESSION_ID_LEN, X25519_GROUP, client_hello::fixtures};

    static CLIENT: OnceLock<ClientHello> = OnceLock::new();
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

    let client = CLIENT.get_or_init(|| {
        ClientHello::parse_message(&fixtures::client_hello_with_key_share(
            [0x44; 32],
            &[0x11; SESSION_ID_LEN],
            "www.example.com",
            &[b"h2"],
            X25519_GROUP,
            &[0x22; 32],
        ))
        .expect("fixed fuzz ClientHello must parse")
    });
    let Some((&control, mutated_bytes)) = input.split_first() else {
        return;
    };
    let generated;
    let bytes = if control & 0x40 == 0 {
        generated = {
            let mut prefix = fuzz_target_server_hello();
            prefix.extend_from_slice(mutated_bytes);
            prefix
        };
        generated.as_slice()
    } else {
        mutated_bytes
    };
    let runtime = RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("fuzz runtime must build")
    });
    let mut reader = FuzzFlightReader {
        bytes,
        position: 0,
        chunk_size: usize::from(control & 0x1f) + 1,
        probe_would_block: control & 0x80 != 0,
    };
    let _ = runtime.block_on(read_target_server_flight(
        &mut reader,
        client,
        Duration::from_millis(1),
    ));
}

#[cfg(feature = "fuzzing")]
fn fuzz_target_server_hello() -> Vec<u8> {
    fn extension(output: &mut Vec<u8>, extension_type: u16, value: &[u8]) {
        output.extend_from_slice(&extension_type.to_be_bytes());
        output.extend_from_slice(
            &u16::try_from(value.len())
                .expect("fixed fuzz extension must fit")
                .to_be_bytes(),
        );
        output.extend_from_slice(value);
    }

    let mut body = Vec::new();
    body.extend_from_slice(&0x0303_u16.to_be_bytes());
    body.extend_from_slice(&[0x33; 32]);
    body.push(32);
    body.extend_from_slice(&[0x11; 32]);
    body.extend_from_slice(&0x1301_u16.to_be_bytes());
    body.push(0);

    let mut extensions = Vec::new();
    extension(&mut extensions, 0x002b, &0x0304_u16.to_be_bytes());
    let mut share = Vec::new();
    share.extend_from_slice(&0x001d_u16.to_be_bytes());
    share.extend_from_slice(&32_u16.to_be_bytes());
    share.extend_from_slice(&[0x55; 32]);
    extension(&mut extensions, 0x0033, &share);
    body.extend_from_slice(
        &u16::try_from(extensions.len())
            .expect("fixed fuzz extensions must fit")
            .to_be_bytes(),
    );
    body.extend_from_slice(&extensions);

    let mut message = vec![2];
    let message_len = u32::try_from(body.len()).expect("fixed fuzz ServerHello must fit");
    message.extend_from_slice(&message_len.to_be_bytes()[1..]);
    message.extend_from_slice(&body);

    let mut record = vec![22, 3, 3];
    record.extend_from_slice(
        &u16::try_from(message.len())
            .expect("fixed fuzz record must fit")
            .to_be_bytes(),
    );
    record.extend_from_slice(&message);
    record
}

#[cfg(feature = "fuzzing")]
struct FuzzFlightReader<'input> {
    bytes: &'input [u8],
    position: usize,
    chunk_size: usize,
    probe_would_block: bool,
}

#[cfg(feature = "fuzzing")]
impl AsyncRead for FuzzFlightReader<'_> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _context: &mut std::task::Context<'_>,
        output: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let remaining = &self.bytes[self.position..];
        let read = remaining.len().min(self.chunk_size).min(output.remaining());
        output.put_slice(&remaining[..read]);
        self.position += read;
        std::task::Poll::Ready(Ok(()))
    }
}

#[cfg(feature = "fuzzing")]
impl CoverFlightIo for FuzzFlightReader<'_> {
    fn try_read_now(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.probe_would_block {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let remaining = &self.bytes[self.position..];
        let read = remaining.len().min(output.len());
        output[..read].copy_from_slice(&remaining[..read]);
        self.position += read;
        Ok(read)
    }
}

#[cfg(test)]
mod tests;
