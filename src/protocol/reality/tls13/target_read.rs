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
mod tests {
    use std::{
        io,
        io::Write as _,
        net::{TcpListener as StdTcpListener, TcpStream as StdTcpStream},
        pin::Pin,
        sync::mpsc,
        task::Poll,
        thread,
        time::Duration,
    };

    use tokio::{
        io::{AsyncRead, AsyncWriteExt, DuplexStream, ReadBuf},
        net::{TcpListener, TcpStream},
        sync::oneshot,
    };

    use super::{
        BufferedFlightReader, CoverFlightIo, CoverHandshakePlan, CoverHandshakeRecordShape,
        MAX_RETAINED_COVER_PREFIX_LEN, TargetServerHelloReadErrorKind, read_target_server_flight,
        read_target_server_hello,
    };
    use crate::protocol::reality::{
        ClientHello, SESSION_ID_LEN, X25519_GROUP, client_hello::fixtures,
    };

    struct OneByteReader {
        bytes: Vec<u8>,
        position: usize,
    }

    impl AsyncRead for OneByteReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let Some(byte) = self.bytes.get(self.position).copied() else {
                return Poll::Ready(Ok(()));
            };
            output.put_slice(&[byte]);
            self.position += 1;
            Poll::Ready(Ok(()))
        }
    }

    impl CoverFlightIo for OneByteReader {
        fn try_read_now(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let remaining = self.bytes.len().saturating_sub(self.position);
            let read = remaining.min(output.len());
            if read == 0 {
                return Ok(0);
            }
            output[..read].copy_from_slice(&self.bytes[self.position..self.position + read]);
            self.position += read;
            Ok(read)
        }
    }

    impl CoverFlightIo for DuplexStream {
        fn try_read_now(&mut self, _output: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }
    }

    /// Real TCP reader whose blocking reads stop on fixture record boundaries.
    /// `try_read_now` remains the production `TcpStream::try_read` operation.
    struct RecordBoundaryTcpReader {
        stream: TcpStream,
        position: usize,
        boundaries: Vec<usize>,
    }

    impl AsyncRead for RecordBoundaryTcpReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let boundary = self
                .boundaries
                .iter()
                .copied()
                .find(|boundary| *boundary > self.position)
                .unwrap_or(usize::MAX);
            let limit = boundary
                .saturating_sub(self.position)
                .min(output.remaining())
                .min(4 * 1024);
            if limit == 0 {
                return Poll::Ready(Ok(()));
            }
            let mut scratch = [0_u8; 4 * 1024];
            let mut read_buffer = ReadBuf::new(&mut scratch[..limit]);
            match Pin::new(&mut self.stream).poll_read(context, &mut read_buffer) {
                Poll::Ready(Ok(())) => {
                    let read = read_buffer.filled().len();
                    output.put_slice(read_buffer.filled());
                    self.position += read;
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl CoverFlightIo for RecordBoundaryTcpReader {
        fn try_read_now(&mut self, output: &mut [u8]) -> io::Result<usize> {
            self.stream.try_read(output)
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retained_prefix_accepts_the_exact_global_limit_and_rejects_one_more_byte() {
        let mut reader = OneByteReader {
            bytes: vec![0x5a],
            position: 0,
        };
        let mut flight = BufferedFlightReader {
            reader: &mut reader,
            deadline: tokio::time::Instant::now() + Duration::from_secs(1),
            buffer: vec![0; MAX_RETAINED_COVER_PREFIX_LEN - 1],
            consumed: MAX_RETAINED_COVER_PREFIX_LEN - 1,
        };

        flight
            .fill(1)
            .await
            .expect("the exact 66,642-byte prefix limit must be accepted");
        assert_eq!(flight.buffer.len(), MAX_RETAINED_COVER_PREFIX_LEN);
        assert_eq!(flight.buffer.last(), Some(&0x5a));
        assert!(matches!(
            flight.fill(2).await,
            Err(TargetServerHelloReadErrorKind::RecordTooLarge)
        ));
        assert_eq!(flight.buffer.len(), MAX_RETAINED_COVER_PREFIX_LEN);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reads_fragmented_target_record_without_consuming_next_record() {
        let client = client();
        let record = target_record(&[0x55; 32]);
        let mut input = record.clone();
        input.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
        let mut reader = OneByteReader {
            bytes: input,
            position: 0,
        };

        let read = read_target_server_hello(&mut reader, &client, Duration::from_secs(1))
            .await
            .expect("compatible target ServerHello must be read");

        assert_eq!(read.wire_record(), record);
        assert_eq!(read.template().key_share_group(), X25519_GROUP);
        assert_eq!(reader.position, record.len());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn invalid_target_returns_complete_byte_exact_record() {
        let client = client();
        let mut record = target_record(&[0x55; 32]);
        record[5] = 1;
        let mut reader = OneByteReader {
            bytes: record.clone(),
            position: 0,
        };

        let error = read_target_server_hello(&mut reader, &client, Duration::from_secs(1))
            .await
            .expect_err("non-ServerHello handshake must fail");

        assert!(matches!(
            error.kind(),
            TargetServerHelloReadErrorKind::Invalid(_)
        ));
        assert_eq!(error.fallback_prefix(), record);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn timeout_returns_partial_target_prefix() {
        let client = client();
        let (mut local, mut remote) = tokio::io::duplex(16);
        let prefix = [22, 3, 3, 0, 128, 2, 0];
        remote
            .write_all(&prefix)
            .await
            .expect("partial target response must be written");

        let error = read_target_server_hello(&mut local, &client, Duration::from_millis(20))
            .await
            .expect_err("incomplete target response must time out");

        assert!(matches!(
            error.kind(),
            TargetServerHelloReadErrorKind::Timeout
        ));
        assert_eq!(error.fallback_prefix(), prefix);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rejects_non_handshake_header_without_reading_declared_body() {
        let client = client();
        let header = [21, 3, 3, 0, 64];
        let mut reader = OneByteReader {
            bytes: header.to_vec(),
            position: 0,
        };

        let error = read_target_server_hello(&mut reader, &client, Duration::from_secs(1))
            .await
            .expect_err("alert record must not be accepted as ServerHello");

        assert!(matches!(
            error.kind(),
            TargetServerHelloReadErrorKind::UnexpectedRecord
        ));
        assert_eq!(error.fallback_prefix(), header);
        assert_eq!(reader.position, header.len());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn coalesced_shape_consumes_the_header_and_first_body_byte() {
        let client = client();
        let server_hello = target_record(&[0x55; 32]);
        let ccs = [20, 3, 3, 0, 1, 1];
        let encrypted = opaque_record(23, 600, 0xa5);
        let expected_prefix_len = server_hello.len() + ccs.len() + 6;
        let mut input = server_hello.clone();
        input.extend_from_slice(&ccs);
        input.extend_from_slice(&encrypted);
        let mut reader = OneByteReader {
            bytes: input.clone(),
            position: 0,
        };

        let read = read_target_server_flight(&mut reader, &client, Duration::from_secs(1))
            .await
            .expect("large first encrypted record must select coalescing");
        let (_, plan, prefix) = read.into_parts();

        assert_eq!(
            plan,
            CoverHandshakePlan {
                emit_ccs: true,
                shape: CoverHandshakeRecordShape::Coalesced { wire_len: 605 },
            }
        );
        assert_eq!(prefix, input[..expected_prefix_len]);
        assert_eq!(reader.position, expected_prefix_len);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn coalesced_header_without_a_body_byte_times_out_with_exact_prefix() {
        let client = client();
        let mut prefix = target_record(&[0x55; 32]);
        prefix.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
        prefix.extend_from_slice(&[23, 3, 3, 2, 88]);
        let (mut local, mut remote) = tokio::io::duplex(2_048);
        remote
            .write_all(&prefix)
            .await
            .expect("header-only target flight must be written");

        let error = read_target_server_flight(&mut local, &client, Duration::from_millis(20))
            .await
            .expect_err("a declared coalesced record must contain ciphertext");

        assert!(matches!(
            error.kind(),
            TargetServerHelloReadErrorKind::Timeout
        ));
        assert_eq!(error.fallback_prefix(), prefix);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn invalid_change_cipher_spec_retains_the_exact_consumed_prefix() {
        let client = client();
        let mut input = target_record(&[0x55; 32]);
        input.extend_from_slice(&[20, 3, 3, 0, 1, 2]);
        let mut reader = OneByteReader {
            bytes: input.clone(),
            position: 0,
        };

        let error = read_target_server_flight(&mut reader, &client, Duration::from_secs(1))
            .await
            .expect_err("invalid CCS content must be rejected");

        assert!(matches!(
            error.kind(),
            TargetServerHelloReadErrorKind::UnexpectedRecord
        ));
        assert_eq!(error.fallback_prefix(), input);
        assert_eq!(reader.position, input.len());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn positional_shape_probes_and_retains_a_fifth_ticket_record() {
        let client = client();
        let mut input = target_record(&[0x55; 32]);
        input.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
        let body_lens = [32_usize, 208, 89, 53];
        for (index, body_len) in body_lens.into_iter().enumerate() {
            input.extend_from_slice(&opaque_record(23, body_len, index as u8));
        }
        input.extend_from_slice(&opaque_record(23, 24, 0xff));
        let mut reader = OneByteReader {
            bytes: input.clone(),
            position: 0,
        };

        let read = read_target_server_flight(&mut reader, &client, Duration::from_secs(1))
            .await
            .expect("four small encrypted records must be read positionally");
        let (_, plan, prefix) = read.into_parts();

        assert_eq!(
            plan,
            CoverHandshakePlan {
                emit_ccs: true,
                shape: CoverHandshakeRecordShape::PositionalRecords {
                    wire_lens: [37, 213, 94, 58],
                    nst_wire_len: Some(29),
                },
            }
        );
        assert_eq!(prefix, input);
        assert_eq!(reader.position, input.len());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn positional_shape_without_ccs_or_ticket_is_retained_exactly() {
        let client = client();
        let mut input = target_record(&[0x55; 32]);
        for (index, body_len) in [32_usize, 208, 89, 53].into_iter().enumerate() {
            input.extend_from_slice(&opaque_record(23, body_len, index as u8));
        }
        let mut reader = OneByteReader {
            bytes: input.clone(),
            position: 0,
        };

        let read = read_target_server_flight(&mut reader, &client, Duration::from_secs(1))
            .await
            .expect("CCS-less four-record cover flight must be accepted");
        let (_, plan, prefix) = read.into_parts();

        assert_eq!(
            plan,
            CoverHandshakePlan {
                emit_ccs: false,
                shape: CoverHandshakeRecordShape::PositionalRecords {
                    wire_lens: [37, 213, 94, 58],
                    nst_wire_len: None,
                },
            }
        );
        assert_eq!(prefix, input);
        assert_eq!(reader.position, input.len());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tcp_record_delay_matrix_covers_fifth_probe_timing() {
        const DELAYS_MS: [u64; 5] = [0, 20, 50, 100, 200];
        const CASES: [&str; 3] = [
            "already-buffered",
            "single-probe-present",
            "absent-would-block",
        ];

        for delay_ms in DELAYS_MS {
            for case in CASES {
                let client = client();
                let server_hello = target_record(&[0x55; 32]);
                let ccs = [20, 3, 3, 0, 1, 1].to_vec();
                let encrypted: Vec<Vec<u8>> = [32_usize, 48, 64, 80]
                    .into_iter()
                    .enumerate()
                    .map(|(index, body_len)| opaque_record(23, body_len, index as u8))
                    .collect();
                let ticket = opaque_record(23, 24, 0xf5);
                let emit_ccs = case != "single-probe-present";
                let mut records = vec![server_hello.clone()];
                if emit_ccs {
                    records.push(ccs.clone());
                }
                records.extend(encrypted.iter().cloned());
                if case != "absent-would-block" {
                    records.push(ticket.clone());
                }
                let prefix_without_ticket: Vec<u8> = records
                    .iter()
                    .take(records.len() - usize::from(case != "absent-would-block"))
                    .flatten()
                    .copied()
                    .collect();

                let listener = StdTcpListener::bind("127.0.0.1:0")
                    .expect("record-delay fixture listener must bind");
                let address = listener
                    .local_addr()
                    .expect("record-delay fixture must have an address");
                let (sent_tx, sent_rx) = mpsc::sync_channel(1);
                let (done_tx, done_rx) = mpsc::sync_channel(1);
                let server = thread::spawn(move || {
                    let (mut stream, _) = listener
                        .accept()
                        .expect("record-delay fixture connection must arrive");
                    for (index, record) in records.iter().enumerate() {
                        if index > 0 {
                            thread::sleep(Duration::from_millis(delay_ms));
                        }
                        stream
                            .write_all(record)
                            .expect("complete TLS record must be sent in one fixture write");
                    }
                    sent_tx
                        .send(())
                        .expect("reader must await the complete scheduled flight");
                    done_rx
                        .recv_timeout(Duration::from_secs(2))
                        .expect("reader must complete before fixture closes");
                });
                let stream = StdTcpStream::connect(address)
                    .expect("record-delay fixture TCP connection must open");
                stream
                    .set_nonblocking(true)
                    .expect("Tokio TCP stream requires nonblocking mode");
                sent_rx
                    .recv_timeout(Duration::from_secs(3))
                    .expect("record-delay fixture must send within its bound");
                let stream =
                    TcpStream::from_std(stream).expect("fixture std stream must convert to Tokio");

                let mut position = 0;
                let mut boundaries = Vec::new();
                let records_before_ticket = 1 + usize::from(emit_ccs) + encrypted.len();
                for record in std::iter::once(&server_hello)
                    .chain(emit_ccs.then_some(&ccs))
                    .chain(encrypted.iter())
                {
                    position += record.len();
                    boundaries.push(position);
                }
                if case == "already-buffered" {
                    *boundaries
                        .get_mut(records_before_ticket - 1)
                        .expect("fourth encrypted boundary must exist") += 5;
                }
                let mut reader = RecordBoundaryTcpReader {
                    stream,
                    position: 0,
                    boundaries,
                };
                let read = read_target_server_flight(&mut reader, &client, Duration::from_secs(2))
                    .await
                    .expect("record-delay matrix flight must parse");
                let (_, plan, prefix) = read.into_parts();
                let expected_ticket_len = (case != "absent-would-block").then_some(ticket.len());
                assert_eq!(
                    plan,
                    CoverHandshakePlan {
                        emit_ccs,
                        shape: CoverHandshakeRecordShape::PositionalRecords {
                            wire_lens: [37, 53, 69, 85],
                            nst_wire_len: expected_ticket_len,
                        },
                    },
                    "delay={delay_ms}ms case={case}"
                );
                let expected_prefix = match case {
                    "already-buffered" => {
                        let mut expected = prefix_without_ticket.clone();
                        expected.extend_from_slice(&ticket[..5]);
                        expected
                    }
                    "single-probe-present" => {
                        let mut expected = prefix_without_ticket.clone();
                        expected.extend_from_slice(&ticket);
                        expected
                    }
                    "absent-would-block" => prefix_without_ticket.clone(),
                    _ => unreachable!(),
                };
                assert_eq!(prefix, expected_prefix, "delay={delay_ms}ms case={case}");
                done_tx
                    .send(())
                    .expect("fixture server must still be waiting");
                server
                    .join()
                    .expect("record-delay fixture server must finish");
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn positional_timeout_retains_the_exact_partial_record() {
        let client = client();
        let mut prefix = target_record(&[0x55; 32]);
        prefix.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
        prefix.extend_from_slice(&opaque_record(23, 32, 0x01));
        prefix.extend_from_slice(&[23, 3, 3, 0, 64, 0xaa, 0xbb, 0xcc]);
        let (mut local, mut remote) = tokio::io::duplex(2_048);
        remote
            .write_all(&prefix)
            .await
            .expect("partial target flight must be written");

        let error = read_target_server_flight(&mut local, &client, Duration::from_millis(20))
            .await
            .expect_err("partial positional record must time out");

        assert!(matches!(
            error.kind(),
            TargetServerHelloReadErrorKind::Timeout
        ));
        assert_eq!(error.fallback_prefix(), prefix);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tcp_mid_record_close_returns_exact_prefix_and_unexpected_eof() {
        let client = client();
        let prefix = partial_positional_flight();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("ephemeral TCP listener must bind");
        let address = listener
            .local_addr()
            .expect("ephemeral TCP listener must have an address");
        let server_prefix = prefix.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("cover TCP connection must arrive");
            stream
                .write_all(&server_prefix)
                .await
                .expect("partial cover flight must be written");
            stream
                .shutdown()
                .await
                .expect("partial cover connection must close cleanly");
        });
        let mut stream = TcpStream::connect(address)
            .await
            .expect("cover TCP connection must open");

        let error = tokio::time::timeout(
            Duration::from_secs(1),
            read_target_server_flight(&mut stream, &client, Duration::from_millis(250)),
        )
        .await
        .expect("closed cover connection must fail within the outer test deadline")
        .expect_err("closing in the middle of a record must fail");
        server.await.expect("cover TCP task must complete");

        assert!(matches!(
            error.kind(),
            TargetServerHelloReadErrorKind::UnexpectedEof
        ));
        assert_eq!(error.fallback_prefix(), prefix);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tcp_mid_record_stall_returns_exact_prefix_and_timeout() {
        let client = client();
        let prefix = partial_positional_flight();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("ephemeral TCP listener must bind");
        let address = listener
            .local_addr()
            .expect("ephemeral TCP listener must have an address");
        let server_prefix = prefix.clone();
        let (written_tx, written_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("cover TCP connection must arrive");
            stream
                .write_all(&server_prefix)
                .await
                .expect("partial cover flight must be written");
            written_tx
                .send(())
                .expect("test reader must await the written prefix");
            let _ = release_rx.await;
        });
        let mut stream = TcpStream::connect(address)
            .await
            .expect("cover TCP connection must open");
        written_rx
            .await
            .expect("cover TCP task must report the written prefix");

        let error = tokio::time::timeout(
            Duration::from_secs(1),
            read_target_server_flight(&mut stream, &client, Duration::from_millis(100)),
        )
        .await
        .expect("stalled cover connection must fail within the outer test deadline")
        .expect_err("stalling in the middle of a record must time out");
        assert!(matches!(
            error.kind(),
            TargetServerHelloReadErrorKind::Timeout
        ));
        assert_eq!(error.fallback_prefix(), prefix);

        let _ = release_tx.send(());
        server.await.expect("cover TCP task must complete");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn every_positional_flight_truncation_retains_the_exact_prefix() {
        let client = client();
        let mut complete = target_record(&[0x55; 32]);
        complete.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
        for (index, body_len) in [32_usize, 48, 64, 40].into_iter().enumerate() {
            complete.extend_from_slice(&opaque_record(23, body_len, index as u8));
        }

        for cutoff in 0..complete.len() {
            let expected = complete[..cutoff].to_vec();
            let mut reader = OneByteReader {
                bytes: expected.clone(),
                position: 0,
            };
            let error = read_target_server_flight(&mut reader, &client, Duration::from_secs(1))
                .await
                .expect_err("every truncated flight must fail closed");

            assert!(matches!(
                error.kind(),
                TargetServerHelloReadErrorKind::UnexpectedEof
            ));
            assert_eq!(error.fallback_prefix(), expected);
            assert_eq!(reader.position, cutoff);
        }
    }

    fn client() -> ClientHello {
        ClientHello::parse_message(&fixtures::client_hello_with_key_share(
            [0x44; 32],
            &[0x11; SESSION_ID_LEN],
            "www.example.com",
            &[b"h2"],
            X25519_GROUP,
            &[0x22; 32],
        ))
        .expect("test ClientHello must parse")
    }

    fn target_record(key_exchange: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303_u16.to_be_bytes());
        body.extend_from_slice(&[0x33; 32]);
        body.push(u8::try_from(SESSION_ID_LEN).expect("test session ID must fit"));
        body.extend_from_slice(&[0x11; SESSION_ID_LEN]);
        body.extend_from_slice(&0x1301_u16.to_be_bytes());
        body.push(0);

        let mut extensions = Vec::new();
        push_extension(&mut extensions, 0x002b, &0x0304_u16.to_be_bytes());
        let mut share = Vec::new();
        share.extend_from_slice(&X25519_GROUP.to_be_bytes());
        share.extend_from_slice(
            &u16::try_from(key_exchange.len())
                .expect("test key share must fit")
                .to_be_bytes(),
        );
        share.extend_from_slice(key_exchange);
        push_extension(&mut extensions, 0x0033, &share);
        body.extend_from_slice(
            &u16::try_from(extensions.len())
                .expect("test extensions must fit")
                .to_be_bytes(),
        );
        body.extend_from_slice(&extensions);

        let mut message = vec![2];
        let message_len = u32::try_from(body.len()).expect("test ServerHello body must fit");
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

    fn opaque_record(content_type: u8, body_len: usize, fill: u8) -> Vec<u8> {
        let mut record = vec![content_type, 3, 3];
        record.extend_from_slice(
            &u16::try_from(body_len)
                .expect("test record body must fit")
                .to_be_bytes(),
        );
        record.resize(5 + body_len, fill);
        record
    }

    fn partial_positional_flight() -> Vec<u8> {
        let mut prefix = target_record(&[0x55; 32]);
        prefix.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
        prefix.extend_from_slice(&opaque_record(23, 32, 0x01));
        prefix.extend_from_slice(&[23, 3, 3, 0, 64, 0xaa, 0xbb, 0xcc]);
        prefix
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
