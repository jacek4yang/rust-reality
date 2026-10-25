//! Nested TLS record reading and Vision padding classification.
//!
//! Internal to [`crate::server::vision`]: destination-side record framing and
//! the TLS 1.3 ServerHello detector that drives padding Direct/End decisions.
//! Public fuzz entry [`fuzz_nested_tls_header_prefix`] is re-exported from the
//! parent module so existing fuzz targets keep their path.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, ReadBuf},
    net::tcp::OwnedReadHalf,
};

use crate::protocol::reality::tls13::{IdleDeadline, VectoredRead};

use super::{VisionSessionError, idle_failure};

const NESTED_TLS_HEADER_SIZE: usize = 5;
const MAX_NESTED_TLS_RECORD_SIZE: usize = (1 << 14) + 2_048;
const MAX_NESTED_SERVER_HELLO_SIZE: usize = 8 * 1024;
const MAX_CLASSIFICATION_RECORDS: u8 = 8;
const TLS_HANDSHAKE: u8 = 22;
const TLS_APPLICATION_DATA: u8 = 23;
const TLS_SERVER_HELLO: u8 = 2;
const TLS13_VERSION: [u8; 2] = [0x03, 0x04];
const TLS_AES_128_CCM_8_SHA256: u16 = 0x1305;

/// The outcome of one nested-record read from the buffered connection storage.
///
/// Both non-EOF variants borrow their bytes from the reader's socket buffer
/// rather than copying into an owned `Vec`, which removes the per-record
/// downlink allocation. The borrow ends before the next read.
pub(crate) enum NestedRead<'a> {
    Eof,
    Record(&'a [u8]),
    Unframed(&'a [u8]),
}

/// Capacity of the nested reader's socket buffer.
///
/// Four maximum-sized nested records per refill, so a burst of destination
/// records costs one syscall per refill instead of one header read plus one
/// body read per record.
const NESTED_SOCKET_BUFFER_CAPACITY: usize =
    4 * (NESTED_TLS_HEADER_SIZE + MAX_NESTED_TLS_RECORD_SIZE);

/// Buffered nested-TLS record reader over the destination's read half.
///
/// The same grow-only socket-buffer mechanics as the outer TLS reader: one
/// refill moves available destination bytes into the connection-owned buffer
/// with a single socket read, and nested records are classified out of the
/// buffered range. Bytes buffered beyond an unframed prefix or a Direct
/// boundary stay owned by the reader: the outer downlink relay drains them
/// first through the `AsyncRead` impl, and the Direct transition hands them to
/// the caller via [`NestedRecordReader::into_inner_with_pending`].
pub(crate) struct NestedRecordReader {
    io: OwnedReadHalf,
    socket_buffer: Vec<u8>,
    buffered_start: usize,
    buffered_end: usize,
    pub(crate) idle: IdleDeadline,
}

impl NestedRecordReader {
    /// Borrows the destination descriptor for abort-path socket options.
    pub(crate) fn fd(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd as _;
        self.io.as_ref().as_fd()
    }

    pub(crate) fn new(io: OwnedReadHalf) -> Self {
        Self {
            io,
            socket_buffer: Vec::new(),
            buffered_start: 0,
            buffered_end: 0,
            idle: IdleDeadline::new(),
        }
    }

    /// Classifies the next nested record out of the buffered range.
    ///
    /// A prefix that cannot be TLS is returned immediately as `Unframed`, even
    /// when fewer than five bytes are available. Otherwise EOF before any byte
    /// is `Eof`; socket EOF with fewer than five buffered bytes
    /// yields the remaining bytes as `Unframed`; a header that fails
    /// [`looks_like_tls_record_header`] or declares a body above
    /// [`MAX_NESTED_TLS_RECORD_SIZE`] yields the five header bytes as
    /// `Unframed` while any remaining buffered bytes stay owned by the reader;
    /// EOF inside an otherwise accepted record is
    /// [`VisionSessionError::DestinationTruncatedTlsRecord`].
    pub(crate) async fn next(
        &mut self,
        timeout: Duration,
    ) -> Result<NestedRead<'_>, VisionSessionError> {
        while self.buffered_end - self.buffered_start < NESTED_TLS_HEADER_SIZE {
            let start = self.buffered_start;
            let prefix = self
                .socket_buffer
                .get(start..self.buffered_end)
                .unwrap_or_default();
            // Do not wait for more application bytes once TLS is impossible:
            // an origin can legitimately wait for the next request after a
            // one-byte response, without sending FIN.
            if !could_be_tls_record_header(prefix) {
                self.buffered_start = self.buffered_end;
                return Ok(NestedRead::Unframed(
                    self.socket_buffer
                        .get(start..self.buffered_end)
                        .unwrap_or_default(),
                ));
            }
            if !self.refill(timeout).await? {
                let start = self.buffered_start;
                let remaining = self.buffered_end - start;
                if remaining == 0 {
                    return Ok(NestedRead::Eof);
                }
                self.buffered_start = self.buffered_end;
                return Ok(NestedRead::Unframed(
                    self.socket_buffer
                        .get(start..self.buffered_end)
                        .unwrap_or_default(),
                ));
            }
        }
        let header_end = self.buffered_start + NESTED_TLS_HEADER_SIZE;
        let header: [u8; NESTED_TLS_HEADER_SIZE] = self
            .socket_buffer
            .get(self.buffered_start..header_end)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(VisionSessionError::DestinationTruncatedTlsRecord)?;
        let body_length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if !looks_like_tls_record_header(&header) || body_length > MAX_NESTED_TLS_RECORD_SIZE {
            let start = self.buffered_start;
            self.buffered_start = header_end;
            return Ok(NestedRead::Unframed(
                self.socket_buffer
                    .get(start..header_end)
                    .unwrap_or_default(),
            ));
        }

        let record_length = NESTED_TLS_HEADER_SIZE + body_length;
        while self.buffered_end - self.buffered_start < record_length {
            if !self.refill(timeout).await? {
                return Err(VisionSessionError::DestinationTruncatedTlsRecord);
            }
        }
        let start = self.buffered_start;
        self.buffered_start = start + record_length;
        Ok(NestedRead::Record(
            self.socket_buffer
                .get(start..start + record_length)
                .unwrap_or_default(),
        ))
    }

    /// Moves available socket bytes into the buffer under one idle window.
    ///
    /// Returns `false` on socket EOF. The buffer is allocated and zero-filled
    /// once, compacted only when the free tail can no longer hold one
    /// maximum-sized nested record, and grown only if a single record ever
    /// needs more than the whole buffer.
    async fn refill(&mut self, timeout: Duration) -> Result<bool, VisionSessionError> {
        if self.socket_buffer.capacity() == 0 {
            let mut buffer = Vec::new();
            buffer
                .try_reserve_exact(NESTED_SOCKET_BUFFER_CAPACITY)
                .map_err(|_| VisionSessionError::AllocationFailed)?;
            buffer.resize(NESTED_SOCKET_BUFFER_CAPACITY, 0);
            self.socket_buffer = buffer;
        }
        if self.buffered_start == self.buffered_end {
            self.buffered_start = 0;
            self.buffered_end = 0;
        } else if self.socket_buffer.len() - self.buffered_end
            < NESTED_TLS_HEADER_SIZE + MAX_NESTED_TLS_RECORD_SIZE
        {
            let buffered = self.buffered_end - self.buffered_start;
            self.socket_buffer
                .copy_within(self.buffered_start..self.buffered_end, 0);
            self.buffered_start = 0;
            self.buffered_end = buffered;
        }
        if self.buffered_end == self.socket_buffer.len() {
            self.socket_buffer
                .try_reserve_exact(NESTED_SOCKET_BUFFER_CAPACITY)
                .map_err(|_| VisionSessionError::AllocationFailed)?;
            self.socket_buffer
                .resize(self.socket_buffer.len() + NESTED_SOCKET_BUFFER_CAPACITY, 0);
        }
        self.idle
            .reset(timeout)
            .map_err(|_| VisionSessionError::Timeout)?;
        let end = self.buffered_end;
        let destination = self
            .socket_buffer
            .get_mut(end..)
            .ok_or(VisionSessionError::AllocationFailed)?;
        let read = self
            .idle
            .read(&mut self.io, destination)
            .await
            .map_err(idle_failure)?;
        if read == 0 {
            return Ok(false);
        }
        self.buffered_end += read;
        Ok(true)
    }

    /// Consumes the reader and returns unparsed buffered bytes plus the transport.
    ///
    /// Every buffered byte is a post-boundary raw byte the destination
    /// pipelined behind its boundary record; the caller must deliver them, in
    /// order, ahead of every byte any raw relay moves.
    pub(crate) fn into_inner_with_pending(self) -> (Vec<u8>, OwnedReadHalf) {
        let pending = self
            .socket_buffer
            .get(self.buffered_start..self.buffered_end)
            .unwrap_or_default()
            .to_vec();
        (pending, self.io)
    }
}

impl AsyncRead for NestedRecordReader {
    /// Drains buffered bytes before touching the socket.
    ///
    /// The outer downlink relay reads through this impl, so bytes buffered by
    /// the classification reads are forwarded ahead of — never lost behind —
    /// the bytes still in the kernel.
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let buffered = self.buffered_end - self.buffered_start;
        if buffered > 0 {
            let start = self.buffered_start;
            let count = buffered.min(buffer.remaining());
            buffer.put_slice(
                self.socket_buffer
                    .get(start..start + count)
                    .unwrap_or_default(),
            );
            self.buffered_start += count;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.io).poll_read(context, buffer)
    }
}

impl VectoredRead for NestedRecordReader {
    /// Drains buffered bytes into the first buffer, otherwise one `readv`.
    ///
    /// Buffered bytes are the rare post-classification leftovers; they fill
    /// only the first non-empty buffer, exactly like the scalar
    /// [`AsyncRead`] impl. Once the buffer is empty the call forwards to one
    /// vectored socket read, which is what lets the batched downlink relay
    /// (experiment D11) fill several record slots per syscall.
    async fn read_vectored<'buf>(
        &'buf mut self,
        buffers: &'buf mut [io::IoSliceMut<'buf>],
    ) -> io::Result<usize> {
        let buffered = self.buffered_end - self.buffered_start;
        if buffered > 0 {
            let Some(first) = buffers.iter_mut().find(|buffer| !buffer.is_empty()) else {
                return Ok(0);
            };
            let count = buffered.min(first.len());
            let start = self.buffered_start;
            first[..count].copy_from_slice(
                self.socket_buffer
                    .get(start..start + count)
                    .unwrap_or_default(),
            );
            self.buffered_start += count;
            return Ok(count);
        }
        loop {
            self.io.readable().await?;
            match self.io.try_read_vectored(buffers) {
                Ok(read) => return Ok(read),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error),
            }
        }
    }
}

/// Whether the available prefix can still satisfy the existing TLS header
/// predicate. Empty and ambiguous prefixes remain undecided; no sniff timer or
/// speculative Direct transition is introduced.
fn could_be_tls_record_header(prefix: &[u8]) -> bool {
    prefix.first().is_none_or(|byte| matches!(byte, 20..=23))
        && prefix.get(1).is_none_or(|byte| *byte == 0x03)
        && prefix.get(2).is_none_or(|byte| *byte <= 0x04)
}

fn looks_like_tls_record_header(header: &[u8; NESTED_TLS_HEADER_SIZE]) -> bool {
    could_be_tls_record_header(header)
}

/// Exercises the production nested-header prefix predicate without socket I/O.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_nested_tls_header_prefix(prefix: &[u8]) -> bool {
    could_be_tls_record_header(prefix)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PaddingDecision {
    Continue,
    End,
    Direct,
}

#[derive(Debug)]
pub(crate) struct NestedTlsDetector {
    records_seen: u8,
    server_hello: Vec<u8>,
    server_hello_length: Option<usize>,
    tls13: Option<bool>,
}

impl NestedTlsDetector {
    pub(crate) const fn new() -> Self {
        Self {
            records_seen: 0,
            server_hello: Vec::new(),
            server_hello_length: None,
            tls13: None,
        }
    }

    pub(crate) fn observe(&mut self, record: &[u8]) -> PaddingDecision {
        self.records_seen = self.records_seen.saturating_add(1);
        let content_type = record.first().copied();
        let body = record.get(NESTED_TLS_HEADER_SIZE..).unwrap_or_default();

        if self.tls13.is_none() && content_type == Some(TLS_HANDSHAKE) {
            self.observe_server_hello(body);
        }
        match self.tls13 {
            Some(true) if content_type == Some(TLS_APPLICATION_DATA) => PaddingDecision::Direct,
            Some(false) => PaddingDecision::End,
            None if self.records_seen >= MAX_CLASSIFICATION_RECORDS => PaddingDecision::End,
            _ => PaddingDecision::Continue,
        }
    }

    fn observe_server_hello(&mut self, body: &[u8]) {
        if self.server_hello_length.is_none() {
            if self.server_hello.is_empty() && body.first() != Some(&TLS_SERVER_HELLO) {
                return;
            }
            let header_remaining = 4_usize.saturating_sub(self.server_hello.len());
            let header_bytes = header_remaining.min(body.len());
            if self.server_hello.try_reserve(header_bytes).is_err() {
                self.tls13 = Some(false);
                return;
            }
            self.server_hello.extend_from_slice(&body[..header_bytes]);
            if self.server_hello.len() < 4 {
                return;
            }
            let length = (usize::from(self.server_hello[1]) << 16)
                | (usize::from(self.server_hello[2]) << 8)
                | usize::from(self.server_hello[3]);
            let Some(total) = length.checked_add(4) else {
                self.tls13 = Some(false);
                return;
            };
            if total > MAX_NESTED_SERVER_HELLO_SIZE {
                self.tls13 = Some(false);
                return;
            }
            self.server_hello_length = Some(total);
            self.extend_server_hello(&body[header_bytes..], total);
        } else if let Some(expected) = self.server_hello_length {
            self.extend_server_hello(body, expected);
        }

        let Some(expected) = self.server_hello_length else {
            return;
        };
        if self.server_hello.len() == expected {
            self.tls13 = Some(is_tls13_server_hello(&self.server_hello));
        }
    }

    fn extend_server_hello(&mut self, body: &[u8], expected: usize) {
        let remaining = expected.saturating_sub(self.server_hello.len());
        let count = remaining.min(body.len());
        if self.server_hello.try_reserve(count).is_err() {
            self.tls13 = Some(false);
            return;
        }
        self.server_hello.extend_from_slice(&body[..count]);
    }
}

pub(crate) fn is_tls13_server_hello(message: &[u8]) -> bool {
    let Some(body) = message.get(4..) else {
        return false;
    };
    let Some(session_id_length) = body.get(34).copied().map(usize::from) else {
        return false;
    };
    let Some(cipher_offset) = 35_usize.checked_add(session_id_length) else {
        return false;
    };
    let Some(cipher_bytes) = body.get(cipher_offset..cipher_offset + 2) else {
        return false;
    };
    let cipher_suite = u16::from_be_bytes([cipher_bytes[0], cipher_bytes[1]]);
    if cipher_suite == TLS_AES_128_CCM_8_SHA256 {
        return false;
    }
    let Some(extensions_length_offset) = cipher_offset.checked_add(3) else {
        return false;
    };
    let Some(length_bytes) = body.get(extensions_length_offset..extensions_length_offset + 2)
    else {
        return false;
    };
    let extensions_length = usize::from(u16::from_be_bytes([length_bytes[0], length_bytes[1]]));
    let extensions_start = extensions_length_offset + 2;
    let Some(extensions_end) = extensions_start.checked_add(extensions_length) else {
        return false;
    };
    let Some(extensions) = body.get(extensions_start..extensions_end) else {
        return false;
    };

    let mut cursor = 0;
    while cursor + 4 <= extensions.len() {
        let extension_type = u16::from_be_bytes([extensions[cursor], extensions[cursor + 1]]);
        let extension_length = usize::from(u16::from_be_bytes([
            extensions[cursor + 2],
            extensions[cursor + 3],
        ]));
        cursor += 4;
        let Some(end) = cursor.checked_add(extension_length) else {
            return false;
        };
        let Some(value) = extensions.get(cursor..end) else {
            return false;
        };
        if extension_type == 43 {
            return value == TLS13_VERSION;
        }
        cursor = end;
    }
    false
}
