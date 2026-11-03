//! In-protocol fragmentation and bounded reassembly.
//!
//! A DATA plaintext larger than the session's packetization limit is split
//! into at most [`MAX_FRAGMENTS`] FRAG plaintexts, each sealed as its own
//! packet with its own counter (so each fragment is individually
//! authenticated and replay-protected). The receiver reassembles under
//! strict limits: a bounded number of concurrent groups, a bounded byte
//! total, and a timeout. Anything outside the limits is discarded; an
//! incomplete group never delivers partial data.

use std::time::{Duration, Instant};

use super::wire::{FRAG_HEADER_LEN, MAX_DATA_PLAINTEXT_LEN, UdpPacketError};

/// Most fragments one datagram may be split into.
pub const MAX_FRAGMENTS: usize = 16;

/// Reassembly bounds for one session direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReassemblyLimits {
    /// Concurrent incomplete groups.
    pub max_groups: usize,
    /// Buffered fragment bytes across all groups.
    pub max_bytes: usize,
    /// Age after which an incomplete group is discarded.
    pub timeout: Duration,
}

impl Default for ReassemblyLimits {
    fn default() -> Self {
        Self {
            max_groups: 8,
            max_bytes: 4 * MAX_DATA_PLAINTEXT_LEN,
            timeout: Duration::from_secs(3),
        }
    }
}

/// Splits `plaintext` into FRAG plaintexts whose chunks are at most
/// `max_chunk` bytes. Returns the FRAG plaintexts in order.
///
/// # Errors
///
/// Rejects an empty or oversized plaintext, a zero chunk size, and a split
/// that would need more than [`MAX_FRAGMENTS`] fragments.
pub fn split_fragments(
    fragment_id: u32,
    plaintext: &[u8],
    max_chunk: usize,
) -> Result<Vec<Vec<u8>>, UdpPacketError> {
    if plaintext.is_empty() || plaintext.len() > MAX_DATA_PLAINTEXT_LEN || max_chunk == 0 {
        return Err(UdpPacketError::Length);
    }
    let count = plaintext.len().div_ceil(max_chunk);
    if count > MAX_FRAGMENTS {
        return Err(UdpPacketError::Length);
    }
    let count_byte = u8::try_from(count).map_err(|_| UdpPacketError::Length)?;
    let mut fragments = Vec::with_capacity(count);
    for (index, chunk) in plaintext.chunks(max_chunk).enumerate() {
        let mut fragment = Vec::with_capacity(FRAG_HEADER_LEN + chunk.len());
        fragment.extend_from_slice(&fragment_id.to_be_bytes());
        fragment.push(u8::try_from(index).map_err(|_| UdpPacketError::Length)?);
        fragment.push(count_byte);
        fragment.extend_from_slice(chunk);
        fragments.push(fragment);
    }
    Ok(fragments)
}

struct Group {
    id: u32,
    count: usize,
    chunks: Vec<Option<Vec<u8>>>,
    received: usize,
    bytes: usize,
    started: Instant,
}

/// Bounded reassembly state for one receive direction.
pub struct Reassembler {
    limits: ReassemblyLimits,
    groups: Vec<Group>,
    bytes: usize,
    dropped: u64,
}

impl Reassembler {
    /// Empty reassembly state under `limits`.
    #[must_use]
    pub const fn new(limits: ReassemblyLimits) -> Self {
        Self {
            limits,
            groups: Vec::new(),
            bytes: 0,
            dropped: 0,
        }
    }

    /// Groups discarded so far (timeout, eviction, or inconsistency).
    #[must_use]
    pub const fn dropped_groups(&self) -> u64 {
        self.dropped
    }

    /// Buffered fragment bytes.
    #[must_use]
    pub const fn buffered_bytes(&self) -> usize {
        self.bytes
    }

    /// Incomplete groups currently held.
    #[must_use]
    pub fn pending_groups(&self) -> usize {
        self.groups.len()
    }

    /// Discards groups older than the timeout.
    pub fn expire(&mut self, now: Instant) {
        let timeout = self.limits.timeout;
        let mut index = 0;
        while index < self.groups.len() {
            if now.saturating_duration_since(self.groups[index].started) >= timeout {
                self.remove(index);
                self.dropped += 1;
            } else {
                index += 1;
            }
        }
    }

    fn remove(&mut self, index: usize) {
        let group = self.groups.swap_remove(index);
        self.bytes -= group.bytes;
    }

    fn evict_oldest(&mut self) {
        if let Some((index, _)) = self
            .groups
            .iter()
            .enumerate()
            .min_by_key(|(_, group)| group.started)
        {
            self.remove(index);
            self.dropped += 1;
        }
    }

    /// Accepts one authenticated FRAG plaintext. Returns the reassembled DATA
    /// plaintext once every fragment of its group has arrived.
    ///
    /// # Errors
    ///
    /// Rejects malformed fragment headers. Inconsistent groups are discarded
    /// (counted in [`Self::dropped_groups`]) rather than reported.
    pub fn insert(
        &mut self,
        fragment: &[u8],
        now: Instant,
    ) -> Result<Option<Vec<u8>>, UdpPacketError> {
        self.expire(now);
        if fragment.len() <= FRAG_HEADER_LEN {
            return Err(UdpPacketError::Length);
        }
        let id = u32::from_be_bytes([fragment[0], fragment[1], fragment[2], fragment[3]]);
        let index = usize::from(fragment[4]);
        let count = usize::from(fragment[5]);
        if !(2..=MAX_FRAGMENTS).contains(&count) || index >= count {
            return Err(UdpPacketError::Length);
        }
        let chunk = &fragment[FRAG_HEADER_LEN..];
        if chunk.len() > MAX_DATA_PLAINTEXT_LEN || chunk.len() > self.limits.max_bytes {
            return Err(UdpPacketError::Length);
        }
        let position = match self.groups.iter().position(|group| group.id == id) {
            Some(position) => position,
            None => {
                while self.groups.len() >= self.limits.max_groups {
                    self.evict_oldest();
                }
                self.groups.push(Group {
                    id,
                    count,
                    chunks: vec![None; count],
                    received: 0,
                    bytes: 0,
                    started: now,
                });
                self.groups.len() - 1
            }
        };
        if self.groups[position].count != count {
            self.remove(position);
            self.dropped += 1;
            return Ok(None);
        }
        if self.groups[position].chunks[index].is_some() {
            // Duplicates cannot pass the replay window; a repeated index under
            // a fresh counter is a sender bug and is ignored.
            return Ok(None);
        }
        let group_total = self.groups[position].bytes + chunk.len();
        if group_total > MAX_DATA_PLAINTEXT_LEN {
            self.remove(position);
            self.dropped += 1;
            return Ok(None);
        }
        while self.bytes + chunk.len() > self.limits.max_bytes {
            let oldest_other = self
                .groups
                .iter()
                .enumerate()
                .filter(|(_, group)| group.id != id)
                .min_by_key(|(_, group)| group.started)
                .map(|(index, _)| index);
            match oldest_other {
                Some(other) => {
                    self.remove(other);
                    self.dropped += 1;
                }
                None => {
                    if let Some(own) = self.groups.iter().position(|group| group.id == id) {
                        self.remove(own);
                    }
                    self.dropped += 1;
                    return Ok(None);
                }
            }
        }
        let position = self
            .groups
            .iter()
            .position(|group| group.id == id)
            .ok_or(UdpPacketError::Length)?;
        let group = &mut self.groups[position];
        group.chunks[index] = Some(chunk.to_vec());
        group.received += 1;
        group.bytes += chunk.len();
        self.bytes += chunk.len();
        if group.received < group.count {
            return Ok(None);
        }
        let group = self.groups.swap_remove(position);
        self.bytes -= group.bytes;
        let mut whole = Vec::with_capacity(group.bytes);
        for chunk in group.chunks.into_iter().flatten() {
            whole.extend_from_slice(&chunk);
        }
        Ok(Some(whole))
    }
}
