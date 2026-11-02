//! Bounds-checked big-endian reader for continuation-state blobs.

use super::super::HandoffError;

pub(super) struct BlobCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> BlobCursor<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub(super) fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    pub(super) fn take(&mut self, length: usize) -> Result<&'a [u8], HandoffError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(HandoffError::State)?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or(HandoffError::State)?;
        self.position = end;
        Ok(slice)
    }

    pub(super) fn u8(&mut self) -> Result<u8, HandoffError> {
        Ok(self.take(1)?[0])
    }

    pub(super) fn u16(&mut self) -> Result<u16, HandoffError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| HandoffError::State)?,
        ))
    }

    pub(super) fn u32(&mut self) -> Result<u32, HandoffError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| HandoffError::State)?,
        ))
    }

    pub(super) fn u64(&mut self) -> Result<u64, HandoffError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| HandoffError::State)?,
        ))
    }
}
