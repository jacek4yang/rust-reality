//! Process memory observation.
//!
//! The dedicated-machine resource mode samples one lightweight memory signal
//! on a bounded interval. The primary signal is the cgroup v2 `memory.current`
//! file, which the protocol crate reads directly; this module provides the
//! fallback, the resident set size from `/proc/self/statm`, for hosts where the
//! cgroup file is absent or unreadable.
//!
//! The sample runs on a timer for the life of the process, so it does no
//! allocation: the file is read into a fixed stack buffer and parsed by an
//! explicit ASCII integer scanner with checked arithmetic. Nothing here is a
//! general `/proc` reader — it answers exactly one question.

use rustix::{
    fd::AsFd,
    fs::{Mode, OFlags},
    io::Errno,
};

/// Why a resident-set sample could not be produced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryError {
    /// The kernel refused to open or read `/proc/self/statm`.
    Kernel(Errno),
    /// `/proc/self/statm` did not have the documented shape, or reported a
    /// resident size that cannot be expressed in bytes.
    Malformed,
}

/// Bytes read from `/proc/self/statm`.
///
/// The file is seven space-separated decimal fields. Only the first two matter
/// here, and they need at most 42 bytes even if the kernel printed the largest
/// `u64` it can represent, so the resident field is always complete. Reads that
/// do hit this bound are still unambiguous: [`terminated_field`] accepts a
/// field only when it saw the separator that ends it.
const STATM_READ_LIMIT: usize = 128;

/// The zero-based index of the resident page count in `/proc/self/statm`.
const RESIDENT_FIELD: usize = 1;

/// The page size assumed when the kernel reports one that does not fit a `u64`.
const CONSERVATIVE_PAGE_SIZE: u64 = 4_096;

/// Returns the process resident set size in bytes from `/proc/self/statm`.
///
/// The second `statm` field is the resident page count; converting pages to
/// bytes needs the kernel page size, which is why this lives in the crate that
/// owns Linux mechanisms.
///
/// # Errors
///
/// Returns [`MemoryError::Kernel`] when `/proc/self/statm` cannot be opened or
/// read, and [`MemoryError::Malformed`] when its shape is not the documented
/// one — a missing, empty, truncated, non-decimal, or overflowing resident
/// field.
pub fn resident_set_bytes() -> Result<u64, MemoryError> {
    let statm = rustix::fs::open(
        "/proc/self/statm",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(MemoryError::Kernel)?;
    let mut buffer = [0_u8; STATM_READ_LIMIT];
    let read = read_bounded(&statm, &mut buffer).map_err(MemoryError::Kernel)?;
    let pages = resident_pages(read).ok_or(MemoryError::Malformed)?;
    pages.checked_mul(page_size()).ok_or(MemoryError::Malformed)
}

/// Fills `buffer` from `fd` until end of file or the buffer is full.
fn read_bounded(fd: impl AsFd, buffer: &mut [u8]) -> Result<&[u8], Errno> {
    let fd = fd.as_fd();
    let mut filled = 0;
    while filled < buffer.len() {
        match rustix::io::read(fd, &mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(Errno::INTR) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(&buffer[..filled])
}

/// Parses the resident page count out of `/proc/self/statm` content.
fn resident_pages(statm: &[u8]) -> Option<u64> {
    parse_decimal(terminated_field(statm, RESIDENT_FIELD)?)
}

/// Returns the `index`-th whitespace-separated field, if a separator ends it.
///
/// Requiring the terminator is what makes a bounded read unambiguous: a field
/// running to the end of the buffer may be missing digits, so it is rejected
/// rather than parsed into a plausible wrong number.
fn terminated_field(bytes: &[u8], index: usize) -> Option<&[u8]> {
    let mut rest = bytes;
    let mut remaining = index;
    loop {
        let start = rest.iter().position(|byte| !byte.is_ascii_whitespace())?;
        rest = rest.get(start..)?;
        let end = rest.iter().position(u8::is_ascii_whitespace)?;
        let (field, tail) = rest.split_at(end);
        if remaining == 0 {
            return Some(field);
        }
        remaining -= 1;
        rest = tail;
    }
}

/// Parses an unsigned decimal field with no sign, no prefix, and no overflow.
fn parse_decimal(field: &[u8]) -> Option<u64> {
    if field.is_empty() {
        return None;
    }
    let mut value = 0_u64;
    for byte in field {
        let digit = byte.wrapping_sub(b'0');
        if digit > 9 {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u64::from(digit))?;
    }
    Some(value)
}

/// Returns the kernel memory page size in bytes.
///
/// rustix reads `AT_PAGESZ` from the kernel-provided aux vector once and caches
/// it, so this is not a syscall per sample. It is only ever reached after
/// `/proc/self/statm` was read successfully, which already establishes that
/// this process can see its own `/proc` entries.
fn page_size() -> u64 {
    u64::try_from(rustix::param::page_size()).unwrap_or(CONSERVATIVE_PAGE_SIZE)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::{
        MemoryError, RESIDENT_FIELD, page_size, parse_decimal, resident_pages, resident_set_bytes,
        terminated_field,
    };

    #[test]
    fn the_live_sample_is_a_plausible_resident_set() {
        let bytes = resident_set_bytes().expect("/proc/self/statm must be readable");
        assert!(
            bytes >= page_size(),
            "a running process holds at least one resident page"
        );
        assert_eq!(
            bytes % page_size(),
            0,
            "the sample must be a whole number of pages"
        );
    }

    #[test]
    fn the_kernel_page_size_is_a_power_of_two() {
        let size = page_size();
        assert!(size >= 4_096 && size.is_power_of_two(), "page size {size}");
    }

    #[test]
    fn the_documented_shape_parses_to_the_second_field() {
        assert_eq!(
            resident_pages(b"5423 1092 823 12 0 1470 0\n"),
            Some(1_092),
            "the resident page count is the second field"
        );
        assert_eq!(
            resident_pages(b"5423 1092 823 12 0 1470 0"),
            Some(1_092),
            "a file without a trailing newline still terminates the second field"
        );
        assert_eq!(
            resident_pages(b"  5423   1092  823\n"),
            Some(1_092),
            "runs of separators are one separator"
        );
    }

    #[test]
    fn a_shape_that_is_not_the_documented_one_is_rejected() {
        for malformed in [
            &b""[..],
            &b"\n"[..],
            &b"   "[..],
            &b"5423"[..],
            &b"5423 "[..],
            &b"5423\n"[..],
            &b"5423 1092"[..],
            &b"5423 -1 823\n"[..],
            &b"5423 +1 823\n"[..],
            &b"5423 1_092 823\n"[..],
            &b"5423 0x10 823\n"[..],
            &b"5423 10.5 823\n"[..],
            &b"5423 abc 823\n"[..],
            &b"5423 1092abc 823\n"[..],
            &b"5423 18446744073709551616 823\n"[..],
            &b"5423 99999999999999999999999 823\n"[..],
        ] {
            assert_eq!(
                resident_pages(malformed),
                None,
                "must reject {:?}",
                core::str::from_utf8(malformed)
            );
        }
    }

    #[test]
    fn a_field_that_reaches_the_end_of_a_bounded_read_is_never_parsed() {
        // The read stopped mid-number: `109` is a prefix of `1092`, and
        // accepting it would report a wrong resident size as a valid one.
        assert_eq!(resident_pages(b"5423 109"), None);
        assert_eq!(
            terminated_field(b"5423 109", RESIDENT_FIELD),
            None,
            "an unterminated field is not a field"
        );
        assert_eq!(
            terminated_field(b"5423 109 ", RESIDENT_FIELD),
            Some(&b"109"[..]),
            "one more byte makes the same field unambiguous"
        );
    }

    #[test]
    fn the_largest_representable_field_parses_and_the_next_one_does_not() {
        assert_eq!(parse_decimal(b"18446744073709551615"), Some(u64::MAX));
        assert_eq!(parse_decimal(b"18446744073709551616"), None);
        assert_eq!(parse_decimal(b"00000000000000000042"), Some(42));
    }

    #[test]
    fn a_resident_count_that_cannot_be_expressed_in_bytes_is_rejected() {
        // Reached through the same arithmetic `resident_set_bytes` performs.
        assert_eq!(
            u64::MAX
                .checked_mul(page_size())
                .ok_or(MemoryError::Malformed),
            Err(MemoryError::Malformed),
            "an impossible page count must not wrap into a plausible byte count"
        );
    }
}
