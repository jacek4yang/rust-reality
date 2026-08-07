//! Process memory observation.
//!
//! The dedicated-machine resource mode samples one lightweight memory signal
//! on a bounded interval. The primary signal is the cgroup v2
//! `memory.current` file, which the protocol crate reads directly; this module
//! provides the fallback, the resident set size from `/proc/self/statm`, for
//! hosts where the cgroup file is absent or unreadable.

use std::io;

/// Returns the process resident set size in bytes from `/proc/self/statm`.
///
/// The second `statm` field is the resident page count. Reading a `/proc`
/// file is safe, but converting pages to bytes needs the kernel page size,
/// which is why this lives in the crate that may use `libc`.
///
/// # Errors
///
/// Returns the raw I/O error when `/proc/self/statm` cannot be read, or
/// [`io::ErrorKind::InvalidData`] when its shape is not the documented one.
#[cfg(target_os = "linux")]
pub fn resident_set_bytes() -> io::Result<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm")?;
    let resident_pages = statm
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "statm has no resident field"))?
        .parse::<u64>()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "statm resident field is not a number",
            )
        })?;
    Ok(resident_pages.saturating_mul(page_size()))
}

/// Returns the process resident set size on a platform without `/proc`.
///
/// # Errors
///
/// Always returns [`io::ErrorKind::Unsupported`] so a caller cannot mistake an
/// absent measurement for a zero reading.
#[cfg(not(target_os = "linux"))]
pub fn resident_set_bytes() -> io::Result<u64> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "resident set size is only observable on Linux",
    ))
}

/// Returns the kernel memory page size in bytes.
#[cfg(target_os = "linux")]
fn page_size() -> u64 {
    // SAFETY: `_SC_PAGESIZE` is a valid `sysconf` name, the call takes no
    // pointer arguments, and it cannot fail for this name; a negative return
    // is clamped to the conservative 4 KiB default below.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    u64::try_from(size).unwrap_or(4_096)
}
