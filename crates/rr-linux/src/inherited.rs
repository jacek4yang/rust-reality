//! Close descriptors inherited from the parent before this process opens its own.
//!
//! A runner, shell, or supervisor can leave pipe ends above stderr in the
//! child. Those ends are not relay permits. The ownership check correctly
//! rejects them; the process must not keep them.

use core::mem::MaybeUninit;

use rustix::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use rustix::fs::{Mode, OFlags, RawDir, open};
use rustix::io::Errno;

/// Closes every descriptor above stderr.
///
/// Standard streams stay open. The current product does not accept inherited
/// sockets, so anything still open above stderr at startup is parent state,
/// not a grant. Call this before the process opens its own descriptors.
///
/// # Errors
///
/// Returns the kernel error if `/proc/self/fd` cannot be read.
pub fn close_inherited_descriptors() -> Result<(), Errno> {
    // Closing does not create descriptors. Repeat so a parent that left more
    // than one scan batch still ends with only the standard streams.
    loop {
        let found = inherited_descriptors()?;
        if found.len == 0 {
            return Ok(());
        }
        for index in 0..found.len {
            close_one(found.values[index]);
        }
    }
}

fn inherited_descriptors() -> Result<Found, Errno> {
    let dir = open(
        "/proc/self/fd",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let dir_fd = dir.as_fd().as_raw_fd();
    let mut buf = [MaybeUninit::uninit(); 2048];
    let mut iter = RawDir::new(dir.as_fd(), &mut buf);
    let mut found = Found::new();
    while let Some(entry) = iter.next() {
        let entry = entry?;
        let name = entry.file_name();
        let Ok(number) = parse_fd(name.to_bytes()) else {
            continue;
        };
        if number <= 2 || number == dir_fd {
            continue;
        }
        found.push(number);
    }
    Ok(found)
}

fn parse_fd(name: &[u8]) -> Result<i32, ()> {
    if name.is_empty() || !name.iter().all(u8::is_ascii_digit) {
        return Err(());
    }
    let mut value: i32 = 0;
    for byte in name {
        value = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(i32::from(*byte - b'0')))
            .ok_or(())?;
    }
    Ok(value)
}

fn close_one(number: i32) {
    // SAFETY: this number was just read from `/proc/self/fd`, is above stderr,
    // and is not the directory being scanned. Startup is single-threaded, so
    // the number cannot be reused before this close. The owned value closes it
    // exactly once.
    drop(unsafe { OwnedFd::from_raw_fd(number) });
}

struct Found {
    values: [i32; 64],
    len: usize,
}

impl Found {
    fn new() -> Self {
        Self {
            values: [0; 64],
            len: 0,
        }
    }

    fn push(&mut self, number: i32) {
        if self.len < self.values.len() {
            self.values[self.len] = number;
            self.len += 1;
        }
    }
}

#[cfg(all(test, feature = "std", target_os = "linux"))]
mod tests {
    use std::os::fd::AsRawFd as _;
    use std::vec::Vec;

    use rustix::io::Errno;
    use rustix::pipe::pipe;

    use super::inherited_descriptors;

    #[test]
    fn inherited_scan_sees_a_new_pipe_and_keeps_stdio() {
        let (reader, writer) = pipe().expect("pipe");
        let numbers = inherited_descriptors().expect("scan");
        let found = numbers.values[..numbers.len]
            .iter()
            .copied()
            .collect::<Vec<_>>();
        assert!(found.contains(&reader.as_raw_fd()));
        assert!(found.contains(&writer.as_raw_fd()));
        assert!(!found.contains(&0));
        assert!(!found.contains(&1));
        assert!(!found.contains(&2));
        assert_ne!(reader.as_raw_fd(), writer.as_raw_fd());
        let _ = Errno::BADF;
    }
}
