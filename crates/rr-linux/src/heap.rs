//! Returning freed allocator memory to the kernel.
//!
//! glibc keeps freed memory inside its per-thread arenas. When a burst of
//! relay traffic has grown an arena and then ended, almost all of that arena
//! is free, but the pages stay resident because a few small live allocations
//! sit above them and the arena can only shrink from its top. `malloc_trim`
//! walks every arena and hands whole free pages back with `MADV_DONTNEED`, so
//! resident memory follows live memory again.
//!
//! This is the one libc function this crate calls. It is a C library policy,
//! not a kernel mechanism, so neither rustix nor linux-raw-sys can provide it.
//! Other C libraries (musl) already return memory eagerly and need nothing.

/// Asks the C library to return free heap pages to the kernel.
///
/// Returns `true` when glibc reports that it released memory. On C libraries
/// without `malloc_trim` this does nothing and returns `false`.
#[must_use]
pub fn release_free_heap() -> bool {
    #[cfg(target_env = "gnu")]
    {
        // SAFETY: `malloc_trim` takes a plain size and only touches glibc's
        // allocator state under glibc's own arena locks; it is documented
        // MT-Safe and never invalidates a live allocation.
        unsafe { libc::malloc_trim(0) != 0 }
    }
    #[cfg(not(target_env = "gnu"))]
    {
        false
    }
}
