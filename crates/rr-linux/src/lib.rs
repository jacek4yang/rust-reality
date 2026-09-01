//! The `no_std` Linux ABI boundary for rust-reality.
//!
//! This crate is the only place the project speaks to the kernel. It exists so
//! the protocol crate can stay `#![deny(unsafe_code)]` and runtime-agnostic
//! while descriptor limits, socket options, `FIONREAD`, `splice`, and `/proc`
//! remain exactly what they are: Linux mechanisms.
//!
//! # Shape of the boundary
//!
//! * **No `std`.** The crate is `#![no_std]` and every mechanism compiles
//!   against `core` alone. Kernel work goes through [`rustix`], which on Linux
//!   resolves its `linux_raw` backend and issues syscalls directly instead of
//!   routing them through a C library.
//! * **Kernel errors stay kernel errors.** Mechanisms return [`Errno`]. The
//!   Runtime Adapter converts it into `std::io::Error` at the one place that
//!   needs an `std` error, and no diagnostic string is invented down here.
//! * **Descriptors are owned, never raw.** Creation returns [`OwnedFd`];
//!   observation takes `impl `[`AsFd`]. Nothing in the public API hands a bare
//!   descriptor number to a caller.
//!
//! # The `std` feature
//!
//! `std` is enabled by default and is what production builds with. It forwards
//! `rustix/std`, which makes [`OwnedFd`] and [`BorrowedFd`] *the same types* as
//! `std::os::fd`'s rather than merely convertible ones. That is what lets the
//! Transport move a bound, listening descriptor into `std::net::TcpListener`
//! and then Tokio without a single `unsafe` block above this crate.
//!
//! It enables no mechanism. `cargo check -p rr-linux --no-default-features`
//! compiles this crate's complete implementation, unchanged, with a dependency
//! closure in which no crate has a `std` feature enabled.

#![no_std]

// The tests exercise the `std` interoperability boundary itself, so they
// compile only in that composition; the mechanisms above compile without it.
#[cfg(all(test, feature = "std", target_os = "linux"))]
extern crate std;

#[cfg(target_os = "linux")]
pub mod errno;
#[cfg(target_os = "linux")]
pub mod memory;
#[cfg(target_os = "linux")]
pub mod pipe;
#[cfg(target_os = "linux")]
pub mod rlimit;
#[cfg(target_os = "linux")]
pub mod socket;

/// Descriptor ownership types, re-exported so callers name one boundary.
///
/// With the `std` feature these are `std::os::fd`'s own types, so an
/// [`OwnedFd`] produced here converts into a std or Tokio socket by value.
#[cfg(target_os = "linux")]
pub use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
/// The raw kernel error every mechanism in this crate reports.
#[cfg(target_os = "linux")]
pub use rustix::io::Errno;

#[cfg(target_os = "linux")]
pub use memory::{MemoryError, resident_set_bytes};
#[cfg(target_os = "linux")]
pub use rlimit::{
    DescriptorLimit, descriptor_limit, memlock_limit, open_reserve_descriptor,
    raise_descriptor_soft_limit,
};
