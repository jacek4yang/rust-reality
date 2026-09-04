//! The cryptographic implementation boundary: architecture-specific assembly
//! behind a safe, `no_std` API.
//!
//! # Why this is a crate
//!
//! The main crate is `#![deny(unsafe_code)]` and stays that way. Assembly
//! cannot live there, so an implementation rust-reality owns needs a home with
//! a different, narrower safety policy — the same reasoning
//! [ADR 0015](../../../docs/adr/0015-rr-linux-is-a-no-std-linux-abi-boundary.md)
//! used for `rr-linux`, applied to arithmetic instead of syscalls. See
//! [ADR 0023](../../../docs/adr/0023-rr-crypto-is-the-unsafe-crypto-boundary.md).
//!
//! This is not a cryptography library and is not trying to become one. It holds
//! the primitives rust-reality performs, in the shapes rust-reality performs
//! them, and nothing else.
//!
//! # Safety policy
//!
//! `unsafe` is permitted here and nowhere else in the production graph. It is
//! bounded by three rules the build enforces rather than the reviewer:
//!
//! 1. every block carries a SAFETY comment stating the invariant that makes it
//!    sound — `clippy::undocumented_unsafe_blocks` is `deny`;
//! 2. an unsafe call that depends on a CPU feature is reachable only through a
//!    runtime probe of that feature, so no binary can execute an instruction
//!    its CPU lacks;
//! 3. the public API is safe. A caller outside this crate cannot construct an
//!    input that violates an invariant an `unsafe` block relies on.
//!
//! # `no_std`
//!
//! `core` only — no `alloc`, no allocation on any path. rust-reality's protocol
//! core is `no_std`-ready and mechanically enforced (ADR 0016), and the reason
//! the binary carries two X25519 implementations today is that its provider
//! requires `std`. A boundary that reintroduced that would have missed the
//! point.
//!
//! # What is claimed, and what is not
//!
//! The imported assembly is machine-checked in its upstream's own proof
//! development. **That proof does not travel with this import**: it covers
//! upstream's build of upstream's source, not this crate's. What is
//! demonstrated here is narrower and testable — that the committed assembly is
//! a mechanical expansion of the vendored upstream, that the machine code Rust
//! emits matches what GNU `as` produces from the same input, and that results
//! agree with RFC 7748 and with independent implementations.
//!
//! Provenance, the pinned upstream revision and the exact transformation
//! applied are recorded in `PROVENANCE.md` beside this file.

#![no_std]

#[cfg(test)]
extern crate alloc;
#[cfg(test)]
extern crate std;

#[cfg(target_arch = "x86_64")]
pub mod detect;

pub mod x25519;

pub use x25519::{EphemeralSecret, KEY_LEN, SharedSecret, StaticSecret};

/// This crate's version, for benchmark output and bug reports.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
