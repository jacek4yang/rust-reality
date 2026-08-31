//! Bounded Linux kernel relay primitives for rust-reality.
//!
//! This crate exists for exactly one reason: the protocol crate denies
//! `unsafe_code`, but raw Linux ABI — descriptor limits, socket options,
//! `FIONREAD` — cannot be touched without `unsafe`. Every unavoidable
//! `unsafe` block therefore lives here, behind narrow safe APIs, with a
//! precise `SAFETY:` comment and a direct ABI or lifecycle test.
//!
//! The crate deliberately knows nothing about VLESS, REALITY or Vision. It
//! wraps the kernel interfaces the relay path actually uses.

#![cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "Linux-only crate")
)]

#[cfg(target_os = "linux")]
pub mod errno;
#[cfg(target_os = "linux")]
pub mod memory;
#[cfg(target_os = "linux")]
pub mod pipe;
pub mod rlimit;
pub mod socket;

pub use memory::resident_set_bytes;
pub use rlimit::{
    DescriptorLimit, descriptor_limit, memlock_limit, open_reserve_descriptor,
    raise_descriptor_soft_limit,
};
