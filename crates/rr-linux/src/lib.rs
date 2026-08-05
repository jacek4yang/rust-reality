//! Bounded Linux kernel relay backends for rust-reality.
//!
//! This crate exists for exactly one reason: the protocol crate denies
//! `unsafe_code`, but a bounded io_uring driver and an eBPF `SOCKHASH` verdict
//! program cannot be written without touching raw Linux ABI. Every unavoidable
//! `unsafe` block therefore lives here, behind narrow safe APIs, with a precise
//! `SAFETY:` comment and a direct ABI or lifecycle test.
//!
//! The crate deliberately knows nothing about VLESS, REALITY or Vision. It
//! moves already-authenticated plaintext bytes between two sockets it has been
//! given, or it declines with a fixed reason.
//!
//! # Bounds
//!
//! Every structure here is bounded at construction:
//!
//! * driver shards are `min(visible CPUs, configured maximum)`;
//! * each shard owns one ring with a fixed submission and completion depth;
//! * request slots, buffer slots and duplicated descriptors are pre-reserved;
//! * the submission channel is a bounded `sync_channel`, never an unbounded one;
//! * every eBPF map has a fixed `max_entries`.
//!
//! # Capability reporting
//!
//! Nothing here assumes a capability. Each backend probes what it actually uses
//! and reports a fixed [`DeclineReason`] when the running kernel, capability
//! set, seccomp policy or security module refuses.

#![cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "Linux-only crate")
)]

use std::fmt;

pub mod bpf;
pub mod capability;
pub mod rlimit;
pub mod socket;
pub mod sockhash;
pub mod uring;

pub use capability::{DeclineReason, Probe, ProbeReport};
pub use rlimit::{DescriptorLimit, descriptor_limit, open_reserve_descriptor};

/// A bounded resource budget shared by both kernel backends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Budget {
    /// Maximum concurrently armed relays.
    pub max_relays: u32,
    /// Bytes per registered or pooled buffer.
    pub buffer_bytes: u32,
    /// Maximum driver shards.
    pub max_shards: u16,
    /// Submission-queue depth per shard.
    pub queue_depth: u16,
}

impl Budget {
    /// Returns whether every field is usable and the products cannot overflow.
    ///
    /// # Errors
    ///
    /// Returns the field that made the budget impossible.
    pub const fn validate(&self) -> Result<(), BudgetError> {
        if self.max_relays == 0 {
            return Err(BudgetError::ZeroRelays);
        }
        if self.buffer_bytes == 0 {
            return Err(BudgetError::ZeroBufferBytes);
        }
        if self.max_shards == 0 {
            return Err(BudgetError::ZeroShards);
        }
        if self.queue_depth == 0 || !self.queue_depth.is_power_of_two() {
            return Err(BudgetError::QueueDepth);
        }
        if self.registered_bytes().is_none() {
            return Err(BudgetError::Overflow);
        }
        Ok(())
    }

    /// Returns the total registered buffer bytes, or `None` on overflow.
    ///
    /// Two directions per relay, one buffer per direction.
    #[must_use]
    pub const fn registered_bytes(&self) -> Option<u64> {
        let relays = self.max_relays as u64;
        let bytes = self.buffer_bytes as u64;
        match relays.checked_mul(2) {
            Some(directions) => directions.checked_mul(bytes),
            None => None,
        }
    }

    /// Returns the number of shards to create for `visible_cpus`.
    #[must_use]
    pub const fn shards(&self, visible_cpus: usize) -> usize {
        let cpus = if visible_cpus == 0 { 1 } else { visible_cpus };
        let maximum = self.max_shards as usize;
        if cpus < maximum { cpus } else { maximum }
    }
}

/// A relay budget that cannot be satisfied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetError {
    /// The relay limit was zero while the backend was enabled.
    ZeroRelays,
    /// The buffer size was zero.
    ZeroBufferBytes,
    /// The shard limit was zero.
    ZeroShards,
    /// The queue depth was zero or not a power of two.
    QueueDepth,
    /// The budget product overflowed.
    Overflow,
}

impl fmt::Display for BudgetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroRelays => "an enabled kernel backend needs a nonzero relay limit",
            Self::ZeroBufferBytes => "a kernel backend needs a nonzero buffer size",
            Self::ZeroShards => "a kernel backend needs at least one driver shard",
            Self::QueueDepth => "queue depth must be a nonzero power of two",
            Self::Overflow => "the configured kernel relay budget overflows",
        })
    }
}

impl std::error::Error for BudgetError {}

#[cfg(test)]
mod tests {
    use super::{Budget, BudgetError};

    const VALID: Budget = Budget {
        max_relays: 256,
        buffer_bytes: 32 * 1024,
        max_shards: 4,
        queue_depth: 256,
    };

    #[test]
    fn a_valid_budget_is_accepted() {
        assert_eq!(VALID.validate(), Ok(()));
        assert_eq!(VALID.registered_bytes(), Some(256 * 2 * 32 * 1024));
    }

    #[test]
    fn every_impossible_budget_is_named() {
        for (budget, expected) in [
            (
                Budget {
                    max_relays: 0,
                    ..VALID
                },
                BudgetError::ZeroRelays,
            ),
            (
                Budget {
                    buffer_bytes: 0,
                    ..VALID
                },
                BudgetError::ZeroBufferBytes,
            ),
            (
                Budget {
                    max_shards: 0,
                    ..VALID
                },
                BudgetError::ZeroShards,
            ),
            (
                Budget {
                    queue_depth: 0,
                    ..VALID
                },
                BudgetError::QueueDepth,
            ),
            (
                Budget {
                    queue_depth: 100,
                    ..VALID
                },
                BudgetError::QueueDepth,
            ),
            (
                Budget {
                    max_relays: u32::MAX,
                    buffer_bytes: u32::MAX,
                    ..VALID
                },
                BudgetError::Overflow,
            ),
        ] {
            assert_eq!(budget.validate(), Err(expected));
        }
    }

    #[test]
    fn shard_count_is_bounded_by_both_cpus_and_configuration() {
        assert_eq!(VALID.shards(1), 1);
        assert_eq!(VALID.shards(2), 2);
        assert_eq!(VALID.shards(64), 4);
        assert_eq!(VALID.shards(0), 1);
    }

    #[test]
    fn the_maximum_budget_product_does_not_overflow_silently() {
        let budget = Budget {
            max_relays: u32::MAX,
            buffer_bytes: u32::MAX,
            ..VALID
        };
        assert_eq!(budget.registered_bytes(), None);
    }
}
