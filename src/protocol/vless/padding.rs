use chacha20::{
    ChaCha12,
    cipher::{KeyIvInit, StreamCipher},
};
use zeroize::Zeroize;

/// Keystream bytes generated per refill.
const BLOCK_BYTES: usize = 256;

/// Keystream bytes drawn from one seed before reseeding from the operating system.
///
/// The bound keeps generator lifetime short without paying an operating-system
/// entropy call per frame. It is a policy bound, not a security limit: ChaCha12
/// remains indistinguishable far beyond this budget.
const RESEED_AFTER_BYTES: u64 = 1 << 20;

/// Cryptographically secure per-connection padding-length generator.
///
/// Xray-compatible Vision padding draws one uniform value per frame. Calling the
/// operating system for four bytes per frame is a measurable syscall cost on the
/// downlink hot path, and a table of repeating values would make padding lengths
/// predictable to an observer. This generator keeps the security property and
/// removes the per-frame syscall by expanding a `getrandom` seed with ChaCha12
/// and reseeding on a bounded budget.
///
/// State is fixed size, never grows, and is zeroized on drop.
pub struct PaddingRng {
    cipher: ChaCha12,
    buffer: [u8; BLOCK_BYTES],
    position: usize,
    issued: u64,
}

impl PaddingRng {
    /// Seeds one generator from operating-system entropy.
    ///
    /// # Errors
    ///
    /// Returns [`EntropyUnavailable`] when `getrandom` fails.
    pub fn from_os() -> Result<Self, EntropyUnavailable> {
        let mut seed = [0_u8; 44];
        crate::crypto::entropy::fill(&mut seed).map_err(|_| EntropyUnavailable)?;
        let generator = Self::from_seed(&seed);
        seed.zeroize();
        Ok(generator)
    }

    /// Seeds one generator deterministically for tests and differential oracles.
    ///
    /// Production code always uses [`PaddingRng::from_os`]; this constructor
    /// exists so padding-dependent behaviour can be reproduced exactly without
    /// weakening the production generator.
    #[must_use]
    pub fn from_seed(seed: &[u8; 44]) -> Self {
        let mut key = [0_u8; 32];
        let mut nonce = [0_u8; 12];
        key.copy_from_slice(&seed[..32]);
        nonce.copy_from_slice(&seed[32..]);
        let mut cipher = ChaCha12::new(&key.into(), &nonce.into());
        key.zeroize();
        nonce.zeroize();
        let mut buffer = [0_u8; BLOCK_BYTES];
        cipher.apply_keystream(&mut buffer);
        Self {
            cipher,
            buffer,
            position: 0,
            issued: BLOCK_BYTES as u64,
        }
    }

    /// Returns a uniform value in `0..upper` using rejection sampling.
    ///
    /// The acceptance limit reproduces the distribution of the previous
    /// `getrandom`-backed implementation exactly.
    ///
    /// # Errors
    ///
    /// Returns [`EntropyUnavailable`] only when a reseed fails.
    pub fn below(&mut self, upper: u32) -> Result<u32, EntropyUnavailable> {
        if upper == 0 {
            return Ok(0);
        }
        let acceptance_limit = u32::MAX - (u32::MAX % upper);
        loop {
            let value = u32::from_ne_bytes(self.next_four()?);
            if value < acceptance_limit {
                return Ok(value % upper);
            }
        }
    }

    fn next_four(&mut self) -> Result<[u8; 4], EntropyUnavailable> {
        if self.position + 4 > BLOCK_BYTES {
            self.refill()?;
        }
        let mut value = [0_u8; 4];
        let start = self.position;
        value.copy_from_slice(
            self.buffer
                .get(start..start + 4)
                .ok_or(EntropyUnavailable)?,
        );
        self.position += 4;
        Ok(value)
    }

    fn refill(&mut self) -> Result<(), EntropyUnavailable> {
        if self.issued >= RESEED_AFTER_BYTES {
            *self = Self::from_os()?;
            return Ok(());
        }
        self.buffer.zeroize();
        self.cipher.apply_keystream(&mut self.buffer);
        self.position = 0;
        self.issued = self.issued.saturating_add(BLOCK_BYTES as u64);
        Ok(())
    }
}

impl Drop for PaddingRng {
    fn drop(&mut self) {
        self.buffer.zeroize();
    }
}

impl core::fmt::Debug for PaddingRng {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PaddingRng")
            .field("state", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Operating-system entropy was unavailable while seeding padding randomness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntropyUnavailable;

#[cfg(test)]
mod tests {
    use super::{BLOCK_BYTES, PaddingRng};

    const SEED: [u8; 44] = [7; 44];

    #[test]
    fn deterministic_seed_reproduces_the_same_sequence() {
        let mut first = PaddingRng::from_seed(&SEED);
        let mut second = PaddingRng::from_seed(&SEED);

        for _ in 0..1_000 {
            assert_eq!(
                first.below(500).expect("seeded generator must not fail"),
                second.below(500).expect("seeded generator must not fail")
            );
        }
    }

    #[test]
    fn different_seeds_produce_different_sequences() {
        let mut first = PaddingRng::from_seed(&SEED);
        let mut second = PaddingRng::from_seed(&[9; 44]);
        let left: Vec<u32> = (0..64)
            .map(|_| first.below(500).expect("generator must not fail"))
            .collect();
        let right: Vec<u32> = (0..64)
            .map(|_| second.below(500).expect("generator must not fail"))
            .collect();

        assert_ne!(left, right);
    }

    #[test]
    fn values_stay_inside_the_requested_range() {
        let mut generator = PaddingRng::from_seed(&SEED);

        for _ in 0..10_000 {
            let value = generator.below(500).expect("generator must not fail");
            assert!(value < 500);
        }
        assert_eq!(generator.below(1).expect("generator must not fail"), 0);
        assert_eq!(generator.below(0).expect("generator must not fail"), 0);
    }

    #[test]
    fn refill_crosses_block_boundaries_without_repeating_state() {
        let mut generator = PaddingRng::from_seed(&SEED);
        let draws = (BLOCK_BYTES / 4) * 4;
        let mut seen = Vec::with_capacity(draws);

        for _ in 0..draws {
            seen.push(generator.below(u32::MAX).expect("generator must not fail"));
        }

        let first_block = &seen[..BLOCK_BYTES / 4];
        let second_block = &seen[BLOCK_BYTES / 4..BLOCK_BYTES / 2];
        assert_ne!(first_block, second_block);
    }

    #[test]
    fn distribution_covers_the_range_uniformly_enough() {
        let mut generator = PaddingRng::from_seed(&SEED);
        let mut buckets = [0_u32; 10];
        for _ in 0..100_000 {
            let value = generator.below(500).expect("generator must not fail");
            buckets[(value / 50) as usize] += 1;
        }

        for bucket in buckets {
            assert!(
                (8_000..12_000).contains(&bucket),
                "padding lengths must stay close to uniform, saw {bucket}"
            );
        }
    }

    #[test]
    fn operating_system_seeding_succeeds() {
        let mut generator = PaddingRng::from_os().expect("system entropy must be available");
        assert!(generator.below(256).expect("generator must not fail") < 256);
    }
}
