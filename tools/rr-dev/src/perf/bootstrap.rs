//! Deterministic block bootstrap, bit-compatible with the Python evaluator.
//!
//! The interval this module produces is **reporting only**. The evidence schema
//! labels it `"deterministic 95% block bootstrap (reporting only)"`, and no verdict
//! consults it: `PASS` and `REGRESSION` come from the exact sign-flip test and Holm
//! correction in [`super::stats`], both of which are fully deterministic and use no
//! random numbers at all.
//!
//! That distinction is worth stating plainly, because it sets how much of this
//! module is load-bearing. Reproducing Python's Mersenne Twister is **not** needed
//! for decision parity. It is needed so a report regenerated from preserved
//! evidence still matches the interval recorded at the time, which is what keeps
//! historical gate artifacts comparable.
//!
//! Reproducing it requires matching three things exactly:
//!
//! 1. `MT19937` seeded the way `CPython` seeds an integer, via `init_by_array` over the
//!    seed's 32-bit little-endian words.
//! 2. `random()`, which `CPython` builds from two tempered outputs as
//!    `(a >> 5) * 2^26 + (b >> 6)` scaled by `2^-53`.
//! 3. `random.choices(population, k)` without weights, which indexes with
//!    `floor(random() * len(population))` — not the rejection-sampling path used by
//!    `randrange`.

use super::stats::{StatsError, median};

/// The number of resamples the evaluator's method block records.
///
/// Retained as the documented default even though callers now read the value from
/// the manifest, because the percentile-index tests pin their arithmetic to it.
#[cfg(test)]
pub const DEFAULT_ITERATIONS: usize = 20_000;

/// `CPython`'s `random.Random`, restricted to what the bootstrap needs.
///
/// Only the integer-seeded construction and `random()` are implemented, because
/// those are the only entry points the evaluator uses.
pub struct PythonRandom {
    state: [u32; 624],
    index: usize,
}

impl PythonRandom {
    /// Seeds the generator the way `random.Random(n)` seeds an integer.
    ///
    /// `CPython` converts the absolute value of the integer into little-endian 32-bit
    /// words and calls `init_by_array`. A zero seed yields a single zero word rather
    /// than an empty key.
    #[must_use]
    pub fn seeded(seed: u64) -> Self {
        let mut key = Vec::new();
        let mut remaining = seed;
        if remaining == 0 {
            key.push(0);
        }
        while remaining > 0 {
            #[allow(
                clippy::cast_possible_truncation,
                reason = "the mask keeps exactly the low 32 bits"
            )]
            key.push((remaining & 0xffff_ffff) as u32);
            remaining >>= 32;
        }
        let mut generator = Self {
            state: [0; 624],
            index: 625,
        };
        generator.init_by_array(&key);
        generator
    }

    fn init_genrand(&mut self, seed: u32) {
        self.state[0] = seed;
        for index in 1..624 {
            let previous = self.state[index - 1];
            #[expect(
                clippy::cast_possible_truncation,
                reason = "the arithmetic is defined modulo 2^32"
            )]
            let next = 1_812_433_253_u32
                .wrapping_mul(previous ^ (previous >> 30))
                .wrapping_add(index as u32);
            self.state[index] = next;
        }
        self.index = 624;
    }

    fn init_by_array(&mut self, key: &[u32]) {
        self.init_genrand(19_650_218);
        let mut i = 1_usize;
        let mut j = 0_usize;
        let mut k = 624.max(key.len());
        while k > 0 {
            let previous = self.state[i - 1];
            self.state[i] = (self.state[i] ^ (previous ^ (previous >> 30)).wrapping_mul(1_664_525))
                .wrapping_add(key[j])
                .wrapping_add(
                    #[expect(
                        clippy::cast_possible_truncation,
                        reason = "j is bounded by the key length"
                    )]
                    {
                        j as u32
                    },
                );
            i += 1;
            j += 1;
            if i >= 624 {
                self.state[0] = self.state[623];
                i = 1;
            }
            if j >= key.len() {
                j = 0;
            }
            k -= 1;
        }
        let mut k = 623;
        while k > 0 {
            let previous = self.state[i - 1];
            self.state[i] = (self.state[i]
                ^ (previous ^ (previous >> 30)).wrapping_mul(1_566_083_941))
            .wrapping_sub(
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "i is bounded by the state length"
                )]
                {
                    i as u32
                },
            );
            i += 1;
            if i >= 624 {
                self.state[0] = self.state[623];
                i = 1;
            }
            k -= 1;
        }
        self.state[0] = 0x8000_0000;
        self.index = 624;
    }

    fn generate(&mut self) {
        const UPPER_MASK: u32 = 0x8000_0000;
        const LOWER_MASK: u32 = 0x7fff_ffff;
        const MATRIX: u32 = 0x9908_b0df;
        for index in 0..624 {
            let y = (self.state[index] & UPPER_MASK) | (self.state[(index + 1) % 624] & LOWER_MASK);
            let mut next = self.state[(index + 397) % 624] ^ (y >> 1);
            if y & 1 != 0 {
                next ^= MATRIX;
            }
            self.state[index] = next;
        }
        self.index = 0;
    }

    /// Returns the next tempered 32-bit output.
    fn next_u32(&mut self) -> u32 {
        if self.index >= 624 {
            self.generate();
        }
        let mut y = self.state[self.index];
        self.index += 1;
        y ^= y >> 11;
        y ^= (y << 7) & 0x9d2c_5680;
        y ^= (y << 15) & 0xefc6_0000;
        y ^= y >> 18;
        y
    }

    /// Returns the next float in `[0, 1)`, matching `CPython`'s `random()`.
    ///
    /// `CPython` composes 53 bits of randomness from two tempered words, taking the
    /// high 27 bits of the first and the high 26 of the second.
    pub fn random(&mut self) -> f64 {
        let a = self.next_u32() >> 5;
        let b = self.next_u32() >> 6;
        (f64::from(a) * 67_108_864.0 + f64::from(b)) * (1.0 / 9_007_199_254_740_992.0)
    }

    /// Draws `count` values with replacement, matching `random.choices`.
    ///
    /// The unweighted path in `CPython` indexes with `floor(random() * n)` where `n`
    /// has been converted to a float. It deliberately does not use the
    /// rejection-sampling `_randbelow` that `randrange` uses, so the stream of
    /// consumed random values differs between the two — which is why this must
    /// mirror `choices` specifically.
    pub fn choices(&mut self, population: &[f64], count: usize) -> Vec<f64> {
        #[expect(
            clippy::cast_precision_loss,
            reason = "block counts are tiny, exactly representable"
        )]
        let length = population.len() as f64;
        (0..count)
            .map(|_| {
                #[expect(
                    clippy::cast_possible_truncation,
                    clippy::cast_sign_loss,
                    reason = "random() < 1 so the product is below the population length"
                )]
                let index = (self.random() * length).floor() as usize;
                population[index.min(population.len() - 1)]
            })
            .collect()
    }
}

/// Derives the evaluator's per-metric seed from a label.
///
/// The seed is the first eight bytes of `sha256(label)` read big-endian, so the
/// interval for one metric is stable across runs and independent of every other
/// metric — the property that makes the interval "deterministic" despite being a
/// resampling procedure.
#[must_use]
pub fn seed_from_label(label: &str) -> u64 {
    let digest = sha256(label.as_bytes());
    u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ])
}

/// The deterministic 95% block-bootstrap interval, for reporting.
///
/// Percentile indices are taken exactly as the original does: the lower bound is
/// element `iterations / 40` and the upper is `(iterations * 39) / 40 - 1` of the
/// sorted resample medians.
///
/// # Errors
///
/// Returns [`StatsError::BootstrapSample`] with fewer than three blocks, matching
/// the original's refusal to interval-estimate from almost no data.
pub fn interval(label: &str, ratios: &[f64], iterations: usize) -> Result<[f64; 2], StatsError> {
    interval_with_seed(seed_from_label(label), label, ratios, iterations)
}

/// The same interval, with the seed supplied directly.
///
/// The evaluator derives its seed from a metric label, but the ABBA benchmark
/// harnesses seed with a literal integer instead — `random.Random(0x464200 + conc)`
/// and `random.Random(0x4642C0)` in `benchmark-fallback-ab.sh`, `0x525200 + conc`
/// and `0x5252C0` in `benchmark-setup-rate.sh`. Their archived `summary.json`
/// intervals only reproduce when the generator is seeded with that exact integer,
/// so the seed is an input here rather than something derived from a name.
///
/// `label` names the metric in the error only.
///
/// # Errors
///
/// Returns [`StatsError::BootstrapSample`] with fewer than three blocks.
pub fn interval_with_seed(
    seed: u64,
    label: &str,
    ratios: &[f64],
    iterations: usize,
) -> Result<[f64; 2], StatsError> {
    if ratios.len() < 3 {
        return Err(StatsError::BootstrapSample {
            metric: label.to_owned(),
            found: ratios.len(),
        });
    }
    let mut generator = PythonRandom::seeded(seed);
    let mut medians = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let resample = generator.choices(ratios, ratios.len());
        medians.push(median(&resample)?);
    }
    medians.sort_unstable_by(f64::total_cmp);
    Ok([
        medians[iterations / 40],
        medians[(iterations * 39) / 40 - 1],
    ])
}

/// A minimal `SHA-256`, used only to derive the bootstrap seed.
///
/// The evaluator needs one digest of a short metric label. Pulling a hashing crate
/// into the tooling workspace for that would add a dependency without adding
/// safety, and this implementation is checked against published test vectors.
/// `SHA-256` round constants.
const SHA256_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// A minimal `SHA-256`, used only to derive the bootstrap seed.
///
/// The evaluator needs one digest of a short metric label. Pulling a hashing crate
/// into the tooling workspace for that would add a dependency without adding
/// safety, and this implementation is checked against published test vectors.
#[must_use]
pub fn sha256(message: &[u8]) -> [u8; 32] {
    let mut hash: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];

    let mut padded = message.to_vec();
    let bit_length = (message.len() as u64) * 8;
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_length.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        compress(&mut hash, chunk);
    }

    let mut digest = [0_u8; 32];
    for (index, word) in hash.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// One `SHA-256` compression round over a 64-byte block.
fn compress(hash: &mut [u32; 8], chunk: &[u8]) {
    let mut w = [0_u32; 64];
    for (index, word) in chunk.chunks_exact(4).enumerate() {
        w[index] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
    }
    for index in 16..64 {
        let s0 =
            w[index - 15].rotate_right(7) ^ w[index - 15].rotate_right(18) ^ (w[index - 15] >> 3);
        let s1 =
            w[index - 2].rotate_right(17) ^ w[index - 2].rotate_right(19) ^ (w[index - 2] >> 10);
        w[index] = w[index - 16]
            .wrapping_add(s0)
            .wrapping_add(w[index - 7])
            .wrapping_add(s1);
    }

    let mut v = *hash;
    for index in 0..64 {
        let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
        let choose = (v[4] & v[5]) ^ (!v[4] & v[6]);
        let temp1 = v[7]
            .wrapping_add(s1)
            .wrapping_add(choose)
            .wrapping_add(SHA256_K[index])
            .wrapping_add(w[index]);
        let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
        let majority = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
        let temp2 = s0.wrapping_add(majority);
        v[7] = v[6];
        v[6] = v[5];
        v[5] = v[4];
        v[4] = v[3].wrapping_add(temp1);
        v[3] = v[2];
        v[2] = v[1];
        v[1] = v[0];
        v[0] = temp1.wrapping_add(temp2);
    }
    for (slot, value) in hash.iter_mut().zip(v) {
        *slot = slot.wrapping_add(value);
    }
}

#[cfg(test)]
#[expect(
    clippy::float_cmp,
    reason = "these are golden-parity tests: bit-exact comparison against recorded \
              evidence is the property under test, so an epsilon would defeat them"
)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        })
    }

    #[test]
    fn sha256_matches_published_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // Long enough to require a second compression block.
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn the_mersenne_twister_matches_cpython_for_a_known_seed() {
        // Reference from CPython:
        //   r = random.Random(42); [r.random() for _ in range(5)]
        let mut generator = PythonRandom::seeded(42);
        let observed: Vec<f64> = (0..5).map(|_| generator.random()).collect();
        assert_eq!(
            observed,
            vec![
                0.639_426_798_457_883_7,
                0.025_010_755_222_666_936,
                0.275_029_318_369_119_26,
                0.223_210_738_148_822_75,
                0.736_471_214_164_012_4,
            ],
            "the generator must reproduce CPython's stream exactly"
        );
    }

    #[test]
    fn choices_indexes_with_floor_of_the_scaled_float() {
        // Reference from CPython:
        //   r = random.Random(7); r.choices([0.0,1.0,2.0,3.0], k=8)
        let mut generator = PythonRandom::seeded(7);
        let drawn = generator.choices(&[0.0, 1.0, 2.0, 3.0], 8);
        assert_eq!(
            drawn,
            vec![1.0, 0.0, 2.0, 0.0, 2.0, 1.0, 0.0, 2.0],
            "choices must consume the stream the same way CPython does"
        );
    }

    #[test]
    fn the_seed_is_the_leading_eight_digest_bytes_big_endian() {
        let digest = sha256(b"setup:c1:throughput");
        let expected = u64::from_be_bytes([
            digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
        ]);
        assert_eq!(seed_from_label("setup:c1:throughput"), expected);
    }

    #[test]
    fn the_interval_is_deterministic_across_calls() {
        let ratios = vec![
            1.0, 1.01, 0.99, 1.02, 0.98, 1.005, 0.995, 1.03, 0.97, 1.0, 1.01, 0.99,
        ];
        let first = interval("metric", &ratios, 2_000).expect("enough blocks");
        let second = interval("metric", &ratios, 2_000).expect("enough blocks");
        // Exact equality is the point: a deterministic procedure must return the
        // identical pair of bounds, not merely close ones.
        assert_eq!(first, second, "the same label must reproduce the interval");
    }

    #[test]
    fn different_labels_seed_different_streams() {
        // Asserting that two labels produce different *intervals* is a weak test:
        // resample medians over a dozen blocks are heavily quantised, so two
        // streams can legitimately agree. The property that actually matters is
        // that the seeds differ, which is what decorrelates the streams.
        let left = seed_from_label("metric-a");
        let right = seed_from_label("metric-b");
        assert_ne!(left, right, "per-metric seeding must differ by label");

        let mut first = PythonRandom::seeded(left);
        let mut second = PythonRandom::seeded(right);
        let a: Vec<f64> = (0..8).map(|_| first.random()).collect();
        let b: Vec<f64> = (0..8).map(|_| second.random()).collect();
        assert_ne!(a, b, "different seeds must yield different streams");
    }

    #[test]
    fn the_interval_brackets_the_median() {
        let ratios = vec![
            1.0, 1.01, 0.99, 1.02, 0.98, 1.005, 0.995, 1.03, 0.97, 1.0, 1.01, 0.99,
        ];
        let bounds = interval("m", &ratios, 4_000).expect("ok");
        let point = median(&ratios).expect("non-empty");
        assert!(
            bounds[0] <= point && point <= bounds[1],
            "the reported interval must contain the point estimate: {bounds:?} vs {point}"
        );
    }

    #[test]
    fn fewer_than_three_blocks_fails_closed() {
        assert!(matches!(
            interval("m", &[1.0, 1.0], 100),
            Err(StatsError::BootstrapSample { found: 2, .. })
        ));
    }

    #[test]
    fn a_recorded_gate_interval_replays_bit_for_bit() {
        // Golden data from artifacts/v180-release-gate/gates/evaluation-r01.json,
        // metric `matrix-c1:direct-upload_32_1:p99-latency`. The recorded interval
        // was produced by the Python evaluator at release time; reproducing it here
        // is what keeps historical gate reports comparable after the migration.
        let ratios = vec![
            1.010_752_480_599_204_8,
            1.002_100_273_887_067_7,
            1.295_504_478_004_131_2,
            0.840_590_560_783_179_4,
            1.144_003_999_294_242_1,
            0.997_321_357_707_876,
            0.988_555_785_791_684_9,
            1.095_088_664_311_070_4,
            1.009_385_513_414_038,
            1.140_572_764_312_578_3,
            1.046_156_422_709_764,
            1.229_912_065_504_826_8,
        ];
        let bounds = interval(
            "matrix-c1:direct-upload_32_1:p99-latency",
            &ratios,
            DEFAULT_ITERATIONS,
        )
        .expect("twelve blocks is enough");
        assert_eq!(
            bounds,
            [0.999_710_815_797_471_9, 1.142_288_381_803_410_2],
            "the recorded bootstrap95 must be reproduced exactly"
        );
    }

    #[test]
    fn the_percentile_indices_follow_the_original_formula() {
        // With 20000 iterations the bounds are elements 500 and 19499.
        assert_eq!(DEFAULT_ITERATIONS / 40, 500);
        assert_eq!((DEFAULT_ITERATIONS * 39) / 40 - 1, 19_499);
    }

    /// The ABBA harnesses seed with a literal integer, so the resample stream for
    /// those exact seeds must match `CPython`. References from:
    ///   `random.Random(0x4642C0).choices([0.0..6.0], k=7)`
    ///   `random.Random(0x525201).choices([0.0..6.0], k=7)`
    #[test]
    fn the_legacy_integer_seeds_reproduce_the_cpython_stream() {
        let population = [0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0];
        assert_eq!(
            PythonRandom::seeded(0x0046_42C0).choices(&population, 7),
            [1.0, 0.0, 2.0, 4.0, 5.0, 4.0, 3.0],
            "benchmark-fallback-ab.sh CPU seed 0x4642C0"
        );
        assert_eq!(
            PythonRandom::seeded(0x0052_5201).choices(&population, 7),
            [5.0, 3.0, 6.0, 2.0, 5.0, 3.0, 1.0],
            "benchmark-setup-rate.sh concurrency-1 seed 0x525200 + 1"
        );
    }

    /// The interval must follow the supplied integer seed, not a label digest.
    /// References computed with the legacy expression at 200 iterations, where the
    /// empirical distribution has not yet converged and the seeds are separable:
    ///   `sorted(median(Random(s).choices(r, k=len(r))) for _ in range(200))[5], [194]`
    #[test]
    fn an_integer_seeded_interval_follows_that_seed() {
        let ratios = [0.80, 0.88, 0.95, 1.00, 1.06, 1.14, 1.25];
        assert_eq!(
            interval_with_seed(0x0052_52C0, "setup-rate:cpu", &ratios, 200).unwrap(),
            [0.88, 1.25],
            "benchmark-setup-rate.sh CPU seed 0x5252C0"
        );
        assert_eq!(
            interval_with_seed(0x0052_5201, "setup-rate:c1", &ratios, 200).unwrap(),
            [0.80, 1.14],
            "benchmark-setup-rate.sh concurrency-1 seed"
        );
        assert_eq!(
            interval_with_seed(0x0046_42C0, "fallback:cpu", &ratios, 200).unwrap(),
            [0.88, 1.14],
            "benchmark-fallback-ab.sh CPU seed 0x4642C0"
        );
    }

    /// The label-seeded entry point is the same procedure with a derived seed, so
    /// the evaluator's recorded intervals cannot drift from this refactoring.
    #[test]
    fn the_label_interval_delegates_to_the_seeded_one() {
        let ratios = [0.9, 0.95, 1.0, 1.05, 1.1];
        let label = "matrix-c1:direct-upload_32_1:p99-latency";
        assert_eq!(
            interval(label, &ratios, 2_000).unwrap(),
            interval_with_seed(seed_from_label(label), label, &ratios, 2_000).unwrap()
        );
    }

    #[test]
    fn a_seeded_interval_still_refuses_fewer_than_three_blocks() {
        assert!(interval_with_seed(0x0046_42C0, "fallback:cpu", &[1.0, 1.1], 200).is_err());
    }
}
