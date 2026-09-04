//! x86_64 CPU feature detection.
//!
//! `Features::detect` reads CPUID (and XGETBV where the OSXSAVE bit says it is
//! available). `Features::cached` reads a lazily initialised, process-wide
//! atomic cache instead, so that hot paths (for example a TLS record loop)
//! never pay for repeated detection. Detection is idempotent, so racing
//! initialisations may recompute but can never disagree.
//!
//! The probe is implemented directly rather than via the std-only
//! `is_x86_feature_detected` macro so that this crate stays no_std. The in-crate
//! tests cross-check every flag against that macro.

use core::arch::x86_64::{__cpuid, __cpuid_count};
use core::sync::atomic::{AtomicU32, Ordering};

/// Bit set once the cache has been populated.
const CACHED: u32 = 1 << 31;

const BIT_SHA_NI: u32 = 1 << 0;
const BIT_AES_NI: u32 = 1 << 1;
const BIT_PCLMULQDQ: u32 = 1 << 2;
const BIT_AVX2: u32 = 1 << 3;
const BIT_VAES: u32 = 1 << 4;
const BIT_VPCLMULQDQ: u32 = 1 << 5;
const BIT_AVX512F: u32 = 1 << 6;
const BIT_BMI2: u32 = 1 << 7;
const BIT_ADX: u32 = 1 << 8;

// CPUID leaf 1, ECX.
const LEAF1_ECX_PCLMULQDQ: u32 = 1 << 19;
const LEAF1_ECX_AESNI: u32 = 1 << 25;
const LEAF1_ECX_OSXSAVE: u32 = 1 << 27;

// CPUID leaf 7 sub-leaf 0, EBX.
const LEAF7_EBX_AVX2: u32 = 1 << 5;
const LEAF7_EBX_BMI2: u32 = 1 << 8;
const LEAF7_EBX_AVX512F: u32 = 1 << 16;
const LEAF7_EBX_ADX: u32 = 1 << 19;
const LEAF7_EBX_SHA: u32 = 1 << 29;

// CPUID leaf 7 sub-leaf 0, ECX.
const LEAF7_ECX_VAES: u32 = 1 << 9;
const LEAF7_ECX_VPCLMULQDQ: u32 = 1 << 10;

// XCR0 state bits that the OS must have enabled for each feature class.
const XCR0_SSE: u64 = 1 << 1;
const XCR0_YMM: u64 = 1 << 2;
const XCR0_AVX512: u64 = (1 << 5) | (1 << 6) | (1 << 7);

/// Process-wide feature cache.
static CACHE: AtomicU32 = AtomicU32::new(0);

/// CPU features that this library knows how to use on x86_64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Features {
    bits: u32,
}

impl Features {
    /// Probes the CPU directly.
    ///
    /// Costs several CPUID executions; do not call it in a hot loop, use
    /// `Features::cached` instead.
    #[must_use]
    pub fn detect() -> Self {
        let leaf1 = __cpuid(1);
        let leaf7 = __cpuid_count(7, 0);

        // XGETBV is only executable when the OS has enabled XSAVE, which the
        // OSXSAVE bit reports. Executing it unconditionally would fault on a
        // kernel that has not enabled XSAVE.
        let xcr0 = if leaf1.ecx & LEAF1_ECX_OSXSAVE != 0 {
            // SAFETY: OSXSAVE (CPUID.1:ECX[27]) is set, so the OS has enabled
            // XSAVE and XGETBV is executable at the current privilege level;
            // index 0 (XCR0) is architecturally valid on every x86_64 CPU.
            // XGETBV reads a control register and has no memory effects.
            unsafe { core::arch::x86_64::_xgetbv(0) }
        } else {
            0
        };
        let ymm_enabled = xcr0 & XCR0_SSE != 0 && xcr0 & XCR0_YMM != 0;
        let avx512_enabled = ymm_enabled && xcr0 & XCR0_AVX512 == XCR0_AVX512;

        let mut bits = 0;
        if leaf1.ecx & LEAF1_ECX_PCLMULQDQ != 0 {
            bits |= BIT_PCLMULQDQ;
        }
        if leaf1.ecx & LEAF1_ECX_AESNI != 0 {
            bits |= BIT_AES_NI;
        }
        if leaf7.ebx & LEAF7_EBX_SHA != 0 {
            bits |= BIT_SHA_NI;
        }
        // BMI2 and ADX are general-purpose integer extensions: they use no
        // extended register state, so unlike AVX they need no XCR0 agreement.
        if leaf7.ebx & LEAF7_EBX_BMI2 != 0 {
            bits |= BIT_BMI2;
        }
        if leaf7.ebx & LEAF7_EBX_ADX != 0 {
            bits |= BIT_ADX;
        }
        if leaf7.ebx & LEAF7_EBX_AVX2 != 0 && ymm_enabled {
            bits |= BIT_AVX2;
        }
        if leaf7.ecx & LEAF7_ECX_VAES != 0 && ymm_enabled {
            bits |= BIT_VAES;
        }
        if leaf7.ecx & LEAF7_ECX_VPCLMULQDQ != 0 && ymm_enabled {
            bits |= BIT_VPCLMULQDQ;
        }
        if leaf7.ebx & LEAF7_EBX_AVX512F != 0 && avx512_enabled {
            bits |= BIT_AVX512F;
        }
        Self { bits }
    }

    /// Returns the cached feature set, probing at most once per process.
    ///
    /// Concurrent callers may each perform the probe; the result is identical,
    /// so the race is benign and no initialisation flag is needed.
    #[must_use]
    pub fn cached() -> Self {
        let v = CACHE.load(Ordering::Relaxed);
        if v & CACHED != 0 {
            return Self { bits: v & !CACHED };
        }
        let f = Self::detect();
        CACHE.store(f.bits | CACHED, Ordering::Relaxed);
        f
    }

    /// Clears the cache. Only useful for tests that want to re-detect.
    pub fn reset_cache() {
        CACHE.store(0, Ordering::Relaxed);
    }

    /// Intel SHA Extensions (SHA-1 and SHA-256 round instructions).
    #[must_use]
    pub const fn sha_ni(&self) -> bool {
        self.bits & BIT_SHA_NI != 0
    }

    /// AES-NI (AESENC/AESDEC and friends).
    #[must_use]
    pub const fn aes_ni(&self) -> bool {
        self.bits & BIT_AES_NI != 0
    }

    /// Carry-less multiplication, needed for GHASH.
    #[must_use]
    pub const fn pclmulqdq(&self) -> bool {
        self.bits & BIT_PCLMULQDQ != 0
    }

    /// AVX2 (256-bit integer vectors).
    #[must_use]
    pub const fn avx2(&self) -> bool {
        self.bits & BIT_AVX2 != 0
    }

    /// VAES (vectorised AES).
    #[must_use]
    pub const fn vaes(&self) -> bool {
        self.bits & BIT_VAES != 0
    }

    /// VPCLMULQDQ (vectorised carry-less multiplication).
    #[must_use]
    pub const fn vpclmulqdq(&self) -> bool {
        self.bits & BIT_VPCLMULQDQ != 0
    }

    /// AVX-512F (512-bit vectors, foundation).
    #[must_use]
    pub const fn avx512f(&self) -> bool {
        self.bits & BIT_AVX512F != 0
    }

    /// BMI2 (`MULX` and the flag-free shifts).
    #[must_use]
    pub const fn bmi2(&self) -> bool {
        self.bits & BIT_BMI2 != 0
    }

    /// ADX (`ADCX`/`ADOX`, two independent carry chains).
    #[must_use]
    pub const fn adx(&self) -> bool {
        self.bits & BIT_ADX != 0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{CACHED, Features};

    /// Cross-check every flag against the std-provided detector, which is the
    /// reference implementation for x86_64 feature probing.
    #[test]
    fn matches_std_feature_detection() {
        let f = Features::detect();
        assert_eq!(f.sha_ni(), std::arch::is_x86_feature_detected!("sha"));
        assert_eq!(f.aes_ni(), std::arch::is_x86_feature_detected!("aes"));
        assert_eq!(
            f.pclmulqdq(),
            std::arch::is_x86_feature_detected!("pclmulqdq")
        );
        assert_eq!(f.avx2(), std::arch::is_x86_feature_detected!("avx2"));
        assert_eq!(f.vaes(), std::arch::is_x86_feature_detected!("vaes"));
        assert_eq!(
            f.vpclmulqdq(),
            std::arch::is_x86_feature_detected!("vpclmulqdq")
        );
        assert_eq!(f.avx512f(), std::arch::is_x86_feature_detected!("avx512f"));
        assert_eq!(f.bmi2(), std::arch::is_x86_feature_detected!("bmi2"));
        assert_eq!(f.adx(), std::arch::is_x86_feature_detected!("adx"));
    }

    #[test]
    fn detect_is_idempotent() {
        assert_eq!(Features::detect(), Features::detect());
    }

    #[test]
    fn cached_agrees_with_detect() {
        Features::reset_cache();
        assert_eq!(Features::cached(), Features::detect());
        // Second call must come from the cache and still agree.
        assert_eq!(Features::cached(), Features::detect());
    }

    #[test]
    fn reset_cache_forces_redetection() {
        Features::reset_cache();
        let first = Features::cached();
        Features::reset_cache();
        assert_eq!(Features::cached(), first);
    }

    #[test]
    fn cached_bit_is_not_leaked_into_features() {
        let f = Features::cached();
        assert_eq!(f.bits & CACHED, 0);
    }

    /// Prints the probe result so that a failing run carries the CPU context;
    /// visible with cargo test -- --nocapture.
    #[test]
    fn print_features() {
        let f = Features::cached();
        std::eprintln!(
            "x86_64 features: sha_ni={} aes_ni={} pclmulqdq={} avx2={} vaes={} vpclmulqdq={} avx512f={}",
            f.sha_ni(),
            f.aes_ni(),
            f.pclmulqdq(),
            f.avx2(),
            f.vaes(),
            f.vpclmulqdq(),
            f.avx512f()
        );
    }
}
