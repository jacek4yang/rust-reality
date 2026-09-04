//! X25519 on AArch64, computed by s2n-bignum's assembly.
//!
//! The AArch64 counterpart of `fastcrypto-x86`'s import, and it exists for the
//! same reason: rust-reality ships an `aarch64-unknown-linux-gnu` release, and
//! `aws-lc-rs` cannot be removed from its dependency graph while X25519 on that
//! target still needs it. Porting x86_64 alone would not simplify anything — it
//! would leave the ~2.6 MB vendored C libcrypto and its `CMake` build in place for
//! every architecture.
//!
//! Provenance, the pinned revision and the exact transformation are recorded in
//! `docs/PROVENANCE.md`. Note that the AArch64 routines have a longer
//! attribution chain than the x86_64 ones: upstream states they are
//! substantially derived from Emil Lenngren's X25519-AArch64 (CC0-1.0) and from
//! the SLOTHY re-scheduling of it (MIT). Both are permissive; the chain is
//! recorded rather than collapsed into "Apache-2.0".
//!
//! # Contract of the imported routines
//!
//! Identical to the x86_64 import: little-endian 32-byte encodings in and out,
//! the scalar is clamped internally per RFC 7748, and the RFC 7748 section 6.1
//! zero check is **not** performed — a non-contributory peer share produces an
//! all-zero output that the caller must reject.
//!
//! ABI: AAPCS64. `X0` = result, `X1` = scalar, `X2` = point; no return value;
//! callee-saved registers and the stack frame are the routine's own; inputs and
//! outputs may not overlap.
//!
//! The committed assembly emits ELF directives, so this module is gated to
//! AArch64 **Linux**, which is rust-reality's whole ARM release matrix.
//!
//! # Dispatch
//!
//! Unlike x86_64, **both variants run on every ARMv8 CPU** — neither needs an
//! optional instruction. The choice is purely about multiplier throughput: the
//! `_alt` routines win on cores with a wide multiplier, and lose on the rest.
//!
//! The probe therefore mirrors AWS-LC's `use_s2n_bignum_alt()` exactly: read
//! `MIDR_EL1` and select `_alt` for Neoverse V1, V2 and V3. AWS-LC also selects
//! it for Apple silicon, but only through a macOS `sysctl` path; it does *not*
//! detect Apple parts by MIDR on Linux, and neither does this, because adding a
//! rule this repository cannot test would be guesswork rather than parity.
//!
//! If the probe is unavailable the standard routines are used. That is always
//! correct — the worst case is leaving throughput on the table on a core we
//! failed to recognise, never an illegal instruction.

use core::arch::{asm, global_asm};
use core::sync::atomic::{AtomicU32, Ordering};

global_asm!(include_str!("aarch64/curve25519_x25519_byte.s"));
global_asm!(include_str!("aarch64/curve25519_x25519_byte_alt.s"));
global_asm!(include_str!("aarch64/curve25519_x25519base_byte.s"));
global_asm!(include_str!("aarch64/curve25519_x25519base_byte_alt.s"));

unsafe extern "C" {
    /// s2n-bignum `curve25519_x25519_byte`.
    fn rr_crypto_curve25519_x25519_byte(res: *mut u8, scalar: *const u8, point: *const u8);
    /// s2n-bignum `curve25519_x25519_byte_alt`.
    fn rr_crypto_curve25519_x25519_byte_alt(res: *mut u8, scalar: *const u8, point: *const u8);
    /// s2n-bignum `curve25519_x25519base_byte`.
    fn rr_crypto_curve25519_x25519base_byte(res: *mut u8, scalar: *const u8);
    /// s2n-bignum `curve25519_x25519base_byte_alt`.
    fn rr_crypto_curve25519_x25519base_byte_alt(res: *mut u8, scalar: *const u8);

    /// glibc/musl `getauxval`, used to read `AT_HWCAP`.
    ///
    /// Declared rather than taken from a crate so that this stays `no_std` and
    /// dependency-free. Every supported AArch64 Linux target links a libc that
    /// provides it.
    fn getauxval(kind: core::ffi::c_ulong) -> core::ffi::c_ulong;
}

/// `AT_HWCAP`, from `<elf.h>`.
const AT_HWCAP: core::ffi::c_ulong = 16;
/// `HWCAP_CPUID`: the kernel emulates `MRS` reads of the ID registers.
const HWCAP_CPUID: core::ffi::c_ulong = 1 << 11;

/// `MIDR_EL1` implementer field, bits 31:24.
const MIDR_IMPLEMENTER_SHIFT: u64 = 24;
/// `MIDR_EL1` part-number field, bits 15:4.
const MIDR_PARTNUM_SHIFT: u64 = 4;
/// Implementer 0x41: Arm Limited.
const IMPLEMENTER_ARM: u64 = 0x41;
/// Part numbers whose multiplier the `_alt` routines are tuned for.
const WIDE_MULTIPLIER_PARTS: [u64; 3] = [
    0xd40, // Neoverse V1
    0xd4f, // Neoverse V2
    0xd84, // Neoverse V3
];

/// Bit set once the cache has been populated.
const CACHED: u32 = 1 << 31;
/// Bit meaning "this CPU wants the `_alt` routines".
const BIT_WIDE_MULTIPLIER: u32 = 1 << 0;

/// Process-wide dispatch cache.
static CACHE: AtomicU32 = AtomicU32::new(0);

/// Which of the two compiled implementations this machine runs.
///
/// Reporting and testing only. Both variants compute the same function, both
/// run on every ARMv8 CPU, and a caller must never branch on this for
/// correctness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Variant {
    /// The routines tuned for a standard multiplier.
    Standard,
    /// The `_alt` routines, tuned for a wide multiplier.
    WideMultiplier,
}

impl Variant {
    /// Stable name for benchmark output and bug reports.
    #[must_use]
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Standard => "s2n-bignum-standard",
            Self::WideMultiplier => "s2n-bignum-wide-multiplier",
        }
    }
}

/// Reads `MIDR_EL1` and decides which variant this core prefers.
///
/// Costs one `getauxval` and one emulated register read; use [`variant`], which
/// caches.
#[must_use]
pub(crate) fn detect() -> Variant {
    // SAFETY: `getauxval` takes and returns an integer, touches no memory the
    // caller owns, and is provided by the libc every supported AArch64 Linux
    // target links.
    let hwcap = unsafe { getauxval(AT_HWCAP) };
    if hwcap & HWCAP_CPUID == 0 {
        // Without the kernel's ID-register emulation the `MRS` below would
        // fault, so stop here. Valgrind also reports the bit as absent, which
        // is exactly the behaviour wanted.
        return Variant::Standard;
    }

    let midr: u64;
    // SAFETY: `HWCAP_CPUID` is set, so the kernel emulates EL0 reads of the ID
    // registers and this instruction cannot fault. It reads a register, has no
    // memory operands and no side effects.
    unsafe {
        asm!("mrs {midr}, midr_el1", midr = out(reg) midr, options(nomem, nostack, preserves_flags));
    }

    let implementer = (midr >> MIDR_IMPLEMENTER_SHIFT) & 0xff;
    let part = (midr >> MIDR_PARTNUM_SHIFT) & 0xfff;
    if implementer == IMPLEMENTER_ARM && WIDE_MULTIPLIER_PARTS.contains(&part) {
        Variant::WideMultiplier
    } else {
        Variant::Standard
    }
}

/// The variant this machine dispatches to, probing at most once per process.
///
/// Concurrent callers may each probe; the result is identical, so the race is
/// benign and no initialisation flag is needed.
#[must_use]
pub(crate) fn variant() -> Variant {
    let cached = CACHE.load(Ordering::Relaxed);
    if cached & CACHED != 0 {
        return if cached & BIT_WIDE_MULTIPLIER == 0 {
            Variant::Standard
        } else {
            Variant::WideMultiplier
        };
    }
    let detected = detect();
    let bits = match detected {
        Variant::Standard => 0,
        Variant::WideMultiplier => BIT_WIDE_MULTIPLIER,
    };
    CACHE.store(bits | CACHED, Ordering::Relaxed);
    detected
}

/// Clears the dispatch cache. Only useful for tests that want to re-probe.
pub(crate) fn reset_cache() {
    CACHE.store(0, Ordering::Relaxed);
}

/// Computes the X25519 function: the u-coordinate of `scalar * point`.
///
/// `scalar` is clamped by the implementation. An all-zero `out` means the peer
/// share was non-contributory and the caller must reject it — this function
/// does not.
pub(crate) fn x25519(out: &mut [u8; 32], scalar: &[u8; 32], point: &[u8; 32]) {
    // SAFETY: all three pointers address distinct 32-byte objects the borrow
    // checker proves are live and non-overlapping for this call (`out` is a
    // unique borrow, the inputs are shared borrows). The routine writes exactly
    // 32 bytes through `res`, reads exactly 32 through each input, and manages
    // its own frame and callee-saved registers. Both variants execute on every
    // ARMv8 CPU, so the selection carries no feature precondition.
    unsafe {
        match variant() {
            Variant::Standard => {
                rr_crypto_curve25519_x25519_byte(out.as_mut_ptr(), scalar.as_ptr(), point.as_ptr());
            }
            Variant::WideMultiplier => {
                rr_crypto_curve25519_x25519_byte_alt(
                    out.as_mut_ptr(),
                    scalar.as_ptr(),
                    point.as_ptr(),
                );
            }
        }
    }
}

/// Computes the X25519 public key for `scalar`: `scalar * G`.
///
/// `scalar` is clamped by the implementation. A dedicated fixed-base routine,
/// not the general function applied to u = 9.
pub(crate) fn x25519_base(out: &mut [u8; 32], scalar: &[u8; 32]) {
    // SAFETY: as for `x25519`, with two distinct live 32-byte objects. The
    // routine also reads its own 48,576-byte read-only precomputed table, which
    // is part of this crate's `.rodata`.
    unsafe {
        match variant() {
            Variant::Standard => {
                rr_crypto_curve25519_x25519base_byte(out.as_mut_ptr(), scalar.as_ptr());
            }
            Variant::WideMultiplier => {
                rr_crypto_curve25519_x25519base_byte_alt(out.as_mut_ptr(), scalar.as_ptr());
            }
        }
    }
}

#[cfg(test)]
/// Computes the X25519 function with the standard-multiplier routine.
///
/// Testing and benchmarking only: it lets both compiled variants be compared on
/// one machine. Production callers use [`x25519`], which dispatches.
pub(crate) fn x25519_standard(out: &mut [u8; 32], scalar: &[u8; 32], point: &[u8; 32]) {
    // SAFETY: pointer contract as in `x25519`; runs on every ARMv8 CPU.
    unsafe { rr_crypto_curve25519_x25519_byte(out.as_mut_ptr(), scalar.as_ptr(), point.as_ptr()) }
}

#[cfg(test)]
/// Computes the X25519 function with the wide-multiplier routine.
///
/// Testing and benchmarking only.
pub(crate) fn x25519_wide_multiplier(out: &mut [u8; 32], scalar: &[u8; 32], point: &[u8; 32]) {
    // SAFETY: pointer contract as in `x25519`; runs on every ARMv8 CPU.
    unsafe {
        rr_crypto_curve25519_x25519_byte_alt(out.as_mut_ptr(), scalar.as_ptr(), point.as_ptr());
    }
}

#[cfg(test)]
/// Computes the X25519 public key with the standard-multiplier routine.
///
/// Testing and benchmarking only.
pub(crate) fn x25519_base_standard(out: &mut [u8; 32], scalar: &[u8; 32]) {
    // SAFETY: pointer contract as in `x25519_base`; runs on every ARMv8 CPU.
    unsafe { rr_crypto_curve25519_x25519base_byte(out.as_mut_ptr(), scalar.as_ptr()) }
}

#[cfg(test)]
/// Computes the X25519 public key with the wide-multiplier routine.
///
/// Testing and benchmarking only.
pub(crate) fn x25519_base_wide_multiplier(out: &mut [u8; 32], scalar: &[u8; 32]) {
    // SAFETY: pointer contract as in `x25519_base`; runs on every ARMv8 CPU.
    unsafe { rr_crypto_curve25519_x25519base_byte_alt(out.as_mut_ptr(), scalar.as_ptr()) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;
    use std::process::Command;
    use std::string::{String, ToString};
    use std::vec::Vec;
    use std::{fs, println};

    use super::{
        Variant, detect, reset_cache, variant, x25519, x25519_base, x25519_base_standard,
        x25519_base_wide_multiplier, x25519_standard, x25519_wide_multiplier,
    };

    fn hex32(text: &str) -> [u8; 32] {
        let mut out = [0_u8; 32];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("hex digit");
        }
        out
    }

    fn hex(bytes: &[u8; 32]) -> String {
        let mut out = String::new();
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    type Agree = fn(&mut [u8; 32], &[u8; 32], &[u8; 32]);
    type Base = fn(&mut [u8; 32], &[u8; 32]);

    /// Both variants, always. Unlike x86_64 there is no feature gate: every
    /// ARMv8 CPU can execute either, so neither is ever untested here.
    const VARIANTS: [(Agree, Base); 2] = [
        (x25519_standard, x25519_base_standard),
        (x25519_wide_multiplier, x25519_base_wide_multiplier),
    ];

    fn for_each_variant(mut body: impl FnMut(Agree, Base)) {
        for (agree, base) in VARIANTS {
            body(agree, base);
        }
    }

    #[test]
    fn rfc7748_section_5_2_vectors_hold() {
        let cases = [
            (
                "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
                "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
                "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
            ),
            (
                "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
                "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
                "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
            ),
        ];
        for (scalar, point, expected) in cases {
            for_each_variant(|agree, _| {
                let mut out = [0_u8; 32];
                agree(&mut out, &hex32(scalar), &hex32(point));
                assert_eq!(hex(&out), expected);
            });
        }
    }

    #[test]
    fn rfc7748_section_6_1_key_exchange_holds() {
        let alice = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_public =
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a".to_string();
        let bob = hex32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_public =
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f".to_string();
        let shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

        for_each_variant(|agree, base| {
            let mut public = [0_u8; 32];
            base(&mut public, &alice);
            assert_eq!(hex(&public), alice_public);
            base(&mut public, &bob);
            assert_eq!(hex(&public), bob_public);

            let mut secret = [0_u8; 32];
            agree(&mut secret, &alice, &hex32(&bob_public));
            assert_eq!(hex(&secret), shared);
            agree(&mut secret, &bob, &hex32(&alice_public));
            assert_eq!(hex(&secret), shared);
        });
    }

    /// RFC 7748 section 5.2's iterated test, one and one thousand rounds — the
    /// vector that catches carry-propagation and reduction bugs.
    #[test]
    fn rfc7748_iterated_vectors_hold() {
        for_each_variant(|agree, _| {
            let mut k = hex32("0900000000000000000000000000000000000000000000000000000000000000");
            let mut u = k;
            for round in 1..=1000 {
                let mut out = [0_u8; 32];
                agree(&mut out, &k, &u);
                u = k;
                k = out;
                if round == 1 {
                    assert_eq!(
                        hex(&k),
                        "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"
                    );
                }
            }
            assert_eq!(
                hex(&k),
                "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"
            );
        });
    }

    #[test]
    fn the_assembly_clamps_the_scalar_itself() {
        let raw = hex32("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");
        let mut clamped = raw;
        clamped[0] &= 248;
        clamped[31] &= 127;
        clamped[31] |= 64;
        assert_ne!(raw, clamped, "the fixture must actually need clamping");
        let point = hex32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");

        for_each_variant(|agree, base| {
            let (mut from_raw, mut from_clamped) = ([0_u8; 32], [0_u8; 32]);
            agree(&mut from_raw, &raw, &point);
            agree(&mut from_clamped, &clamped, &point);
            assert_eq!(from_raw, from_clamped);

            base(&mut from_raw, &raw);
            base(&mut from_clamped, &clamped);
            assert_eq!(from_raw, from_clamped);
        });
    }

    #[test]
    fn non_contributory_shares_produce_zero() {
        const SHARES: &[&str] = &[
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ];
        for share in SHARES {
            for_each_variant(|agree, _| {
                let mut out = [0_u8; 32];
                agree(&mut out, &[0x11; 32], &hex32(share));
                assert_eq!(out, [0_u8; 32], "expected a zero secret for {share}");
            });
        }
    }

    /// The two compiled variants are one function, not two.
    #[test]
    fn the_variants_agree_with_each_other() {
        let mut scalar = [0_u8; 32];
        let mut point = [0_u8; 32];
        for round in 0_u8..64 {
            for (index, byte) in scalar.iter_mut().enumerate() {
                #[expect(clippy::cast_possible_truncation, reason = "deliberate byte mixing")]
                {
                    *byte = round.wrapping_mul(31).wrapping_add(index as u8);
                }
            }
            for (index, byte) in point.iter_mut().enumerate() {
                #[expect(clippy::cast_possible_truncation, reason = "deliberate byte mixing")]
                {
                    *byte = round.wrapping_mul(17).wrapping_add((index as u8) << 1);
                }
            }
            let (mut standard, mut wide) = ([0_u8; 32], [0_u8; 32]);
            x25519_standard(&mut standard, &scalar, &point);
            x25519_wide_multiplier(&mut wide, &scalar, &point);
            assert_eq!(
                standard, wide,
                "variable-base disagreement at round {round}"
            );

            x25519_base_standard(&mut standard, &scalar);
            x25519_base_wide_multiplier(&mut wide, &scalar);
            assert_eq!(standard, wide, "fixed-base disagreement at round {round}");
        }
    }

    #[test]
    fn dispatch_matches_the_selected_variant() {
        let scalar = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let point = hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let (mut dispatched, mut direct) = ([0_u8; 32], [0_u8; 32]);

        x25519(&mut dispatched, &scalar, &point);
        match variant() {
            Variant::Standard => x25519_standard(&mut direct, &scalar, &point),
            Variant::WideMultiplier => x25519_wide_multiplier(&mut direct, &scalar, &point),
        }
        assert_eq!(dispatched, direct);

        x25519_base(&mut dispatched, &scalar);
        match variant() {
            Variant::Standard => x25519_base_standard(&mut direct, &scalar),
            Variant::WideMultiplier => x25519_base_wide_multiplier(&mut direct, &scalar),
        }
        assert_eq!(dispatched, direct);
    }

    /// The probe must be stable and must survive a cache reset, and it must
    /// never fault: reaching this assertion at all proves the `HWCAP_CPUID`
    /// guard held on this machine, including under emulation.
    #[test]
    fn the_probe_is_idempotent_and_cached() {
        let probed = detect();
        assert_eq!(probed, detect());
        reset_cache();
        assert_eq!(variant(), probed);
        assert_eq!(variant(), probed);
        println!("aarch64 X25519 variant: {}", probed.name());
    }

    /// The committed `.s` files must be the mechanical macro expansion of the
    /// vendored upstream `.S` files. See the x86_64 module for why every
    /// preprocessor conditional is pinned on the command line, and why this
    /// skips rather than fails when no C preprocessor is present.
    #[test]
    fn regenerating_the_assembly_reproduces_it() {
        if Command::new("cpp").arg("--version").output().is_err() {
            std::eprintln!(
                "skipping: no C preprocessor on PATH. This verifies the vendored \
                 assembly against upstream and is not required to build."
            );
            return;
        }
        const UNITS: &[&str] = &[
            "curve25519_x25519_byte",
            "curve25519_x25519_byte_alt",
            "curve25519_x25519base_byte",
            "curve25519_x25519base_byte_alt",
        ];
        let root = format!("{}/src/x25519/aarch64", env!("CARGO_MANIFEST_DIR"));

        for unit in UNITS {
            let output = Command::new("cpp")
                .args([
                    "-P",
                    "-I",
                    &format!("{root}/upstream"),
                    "-U__APPLE__",
                    "-U__CET__",
                    "-D__ELF__",
                    "-D__linux__",
                    "-DS2N_BN_HIDE_SYMBOLS",
                    &format!("{root}/upstream/{unit}.S"),
                ])
                .output()
                .expect("cpp is on PATH: its absence was checked above");
            assert!(
                output.status.success(),
                "cpp failed for {unit}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let expanded = String::from_utf8(output.stdout).expect("cpp emitted non-UTF-8");
            let regenerated = prefix_exported_symbols(&expanded);
            let committed =
                fs::read_to_string(format!("{root}/{unit}.s")).expect("committed assembly");

            let (expected, actual) = (
                significant_lines(&regenerated),
                significant_lines(&committed),
            );
            if let Some((line, (from_upstream, from_tree))) = expected
                .iter()
                .zip(actual.iter())
                .enumerate()
                .find(|(_, (a, b))| a != b)
            {
                panic!(
                    "{unit}.s line {} is not what upstream/{unit}.S expands to\n\
                     upstream: {from_upstream}\n\
                     in tree:  {from_tree}",
                    line + 1
                );
            }
            assert_eq!(
                expected.len(),
                actual.len(),
                "{unit}.s has {} significant lines, upstream expands to {}",
                actual.len(),
                expected.len()
            );
        }
    }

    fn significant_lines(text: &str) -> Vec<&str> {
        text.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect()
    }

    fn prefix_exported_symbols(text: &str) -> String {
        const NEEDLE: &str = "curve25519_";
        let mut out = String::with_capacity(text.len() + text.len() / 16);
        let mut rest = text;
        let mut consumed = 0;
        while let Some(offset) = rest.find(NEEDLE) {
            let preceded_by_word_character = text[..consumed + offset]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_');
            out.push_str(&rest[..offset]);
            if !preceded_by_word_character {
                out.push_str("rr_crypto_");
            }
            out.push_str(NEEDLE);
            let advance = offset + NEEDLE.len();
            rest = &rest[advance..];
            consumed += advance;
        }
        out.push_str(rest);
        out
    }

    /// The vendored upstream must be the exact revision `docs/PROVENANCE.md`
    /// pins, so that an edit to it cannot pass unnoticed.
    #[test]
    fn vendored_upstream_matches_the_recorded_digests() {
        // sha256, s2n-bignum 7948ca132c8cdd22fbd7372bd14a4f4ae0a2da7c.
        const DIGESTS: &[(&str, &str)] = &[
            (
                "_internal_s2n_bignum_arm.h",
                "4440189056f29fd349db8e981bcad78630564f0e472f36f377d1a70b1e674ddd",
            ),
            (
                "curve25519_x25519_byte.S",
                "c99e77052afa785252e5364db4235f89b574610989ab8299aa21b7aca2bc0fdf",
            ),
            (
                "curve25519_x25519_byte_alt.S",
                "c44b7a1af90de5c413ef707d67da439e995ec23fd5801f7bf20956b2ec9e3339",
            ),
            (
                "curve25519_x25519base_byte.S",
                "7a4d61f740fa6d6809a8982af28a2dafd1dcdf51da4ecc0be84e341fedac356f",
            ),
            (
                "curve25519_x25519base_byte_alt.S",
                "f8c555ba9989f4cf2c5376db26b48c302ee0df695d2960a83933e96dbcfa1db7",
            ),
            (
                "LICENSE",
                "41c6380384dc6065456d01405ef0b43e5fe39ba1bccc4ec67801cc66142728e5",
            ),
        ];
        let root = format!("{}/src/x25519/aarch64/upstream", env!("CARGO_MANIFEST_DIR"));
        for (name, expected) in DIGESTS {
            let bytes = fs::read(format!("{root}/{name}")).expect("vendored upstream file");
            let mut digest = <sha2::Sha256 as sha2::Digest>::new();
            sha2::Digest::update(&mut digest, &bytes);
            assert_eq!(
                hex(&<[u8; 32]>::from(sha2::Digest::finalize(digest))),
                *expected,
                "{name} is not the pinned upstream revision"
            );
        }
    }
}
