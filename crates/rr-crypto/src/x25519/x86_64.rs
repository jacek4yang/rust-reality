//! X25519 on x86_64, computed by s2n-bignum's assembly.
//!
//! # Why assembly, and why this assembly
//!
//! rust-reality performs three X25519 operations per public REALITY session
//! (REALITY static agreement, TLS ephemeral public derivation, TLS ephemeral
//! agreement), which together measured **14.6% of server CPU per session**.
//! Its incumbent is `aws-lc-rs`, whose X25519 is these exact s2n-bignum
//! routines reached through AWS-LC's ~2.6 MB vendored C libcrypto. A portable
//! Rust replacement is not competitive: `x25519-dalek` measured 1.85x the
//! incumbent on the static-agreement shape, which would cost about +12.5%
//! session CPU.
//!
//! So this module does not reimplement the arithmetic. It takes the same
//! upstream artifact the incumbent already runs and calls it directly, which
//! removes the C toolchain, the build script and the megabytes of unrelated
//! libcrypto while keeping the arithmetic that earned its place.
//!
//! Provenance, the pinned revision and the exact transformation applied to the
//! upstream sources are recorded in `docs/PROVENANCE.md`. The upstream sources
//! themselves are vendored byte-for-byte under `src/x25519/upstream/`, and
//! `regenerating_the_assembly_reproduces_it` proves the committed `.s` files
//! are their mechanical macro expansion.
//!
//! # Contract of the imported routines
//!
//! Both entry points take and return little-endian 32-byte encodings, and both
//! **clamp the scalar internally** exactly as RFC 7748 specifies, so a caller
//! must not clamp again (`the_assembly_clamps_the_scalar_itself` proves it).
//!
//! Neither implements the RFC 7748 section 6.1 zero check: a low-order or
//! otherwise non-contributory peer share yields an all-zero output rather than
//! an error. Rejecting that is the caller's responsibility and belongs in the
//! safe API, not here.
//!
//! The committed assembly emits ELF directives (`.section .rodata`,
//! `.note.GNU-stack`, `.type ..., %object`), so this module is gated to
//! `x86_64` **Linux**. rust-reality is a Linux-only product, so that is the
//! whole of its release matrix for this architecture; upstream also ships
//! Mach-O forms, and adding them would be work for a consumer that does not
//! exist.
//!
//! ABI: the System V AMD64 calling convention, `RDI`/`RSI`/`RDX` in, no return
//! value, callee-saved registers preserved by the routine itself, at most
//! ~450 bytes of its own stack frame, and no dependence on the red zone.
//! Inputs and outputs may not overlap.
//!
//! # Dispatch
//!
//! The primary routines use BMI2 and ADX (Haswell, 2013 and later; Zen and
//! later). The `_alt` routines are the baseline-x86_64 fallback for machines
//! without them, and are what a generic release binary runs on a pre-Haswell
//! CPU. Selection is a cached CPUID probe — see [`Variant`]. This mirrors
//! AWS-LC's own `use_s2n_bignum_alt()` decision, so no generic binary can
//! execute an instruction its CPU lacks.
//!
//! # Claims
//!
//! The upstream routines are machine-checked in s2n-bignum's own proof
//! development. **That proof does not travel with this import**: it covers
//! upstream's build of upstream's source, not this crate's. What this crate
//! demonstrates instead is narrower and testable — that the machine code Rust
//! emits is byte-identical to what GNU `as` produces from the same input, that
//! the committed assembly is a mechanical expansion of the vendored upstream,
//! and that the results match RFC 7748 and two independent implementations.

use core::arch::global_asm;

use crate::detect::Features;

global_asm!(
    include_str!("x86_64/curve25519_x25519.s"),
    options(att_syntax)
);
global_asm!(
    include_str!("x86_64/curve25519_x25519_alt.s"),
    options(att_syntax)
);
global_asm!(
    include_str!("x86_64/curve25519_x25519base.s"),
    options(att_syntax)
);
global_asm!(
    include_str!("x86_64/curve25519_x25519base_alt.s"),
    options(att_syntax)
);

unsafe extern "C" {
    /// s2n-bignum `curve25519_x25519_byte`, BMI2 + ADX.
    fn rr_crypto_curve25519_x25519_byte(res: *mut u8, scalar: *const u8, point: *const u8);
    /// s2n-bignum `curve25519_x25519_byte_alt`, baseline x86_64.
    fn rr_crypto_curve25519_x25519_byte_alt(res: *mut u8, scalar: *const u8, point: *const u8);
    /// s2n-bignum `curve25519_x25519base_byte`, BMI2 + ADX.
    fn rr_crypto_curve25519_x25519base_byte(res: *mut u8, scalar: *const u8);
    /// s2n-bignum `curve25519_x25519base_byte_alt`, baseline x86_64.
    fn rr_crypto_curve25519_x25519base_byte_alt(res: *mut u8, scalar: *const u8);
}

/// Which of the two compiled implementations this machine runs.
///
/// Reporting and testing only. Both variants compute the same function; a
/// caller must never branch on this for correctness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Variant {
    /// The BMI2 + ADX routines.
    Adx,
    /// The baseline-x86_64 `_alt` routines.
    Baseline,
}

impl Variant {
    /// Stable name for benchmark output and bug reports.
    #[must_use]
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Adx => "s2n-bignum-adx",
            Self::Baseline => "s2n-bignum-baseline",
        }
    }
}

/// The variant this machine dispatches to.
#[must_use]
pub(crate) fn variant() -> Variant {
    let features = Features::cached();
    if features.bmi2() && features.adx() {
        Variant::Adx
    } else {
        Variant::Baseline
    }
}

/// Computes the X25519 function: the u-coordinate of `scalar * point`.
///
/// `scalar` is clamped by the implementation; the caller passes the raw private
/// key. An all-zero `out` means the peer share was non-contributory and the
/// caller must reject it — this function does not.
pub(crate) fn x25519(out: &mut [u8; 32], scalar: &[u8; 32], point: &[u8; 32]) {
    // SAFETY: all three pointers address distinct 32-byte objects that the
    // borrow checker proves are live and non-overlapping for this call (`out`
    // is a unique borrow, the inputs are shared borrows, so no input can alias
    // the output). The routine writes exactly 32 bytes through `res`, reads
    // exactly 32 through each input, restores every callee-saved register and
    // uses only its own stack frame. Both variants share this contract; the
    // selected one is executable because `Variant::Adx` is chosen only when
    // CPUID reported BMI2 and ADX.
    unsafe {
        match variant() {
            Variant::Adx => {
                rr_crypto_curve25519_x25519_byte(out.as_mut_ptr(), scalar.as_ptr(), point.as_ptr());
            }
            Variant::Baseline => {
                rr_crypto_curve25519_x25519_byte_alt(
                    out.as_mut_ptr(),
                    scalar.as_ptr(),
                    point.as_ptr(),
                );
            }
        }
    }
}

/// Computes the X25519 public key for `scalar`: `scalar * G`, `G` the standard
/// generator.
///
/// `scalar` is clamped by the implementation. This is a dedicated fixed-base
/// routine, not the general function applied to u = 9.
pub(crate) fn x25519_base(out: &mut [u8; 32], scalar: &[u8; 32]) {
    // SAFETY: as for `x25519`, with two distinct live 32-byte objects: `out` is
    // a unique borrow so it cannot alias `scalar`. The routine writes exactly
    // 32 bytes through `res` and reads exactly 32 through `scalar`, and also
    // reads its own 48,576-byte read-only precomputed table, which is part of
    // this crate's `.rodata`.
    unsafe {
        match variant() {
            Variant::Adx => {
                rr_crypto_curve25519_x25519base_byte(out.as_mut_ptr(), scalar.as_ptr());
            }
            Variant::Baseline => {
                rr_crypto_curve25519_x25519base_byte_alt(out.as_mut_ptr(), scalar.as_ptr());
            }
        }
    }
}

#[cfg(test)]
/// Computes the X25519 function with the BMI2 + ADX routine.
///
/// Testing and benchmarking only: it lets both compiled variants be compared on
/// one machine. Production callers use [`x25519`], which dispatches.
///
/// # Safety
///
/// The CPU must support BMI2 and ADX.
pub(crate) unsafe fn x25519_adx(out: &mut [u8; 32], scalar: &[u8; 32], point: &[u8; 32]) {
    // SAFETY: pointer contract as in `x25519`; the caller guarantees BMI2/ADX.
    unsafe { rr_crypto_curve25519_x25519_byte(out.as_mut_ptr(), scalar.as_ptr(), point.as_ptr()) }
}

#[cfg(test)]
/// Computes the X25519 function with the baseline-x86_64 routine.
///
/// Testing and benchmarking only. Executable on every x86_64 CPU.
pub(crate) fn x25519_baseline(out: &mut [u8; 32], scalar: &[u8; 32], point: &[u8; 32]) {
    // SAFETY: pointer contract as in `x25519`. The `_alt` routine uses only
    // baseline x86_64 instructions, so it needs no feature precondition.
    unsafe {
        rr_crypto_curve25519_x25519_byte_alt(out.as_mut_ptr(), scalar.as_ptr(), point.as_ptr());
    }
}

#[cfg(test)]
/// Computes the X25519 public key with the BMI2 + ADX routine.
///
/// Testing and benchmarking only.
///
/// # Safety
///
/// The CPU must support BMI2 and ADX.
pub(crate) unsafe fn x25519_base_adx(out: &mut [u8; 32], scalar: &[u8; 32]) {
    // SAFETY: pointer contract as in `x25519_base`; the caller guarantees
    // BMI2/ADX.
    unsafe { rr_crypto_curve25519_x25519base_byte(out.as_mut_ptr(), scalar.as_ptr()) }
}

#[cfg(test)]
/// Computes the X25519 public key with the baseline-x86_64 routine.
///
/// Testing and benchmarking only. Executable on every x86_64 CPU.
pub(crate) fn x25519_base_baseline(out: &mut [u8; 32], scalar: &[u8; 32]) {
    // SAFETY: pointer contract as in `x25519_base`. The `_alt` routine uses
    // only baseline x86_64 instructions.
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
        Variant, variant, x25519, x25519_adx, x25519_base, x25519_base_adx, x25519_base_baseline,
        x25519_baseline,
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

    fn agree_adx(out: &mut [u8; 32], scalar: &[u8; 32], point: &[u8; 32]) {
        // SAFETY: only reachable through `executable_variants`, which adds this
        // pair to the list solely when CPUID reported BMI2 and ADX.
        unsafe { x25519_adx(out, scalar, point) }
    }

    fn base_adx(out: &mut [u8; 32], scalar: &[u8; 32]) {
        // SAFETY: as for `agree_adx`.
        unsafe { x25519_base_adx(out, scalar) }
    }

    /// Every compiled variant this machine can execute, so a test never covers
    /// only the dispatched one.
    fn executable_variants() -> Vec<(Agree, Base)> {
        let mut variants: Vec<(Agree, Base)> = Vec::new();
        variants.push((x25519_baseline, x25519_base_baseline));
        if variant() == Variant::Adx {
            variants.push((agree_adx, base_adx));
        }
        variants
    }

    /// Runs `body` for every compiled variant this machine can execute.
    fn for_each_variant(mut body: impl FnMut(Agree, Base)) {
        for (agree, base) in executable_variants() {
            body(agree, base);
        }
    }

    #[test]
    fn rfc7748_section_5_2_vectors_hold() {
        // The two variable-base vectors from RFC 7748 section 5.2.
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

    /// RFC 7748 section 5.2's iterated test, one and one thousand rounds.
    ///
    /// This is the vector that catches carry-propagation and reduction bugs a
    /// single multiplication would hide.
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

    /// The imported routines clamp internally, so the safe API must not clamp
    /// again. This proves the property rather than trusting the comment.
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

    /// Every canonical low-order point, and the non-canonical field encodings,
    /// must produce the all-zero output the safe API rejects.
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
        if variant() != Variant::Adx {
            println!("machine lacks BMI2/ADX; only one variant is executable");
            return;
        }
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
            let (mut adx, mut baseline) = ([0_u8; 32], [0_u8; 32]);
            // SAFETY: guarded by the `variant() == Variant::Adx` check above,
            // which is the CPUID probe reporting BMI2 and ADX.
            unsafe { x25519_adx(&mut adx, &scalar, &point) };
            x25519_baseline(&mut baseline, &scalar, &point);
            assert_eq!(adx, baseline, "variable-base disagreement at round {round}");

            // SAFETY: same guard as immediately above.
            unsafe { x25519_base_adx(&mut adx, &scalar) };
            x25519_base_baseline(&mut baseline, &scalar);
            assert_eq!(adx, baseline, "fixed-base disagreement at round {round}");
        }
    }

    /// The dispatched entry points must agree with the variant they select.
    #[test]
    fn dispatch_matches_the_selected_variant() {
        let scalar = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let point = hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let (mut dispatched, mut direct) = ([0_u8; 32], [0_u8; 32]);

        x25519(&mut dispatched, &scalar, &point);
        match variant() {
            // SAFETY: this arm is reached only when the CPUID probe selected
            // `Adx`, which means BMI2 and ADX are present.
            Variant::Adx => unsafe { x25519_adx(&mut direct, &scalar, &point) },
            Variant::Baseline => x25519_baseline(&mut direct, &scalar, &point),
        }
        assert_eq!(dispatched, direct);

        x25519_base(&mut dispatched, &scalar);
        match variant() {
            // SAFETY: same guard as immediately above.
            Variant::Adx => unsafe { x25519_base_adx(&mut direct, &scalar) },
            Variant::Baseline => x25519_base_baseline(&mut direct, &scalar),
        }
        assert_eq!(dispatched, direct);
    }

    /// The committed `.s` files must be the mechanical macro expansion of the
    /// vendored upstream `.S` files, so that reviewing the import means
    /// reviewing upstream rather than 18,000 lines of expanded output.
    ///
    /// Requires a C preprocessor, and **skips** rather than fails without one.
    ///
    /// The distinction is the point of the whole import: building this crate
    /// needs no build script, no CMake and no C compiler, and a developer
    /// without `cpp` must still be able to run the suite. Verifying that the
    /// committed assembly is upstream's expansion is a different question from
    /// building it, and CI — which has a C toolchain — answers it on every
    /// change.
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
            "curve25519_x25519",
            "curve25519_x25519_alt",
            "curve25519_x25519base",
            "curve25519_x25519base_alt",
        ];
        let root = format!("{}/src/x25519/x86_64", env!("CARGO_MANIFEST_DIR"));

        for unit in UNITS {
            let output = Command::new("cpp")
                .args([
                    "-P",
                    "-I",
                    &format!("{root}/upstream"),
                    // Every conditional in upstream's header is pinned on the
                    // command line, so the result cannot depend on how the
                    // host's compiler was configured. `-U__CET__` matters in
                    // practice: a distribution that defaults to
                    // `-fcf-protection` pulls in glibc's `cet.h`, which spells
                    // the same ENDBR64 as a mnemonic and adds a
                    // `.note.gnu.property` section. Taking upstream's explicit
                    // byte sequence instead assembles to identical machine code
                    // and needs no glibc header.
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

    /// Blank lines and indentation are preprocessor-version noise; anything
    /// else is a real difference.
    fn significant_lines(text: &str) -> Vec<&str> {
        text.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect()
    }

    /// Namespaces upstream's exported symbols, which is the only edit the
    /// import makes to the expanded assembly.
    ///
    /// The prefix is applied at word boundaries, so upstream's local labels
    /// (`Lcurve25519_x25519_scalarloop` and friends) keep their names and stay
    /// recognisable in a profile.
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
                "_internal_s2n_bignum_x86_att.h",
                "4071bcd6552e0bd6cb82163b82f11cba63c6aa731c32380c5e8bfd467e9bc91b",
            ),
            (
                "curve25519_x25519.S",
                "ceb0e236702a1d76540a78c51814cc82128630568c88f7e7f242a9aa0b011831",
            ),
            (
                "curve25519_x25519_alt.S",
                "3031540a6d2f2d58e099d062c3f585eb2a4f57a501554a775ca6a7d7a486a75a",
            ),
            (
                "curve25519_x25519base.S",
                "c3afcf71c6f7e3171224991cd89ceece87cb7210296704bab07db308577b7914",
            ),
            (
                "curve25519_x25519base_alt.S",
                "2a6ab011708a9cd0419be614d3a9e1fc45ec0063e071902f4ca8a76d68a24b16",
            ),
            (
                "LICENSE",
                "41c6380384dc6065456d01405ef0b43e5fe39ba1bccc4ec67801cc66142728e5",
            ),
        ];
        let root = format!("{}/src/x25519/x86_64/upstream", env!("CARGO_MANIFEST_DIR"));
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
