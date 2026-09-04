# Cryptographic implementation provenance

English only. This is a technical record, like an ADR, and translating a
licence chain would create a second thing to keep true.

Every non-trivial implementation `crates/rr-crypto` did not write is recorded
here before it is used: where it came from, at exactly which revision, under
which licence, what was copied unchanged, what was changed, and — separately —
what upstream verification does **not** carry over. Code with unclear licensing
or unclear provenance does not enter this repository.

## The obligations this discharges

The imported sources are `Apache-2.0 OR ISC OR MIT-0`, all permissive and all
compatible with this repository's `MIT OR Apache-2.0`. Attribution is satisfied
in three places at once, deliberately, so that removing any one of them is
visible:

1. every vendored file keeps its upstream copyright header verbatim;
2. the upstream `LICENSE` is vendored beside the sources it covers, once per
   architecture, so each vendored tree is self-contained;
3. this register names the project, the revision and the files.

## What upstream proofs do and do not mean here

The imported routines are machine-checked in their upstream's own proof
development. **Those proofs cover upstream's build of upstream's sources, not
this repository's.** A mechanical transformation was applied (macro expansion
and a symbol prefix), the surrounding Rust is ours, and the toolchain is
different. What this repository demonstrates instead is narrower and testable,
and each claim has a test named beside it below.

The words *audited*, *formally verified* and *constant-time proven* are not
used about this code, because none of them is true of this build.

## Register

### 1. X25519 scalar multiplication, x86_64

| field | content |
| --- | --- |
| primitive | X25519 variable-base and fixed-base scalar multiplication, x86_64 only |
| upstream project | s2n-bignum |
| upstream URL | <https://github.com/awslabs/s2n-bignum> |
| commit / tag | `7948ca132c8cdd22fbd7372bd14a4f4ae0a2da7c` (2026-09-03; no release tags exist) |
| source paths | `x86_att/curve25519/curve25519_x25519{,_alt,base,base_alt}.S`, `include/_internal_s2n_bignum_x86_att.h`, `LICENSE` |
| license | `Apache-2.0 OR ISC OR MIT-0` — declared in the `LICENSE` file and repeated as an SPDX header in every imported `.S` |
| notices | `Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.` retained verbatim at the head of each vendored file; the full upstream `LICENSE` is vendored beside them at `crates/rr-crypto/src/x25519/x86_64/upstream/LICENSE` |
| copied | all four routines, byte-for-byte, as `crates/rr-crypto/src/x25519/x86_64/upstream/*.S` |
| rewritten | nothing — no arithmetic, scheduling, register allocation or memory layout was touched |
| structural changes | the committed `.s` files are the C-preprocessor expansion of those `.S` files with exported symbols namespaced (below); a Rust wrapper adds dispatch and the RFC 7748 §6.1 zero check that upstream deliberately omits |
| verification status | **the upstream HOL Light proofs do not travel with this import.** See below. |

**Why this import exists.** rust-reality already runs this exact upstream
project's X25519, reached through `aws-lc-rs` → `aws-lc-sys` → a vendored
~2.6 MB C libcrypto with a CMake/C build. Importing the four routines directly
keeps the arithmetic and drops the build system: `global_asm!`, no build script,
no CMake, and about 164 KB of `.text` plus `.rodata` instead of 2.6 MB.

This does **not** make the build C-free, and the distinction is worth stating
because it is easy to overclaim. `ring` also compiles C, through `cc-rs`, and it
is reachable via `ureq -> rustls`, so a C compiler remains a build requirement
for this repository. What leaves with `aws-lc-rs` is CMake, its build script and
the vendored libcrypto.

**Exact transformation.** For each of the four units:

```sh
cpp -P -I upstream -U__APPLE__ -U__CET__ -D__ELF__ -D__linux__ \
    -DS2N_BN_HIDE_SYMBOLS upstream/<unit>.S \
  | sed -E 's/\bcurve25519_/rr_crypto_curve25519_/g' > <unit>.s
```

That is macro expansion plus a symbol prefix, and nothing else. The prefix is
applied at word boundaries so upstream's local labels keep their names and stay
recognisable in a profile; it exists because a binary may legitimately contain
both this import and AWS-LC's copy during A/B measurement, and two definitions
of `curve25519_x25519` would collide at link time.

Every conditional in upstream's header is pinned on the command line so the
result cannot depend on how the host compiler was configured. `-U__CET__` is
the one that bites: a distribution defaulting to `-fcf-protection` defines it,
which pulls in glibc's `cet.h` and spells the same ENDBR64 as a mnemonic while
adding a `.note.gnu.property` section. Upstream's own explicit byte sequence
assembles to identical machine code, needs no glibc header, and is what is
committed. `-D__ELF__ -D__linux__` fix the output to the ELF form, which is why
the module is gated to Linux.

`rr_crypto::x25519::x86_64::tests::regenerating_the_assembly_reproduces_it`
re-runs that pipeline and compares, so the claim is checked rather than
asserted, and
`rr_crypto::x25519::x86_64::tests::vendored_upstream_matches_the_recorded_digests`
pins the vendored inputs by SHA-256.

**Relationship to what AWS-LC ships.** `aws-lc-sys` 0.45.0 vendors an *older*
import of the same files. They differ in three upstream commits, none of which
touches the arithmetic: `#428` (loop alignment for the Skylake JCC erratum),
`#242` and `#446` (moving the 48,576-byte precomputed table into `.rodata` and
fixing its Mach-O references). This import is therefore the same routines at a
newer revision, not a copy of AWS-LC's artefact, and the difference is recorded
here rather than glossed as "identical".

**Required CPU features and dispatch.** `curve25519_x25519` and
`curve25519_x25519base` use BMI2 and ADX. The `_alt` routines are baseline
x86_64. Both are compiled in and selected by a cached CPUID probe, mirroring
AWS-LC's own `use_s2n_bignum_alt()`, so a generic release binary cannot execute
an instruction the CPU lacks.

**ABI.** System V AMD64: `RDI` = result, `RSI` = scalar, `RDX` = point; no
return value; the routines preserve `RBX`, `RBP` and `R12`–`R15` themselves,
allocate their own frame (about 416 bytes for the variable-base routine), do not
use the red zone, and require that the result not alias either input. Inputs
and outputs are little-endian 32-byte encodings. Both routines clamp the scalar
internally per RFC 7748; neither performs the §6.1 zero check.

**Verification status, stated narrowly.** s2n-bignum's routines are accompanied
by machine-checked HOL Light proofs in the upstream repository. Those proofs
cover upstream's source; this repository has neither reproduced them nor
extended them to its own build, and **must not claim otherwise**. Nothing in
the arithmetic was modified, but "unmodified" is not the same as "proved", and
the assembler, linker and build configuration here are not upstream's.

What this repository has actually demonstrated, and will say instead:

- the machine code Rust's `global_asm!` emits is **byte-identical** to what GNU
  `as` produces from the same input, for all four routines' `.text` and both
  `.rodata` tables — so the integration introduces no codegen divergence. To
  reproduce, for each unit:

  ```sh
  as --64 -o gnu.o crates/rr-crypto/src/x25519/x86_64/<unit>.s
  printf '#![no_std]\ncore::arch::global_asm!(include_str!("%s"), options(att_syntax));\n' \
    "$PWD/crates/rr-crypto/src/x25519/x86_64/<unit>.s" > /tmp/unit.rs
  rustc --edition 2021 --crate-type lib --emit=obj -O -o llvm.o /tmp/unit.rs
  for section in .text .rodata; do
      objcopy -O binary --only-section=$section gnu.o a.bin
      objcopy -O binary --only-section=$section llvm.o b.bin
      cmp a.bin b.bin
  done
  ```

- RFC 7748 §5.2 and §6.1 vectors pass, including the 1,000-iteration one;
- results match **two independent implementations**, `aws-lc-rs` and
  `x25519-dalek`, over randomised secrets, randomised peer encodings, the
  ignored high bit, and the canonical low-order points;
- a differential fuzz target against `x25519-dalek` exists.

Constant-time behaviour is inherited from upstream's design, not measured here.
Until a timing experiment is recorded, the honest phrasing is "no
secret-dependent control flow was found by source review", not "constant-time
verified".

### 2. X25519 scalar multiplication, AArch64

| field | content |
| --- | --- |
| primitive | X25519 variable-base and fixed-base scalar multiplication, AArch64 only |
| upstream project | s2n-bignum |
| upstream URL | <https://github.com/awslabs/s2n-bignum> |
| commit / tag | `7948ca132c8cdd22fbd7372bd14a4f4ae0a2da7c` — the same revision as entry 1 |
| source paths | `arm/curve25519/curve25519_x25519_byte{,_alt}.S`, `arm/curve25519/curve25519_x25519base_byte{,_alt}.S`, `include/_internal_s2n_bignum_arm.h`, `LICENSE` |
| license | `Apache-2.0 OR ISC OR MIT-0`, declared in `LICENSE` and repeated as an SPDX header in every imported `.S` |
| notices | `Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.` retained verbatim, together with upstream's own attribution comment naming the two projects below; the full upstream `LICENSE` is vendored at `crates/rr-crypto/src/x25519/aarch64/upstream/LICENSE` |
| copied | all four routines, byte-for-byte, as `crates/rr-crypto/src/x25519/aarch64/upstream/*.S` |
| rewritten | nothing |
| structural changes | macro expansion and symbol namespacing, by the same pinned pipeline as entry 1; a Rust wrapper adds MIDR-based dispatch and the RFC 7748 §6.1 zero check |
| verification status | no upstream proof is claimed. See below. |

**The attribution chain is longer here, and collapsing it would be wrong.**
Upstream's own header states that this code is *substantially derived from*:

| project | URL | license |
| --- | --- | --- |
| Emil Lenngren's X25519-AArch64 | <https://github.com/Emill/X25519-AArch64> | **CC0-1.0** (public domain dedication) |
| the SLOTHY re-scheduling of it, by Abdulrahman, Becker, Kannwischer and Klein | <https://github.com/slothy-optimizer/slothy> | **MIT** (Arm Limited, Hanno Becker, Amin Abdulrahman, Matthias Kannwischer) |

Both were checked at import time and both are permissive and compatible. The
chain is recorded because "it is Apache-2.0 because Amazon says so" is not a
licence review — the question is whether *everything it descends from* permits
this use, and here it does.

**Why both variants ship.** Unlike x86_64, neither AArch64 variant needs an
optional instruction: both execute on every ARMv8 CPU, and the `_alt` routines
are simply tuned for cores with a wide multiplier. Dispatch mirrors AWS-LC's
`use_s2n_bignum_alt()` — read `MIDR_EL1` (guarded by `HWCAP_CPUID`, because the
`MRS` would fault where the kernel does not emulate ID-register reads) and take
`_alt` for Neoverse V1, V2 and V3. AWS-LC also prefers `_alt` on Apple silicon,
but reaches that conclusion through a macOS `sysctl`, not through MIDR on Linux;
this port does not add a rule it cannot test. A failed probe selects the
standard routines, which is always correct — the worst case is unclaimed
throughput, never an illegal instruction.

**ABI.** AAPCS64: `X0` = result, `X1` = scalar, `X2` = point, no return value,
callee-saved registers and stack frame managed by the routine, result must not
alias either input. Little-endian 32-byte encodings; the scalar is clamped
internally; the §6.1 zero check is the caller's.

**Verification status, stated narrowly.** As with entry 1, upstream's
machine-checked proofs cover upstream's build and are not claimed here. What is
demonstrated:

- the machine code `global_asm!` emits is **byte-identical** to
  `aarch64-linux-gnu-as` output, for all four routines' `.text` and both
  `.rodata` tables;
- RFC 7748 §5.2 and §6.1 vectors pass, including the 1,000-iteration one, **for
  both variants**, executed on real AArch64 instructions under user-mode QEMU
  rather than merely compiled;
- the committed assembly is the mechanical expansion of the vendored upstream,
  checked by a test;
- the vendored upstream is pinned by SHA-256, checked by a test.

Differential testing against `aws-lc-rs` and `x25519-dalek` runs on x86_64. On
AArch64 the same *implementation* is exercised against RFC 7748 vectors and
against the other variant, which is weaker, and that difference is deliberate:
cross-building the C incumbent for AArch64 to run it under emulation would
compare two emulated implementations rather than validate ours.
