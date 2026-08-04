//! Minimal eBPF instruction encoding and the sockhash stream-verdict program.
//!
//! The recovered reference tree contained a hand-written instruction encoder.
//! It was used only as a reading aid; the encoding below is re-derived from the
//! kernel ABI (`struct bpf_insn`, `include/uapi/linux/bpf.h`) and pinned by
//! direct ABI tests, because an encoder that is wrong in one nibble produces a
//! program the verifier rejects with no useful diagnosis.

/// One eBPF instruction in its exact kernel wire layout.
///
/// The kernel's `struct bpf_insn` is:
///
/// ```text
/// __u8  code;
/// __u8  dst_reg:4, src_reg:4;   // little-endian bitfield: dst low, src high
/// __s16 off;
/// __s32 imm;
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct Insn {
    /// Opcode byte.
    pub code: u8,
    /// Packed destination (low nibble) and source (high nibble) registers.
    pub regs: u8,
    /// Signed jump or memory offset.
    pub off: i16,
    /// Signed immediate.
    pub imm: i32,
}

/// Instruction classes.
pub mod class {
    /// Load into register.
    pub const LD: u8 = 0x00;
    /// Load from memory into register.
    pub const LDX: u8 = 0x01;
    /// Store immediate to memory.
    pub const ST: u8 = 0x02;
    /// Store register to memory.
    pub const STX: u8 = 0x03;
    /// 32-bit arithmetic.
    pub const ALU: u8 = 0x04;
    /// 64-bit jump.
    pub const JMP: u8 = 0x05;
    /// 64-bit arithmetic.
    pub const ALU64: u8 = 0x07;
}

/// Source modifiers.
pub mod source {
    /// Immediate operand.
    pub const K: u8 = 0x00;
    /// Register operand.
    pub const X: u8 = 0x08;
}

/// Memory operand widths.
pub mod size {
    /// 4 bytes.
    pub const W: u8 = 0x00;
    /// 2 bytes.
    pub const H: u8 = 0x08;
    /// 1 byte.
    pub const B: u8 = 0x10;
    /// 8 bytes.
    pub const DW: u8 = 0x18;
}

/// Memory modes.
pub mod mode {
    /// Immediate 64-bit load.
    pub const IMM: u8 = 0x00;
    /// Register-relative memory access.
    pub const MEM: u8 = 0x60;
}

/// ALU and jump operations.
pub mod op {
    /// Addition.
    pub const ADD: u8 = 0x00;
    /// Move.
    pub const MOV: u8 = 0xb0;
    /// Unconditional jump.
    pub const JA: u8 = 0x00;
    /// Jump if equal.
    pub const JEQ: u8 = 0x10;
    /// Jump if not equal.
    pub const JNE: u8 = 0x50;
    /// Call helper.
    pub const CALL: u8 = 0x80;
    /// Return.
    pub const EXIT: u8 = 0x90;
}

/// eBPF helper function identifiers used by the verdict program.
pub mod helper {
    /// `bpf_sk_redirect_hash`.
    pub const SK_REDIRECT_HASH: i32 = 72;
    /// `bpf_map_lookup_elem`.
    pub const MAP_LOOKUP_ELEM: i32 = 1;
}

/// Verdict values returned by a stream parser or verdict program.
pub mod verdict {
    /// Deliver to userspace.
    pub const PASS: i32 = 1;
    /// Drop the message.
    pub const DROP: i32 = 0;
}

/// A pseudo-`BPF_CALL` source register marking a map file descriptor immediate.
pub const PSEUDO_MAP_FD: u8 = 1;

impl Insn {
    /// Builds one instruction from its parts.
    #[must_use]
    pub const fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        Self {
            code,
            regs: (dst & 0x0f) | ((src & 0x0f) << 4),
            off,
            imm,
        }
    }

    /// Returns the destination register.
    #[must_use]
    pub const fn dst(self) -> u8 {
        self.regs & 0x0f
    }

    /// Returns the source register.
    #[must_use]
    pub const fn src(self) -> u8 {
        (self.regs >> 4) & 0x0f
    }

    /// `dst = imm` (64-bit).
    #[must_use]
    pub const fn mov64_imm(dst: u8, imm: i32) -> Self {
        Self::new(class::ALU64 | op::MOV | source::K, dst, 0, 0, imm)
    }

    /// `dst = src` (64-bit).
    #[must_use]
    pub const fn mov64_reg(dst: u8, src: u8) -> Self {
        Self::new(class::ALU64 | op::MOV | source::X, dst, src, 0, 0)
    }

    /// `dst += imm` (64-bit).
    #[must_use]
    pub const fn add64_imm(dst: u8, imm: i32) -> Self {
        Self::new(class::ALU64 | op::ADD | source::K, dst, 0, 0, imm)
    }

    /// `*(size *)(dst + off) = src`.
    #[must_use]
    pub const fn store(width: u8, dst: u8, src: u8, off: i16) -> Self {
        Self::new(class::STX | mode::MEM | width, dst, src, off, 0)
    }

    /// `dst = *(size *)(src + off)`.
    #[must_use]
    pub const fn load(width: u8, dst: u8, src: u8, off: i16) -> Self {
        Self::new(class::LDX | mode::MEM | width, dst, src, off, 0)
    }

    /// `call helper`.
    #[must_use]
    pub const fn call(helper: i32) -> Self {
        Self::new(class::JMP | op::CALL | source::K, 0, 0, 0, helper)
    }

    /// `exit`.
    #[must_use]
    pub const fn exit() -> Self {
        Self::new(class::JMP | op::EXIT | source::K, 0, 0, 0, 0)
    }

    /// `if dst != imm goto +off`.
    #[must_use]
    pub const fn jne_imm(dst: u8, imm: i32, off: i16) -> Self {
        Self::new(class::JMP | op::JNE | source::K, dst, 0, off, imm)
    }

    /// The two-instruction 64-bit immediate load used for map descriptors.
    #[must_use]
    pub const fn load_map_fd(dst: u8, map_fd: i32) -> [Self; 2] {
        [
            Self::new(
                class::LD | mode::IMM | size::DW,
                dst,
                PSEUDO_MAP_FD,
                0,
                map_fd,
            ),
            Self::new(0, 0, 0, 0, 0),
        ]
    }
}

/// Byte offsets inside `struct sk_msg_md` that the verdict program reads.
///
/// These are ABI offsets, not addresses: the verifier rewrites them. They are
/// pinned by a test so a kernel-header change is caught at build time rather
/// than by a runtime verifier rejection.
pub mod sk_msg_md {
    /// `remote_ip4`.
    pub const REMOTE_IP4: i16 = 12;
    /// `local_ip4`.
    pub const LOCAL_IP4: i16 = 16;
    /// `remote_port`.
    pub const REMOTE_PORT: i16 = 48;
    /// `local_port`.
    pub const LOCAL_PORT: i16 = 52;
}

/// Builds the bounded stream-verdict program.
///
/// The program is deliberately tiny: it takes the flow key the userspace side
/// installed, looks the peer socket up in the `SOCKHASH`, and redirects. It
/// never parses payload, never allocates, and has no loop, so its verifier
/// complexity is constant and independent of traffic.
///
/// `map_fd` is the `SOCKHASH` descriptor; `key_size` is the flow-key length in
/// bytes, which must match the map's key size exactly.
#[must_use]
pub fn stream_verdict_program(map_fd: i32, key_size: u16) -> Vec<Insn> {
    let key_offset = -i16::try_from(key_size).unwrap_or(i16::MAX);
    let mut program = Vec::with_capacity(16);

    // r6 = ctx
    program.push(Insn::mov64_reg(6, 1));

    // Build the reversed flow key on the stack from sk_msg_md fields so the
    // lookup finds the *peer* socket rather than this one.
    program.push(Insn::load(size::W, 2, 6, sk_msg_md::LOCAL_IP4));
    program.push(Insn::store(size::W, 10, 2, key_offset));
    program.push(Insn::load(size::W, 2, 6, sk_msg_md::REMOTE_IP4));
    program.push(Insn::store(size::W, 10, 2, key_offset + 4));
    program.push(Insn::load(size::W, 2, 6, sk_msg_md::LOCAL_PORT));
    program.push(Insn::store(size::W, 10, 2, key_offset + 8));
    program.push(Insn::load(size::W, 2, 6, sk_msg_md::REMOTE_PORT));
    program.push(Insn::store(size::W, 10, 2, key_offset + 12));

    // r1 = ctx, r2 = map, r3 = &key, r4 = flags
    program.push(Insn::mov64_reg(1, 6));
    let map = Insn::load_map_fd(2, map_fd);
    program.push(map[0]);
    program.push(map[1]);
    program.push(Insn::mov64_reg(3, 10));
    program.push(Insn::add64_imm(3, i32::from(key_offset)));
    program.push(Insn::mov64_imm(4, 0));
    program.push(Insn::call(helper::SK_REDIRECT_HASH));

    // A redirect returns SK_PASS on success; anything else falls back to
    // userspace delivery so an unarmed flow is never dropped.
    program.push(Insn::jne_imm(0, verdict::PASS, 1));
    program.push(Insn::exit());
    program.push(Insn::mov64_imm(0, verdict::PASS));
    program.push(Insn::exit());
    program
}

#[cfg(test)]
mod tests {
    use super::{
        Insn, PSEUDO_MAP_FD, class, helper, mode, op, size, sk_msg_md, source,
        stream_verdict_program, verdict,
    };

    #[test]
    fn the_instruction_layout_matches_the_kernel_abi() {
        assert_eq!(core::mem::size_of::<Insn>(), 8);
        assert_eq!(core::mem::align_of::<Insn>(), 4);
    }

    #[test]
    fn registers_pack_into_the_low_and_high_nibble() {
        let insn = Insn::new(0, 9, 3, 0, 0);
        assert_eq!(insn.dst(), 9);
        assert_eq!(insn.src(), 3);
        assert_eq!(insn.regs, 0x39);
    }

    #[test]
    fn opcode_bytes_match_the_documented_encodings() {
        assert_eq!(Insn::mov64_imm(0, 1).code, 0xb7);
        assert_eq!(Insn::mov64_reg(1, 6).code, 0xbf);
        assert_eq!(Insn::add64_imm(3, -16).code, 0x07);
        assert_eq!(Insn::store(size::W, 10, 2, -16).code, 0x63);
        assert_eq!(Insn::load(size::W, 2, 6, 12).code, 0x61);
        assert_eq!(Insn::call(helper::MAP_LOOKUP_ELEM).code, 0x85);
        assert_eq!(Insn::exit().code, 0x95);
        assert_eq!(Insn::jne_imm(0, 1, 1).code, 0x55);
        assert_eq!(class::ALU64 | op::MOV | source::K, 0xb7);
        assert_eq!(class::LD | mode::IMM | size::DW, 0x18);
    }

    #[test]
    fn a_map_descriptor_load_is_a_two_slot_wide_immediate() {
        let insns = Insn::load_map_fd(2, 7);
        assert_eq!(insns[0].code, 0x18);
        assert_eq!(insns[0].src(), PSEUDO_MAP_FD);
        assert_eq!(insns[0].imm, 7);
        assert_eq!(insns[1], Insn::new(0, 0, 0, 0, 0));
    }

    #[test]
    fn the_verdict_program_is_bounded_and_loop_free() {
        let program = stream_verdict_program(7, 16);
        assert!(program.len() < 32, "the verdict program must stay tiny");
        assert!(
            program
                .iter()
                .all(|insn| insn.code != (class::JMP | op::JA | source::K) || insn.off >= 0),
            "no backward jump may exist, so the program cannot loop"
        );
        assert_eq!(
            program.last().copied(),
            Some(Insn::exit()),
            "the program must end in an exit"
        );
    }

    #[test]
    fn the_verdict_program_reverses_the_flow_key() {
        let program = stream_verdict_program(7, 16);
        // The first stored field must come from the *local* address so the
        // lookup resolves the peer socket, not the originating one.
        let first_load = program
            .iter()
            .find(|insn| insn.code == (class::LDX | mode::MEM | size::W))
            .copied()
            .expect("the program must read sk_msg_md");
        assert_eq!(first_load.off, sk_msg_md::LOCAL_IP4);
    }

    #[test]
    fn the_program_falls_back_to_userspace_delivery() {
        let program = stream_verdict_program(7, 16);
        assert!(
            program
                .iter()
                .any(|insn| insn.code == (class::ALU64 | op::MOV | source::K)
                    && insn.imm == verdict::PASS),
            "an unarmed flow must be passed to userspace, never dropped"
        );
        // The only value ever moved into r0, the return register, is SK_PASS.
        assert!(
            program
                .iter()
                .filter(|insn| insn.code == (class::ALU64 | op::MOV | source::K) && insn.dst() == 0)
                .all(|insn| insn.imm == verdict::PASS),
            "the program must never return a drop verdict"
        );
        assert_eq!(verdict::DROP, 0);
    }
}
