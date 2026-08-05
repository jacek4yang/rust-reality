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
    /// Bitwise or.
    pub const OR: u8 = 0x40;
    /// Left shift.
    pub const LSH: u8 = 0x60;
    /// Right shift.
    pub const RSH: u8 = 0x70;
    /// Move.
    pub const MOV: u8 = 0xb0;
    /// Byte-order conversion.
    pub const END: u8 = 0xd0;
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
///
/// # Why the previous constant was wrong
///
/// The merged implementation called helper 72 from a `BPF_PROG_TYPE_SK_MSG`
/// program. Helper 72 is `bpf_sk_redirect_hash`, which belongs to
/// `BPF_PROG_TYPE_SK_SKB`. The kernel's own header settles it:
///
/// ```text
/// FN(msg_redirect_hash, 71, ##ctx)    <- the SK_MSG helper
/// FN(sk_redirect_hash,  72, ##ctx)    <- the SK_SKB helper
/// ```
///
/// The verifier rejects the mismatch with
/// `program of this type cannot use helper bpf_sk_redirect_hash#72`, and that
/// rejection is reported as `EACCES` — the exact errno in the incident trace.
pub mod helper {
    /// `bpf_msg_redirect_hash`, the redirect helper for `SK_MSG` programs.
    pub const MSG_REDIRECT_HASH: i32 = 71;
    /// `bpf_sk_redirect_hash`, the redirect helper for `SK_SKB` programs.
    ///
    /// Declared so the distinction stays visible and testable. Never called.
    pub const SK_REDIRECT_HASH: i32 = 72;
    /// `bpf_map_lookup_elem`.
    pub const MAP_LOOKUP_ELEM: i32 = 1;
}

/// Address families as they appear in `sk_msg_md.family`.
pub mod family {
    /// `AF_INET`.
    pub const INET: i32 = 2;
    /// `AF_INET6`.
    pub const INET6: i32 = 10;
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

    /// `dst |= src` (64-bit).
    #[must_use]
    pub const fn or64_reg(dst: u8, src: u8) -> Self {
        Self::new(class::ALU64 | op::OR | source::X, dst, src, 0, 0)
    }

    /// `dst <<= imm` (64-bit).
    #[must_use]
    pub const fn lsh64_imm(dst: u8, imm: i32) -> Self {
        Self::new(class::ALU64 | op::LSH | source::K, dst, 0, 0, imm)
    }

    /// `dst >>= imm` (64-bit, logical).
    #[must_use]
    pub const fn rsh64_imm(dst: u8, imm: i32) -> Self {
        Self::new(class::ALU64 | op::RSH | source::K, dst, 0, 0, imm)
    }

    /// `dst = htobe<bits>(dst)`.
    ///
    /// On a little-endian host this is a byte swap; on a big-endian host it is
    /// a no-op. Both are correct here because the resulting value is written to
    /// and read from the flow key in native order on the same machine.
    #[must_use]
    pub const fn to_big_endian(dst: u8, bits: i32) -> Self {
        Self::new(class::ALU | op::END | source::X, dst, 0, 0, bits)
    }

    /// `*(size *)(dst + off) = imm`.
    #[must_use]
    pub const fn store_imm(width: u8, dst: u8, off: i16, imm: i32) -> Self {
        Self::new(class::ST | mode::MEM | width, dst, 0, off, imm)
    }

    /// `goto +off`.
    #[must_use]
    pub const fn jump(off: i16) -> Self {
        Self::new(class::JMP | op::JA | source::K, 0, 0, off, 0)
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

/// Byte offsets inside `struct __sk_buff` that the verdict program reads.
///
/// # Why this is `__sk_buff` and not `sk_msg_md`
///
/// The merged implementation loaded a `BPF_PROG_TYPE_SK_MSG` program. `SK_MSG`
/// hooks `sendmsg`, i.e. data the *local application* is sending. A proxy needs
/// the opposite: data arriving on one socket must be handed to another socket
/// without ever entering userspace. That is the `SK_SKB` stream-verdict hook,
/// whose context is `struct __sk_buff`.
///
/// This was confirmed by measurement, not by reading. An `SK_MSG` program that
/// loads and attaches cleanly still moves no bytes for a relayed pair; the same
/// logic as `SK_SKB`/`BPF_SK_SKB_STREAM_VERDICT` redirects byte-exactly in both
/// directions.
///
/// The offsets below count the twenty-two `__u32` slots that precede `family`,
/// including `cb[5]`.
pub mod sk_buff {
    /// `family`.
    pub const FAMILY: i16 = 88;
    /// `remote_ip4`, network byte order.
    pub const REMOTE_IP4: i16 = 92;
    /// `local_ip4`, network byte order.
    pub const LOCAL_IP4: i16 = 96;
    /// `remote_ip6[4]`, network byte order.
    pub const REMOTE_IP6: i16 = 100;
    /// `local_ip6[4]`, network byte order.
    pub const LOCAL_IP6: i16 = 116;
    /// `remote_port`, a network-order 16-bit port delivered in the high half.
    pub const REMOTE_PORT: i16 = 132;
    /// `local_port`, delivered in host byte order.
    pub const LOCAL_PORT: i16 = 136;
}

/// Byte offsets inside `struct sk_msg_md`.
///
/// Retained because the corrected values document the merged implementation's
/// second defect, and because a future `SK_MSG` use would need them.
///
/// These are ABI offsets, not addresses: the verifier rewrites them.
///
/// # Why the previous offsets were wrong
///
/// The merged implementation used 12, 16, 48 and 52 — the offsets for a layout
/// with 4-byte context pointers. `__bpf_md_ptr` forces 8-byte alignment and 8
/// bytes of storage per pointer:
///
/// ```text
/// union { type name; __u64 :64; } __attribute__((aligned(8)))
/// ```
///
/// so `data` and `data_end` occupy bytes 0..16 and every later field sits eight
/// bytes beyond where the old constants assumed. Offset 12 landed *inside* the
/// `data_end` pointer and the verifier refused it with
/// `invalid bpf_context access off=12 size=4`, before the helper call was ever
/// reached. That rejection is reported as `EACCES`.
///
/// The layout below is taken from `struct sk_msg_md` in
/// `include/uapi/linux/bpf.h`.
pub mod sk_msg_md {
    /// `family`.
    pub const FAMILY: i16 = 16;
    /// `remote_ip4`, network byte order.
    pub const REMOTE_IP4: i16 = 20;
    /// `local_ip4`, network byte order.
    pub const LOCAL_IP4: i16 = 24;
    /// `remote_ip6[4]`, network byte order.
    pub const REMOTE_IP6: i16 = 28;
    /// `local_ip6[4]`, network byte order.
    pub const LOCAL_IP6: i16 = 44;
    /// `remote_port`, a network-order 16-bit port delivered in the high half.
    pub const REMOTE_PORT: i16 = 60;
    /// `local_port`, delivered in host byte order.
    pub const LOCAL_PORT: i16 = 64;
    /// `size`.
    pub const SIZE: i16 = 68;
}

/// The exact flow-key length shared by the map, the program and userspace.
///
/// The merged implementation created the map with a 40-byte key but built the
/// program with a 16-byte one. `ARG_PTR_TO_MAP_KEY` requires `map->key_size`
/// readable bytes at the key pointer, so a 16-byte stack slot against a 40-byte
/// map is an out-of-frame read the verifier refuses. One constant now feeds all
/// three, and [`stream_verdict_program`] takes no key-size argument at all, so
/// the two can no longer disagree.
pub const FLOW_KEY_SIZE: i16 = 40;

/// Builds the bounded `SK_SKB` stream-verdict redirect program.
///
/// # What the program does
///
/// For every segment arriving on a socket that is present in the `SOCKHASH`,
/// the program rebuilds that socket's own four-tuple key, looks it up, and
/// redirects the segment to whatever socket userspace registered under it.
///
/// # Why the key is the socket's own tuple, not a reversed one
///
/// A proxy relays two *independent* TCP connections. There is no tuple
/// relationship between the inbound socket and the outbound socket, so no key
/// derived from one can name the other. Userspace therefore registers the peer
/// under each socket's own key:
///
/// ```text
/// map[key(inbound)]  = outbound socket
/// map[key(outbound)] = inbound socket
/// ```
///
/// and the program only has to describe itself. The reversed-key scheme the
/// merged implementation used can only ever find the other end of the *same*
/// connection, which is never the socket a relay wants.
///
/// # Key layout
///
/// ```text
/// key[ 0..16]  local address, IPv4-mapped for v4 flows
/// key[16..32]  remote address
/// key[32..36]  local port                        (u32, native order)
/// key[36..40]  (family << 16) | remote port      (u32, native order)
/// ```
///
/// Ports are 16-bit, so the address family rides in the high half of the last
/// word. That fills exactly forty bytes with no padding and still keeps an
/// IPv4-mapped address distinct from a native IPv6 one.
///
/// `__sk_buff.local_port` arrives in host byte order and is stored unchanged.
/// `__sk_buff.remote_port` arrives as a network-order 16-bit port in the high
/// half of a 32-bit word, so it is shifted down and byte-swapped.
///
/// # Every byte is initialised
///
/// The first five instructions zero all forty key bytes with 8-byte immediate
/// stores, so no verifier path can reach the helper with an uninitialised stack
/// byte regardless of which family branch ran.
///
/// # Verdict
///
/// The program returns the helper's own result. `bpf_sk_redirect_hash` returns
/// `SK_PASS` when it found a peer and `SK_DROP` when it did not — and for a
/// socket that is *in* the map, "no peer" means the relay was torn down, so
/// dropping is correct. A socket that was never armed does not run this program
/// at all and is unaffected.
///
/// # Complexity
///
/// There is no loop and no payload access, so verifier complexity is constant
/// and independent of traffic.
#[must_use]
pub fn stream_verdict_program(map_fd: i32) -> Vec<Insn> {
    let key = FLOW_KEY_SIZE;
    let mut program = Vec::with_capacity(64);

    // r6 = ctx
    program.push(Insn::mov64_reg(6, 1));

    // Zero the whole key so every byte is initialised on every path.
    let mut offset = -key;
    while offset < 0 {
        program.push(Insn::store_imm(size::DW, 10, offset, 0));
        offset += 8;
    }

    // r2 = family
    program.push(Insn::load(size::W, 2, 6, sk_buff::FAMILY));

    let ipv4 = ipv4_address_block(key);
    let ipv6 = ipv6_address_block(key);
    let ipv4_len = i16::try_from(ipv4.len()).unwrap_or(i16::MAX);
    program.push(Insn::jne_imm(2, family::INET, ipv4_len + 1));
    program.extend_from_slice(&ipv4);
    program.push(Insn::jump(i16::try_from(ipv6.len()).unwrap_or(i16::MAX)));
    program.extend_from_slice(&ipv6);

    // key[32..36] = local port, already host order.
    program.push(Insn::load(size::W, 2, 6, sk_buff::LOCAL_PORT));
    program.push(Insn::store(size::W, 10, 2, -key + 32));

    // key[36..40] = (family << 16) | remote port, normalised to host order.
    program.push(Insn::load(size::W, 2, 6, sk_buff::REMOTE_PORT));
    program.push(Insn::rsh64_imm(2, 16));
    program.push(Insn::to_big_endian(2, 16));
    program.push(Insn::load(size::W, 3, 6, sk_buff::FAMILY));
    program.push(Insn::lsh64_imm(3, 16));
    program.push(Insn::or64_reg(2, 3));
    program.push(Insn::store(size::W, 10, 2, -key + 36));

    // bpf_sk_redirect_hash(ctx, &map, &key, 0)
    program.push(Insn::mov64_reg(1, 6));
    let map = Insn::load_map_fd(2, map_fd);
    program.push(map[0]);
    program.push(map[1]);
    program.push(Insn::mov64_reg(3, 10));
    program.push(Insn::add64_imm(3, i32::from(-key)));
    program.push(Insn::mov64_imm(4, 0));
    program.push(Insn::call(helper::SK_REDIRECT_HASH));
    program.push(Insn::exit());
    program
}

/// Writes an IPv4-mapped address pair into the key.
fn ipv4_address_block(key: i16) -> Vec<Insn> {
    vec![
        // key[10..12] = 0xffff, the IPv4-mapped IPv6 prefix.
        Insn::mov64_imm(2, 0xffff),
        Insn::store(size::H, 10, 2, -key + 10),
        Insn::load(size::W, 2, 6, sk_buff::LOCAL_IP4),
        Insn::store(size::W, 10, 2, -key + 12),
        Insn::mov64_imm(2, 0xffff),
        Insn::store(size::H, 10, 2, -key + 26),
        Insn::load(size::W, 2, 6, sk_buff::REMOTE_IP4),
        Insn::store(size::W, 10, 2, -key + 28),
    ]
}

/// Writes a native IPv6 address pair into the key.
///
/// The words are copied four bytes at a time. The context permits only 4-byte
/// access to `remote_ip6`/`local_ip6`; an 8-byte load is refused with
/// `invalid bpf_context access`.
fn ipv6_address_block(key: i16) -> Vec<Insn> {
    let mut block = Vec::with_capacity(16);
    for word in 0..4_i16 {
        block.push(Insn::load(size::W, 2, 6, sk_buff::LOCAL_IP6 + word * 4));
        block.push(Insn::store(size::W, 10, 2, -key + word * 4));
    }
    for word in 0..4_i16 {
        block.push(Insn::load(size::W, 2, 6, sk_buff::REMOTE_IP6 + word * 4));
        block.push(Insn::store(size::W, 10, 2, -key + 16 + word * 4));
    }
    block
}

#[cfg(test)]
mod tests {
    use super::{
        FLOW_KEY_SIZE, Insn, PSEUDO_MAP_FD, class, family, helper, mode, op, size, sk_buff,
        sk_msg_md, source, stream_verdict_program, verdict,
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
        let program = stream_verdict_program(7);
        assert!(program.len() < 64, "the verdict program must stay tiny");
        assert!(
            program
                .iter()
                .all(|insn| insn.code != (class::JMP | op::JA | source::K) || insn.off >= 0),
            "no backward jump may exist, so the program cannot loop"
        );
        assert!(
            program
                .iter()
                .all(|insn| insn.code != (class::JMP | op::JNE | source::K) || insn.off >= 0),
            "no backward conditional jump may exist either"
        );
        assert_eq!(
            program.last().copied(),
            Some(Insn::exit()),
            "the program must end in an exit"
        );
    }

    #[test]
    fn the_program_calls_the_socket_redirect_helper_for_its_program_type() {
        // The merged implementation paired helper 72 with an SK_MSG program.
        // Helper 72 was right for the intent; the program type was wrong. The
        // verifier answers `program of this type cannot use helper
        // bpf_sk_redirect_hash#72` when the two disagree.
        let program = stream_verdict_program(7);
        let call = program
            .iter()
            .find(|insn| insn.code == (class::JMP | op::CALL | source::K))
            .copied()
            .expect("the program must call a helper");
        assert_eq!(call.imm, helper::SK_REDIRECT_HASH);
        assert_eq!(helper::SK_REDIRECT_HASH, 72);
        assert_eq!(helper::MSG_REDIRECT_HASH, 71);
        assert_ne!(
            call.imm,
            helper::MSG_REDIRECT_HASH,
            "helper 71 belongs to SK_MSG and cannot be called from SK_SKB"
        );
    }

    #[test]
    fn the_key_pointer_and_the_map_key_size_are_one_constant() {
        // The merged implementation created a 40-byte-key map and built the
        // program against a 16-byte key, so the helper's ARG_PTR_TO_MAP_KEY
        // check read 24 bytes past the frame pointer.
        let program = stream_verdict_program(7);
        let key_pointer = program
            .iter()
            .find(|insn| insn.code == (class::ALU64 | op::ADD | source::K) && insn.dst() == 3)
            .copied()
            .expect("the program must compute a key pointer in r3");
        assert_eq!(key_pointer.imm, -i32::from(FLOW_KEY_SIZE));
        assert_eq!(FLOW_KEY_SIZE, 40);
    }

    #[test]
    fn every_key_byte_is_initialised_before_the_helper_call() {
        let program = stream_verdict_program(7);
        let zeroing: Vec<_> = program
            .iter()
            .filter(|insn| insn.code == (class::ST | mode::MEM | size::DW) && insn.imm == 0)
            .collect();
        assert_eq!(
            zeroing.len(),
            usize::try_from(FLOW_KEY_SIZE).expect("positive") / 8,
            "the whole key must be zeroed so no verifier path sees uninitialised stack"
        );
        let mut covered: Vec<i16> = zeroing.iter().map(|insn| insn.off).collect();
        covered.sort_unstable();
        assert_eq!(covered, vec![-40, -32, -24, -16, -8]);
    }

    #[test]
    fn the_context_offsets_match_the_kernel_layout() {
        // `__bpf_md_ptr` stores each context pointer in 8 bytes aligned to 8,
        // so `data` and `data_end` occupy 0..16 and every later field follows.
        // The merged implementation used a 4-byte-pointer layout and the
        // verifier refused it with `invalid bpf_context access off=12 size=4`.
        // `__sk_buff`: twenty-two u32 slots precede `family`, including cb[5].
        assert_eq!(sk_buff::FAMILY, 88);
        assert_eq!(sk_buff::REMOTE_IP4, 92);
        assert_eq!(sk_buff::LOCAL_IP4, 96);
        assert_eq!(sk_buff::REMOTE_IP6, 100);
        assert_eq!(sk_buff::LOCAL_IP6, 116);
        assert_eq!(sk_buff::REMOTE_PORT, 132);
        assert_eq!(sk_buff::LOCAL_PORT, 136);
        assert_eq!(
            sk_buff::LOCAL_IP6 - sk_buff::REMOTE_IP6,
            16,
            "each ipv6 field is four 32-bit words"
        );
        // `__bpf_md_ptr` stores each context pointer in 8 bytes aligned to 8,
        // so `sk_msg_md.data`/`data_end` occupy 0..16. The merged
        // implementation assumed 4-byte pointers and the verifier refused it
        // with `invalid bpf_context access off=12 size=4`.
        assert_eq!(sk_msg_md::FAMILY, 16);
        assert_eq!(sk_msg_md::REMOTE_IP4, 20);
        assert_eq!(sk_msg_md::LOCAL_IP4, 24);
    }

    #[test]
    fn both_address_families_are_handled_explicitly() {
        let program = stream_verdict_program(7);
        let reads_family = program.iter().any(|insn| {
            insn.code == (class::LDX | mode::MEM | size::W) && insn.off == sk_buff::FAMILY
        });
        assert!(
            reads_family,
            "the program must branch on the address family"
        );
        let branches_on_inet = program.iter().any(|insn| {
            insn.code == (class::JMP | op::JNE | source::K) && insn.imm == family::INET
        });
        assert!(branches_on_inet, "the IPv4 branch must test AF_INET");
        let reads_ipv6 = program.iter().any(|insn| {
            insn.code == (class::LDX | mode::MEM | size::W) && insn.off == sk_buff::LOCAL_IP6
        });
        assert!(reads_ipv6, "IPv6 flows must build a real IPv6 key");
        assert!(
            program.iter().all(|insn| {
                insn.code != (class::LDX | mode::MEM | size::DW) || insn.src() != 6
            }),
            "sk_msg_md permits only 4-byte context access to the ipv6 words"
        );
    }

    #[test]
    fn the_remote_port_is_normalised_to_host_order() {
        // `sk_msg_md.remote_port` arrives as a network-order 16-bit port in the
        // high half of a 32-bit word; `local_port` arrives in host order and
        // must not be transformed.
        let program = stream_verdict_program(7);
        assert!(
            program
                .iter()
                .any(|insn| insn.code == (class::ALU64 | op::RSH | source::K) && insn.imm == 16),
            "the remote port must be shifted down out of the high half"
        );
        assert!(
            program
                .iter()
                .any(|insn| insn.code == (class::ALU | op::END | source::X) && insn.imm == 16),
            "the remote port must then be byte-swapped to host order"
        );
    }

    #[test]
    fn the_address_family_rides_in_the_high_half_of_the_last_key_word() {
        let program = stream_verdict_program(7);
        assert!(
            program
                .iter()
                .any(|insn| insn.code == (class::ALU64 | op::LSH | source::K) && insn.imm == 16),
            "the family must be shifted into the high half"
        );
        assert!(
            program
                .iter()
                .any(|insn| insn.code == (class::ALU64 | op::OR | source::X)),
            "the family and the port must be combined into one word"
        );
    }

    #[test]
    fn the_program_returns_the_helper_verdict() {
        // The program returns whatever the helper returned. A socket that was
        // never armed never runs this program, so there is no unarmed flow to
        // protect here; a socket that *is* armed but whose peer has gone is a
        // torn-down relay, where dropping is correct.
        let program = stream_verdict_program(7);
        let call_index = program
            .iter()
            .position(|insn| insn.code == (class::JMP | op::CALL | source::K))
            .expect("the program must call a helper");
        assert_eq!(
            program.get(call_index + 1).copied(),
            Some(Insn::exit()),
            "the exit must immediately follow the call so r0 is the helper result"
        );
        assert!(
            !program
                .iter()
                .any(|insn| insn.code == (class::ALU64 | op::MOV | source::K) && insn.dst() == 0),
            "nothing may overwrite the helper's verdict in r0"
        );
        assert_eq!(verdict::PASS, 1);
        assert_eq!(verdict::DROP, 0);
    }
}
