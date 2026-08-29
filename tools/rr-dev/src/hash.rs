//! A small, dependency-free SHA-256.
//!
//! Uses `std::fmt::Write` for hex rendering.
//!
//! The release stages hash whole files with the external `sha256sum`, but the
//! config-identity fingerprint hashes many small in-memory JSON values, so a
//! per-value subprocess would be absurd. Rather than pull `sha2` and its
//! `digest`/`generic-array`/`cpufeatures` graph into the otherwise minimal tools
//! workspace, this implements FIPS 180-4 SHA-256 directly. It is verified against
//! the standard test vectors.

use std::fmt::Write as _;

const H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const K: [u32; 64] = [
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

/// Returns the lowercase hex SHA-256 of a file's contents.
///
/// # Errors
///
/// Returns a message when the file cannot be read.
pub fn sha256_file(path: &std::path::Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(sha256_hex(&bytes))
}

/// Returns the lowercase hex SHA-256 of `data`.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = sha256(data);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

/// Computes the raw 32-byte SHA-256 digest of `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hash = H0;

    // Pad: message, 0x80, zeros, then 64-bit big-endian bit length.
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut message = data.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in message.chunks_exact(64) {
        let mut w = [0_u32; 64];
        for (index, word) in chunk.chunks_exact(4).enumerate() {
            w[index] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }

        let mut v = hash;
        for index in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ ((!v[4]) & v[6]);
            let temp1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[index])
                .wrapping_add(w[index]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let temp2 = s0.wrapping_add(maj);
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

    let mut out = [0_u8; 32];
    for (index, word) in hash.iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// An incremental SHA-256 for streaming bodies.
///
/// The origin's access log hashes request bodies that arrive in 256 KiB reads;
/// buffering a whole multi-MiB upload to hash it once would double the memory
/// the heaviest cells push through the origin.
pub struct Sha256 {
    state: [u32; 8],
    buffered: [u8; 64],
    buffered_len: usize,
    total_len: u64,
}

impl Sha256 {
    /// Starts a fresh digest.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: H0,
            buffered: [0; 64],
            buffered_len: 0,
            total_len: 0,
        }
    }

    /// Absorbs one more slice of the message.
    pub fn update(&mut self, data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        let mut rest = data;
        if self.buffered_len > 0 {
            let take = (64 - self.buffered_len).min(rest.len());
            self.buffered[self.buffered_len..self.buffered_len + take]
                .copy_from_slice(&rest[..take]);
            self.buffered_len += take;
            rest = &rest[take..];
            if self.buffered_len == 64 {
                let block = self.buffered;
                Self::compress(&mut self.state, &block);
                self.buffered_len = 0;
            }
        }
        for chunk in rest.chunks_exact(64) {
            if let Ok(block) = chunk.try_into() {
                Self::compress(&mut self.state, block);
            }
        }
        // Only overwrite the buffer when this call actually brought bytes; an
        // empty update must leave previously buffered data alone.
        if !rest.is_empty() {
            let tail = rest.len() - rest.len() / 64 * 64;
            self.buffered[..tail].copy_from_slice(&rest[rest.len() - tail..]);
            self.buffered_len = tail;
        }
    }

    /// Finishes the digest and renders it as lowercase hex.
    #[must_use]
    pub fn finish_hex(self) -> String {
        let mut block = [0_u8; 128];
        block[..self.buffered_len].copy_from_slice(&self.buffered[..self.buffered_len]);
        block[self.buffered_len] = 0x80;
        let head = self.buffered_len + 1;
        let tail = if head <= 56 { 56 } else { 120 };
        let bit_len = self.total_len.wrapping_mul(8).to_be_bytes();
        block[tail..tail + 8].copy_from_slice(&bit_len);
        let mut state = self.state;
        for chunk in block[..tail + 8].chunks_exact(64) {
            if let Ok(block) = chunk.try_into() {
                Self::compress(&mut state, block);
            }
        }
        let mut out = String::with_capacity(64);
        for word in state {
            for byte in word.to_be_bytes() {
                let _ = write!(out, "{byte:02x}");
            }
        }
        out
    }

    fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
        let mut w = [0_u32; 64];
        for (index, word) in block.chunks_exact(4).enumerate() {
            w[index] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }
        let mut v = *state;
        for index in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ ((!v[4]) & v[6]);
            let temp1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[index])
                .wrapping_add(w[index]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let temp2 = s0.wrapping_add(maj);
            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3].wrapping_add(temp1);
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = temp1.wrapping_add(temp2);
        }
        for (slot, value) in state.iter_mut().zip(v) {
            *slot = slot.wrapping_add(value);
        }
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_standard_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn a_block_boundary_length_is_correct() {
        // 56 bytes forces an extra padding block.
        let input = vec![b'a'; 56];
        assert_eq!(
            sha256_hex(&input),
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
        );
    }
    #[test]
    fn every_prefix_length_matches_one_shot() {
        // Every message length 0..=200 in one update, then in two splits,
        // must reproduce the one-shot digest; the first divergence names the
        // broken code path.
        for total in 0..=200_usize {
            let message: Vec<u8> = (0..total)
                .map(|index| u8::try_from((index * 7 + 3) % 256).unwrap())
                .collect();
            let expected = sha256_hex(&message);
            let mut single = Sha256::new();
            single.update(&message);
            assert_eq!(
                single.finish_hex(),
                expected,
                "single update, total={total}"
            );
            for split in 0..=total {
                if total == 1 && split == 1 {
                    let mut probe = Sha256::new();
                    probe.update(&message[..1]);
                    let after_first = probe.finish_hex();
                    let mut probe = Sha256::new();
                    probe.update(&message[..1]);
                    probe.update(&message[1..]);
                    assert_eq!(after_first, expected, "first-update digest already wrong");
                }
                let mut parts = Sha256::new();
                parts.update(&message[..split]);
                parts.update(&message[split..]);
                assert_eq!(parts.finish_hex(), expected, "split {split}/{total}");
            }
        }
    }

    #[test]
    fn incremental_hashing_matches_one_shot() {
        let mut incremental = Sha256::new();
        let mut one_shot = Vec::new();
        let mut seed = 0x1234_5678_u32;
        for _ in 0..1000 {
            let length = (seed % 300) as usize;
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let seed_byte = seed.to_le_bytes()[0];
            let chunk: Vec<u8> = (0..length)
                .map(|index| u8::try_from(index % 256).unwrap() ^ seed_byte)
                .collect();
            incremental.update(&chunk);
            one_shot.extend_from_slice(&chunk);
        }
        assert_eq!(incremental.finish_hex(), sha256_hex(&one_shot));
    }

    #[test]
    fn empty_and_exact_block_boundaries_match_one_shot() {
        assert_eq!(Sha256::new().finish_hex(), sha256_hex(b""));
        let exact = vec![7_u8; 64];
        let mut incremental = Sha256::new();
        incremental.update(&exact);
        assert_eq!(incremental.finish_hex(), sha256_hex(&exact));
        let mut incremental = Sha256::new();
        incremental.update(&exact);
        incremental.update(&exact);
        assert_eq!(incremental.finish_hex(), sha256_hex(&[7_u8; 128]));
    }
}
