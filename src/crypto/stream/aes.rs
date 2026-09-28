//! AES block cipher (FIPS 197).
//!
//! Round functions: the hardware when the CPU has it — AES-NI on
//! x86/x86_64, the ARMv8 AES instructions on aarch64 (runtime-detected, see
//! [`aes_hw`](super::aes_hw)) — and the software rounds below otherwise. The
//! key schedule has exactly one implementation (the table-driven FIPS 197
//! reference) and both paths consume the same round-key bytes, so they
//! cannot disagree; the software rounds use fixed S-box tables and no
//! data-dependent branches, the standard portable fallback.

use super::aes_hw;
use crate::crypto::util::load_u32_be;

/// The AES S-box (generated from the multiplicative inverse in GF(2^8) plus
/// an affine transform). Precomputed table.
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// Inverse S-box.
const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

/// Round constants.
const RCON: [u32; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// AES key schedule for a 128/192/256-bit key, with the round functions on
/// the hardware when the CPU provides them.
pub struct Aes {
    /// Round keys in FIPS 197 byte order: `rounds + 1` blocks of 16 bytes,
    /// the layout the hardware instructions load and `add_round_key` XORs.
    round_keys: [[u8; 16]; 15],
    rounds: usize,
    /// Whether the round functions may take the hardware path. Only ever
    /// `true` when `aes_hw::available()` said so for this CPU; on
    /// architectures without a back end the field is always `false` and the
    /// reader below is compiled out.
    #[cfg_attr(
        not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")),
        allow(dead_code)
    )]
    hw: bool,
}

impl Aes {
    /// Construct from a 16, 24 or 32-byte key.
    pub fn new(key: &[u8]) -> Result<Self, crate::crypto::InvalidLength> {
        Self::with_backend(key, true)
    }

    /// Construct from a key, gating the hardware path on `hw` (still
    /// subject to CPU detection). The tests use `false` to run the same
    /// vectors through both paths side by side.
    fn with_backend(key: &[u8], hw: bool) -> Result<Self, crate::crypto::InvalidLength> {
        let nk = match key.len() {
            16 => 4,
            24 => 6,
            32 => 8,
            _ => return Err(crate::crypto::InvalidLength),
        };
        let rounds = nk + 6; // 10 / 12 / 14

        let mut w = [0u32; 60];
        for (i, word) in w[..nk].iter_mut().enumerate() {
            *word = load_u32_be(&key[i * 4..]);
        }

        let total = 4 * (rounds + 1);
        for i in nk..total {
            let mut temp = w[i - 1];
            if i % nk == 0 {
                let r = temp.rotate_left(8);
                temp = u32::from_be_bytes([
                    SBOX[(r >> 24) as usize],
                    SBOX[(r >> 16 & 0xff) as usize],
                    SBOX[(r >> 8 & 0xff) as usize],
                    SBOX[(r & 0xff) as usize],
                ]) ^ (RCON[i / nk - 1] << 24);
            } else if nk > 6 && i % nk == 4 {
                temp = u32::from_be_bytes([
                    SBOX[(temp >> 24) as usize],
                    SBOX[(temp >> 16 & 0xff) as usize],
                    SBOX[(temp >> 8 & 0xff) as usize],
                    SBOX[(temp & 0xff) as usize],
                ]);
            }
            w[i] = w[i - nk] ^ temp;
        }

        let mut round_keys = [[0u8; 16]; 15];
        for (block, words) in round_keys.iter_mut().zip(w[..total].chunks_exact(4)) {
            for (word, out) in words.iter().zip(block.chunks_exact_mut(4)) {
                out.copy_from_slice(&word.to_be_bytes());
            }
        }

        Ok(Aes {
            round_keys,
            rounds,
            hw: hw && aes_hw::available(),
        })
    }

    #[inline]
    fn add_round_key(state: &mut [u8; 16], round_key: &[u8; 16]) {
        for (s, k) in state.iter_mut().zip(round_key.iter()) {
            *s ^= k;
        }
    }

    /// Encrypt one 16-byte block in place, on the hardware rounds when the
    /// CPU has them.
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
        if self.hw && aes_hw::encrypt_block(self.rounds, &self.round_keys, block) {
            return;
        }

        let mut state = *block;
        Self::add_round_key(&mut state, &self.round_keys[0]);

        for round in 1..self.rounds {
            // SubBytes
            for b in state.iter_mut() {
                *b = SBOX[*b as usize];
            }
            // ShiftRows
            let mut t = [0u8; 16];
            for r in 0..4 {
                for c in 0..4 {
                    t[c * 4 + r] = state[((c + r) % 4) * 4 + r];
                }
            }
            state = t;
            // MixColumns
            mix_columns(&mut state);
            Self::add_round_key(&mut state, &self.round_keys[round]);
        }

        // Final round (no MixColumns).
        for b in state.iter_mut() {
            *b = SBOX[*b as usize];
        }
        let mut t = [0u8; 16];
        for r in 0..4 {
            for c in 0..4 {
                t[c * 4 + r] = state[((c + r) % 4) * 4 + r];
            }
        }
        state = t;
        Self::add_round_key(&mut state, &self.round_keys[self.rounds]);

        *block = state;
    }

    /// Decrypt one 16-byte block in place, on the hardware rounds when the
    /// CPU has them.
    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
        if self.hw && aes_hw::decrypt_block(self.rounds, &self.round_keys, block) {
            return;
        }

        let mut state = *block;
        Self::add_round_key(&mut state, &self.round_keys[self.rounds]);

        for round in (1..self.rounds).rev() {
            inv_shift_rows(&mut state);
            for b in state.iter_mut() {
                *b = INV_SBOX[*b as usize];
            }
            Self::add_round_key(&mut state, &self.round_keys[round]);
            inv_mix_columns(&mut state);
        }

        inv_shift_rows(&mut state);
        for b in state.iter_mut() {
            *b = INV_SBOX[*b as usize];
        }
        Self::add_round_key(&mut state, &self.round_keys[0]);

        *block = state;
    }
}

/// Multiply two GF(2^8) elements via the Russian-peasant algorithm with
/// branch-free reduction (a fixed 8-iteration loop, constant-time).
#[inline]
fn gf_mul(a: u8, b: u8) -> u8 {
    let mut result = 0u8;
    let mut a = a;
    let mut b = b;
    for _ in 0..8 {
        let bit = (b & 1).wrapping_neg();
        result ^= a & bit;
        let carry = ((a >> 7) & 1).wrapping_neg();
        a <<= 1;
        a ^= 0x1b & carry;
        b >>= 1;
    }
    result
}

fn mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let i = c * 4;
        let a = state[i];
        let b = state[i + 1];
        let cc = state[i + 2];
        let d = state[i + 3];
        state[i] = gf_mul(a, 2) ^ gf_mul(b, 3) ^ cc ^ d;
        state[i + 1] = a ^ gf_mul(b, 2) ^ gf_mul(cc, 3) ^ d;
        state[i + 2] = a ^ b ^ gf_mul(cc, 2) ^ gf_mul(d, 3);
        state[i + 3] = gf_mul(a, 3) ^ b ^ cc ^ gf_mul(d, 2);
    }
}

fn inv_mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let i = c * 4;
        let a = state[i];
        let b = state[i + 1];
        let cc = state[i + 2];
        let d = state[i + 3];
        state[i] = gf_mul(a, 14) ^ gf_mul(b, 11) ^ gf_mul(cc, 13) ^ gf_mul(d, 9);
        state[i + 1] = gf_mul(a, 9) ^ gf_mul(b, 14) ^ gf_mul(cc, 11) ^ gf_mul(d, 13);
        state[i + 2] = gf_mul(a, 13) ^ gf_mul(b, 9) ^ gf_mul(cc, 14) ^ gf_mul(d, 11);
        state[i + 3] = gf_mul(a, 11) ^ gf_mul(b, 13) ^ gf_mul(cc, 9) ^ gf_mul(d, 14);
    }
}

fn inv_shift_rows(state: &mut [u8; 16]) {
    let mut t = [0u8; 16];
    for r in 0..4 {
        for c in 0..4 {
            t[c * 4 + r] = state[((c + 4 - r) % 4) * 4 + r];
        }
    }
    *state = t;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::new();
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    #[test]
    fn fips197_encrypt() {
        // FIPS 197 Appendix C.1: AES-128.
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let pt = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        for hw in [true, false] {
            let aes = Aes::with_backend(&key, hw).unwrap();
            let mut block = pt;
            aes.encrypt_block(&mut block);
            assert_eq!(hex(&block), "69c4e0d86a7b0430d8cdb78070b4c55a");
            aes.decrypt_block(&mut block);
            assert_eq!(block, pt);
        }
    }

    #[test]
    fn fips197_aes192() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ];
        let pt = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        for hw in [true, false] {
            let aes = Aes::with_backend(&key, hw).unwrap();
            let mut block = pt;
            aes.encrypt_block(&mut block);
            assert_eq!(hex(&block), "dda97ca4864cdfe06eaf70a0ec0d7191");
            aes.decrypt_block(&mut block);
            assert_eq!(block, pt);
        }
    }

    #[test]
    fn fips197_aes256() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let pt = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        for hw in [true, false] {
            let aes = Aes::with_backend(&key, hw).unwrap();
            let mut block = pt;
            aes.encrypt_block(&mut block);
            assert_eq!(hex(&block), "8ea2b7ca516745bfeafc49904b496089");
            aes.decrypt_block(&mut block);
            assert_eq!(block, pt);
        }
    }

    #[test]
    fn roundtrip_random_blocks() {
        for len in [16usize, 24, 32] {
            let key = [0x5au8; 32];
            let aes = Aes::new(&key[..len]).unwrap();
            for seed in 0u8..=20 {
                let mut block = [seed; 16];
                let orig = block;
                aes.encrypt_block(&mut block);
                assert_ne!(block, orig);
                aes.decrypt_block(&mut block);
                assert_eq!(block, orig);
            }
        }
    }

    /// The hardware round functions and the software rounds must agree on
    /// every key size, in both directions. On a CPU without a hardware back
    /// end this only runs the software path twice; on one with it (x86_64
    /// here, aarch64 anywhere the crate is built for ARM) it is the cross
    /// check between the two implementations — including the ARMv8 round
    /// ordering, which an x86 development machine cannot execute.
    #[test]
    fn hardware_rounds_match_the_software_rounds() {
        if !aes_hw::available() {
            return;
        }
        for len in [16usize, 24, 32] {
            let mut key = [0u8; 32];
            for (i, b) in key.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(37).wrapping_add(len as u8);
            }
            let hw = Aes::with_backend(&key[..len], true).unwrap();
            let sw = Aes::with_backend(&key[..len], false).unwrap();
            assert!(hw.hw, "hardware backend not selected for a {len}-byte key");
            for seed in 0u8..=32 {
                let mut orig = [0u8; 16];
                for (i, b) in orig.iter_mut().enumerate() {
                    *b = seed ^ (i as u8).wrapping_mul(23);
                }
                let mut hw_block = orig;
                let mut sw_block = orig;
                hw.encrypt_block(&mut hw_block);
                sw.encrypt_block(&mut sw_block);
                assert_eq!(
                    hw_block, sw_block,
                    "encrypt mismatch, {len}-byte key, seed {seed}"
                );
                let mut hw_back = hw_block;
                let mut sw_back = hw_block;
                hw.decrypt_block(&mut hw_back);
                sw.decrypt_block(&mut sw_back);
                assert_eq!(
                    hw_back, sw_back,
                    "decrypt mismatch, {len}-byte key, seed {seed}"
                );
                assert_eq!(hw_back, orig);
            }
        }
    }
}
