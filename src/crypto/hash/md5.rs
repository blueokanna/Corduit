//! MD5 (RFC 1321). Implemented for protocol compatibility (Shadowsocks
//! `EVP_BytesToKey`, VMess command-key derivation). **Not** collision
//! resistant — never use for security-critical integrity.

use crate::crypto::digest::Digest;
use crate::crypto::util::{load_u32_le, store_u32_le};

const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, // round 1
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, // round 2
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, // round 3
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, // round 4
];

const K: [u32; 64] = [
    0xd76a_a478,
    0xe8c7_b756,
    0x2420_70db,
    0xc1bd_ceee,
    0xf57c_0faf,
    0x4787_c62a,
    0xa830_4613,
    0xfd46_9501,
    0x6980_98d8,
    0x8b44_f7af,
    0xffff_5bb1,
    0x895c_d7be,
    0x6b90_1122,
    0xfd98_7193,
    0xa679_438e,
    0x49b4_0821,
    0xf61e_2562,
    0xc040_b340,
    0x265e_5a51,
    0xe9b6_c7aa,
    0xd62f_105d,
    0x0244_1453,
    0xd8a1_e681,
    0xe7d3_fbc8,
    0x21e1_cde6,
    0xc337_07d6,
    0xf4d5_0d87,
    0x455a_14ed,
    0xa9e3_e905,
    0xfcef_a3f8,
    0x676f_02d9,
    0x8d2a_4c8a,
    0xfffa_3942,
    0x8771_f681,
    0x6d9d_6122,
    0xfde5_380c,
    0xa4be_ea44,
    0x4bde_cfa9,
    0xf6bb_4b60,
    0xbebf_bc70,
    0x289b_7ec6,
    0xeaa1_27fa,
    0xd4ef_3085,
    0x0488_1d05,
    0xd9d4_d039,
    0xe6db_99e5,
    0x1fa2_7cf8,
    0xc4ac_5665,
    0xf429_2244,
    0x432a_ff97,
    0xab94_23a7,
    0xfc93_a039,
    0x655b_59c3,
    0x8f0c_cc92,
    0xffef_f47d,
    0x8584_5dd1,
    0x6fa8_7e4f,
    0xfe2c_e6e0,
    0xa301_4314,
    0x4e08_11a1,
    0xf753_7e82,
    0xbd3a_f235,
    0x2ad7_d2bb,
    0xeb86_d391,
];

// Per-round message index permutation.
const X: [usize; 64] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, // round 1
    1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, // round 2
    5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2, // round 3
    0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9, // round 4
];

const INIT: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

/// MD5 hasher.
#[derive(Clone)]
pub struct Md5 {
    state: [u32; 4],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Default for Md5 {
    fn default() -> Self {
        Self::new()
    }
}

impl Md5 {
    /// One-shot convenience: MD5 of `data`.
    pub fn digest(data: &[u8]) -> [u8; 16] {
        let mut h = Md5::new();
        h.update(data);
        h.finalize()
    }

    /// Finalize into a 16-byte array.
    pub fn finalize(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        Digest::finalize_into(self, &mut out);
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut m = [0u32; 16];
        for (i, word) in m.iter_mut().enumerate() {
            *word = load_u32_le(&block[i * 4..]);
        }

        let [mut a, mut b, mut c, mut d] = self.state;

        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), X[i]),
                1 => ((d & b) | (!d & c), X[i]),
                2 => (b ^ c ^ d, X[i]),
                _ => (c ^ (b | !d), X[i]),
            };
            let tmp = d;
            d = c;
            c = b;
            let sum = a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]);
            b = b.wrapping_add(sum.rotate_left(S[i]));
            a = tmp;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }

    fn absorb(&mut self, block: &[u8]) {
        for &byte in block {
            self.buf[self.buf_len] = byte;
            self.buf_len += 1;
            if self.buf_len == 64 {
                let full = self.buf;
                self.compress(&full);
                self.buf_len = 0;
            }
        }
    }
}

impl Digest for Md5 {
    const OUTPUT_LEN: usize = 16;
    const BLOCK_LEN: usize = 64;

    fn new() -> Self {
        Md5 {
            state: INIT,
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        // Top up the partial block first.
        if self.buf_len != 0 {
            let need = 64 - self.buf_len;
            let take = need.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let full = self.buf;
                self.compress(&full);
                self.buf_len = 0;
            }
        }

        // Full blocks straight from the input slice.
        while data.len() >= 64 {
            let block: [u8; 64] = data[..64].try_into().expect("len checked");
            self.compress(&block);
            data = &data[64..];
        }

        // Trailing partial block.
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    fn finalize_into(mut self, out: &mut [u8]) {
        debug_assert!(out.len() >= Self::OUTPUT_LEN);

        // RFC 1321 padding: 0x80, zeros to 56 mod 64, then 64-bit LE bit length.
        let bit_len = self.total_len.wrapping_mul(8);
        self.absorb(&[0x80]);
        while self.buf_len != 56 {
            self.absorb(&[0x00]);
        }
        self.absorb(&bit_len.to_le_bytes());
        debug_assert_eq!(self.buf_len, 0);

        store_u32_le(&mut out[0..], self.state[0]);
        store_u32_le(&mut out[4..], self.state[1]);
        store_u32_le(&mut out[8..], self.state[2]);
        store_u32_le(&mut out[12..], self.state[3]);
    }
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
    fn rfc1321_vectors() {
        // RFC 1321 test suite.
        assert_eq!(hex(&Md5::digest(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(&Md5::digest(b"a")), "0cc175b9c0f1b6a831c399e269772661");
        assert_eq!(
            hex(&Md5::digest(b"abc")),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            hex(&Md5::digest(b"message digest")),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );
        assert_eq!(
            hex(&Md5::digest(b"abcdefghijklmnopqrstuvwxyz")),
            "c3fcd3d76192e4007dfb496cca67e13b"
        );
        assert_eq!(
            hex(&Md5::digest(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            )),
            "d174ab98d277d9f5a5611c2c9f419d9f"
        );
        assert_eq!(
            hex(&Md5::digest(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            )),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
    }

    #[test]
    fn incremental_matches_oneshot() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let mut h = Md5::new();
        h.update(&data[..10]);
        h.update(&data[10..20]);
        h.update(&data[20..]);
        assert_eq!(h.finalize(), Md5::digest(data));
    }

    #[test]
    fn empty_via_incremental() {
        let h = Md5::new();
        assert_eq!(h.finalize(), Md5::digest(b""));
    }
}
