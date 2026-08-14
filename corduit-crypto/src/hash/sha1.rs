//! SHA-1 (FIPS 180-4). Implemented for Shadowsocks HKDF-SHA1 and VMess
//! WebSocket handshake compatibility. **Not** collision resistant — never
//! use for signatures or trust anchors.

use crate::digest::Digest;
use crate::util::{load_u32_be, rotl32, store_u32_be};

const INIT: [u32; 5] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0];

/// SHA-1 hasher.
#[derive(Clone)]
pub struct Sha1 {
    state: [u32; 5],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    /// One-shot convenience: SHA-1 of `data`.
    pub fn digest(data: &[u8]) -> [u8; 20] {
        let mut h = Sha1::new();
        h.update(data);
        h.finalize()
    }

    /// Finalize into a 20-byte array.
    pub fn finalize(self) -> [u8; 20] {
        let mut out = [0u8; 20];
        Digest::finalize_into(self, &mut out);
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 80];
        for (i, word) in w[..16].iter_mut().enumerate() {
            *word = load_u32_be(&block[i * 4..]);
        }
        for i in 16..80 {
            w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }

        let [mut a, mut b, mut c, mut d, mut e] = self.state;

        for i in 0..80 {
            let (f, k) = match i / 20 {
                0 => ((b & c) | (!b & d), 0x5a82_7999u32),
                1 => (b ^ c ^ d, 0x6ed9_eba1),
                2 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let temp = rotl32(a, 5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = rotl32(b, 30);
            b = a;
            a = temp;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }
}

impl Digest for Sha1 {
    const OUTPUT_LEN: usize = 20;
    const BLOCK_LEN: usize = 64;

    fn new() -> Self {
        Sha1 {
            state: INIT,
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

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

        while data.len() >= 64 {
            let block: [u8; 64] = data[..64].try_into().expect("len checked");
            self.compress(&block);
            data = &data[64..];
        }

        self.buf[..data.len()].copy_from_slice(data);
        if !data.is_empty() {
            self.buf_len = data.len();
        }
    }

    fn finalize_into(mut self, out: &mut [u8]) {
        debug_assert!(out.len() >= Self::OUTPUT_LEN);

        let bit_len = self.total_len.wrapping_mul(8);
        if self.buf_len < 56 {
            // 0x80 + zeros + 64-bit length all fit in the current block.
            self.buf[self.buf_len] = 0x80;
            // Zero any stale bytes between the 0x80 and the length field.
            for b in &mut self.buf[self.buf_len + 1..56] {
                *b = 0;
            }
            self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
            let block = self.buf;
            self.compress(&block);
        } else {
            // 0x80 at buf_len, zeros to the end, then a fresh length block.
            self.buf[self.buf_len] = 0x80;
            for b in &mut self.buf[self.buf_len + 1..64] {
                *b = 0;
            }
            let block = self.buf;
            self.compress(&block);
            let mut len_block = [0u8; 64];
            len_block[56..64].copy_from_slice(&bit_len.to_be_bytes());
            self.compress(&len_block);
        }

        store_u32_be(&mut out[0..], self.state[0]);
        store_u32_be(&mut out[4..], self.state[1]);
        store_u32_be(&mut out[8..], self.state[2]);
        store_u32_be(&mut out[12..], self.state[3]);
        store_u32_be(&mut out[16..], self.state[4]);
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
    fn fips_vectors() {
        assert_eq!(
            hex(&Sha1::digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(&Sha1::digest(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        // One million 'a' — split to keep the test fast but still valid.
        let mut h = Sha1::new();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            h.update(&chunk);
        }
        assert_eq!(
            hex(&h.finalize()),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }

    #[test]
    fn empty() {
        assert_eq!(
            hex(&Sha1::digest(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn incremental_matches_oneshot() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let mut h = Sha1::new();
        for chunk in data.chunks(7) {
            h.update(chunk);
        }
        assert_eq!(h.finalize(), Sha1::digest(data));
    }
}
