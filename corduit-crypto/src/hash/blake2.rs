//! BLAKE2 (RFC 7693): BLAKE2b and BLAKE2s.
//!
//! Both support keyed hashing (used by WireGuard's MAC) and configurable
//! digest length. The unkeyed defaults implement [`crate::digest::Digest`].

use crate::digest::Digest;
use crate::util::{load_u64_le, store_u64_le};

/// Message schedule shared by both variants.
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

const IV64: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

const IV32: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

// ---------------------------------------------------------------------------
// BLAKE2b
// ---------------------------------------------------------------------------

const BLOCK_BYTES_B: usize = 128;
const MAX_DIGEST_B: usize = 64;
const MAX_KEY_B: usize = 64;

/// BLAKE2b hasher (64-bit word size, 128-byte block).
#[derive(Clone)]
pub struct Blake2b {
    h: [u64; 8],
    t: u128, // byte counter (full width)
    buf: [u8; BLOCK_BYTES_B],
    buf_len: usize,
    digest_len: usize,
}

impl Default for Blake2b {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake2b {
    /// One-shot: BLAKE2b-512 of `data`.
    pub fn digest(data: &[u8]) -> [u8; 64] {
        let mut h = Blake2b::new();
        h.update(data);
        h.finalize()
    }

    /// Finalize into a 64-byte array (only `digest_len` bytes are valid
    /// when a custom digest length was requested).
    pub fn finalize(self) -> [u8; 64] {
        let mut out = [0u8; 64];
        Digest::finalize_into(self, &mut out);
        out
    }

    /// Unkeyed BLAKE2b-512.
    pub fn new() -> Self {
        Self::init(MAX_DIGEST_B, &[])
    }

    /// Keyed BLAKE2b-512. Keys longer than 64 bytes are rejected.
    pub fn new_keyed(key: &[u8]) -> Result<Self, crate::InvalidLength> {
        if key.len() > MAX_KEY_B {
            return Err(crate::InvalidLength);
        }
        Ok(Self::init(MAX_DIGEST_B, key))
    }

    /// BLAKE2b with a custom digest length and optional key.
    pub fn with_params(digest_len: usize, key: &[u8]) -> Result<Self, crate::InvalidLength> {
        if digest_len == 0 || digest_len > MAX_DIGEST_B || key.len() > MAX_KEY_B {
            return Err(crate::InvalidLength);
        }
        Ok(Self::init(digest_len, key))
    }

    fn init(digest_len: usize, key: &[u8]) -> Self {
        let mut h = IV64;
        h[0] ^= 0x0101_0000u64 ^ ((key.len() as u64) << 8) ^ (digest_len as u64);

        let mut hasher = Blake2b {
            h,
            t: 0,
            buf: [0u8; BLOCK_BYTES_B],
            buf_len: 0,
            digest_len,
        };

        // Keyed mode: per RFC 7693 §3.3 / the reference implementation, the
        // key (padded to a full block) is buffered as the first block of the
        // message stream and compressed lazily — either as a regular block
        // (f[0]=0, t=block size) when more data follows, or as the final
        // block (f[0]=1) for an empty message.
        if !key.is_empty() {
            hasher.buf[..key.len()].copy_from_slice(key);
            hasher.buf_len = BLOCK_BYTES_B;
        }
        hasher
    }

    fn compress(&mut self, block: &[u8; BLOCK_BYTES_B], is_last: bool) {
        let mut m = [0u64; 16];
        for (i, word) in m.iter_mut().enumerate() {
            *word = load_u64_le(&block[i * 8..]);
        }

        let mut v = [0u64; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&IV64);
        let t = self.t as u64;
        v[12] ^= t;
        v[13] ^= (self.t >> 64) as u64;
        if is_last {
            v[14] = !v[14];
        }

        for round in 0..12 {
            let s = &SIGMA[round % 10];
            blake2b_g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            blake2b_g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            blake2b_g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            blake2b_g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            blake2b_g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            blake2b_g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            blake2b_g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            blake2b_g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }

        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }
}

#[inline]
fn blake2b_g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

impl Digest for Blake2b {
    const OUTPUT_LEN: usize = 64;
    const BLOCK_LEN: usize = 128;

    fn new() -> Self {
        Blake2b::new()
    }

    fn update(&mut self, mut data: &[u8]) {
        if self.buf_len != 0 {
            let need = BLOCK_BYTES_B - self.buf_len;
            let take = need.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == BLOCK_BYTES_B {
                self.t = self.t.wrapping_add(BLOCK_BYTES_B as u128);
                let block = self.buf;
                self.compress(&block, false);
                self.buf_len = 0;
            }
        }

        while data.len() >= BLOCK_BYTES_B {
            self.t = self.t.wrapping_add(BLOCK_BYTES_B as u128);
            let block: [u8; BLOCK_BYTES_B] = data[..BLOCK_BYTES_B].try_into().expect("len");
            self.compress(&block, false);
            data = &data[BLOCK_BYTES_B..];
        }

        self.buf[..data.len()].copy_from_slice(data);
        if !data.is_empty() {
            self.buf_len = data.len();
        }
    }

    fn finalize_into(mut self, out: &mut [u8]) {
        debug_assert!(out.len() >= self.digest_len);
        self.t = self.t.wrapping_add(self.buf_len as u128);
        let mut block = self.buf;
        // Zero the tail so the final block pads with zeros.
        for b in block[self.buf_len..].iter_mut() {
            *b = 0;
        }
        self.compress(&block, true);

        let mut full = [0u8; 64];
        for (i, word) in self.h.iter().enumerate() {
            store_u64_le(&mut full[i * 8..], *word);
        }
        out[..self.digest_len].copy_from_slice(&full[..self.digest_len]);
    }
}

// ---------------------------------------------------------------------------
// BLAKE2s
// ---------------------------------------------------------------------------

const BLOCK_BYTES_S: usize = 64;
const MAX_DIGEST_S: usize = 32;
const MAX_KEY_S: usize = 32;

/// BLAKE2s hasher (32-bit word size, 64-byte block).
#[derive(Clone)]
pub struct Blake2s {
    h: [u32; 8],
    t: u64,
    buf: [u8; BLOCK_BYTES_S],
    buf_len: usize,
    digest_len: usize,
}

impl Default for Blake2s {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake2s {
    /// One-shot: BLAKE2s-256 of `data`.
    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut h = Blake2s::new();
        h.update(data);
        h.finalize()
    }

    /// Finalize into a 32-byte array (only `digest_len` bytes are valid
    /// when a custom digest length was requested).
    pub fn finalize(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        Digest::finalize_into(self, &mut out);
        out
    }

    /// Unkeyed BLAKE2s-256.
    pub fn new() -> Self {
        Self::init(MAX_DIGEST_S, &[])
    }

    /// Keyed BLAKE2s-256 (WireGuard HMAC-style MAC).
    pub fn new_keyed(key: &[u8]) -> Result<Self, crate::InvalidLength> {
        if key.len() > MAX_KEY_S {
            return Err(crate::InvalidLength);
        }
        Ok(Self::init(MAX_DIGEST_S, key))
    }

    /// BLAKE2s with a custom digest length and optional key.
    pub fn with_params(digest_len: usize, key: &[u8]) -> Result<Self, crate::InvalidLength> {
        if digest_len == 0 || digest_len > MAX_DIGEST_S || key.len() > MAX_KEY_S {
            return Err(crate::InvalidLength);
        }
        Ok(Self::init(digest_len, key))
    }

    fn init(digest_len: usize, key: &[u8]) -> Self {
        let mut h = IV32;
        h[0] ^= 0x0101_0000u32 ^ ((key.len() as u32) << 8) ^ (digest_len as u32);

        let mut hasher = Blake2s {
            h,
            t: 0,
            buf: [0u8; BLOCK_BYTES_S],
            buf_len: 0,
            digest_len,
        };

        if !key.is_empty() {
            hasher.buf[..key.len()].copy_from_slice(key);
            hasher.buf_len = BLOCK_BYTES_S;
        }
        hasher
    }

    fn compress(&mut self, block: &[u8; BLOCK_BYTES_S], is_last: bool) {
        let mut m = [0u32; 16];
        for (i, word) in m.iter_mut().enumerate() {
            *word = u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().expect("4 bytes"));
        }

        let mut v = [0u32; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&IV32);
        v[12] ^= self.t as u32;
        v[13] ^= (self.t >> 32) as u32;
        if is_last {
            v[14] = !v[14];
        }

        for round in 0..10 {
            let s = &SIGMA[round];
            blake2s_g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            blake2s_g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            blake2s_g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            blake2s_g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            blake2s_g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            blake2s_g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            blake2s_g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            blake2s_g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }

        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }
}

#[inline]
fn blake2s_g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

impl Digest for Blake2s {
    const OUTPUT_LEN: usize = 32;
    const BLOCK_LEN: usize = 64;

    fn new() -> Self {
        Blake2s::new()
    }

    fn update(&mut self, mut data: &[u8]) {
        if self.buf_len != 0 {
            let need = BLOCK_BYTES_S - self.buf_len;
            let take = need.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == BLOCK_BYTES_S {
                self.t = self.t.wrapping_add(BLOCK_BYTES_S as u64);
                let block = self.buf;
                self.compress(&block, false);
                self.buf_len = 0;
            }
        }

        while data.len() >= BLOCK_BYTES_S {
            self.t = self.t.wrapping_add(BLOCK_BYTES_S as u64);
            let block: [u8; BLOCK_BYTES_S] = data[..BLOCK_BYTES_S].try_into().expect("len");
            self.compress(&block, false);
            data = &data[BLOCK_BYTES_S..];
        }

        self.buf[..data.len()].copy_from_slice(data);
        if !data.is_empty() {
            self.buf_len = data.len();
        }
    }

    fn finalize_into(mut self, out: &mut [u8]) {
        debug_assert!(out.len() >= self.digest_len);
        self.t = self.t.wrapping_add(self.buf_len as u64);
        let mut block = self.buf;
        for b in block[self.buf_len..].iter_mut() {
            *b = 0;
        }
        self.compress(&block, true);

        let mut full = [0u8; 32];
        for (i, word) in self.h.iter().enumerate() {
            full[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out[..self.digest_len].copy_from_slice(&full[..self.digest_len]);
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
    fn blake2b512_vectors() {
        // RFC 7693 appendix A.
        assert_eq!(
            hex(&Blake2b::digest(b"abc")),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
        assert_eq!(
            hex(&Blake2b::digest(b"")),
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        );
    }

    #[test]
    fn blake2s256_vectors() {
        // RFC 7693 appendix A.
        assert_eq!(
            hex(&Blake2s::digest(b"abc")),
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
        );
        assert_eq!(
            hex(&Blake2s::digest(b"")),
            "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
        );
    }

    #[test]
    fn keyed_blake2s_matches_known() {
        // RFC 7693: key = 00..1f, msg = "abc"
        let key: Vec<u8> = (0u8..0x20).collect();
        let mut h = Blake2s::new_keyed(&key).unwrap();
        h.update(b"abc");
        assert_eq!(
            hex(&h.finalize()),
            "a281f725754969a702f6fe36fc591b7def866e4b70173ece402fc01c064d6b65"
        );
    }

    #[test]
    fn keyed_blake2b_matches_known() {
        // RFC 7693: key = 00..3f, msg = "abc"
        let key: Vec<u8> = (0u8..0x40).collect();
        let mut h = Blake2b::new_keyed(&key).unwrap();
        h.update(b"abc");
        assert_eq!(
            hex(&h.finalize()),
            "06bbc3dedf13a31139498655251b7588ccd3bb5aaa071b2d44d8e0a04095579ed590fbfdcf941f4370ce5ce623624e7a76d33e7a8109dcda9b57d72f8f8efa51"
        );
    }

    #[test]
    fn blake2s_custom_digest_len() {
        // RFC 7693: a 16-byte BLAKE2s digest of "abc".
        let mut h = Blake2s::with_params(16, &[]).unwrap();
        h.update(b"abc");
        let mut out = [0u8; 16];
        h.finalize_into(&mut out);
        assert_eq!(hex(&out), "aa4938119b1dc7b87cbad0ffd200d0ae");
    }

    #[test]
    fn incremental_matches_oneshot() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let mut h = Blake2b::new();
        for c in data.chunks(9) {
            h.update(c);
        }
        assert_eq!(h.finalize(), Blake2b::digest(data));
        let mut h = Blake2s::new();
        for c in data.chunks(9) {
            h.update(c);
        }
        assert_eq!(h.finalize(), Blake2s::digest(data));
    }
}
