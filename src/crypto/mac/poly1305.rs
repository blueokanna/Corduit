//! Poly1305 one-time authenticator (RFC 8439 §2.5).
//!
//! Portable 26-bit-limb implementation; all arithmetic is data-independent
//! (no secret-dependent branches or table lookups).

const MASK26: u32 = 0x03ff_ffff;

/// Poly1305 incremental MAC.
#[derive(Clone)]
pub struct Poly1305 {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
    buffer: [u8; 16],
    buffer_len: usize,
    /// Whether we have processed at least one full block (affects the
    /// `2^128` term of the final partial block).
    finished: bool,
}

impl Poly1305 {
    /// Create a new authenticator from the 32-byte key.
    pub fn new(key: &[u8; 32]) -> Self {
        // Clamp r per RFC 8439 §2.5.
        let r = [
            u32::from_le_bytes(key[0..4].try_into().expect("4")) & 0x3ff_ffff,
            (u32::from_le_bytes(key[3..7].try_into().expect("4")) >> 2) & 0x3ff_ff03,
            (u32::from_le_bytes(key[6..10].try_into().expect("4")) >> 4) & 0x3ff_c0ff,
            (u32::from_le_bytes(key[9..13].try_into().expect("4")) >> 6) & 0x3f0_3fff,
            (u32::from_le_bytes(key[12..16].try_into().expect("4")) >> 8) & 0x00f_ffff,
        ];
        let pad = [
            u32::from_le_bytes(key[16..20].try_into().expect("4")),
            u32::from_le_bytes(key[20..24].try_into().expect("4")),
            u32::from_le_bytes(key[24..28].try_into().expect("4")),
            u32::from_le_bytes(key[28..32].try_into().expect("4")),
        ];
        Poly1305 {
            r,
            h: [0; 5],
            pad,
            buffer: [0u8; 16],
            buffer_len: 0,
            finished: false,
        }
    }

    /// Absorb message data. `hibit` is `1 << 24` for a final partial block
    /// (the appended 0x01) and `1 << 25` for full blocks (the implicit top
    /// bit of the 129-bit number).
    fn blocks(&mut self, m: &[u8], hibit: u32) {
        let r = self.r;
        // 5 * r limbs, used to fold the high limbs mod 2^130-5 during the
        // product accumulation (2^130 ≡ 5).
        let s1 = r[1].wrapping_mul(5);
        let s2 = r[2].wrapping_mul(5);
        let s3 = r[3].wrapping_mul(5);
        let s4 = r[4].wrapping_mul(5);

        let mut h = self.h;
        debug_assert!(m.len().is_multiple_of(16));
        for block in m.as_chunks::<16>().0 {
            let t0 = u32::from_le_bytes(block[0..4].try_into().expect("4"));
            let t1 = u32::from_le_bytes(block[4..8].try_into().expect("4"));
            let t2 = u32::from_le_bytes(block[8..12].try_into().expect("4"));
            let t3 = u32::from_le_bytes(block[12..16].try_into().expect("4"));

            // h += block (+ 2^128 term encoded by `hibit` for full blocks)
            h[0] += t0 & MASK26;
            h[1] += ((t0 >> 26) | (t1 << 6)) & MASK26;
            h[2] += ((t1 >> 20) | (t2 << 12)) & MASK26;
            h[3] += ((t2 >> 14) | (t3 << 18)) & MASK26;
            h[4] += (t3 >> 8) | hibit;

            // h *= r (mod 2^130-5), with the reduction folded in.
            let mut h0 = h[0] as u64;
            let mut h1 = h[1] as u64;
            let mut h2 = h[2] as u64;
            let mut h3 = h[3] as u64;
            let mut h4 = h[4] as u64;
            let r0 = r[0] as u64;
            let r1 = r[1] as u64;
            let r2 = r[2] as u64;
            let r3 = r[3] as u64;
            let r4 = r[4] as u64;
            let s1 = s1 as u64;
            let s2 = s2 as u64;
            let s3 = s3 as u64;
            let s4 = s4 as u64;

            let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
            let mut d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
            let mut d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
            let mut d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
            let mut d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

            // (partial) h %= p
            let mut c;
            c = (d0 >> 26) as u32;
            h0 = d0 & MASK26 as u64;
            d1 += c as u64;
            c = (d1 >> 26) as u32;
            h1 = d1 & MASK26 as u64;
            d2 += c as u64;
            c = (d2 >> 26) as u32;
            h2 = d2 & MASK26 as u64;
            d3 += c as u64;
            c = (d3 >> 26) as u32;
            h3 = d3 & MASK26 as u64;
            d4 += c as u64;
            c = (d4 >> 26) as u32;
            h4 = d4 & MASK26 as u64;
            h0 += (c as u64) * 5;
            c = (h0 >> 26) as u32;
            h0 &= MASK26 as u64;
            h1 += c as u64;

            h = [h0 as u32, h1 as u32, h2 as u32, h3 as u32, h4 as u32];
        }
        self.h = h;
    }

    /// Absorb message bytes (any length).
    pub fn update(&mut self, mut m: &[u8]) {
        if self.buffer_len > 0 {
            let want = 16 - self.buffer_len;
            let take = want.min(m.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&m[..take]);
            self.buffer_len += take;
            m = &m[take..];
            if self.buffer_len == 16 {
                let full = self.buffer;
                self.blocks(&full, 1 << 24);
                self.buffer_len = 0;
            }
        }

        if m.len() >= 16 {
            let full = m.len() - (m.len() % 16);
            self.blocks(&m[..full], 1 << 24);
            m = &m[full..];
        }

        if !m.is_empty() {
            self.buffer[..m.len()].copy_from_slice(m);
            self.buffer_len = m.len();
        }
        self.finished = false;
    }

    /// Produce the 16-byte tag.
    pub fn finalize(mut self) -> [u8; 16] {
        if self.buffer_len > 0 {
            // pad with 1 bit (append 0x01) then zeros; this block uses hibit=0
            // because the 2^128 term is already encoded by the 0x01 byte.
            self.buffer[self.buffer_len] = 1;
            for b in &mut self.buffer[self.buffer_len + 1..] {
                *b = 0;
            }
            let block = self.buffer;
            self.blocks(&block, 0);
            self.buffer_len = 0;
        }

        // Fully carry h.
        let mut h = self.h;
        let mut c = h[1] >> 26;
        h[1] &= MASK26;
        h[2] += c;
        c = h[2] >> 26;
        h[2] &= MASK26;
        h[3] += c;
        c = h[3] >> 26;
        h[3] &= MASK26;
        h[4] += c;
        c = h[4] >> 26;
        h[4] &= MASK26;
        h[0] += c * 5;
        c = h[0] >> 26;
        h[0] &= MASK26;
        h[1] += c;

        // Compute h - p (i.e. h + 5 mod 2^130-5) and select it if no borrow.
        let mut g0 = h[0].wrapping_add(5);
        c = g0 >> 26;
        g0 &= MASK26;
        let mut g1 = h[1].wrapping_add(c);
        c = g1 >> 26;
        g1 &= MASK26;
        let mut g2 = h[2].wrapping_add(c);
        c = g2 >> 26;
        g2 &= MASK26;
        let mut g3 = h[3].wrapping_add(c);
        c = g3 >> 26;
        g3 &= MASK26;
        let mut g4 = h[4].wrapping_add(c);
        c = g4 >> 26;
        g4 &= MASK26;
        // If g overflowed (c == 1), g = h - p is the reduced value; otherwise
        // (c == 0) keep h.
        let mask = 0u32.wrapping_sub(c); // all-ones when c==1, 0 when c==0
        let h0 = (h[0] & !mask) | (g0 & mask);
        let h1 = (h[1] & !mask) | (g1 & mask);
        let h2 = (h[2] & !mask) | (g2 & mask);
        let h3 = (h[3] & !mask) | (g3 & mask);
        let h4 = (h[4] & !mask) | (g4 & mask);

        // Reassemble as 4×32-bit words (mod 2^128).
        let w0 = h0 | (h1 << 26);
        let w1 = (h1 >> 6) | (h2 << 20);
        let w2 = (h2 >> 12) | (h3 << 14);
        let w3 = (h3 >> 18) | (h4 << 8);

        // Add the pad (s) mod 2^128.
        let f0 = (w0 as u64).wrapping_add(self.pad[0] as u64);
        let f1 = (w1 as u64)
            .wrapping_add(self.pad[1] as u64)
            .wrapping_add(f0 >> 32);
        let f2 = (w2 as u64)
            .wrapping_add(self.pad[2] as u64)
            .wrapping_add(f1 >> 32);
        let f3 = (w3 as u64)
            .wrapping_add(self.pad[3] as u64)
            .wrapping_add(f2 >> 32);

        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&(f0 as u32).to_le_bytes());
        out[4..8].copy_from_slice(&(f1 as u32).to_le_bytes());
        out[8..12].copy_from_slice(&(f2 as u32).to_le_bytes());
        out[12..16].copy_from_slice(&(f3 as u32).to_le_bytes());
        out
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
    fn rfc8439_vectors() {
        // RFC 8439 §2.5.2.
        let key = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let msg = b"Cryptographic Forum Research Group";
        let mut mac = Poly1305::new(&key);
        mac.update(msg);
        assert_eq!(hex(&mac.finalize()), "a8061dc1305136c6c22b8baf0c0127a9");
    }

    #[test]
    fn rfc8439_empty() {
        let key = [0u8; 32];
        let mut mac = Poly1305::new(&key);
        mac.update(b"");
        assert_eq!(hex(&mac.finalize()), "00000000000000000000000000000000");
    }

    #[test]
    fn incremental_matches_oneshot() {
        let key = [0x42u8; 32];
        let msg: Vec<u8> = (0u8..=200).collect();
        let mut one = Poly1305::new(&key);
        one.update(&msg);
        let expected = one.finalize();

        let mut inc = Poly1305::new(&key);
        for chunk in msg.chunks(7) {
            inc.update(chunk);
        }
        assert_eq!(inc.finalize(), expected);
    }
}
