//! Deterministic CSPRNG built on ChaCha20.
//!
//! **Seeding is the caller's responsibility.** This generator is only as
//! secure as its seed; in std contexts seed it from the OS RNG (e.g.
//! `getrandom`). All output generation is branch-free and does not touch
//! the platform.

use crate::crypto::stream::ChaCha20;

/// A ChaCha20-based pseudo-random generator.
///
/// The 32-byte seed is the ChaCha key; the 64-bit stream number selects a
/// distinct output stream (so re-seeding with the same key plus a fresh
/// stream counter is safe after a fork/reset).
#[derive(Clone)]
pub struct ChaChaRng {
    cipher: ChaCha20,
    buffer: [u8; 64],
    pos: usize,
}

impl ChaChaRng {
    /// Create from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self::from_seed_and_stream(seed, 0)
    }

    /// Create from a 32-byte seed and a stream number.
    pub fn from_seed_and_stream(seed: &[u8; 32], stream: u64) -> Self {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&stream.to_le_bytes());
        let cipher = ChaCha20::new(seed, &nonce, 0);
        ChaChaRng {
            cipher,
            buffer: [0u8; 64],
            pos: 64,
        }
    }

    fn refill(&mut self) {
        self.cipher.next_block(&mut self.buffer);
        self.pos = 0;
    }

    /// Fill `out` with random bytes.
    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        let mut written = 0;
        if self.pos < 64 {
            let take = (64 - self.pos).min(out.len());
            out[..take].copy_from_slice(&self.buffer[self.pos..self.pos + take]);
            self.pos += take;
            written += take;
        }
        while written < out.len() {
            self.refill();
            let take = (out.len() - written).min(64);
            out[written..written + take].copy_from_slice(&self.buffer[..take]);
            self.pos = take;
            written += take;
        }
    }

    /// Next `u8`.
    pub fn next_u8(&mut self) -> u8 {
        if self.pos >= 64 {
            self.refill();
        }
        let v = self.buffer[self.pos];
        self.pos += 1;
        v
    }

    /// Next `u16` (little-endian).
    pub fn next_u16(&mut self) -> u16 {
        let mut b = [0u8; 2];
        self.fill_bytes(&mut b);
        u16::from_le_bytes(b)
    }

    /// Next `u32` (little-endian).
    pub fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    /// Next `u64` (little-endian).
    pub fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    /// Fill a fixed-size array.
    pub fn fill_array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        self.fill_bytes(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_from_seed() {
        let seed = [0x42u8; 32];
        let mut a = ChaChaRng::from_seed(&seed);
        let mut b = ChaChaRng::from_seed(&seed);
        let mut x = [0u8; 100];
        let mut y = [0u8; 100];
        a.fill_bytes(&mut x);
        b.fill_bytes(&mut y);
        assert_eq!(x, y);

        // Different seed → different stream.
        let mut c = ChaChaRng::from_seed(&[0x43u8; 32]);
        let mut z = [0u8; 100];
        c.fill_bytes(&mut z);
        assert_ne!(x, z);
    }

    #[test]
    fn stream_separation() {
        let seed = [7u8; 32];
        let mut a = ChaChaRng::from_seed_and_stream(&seed, 0);
        let mut b = ChaChaRng::from_seed_and_stream(&seed, 1);
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        a.fill_bytes(&mut x);
        b.fill_bytes(&mut y);
        assert_ne!(x, y);
    }

    #[test]
    fn all_bits_used() {
        // Exhaust the internal buffer and make sure output stays uniform-ish
        // (no panics, deterministic).
        let seed = [1u8; 32];
        let mut rng = ChaChaRng::from_seed(&seed);
        let mut seen = [0u32; 256];
        for _ in 0..10_000 {
            let v = rng.next_u8();
            seen[v as usize] += 1;
        }
        for &count in seen.iter() {
            assert!(count > 0, "some byte value never produced");
        }
    }
}
