//! zlib checksums: CRC-32 and Adler-32.
//!
//! These are **not** message authentication codes. Both are linear over
//! GF(2)/modular arithmetic, so an attacker who can see a checksum can adjust
//! the data to keep it valid — Adler-32 in particular is trivially forgeable.
//! They are here because ShadowsocksR's `auth_sha1_v4` and `auth_chain_a`
//! handshakes use them as a cheap "is this frame shaped like a frame" test, in
//! front of separate HMACs that carry the actual integrity guarantee. Never
//! use either of them as a substitute for one.
//!
//! Both are table-driven; the tables are built with `const fn` so the
//! implementation stays `no_std` and allocation-free.

/// CRC-32/ISO-HDLC (zlib, gzip, PNG): reflected, polynomial `0xEDB88320`,
/// initial value `0xFFFFFFFF`, final XOR `0xFFFFFFFF`.
const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// Running CRC-32 state.
///
/// A struct rather than a one-shot function because the callers checksum a
/// handshake built from several pieces, and because the SSR code compares a
/// CRC over a prefix of a frame with one over the whole frame.
#[derive(Clone)]
pub struct Crc32 {
    state: u32,
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32 {
    /// A fresh checksum (initial value `0xFFFFFFFF`).
    pub fn new() -> Self {
        Self { state: 0xFFFF_FFFF }
    }

    /// Feed more bytes.
    pub fn update(&mut self, data: &[u8]) {
        let mut crc = self.state;
        for byte in data {
            let index = ((crc ^ u32::from(*byte)) & 0xFF) as usize;
            crc = (crc >> 8) ^ CRC32_TABLE[index];
        }
        self.state = crc;
    }

    /// The checksum of everything fed so far (final XOR applied).
    pub fn finalize(&self) -> u32 {
        self.state ^ 0xFFFF_FFFF
    }

    /// One-shot convenience.
    pub fn compute(data: &[u8]) -> u32 {
        let mut crc = Self::new();
        crc.update(data);
        crc.finalize()
    }
}

/// Adler-32 (RFC 1950): two 16-bit sums modulo 65521.
///
/// The sums are reduced per chunk rather than per byte: 5552 is the largest
/// run for which 32-bit accumulators cannot overflow (2550 * 65520 + 65520 <
/// 2^32), which is the bound zlib documents.
#[derive(Clone)]
pub struct Adler32 {
    a: u32,
    b: u32,
}

impl Default for Adler32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Adler32 {
    /// A fresh checksum (`a = 1`, `b = 0`).
    pub fn new() -> Self {
        Self { a: 1, b: 0 }
    }

    /// Feed more bytes.
    pub fn update(&mut self, data: &[u8]) {
        const MOD: u32 = 65521;
        const MAX_CHUNK: usize = 5552;

        for chunk in data.chunks(MAX_CHUNK) {
            for byte in chunk {
                self.a += u32::from(*byte);
                self.b += self.a;
            }
            self.a %= MOD;
            self.b %= MOD;
        }
    }

    /// The checksum of everything fed so far.
    pub fn finalize(&self) -> u32 {
        (self.b << 16) | self.a
    }

    /// One-shot convenience.
    pub fn compute(data: &[u8]) -> u32 {
        let mut adler = Self::new();
        adler.update(data);
        adler.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical CRC-32 check value: `crc32("123456789")`.
    #[test]
    fn crc32_check_value_is_cbf43926() {
        assert_eq!(Crc32::compute(b"123456789"), 0xCBF4_3926);
    }

    /// The other check values published with the same polynomial, to pin the
    /// reflection and the initial/final XOR independently of the first vector.
    #[test]
    fn crc32_matches_the_published_check_values() {
        assert_eq!(Crc32::compute(b""), 0x0000_0000);
        assert_eq!(Crc32::compute(b"a"), 0xE8B7_BE43);
        assert_eq!(Crc32::compute(b"abc"), 0x3524_41C2);
        assert_eq!(
            Crc32::compute(b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
    }

    /// Adler-32's canonical check values (RFC 1950 and the usual test strings).
    #[test]
    fn adler32_check_values() {
        assert_eq!(Adler32::compute(b"Wikipedia"), 0x11E6_0398);
        assert_eq!(Adler32::compute(b"123456789"), 0x091E_01DE);
        assert_eq!(Adler32::compute(b""), 1, "the empty input has a = 1, b = 0");
    }

    /// Incremental use must equal the one-shot form, including across a chunk
    /// boundary larger than the 5552-byte reduction window.
    #[test]
    fn incremental_use_equals_the_one_shot_form() {
        let data: Vec<u8> = (0..=255u8).cycle().take(70_000).collect();

        let mut crc = Crc32::new();
        let mut adler = Adler32::new();
        for chunk in data.chunks(997) {
            crc.update(chunk);
            adler.update(chunk);
        }
        assert_eq!(crc.finalize(), Crc32::compute(&data));
        assert_eq!(adler.finalize(), Adler32::compute(&data));
    }

    /// Adler-32's reduction is what keeps the accumulators from wrapping: a
    /// long run of 0xff bytes would overflow a naive 32-bit `a` without it.
    #[test]
    fn adler32_does_not_overflow_on_a_long_run_of_maximal_bytes() {
        let data = vec![0xFFu8; 200_000];
        let checksum = Adler32::compute(&data);
        assert_eq!(checksum, Adler32::compute(&data), "deterministic");
        // Recomputing the same data in one huge chunk and in small ones must
        // agree; an overflow would show up as a difference here.
        let mut incremental = Adler32::new();
        for chunk in data.chunks(13) {
            incremental.update(chunk);
        }
        assert_eq!(incremental.finalize(), checksum);
    }

    /// Neither checksum may be mistaken for the other: identical inputs give
    /// different values, which is what makes the four-byte comparison in the
    /// SSR handshake meaningful.
    #[test]
    fn the_two_checksums_are_independent_functions() {
        let data = b"shadowsocksr handshake";
        assert_ne!(
            u64::from(Crc32::compute(data)),
            u64::from(Adler32::compute(data))
        );
    }
}
