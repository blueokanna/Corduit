//! SHA-3 (FIPS 202): SHA3-224/256/384/512, built on the Keccak-f[1600]
//! permutation and the sponge construction.
//!
//! The implementation is a straight sponge: absorb `rate` bytes per
//! permutation, then squeeze. Only the 24-round Keccak-f[1600] is needed.

use crate::digest::Digest;
use crate::util::load_u64_le;

/// Keccak-f[1600] round constants.
const RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Rotation offsets for lane (x + 5*y).
const RHO: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

/// Pi lane permutation: dst index = y + 5*((2x+3y) mod 5) for lane x+5y.
const PI: [usize; 25] = [
    0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14, 24, 9, 19, 4,
];

/// One round of Keccak-f[1600]. The theta step is computed with the
/// standard column-parity trick; rho/pi/chi are merged into a single pass.
#[inline]
fn keccak_round(a: &mut [u64; 25], rc: u64) {
    // theta
    let mut c = [0u64; 5];
    for x in 0..5 {
        c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
    }
    let mut d = [0u64; 5];
    for x in 0..5 {
        d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
    }
    for y in 0..5 {
        for x in 0..5 {
            a[x + 5 * y] ^= d[x];
        }
    }

    // rho + pi + chi, with the rotation applied to the permuted lane.
    let mut b = [0u64; 25];
    for y in 0..5 {
        for x in 0..5 {
            let i = x + 5 * y;
            let j = PI[i];
            b[j] = a[i].rotate_left(RHO[i]);
        }
    }
    for y in 0..5 {
        for x in 0..5 {
            let i = x + 5 * y;
            a[i] = b[i] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
        }
    }

    // iota
    a[0] ^= rc;
}

/// Keccak-f[1600] permutation.
fn keccak_f1600(state: &mut [u64; 25]) {
    for &rc in RC.iter() {
        keccak_round(state, rc);
    }
}

/// Sponge-based SHA-3 hasher.
#[derive(Clone)]
pub struct Sha3 {
    state: [u64; 25],
    rate: usize,
    buf: [u8; 168], // max rate = 168 bytes (SHA3-224)
    buf_len: usize,
    out_len: usize,
    finished: bool,
    domain: u8,
}

impl Sha3 {
    /// Create a hasher with the given rate (bytes per permutation) and
    /// output length. `domain` is the multi-rate padding suffix (0x06 for
    /// SHA-3, 0x1f for SHAKE).
    pub(crate) fn new(rate: usize, out_len: usize, domain: u8) -> Self {
        Sha3 {
            state: [0u64; 25],
            rate,
            buf: [0u8; 168],
            buf_len: 0,
            out_len,
            finished: false,
            domain,
        }
    }

    fn absorb_block(&mut self, block: &[u8]) {
        debug_assert_eq!(block.len(), self.rate);
        for (i, chunk) in block.chunks_exact(8).enumerate() {
            self.state[i] ^= load_u64_le(chunk);
        }
        keccak_f1600(&mut self.state);
    }
}

/// Multi-rate padding domain suffixes (FIPS 202 §6).
mod private {
    pub const DOMAIN_SHA3: u8 = 0x06;
    #[allow(dead_code)]
    pub const DOMAIN_SHAKE: u8 = 0x1f;
}

impl Digest for Sha3 {
    const OUTPUT_LEN: usize = 32; // overridden per-type below via wrapper types
    const BLOCK_LEN: usize = 136;

    fn new() -> Self {
        Sha3::new(136, 32, private::DOMAIN_SHA3)
    }

    fn update(&mut self, mut data: &[u8]) {
        if self.finished {
            // absorbing after squeeze is not allowed
            return;
        }
        if self.buf_len != 0 {
            let need = self.rate - self.buf_len;
            let take = need.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == self.rate {
                let mut arr = [0u8; 168];
                arr[..self.rate].copy_from_slice(&self.buf[..self.rate]);
                self.absorb_block(&arr[..self.rate]);
                self.buf_len = 0;
            }
        }

        while data.len() >= self.rate {
            let mut arr = [0u8; 168];
            arr[..self.rate].copy_from_slice(&data[..self.rate]);
            self.absorb_block(&arr[..self.rate]);
            data = &data[self.rate..];
        }

        self.buf[..data.len()].copy_from_slice(data);
        if !data.is_empty() {
            self.buf_len = data.len();
        }
    }

    fn finalize_into(mut self, out: &mut [u8]) {
        debug_assert!(out.len() >= self.out_len);
        // multi-rate padding: domain byte after the message, 0x80 at the last
        // position of the block, zeros in between.
        self.buf[self.buf_len] ^= self.domain;
        for b in &mut self.buf[self.buf_len + 1..self.rate - 1] {
            *b = 0;
        }
        self.buf[self.rate - 1] ^= 0x80;
        let mut arr = [0u8; 168];
        arr[..self.rate].copy_from_slice(&self.buf[..self.rate]);
        self.absorb_block(&arr[..self.rate]);
        self.finished = true;
        self.buf_len = 0;

        // squeeze
        let mut written = 0;
        while written < self.out_len {
            let mut bytes = [0u8; 168];
            // Only the `rate` bytes of the state are fresh output.
            for (i, word) in self.state[..self.rate / 8].iter().enumerate() {
                bytes[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
            }
            let take = (self.out_len - written).min(self.rate);
            out[written..written + take].copy_from_slice(&bytes[..take]);
            written += take;
            if written < self.out_len {
                keccak_f1600(&mut self.state);
            }
        }
    }
}

macro_rules! define_sha3 {
    ($name:ident, $rate:expr, $out:expr) => {
        /// SHA-3 hasher.
        #[derive(Clone)]
        pub struct $name {
            inner: Sha3,
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $name {
            /// One-shot convenience digest.
            pub fn digest(data: &[u8]) -> [u8; $out] {
                let mut h = $name::new();
                h.update(data);
                h.finalize()
            }

            /// Finalize into a fixed-size array.
            pub fn finalize(self) -> [u8; $out] {
                let mut out = [0u8; $out];
                Digest::finalize_into(self, &mut out);
                out
            }
        }

        impl Digest for $name {
            const OUTPUT_LEN: usize = $out;
            const BLOCK_LEN: usize = $rate;

            fn new() -> Self {
                $name {
                    inner: Sha3::new($rate, $out, private::DOMAIN_SHA3),
                }
            }

            fn update(&mut self, data: &[u8]) {
                self.inner.update(data);
            }

            fn finalize_into(self, out: &mut [u8]) {
                debug_assert!(out.len() >= Self::OUTPUT_LEN);
                self.inner.finalize_into(out);
            }
        }
    };
}

define_sha3!(Sha3_224, 144, 28);
define_sha3!(Sha3_256, 136, 32);
define_sha3!(Sha3_384, 104, 48);
define_sha3!(Sha3_512, 72, 64);

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
    fn sha3_256_vectors() {
        // NIST FIPS 202 examples.
        assert_eq!(
            hex(&Sha3_256::digest(b"")),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        assert_eq!(
            hex(&Sha3_256::digest(b"abc")),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }

    #[test]
    fn sha3_512_vectors() {
        assert_eq!(
            hex(&Sha3_512::digest(b"")),
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        );
        assert_eq!(
            hex(&Sha3_512::digest(b"abc")),
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        );
    }

    #[test]
    fn sha3_224_and_384() {
        assert_eq!(
            hex(&Sha3_224::digest(b"abc")),
            "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"
        );
        assert_eq!(
            hex(&Sha3_384::digest(b"abc")),
            "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"
        );
    }

    #[test]
    fn incremental_matches_oneshot() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let mut h = Sha3_256::new();
        for chunk in data.chunks(5) {
            h.update(chunk);
        }
        assert_eq!(h.finalize(), Sha3_256::digest(data));
        let mut h = Sha3_512::new();
        for chunk in data.chunks(17) {
            h.update(chunk);
        }
        assert_eq!(h.finalize(), Sha3_512::digest(data));
    }
}
