//! Salsa20 (the original 2005 design, 20 rounds) — needed only because
//! ShadowsocksR names a `salsa20` method.
//!
//! Salsa20 is ChaCha20's ancestor: the same ARX construction over a 4×4 word
//! state, with a **64-bit** nonce and a **64-bit** block counter instead of
//! ChaCha's split. It is not obsolete as a cipher (no practical attack
//! applies to the 20-round variant), but nothing new should choose it either —
//! ChaCha20 is faster on every platform and has a better-studied
//! implementation record. It is here for wire compatibility, and the RFC 8439
//! variant in [`super::chacha20`] is what everything else uses.
//!
//! # Two things that are easy to get wrong
//!
//! * **The round order.** Salsa20's double round is *column* quarter-rounds
//!   followed by *row* quarter-rounds, on the state read as a 4×4 matrix in
//!   column-major order — which is why the column indices look like
//!   `(0,4,8,12)` rather than `(0,1,2,3)`. An implementation that swapped the
//!   two would produce a different, perfectly plausible keystream.
//! * **Byte order.** The state is little-endian throughout, and the counter is
//!   the low half of the state's last two words.
//!
//! The ECRYPT test vector below pins both.

/// "expa", "nd 3", "2-by", "te k" — the same four constants ChaCha20 uses.
const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// Salsa20/20 keystream generator.
#[derive(Clone)]
pub struct Salsa20 {
    state: [u32; 16],
    /// Keystream of the block currently being consumed, and what is left of it.
    pending: [u8; 64],
    pending_left: usize,
}

impl Salsa20 {
    /// Build from a 32-byte key, an 8-byte nonce and a 64-bit block counter.
    ///
    /// The counter starts at zero for a fresh stream; a caller that needs to
    /// resume at a known offset (the cipher's per-connection IV handling does
    /// not, but a stream that was cut short would) can set it here.
    pub fn new(key: &[u8; 32], nonce: &[u8; 8], counter: u64) -> Self {
        let mut state = [0u32; 16];
        state[0] = CONSTANTS[0];
        state[5] = CONSTANTS[1];
        state[10] = CONSTANTS[2];
        state[15] = CONSTANTS[3];
        for (i, word) in state[1..5].iter_mut().enumerate() {
            *word = load_u32_le(key, i * 4);
        }
        for (i, word) in state[11..15].iter_mut().enumerate() {
            *word = load_u32_le(key, 16 + i * 4);
        }
        state[6] = load_u32_le(nonce, 0);
        state[7] = load_u32_le(nonce, 4);
        state[8] = counter as u32;
        state[9] = (counter >> 32) as u32;
        Self {
            state,
            pending: [0u8; 64],
            pending_left: 0,
        }
    }

    /// Generate the next 64-byte keystream block into `out`.
    ///
    /// A partly-consumed block is dropped, as in [`super::ChaCha20::next_block`].
    pub fn next_block(&mut self, out: &mut [u8; 64]) {
        let mut x = self.state;

        // Ten double rounds: columns, then rows. The indices below encode the
        // column-major reading of a 4x4 matrix, which is the form the
        // specification states.
        for _ in 0..10 {
            quarter_round(&mut x, 0, 4, 8, 12);
            quarter_round(&mut x, 5, 9, 13, 1);
            quarter_round(&mut x, 10, 14, 2, 6);
            quarter_round(&mut x, 15, 3, 7, 11);
            quarter_round(&mut x, 0, 1, 2, 3);
            quarter_round(&mut x, 5, 6, 7, 4);
            quarter_round(&mut x, 10, 11, 8, 9);
            quarter_round(&mut x, 15, 12, 13, 14);
        }

        for i in 0..16 {
            let value = x[i].wrapping_add(self.state[i]);
            out[i * 4..i * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        self.pending_left = 0;

        // The counter is the low word pair; carry into the high word.
        let (low, carry) = self.state[8].overflowing_add(1);
        self.state[8] = low;
        if carry {
            self.state[9] = self.state[9].wrapping_add(1);
        }
    }

    /// XOR `buf` with the keystream, keeping the position across calls.
    ///
    /// The unused tail of a partly-consumed block is carried over: a proxy's
    /// write boundaries have nothing to do with the cipher's block size, and
    /// losing the tail would desynchronise the two sides from the next call on.
    pub fn apply_keystream(&mut self, buf: &mut [u8]) {
        let mut offset = 0usize;
        while offset < buf.len() && self.pending_left > 0 {
            let index = 64 - self.pending_left;
            buf[offset] ^= self.pending[index];
            self.pending_left -= 1;
            offset += 1;
        }
        while offset < buf.len() {
            let mut block = [0u8; 64];
            self.next_block(&mut block);
            self.pending = block;
            self.pending_left = 64;

            let take = (buf.len() - offset).min(64);
            for i in 0..take {
                buf[offset + i] ^= self.pending[i];
            }
            self.pending_left -= take;
            offset += take;
        }
    }
}

#[inline]
fn load_u32_le(src: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        src[offset],
        src[offset + 1],
        src[offset + 2],
        src[offset + 3],
    ])
}

/// The Salsa20 quarter-round: rotate counts 7, 9, 13, 18, and the operands
/// arrive as `(b, c, d, a)` relative to the notation in the specification.
#[inline]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[b] ^= state[a].wrapping_add(state[d]).rotate_left(7);
    state[c] ^= state[b].wrapping_add(state[a]).rotate_left(9);
    state[d] ^= state[c].wrapping_add(state[b]).rotate_left(13);
    state[a] ^= state[d].wrapping_add(state[c]).rotate_left(18);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::new();
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// ECRYPT eSTREAM Salsa20 test vectors, Set 1 vector 0: a key that is one
    /// bit set in the first byte and zeroes elsewhere, a zero IV.
    #[test]
    fn ecrypt_set1_vector0_first_block() {
        let mut key = [0u8; 32];
        key[0] = 0x80;
        let nonce = [0u8; 8];

        let mut salsa = Salsa20::new(&key, &nonce, 0);
        let mut block = [0u8; 64];
        salsa.next_block(&mut block);

        assert_eq!(
            hex(&block),
            concat!(
                "e3be8fdd8beca2e3ea8ef9475b29a6e7",
                "003951e1097a5c38d23b7a5fad9f6844",
                "b22c97559e2723c7cbbd3fe4fc8d9a07",
                "44652a83e72a9c461876af4d7ef1a117",
            )
        );
    }

    /// The counter is 64-bit and lives in the state's words 8 and 9: advancing
    /// it by one must change only those, and crossing 2^32 must carry.
    #[test]
    fn the_counter_is_a_64_bit_little_endian_value() {
        let key = [1u8; 32];
        let nonce = [2u8; 8];

        let mut zero = Salsa20::new(&key, &nonce, 0);
        let one = Salsa20::new(&key, &nonce, 1);
        assert_eq!(zero.state[8], 0);
        assert_eq!(zero.state[9], 0);
        assert_eq!(one.state[8], 1);
        assert_eq!(one.state[9], 0);

        let high = Salsa20::new(&key, &nonce, 1 << 32);
        assert_eq!(high.state[8], 0);
        assert_eq!(high.state[9], 1);

        // Advancing a block increments the counter, carrying into word 9.
        zero.next_block(&mut [0u8; 64]);
        assert_eq!(zero.state[8], 1);
        let mut carry = Salsa20::new(&key, &nonce, u32::MAX as u64);
        carry.next_block(&mut [0u8; 64]);
        assert_eq!(carry.state[8], 0);
        assert_eq!(carry.state[9], 1, "the carry reaches the high word");
    }

    #[test]
    fn the_keystream_continues_across_calls_of_any_size() {
        let key = [7u8; 32];
        let nonce = [9u8; 8];

        let mut whole = vec![0u8; 200];
        Salsa20::new(&key, &nonce, 0).apply_keystream(&mut whole);

        let mut split = vec![0u8; 200];
        {
            let mut salsa = Salsa20::new(&key, &nonce, 0);
            let mut rest = &mut split[..];
            for size in [1usize, 63, 64, 65, 7] {
                if rest.is_empty() {
                    break;
                }
                let take = size.min(rest.len());
                let (chunk, tail) = rest.split_at_mut(take);
                salsa.apply_keystream(chunk);
                rest = tail;
            }
        }
        assert_eq!(split, whole);
    }

    /// Decrypting is applying the same keystream.
    #[test]
    fn applying_twice_restores_the_plaintext() {
        let key = [3u8; 32];
        let nonce = [4u8; 8];
        let plaintext = b"salsa20 is only here for wire compatibility";
        let mut buf = plaintext.to_vec();
        Salsa20::new(&key, &nonce, 0).apply_keystream(&mut buf);
        assert_ne!(&buf[..], &plaintext[..]);
        Salsa20::new(&key, &nonce, 0).apply_keystream(&mut buf);
        assert_eq!(&buf[..], &plaintext[..]);
    }
}
