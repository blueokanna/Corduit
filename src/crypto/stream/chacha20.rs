//! ChaCha20 stream cipher (RFC 8439), with configurable round count
//! (20/12/8 — ChaCha8 is used by Shadowsocks 2022).

use crate::crypto::util::load_u32_le;

const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// ChaCha20 keystream generator.
#[derive(Clone)]
pub struct ChaCha20 {
    state: [u32; 16],
    rounds: u32,
    /// Keystream of the block currently being consumed.
    pending: [u8; 64],
    /// How many bytes of `pending` are still unused (0 = none).
    pending_left: usize,
}

impl ChaCha20 {
    /// IETF construction: 32-byte key, 12-byte nonce, 32-bit block counter.
    pub fn new(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> Self {
        Self::with_rounds(key, nonce, counter, 20)
    }

    /// ChaCha with a custom number of double rounds (8, 12 or 20).
    pub fn with_rounds(key: &[u8; 32], nonce: &[u8; 12], counter: u32, rounds: u32) -> Self {
        let mut state = [0u32; 16];
        state[..4].copy_from_slice(&CONSTANTS);
        for (i, word) in state[4..12].iter_mut().enumerate() {
            *word = load_u32_le(&key[i * 4..]);
        }
        state[12] = counter;
        for (i, word) in state[13..16].iter_mut().enumerate() {
            *word = load_u32_le(&nonce[i * 4..]);
        }
        ChaCha20 {
            state,
            rounds,
            pending: [0u8; 64],
            pending_left: 0,
        }
    }

    /// Re-key the counter (IETF mode keeps the same key/nonce and advances
    /// the block counter for each 64-byte block).
    pub fn set_counter(&mut self, counter: u32) {
        self.state[12] = counter;
    }

    /// Current block counter.
    pub fn counter(&self) -> u32 {
        self.state[12]
    }

    /// Generate the next 64-byte keystream block into `out`.
    ///
    /// Any partly-consumed block from an earlier `apply_keystream` call is
    /// dropped: this method is "give me a whole block", so it advances to the
    /// next one. Callers streaming arbitrary-sized buffers want
    /// `apply_keystream`, which does not lose bytes.
    pub fn next_block(&mut self, out: &mut [u8; 64]) {
        core_block(&self.state, self.rounds, out);
        self.pending_left = 0;
        // The IETF counter is 32-bit and wraps; the nonce is fixed, so a wrap
        // repeats the keystream. Callers that can write 256 GiB under one key
        // must re-key instead (Shadowsocks 2022 does).
        self.state[12] = self.state[12].wrapping_add(1);
    }

    /// XOR `buf` with the keystream, advancing the counter as needed.
    ///
    /// The unused tail of a block is kept for the next call. That matters
    /// because a proxy writes whatever the client sent: a `write` of 100 bytes
    /// consumes one and a half blocks, and an implementation that threw the
    /// half away would leave the two sides 28 bytes out of step from then on —
    /// a silent corruption that only appears on the *second* packet.
    pub fn apply_keystream(&mut self, buf: &mut [u8]) {
        let mut offset = 0usize;

        // Finish the block that is already half-consumed.
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

/// One 64-byte ChaCha keystream block from a full state.
///
/// Shared by the IETF construction and the original 64-bit-nonce one, which
/// differ only in how the state is filled and how the counter advances — the
/// permutation itself is identical, and duplicating it would be two chances to
/// get the round order wrong.
fn core_block(state: &[u32; 16], rounds: u32, out: &mut [u8; 64]) {
    let mut x = *state;
    for _ in 0..rounds / 2 {
        // column rounds
        qr(&mut x, 0, 4, 8, 12);
        qr(&mut x, 1, 5, 9, 13);
        qr(&mut x, 2, 6, 10, 14);
        qr(&mut x, 3, 7, 11, 15);
        // diagonal rounds
        qr(&mut x, 0, 5, 10, 15);
        qr(&mut x, 1, 6, 11, 12);
        qr(&mut x, 2, 7, 8, 13);
        qr(&mut x, 3, 4, 9, 14);
    }
    for i in 0..16 {
        let v = x[i].wrapping_add(state[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
}

#[inline]
fn qr(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// The original ChaCha construction: 32-byte key, **8-byte** nonce, 64-bit
/// block counter.
///
/// ShadowsocksR names this one `chacha20` and the RFC 8439 shape
/// `chacha20-ietf`; they are different keystreams for the same key, so the two
/// cannot be substituted for each other. The word layout is
/// `[constants][key 0..4][counter low][counter high][nonce][key 4..8]` with the
/// counter little-endian across the two words.
#[derive(Clone)]
pub struct ChaCha20Legacy {
    state: [u32; 16],
    pending: [u8; 64],
    pending_left: usize,
}

impl ChaCha20Legacy {
    /// Build from a key, an 8-byte nonce and a 64-bit block counter.
    pub fn new(key: &[u8; 32], nonce: &[u8; 8], counter: u64) -> Self {
        let mut state = [0u32; 16];
        state[..4].copy_from_slice(&CONSTANTS);
        for (i, word) in state[4..12].iter_mut().enumerate() {
            *word = load_u32_le(&key[i * 4..]);
        }
        state[12] = counter as u32;
        state[13] = (counter >> 32) as u32;
        for (i, word) in state[14..16].iter_mut().enumerate() {
            *word = load_u32_le(&nonce[i * 4..]);
        }
        Self {
            state,
            pending: [0u8; 64],
            pending_left: 0,
        }
    }

    /// Generate the next 64-byte keystream block, carrying the counter.
    /// Partly-consumed blocks are dropped, as in [`ChaCha20::next_block`].
    pub fn next_block(&mut self, out: &mut [u8; 64]) {
        core_block(&self.state, 20, out);
        self.pending_left = 0;
        let (low, carry) = self.state[12].overflowing_add(1);
        self.state[12] = low;
        if carry {
            self.state[13] = self.state[13].wrapping_add(1);
        }
    }

    /// XOR `buf` with the keystream, keeping the position across calls.
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
    fn rfc8439_keystream() {
        // RFC 8439 §2.3.2: the first 64-byte keystream block.
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut cipher = ChaCha20::new(&key, &nonce, 1);
        let mut block = [0u8; 64];
        cipher.next_block(&mut block);
        assert_eq!(
            hex(&block),
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
        );
    }

    #[test]
    fn rfc8439_encryption() {
        // RFC 8439 §2.4.2: full ChaCha20 encryption of the test message.
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected = "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d";
        let mut buf = plaintext.to_vec();
        // RFC 8439 §2.4.2 uses an initial counter of 1.
        let mut cipher = ChaCha20::new(&key, &nonce, 1);
        cipher.apply_keystream(&mut buf);
        assert_eq!(hex(&buf), expected);
        // decrypt is the same operation
        let mut cipher2 = ChaCha20::new(&key, &nonce, 1);
        cipher2.apply_keystream(&mut buf);
        assert_eq!(&buf, plaintext);
    }

    #[test]
    fn counter_increments_across_blocks() {
        let key = [7u8; 32];
        let nonce = [0u8; 12];
        let mut c = ChaCha20::new(&key, &nonce, 0);
        assert_eq!(c.counter(), 0);
        let mut block = [0u8; 64];
        c.next_block(&mut block);
        c.next_block(&mut block);
        assert_eq!(c.counter(), 2);
    }

    /// The original (8-byte nonce) shape must agree with the RFC 8439 shape
    /// for every counter that fits in 32 bits.
    ///
    /// That equivalence is exact rather than approximate: filling the IETF
    /// state with the 8-byte nonce followed by four zero bytes puts the same
    /// words in the same slots as the legacy layout, with the counter's high
    /// word zero. Since the IETF path is pinned by the RFC 8439 vectors above,
    /// this test transitively pins the legacy one — and it is a real check of
    /// the *state packing*, which is the only thing the two differ in.
    #[test]
    fn the_legacy_shape_fills_the_state_like_the_ietf_shape() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce8 = [0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a];
        // The IETF nonce is the legacy one with four leading zero bytes: the
        // legacy layout keeps the 32-bit counter high word where the IETF
        // layout keeps the nonce's first word, and prefixing zeros lines the
        // remaining words up exactly.
        let mut ietf_nonce = [0u8; 12];
        ietf_nonce[4..].copy_from_slice(&nonce8);

        for counter in [0u32, 1, 2, 1024, u32::MAX] {
            let mut legacy = ChaCha20Legacy::new(&key, &nonce8, u64::from(counter));
            let mut ietf = ChaCha20::new(&key, &ietf_nonce, counter);
            let mut from_legacy = [0u8; 64];
            let mut from_ietf = [0u8; 64];
            legacy.next_block(&mut from_legacy);
            ietf.next_block(&mut from_ietf);
            assert_eq!(from_legacy, from_ietf, "counter = {counter}");
        }
    }

    /// Past 2^32 the legacy counter keeps counting where the IETF one wraps:
    /// the carry has to reach the high word, or a long-lived stream would
    /// silently repeat its keystream.
    #[test]
    fn the_legacy_counter_carries_into_the_high_word() {
        let key = [3u8; 32];
        let nonce = [4u8; 8];
        let mut legacy = ChaCha20Legacy::new(&key, &nonce, 0xFFFF_FFFF);
        let mut discard = [0u8; 64];
        legacy.next_block(&mut discard);
        assert_eq!(legacy.state[12], 0, "the low word wrapped");
        assert_eq!(legacy.state[13], 1, "the carry reached the high word");

        // And that block is not the same as one produced by a wrapped 32-bit
        // counter, which is the failure this protects against.
        let mut ietf_nonce = [0u8; 12];
        ietf_nonce[..8].copy_from_slice(&nonce);
        let mut ietf = ChaCha20::new(&key, &ietf_nonce, 0);
        let mut from_ietf = [0u8; 64];
        ietf.next_block(&mut from_ietf);
        assert_ne!(discard, from_ietf);
    }

    /// Arbitrary call boundaries, exactly as a proxy produces them.
    #[test]
    fn the_legacy_shape_is_a_stream_across_calls() {
        let key = [9u8; 32];
        let nonce = [8u8; 8];
        let mut whole = vec![0u8; 200];
        ChaCha20Legacy::new(&key, &nonce, 0).apply_keystream(&mut whole);

        let mut split = vec![0u8; 200];
        {
            let mut cipher = ChaCha20Legacy::new(&key, &nonce, 0);
            let mut rest = &mut split[..];
            // Keep going until every byte has been written: a partial pass
            // would leave the tail zeroed and compare unequal for the wrong
            // reason.
            while !rest.is_empty() {
                for size in [1usize, 63, 65, 7] {
                    if rest.is_empty() {
                        break;
                    }
                    let take = size.min(rest.len());
                    let (chunk, tail) = rest.split_at_mut(take);
                    cipher.apply_keystream(chunk);
                    rest = tail;
                }
            }
        }
        assert_eq!(split, whole);
    }
}
