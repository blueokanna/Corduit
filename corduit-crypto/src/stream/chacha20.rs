//! ChaCha20 stream cipher (RFC 8439), with configurable round count
//! (20/12/8 — ChaCha8 is used by Shadowsocks 2022).

use crate::util::load_u32_le;

const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// ChaCha20 keystream generator.
#[derive(Clone)]
pub struct ChaCha20 {
    state: [u32; 16],
    rounds: u32,
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
        ChaCha20 { state, rounds }
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
    pub fn next_block(&mut self, out: &mut [u8; 64]) {
        let mut x = self.state;

        for _ in 0..self.rounds / 2 {
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
            let v = x[i].wrapping_add(self.state[i]);
            out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }

        self.state[12] = self.state[12].wrapping_add(1);
    }

    /// XOR `buf` with the keystream in place, advancing the counter as
    /// needed. Handles arbitrary-length input.
    pub fn apply_keystream(&mut self, mut buf: &mut [u8]) {
        let mut block = [0u8; 64];
        while buf.len() >= 64 {
            self.next_block(&mut block);
            for (dst, src) in buf[..64].iter_mut().zip(block.iter()) {
                *dst ^= src;
            }
            buf = &mut buf[64..];
        }
        if !buf.is_empty() {
            self.next_block(&mut block);
            for (dst, src) in buf.iter_mut().zip(block.iter()) {
                *dst ^= src;
            }
        }
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
        let nonce = [0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00];
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
        let nonce = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00];
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
}
