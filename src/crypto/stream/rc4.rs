//! RC4 (ARC4) — implemented for ShadowsocksR interoperability only.
//!
//! # Do not use this for anything new
//!
//! RC4 is broken in ways that are not fixable by protocol design: the first
//! keystream bytes are biased, `RC4(key || IV)` (the "drop 256 bytes" fix,
//! which this type does **not** apply because the wire format does not either)
//! is worse, and there are practical attacks that recover plaintext from a
//! few gigabytes of ciphertext. It is here because ShadowsocksR's `rc4` and
//! `rc4-md5` methods exist, and a client that cannot speak them cannot talk to
//! the servers that still offer them.
//!
//! # Shape
//!
//! RC4 is a swap-based stream cipher with 256 bytes of state: the key
//! schedules a permutation (KSA), and each output byte consumes one swap
//! (PRGA). The state update is inherently data-dependent, which is the other
//! reason this cipher cannot be made constant-time — and why nothing else in
//! this crate borrows from it.
//!
//! The keystream position is kept across calls, because a proxy stream's write
//! boundaries have nothing to do with the cipher's block structure. An RC4
//! instance that restarted its PRGA per call would produce a different
//! keystream than the peer computes, and the two sides would drift apart one
//! byte into the second packet.

use crate::crypto::InvalidLength;

/// RC4 keystream generator.
#[derive(Clone)]
pub struct Rc4 {
    state: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// Schedule `key` (1 to 256 bytes, per the cipher's definition).
    pub fn new(key: &[u8]) -> Result<Self, InvalidLength> {
        if key.is_empty() || key.len() > 256 {
            return Err(InvalidLength);
        }

        let mut state = [0u8; 256];
        for (i, byte) in state.iter_mut().enumerate() {
            *byte = i as u8;
        }

        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(state[i]).wrapping_add(key[i % key.len()]);
            state.swap(i, usize::from(j));
        }

        Ok(Self { state, i: 0, j: 0 })
    }

    /// Produce one keystream byte.
    pub fn next_byte(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.state[usize::from(self.i)]);
        self.state.swap(usize::from(self.i), usize::from(self.j));
        let index = self.state[usize::from(self.i)].wrapping_add(self.state[usize::from(self.j)]);
        self.state[usize::from(index)]
    }

    /// XOR `buf` with the keystream, continuing from wherever the previous
    /// call stopped.
    pub fn apply_keystream(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            *byte ^= self.next_byte();
        }
    }
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

    /// RFC 6229 §3, 128-bit key `0x0102030405060708090a0b0c0d0e0f10`: the first
    /// 16 keystream bytes. This is the only kind of test that can catch a
    /// wrong KSA (a permutation off by one element still produces plausible
    /// bytes) or an off-by-one in the PRGA's swap order.
    #[test]
    fn rfc6229_keystream_prefix() {
        let key = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let mut rc4 = Rc4::new(&key).expect("16-byte key");
        let mut stream = [0u8; 16];
        rc4.apply_keystream(&mut stream);
        assert_eq!(hex(&stream), "9ac7cc9a609d1ef7b2932899cde41b97");
    }

    /// The keystream continues across calls, in the sense that matters for a
    /// proxy: skipping `n` bytes then reading agrees with reading a longer
    /// buffer and slicing it, for every `n`.
    #[test]
    fn skipping_bytes_agrees_with_a_longer_read() {
        let key = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let mut whole = [0u8; 256];
        Rc4::new(&key).unwrap().apply_keystream(&mut whole);

        for skip in [0usize, 1, 15, 16, 240, 255] {
            let mut rc4 = Rc4::new(&key).unwrap();
            let mut discard = vec![0u8; skip];
            rc4.apply_keystream(&mut discard);
            let mut rest = vec![0u8; 256 - skip];
            rc4.apply_keystream(&mut rest);
            assert_eq!(rest, whole[skip..], "skip = {skip}");
        }
    }

    /// A differential test against the textbook formulation (index arithmetic
    /// instead of the in-place swap chain): two independent ways of writing the
    /// same cipher must agree byte for byte over a long stream.
    #[test]
    fn agrees_with_the_textbook_formulation_over_a_long_stream() {
        let key = b"a-shadowsocksr-key";
        let mut optimized = Rc4::new(key).expect("valid key");

        // Textbook KSA/PRGA, written out independently.
        let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
        let mut j: u8 = 0;
        for i in 0..256usize {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, usize::from(j));
        }
        let (mut i, mut j) = (0u8, 0u8);
        let mut expected = Vec::new();
        for _ in 0..4096 {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[usize::from(i)]);
            s.swap(usize::from(i), usize::from(j));
            expected.push(s[usize::from(s[usize::from(i)].wrapping_add(s[usize::from(j)]))]);
        }

        let mut actual = vec![0u8; 4096];
        optimized.apply_keystream(&mut actual);
        assert_eq!(actual, expected);
    }

    /// The keystream must continue across calls, not restart.
    #[test]
    fn calls_share_one_keystream_position() {
        let key = b"key";
        let mut whole = Rc4::new(key).unwrap();
        let mut reference = vec![0u8; 32];
        whole.apply_keystream(&mut reference);

        let mut split = Rc4::new(key).unwrap();
        let mut first = vec![0u8; 7];
        let mut second = vec![0u8; 25];
        split.apply_keystream(&mut first);
        split.apply_keystream(&mut second);
        assert_eq!(first, reference[..7]);
        assert_eq!(second, reference[7..]);
    }

    /// Encryption and decryption are the same operation.
    #[test]
    fn applying_twice_restores_the_plaintext() {
        let plaintext = b"the quick brown fox jumps over the lazy dog";
        let mut buf = plaintext.to_vec();
        Rc4::new(b"k").unwrap().apply_keystream(&mut buf);
        assert_ne!(&buf, plaintext);
        Rc4::new(b"k").unwrap().apply_keystream(&mut buf);
        assert_eq!(&buf, plaintext);
    }

    #[test]
    fn the_key_length_is_bounded_by_the_cipher_definition() {
        assert!(Rc4::new(b"").is_err());
        assert!(Rc4::new(&[0u8; 256]).is_ok());
        assert!(Rc4::new(&[0u8; 257]).is_err());
    }
}
