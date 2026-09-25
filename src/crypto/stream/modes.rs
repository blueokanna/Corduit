//! Block-cipher modes over [`Aes`]: CFB128, CTR and CBC.
//!
//! # Why these three, in this shape
//!
//! All three exist because ShadowsocksR names them (`aes-256-cfb`,
//! `aes-128-ctr`) and because its handshake protocols need a bare CBC block
//! transform. Two properties are what make them interoperable, and both are
//! easy to get subtly wrong:
//!
//! * **CFB128 and CTR are stream modes with state that survives a call
//!   boundary.** A proxy writes whatever the client sent, so a write almost
//!   never lands on a 16-byte boundary. An implementation that restarts the
//!   feedback register (or a fresh counter block) per call produces a
//!   keystream the peer cannot reproduce, and the two sides desynchronise one
//!   byte into the second packet. The offset/keystream state here is kept for
//!   exactly that reason, matching OpenSSL's `EVP_aes_*_cfb128` / `_ctr`
//!   semantics — which is what every Shadowsocks/SSR implementation links
//!   against.
//! * **The CFB feedback register is filled with *ciphertext* bytes**, and the
//!   register bytes are overwritten as they are consumed. That is the same
//!   statement as "the feedback block is the last 16 ciphertext bytes", but it
//!   is the form that also defines what happens mid-block.
//!
//! CBC is the odd one out: it is not a stream mode, it has no carried state,
//! and it takes whole blocks. It is here because the SSR `auth_aes128_*` and
//! `auth_chain_*` handshakes encrypt one 16-byte block with it and decrypt a
//! zero-padded one back.

use super::aes::Aes;
use crate::crypto::InvalidLength;

/// AES in 128-bit cipher-feedback mode (OpenSSL's `aes-<n>-cfb`).
pub struct Cfb128 {
    aes: Aes,
    /// The block that is encrypted to produce the current keystream, with the
    /// bytes already consumed replaced by the ciphertext they produced.
    feedback: [u8; 16],
    /// Keystream position inside the block, 0..16.
    offset: usize,
}

impl Cfb128 {
    /// `iv` is the initial feedback block (the method's per-connection IV).
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self, InvalidLength> {
        if iv.len() != 16 {
            return Err(InvalidLength);
        }
        let mut feedback = [0u8; 16];
        feedback.copy_from_slice(iv);
        Ok(Self {
            aes: Aes::new(key)?,
            feedback,
            offset: 0,
        })
    }

    /// Encrypt in place, continuing from the previous call's position.
    pub fn encrypt(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            if self.offset == 0 {
                self.aes.encrypt_block(&mut self.feedback);
            }
            let keystream = self.feedback[self.offset];
            let cipher = *byte ^ keystream;
            // The feedback byte becomes the ciphertext byte it just produced.
            self.feedback[self.offset] = cipher;
            *byte = cipher;
            self.offset = (self.offset + 1) & 15;
        }
    }

    /// Decrypt in place, continuing from the previous call's position.
    pub fn decrypt(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            if self.offset == 0 {
                self.aes.encrypt_block(&mut self.feedback);
            }
            let keystream = self.feedback[self.offset];
            // The feedback byte becomes the *input* byte, which for decryption
            // is the ciphertext.
            let cipher = *byte;
            self.feedback[self.offset] = cipher;
            *byte = cipher ^ keystream;
            self.offset = (self.offset + 1) & 15;
        }
    }
}

/// AES in counter mode (NIST SP 800-38A), whole-block big-endian counter.
///
/// The counter is the full 128-bit block incremented as an integer, not the
/// per-connection IV plus a 32-bit suffix: the two are different keystreams,
/// and the NIST vectors below pin which one this is.
pub struct Ctr {
    aes: Aes,
    counter: [u8; 16],
    keystream: [u8; 16],
    offset: usize,
}

impl Ctr {
    /// `iv` is the initial counter block.
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self, InvalidLength> {
        if iv.len() != 16 {
            return Err(InvalidLength);
        }
        let mut counter = [0u8; 16];
        counter.copy_from_slice(iv);
        Ok(Self {
            aes: Aes::new(key)?,
            counter,
            keystream: [0u8; 16],
            offset: 16,
        })
    }

    fn refill(&mut self) {
        // The keystream block is the encryption of the *counter*, so the
        // counter has to be loaded into the buffer before the block cipher
        // runs. Encrypting the buffer's previous contents (or zeros) would
        // still produce a stream, just not the one the peer computes.
        self.keystream.copy_from_slice(&self.counter);
        self.aes.encrypt_block(&mut self.keystream);
        // Big-endian increment over all 16 bytes so the whole space is used.
        for byte in self.counter.iter_mut().rev() {
            let (next, carried) = byte.overflowing_add(1);
            *byte = next;
            if !carried {
                break;
            }
        }
        self.offset = 0;
    }

    /// XOR `buf` with the keystream, continuing from the previous call.
    pub fn apply_keystream(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            if self.offset == 16 {
                self.refill();
            }
            *byte ^= self.keystream[self.offset];
            self.offset += 1;
        }
    }
}

/// AES in cipher-block chaining mode, unpadded.
///
/// Callers pass whole blocks: the one place this is used (the SSR handshake)
/// pads with zeros itself, and a mode that silently padded would hide the
/// difference between "the plaintext was 16 bytes" and "the plaintext was 5
/// bytes and we invented 11".
pub struct Cbc {
    aes: Aes,
}

impl Cbc {
    /// Build from a key; the IV is supplied per call because the handshake's
    /// IV is derived from the connection, not the method.
    pub fn new(key: &[u8]) -> Result<Self, InvalidLength> {
        Ok(Self {
            aes: Aes::new(key)?,
        })
    }

    /// Decrypt `buf` in place with the given `iv`. `buf` must be a whole
    /// number of 16-byte blocks.
    pub fn decrypt(&self, iv: &[u8; 16], buf: &mut [u8]) -> Result<(), InvalidLength> {
        if buf.len() % 16 != 0 {
            return Err(InvalidLength);
        }
        let mut previous = *iv;
        for block in buf.chunks_exact_mut(16) {
            let cipher = {
                let mut copy = [0u8; 16];
                copy.copy_from_slice(block);
                copy
            };
            self.aes
                .decrypt_block(block.try_into().expect("16-byte chunk"));
            for (byte, prev) in block.iter_mut().zip(previous.iter()) {
                *byte ^= prev;
            }
            previous = cipher;
        }
        Ok(())
    }

    /// Encrypt `buf` in place with the given `iv`. `buf` must be a whole
    /// number of 16-byte blocks.
    pub fn encrypt(&self, iv: &[u8; 16], buf: &mut [u8]) -> Result<(), InvalidLength> {
        if buf.len() % 16 != 0 {
            return Err(InvalidLength);
        }
        let mut previous = *iv;
        for block in buf.chunks_exact_mut(16) {
            for (byte, prev) in block.iter_mut().zip(previous.iter()) {
                *byte ^= prev;
            }
            self.aes
                .encrypt_block(block.try_into().expect("16-byte chunk"));
            previous.copy_from_slice(block);
        }
        Ok(())
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

    fn nibbles(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
            .collect()
    }

    /// NIST SP 800-38A §F.3.13 — CFB128-AES128 encryption, four blocks.
    #[test]
    fn nist_cfb128_aes128_encrypts_the_known_answer() {
        let key = nibbles("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = nibbles("000102030405060708090a0b0c0d0e0f");
        let mut buf = nibbles(concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f69f2445df4f9b17ad2b417be66c3710",
        ));

        Cfb128::new(&key, &iv).unwrap().encrypt(&mut buf);
        assert_eq!(
            hex(&buf),
            concat!(
                "3b3fd92eb72dad20333449f8e83cfb4a",
                "c8a64537a0b3a93fcde3cdad9f1ce58b",
                "26751f67a3cbb140b1808cf187a4f4df",
                "c04b05357c5d1c0eeac4c66f9ff7f2e6",
            )
        );
    }

    /// §F.3.15 — the decryption direction over the same vector.
    #[test]
    fn nist_cfb128_aes128_decrypts_the_known_answer() {
        let key = nibbles("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = nibbles("000102030405060708090a0b0c0d0e0f");
        let mut buf = nibbles(concat!(
            "3b3fd92eb72dad20333449f8e83cfb4a",
            "c8a64537a0b3a93fcde3cdad9f1ce58b",
            "26751f67a3cbb140b1808cf187a4f4df",
            "c04b05357c5d1c0eeac4c66f9ff7f2e6",
        ));
        Cfb128::new(&key, &iv).unwrap().decrypt(&mut buf);
        assert_eq!(
            hex(&buf),
            concat!(
                "6bc1bee22e409f96e93d7e117393172a",
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "30c81c46a35ce411e5fbc1191a0a52ef",
                "f69f2445df4f9b17ad2b417be66c3710",
            )
        );
    }

    /// NIST SP 800-38A §F.5.1 — CTR-AES128 encryption.
    #[test]
    fn nist_ctr_aes128_encrypts_the_known_answer() {
        let key = nibbles("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = nibbles("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let mut buf = nibbles(concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f69f2445df4f9b17ad2b417be66c3710",
        ));
        Ctr::new(&key, &iv).unwrap().apply_keystream(&mut buf);
        assert_eq!(
            hex(&buf),
            concat!(
                "874d6191b620e3261bef6864990db6ce",
                "9806f66b7970fdff8617187bb9fffdff",
                "5ae4df3edbd5d35e5b4f09020db03eab",
                "1e031dda2fbe03d1792170a0f3009cee",
            )
        );
    }

    /// NIST SP 800-38A §F.2.1 — CBC-AES128 encryption.
    #[test]
    fn nist_cbc_aes128_encrypts_the_known_answer() {
        let key = nibbles("2b7e151628aed2a6abf7158809cf4f3c");
        let iv_bytes = nibbles("000102030405060708090a0b0c0d0e0f");
        let iv: [u8; 16] = iv_bytes.as_slice().try_into().expect("16-byte IV");
        let mut buf = nibbles(concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
        ));
        Cbc::new(&key).unwrap().encrypt(&iv, &mut buf).unwrap();
        assert_eq!(
            hex(&buf),
            concat!(
                "7649abac8119b246cee98e9b12e9197d",
                "5086cb9b507219ee95db113a917678b2",
            )
        );
    }

    /// A CBC round trip, including the zero-padded shape the SSR handshake
    /// uses (`[16 zeros] || block || [16 zeros]`, decrypt, take the middle).
    #[test]
    fn cbc_round_trips_including_the_zero_padded_handshake_shape() {
        let key = nibbles("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = [0u8; 16];
        let cbc = Cbc::new(&key).unwrap();

        let block = nibbles("00112233445566778899aabbccddeeff");
        let mut padded = vec![0u8; 16];
        padded.extend_from_slice(&block);
        padded.extend_from_slice(&[0u8; 16]);
        cbc.encrypt(&iv, &mut padded).unwrap();
        assert_ne!(&padded[16..32], &block[..]);

        cbc.decrypt(&iv, &mut padded).unwrap();
        assert_eq!(&padded[16..32], &block[..]);
    }

    /// The stream modes must carry their position across calls, whatever the
    /// split: a proxy's write boundaries are not block boundaries.
    #[test]
    fn cfb_and_ctr_do_not_depend_on_where_the_calls_are_split() {
        let key = nibbles("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = nibbles("000102030405060708090a0b0c0d0e0f");
        let plaintext: Vec<u8> = (0..=255u8).collect();
        // Sizes chosen to land mid-block, on block boundaries, and past the
        // block size, covering every case the offset bookkeeping can get wrong.
        let splits = [1usize, 15, 3, 31, 46, 160];

        let mut whole = plaintext.clone();
        Cfb128::new(&key, &iv).unwrap().encrypt(&mut whole);
        let mut split = plaintext.clone();
        {
            let mut cfb = Cfb128::new(&key, &iv).unwrap();
            let mut rest = &mut split[..];
            while !rest.is_empty() {
                for size in splits {
                    if rest.is_empty() {
                        break;
                    }
                    let take = size.min(rest.len());
                    let (chunk, tail) = rest.split_at_mut(take);
                    cfb.encrypt(chunk);
                    rest = tail;
                }
            }
        }
        assert_eq!(split, whole, "CFB128 must be a stream, not a per-call mode");

        let mut ctr_whole = plaintext.clone();
        Ctr::new(&key, &iv).unwrap().apply_keystream(&mut ctr_whole);
        let mut ctr_split = plaintext.clone();
        {
            let mut ctr = Ctr::new(&key, &iv).unwrap();
            let mut rest = &mut ctr_split[..];
            while !rest.is_empty() {
                for size in splits {
                    if rest.is_empty() {
                        break;
                    }
                    let take = size.min(rest.len());
                    let (chunk, tail) = rest.split_at_mut(take);
                    ctr.apply_keystream(chunk);
                    rest = tail;
                }
            }
        }
        assert_eq!(ctr_split, ctr_whole, "CTR must be a stream");
    }

    /// Three bytes at a time still yields the same CFB stream as one call —
    /// the byte-level feedback rule is what makes that true, and a
    /// feedback-per-block implementation would pass the test above but fail
    /// this one only when the split lands mid-block.
    #[test]
    fn cfb_byte_level_feedback_matches_a_single_pass() {
        let key = nibbles("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = nibbles("000102030405060708090a0b0c0d0e0f");
        let plaintext = nibbles("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c");

        let mut once = plaintext.clone();
        Cfb128::new(&key, &iv).unwrap().encrypt(&mut once);

        let mut per_byte = plaintext.clone();
        {
            let mut cfb = Cfb128::new(&key, &iv).unwrap();
            for byte in per_byte.iter_mut() {
                cfb.encrypt(core::slice::from_mut(byte));
            }
        }
        assert_eq!(per_byte, once);
    }

    #[test]
    fn an_iv_of_the_wrong_length_is_refused() {
        assert!(Cfb128::new(&[0u8; 16], &[0u8; 15]).is_err());
        assert!(Ctr::new(&[0u8; 16], &[0u8; 17]).is_err());
        // Both key sizes the callers use are accepted.
        assert!(Cfb128::new(&[0u8; 16], &[0u8; 16]).is_ok());
        assert!(Ctr::new(&[0u8; 32], &[0u8; 16]).is_ok());
    }

    #[test]
    fn cbc_refuses_a_partial_block() {
        let cbc = Cbc::new(&[0u8; 16]).unwrap();
        let mut short = [0u8; 20];
        assert!(cbc.encrypt(&[0u8; 16], &mut short).is_err());
    }
}
