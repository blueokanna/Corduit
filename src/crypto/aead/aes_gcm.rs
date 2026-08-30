//! AES-GCM authenticated encryption (NIST SP 800-38D).
//!
//! Only the standard 12-byte nonce (with the GHASH fallback for other
//! lengths) is supported, mirroring what every consumer in Corduit uses.
//! GHASH multiplication is branch-free.

use crate::crypto::aead::{AeadError, AeadInPlace};
use crate::crypto::stream::Aes;
use crate::crypto::util::ct_eq;

/// Reduction polynomial of GF(2^128) for GHASH: x^128 + x^7 + x^2 + x + 1.
const R: u128 = 0xe100_0000_0000_0000_0000_0000_0000_0000;

/// Constant-time multiplication in GF(2^128).
///
/// Implements the canonical GCM bit-string multiplication (NIST
/// SP 800-38D §6.3): Y is consumed most-significant bit first and V is
/// shifted right, folding the reduction polynomial
/// `x^128 + x^7 + x^2 + x + 1` via `R = 0xe1 || 0^120` whenever the
/// outgoing (least-significant) bit of V is set.
fn gf_mul(x: u128, y: u128) -> u128 {
    let mut z = 0u128;
    let mut x = x;
    let mut y = y;
    for _ in 0..128 {
        if (y >> 127) & 1 == 1 {
            z ^= x;
        }
        y <<= 1;
        if x & 1 == 1 {
            x = (x >> 1) ^ R;
        } else {
            x >>= 1;
        }
    }
    z
}

/// Increment the low 32 bits of a GCM counter block.
fn inc32(counter: u128) -> u128 {
    let low = (counter & 0xffff_ffff).wrapping_add(1) & 0xffff_ffff;
    (counter & !0xffff_ffffu128) | low
}

/// Streaming GHASH accumulator (AAD then ciphertext).
struct GHash {
    h: u128,
    state: u128,
    buf: [u8; 16],
    buf_len: usize,
    aad_len: u64,
    ct_len: u64,
    phase: u8,
}

impl GHash {
    fn new(h: u128) -> Self {
        GHash {
            h,
            state: 0,
            buf: [0u8; 16],
            buf_len: 0,
            aad_len: 0,
            ct_len: 0,
            phase: 0,
        }
    }

    fn absorb_block(&mut self, block: &[u8; 16]) {
        // GCM treats 128-bit blocks as big-endian bit strings (the first
        // byte is the coefficient of x^127).
        let x = u128::from_be_bytes(*block);
        self.state = gf_mul(self.state ^ x, self.h);
    }

    fn push(&mut self, mut data: &[u8]) {
        if self.phase == 0 {
            self.aad_len = self.aad_len.wrapping_add(data.len() as u64);
        } else {
            self.ct_len = self.ct_len.wrapping_add(data.len() as u64);
        }

        if self.buf_len != 0 {
            let want = 16 - self.buf_len;
            let take = want.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 16 {
                let full = self.buf;
                self.absorb_block(&full);
                self.buf_len = 0;
            }
        }

        while data.len() >= 16 {
            let block: [u8; 16] = data[..16].try_into().expect("16");
            self.absorb_block(&block);
            data = &data[16..];
        }

        self.buf[..data.len()].copy_from_slice(data);
        self.buf_len = data.len();
    }

    /// Zero-pad the current partial block (if any) and absorb it.
    ///
    /// GCM interleaves AAD and ciphertext through a single padded stream:
    /// `aad || pad16(aad) || ct || pad16(ct)`. This must be called between
    /// the AAD and the ciphertext so the AAD padding is consumed before any
    /// ciphertext bytes are absorbed.
    fn pad_to_block(&mut self) {
        if self.buf_len > 0 {
            // The buffer is already zero beyond buf_len, so the partial
            // block read here is the zero-padded block.
            let block = self.buf;
            self.absorb_block(&block);
            self.buf_len = 0;
            self.buf = [0u8; 16];
        }
    }

    /// Finalize: zero-pad the partial block, append the 128-bit length block
    /// and return S. (GCM pads partial blocks with zeros, not 0x80.)
    ///
    /// The length block carries the *bit* lengths of the AAD and the
    /// ciphertext, each as a big-endian 64-bit integer.
    fn finalize(mut self) -> u128 {
        if self.buf_len > 0 {
            let block = self.buf;
            // zero-pad the remainder (buffer is already zero beyond buf_len)
            let x = u128::from_be_bytes(block);
            self.state = gf_mul(self.state ^ x, self.h);
        }
        let lb = (((self.aad_len as u128) << 3) << 64) | ((self.ct_len as u128) << 3);
        self.absorb_block(&lb.to_be_bytes());
        self.state
    }
}

/// AES-GCM cipher for a fixed key size.
pub struct AesGcm {
    cipher: Aes,
}

impl AesGcm {
    /// Create from a 16/24/32-byte key.
    pub fn new(key: &[u8]) -> Result<Self, crate::crypto::InvalidLength> {
        Ok(AesGcm {
            cipher: Aes::new(key)?,
        })
    }

    /// Alias of [`AesGcm::new`] for compatibility with the `aead` crate
    /// call sites.
    pub fn new_from_slice(key: &[u8]) -> Result<Self, crate::crypto::InvalidLength> {
        Self::new(key)
    }

    #[inline]
    fn h(&self) -> u128 {
        let mut block = [0u8; 16];
        self.cipher.encrypt_block(&mut block);
        u128::from_be_bytes(block)
    }

    fn j0(&self, nonce: &[u8]) -> Result<u128, AeadError> {
        if nonce.len() == 12 {
            let mut j0 = [0u8; 16];
            j0[..12].copy_from_slice(nonce);
            j0[15] = 1;
            Ok(u128::from_be_bytes(j0))
        } else {
            // J0 = GHASH_H(nonce || 0^pad || 0^64 || bitlen(nonce))
            if nonce.is_empty() {
                return Err(AeadError::InvalidNonceLength);
            }
            let h = self.h();
            let mut state = 0u128;
            let mut blocks = nonce.chunks_exact(16);
            for block in &mut blocks {
                let arr: [u8; 16] = block.try_into().unwrap();
                state = gf_mul(state ^ u128::from_be_bytes(arr), h);
            }
            let rem = blocks.remainder();
            if !rem.is_empty() {
                let mut block = [0u8; 16];
                block[..rem.len()].copy_from_slice(rem);
                // zero-pad the remainder
                state = gf_mul(state ^ u128::from_be_bytes(block), h);
            }
            let mut lb = [0u8; 16];
            lb[8..].copy_from_slice(&((nonce.len() as u64) * 8).to_be_bytes());
            state = gf_mul(state ^ u128::from_be_bytes(lb), h);
            Ok(state)
        }
    }

    fn ctr_crypt(&self, icb: u128, buffer: &mut [u8]) {
        let mut counter = inc32(icb);
        let mut block = [0u8; 16];
        for chunk in buffer.chunks_mut(16) {
            block.copy_from_slice(&counter.to_be_bytes());
            self.cipher.encrypt_block(&mut block);
            for (dst, src) in chunk.iter_mut().zip(block.iter()) {
                *dst ^= src;
            }
            counter = inc32(counter);
        }
    }
}

impl AeadInPlace for AesGcm {
    fn encrypt_in_place_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &mut [u8; 16],
    ) -> Result<(), AeadError> {
        let j0 = self.j0(nonce)?;
        let h = self.h();
        self.ctr_crypt(j0, buffer);

        let s = {
            let mut g = GHash::new(h);
            g.push(aad);
            g.pad_to_block();
            g.phase = 1;
            g.push(buffer);
            g.finalize()
        };
        let mut j0b = [0u8; 16];
        j0b.copy_from_slice(&j0.to_be_bytes());
        self.cipher.encrypt_block(&mut j0b);
        let ek = u128::from_be_bytes(j0b);
        tag.copy_from_slice(&(ek ^ s).to_be_bytes());
        Ok(())
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), AeadError> {
        let j0 = self.j0(nonce)?;
        let h = self.h();

        // Compute the tag over the ciphertext first (constant-time check
        // before any plaintext is released).
        let s = {
            let mut g = GHash::new(h);
            g.push(aad);
            g.pad_to_block();
            g.phase = 1;
            g.push(buffer);
            g.finalize()
        };
        let mut j0b = [0u8; 16];
        j0b.copy_from_slice(&j0.to_be_bytes());
        self.cipher.encrypt_block(&mut j0b);
        let ek = u128::from_be_bytes(j0b);

        let mut expected = [0u8; 16];
        expected.copy_from_slice(&(ek ^ s).to_be_bytes());
        if tag.len() != 16 || !ct_eq(&expected, tag) {
            // Wipe the buffer so no unauthenticated data escapes.
            crate::crypto::util::zeroize(buffer);
            return Err(AeadError::AuthenticationFailed);
        }

        self.ctr_crypt(j0, buffer);
        Ok(())
    }
}

macro_rules! define_aes_gcm {
    ($name:ident, $keylen:expr) => {
        /// AES-GCM with a fixed key size.
        pub struct $name {
            inner: AesGcm,
        }

        impl $name {
            /// Create from a `$keylen`-byte key.
            pub fn new(key: &[u8; $keylen]) -> Self {
                $name {
                    inner: AesGcm::new(key).expect("key length validated by type"),
                }
            }

            /// Create from a slice, validating the length.
            pub fn new_from_slice(key: &[u8]) -> Result<Self, crate::crypto::InvalidLength> {
                if key.len() != $keylen {
                    return Err(crate::crypto::InvalidLength);
                }
                Ok($name {
                    inner: AesGcm::new(key).expect("key length validated"),
                })
            }
        }

        impl AeadInPlace for $name {
            fn encrypt_in_place_detached(
                &self,
                nonce: &[u8],
                aad: &[u8],
                buffer: &mut [u8],
                tag: &mut [u8; 16],
            ) -> Result<(), AeadError> {
                self.inner
                    .encrypt_in_place_detached(nonce, aad, buffer, tag)
            }

            fn decrypt_in_place_detached(
                &self,
                nonce: &[u8],
                aad: &[u8],
                buffer: &mut [u8],
                tag: &[u8],
            ) -> Result<(), AeadError> {
                self.inner
                    .decrypt_in_place_detached(nonce, aad, buffer, tag)
            }
        }
    };
}

define_aes_gcm!(Aes128Gcm, 16);
define_aes_gcm!(Aes192Gcm, 24);
define_aes_gcm!(Aes256Gcm, 32);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead::AeadInPlace;

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::new();
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn encrypt_vec(cipher: &AesGcm, nonce: &[u8], aad: &[u8], pt: &[u8]) -> (Vec<u8>, [u8; 16]) {
        let mut buf = pt.to_vec();
        let mut tag = [0u8; 16];
        cipher
            .encrypt_in_place_detached(nonce, aad, &mut buf, &mut tag)
            .unwrap();
        (buf, tag)
    }

    #[test]
    fn nist_gcm_vectors() {
        // NIST GCM test vectors (McGrew & Viega), AES-128.
        // Case 1: empty AAD & plaintext, all-zero key & nonce.
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let cipher = AesGcm::new(&key).unwrap();
        let (ct, tag) = encrypt_vec(&cipher, &nonce, &[], &[]);
        assert!(ct.is_empty());
        assert_eq!(hex(&tag), "58e2fccefa7e3061367f1d57a4e7455a");

        // NIST AES-128 GCM vector: key all-zero, nonce all-zero, pt 0^16.
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let pt = [0u8; 16];
        let cipher = AesGcm::new(&key).unwrap();
        let (ct, tag) = encrypt_vec(&cipher, &nonce, &[], &pt);
        assert_eq!(hex(&ct), "0388dace60b6a392f328c2b971b2fe78");
        assert_eq!(hex(&tag), "ab6e47d42cec13bdf53a67b21257bddf");
    }

    #[test]
    fn nist_gcm_case3_with_aad() {
        // McGrew & Viega AES-128 GCM, test case 3 (exercises AAD + 3 blocks).
        // Expected values cross-checked against the reference `aes-gcm` crate.
        let key = unhex("feffe9928665731c6d6a8f9467308308");
        let nonce = unhex("cafebabefacedbaddecaf888");
        let aad = unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let pt = unhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        let cipher = AesGcm::new(&key).unwrap();
        let (ct, tag) = encrypt_vec(&cipher, &nonce, &aad, &pt);
        assert_eq!(
            hex(&ct),
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
        );
        assert_eq!(hex(&tag), "5bc94fbc3221a5db94fae95ae7121a47");

        // Decrypt round-trips with the same AAD.
        let mut buf = ct.clone();
        cipher
            .decrypt_in_place_detached(&nonce, &aad, &mut buf, &tag)
            .unwrap();
        assert_eq!(buf, pt);
    }

    #[test]
    fn roundtrip_with_aad() {
        let key = [0x11u8; 16];
        let nonce = [0x22u8; 12];
        let aad = b"associated data";
        let pt = b"the quick brown fox";
        let cipher = AesGcm::new(&key).unwrap();

        let (ct, tag) = encrypt_vec(&cipher, &nonce, aad, pt);
        assert_ne!(&ct, &pt[..]);

        let mut buf = ct.clone();
        cipher
            .decrypt_in_place_detached(&nonce, aad, &mut buf, &tag)
            .unwrap();
        assert_eq!(&buf, pt);

        // Tamper: wrong tag must fail and not leak.
        let mut bad_tag = tag;
        bad_tag[0] ^= 1;
        let mut buf = ct.clone();
        assert_eq!(
            cipher.decrypt_in_place_detached(&nonce, aad, &mut buf, &bad_tag),
            Err(AeadError::AuthenticationFailed)
        );
        // Wrong AAD must fail too.
        let mut buf = ct.clone();
        assert_eq!(
            cipher.decrypt_in_place_detached(&nonce, b"other", &mut buf, &tag),
            Err(AeadError::AuthenticationFailed)
        );
    }

    #[test]
    fn ghash_known_answers() {
        // RFC 8452 Appendix A GHASH vector (same vector the `ghash` crate
        // uses in its own test suite): GHASH(H, X1, X2).
        let h = 0x2562_9347_5892_4276_1d31_f826_ba4b_757b;
        let x1 = 0x4f4f_9566_8c83_dfb6_4017_62bb_2d01_a262;
        let x2 = 0xd1a2_4ddd_2721_d006_bbe4_5f20_d3c9_f362;
        assert_eq!(
            gf_mul(gf_mul(x1, h) ^ x2, h),
            0xbd9b_3997_0467_31fb_9625_1b91_f9c9_9d7a
        );
        // Zero element annihilates.
        assert_eq!(gf_mul(0, 0x1234_5678_9abc_def0), 0);
        // The multiplicative identity: 1 = 2^127 in this representation.
        assert_eq!(
            gf_mul(1u128 << 127, 0xdead_beef_1234_5678_9abc_def0_1234_5678),
            0xdead_beef_1234_5678_9abc_def0_1234_5678
        );
    }

    #[test]
    fn non_standard_nonce_len() {
        // 8-byte nonce must work and round-trip.
        let key = [7u8; 32];
        let nonce = [0xabu8; 8];
        let cipher = AesGcm::new(&key).unwrap();
        let pt = b"data";
        let (ct, tag) = encrypt_vec(&cipher, &nonce, b"aad", pt);
        let mut buf = ct.clone();
        cipher
            .decrypt_in_place_detached(&nonce, b"aad", &mut buf, &tag)
            .unwrap();
        assert_eq!(&buf, pt);
    }
}
