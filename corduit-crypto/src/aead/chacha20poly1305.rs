//! ChaCha20-Poly1305 AEAD (RFC 8439 §2.8).
//!
//! IETF construction: 32-byte key, 12-byte nonce. The Poly1305 key is the
//! first 32 bytes of the counter-0 keystream block; data is encrypted with
//! the counter starting at 1.

use crate::aead::{AeadError, AeadInPlace};
use crate::mac::Poly1305;
use crate::stream::ChaCha20;
use crate::util::ct_eq;

const TAG_LEN: usize = 16;

/// ChaCha20-Poly1305 AEAD (RFC 8439 §2.8): 32-byte key, 12-byte nonce.
#[derive(Clone)]
pub struct ChaCha20Poly1305 {
    key: [u8; 32],
}

impl ChaCha20Poly1305 {
    /// Create from a 32-byte key.
    pub fn new(key: &[u8; 32]) -> Self {
        ChaCha20Poly1305 { key: *key }
    }

    /// Create from a slice, validating the length.
    pub fn new_from_slice(key: &[u8]) -> Result<Self, crate::InvalidLength> {
        if key.len() != 32 {
            return Err(crate::InvalidLength);
        }
        Ok(Self {
            key: key.try_into().expect("32"),
        })
    }

    fn poly_key(&self, nonce: &[u8]) -> Result<[u8; 32], AeadError> {
        let n: [u8; 12] = nonce
            .try_into()
            .map_err(|_| AeadError::InvalidNonceLength)?;
        let mut cipher = ChaCha20::new(&self.key, &n, 0);
        let mut block = [0u8; 64];
        cipher.next_block(&mut block);
        let mut poly_key = [0u8; 32];
        poly_key.copy_from_slice(&block[..32]);
        Ok(poly_key)
    }

    fn compute_tag(&self, nonce: &[u8], aad: &[u8], ct: &[u8]) -> Result<[u8; TAG_LEN], AeadError> {
        let pk = self.poly_key(nonce)?;
        let mut mac = Poly1305::new(&pk);

        mac.update(aad);
        let aad_rem = aad.len() % 16;
        if aad_rem != 0 {
            mac.update(&[0u8; 16][..16 - aad_rem]);
        }
        mac.update(ct);
        let ct_rem = ct.len() % 16;
        if ct_rem != 0 {
            mac.update(&[0u8; 16][..16 - ct_rem]);
        }
        mac.update(&(aad.len() as u64).to_le_bytes());
        mac.update(&(ct.len() as u64).to_le_bytes());

        Ok(mac.finalize())
    }
}

impl AeadInPlace for ChaCha20Poly1305 {
    fn encrypt_in_place_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &mut [u8; 16],
    ) -> Result<(), AeadError> {
        let n: [u8; 12] = nonce
            .try_into()
            .map_err(|_| AeadError::InvalidNonceLength)?;
        let mut cipher = ChaCha20::new(&self.key, &n, 1);
        cipher.apply_keystream(buffer);
        *tag = self.compute_tag(nonce, aad, buffer)?;
        Ok(())
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), AeadError> {
        let expected = self.compute_tag(nonce, aad, buffer)?;
        if tag.len() != TAG_LEN || !ct_eq(&expected, tag) {
            crate::util::zeroize(buffer);
            return Err(AeadError::AuthenticationFailed);
        }
        let n: [u8; 12] = nonce
            .try_into()
            .map_err(|_| AeadError::InvalidNonceLength)?;
        let mut cipher = ChaCha20::new(&self.key, &n, 1);
        cipher.apply_keystream(buffer);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::AeadInPlace;

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::new();
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    #[test]
    fn rfc8439_vector() {
        let key = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let cipher = ChaCha20Poly1305::new(&key);

        let mut buf = pt.to_vec();
        let mut tag = [0u8; 16];
        cipher
            .encrypt_in_place_detached(&nonce, &aad, &mut buf, &mut tag)
            .unwrap();
        assert_eq!(
            hex(&buf),
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
        );
        assert_eq!(hex(&tag), "1ae10b594f09e26a7e902ecbd0600691");

        let mut buf2 = buf.clone();
        cipher
            .decrypt_in_place_detached(&nonce, &aad, &mut buf2, &tag)
            .unwrap();
        assert_eq!(&buf2, pt);
    }

    #[test]
    fn tamper_detected() {
        let key = [9u8; 32];
        let nonce = [0u8; 12];
        let cipher = ChaCha20Poly1305::new(&key);
        let mut buf = b"secret message".to_vec();
        let mut tag = [0u8; 16];
        cipher
            .encrypt_in_place_detached(&nonce, b"", &mut buf, &mut tag)
            .unwrap();
        buf[0] ^= 1;
        let mut out = buf;
        assert_eq!(
            cipher.decrypt_in_place_detached(&nonce, b"", &mut out, &tag),
            Err(AeadError::AuthenticationFailed)
        );
    }
}
