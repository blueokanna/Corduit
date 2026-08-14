//! HMAC (RFC 2104), generic over any [`crate::digest::Digest`].

use crate::digest::Digest;
use crate::MAX_BLOCK_LEN;

/// HMAC construction parameterized by a hash function.
#[derive(Clone)]
pub struct Hmac<H: Digest> {
    inner: H,
    outer: H,
}

impl<H: Digest> Hmac<H> {
    /// Create from a key of any length (keys longer than the block size are
    /// hashed first per RFC 2104).
    pub fn new(key: &[u8]) -> Self {
        let mut key_block = [0u8; MAX_BLOCK_LEN];
        if key.len() > H::BLOCK_LEN {
            let mut digest = [0u8; 64];
            H::digest_into(key, &mut digest[..H::OUTPUT_LEN]);
            key_block[..H::OUTPUT_LEN].copy_from_slice(&digest[..H::OUTPUT_LEN]);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        let mut ipad = key_block;
        let mut opad = key_block;
        for i in 0..H::BLOCK_LEN {
            ipad[i] ^= 0x36;
            opad[i] ^= 0x5c;
        }

        let mut inner = H::new();
        inner.update(&ipad[..H::BLOCK_LEN]);
        let mut outer = H::new();
        outer.update(&opad[..H::BLOCK_LEN]);

        Hmac { inner, outer }
    }

    /// Absorb data.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Produce the tag, writing exactly [`H::OUTPUT_LEN`] bytes to `out`.
    pub fn finalize_into(self, out: &mut [u8]) {
        debug_assert!(out.len() >= H::OUTPUT_LEN);
        let mut inner_digest = [0u8; 64];
        self.inner.finalize_into(&mut inner_digest[..H::OUTPUT_LEN]);
        let mut outer = self.outer;
        outer.update(&inner_digest[..H::OUTPUT_LEN]);
        outer.finalize_into(out);
    }

    /// One-shot HMAC into a caller-provided buffer.
    pub fn mac_into(key: &[u8], data: &[u8], out: &mut [u8]) {
        let mut mac = Self::new(key);
        mac.update(data);
        mac.finalize_into(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{Md5, Sha1, Sha256, Sha512};

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::new();
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
        let mut out = [0u8; 20];
        Hmac::<Sha1>::mac_into(key, data, &mut out);
        out
    }

    fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        Hmac::<Sha256>::mac_into(key, data, &mut out);
        out
    }

    fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
        let mut out = [0u8; 64];
        Hmac::<Sha512>::mac_into(key, data, &mut out);
        out
    }

    fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
        let mut out = [0u8; 16];
        Hmac::<Md5>::mac_into(key, data, &mut out);
        out
    }

    #[test]
    fn rfc2202_hmac_sha1() {
        // RFC 2202 test cases 1-3.
        assert_eq!(
            hex(&hmac_sha1(b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", b"Hi There")),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
        assert_eq!(
            hex(&hmac_sha1(b"Jefe", b"what do ya want for nothing?")),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
        assert_eq!(
            hex(&hmac_sha1(&[0xaau8; 20], &[0xddu8; 50])),
            "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
        );
    }

    #[test]
    fn rfc4231_hmac_sha256() {
        // RFC 4231 test cases 1-2.
        assert_eq!(
            hex(&hmac_sha256(
                b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
                b"Hi There"
            )),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hmac_sha512_and_md5() {
        // RFC 4231 test case 1 for SHA-512.
        assert_eq!(
            hex(&hmac_sha512(
                b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
                b"Hi There"
            )),
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        );
        // RFC 2104 test case 2 for MD5.
        assert_eq!(
            hex(&hmac_md5(b"Jefe", b"what do ya want for nothing?")),
            "750c783e6ab0b503eaa86e310a5db738"
        );
    }
}
