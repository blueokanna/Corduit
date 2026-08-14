//! HKDF (RFC 5869), generic over any [`crate::digest::Digest`].

use core::marker::PhantomData;

use crate::digest::Digest;
use crate::mac::Hmac;

/// Error returned when the OKM length is out of range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HkdfError;

impl core::fmt::Display for HkdfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HKDF output too long (max 255 hash blocks)")
    }
}

/// HKDF extract-and-expand key derivation.
pub struct Hkdf<H: Digest> {
    prk: [u8; 64],
    _marker: PhantomData<H>,
}

impl<H: Digest> Hkdf<H> {
    /// HKDF-Extract: `PRK = HMAC(salt, IKM)`. An empty salt (RFC default)
    /// is used when `salt` is `None` or empty.
    pub fn new(salt: Option<&[u8]>, ikm: &[u8]) -> Self {
        let mut prk = [0u8; 64];
        Hmac::<H>::mac_into(salt.unwrap_or(&[]), ikm, &mut prk[..H::OUTPUT_LEN]);
        Hkdf {
            prk,
            _marker: PhantomData,
        }
    }

    /// HKDF-Expand: fill `okm` with `HMAC(PRK, T(i-1) || info || i)` blocks.
    pub fn expand(&self, info: &[u8], okm: &mut [u8]) -> Result<(), HkdfError> {
        let n = okm.len().div_ceil(H::OUTPUT_LEN);
        if n > 255 {
            return Err(HkdfError);
        }
        let mut prev = [0u8; 64];
        let mut pos = 0;
        for i in 1..=n as u8 {
            let mut mac = Hmac::<H>::new(&self.prk[..H::OUTPUT_LEN]);
            if i > 1 {
                mac.update(&prev[..H::OUTPUT_LEN]);
            }
            mac.update(info);
            mac.update(&[i]);
            let mut block = [0u8; 64];
            mac.finalize_into(&mut block[..H::OUTPUT_LEN]);
            let take = (okm.len() - pos).min(H::OUTPUT_LEN);
            okm[pos..pos + take].copy_from_slice(&block[..take]);
            pos += take;
            prev[..H::OUTPUT_LEN].copy_from_slice(&block[..H::OUTPUT_LEN]);
        }
        Ok(())
    }

    /// One-shot HKDF.
    pub fn derive(
        salt: Option<&[u8]>,
        ikm: &[u8],
        info: &[u8],
        okm: &mut [u8],
    ) -> Result<(), HkdfError> {
        Self::new(salt, ikm).expand(info, okm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{Sha1, Sha256};

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::new();
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    #[test]
    fn rfc5869_sha256_case1() {
        // RFC 5869 Appendix A.1.
        let ikm = [
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        ];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let mut okm = [0u8; 42];
        Hkdf::<Sha256>::derive(Some(&salt), &ikm, &info, &mut okm).unwrap();
        assert_eq!(
            hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn rfc5869_sha256_case3() {
        // RFC 5869 Appendix A.3 (zero-length salt and info).
        let ikm = [0x0bu8; 22];
        let mut okm = [0u8; 42];
        Hkdf::<Sha256>::derive(None, &ikm, &[], &mut okm).unwrap();
        assert_eq!(
            hex(&okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );
    }

    #[test]
    fn rfc5869_sha1_case1() {
        // RFC 5869 Appendix A.4 (HKDF-SHA1, used by Shadowsocks).
        let ikm = [0x0bu8; 11];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let mut okm = [0u8; 42];
        Hkdf::<Sha1>::derive(Some(&salt), &ikm, &info, &mut okm).unwrap();
        assert_eq!(
            hex(&okm),
            "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896"
        );
    }
}
