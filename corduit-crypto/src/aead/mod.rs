//! Authenticated encryption with associated data.
//!
//! * [`Aes128Gcm`], [`Aes192Gcm`], [`Aes256Gcm`] — NIST SP 800-38D
//! * [`ChaCha20Poly1305`] — RFC 8439

mod aes_gcm;
mod chacha20poly1305;

pub use aes_gcm::{Aes128Gcm, Aes192Gcm, Aes256Gcm, AesGcm};
pub use chacha20poly1305::ChaCha20Poly1305;

/// Failure of an AEAD operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    /// The nonce length is invalid for this construction.
    InvalidNonceLength,
    /// The ciphertext is too short to contain a valid tag.
    CiphertextTooShort,
    /// Authentication failed (tag mismatch). No plaintext was released.
    AuthenticationFailed,
}

impl core::fmt::Display for AeadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AeadError::InvalidNonceLength => f.write_str("invalid nonce length"),
            AeadError::CiphertextTooShort => f.write_str("ciphertext too short"),
            AeadError::AuthenticationFailed => f.write_str("authentication failed"),
        }
    }
}

/// Common AEAD interface (alloc-based convenience layer over the in-place
/// primitives). The in-place `*_detached` methods are always available and
/// are what the protocol code uses.
#[cfg(feature = "alloc")]
pub trait Aead {
    /// Encrypt `plaintext` with `nonce` and `aad`, returning `ciphertext || tag`.
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8])
        -> Result<alloc::vec::Vec<u8>, AeadError>;

    /// Decrypt `ciphertext || tag` with `nonce` and `aad`, returning the
    /// plaintext only after the tag has been verified.
    fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext_and_tag: &[u8],
        aad: &[u8],
    ) -> Result<alloc::vec::Vec<u8>, AeadError>;
}

#[cfg(feature = "alloc")]
impl<T: AeadInPlace> Aead for T {
    fn encrypt(
        &self,
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<alloc::vec::Vec<u8>, AeadError> {
        let mut buf = alloc::vec::Vec::with_capacity(plaintext.len() + 16);
        buf.extend_from_slice(plaintext);
        buf.extend_from_slice(&[0u8; 16]);
        let (ct, tail) = buf.split_at_mut(plaintext.len());
        let tag: &mut [u8; 16] = tail.try_into().expect("16-byte tail");
        self.encrypt_in_place_detached(nonce, aad, ct, tag)?;
        Ok(buf)
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext_and_tag: &[u8],
        aad: &[u8],
    ) -> Result<alloc::vec::Vec<u8>, AeadError> {
        if ciphertext_and_tag.len() < 16 {
            return Err(AeadError::CiphertextTooShort);
        }
        let (ct, tag) = ciphertext_and_tag.split_at(ciphertext_and_tag.len() - 16);
        let mut buf = ct.to_vec();
        self.decrypt_in_place_detached(nonce, aad, &mut buf, tag)?;
        Ok(buf)
    }
}

/// In-place AEAD interface implemented by all concrete ciphers.
pub trait AeadInPlace {
    /// Encrypt `buffer` in place and write the 16-byte tag into `tag`.
    ///
    /// `buffer` must contain the plaintext; after the call it holds the
    /// ciphertext of the same length.
    fn encrypt_in_place_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &mut [u8; 16],
    ) -> Result<(), AeadError>;

    /// Verify `tag` (in constant time) and, only on success, decrypt
    /// `buffer` in place.
    fn decrypt_in_place_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), AeadError>;
}
