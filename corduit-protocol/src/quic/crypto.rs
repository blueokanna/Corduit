use bytes::{BufMut, Bytes, BytesMut};
use corduit_crypto::aead::{Aead, Aes128Gcm, Aes256Gcm, ChaCha20Poly1305};
use corduit_crypto::digest::Digest;
use corduit_crypto::hash::{Blake2b, Sha256};
use corduit_crypto::kdf::Hkdf;

use super::config::CipherKind;
use super::error::{QuicError, Result};

#[allow(clippy::large_enum_variant)]
pub enum Cipher {
    Aes256Gcm(Aes256Gcm),
    Aes128Gcm(Aes128Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl Cipher {
    pub fn new(kind: CipherKind, key: &[u8]) -> Result<Self> {
        let err = || QuicError::Crypto("Invalid key length".into());
        Ok(match kind {
            CipherKind::Aes256Gcm | CipherKind::Aead2022Aes256Gcm => {
                Self::Aes256Gcm(Aes256Gcm::new_from_slice(key).map_err(|_| err())?)
            }
            CipherKind::Aes128Gcm | CipherKind::Aead2022Aes128Gcm => {
                Self::Aes128Gcm(Aes128Gcm::new_from_slice(key).map_err(|_| err())?)
            }
            CipherKind::Chacha20Poly1305 | CipherKind::Aead2022Chacha20Poly1305 => {
                Self::ChaCha20Poly1305(ChaCha20Poly1305::new_from_slice(key).map_err(|_| err())?)
            }
        })
    }

    pub fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let result = match self {
            Self::Aes256Gcm(c) => c.encrypt(nonce, plaintext, &[]),
            Self::Aes128Gcm(c) => c.encrypt(nonce, plaintext, &[]),
            Self::ChaCha20Poly1305(c) => c.encrypt(nonce, plaintext, &[]),
        };
        result.map_err(|_| QuicError::EncryptionFailed)
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let result = match self {
            Self::Aes256Gcm(c) => c.decrypt(nonce, ciphertext, &[]),
            Self::Aes128Gcm(c) => c.decrypt(nonce, ciphertext, &[]),
            Self::ChaCha20Poly1305(c) => c.decrypt(nonce, ciphertext, &[]),
        };
        result.map_err(|_| QuicError::DecryptionFailed)
    }
}

#[derive(Clone)]
pub struct CryptoContext {
    cipher_kind: CipherKind,
    key: Vec<u8>,
    nonce_counter: u64,
}

impl CryptoContext {
    pub fn new(cipher_kind: CipherKind, password: &str) -> Self {
        Self {
            key: derive_key(cipher_kind, password),
            cipher_kind,
            nonce_counter: 0,
        }
    }

    pub fn from_key(cipher_kind: CipherKind, key: Vec<u8>) -> Self {
        Self {
            cipher_kind,
            key,
            nonce_counter: 0,
        }
    }

    #[inline]
    pub fn cipher_kind(&self) -> CipherKind {
        self.cipher_kind
    }

    pub fn cipher(&self) -> Result<Cipher> {
        Cipher::new(self.cipher_kind, &self.key)
    }

    pub fn next_nonce(&mut self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&self.nonce_counter.to_le_bytes());
        self.nonce_counter = self.nonce_counter.wrapping_add(1);
        nonce
    }

    pub fn random_nonce() -> [u8; 12] {
        let mut nonce = [0u8; 12];
        let _ = getrandom::fill(&mut nonce);
        nonce
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Bytes> {
        let cipher = self.cipher()?;
        let nonce = self.next_nonce();
        let ciphertext = cipher.encrypt(&nonce, plaintext)?;

        let mut output = BytesMut::with_capacity(12 + ciphertext.len());
        output.put_slice(&nonce);
        output.put_slice(&ciphertext);
        Ok(output.freeze())
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 28 {
            return Err(QuicError::BufferTooSmall);
        }
        let cipher = self.cipher()?;
        cipher.decrypt(&data[..12], &data[12..])
    }

    pub fn encrypt_with_nonce(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        self.cipher()?.encrypt(nonce, plaintext)
    }

    pub fn decrypt_with_nonce(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.cipher()?.decrypt(nonce, ciphertext)
    }
}

pub fn derive_key(cipher_kind: CipherKind, password: &str) -> Vec<u8> {
    let key_size = cipher_kind.key_size();
    if cipher_kind.is_aead_2022() {
        derive_key_blake2b(password, key_size)
    } else {
        derive_key_hkdf(password, key_size)
    }
}

fn derive_key_hkdf(password: &str, key_size: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(b"shadowsocks"), password.as_bytes());
    let mut key = vec![0u8; key_size];
    hk.expand(b"ss-subkey", &mut key)
        .expect("HKDF expand failed");
    key
}

fn derive_key_blake2b(password: &str, key_size: usize) -> Vec<u8> {
    let mut hasher = Blake2b::new();
    hasher.update(password.as_bytes());
    let digest = hasher.finalize();
    digest[..key_size].to_vec()
}
