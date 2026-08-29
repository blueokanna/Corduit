//! "Salamander" packet obfuscation (Hysteria 2 protocol spec).
//!
//! Salamander is a stateless, per-packet XOR obfuscator that wraps every
//! QUIC datagram:
//!
//! ```text
//! [8 bytes salt][payload]
//! hash   = BLAKE2b-256(key + salt)
//! payload[i] ^= hash[i % 32]
//! ```
//!
//! The salt is fresh per packet, so the transform is symmetric and needs no
//! handshake state: the receiver re-derives the same hash from the salt it
//! just read. Any packet shorter than the 8-byte salt is discarded.
//!
//! This sits between the UDP socket and the QUIC packet codec — it must wrap
//! the *entire* QUIC datagram (headers included), otherwise the on-wire shape
//! of the handshake would leak.

use crate::crypto::digest::Digest;
use crate::crypto::hash::Blake2b;
use courierust::courierust_tls::crypto::rng::fill_random;

/// Salt length prepended to every packet, in bytes.
pub const SALT_LEN: usize = 8;
/// Hash output length (BLAKE2b-256), in bytes.
const HASH_LEN: usize = 32;

/// Stateless XOR obfuscator matching the Hysteria 2 "Salamander" spec.
///
/// `key` is the user-provided pre-shared key (the `obfs-password`).
#[derive(Debug, Clone)]
pub struct Salamander {
    key: Vec<u8>,
}

impl Salamander {
    /// Build an obfuscator from the pre-shared key bytes.
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }

    /// Wrap `payload` with a fresh 8-byte salt and XOR the keystream.
    pub fn obfuscate_packet(&self, payload: &[u8]) -> Vec<u8> {
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt);
        let hash = Self::derive(&self.key, &salt);

        let mut out = Vec::with_capacity(SALT_LEN + payload.len());
        out.extend_from_slice(&salt);
        for (i, &b) in payload.iter().enumerate() {
            out.push(b ^ hash[i % HASH_LEN]);
        }
        out
    }

    /// Unwrap a `[salt][obfuscated]` packet. Returns `None` when the packet
    /// is too short to carry the salt (invalid, discard).
    pub fn deobfuscate_packet(&self, packet: &[u8]) -> Option<Vec<u8>> {
        if packet.len() < SALT_LEN {
            return None;
        }
        let (salt, body) = packet.split_at(SALT_LEN);
        let hash = Self::derive(&self.key, salt);

        let mut out = Vec::with_capacity(body.len());
        for (i, &b) in body.iter().enumerate() {
            out.push(b ^ hash[i % HASH_LEN]);
        }
        Some(out)
    }

    fn derive(key: &[u8], salt: &[u8]) -> [u8; HASH_LEN] {
        let mut hasher = Blake2b::with_params(HASH_LEN, &[]).expect("32 <= 64 digest size");
        hasher.update(key);
        hasher.update(salt);
        let full = hasher.finalize();
        let mut hash = [0u8; HASH_LEN];
        hash.copy_from_slice(&full[..HASH_LEN]);
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_is_identity() {
        let obfs = Salamander::new(b"secret");
        let packet = b"\x00\x01\x02QUIC packet bytes";
        let wrapped = obfs.obfuscate_packet(packet);
        assert_eq!(wrapped.len(), packet.len() + SALT_LEN);
        assert_eq!(obfs.deobfuscate_packet(&wrapped).unwrap(), packet);
    }

    #[test]
    fn salts_are_random_per_packet() {
        let obfs = Salamander::new(b"secret");
        let packet = b"same payload";
        let a = obfs.obfuscate_packet(packet);
        let b = obfs.obfuscate_packet(packet);
        // Different salt -> different ciphertext even for identical input.
        assert_ne!(a, b);
        assert_eq!(obfs.deobfuscate_packet(&a).unwrap(), packet);
        assert_eq!(obfs.deobfuscate_packet(&b).unwrap(), packet);
    }

    #[test]
    fn short_packets_are_discarded() {
        let obfs = Salamander::new(b"secret");
        assert!(obfs.deobfuscate_packet(&[]).is_none());
        assert!(obfs.deobfuscate_packet(&[0u8; SALT_LEN - 1]).is_none());
    }

    #[test]
    fn different_keys_do_not_cross_decode() {
        let a = Salamander::new(b"key-a");
        let b = Salamander::new(b"key-b");
        let wrapped = a.obfuscate_packet(b"payload");
        let decoded = b.deobfuscate_packet(&wrapped).unwrap();
        assert_ne!(decoded, b"payload");
    }
}
