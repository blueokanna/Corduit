//! Packet-level obfuscation for the QUIC outbounds.
//!
//! Two constructions live here, one per Hysteria generation. They look alike
//! and are not: the salt length, the hash and the KDF input differ, so a
//! datagram wrapped by one is garbage to the other.
//!
//! * [`Salamander`] — Hysteria 2: `[8-byte salt][XOR(BLAKE2b-256(key ++ salt))]`
//! * [`XPlus`] — Hysteria 1: `[16-byte salt][XOR(SHA-256(key ++ salt))]`
//!
//! Both are stateless and symmetric: the salt travels in the clear, so the
//! receiver re-derives the same keystream without any handshake state. Both
//! wrap the *entire* QUIC datagram, headers included — otherwise the on-wire
//! shape of the handshake would leak.

use crate::crypto::digest::Digest;
use crate::crypto::hash::{Blake2b, Sha256};
use courierust::courierust_tls::crypto::rng::fill_random;

/// Salt length prepended to every packet, in bytes.
pub const SALT_LEN: usize = 8;
/// Hash output length (BLAKE2b-256), in bytes.
const HASH_LEN: usize = 32;
/// Salt length used by Hysteria 1's XPlus.
pub const XPLUS_SALT_LEN: usize = 16;

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

/// Hysteria 1's `obfs` transform (`XPlus` in the reference client).
///
/// ```text
/// [16 bytes salt][payload]
/// hash = SHA-256(key ++ salt)
/// payload[i] ^= hash[i % 32]
/// ```
///
/// The shape is Salamander's with a longer salt and SHA-256 instead of
/// BLAKE2b-256. That difference is not cosmetic: Hysteria 1 and Hysteria 2
/// servers are different programs, and a datagram wrapped by one obfuscator is
/// unrecoverable by the other. Keeping them as two types rather than one
/// parameterised type is what stops a config typo from connecting to the wrong
/// generation and getting a handshake timeout instead of an error.
#[derive(Debug, Clone)]
pub struct XPlus {
    key: Vec<u8>,
}

impl XPlus {
    /// Build the obfuscator from the pre-shared key bytes (`obfs-password`).
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }

    /// Wrap `payload` with a fresh 16-byte salt and XOR the keystream.
    pub fn obfuscate_packet(&self, payload: &[u8]) -> Vec<u8> {
        let mut salt = [0u8; XPLUS_SALT_LEN];
        fill_random(&mut salt);
        let hash = Self::derive(&self.key, &salt);

        let mut out = Vec::with_capacity(XPLUS_SALT_LEN + payload.len());
        out.extend_from_slice(&salt);
        for (i, &b) in payload.iter().enumerate() {
            out.push(b ^ hash[i % HASH_LEN]);
        }
        out
    }

    /// Unwrap a `[salt][obfuscated]` packet. `None` when it is shorter than
    /// the salt, which cannot be a valid packet.
    pub fn deobfuscate_packet(&self, packet: &[u8]) -> Option<Vec<u8>> {
        if packet.len() < XPLUS_SALT_LEN {
            return None;
        }
        let (salt, body) = packet.split_at(XPLUS_SALT_LEN);
        let hash = Self::derive(&self.key, salt);

        let mut out = Vec::with_capacity(body.len());
        for (i, &b) in body.iter().enumerate() {
            out.push(b ^ hash[i % HASH_LEN]);
        }
        Some(out)
    }

    fn derive(key: &[u8], salt: &[u8]) -> [u8; HASH_LEN] {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(salt);
        let full = hasher.finalize();
        let mut hash = [0u8; HASH_LEN];
        hash.copy_from_slice(&full[..HASH_LEN]);
        hash
    }
}

/// Either obfuscator, as the transport sees it.
///
/// The transport only needs "wrap/unwrap one datagram", so it takes this
/// instead of naming a generation.
#[derive(Debug, Clone)]
pub enum PacketObfs {
    /// Hysteria 2 (and the `salamander` variant of Hysteria 1).
    Salamander(Salamander),
    /// Hysteria 1's default `obfs`.
    XPlus(XPlus),
}

impl PacketObfs {
    /// Wrap one QUIC datagram.
    pub fn obfuscate_packet(&self, payload: &[u8]) -> Vec<u8> {
        match self {
            Self::Salamander(o) => o.obfuscate_packet(payload),
            Self::XPlus(o) => o.obfuscate_packet(payload),
        }
    }

    /// Unwrap one received datagram; `None` when it cannot be one.
    pub fn deobfuscate_packet(&self, packet: &[u8]) -> Option<Vec<u8>> {
        match self {
            Self::Salamander(o) => o.deobfuscate_packet(packet),
            Self::XPlus(o) => o.deobfuscate_packet(packet),
        }
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

    #[test]
    fn xplus_round_trips_and_uses_the_sixteen_byte_salt() {
        let obfs = XPlus::new(b"secret");
        let packet = b"\x00\x01\x02QUIC packet bytes";
        let wrapped = obfs.obfuscate_packet(packet);
        assert_eq!(wrapped.len(), packet.len() + XPLUS_SALT_LEN);
        assert_eq!(obfs.deobfuscate_packet(&wrapped).unwrap(), packet);

        assert!(obfs.deobfuscate_packet(&[]).is_none());
        assert!(obfs
            .deobfuscate_packet(&[0u8; XPLUS_SALT_LEN - 1])
            .is_none());
        // Exactly the salt with no payload is decodable to nothing.
        assert_eq!(
            obfs.deobfuscate_packet(&[0u8; XPLUS_SALT_LEN]).unwrap(),
            Vec::<u8>::new()
        );
    }

    /// The two generations are different transforms. If a config names the
    /// wrong one the datagram must not decode — a silent success here would
    /// mean the two constructions had converged, which they have not.
    #[test]
    fn the_two_obfuscators_do_not_interoperate() {
        let packet = b"datagram";
        let salamander_wrapped = Salamander::new(b"secret").obfuscate_packet(packet);
        let xplus = XPlus::new(b"secret");
        assert_ne!(
            xplus.deobfuscate_packet(&salamander_wrapped),
            Some(packet.to_vec())
        );

        let xplus_wrapped = xplus.obfuscate_packet(packet);
        let salamander = Salamander::new(b"secret");
        assert_ne!(
            salamander.deobfuscate_packet(&xplus_wrapped),
            Some(packet.to_vec())
        );

        // And the wrapped sizes differ, because the salts do.
        assert_eq!(salamander_wrapped.len(), packet.len() + SALT_LEN);
        assert_eq!(xplus_wrapped.len(), packet.len() + XPLUS_SALT_LEN);
    }

    #[test]
    fn the_enum_dispatches_to_the_variant_it_holds() {
        let packet = b"payload";
        let via_xplus = PacketObfs::XPlus(XPlus::new(b"k"));
        assert_eq!(
            via_xplus
                .deobfuscate_packet(&via_xplus.obfuscate_packet(packet))
                .unwrap(),
            packet
        );
        let via_salamander = PacketObfs::Salamander(Salamander::new(b"k"));
        assert_eq!(
            via_salamander
                .deobfuscate_packet(&via_salamander.obfuscate_packet(packet))
                .unwrap(),
            packet
        );
    }
}
