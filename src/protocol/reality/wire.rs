//! REALITY wire format: the authenticated `legacy_session_id` and the
//! ephemeral-certificate proof.
//!
//! REALITY (XTLS) has no RFC; this module implements the wire behaviour of
//! the reference client (`XTLS/Xray-core`, `transport/internet/reality`)
//! exactly, and the inverse operations the server performs, so both halves
//! can be cross-checked in tests:
//!
//! 1. The client generates an ephemeral X25519 key pair and computes
//!    `auth_key = HKDF-SHA256(ECDH(client_ephemeral, server_public), salt =
//!    ClientHello.random[..20], info = "REALITY", L = 32)`.
//! 2. It fills the 32-byte `legacy_session_id` with
//!    `[version:3][reserved:1][unix_time:4][short_id:≤8][zeros]` and seals
//!    the first 16 bytes with AES-256-GCM(`auth_key`), using
//!    `ClientHello.random[20..32]` as the nonce and the **whole ClientHello
//!    handshake message** as associated data. The 32-byte output replaces the
//!    session id in place, so a server that knows its private key can decrypt
//!    it while everyone else sees an opaque session id.
//! 3. The server answers with a certificate whose subject public key is a
//!    throwaway Ed25519 key and whose **signature field** is
//!    `HMAC-SHA512(auth_key, public_key)`. The client checks that instead of
//!    a CA chain.
//!
//! Anything the reference does not define is reported rather than guessed:
//! `mldsa65` post-quantum verification is rejected as unsupported, and the
//! timestamp/version fields are the ones this crate can honestly claim.

use super::{RealityError, Result};
use crate::crypto::aead::{Aead, Aes256Gcm};
use crate::crypto::dh::x25519;
use crate::crypto::hash::{Sha256, Sha512};
use crate::crypto::kdf::Hkdf;
use crate::crypto::mac::Hmac;
use alloc::vec::Vec;

/// Length of the `legacy_session_id` REALITY uses as its carrier.
pub const SESSION_ID_LEN: usize = 32;

/// Number of session-id bytes the AEAD protects (everything else is zero
/// padding).
pub const SESSION_PLAIN_LEN: usize = 16;

/// HKDF info string, verbatim from the reference implementation.
pub const AUTH_KEY_INFO: &[u8] = b"REALITY";

/// Largest short id accepted, in bytes (the reference limits the hex form to
/// 16 characters).
pub const MAX_SHORT_ID_LEN: usize = 8;

/// Offset of the session id inside a `ClientHello` handshake message.
pub const SESSION_ID_OFFSET: usize = crate::protocol::tls13::fingerprint::SESSION_ID_OFFSET;

/// The plaintext fields carried inside the sealed session id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionMeta {
    /// Three version bytes (`x.y.z`) the client claims.
    pub version: [u8; 3],
    /// Unix time, seconds, big endian.
    pub timestamp: u32,
    /// Number of short-id bytes that follow (`0..=MAX_SHORT_ID_LEN`).
    pub short_id_len: u8,
}

impl SessionMeta {
    /// Serialize the 16 plaintext bytes: `version(3) || reserved(1) ||
    /// timestamp(4) || short_id(8, zero padded)`.
    pub fn to_bytes(&self, short_id: &[u8]) -> Result<[u8; SESSION_PLAIN_LEN]> {
        if short_id.len() > MAX_SHORT_ID_LEN {
            return Err(RealityError::Config(alloc::format!(
                "short id is {} bytes, the limit is {MAX_SHORT_ID_LEN}",
                short_id.len()
            )));
        }
        let mut out = [0u8; SESSION_PLAIN_LEN];
        out[..3].copy_from_slice(&self.version);
        out[3] = 0; // reserved
        out[4..8].copy_from_slice(&self.timestamp.to_be_bytes());
        out[8..8 + short_id.len()].copy_from_slice(short_id);
        Ok(out)
    }

    /// Parse the 16 plaintext bytes back out.
    pub fn from_bytes(bytes: &[u8; SESSION_PLAIN_LEN]) -> Self {
        let mut version = [0u8; 3];
        version.copy_from_slice(&bytes[..3]);
        let timestamp = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let short_id_len = bytes[8..16]
            .iter()
            .rposition(|b| *b != 0)
            .map_or(0, |i| i + 1) as u8;
        Self {
            version,
            timestamp,
            short_id_len,
        }
    }
}

/// `auth_key = HKDF-SHA256(ikm = shared, salt = client_random[..20], info =
/// "REALITY", L = 32)`.
pub fn derive_auth_key(shared: &[u8; 32], client_random: &[u8; 32]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(Some(&client_random[..20]), shared);
    let mut out = [0u8; 32];
    hkdf.expand(AUTH_KEY_INFO, &mut out)
        .expect("32 bytes is one SHA-256 output block");
    out
}

/// The client's ephemeral ECDH with the server's static public key.
pub fn client_shared_secret(client_private: &[u8; 32], server_public: &[u8; 32]) -> [u8; 32] {
    x25519(client_private, server_public)
}

/// Seal the session id for `client_hello` **in place**.
///
/// `client_hello` must already contain the meta bytes at
/// [`SESSION_ID_OFFSET`]; the AEAD's associated data is the whole handshake
/// message exactly as it will be sent.
pub fn seal_session_id(
    auth_key: &[u8; 32],
    client_random: &[u8; 32],
    client_hello: &mut [u8],
    meta: &SessionMeta,
    short_id: &[u8],
) -> Result<()> {
    let end = SESSION_ID_OFFSET + SESSION_ID_LEN;
    if client_hello.len() < end {
        return Err(RealityError::Wire(
            "ClientHello is too short to hold a 32-byte session id".into(),
        ));
    }
    // 1. zero the carrier: the reference seals over the marshalled hello,
    // whose session-id field is still 32 zeros at that point
    let plain = meta.to_bytes(short_id)?;
    client_hello[SESSION_ID_OFFSET..end].fill(0);

    // 2. seal with that hello as associated data
    let cipher = Aes256Gcm::new(auth_key);
    let nonce = &client_random[20..32];
    let sealed = cipher
        .encrypt(nonce, &plain, client_hello)
        .map_err(|e| RealityError::Wire(alloc::format!("session id sealing failed: {e}")))?;
    if sealed.len() != SESSION_ID_LEN {
        return Err(RealityError::Wire(alloc::format!(
            "sealed session id is {} bytes, expected {SESSION_ID_LEN}",
            sealed.len()
        )));
    }

    // 3. write the sealed bytes over the session id
    client_hello[SESSION_ID_OFFSET..end].copy_from_slice(&sealed);
    Ok(())
}

/// Unseal a session id (the server side of step 2, also used by tests).
///
/// `client_hello` is the ClientHello exactly as received. The sealed session
/// id is used as the AD carrier with the same zeroing rule as
/// [`seal_session_id`], and the buffer is left as it was found because the
/// handshake transcript needs the received bytes.
pub fn unseal_session_id(
    auth_key: &[u8; 32],
    client_random: &[u8; 32],
    client_hello: &mut [u8],
) -> Result<(SessionMeta, Vec<u8>)> {
    let end = SESSION_ID_OFFSET + SESSION_ID_LEN;
    if client_hello.len() < end {
        return Err(RealityError::Wire(
            "ClientHello is too short to hold a 32-byte session id".into(),
        ));
    }
    let mut sealed = [0u8; SESSION_ID_LEN];
    sealed.copy_from_slice(&client_hello[SESSION_ID_OFFSET..end]);
    client_hello[SESSION_ID_OFFSET..end].fill(0);

    let cipher = Aes256Gcm::new(auth_key);
    let nonce = &client_random[20..32];
    let opened = cipher.decrypt(nonce, &sealed, client_hello);

    // Restore the received bytes whether or not authentication succeeded.
    client_hello[SESSION_ID_OFFSET..end].copy_from_slice(&sealed);

    let plain = opened.map_err(|_| RealityError::Unauthenticated)?;
    if plain.len() != SESSION_PLAIN_LEN {
        return Err(RealityError::Wire(
            "session id plaintext has wrong length".into(),
        ));
    }
    let mut bytes = [0u8; SESSION_PLAIN_LEN];
    bytes.copy_from_slice(&plain);
    let meta = SessionMeta::from_bytes(&bytes);
    let short_id = bytes[8..8 + meta.short_id_len as usize].to_vec();
    Ok((meta, short_id))
}

/// Check the REALITY ephemeral certificate: the key must be a 32-byte Ed25519
/// public key and the certificate's signature field must be
/// `HMAC-SHA512(auth_key, key)`.
///
/// The key bytes are *not* decoded as an Ed25519 point here: the reference
/// check is exactly this HMAC, and `CertificateVerify` (verified by the TLS
/// layer with that key) is what proves possession.
pub fn verify_ephemeral_certificate(
    auth_key: &[u8; 32],
    subject_public_key: &[u8],
    certificate_signature: &[u8],
) -> bool {
    if subject_public_key.len() != 32 {
        return false;
    }
    let mut mac = [0u8; 64];
    Hmac::<Sha512>::mac_into(auth_key, subject_public_key, &mut mac);
    if certificate_signature.len() != mac.len() {
        return false;
    }
    crate::crypto::util::ct_eq(&mac, certificate_signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::tls13::fingerprint::{build_client_hello, ClientHelloSpec, Fingerprint};
    use alloc::string::String;

    fn sample_hello() -> (Vec<u8>, [u8; 32]) {
        let random = [0x37u8; 32];
        let alpn = vec![String::from("h2")];
        let hello = build_client_hello(&ClientHelloSpec {
            server_name: "example.com",
            alpn: &alpn,
            fingerprint: Fingerprint::Chrome,
            random: &random,
            session_id: [0u8; 32],
            key_share: &[0x11; 32],
        })
        .expect("build ClientHello");
        (hello.raw, random)
    }

    /// The client's seal and the server's unseal agree, and the server derives
    /// the same auth key from its own private key and the client's key share
    /// (two independent ECDH directions).
    #[test]
    fn seal_unseal_round_trip_with_server_side_key_agreement() {
        // Client ephemeral key pair.
        let client_private = [0x42u8; 32];
        let client_public = crate::crypto::dh::public_key(&client_private);
        // Server static key pair.
        let server_private = [0x24u8; 32];
        let server_public = crate::crypto::dh::public_key(&server_private);

        let (mut hello, random) = sample_hello();
        let meta = SessionMeta {
            version: [1, 8, 0],
            timestamp: 1_700_000_000,
            short_id_len: 3,
        };
        let short_id = [0xAA, 0xBB, 0xCC];

        let client_shared = client_shared_secret(&client_private, &server_public);
        let client_auth = derive_auth_key(&client_shared, &random);
        seal_session_id(&client_auth, &random, &mut hello, &meta, &short_id)
            .expect("seal session id");

        // The sealed bytes must differ from the plaintext meta.
        assert_ne!(
            &hello[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_PLAIN_LEN],
            &meta.to_bytes(&short_id).expect("meta")[..]
        );

        // Server side: ECDH(server_private, client_public_from_key_share).
        let mut server_shared = [0u8; 32];
        server_shared.copy_from_slice(&x25519(&server_private, &client_public));
        let server_auth = derive_auth_key(&server_shared, &random);
        assert_eq!(client_auth, server_auth, "both sides derive one auth key");

        let (unsealed, unsealed_short_id) =
            unseal_session_id(&server_auth, &random, &mut hello).expect("unseal");
        assert_eq!(unsealed, meta);
        assert_eq!(unsealed_short_id, short_id);
    }

    /// Tampering with any byte of the ClientHello breaks the session id: the
    /// whole message is authenticated as associated data.
    #[test]
    fn unseal_rejects_tampered_client_hello() {
        let client_private = [0x11u8; 32];
        let server_private = [0x22u8; 32];
        let server_public = crate::crypto::dh::public_key(&server_private);
        let (mut hello, random) = sample_hello();
        let meta = SessionMeta {
            version: [0, 3, 9],
            timestamp: 42,
            short_id_len: 0,
        };
        let auth = derive_auth_key(
            &client_shared_secret(&client_private, &server_public),
            &random,
        );
        seal_session_id(&auth, &random, &mut hello, &meta, &[]).expect("seal");

        // Flip one bit in the SNI area: the whole ClientHello is the
        // associated data (with the session-id carrier zeroed), so this must
        // fail authentication.
        let mut tampered = hello.clone();
        let sni_probe = SESSION_ID_OFFSET + SESSION_ID_LEN + 20;
        assert!(sni_probe < tampered.len(), "probe lands inside the hello");
        tampered[sni_probe] ^= 0x01;
        assert!(matches!(
            unseal_session_id(&auth, &random, &mut tampered),
            Err(RealityError::Unauthenticated)
        ));

        // A modified byte inside the sealed carrier must fail the tag check,
        // and the buffer must be restored either way.
        let mut flipped = hello.clone();
        flipped[SESSION_ID_OFFSET] ^= 0x01;
        assert!(matches!(
            unseal_session_id(&auth, &random, &mut flipped),
            Err(RealityError::Unauthenticated)
        ));
        assert_eq!(
            flipped[SESSION_ID_OFFSET],
            hello[SESSION_ID_OFFSET] ^ 0x01,
            "the received bytes are left untouched"
        );

        // With the right session id but the wrong nonce.
        let other_random = [0x99u8; 32];
        assert!(unseal_session_id(&auth, &other_random, &mut hello).is_err());
    }

    /// The ephemeral-certificate proof is `HMAC-SHA512(auth_key, key)` in the
    /// certificate's signature field.
    #[test]
    fn ephemeral_certificate_proof() {
        let auth_key = [0x5Au8; 32];
        let key = [0x17u8; 32];
        let mut expected = [0u8; 64];
        Hmac::<Sha512>::mac_into(&auth_key, &key, &mut expected);

        assert!(verify_ephemeral_certificate(&auth_key, &key, &expected));
        // Wrong key, wrong signature length, wrong auth key: all rejected.
        assert!(!verify_ephemeral_certificate(
            &auth_key,
            &[0x18u8; 32],
            &expected
        ));
        assert!(!verify_ephemeral_certificate(
            &auth_key,
            &key,
            &expected[..32]
        ));
        assert!(!verify_ephemeral_certificate(
            &[0x5Bu8; 32],
            &key,
            &expected
        ));
        // A key of the wrong length is not an Ed25519 key.
        assert!(!verify_ephemeral_certificate(
            &auth_key, &[0u8; 31], &expected
        ));
    }

    /// Short ids are limited to what the reference accepts (16 hex chars).
    #[test]
    fn short_id_length_is_enforced() {
        let meta = SessionMeta {
            version: [0, 0, 1],
            timestamp: 0,
            short_id_len: 0,
        };
        assert!(meta.to_bytes(&[0u8; MAX_SHORT_ID_LEN]).is_ok());
        assert!(matches!(
            meta.to_bytes(&[0u8; MAX_SHORT_ID_LEN + 1]),
            Err(RealityError::Config(_))
        ));
    }

    /// A short id that ends in zero bytes keeps its declared length only up
    /// to the last non-zero byte; this mirrors the reference, which stores
    /// the id verbatim and compares it verbatim.
    #[test]
    fn session_meta_round_trips_fields() {
        let meta = SessionMeta {
            version: [12, 34, 56],
            timestamp: 0x0102_0304,
            short_id_len: 4,
        };
        let bytes = meta.to_bytes(&[0xDE, 0xAD, 0xBE, 0xEF]).expect("meta");
        let parsed = SessionMeta::from_bytes(&bytes);
        assert_eq!(parsed.version, meta.version);
        assert_eq!(parsed.timestamp, meta.timestamp);
        assert_eq!(parsed.short_id_len, 4);
    }
}
