//! RFC 8446 §7.1 key schedule (labeled HKDF) and traffic-key derivation.
//!
//! Everything here is pure computation over the in-repo `crypto` primitives:
//! no I/O, no allocator tricks — usable from `no_std + alloc` code and from
//! unit tests with fixed vectors.
//!
//! The label structure is RFC 8446 §7.1:
//!
//! ```text
//! struct {
//!     uint16 length;
//!     opaque label<7..255> = "tls13 " + Label;
//!     opaque context<0..255> = Context;
//! } HkdfLabel;
//! ```
//!
//! and `HKDF-Expand-Label(Secret, Label, Context, Length)` is plain
//! HKDF-Expand (RFC 5869 §2.3) over `Secret` as the PRK — *not* HKDF-Extract
//! followed by Expand. [`hkdf_expand`] therefore implements RFC 5869 §2.3
//! directly.

use super::codec::{suite_hash_len, suite_key_len, SUITE_AES_256};
use super::{Result, Tls13Error};
use crate::crypto::aead::{Aead, Aes128Gcm, Aes256Gcm, ChaCha20Poly1305};
use crate::crypto::hash::{Sha256, Sha384};
use crate::crypto::mac::Hmac;
use crate::crypto::Digest;
use alloc::vec;
use alloc::vec::Vec;

/// The hash of a TLS 1.3 cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SuiteHash {
    /// SHA-256 (used by `TLS_AES_128_GCM_SHA256` and `TLS_CHACHA20_POLY1305_SHA256`).
    Sha256,
    /// SHA-384 (used by `TLS_AES_256_GCM_SHA384`).
    Sha384,
}

impl SuiteHash {
    /// The hash bound to `suite`.
    pub(crate) fn for_suite(suite: u16) -> Self {
        if suite == SUITE_AES_256 {
            SuiteHash::Sha384
        } else {
            SuiteHash::Sha256
        }
    }

    /// Hash output length in bytes.
    pub(crate) fn len(self) -> usize {
        suite_hash_len(if self == SuiteHash::Sha384 {
            SUITE_AES_256
        } else {
            super::codec::SUITE_AES_128
        })
    }

    /// Digest `data`.
    pub(crate) fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            SuiteHash::Sha256 => {
                let mut out = [0u8; 32];
                Sha256::digest_into(data, &mut out);
                out.to_vec()
            }
            SuiteHash::Sha384 => {
                let mut out = [0u8; 48];
                Sha384::digest_into(data, &mut out);
                out.to_vec()
            }
        }
    }

    /// HMAC over `data` with `key`.
    pub(crate) fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            SuiteHash::Sha256 => {
                let mut out = [0u8; 32];
                Hmac::<Sha256>::mac_into(key, data, &mut out);
                out.to_vec()
            }
            SuiteHash::Sha384 => {
                let mut out = [0u8; 48];
                Hmac::<Sha384>::mac_into(key, data, &mut out);
                out.to_vec()
            }
        }
    }

    /// `Derive-Secret(Secret, Label, Messages)` (RFC 8446 §7.1), where
    /// `messages_hash` is `Transcript-Hash(Messages)`.
    pub(crate) fn derive_secret(
        self,
        secret: &[u8],
        label: &[u8],
        messages_hash: &[u8],
    ) -> Vec<u8> {
        let mut out = vec![0u8; self.len()];
        self.expand_label(secret, label, messages_hash, &mut out);
        out
    }

    /// `HKDF-Expand-Label(Secret, Label, Context, Length)`.
    pub(crate) fn expand_label(self, secret: &[u8], label: &[u8], context: &[u8], out: &mut [u8]) {
        let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
        info.extend_from_slice(&(out.len() as u16).to_be_bytes());
        let full_label_len = 6 + label.len();
        info.push(full_label_len as u8);
        info.extend_from_slice(b"tls13 ");
        info.extend_from_slice(label);
        info.push(context.len() as u8);
        info.extend_from_slice(context);
        match self {
            SuiteHash::Sha256 => hkdf_expand::<Sha256>(secret, &info, out),
            SuiteHash::Sha384 => hkdf_expand::<Sha384>(secret, &info, out),
        }
    }

    /// `HKDF-Expand-Label(Secret, "finished", "", Hash.length)`.
    pub(crate) fn finished_key(self, base_secret: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; self.len()];
        self.expand_label(base_secret, b"finished", &[], &mut out);
        out
    }

    /// `HKDF-Expand-Label(Secret, "traffic upd", "", Hash.length)` — the
    /// next-generation traffic secret for `KeyUpdate` (RFC 8446 §7.2).
    pub(crate) fn next_traffic_secret(self, secret: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; self.len()];
        self.expand_label(secret, b"traffic upd", &[], &mut out);
        out
    }
}

/// HKDF-Expand (RFC 5869 §2.3) with `prk` taken as the pseudorandom key.
///
/// `info` is the caller-composed `HkdfLabel`; `okm` is filled completely.
pub(crate) fn hkdf_expand<H: Digest>(prk: &[u8], info: &[u8], okm: &mut [u8]) {
    let hash_len = H::OUTPUT_LEN;
    let blocks = okm.len().div_ceil(hash_len);
    let mut previous: Vec<u8> = Vec::new();
    let mut written = 0usize;
    for counter in 1..=blocks {
        let mut input = Vec::with_capacity(previous.len() + info.len() + 1);
        input.extend_from_slice(&previous);
        input.extend_from_slice(info);
        input.push(counter as u8);
        let mut block = vec![0u8; hash_len];
        Hmac::<H>::mac_into(prk, &input, &mut block);
        let take = core::cmp::min(hash_len, okm.len() - written);
        okm[written..written + take].copy_from_slice(&block[..take]);
        written += take;
        previous = block;
    }
}

/// A direction's AEAD traffic key (RFC 8446 §7.3).
pub(crate) enum TrafficKey {
    /// `TLS_AES_128_GCM_SHA256`.
    Aes128(Aes128Gcm),
    /// `TLS_AES_256_GCM_SHA384`.
    Aes256(Aes256Gcm),
    /// `TLS_CHACHA20_POLY1305_SHA256`.
    ChaCha(ChaCha20Poly1305),
}

impl TrafficKey {
    /// Derive the traffic key + IV for `suite`/`secret`.
    ///
    /// Returns the AEAD key and the 12-byte static IV; the per-record nonce is
    /// the IV XORed with the 64-bit record sequence number (RFC 8446 §5.3).
    pub(crate) fn derive(suite: u16, hash: SuiteHash, secret: &[u8]) -> Result<(Self, [u8; 12])> {
        let key_len = suite_key_len(suite);
        let mut key = vec![0u8; key_len];
        hash.expand_label(secret, b"key", &[], &mut key);
        let mut iv = [0u8; 12];
        hash.expand_label(secret, b"iv", &[], &mut iv);

        let aead = match suite {
            super::codec::SUITE_AES_128 => {
                let k: [u8; 16] = key
                    .as_slice()
                    .try_into()
                    .map_err(|_| Tls13Error::InvalidConfig("bad AES-128 key length".into()))?;
                TrafficKey::Aes128(Aes128Gcm::new(&k))
            }
            super::codec::SUITE_AES_256 => {
                let k: [u8; 32] = key
                    .as_slice()
                    .try_into()
                    .map_err(|_| Tls13Error::InvalidConfig("bad AES-256 key length".into()))?;
                TrafficKey::Aes256(Aes256Gcm::new(&k))
            }
            super::codec::SUITE_CHACHA => {
                let k: [u8; 32] = key
                    .as_slice()
                    .try_into()
                    .map_err(|_| Tls13Error::InvalidConfig("bad ChaCha20 key length".into()))?;
                TrafficKey::ChaCha(ChaCha20Poly1305::new(&k))
            }
            other => {
                return Err(Tls13Error::Unsupported(alloc::format!(
                    "no traffic keys for cipher suite 0x{other:04x}"
                )))
            }
        };
        Ok((aead, iv))
    }

    /// Seal `plaintext` with `nonce` and `aad`, returning `ciphertext || tag`.
    pub(crate) fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let out = match self {
            TrafficKey::Aes128(a) => a.encrypt(nonce, plaintext, aad),
            TrafficKey::Aes256(a) => a.encrypt(nonce, plaintext, aad),
            TrafficKey::ChaCha(a) => a.encrypt(nonce, plaintext, aad),
        };
        out.map_err(|e| Tls13Error::Protocol(alloc::format!("record encryption failed: {e}")))
    }

    /// Open `ciphertext_and_tag` with `nonce` and `aad`.
    pub(crate) fn open(&self, nonce: &[u8], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        let out = match self {
            TrafficKey::Aes128(a) => a.decrypt(nonce, ct, aad),
            TrafficKey::Aes256(a) => a.decrypt(nonce, ct, aad),
            TrafficKey::ChaCha(a) => a.decrypt(nonce, ct, aad),
        };
        out.map_err(|_| {
            Tls13Error::Protocol("record decryption failed (bad tag or truncated record)".into())
        })
    }
}

/// Handshake-phase secrets (RFC 8446 §7.1 up to "s hs traffic").
pub(crate) struct HandshakeSecrets {
    /// Hash bound to `suite`.
    pub hash: SuiteHash,
    /// `client_handshake_traffic_secret`.
    pub client_hs_traffic: Vec<u8>,
    /// `server_handshake_traffic_secret`.
    pub server_hs_traffic: Vec<u8>,
    /// `handshake_secret` — kept for the master-secret derivation.
    handshake_secret: Vec<u8>,
}

impl HandshakeSecrets {
    /// Run the key schedule from the ECDHE shared secret to the handshake
    /// traffic secrets, mixed with `transcript_hash_ch_sh` =
    /// `Transcript-Hash(ClientHello..ServerHello)`.
    pub(crate) fn new(suite: u16, ecdhe: &[u8], transcript_hash_ch_sh: &[u8]) -> Self {
        let hash = SuiteHash::for_suite(suite);
        let hash_len = hash.len();
        // early_secret = HKDF-Extract(0, 0)
        let early_secret = hash.hmac(&vec![0u8; hash_len], &vec![0u8; hash_len]);
        // derived = Derive-Secret(early_secret, "derived", "")
        let derived = hash.derive_secret(&early_secret, b"derived", &hash.hash(&[]));
        // handshake_secret = HKDF-Extract(derived, ECDHE)
        let handshake_secret = hash.hmac(&derived, ecdhe);
        // c/s hs traffic
        let client_hs_traffic =
            hash.derive_secret(&handshake_secret, b"c hs traffic", transcript_hash_ch_sh);
        let server_hs_traffic =
            hash.derive_secret(&handshake_secret, b"s hs traffic", transcript_hash_ch_sh);
        Self {
            hash,
            client_hs_traffic,
            server_hs_traffic,
            handshake_secret,
        }
    }

    /// Run the rest of the schedule (RFC 8446 §7.1) once the server Finished
    /// has been verified, with `transcript_hash_up_to_fin` =
    /// `Transcript-Hash(ClientHello..server Finished)`.
    pub(crate) fn application(&self, transcript_hash_up_to_fin: &[u8]) -> AppSecrets {
        let hash_len = self.hash.len();
        // derived = Derive-Secret(handshake_secret, "derived", "")
        let derived =
            self.hash
                .derive_secret(&self.handshake_secret, b"derived", &self.hash.hash(&[]));
        // master_secret = HKDF-Extract(derived, 0)
        let master_secret = self.hash.hmac(&derived, &vec![0u8; hash_len]);
        // c/s ap traffic
        let client_app_traffic =
            self.hash
                .derive_secret(&master_secret, b"c ap traffic", transcript_hash_up_to_fin);
        let server_app_traffic =
            self.hash
                .derive_secret(&master_secret, b"s ap traffic", transcript_hash_up_to_fin);
        AppSecrets {
            client_app_traffic,
            server_app_traffic,
        }
    }
}

/// Application-phase traffic secrets.
pub(crate) struct AppSecrets {
    /// `client_application_traffic_secret_0`.
    pub client_app_traffic: Vec<u8>,
    /// `server_application_traffic_secret_0`.
    pub server_app_traffic: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5869 appendix A.2 (SHA-256, 82-byte OKM) — pins `hkdf_expand`
    /// against the published test vector (PRK and OKM are the RFC's).
    #[test]
    fn hkdf_expand_matches_rfc5869_a2() {
        let ikm: Vec<u8> = (0u8..=0x4f).collect();
        let salt: Vec<u8> = (0x60u8..=0xaf).collect();
        let info: Vec<u8> = (0xb0u8..=0xff).collect();

        // PRK = HMAC-SHA256(salt, IKM) (RFC 5869 §2.2, A.2 value).
        let prk = SuiteHash::Sha256.hmac(&salt, &ikm);
        assert_eq!(
            prk,
            hex("06 a6 b8 8c 58 53 36 1a 06 10 4c 9c eb 35 b4 5c
                 ef 76 00 14 90 46 71 01 4a 19 3f 40 c1 5f c2 44"),
            "RFC 5869 A.2 PRK"
        );
        let mut okm = [0u8; 82];
        hkdf_expand::<Sha256>(&prk, &info, &mut okm);
        assert_eq!(
            &okm[..],
            &hex("b1 1e 39 8d c8 03 27 a1 c8 e7 f7 8c 59 6a 49 34
                  4f 01 2e da 2d 4e fa d8 a0 50 cc 4c 19 af a9 7c
                  59 04 5a 99 ca c7 82 72 71 cb 41 c6 5e 59 0e 09
                  da 32 75 60 0c 2f 09 b8 36 77 93 a9 ac a3 db 71
                  cc 30 c5 81 79 ec 3e 87 c1 4c 01 d5 c1 f3 43 4f
                  1d 87")[..],
            "RFC 5869 A.2 OKM"
        );
    }

    fn hex(s: &str) -> Vec<u8> {
        let compact: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        compact
            .chunks(2)
            .map(|pair| {
                let hi = (pair[0] as char).to_digit(16).expect("hex digit") as u8;
                let lo = (pair[1] as char).to_digit(16).expect("hex digit") as u8;
                (hi << 4) | lo
            })
            .collect()
    }

    /// RFC 5869 appendix A.1: 42-byte OKM with a short info string.
    #[test]
    fn hkdf_expand_matches_rfc5869_a1() {
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0u8..=0x0c).collect();
        let info: Vec<u8> = (0xf0u8..=0xf9).collect();
        let prk = SuiteHash::Sha256.hmac(&salt, &ikm);
        assert_eq!(
            prk,
            hex("07 77 09 36 2c 2e 32 df 0d dc 3f 0d c4 7b ba 63
                 90 b6 c7 3b b5 0f 9c 31 22 ec 84 4a d7 c2 b3 e5"),
            "RFC 5869 A.1 PRK"
        );
        let mut okm = [0u8; 42];
        hkdf_expand::<Sha256>(&prk, &info, &mut okm);
        assert_eq!(
            &okm[..],
            &hex("3c b2 5f 25 fa ac d5 7a 90 43 4f 64 d0 36 2f 2a
                  2d 2d 0a 90 cf 1a 5a 4c 5d b0 2d 56 ec c4 c5 bf
                  34 00 72 08 d5 b8 87 18 58 65")[..],
            "RFC 5869 A.1 OKM"
        );
    }

    /// RFC 8448 §3 "Simple 1-RTT Handshake": every derivable step of the
    /// client key schedule is compared against the published trace values.
    ///
    /// Inputs (all from the trace): the ECDHE shared secret, the two
    /// published transcript hashes, and the suite `TLS_AES_128_GCM_SHA256`.
    /// Only the `early_secret` is *not* taken from the trace: it is derived
    /// here from the RFC 8446 §7.1 definition (`Extract(0, 0)`) and checked
    /// against the trace value.
    #[test]
    fn key_schedule_matches_rfc8448_simple_handshake() {
        fn hex(s: &str) -> Vec<u8> {
            let compact: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
            assert!(compact.len() % 2 == 0, "hex literals are byte-aligned");
            compact
                .chunks(2)
                .map(|pair| {
                    let hi = (pair[0] as char).to_digit(16).expect("hex digit") as u8;
                    let lo = (pair[1] as char).to_digit(16).expect("hex digit") as u8;
                    (hi << 4) | lo
                })
                .collect()
        }

        let hash = SuiteHash::Sha256;
        let zero32 = [0u8; 32];

        // {server} extract secret "early"
        let early = hash.hmac(&zero32, &zero32);
        assert_eq!(
            early,
            hex("33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2
                 10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a"),
            "early_secret = HKDF-Extract(0, 0)"
        );

        // derive secret for handshake: "tls13 derived"
        let derived_hs = hash.derive_secret(&early, b"derived", &hash.hash(&[]));
        assert_eq!(
            derived_hs,
            hex("6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba b6 97
                 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba"),
            "Derive-Secret(early, \"derived\", Hash(\"\"))"
        );

        // extract secret "handshake" (IKM = ECDHE shared secret)
        let ecdhe = hex("8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d
                         35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d");
        let hs_secret = hash.hmac(&derived_hs, &ecdhe);
        assert_eq!(
            hs_secret,
            hex("1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b 01
                 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac"),
            "handshake_secret = HKDF-Extract(derived, ECDHE)"
        );

        // Transcript-Hash(ClientHello..ServerHello)
        let transcript_ch_sh = hex("86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed
                                    d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8");
        let hs = HandshakeSecrets::new(
            super::super::codec::SUITE_AES_128,
            &ecdhe,
            &transcript_ch_sh,
        );
        assert_eq!(
            hs.client_hs_traffic,
            hex("b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f
                 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21"),
            "client_handshake_traffic_secret"
        );
        assert_eq!(
            hs.server_hs_traffic,
            hex("b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4
                 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38"),
            "server_handshake_traffic_secret"
        );

        // {server} write traffic keys for handshake data (AES-128-GCM)
        let mut key = [0u8; 16];
        hash.expand_label(&hs.server_hs_traffic, b"key", &[], &mut key);
        assert_eq!(
            &key[..],
            &hex("3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc")[..],
            "server handshake write key"
        );
        let (_, iv) = TrafficKey::derive(
            super::super::codec::SUITE_AES_128,
            hash,
            &hs.server_hs_traffic,
        )
        .expect("traffic key");
        assert_eq!(
            &iv[..],
            &hex("5d 31 3e b2 67 12 76 ee 13 00 0b 30")[..],
            "server handshake write IV"
        );

        // {client} write traffic keys for handshake data
        let mut key = [0u8; 16];
        hash.expand_label(&hs.client_hs_traffic, b"key", &[], &mut key);
        assert_eq!(
            &key[..],
            &hex("db fa a6 93 d1 76 2c 5b 66 6a f5 d9 50 25 8d 01")[..],
            "client handshake write key"
        );
        let (_, iv) = TrafficKey::derive(
            super::super::codec::SUITE_AES_128,
            hash,
            &hs.client_hs_traffic,
        )
        .expect("traffic key");
        assert_eq!(
            &iv[..],
            &hex("5b d3 c7 1b 83 6e 0b 76 bb 73 26 5f")[..],
            "client handshake write IV"
        );

        // "tls13 finished" expansion for both directions
        assert_eq!(
            hash.finished_key(&hs.server_hs_traffic),
            hex("00 8d 3b 66 f8 16 ea 55 9f 96 b5 37 e8 85 c3 1f
                 c0 68 bf 49 2c 65 2f 01 f2 88 a1 d8 cd c1 9f c8"),
            "server finished key"
        );
        assert_eq!(
            hash.finished_key(&hs.client_hs_traffic),
            hex("b8 0a d0 10 15 fb 2f 0b d6 5f f7 d4 da 5d 6b f8
                 3f 84 82 1d 1f 87 fd c7 d3 c7 5b 5a 7b 42 d9 c4"),
            "client finished key"
        );

        // Application traffic secrets (transcript through the server Finished).
        let transcript_fin = hex("96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a
                                  00 0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13");
        let app = hs.application(&transcript_fin);
        assert_eq!(
            app.client_app_traffic,
            hex("9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce 65 52
                 87 5a fa 0b 06 df 00 87 f7 92 eb b7 c1 75 04 a5"),
            "client_application_traffic_secret_0"
        );
        assert_eq!(
            app.server_app_traffic,
            hex("a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9 50 32
                 82 04 b4 f4 4b fb 6b 3a 4b 4f 1f 3f cb 63 16 43"),
            "server_application_traffic_secret_0"
        );

        // Application write keys/IVs.
        let mut key = [0u8; 16];
        hash.expand_label(&app.server_app_traffic, b"key", &[], &mut key);
        assert_eq!(
            &key[..],
            &hex("9f 02 28 3b 6c 9c 07 ef c2 6b b9 f2 ac 92 e3 56")[..],
            "server application write key"
        );
        let (_, iv) = TrafficKey::derive(
            super::super::codec::SUITE_AES_128,
            hash,
            &app.server_app_traffic,
        )
        .expect("traffic key");
        assert_eq!(
            &iv[..],
            &hex("cf 78 2b 88 dd 83 54 9a ad f1 e9 84")[..],
            "server application write IV"
        );
        let mut key = [0u8; 16];
        hash.expand_label(&app.client_app_traffic, b"key", &[], &mut key);
        assert_eq!(
            &key[..],
            &hex("17 42 2d da 59 6e d5 d9 ac d8 90 e3 c6 3f 50 51")[..],
            "client application write key"
        );

        // Nonce/AAD handling: sealing with the derived key must round-trip,
        // and a different AAD must fail authentication (RFC 8446 §5.3).
        let (tk, iv) = TrafficKey::derive(
            super::super::codec::SUITE_AES_128,
            hash,
            &app.client_app_traffic,
        )
        .expect("traffic key");
        let sealed = tk.seal(&iv, b"aad", b"payload").expect("seal");
        assert_eq!(tk.open(&iv, b"aad", &sealed).expect("open"), b"payload");
        assert!(tk.open(&iv, b"not-aad", &sealed).is_err());
    }
}
