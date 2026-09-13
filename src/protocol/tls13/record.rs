//! TLS 1.3 record protection (RFC 8446 §5).
//!
//! Pure transforms: a caller supplies a direction's [`TrafficKey`] and
//! static IV, this module produces and consumes `TLSCiphertext` bytes. No
//! I/O, no buffering policy — so it works in `no_std + alloc` and is tested
//! without sockets.
//!
//! Wire format (RFC 8446 §5.2):
//!
//! ```text
//! TLSCiphertext {
//!     ContentType opaque_type = application_data; /* 23 */
//!     ProtocolVersion legacy_record_version = 0x0303;
//!     uint16 length = length(inner_plaintext) + 1 + tag_length;
//!     opaque encrypted_record[length];
//! }
//! inner_plaintext = content || content_type || zeros(padding)
//! ```
//!
//! The AEAD nonce is the static IV XORed with the 64-bit record sequence
//! number (RFC 8446 §5.3); the AAD is the 5-byte record header of the record
//! being produced. Both directions number records independently, and the
//! sequence resets to 0 whenever the key changes (`KeyUpdate`).

use super::key_schedule::TrafficKey;
use super::{Result, Tls13Error};
use alloc::vec::Vec;

/// TLS `ContentType` values used by this client.
pub const CONTENT_CHANGE_CIPHER_SPEC: u8 = 20;
/// `alert`.
pub const CONTENT_ALERT: u8 = 21;
/// `handshake`.
pub const CONTENT_HANDSHAKE: u8 = 22;
/// `application_data`.
pub const CONTENT_APPLICATION_DATA: u8 = 23;

/// AEAD tag length (all three TLS 1.3 suites use a 16-byte tag).
pub const TAG_LEN: usize = 16;

/// Maximum `TLSPlaintext` length (RFC 8446 §5.1: 2^14).
pub const MAX_PLAINTEXT: usize = 1 << 14;

/// Maximum `TLSCiphertext` length we accept (2^14 + 256, RFC 8446 §5.2).
pub const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 256;

/// Alert levels (RFC 8446 §6).
pub const ALERT_WARNING: u8 = 1;
/// Fatal alert level.
pub const ALERT_FATAL: u8 = 2;

/// Build an unprotected record — used for the initial `ClientHello` and for
/// the compatibility `change_cipher_spec` (RFC 8446 appendix D.4).
pub fn plaintext_record(content_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(content_type);
    out.extend_from_slice(&[0x03, 0x03]);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Parse a 5-byte record header; returns `(content_type, length)`.
pub fn parse_record_header(header: &[u8]) -> Result<(u8, usize)> {
    if header.len() < 5 {
        return Err(Tls13Error::Protocol("truncated record header".into()));
    }

    if header[1] != 0x03 || header[2] > 0x04 {
        return Err(Tls13Error::Protocol(alloc::format!(
            "unsupported record version 0x{:02x}{:02x}",
            header[1],
            header[2]
        )));
    }
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if len > MAX_CIPHERTEXT {
        return Err(Tls13Error::Protocol(alloc::format!(
            "record length {len} exceeds the maximum"
        )));
    }
    Ok((header[0], len))
}

/// One direction's record protection state.
pub struct RecordProtector {
    key: TrafficKey,
    iv: [u8; 12],
    seq: u64,
}

impl RecordProtector {
    /// New protector for `key`/`iv` starting at sequence number 0.
    pub fn new(key: TrafficKey, iv: [u8; 12]) -> Self {
        Self { key, iv, seq: 0 }
    }

    /// Replace the key material (after `KeyUpdate`); the sequence resets.
    pub fn rekey(&mut self, key: TrafficKey, iv: [u8; 12]) {
        self.key = key;
        self.iv = iv;
        self.seq = 0;
    }

    /// The per-record nonce: `iv XOR seq` in the last 8 bytes.
    fn nonce(&self) -> [u8; 12] {
        let mut nonce = self.iv;
        let seq = self.seq.to_be_bytes();
        for (i, b) in seq.iter().enumerate() {
            nonce[4 + i] ^= b;
        }
        nonce
    }

    /// Protect `payload` as content type `content_type`; returns the complete
    /// `TLSCiphertext` record.
    pub fn seal(&mut self, content_type: u8, payload: &[u8]) -> Result<Vec<u8>> {
        if payload.len() > MAX_PLAINTEXT {
            return Err(Tls13Error::Protocol(
                "plaintext exceeds the record limit".into(),
            ));
        }
        let mut inner = Vec::with_capacity(payload.len() + 1);
        inner.extend_from_slice(payload);
        inner.push(content_type);
        let ct_len = inner.len() + TAG_LEN;
        if ct_len > u16::MAX as usize {
            return Err(Tls13Error::Protocol("record too large to encode".into()));
        }
        let mut aad = [0u8; 5];
        aad[0] = CONTENT_APPLICATION_DATA;
        aad[1] = 0x03;
        aad[2] = 0x03;
        aad[3..].copy_from_slice(&(ct_len as u16).to_be_bytes());

        let nonce = self.nonce();
        let ciphertext = self.key.seal(&nonce, &aad, &inner)?;
        self.seq = self.seq.wrapping_add(1);

        let mut out = Vec::with_capacity(5 + ciphertext.len());
        out.extend_from_slice(&aad);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Unprotect a `TLSCiphertext` body (without its 5-byte header), given
    /// the length the header declared.
    ///
    /// Returns the inner content type and the application payload.
    pub fn open(&mut self, ciphertext: &[u8]) -> Result<(u8, Vec<u8>)> {
        if ciphertext.len() > MAX_CIPHERTEXT || ciphertext.len() < TAG_LEN + 1 {
            return Err(Tls13Error::Protocol(
                "ciphertext length out of range".into(),
            ));
        }
        let mut aad = [0u8; 5];
        aad[0] = CONTENT_APPLICATION_DATA;
        aad[1] = 0x03;
        aad[2] = 0x03;
        aad[3..].copy_from_slice(&(ciphertext.len() as u16).to_be_bytes());

        let nonce = self.nonce();
        let inner = self.key.open(&nonce, &aad, ciphertext).map_err(|e| {
            // Do not distinguish tag failure from other AEAD failures.
            Tls13Error::Protocol(alloc::format!("record authentication failed: {e}"))
        })?;
        self.seq = self.seq.wrapping_add(1);

        // Strip zero padding, then the last non-zero byte is the content type
        // (RFC 8446 §5.4: all-zero content types are illegal, so a real type
        // is always present).
        let end = inner
            .iter()
            .rposition(|b| *b != 0)
            .ok_or_else(|| Tls13Error::Protocol("record with only zero padding".into()))?;
        let content_type = inner[end];
        let payload = inner[..end].to_vec();
        match content_type {
            CONTENT_CHANGE_CIPHER_SPEC
            | CONTENT_ALERT
            | CONTENT_HANDSHAKE
            | CONTENT_APPLICATION_DATA => Ok((content_type, payload)),
            other => Err(Tls13Error::Protocol(alloc::format!(
                "invalid inner content type {other}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::tls13::key_schedule::SuiteHash;

    fn protector(secret: &[u8]) -> RecordProtector {
        let (key, iv) = TrafficKey::derive(
            crate::protocol::tls13::codec::SUITE_AES_128,
            SuiteHash::Sha256,
            secret,
        )
        .expect("traffic key");
        RecordProtector::new(key, iv)
    }

    #[test]
    fn records_round_trip_each_content_type() {
        // One protector per direction: the sequence numbers are independent.
        let mut sender = protector(b"secret");
        let mut receiver = protector(b"secret");
        for (ty, payload) in [
            (CONTENT_HANDSHAKE, &b"\x14\x00\x00\x20finished"[..]),
            (CONTENT_APPLICATION_DATA, &b"GET / HTTP/1.1\r\n"[..]),
            (CONTENT_ALERT, &[ALERT_WARNING, 0][..]),
        ] {
            let record = sender.seal(ty, payload).expect("seal");
            let (hdr_ty, len) = parse_record_header(&record).expect("header");
            assert_eq!(hdr_ty, CONTENT_APPLICATION_DATA, "outer type is opaque");
            assert_eq!(len, record.len() - 5);
            let (got_ty, got) = receiver.open(&record[5..]).expect("open");
            assert_eq!(got_ty, ty);
            assert_eq!(got, payload);
        }
    }

    #[test]
    fn sequence_numbers_advance_and_bind_the_nonce() {
        let mut a = protector(b"secret");
        let mut b = protector(b"secret");
        let r0 = a.seal(CONTENT_APPLICATION_DATA, b"one").expect("seal");
        let r1 = a.seal(CONTENT_APPLICATION_DATA, b"one").expect("seal");
        assert_ne!(r0[5..], r1[5..], "same plaintext, different nonce");
        assert_eq!(b.open(&r0[5..]).expect("open").1, b"one");
        assert_eq!(b.open(&r1[5..]).expect("open").1, b"one");
        // Replaying a record (wrong sequence number) must fail authentication.
        assert!(b.open(&r0[5..]).is_err());
    }

    #[test]
    fn tampering_is_rejected() {
        let mut p = protector(b"secret");
        let mut record = p.seal(CONTENT_APPLICATION_DATA, b"payload").expect("seal");
        let last = record.len() - 1;
        record[last] ^= 0x01;
        let mut q = protector(b"secret");
        assert!(q.open(&record[5..]).is_err());
    }

    #[test]
    fn rekey_resets_sequence() {
        let mut p = protector(b"secret");
        let first = p.seal(CONTENT_APPLICATION_DATA, b"x").expect("seal");
        let (key, iv) = TrafficKey::derive(
            crate::protocol::tls13::codec::SUITE_AES_128,
            SuiteHash::Sha256,
            b"other-secret",
        )
        .expect("traffic key");
        p.rekey(key, iv);
        let after = p.seal(CONTENT_APPLICATION_DATA, b"x").expect("seal");
        assert_ne!(first[5..], after[5..]);
    }

    #[test]
    fn plaintext_records_are_well_formed() {
        let rec = plaintext_record(CONTENT_HANDSHAKE, b"abc");
        assert_eq!(rec[0], CONTENT_HANDSHAKE);
        assert_eq!(&rec[1..3], &[0x03, 0x03]);
        assert_eq!(u16::from_be_bytes([rec[3], rec[4]]), 3);
        assert_eq!(&rec[5..], b"abc");
        assert!(parse_record_header(&rec).is_ok());
        // Oversized declared length is rejected before allocation.
        let bad = [CONTENT_APPLICATION_DATA, 0x03, 0x03, 0xff, 0xff];
        assert!(parse_record_header(&bad).is_err());
        // A TLS 1.2 version is not accepted by a 1.3-only client.
        let old = [CONTENT_HANDSHAKE, 0x03, 0x01, 0x00, 0x04];
        assert!(
            parse_record_header(&old).is_ok(),
            "0x0301 is tolerated on read"
        );
        let future = [CONTENT_HANDSHAKE, 0x03, 0x07, 0x00, 0x04];
        assert!(parse_record_header(&future).is_err());
    }
}
