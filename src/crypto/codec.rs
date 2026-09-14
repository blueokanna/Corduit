//! Small text codecs shared by wire formats and configuration: hex, and
//! the base64 entry points the engine needs.
//!
//! Hex is implemented here (a 16-entry table, nothing to prove). Base64 is
//! **not**: the canonical encoder/decoder is
//! [`courierust_crypto::base64`](courierust::courierust_crypto::base64),
//! so the workspace holds one implementation of the bit packing. What this
//! module adds on top is the input normalisation the engine's callers
//! need:
//!
//! * [`base64_decode`] — standard alphabet, `=` optional. courierust's
//!   decoder is canonical (RFC 4648 §4, padded); keys in configuration
//!   files are routinely written without the tail padding.
//! * [`base64url_decode`] — RFC 4648 §5 alphabet, padding optional: the
//!   form RFC 8484 puts in a `?dns=` parameter.
//!
//! Both normalise and then hand the bytes to courierust, so a
//! non-canonical tail (stray bits under the padding) is rejected instead
//! of silently decoded.

/// Encode bytes as lowercase hex.
pub fn hex_encode(data: &[u8]) -> alloc::string::String {
    let mut out = alloc::string::String::with_capacity(data.len() * 2);
    for b in data {
        out.push(char::from(HEX[(b >> 4) as usize]));
        out.push(char::from(HEX[(b & 0xf) as usize]));
    }
    out
}

const HEX: [u8; 16] = *b"0123456789abcdef";

/// Decode failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexDecodeError {
    /// The input contained a character outside `[0-9a-fA-F]`.
    InvalidHexDigit,
    /// The input length was not even.
    OddLength,
}

/// Decode a hex string (odd length or invalid digits rejected).
pub fn hex_decode(input: &[u8]) -> Result<alloc::vec::Vec<u8>, HexDecodeError> {
    if input.len() % 2 != 0 {
        return Err(HexDecodeError::OddLength);
    }
    let mut out = alloc::vec::Vec::with_capacity(input.len() / 2);
    for pair in input.chunks_exact(2) {
        let hi = hex_val(pair[0]).ok_or(HexDecodeError::InvalidHexDigit)?;
        let lo = hex_val(pair[1]).ok_or(HexDecodeError::InvalidHexDigit)?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decode base64 (standard alphabet) with optional `=` padding.
///
/// Returns `None` for any input that is not canonical base64 once padded.
pub fn base64_decode(input: &str) -> Option<alloc::vec::Vec<u8>> {
    decode_normalised(input, false)
}

/// Decode base64url (RFC 4648 §5 alphabet) with optional padding.
pub fn base64url_decode(input: &str) -> Option<alloc::vec::Vec<u8>> {
    decode_normalised(input, true)
}

fn decode_normalised(input: &str, url: bool) -> Option<alloc::vec::Vec<u8>> {
    let body = input.trim_end_matches('=');
    let padding = input.len() - body.len();
    if padding > 0 {
        // Padding, when present, must be the tail of a 4-character quantum:
        // "Zg==" is canonical, "Zg=" and "Zm9vYmFy=" are not.
        if input.len() % 4 != 0 || padding != 4 - body.len() % 4 {
            return None;
        }
    }
    if body.contains('=') {
        return None;
    }

    let mut text = alloc::string::String::with_capacity(body.len() + 3);
    for c in body.chars() {
        let mapped = if url {
            match c {
                '-' => '+',
                '_' => '/',
                other => other,
            }
        } else {
            c
        };
        text.push(mapped);
    }
    while text.len() % 4 != 0 {
        text.push('=');
    }
    courierust::courierust_crypto::base64::decode(text.as_bytes()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let data = [0x00u8, 0x01, 0xab, 0xff, 0x10];
        let enc = hex_encode(&data);
        assert_eq!(enc, "0001abff10");
        assert_eq!(hex_decode(enc.as_bytes()).unwrap(), data);
        assert_eq!(hex_decode(b"abc").unwrap_err(), HexDecodeError::OddLength);
        assert_eq!(
            hex_decode(b"zz").unwrap_err(),
            HexDecodeError::InvalidHexDigit
        );
    }

    #[test]
    fn base64_accepts_padded_and_unpadded() {
        assert_eq!(base64_decode("Zm9vYmFy").unwrap(), b"foobar");
        assert_eq!(base64_decode("Zm9vYg==").unwrap(), b"foob");
        assert_eq!(base64_decode("Zm9vYg").unwrap(), b"foob");
        assert_eq!(base64_decode("Zg").unwrap(), b"f");
    }

    #[test]
    fn base64_rejects_non_canonical_and_junk() {
        assert!(base64_decode("Zg=").is_none());
        assert!(base64_decode("Zh==").is_none());
        assert!(base64_decode("!!!!").is_none());
        assert!(base64_decode("Zm9vYmFy=").is_none());
    }

    #[test]
    fn base64url_accepts_the_url_alphabet() {
        assert_eq!(base64url_decode("--__").unwrap(), [0xfb, 0xef, 0xff]);
        assert_eq!(base64url_decode("_w").unwrap(), [0xff]);
        assert!(base64url_decode("-*").is_none());
    }
}
