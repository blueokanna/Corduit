//! Hexadecimal encoding (lowercase).

/// Encode bytes as lowercase hex.
pub fn encode(data: &[u8]) -> alloc::string::String {
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
pub enum DecodeError {
    /// The input contained a character outside `[0-9a-fA-F]`.
    InvalidHexDigit,
    /// The input length was not even.
    OddLength,
}

/// Decode a hex string (odd length or invalid digits rejected).
pub fn decode(input: &[u8]) -> Result<alloc::vec::Vec<u8>, DecodeError> {
    if !input.len().is_multiple_of(2) {
        return Err(DecodeError::OddLength);
    }
    let mut out = alloc::vec::Vec::with_capacity(input.len() / 2);
    for pair in input.as_chunks::<2>().0 {
        let hi = hex_val(pair[0]).ok_or(DecodeError::InvalidHexDigit)?;
        let lo = hex_val(pair[1]).ok_or(DecodeError::InvalidHexDigit)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let data = [0x00u8, 0x01, 0xab, 0xff, 0x10];
        let enc = encode(&data);
        assert_eq!(enc, "0001abff10");
        assert_eq!(decode(enc.as_bytes()).unwrap(), data);
        assert_eq!(decode(b"abc").unwrap_err(), DecodeError::OddLength);
        assert_eq!(decode(b"zz").unwrap_err(), DecodeError::InvalidHexDigit);
    }
}
