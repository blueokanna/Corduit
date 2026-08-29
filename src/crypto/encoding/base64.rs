//! Base64 encoding (RFC 4648): standard and URL-safe alphabets, with or
//! without padding.

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Which alphabet to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alphabet {
    /// `A-Z a-z 0-9 + /`
    Standard,
    /// `A-Z a-z 0-9 - _`
    UrlSafe,
}

/// Encoding configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// Character set.
    pub alphabet: Alphabet,
    /// Whether to append `=` padding so the output length is a multiple of 4.
    pub pad: bool,
}

impl Config {
    /// RFC 4648 standard alphabet with padding.
    pub const STANDARD: Config = Config {
        alphabet: Alphabet::Standard,
        pad: true,
    };
    /// Standard alphabet, no padding.
    pub const STANDARD_NO_PAD: Config = Config {
        alphabet: Alphabet::Standard,
        pad: false,
    };
    /// URL-safe alphabet with padding.
    pub const URL_SAFE: Config = Config {
        alphabet: Alphabet::UrlSafe,
        pad: true,
    };
    /// URL-safe alphabet, no padding (used by DoH).
    pub const URL_SAFE_NO_PAD: Config = Config {
        alphabet: Alphabet::UrlSafe,
        pad: false,
    };
}

/// Encode `data` into a base64 string (alloc).
pub fn encode(data: &[u8], config: Config) -> alloc::string::String {
    let mut out = alloc::vec::Vec::with_capacity(encoded_len(data.len(), config));
    encode_into(data, config, &mut out);
    // SAFETY: base64 is pure ASCII.
    alloc::string::String::from_utf8(out).expect("base64 is ascii")
}

/// Length of the encoded output for `input_len` bytes.
pub fn encoded_len(input_len: usize, config: Config) -> usize {
    let full = input_len.div_ceil(3) * 4;
    if config.pad {
        full
    } else {
        let rem = input_len % 3;
        full - if rem == 0 { 0 } else { 3 - rem }
    }
}

/// Append the base64 encoding of `data` to `out`.
pub fn encode_into(data: &[u8], config: Config, out: &mut alloc::vec::Vec<u8>) {
    let table = match config.alphabet {
        Alphabet::Standard => STANDARD,
        Alphabet::UrlSafe => URL_SAFE,
    };

    let (chunks, rem) = data.as_chunks::<3>();
    for c in chunks {
        let b0 = c[0] as u32;
        let b1 = c[1] as u32;
        let b2 = c[2] as u32;
        out.push(table[((b0 >> 2) & 0x3f) as usize]);
        out.push(table[(((b0 << 4) | (b1 >> 4)) & 0x3f) as usize]);
        out.push(table[(((b1 << 2) | (b2 >> 6)) & 0x3f) as usize]);
        out.push(table[(b2 & 0x3f) as usize]);
    }

    if !rem.is_empty() {
        let b0 = rem[0] as u32;
        out.push(table[((b0 >> 2) & 0x3f) as usize]);
        if rem.len() == 1 {
            out.push(table[((b0 << 4) & 0x3f) as usize]);
            if config.pad {
                out.push(b'=');
                out.push(b'=');
            }
        } else {
            let b1 = rem[1] as u32;
            out.push(table[(((b0 << 4) | (b1 >> 4)) & 0x3f) as usize]);
            out.push(table[((b1 << 2) & 0x3f) as usize]);
            if config.pad {
                out.push(b'=');
            }
        }
    }
}

/// Decode failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Invalid character in input.
    InvalidByte,
    /// Input length is not valid for the configuration.
    InvalidLength,
}

fn decode_value(c: u8, alphabet: Alphabet) -> Option<u8> {
    let table = match alphabet {
        Alphabet::Standard => STANDARD,
        Alphabet::UrlSafe => URL_SAFE,
    };
    table.iter().position(|&x| x == c).map(|p| p as u8)
}

/// Decode base64 into a fresh buffer (alloc). Padded and unpadded inputs are
/// both accepted; padding is optional regardless of `Config`.
pub fn decode(input: &[u8], config: Config) -> Result<alloc::vec::Vec<u8>, DecodeError> {
    let mut out = alloc::vec::Vec::with_capacity(input.len() * 3 / 4 + 3);
    decode_into(input, config, &mut out)?;
    Ok(out)
}

/// Append the decoded bytes to `out`.
pub fn decode_into(
    input: &[u8],
    config: Config,
    out: &mut alloc::vec::Vec<u8>,
) -> Result<(), DecodeError> {
    // Strip trailing padding for length accounting.
    let mut end = input.len();
    while end > 0 && input[end - 1] == b'=' {
        end -= 1;
    }
    let body = &input[..end];

    if body.len() % 4 == 1 {
        return Err(DecodeError::InvalidLength);
    }

    let (chunks, rem) = body.as_chunks::<4>();
    for c in chunks {
        let a = decode_value(c[0], config.alphabet).ok_or(DecodeError::InvalidByte)?;
        let b = decode_value(c[1], config.alphabet).ok_or(DecodeError::InvalidByte)?;
        let cc = decode_value(c[2], config.alphabet).ok_or(DecodeError::InvalidByte)?;
        let d = decode_value(c[3], config.alphabet).ok_or(DecodeError::InvalidByte)?;
        out.push((a << 2) | (b >> 4));
        out.push((b << 4) | (cc >> 2));
        out.push((cc << 6) | d);
    }

    match rem.len() {
        2 => {
            let a = decode_value(rem[0], config.alphabet).ok_or(DecodeError::InvalidByte)?;
            let b = decode_value(rem[1], config.alphabet).ok_or(DecodeError::InvalidByte)?;
            out.push((a << 2) | (b >> 4));
        }
        3 => {
            let a = decode_value(rem[0], config.alphabet).ok_or(DecodeError::InvalidByte)?;
            let b = decode_value(rem[1], config.alphabet).ok_or(DecodeError::InvalidByte)?;
            let cc = decode_value(rem[2], config.alphabet).ok_or(DecodeError::InvalidByte)?;
            out.push((a << 2) | (b >> 4));
            out.push((b << 4) | (cc >> 2));
        }
        _ => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        // RFC 4648 §10.
        assert_eq!(encode(b"", Config::STANDARD), "");
        assert_eq!(encode(b"f", Config::STANDARD), "Zg==");
        assert_eq!(encode(b"fo", Config::STANDARD), "Zm8=");
        assert_eq!(encode(b"foo", Config::STANDARD), "Zm9v");
        assert_eq!(encode(b"foob", Config::STANDARD), "Zm9vYg==");
        assert_eq!(encode(b"fooba", Config::STANDARD), "Zm9vYmE=");
        assert_eq!(encode(b"foobar", Config::STANDARD), "Zm9vYmFy");
    }

    #[test]
    fn roundtrip_variants() {
        let data: Vec<u8> = (0u8..=255).collect();
        for config in [
            Config::STANDARD,
            Config::STANDARD_NO_PAD,
            Config::URL_SAFE,
            Config::URL_SAFE_NO_PAD,
        ] {
            let enc = encode(&data, config);
            let dec = decode(enc.as_bytes(), config).unwrap();
            assert_eq!(dec, data);
        }
    }

    #[test]
    fn url_safe_no_pad_doe() {
        // DoH uses base64url without padding.
        let input = b"\x01\x02\x03\x04";
        let enc = encode(input, Config::URL_SAFE_NO_PAD);
        assert_eq!(enc, "AQIDBA");
        let dec = decode(enc.as_bytes(), Config::URL_SAFE_NO_PAD).unwrap();
        assert_eq!(dec, input);
    }
}
