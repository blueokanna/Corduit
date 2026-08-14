//! UUID (RFC 4122) — parsing, formatting and v4 generation.
//!
//! v4 generation is deterministic given the supplied [`crate::rng::ChaChaRng`];
//! seed it from OS entropy at the call site.

use crate::rng::ChaChaRng;

/// Error parsing a UUID string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UuidError;

impl core::fmt::Display for UuidError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("invalid UUID")
    }
}

/// A 128-bit (16-byte) universally unique identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Uuid([u8; 16]);

impl Uuid {
    /// Build from raw bytes.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Uuid(bytes)
    }

    /// The raw 16 bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Parse a hyphenated (`8-4-4-4-12`) or plain (32 hex) UUID string.
    pub fn parse_str(s: &str) -> Result<Self, UuidError> {
        let bytes = s.as_bytes();
        let mut out = [0u8; 16];
        let mut nibbles = [0u8; 32];

        let mut n = 0usize;
        for &b in bytes {
            match b {
                b'-' => {
                    // Hyphens must separate 8-4-4-4-12 hex nibbles.
                    if n != 8 && n != 12 && n != 16 && n != 20 {
                        return Err(UuidError);
                    }
                }
                b'0'..=b'9' => {
                    if n >= 32 {
                        return Err(UuidError);
                    }
                    nibbles[n] = b - b'0';
                    n += 1;
                }
                b'a'..=b'f' => {
                    if n >= 32 {
                        return Err(UuidError);
                    }
                    nibbles[n] = b - b'a' + 10;
                    n += 1;
                }
                b'A'..=b'F' => {
                    if n >= 32 {
                        return Err(UuidError);
                    }
                    nibbles[n] = b - b'A' + 10;
                    n += 1;
                }
                _ => return Err(UuidError),
            }
        }
        if n != 32 {
            return Err(UuidError);
        }

        for i in 0..16 {
            out[i] = (nibbles[i * 2] << 4) | nibbles[i * 2 + 1];
        }
        Ok(Uuid(out))
    }

    /// Generate a version-4 (random) UUID from a CSPRNG.
    pub fn new_v4(rng: &mut ChaChaRng) -> Self {
        let mut bytes = rng.fill_array::<16>();
        bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
        bytes[8] = (bytes[8] & 0x3f) | 0x80; // RFC 4122 variant
        Uuid(bytes)
    }

    /// Hyphenated lowercase form.
    pub fn hyphenated(&self) -> Hyphenated<'_> {
        Hyphenated(&self.0)
    }
}

/// Display wrapper printing `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
pub struct Hyphenated<'a>(&'a [u8; 16]);

impl core::fmt::Display for Hyphenated<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for (i, b) in self.0.iter().enumerate() {
            if i == 4 || i == 6 || i == 8 || i == 10 {
                f.write_str("-")?;
            }
            f.write_str(core::str::from_utf8(&[HEX[(b >> 4) as usize]]).unwrap())?;
            f.write_str(core::str::from_utf8(&[HEX[(b & 0xf) as usize]]).unwrap())?;
        }
        Ok(())
    }
}

impl core::fmt::Display for Uuid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.hyphenated().fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn parse_and_format_roundtrip() {
        let s = "550e8400-e29b-41d4-a716-446655440000";
        let u = Uuid::parse_str(s).unwrap();
        assert_eq!(u.to_string(), s);
        assert_eq!(u.as_bytes()[6] >> 4, 4); // version
    }

    #[test]
    fn known_bytes() {
        let u = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        assert_eq!(
            u.as_bytes(),
            &[
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                0xdd, 0xee, 0xff
            ]
        );
    }

    #[test]
    fn invalid_inputs() {
        assert!(Uuid::parse_str("not-a-uuid").is_err());
        assert!(Uuid::parse_str("").is_err());
        assert!(Uuid::parse_str("zz0e8400-e29b-41d4-a716-446655440000").is_err());
        // Too many hex digits.
        assert!(Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000ff").is_err());
        // Hyphen at the wrong position.
        assert!(Uuid::parse_str("550e840-0e29b-41d4-a716-446655440000").is_err());
    }

    #[test]
    fn v4_version_and_variant() {
        let seed = [3u8; 32];
        let mut rng = ChaChaRng::from_seed(&seed);
        let u = Uuid::new_v4(&mut rng);
        assert_eq!(u.as_bytes()[6] >> 4, 4);
        assert_eq!(u.as_bytes()[8] & 0xc0, 0x80);
        let v = u.to_string();
        assert_eq!(v.len(), 36);
        assert!(v.as_bytes()[14] == b'4');
    }
}
