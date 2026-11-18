//! A bounds-checked cursor over a binary rule set.
//!
//! Every binary rule-set format this engine reads is a sequence of scalars with
//! no length field at the front, so all decoders share one cursor: varints the
//! way Go's `encoding/binary` writes them, big-endian fixed widths, and
//! length-prefixed byte slices. Each accessor either produces a value or an
//! error — a truncated file can never be read as a short-but-valid one, because
//! the alternative is a rule set that silently loses its tail.

use crate::engine::error::{Error, Result};

/// Cursor over one decoded rule-set buffer.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    /// Start reading `data`.
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    /// Byte offset of the cursor, for diagnostics.
    pub const fn position(&self) -> usize {
        self.position
    }

    /// Bytes left to read.
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.position)
    }

    /// Whether everything has been consumed.
    pub const fn is_exhausted(&self) -> bool {
        self.position >= self.data.len()
    }

    /// The whole underlying buffer, for decoders that need to retain it.
    pub const fn source(&self) -> &'a [u8] {
        self.data
    }

    fn truncated(&self, wanted: usize) -> Error {
        Error::config(format!(
            "Rule set is truncated at byte {}: {wanted} bytes requested, {} remain",
            self.position,
            self.remaining()
        ))
    }

    /// Take the next `len` bytes.
    pub fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(len)
            .filter(|end| *end <= self.data.len())
            .ok_or_else(|| self.truncated(len))?;
        let slice = &self.data[self.position..end];
        self.position = end;
        Ok(slice)
    }

    /// Consume the rest of the buffer.
    pub fn take_rest(&mut self) -> &'a [u8] {
        let rest = &self.data[self.position..];
        self.position = self.data.len();
        rest
    }

    /// One byte.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// A one-byte flag, which Go writes for `bool`.
    pub fn bool(&mut self) -> Result<bool> {
        Ok(self.u8()? != 0)
    }

    /// Big-endian `u16`.
    pub fn u16_be(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    /// Big-endian `u32`.
    pub fn u32_be(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Big-endian `u64`.
    pub fn u64_be(&mut self) -> Result<u64> {
        let bytes = self.take(8)?;
        let mut value = [0u8; 8];
        value.copy_from_slice(bytes);
        Ok(u64::from_be_bytes(value))
    }

    /// Base-128 varint, the encoding Go's `binary.ReadUvarint` writes.
    ///
    /// Ten bytes is the most that can hold a `u64`, and the tenth may only carry
    /// the single bit that is left; anything else is a corrupt file.
    pub fn uvarint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for shift in 0..10u32 {
            let byte = self.u8()?;
            value |= u64::from(byte & 0x7F) << (shift * 7);
            if byte & 0x80 == 0 {
                if shift == 9 && byte > 1 {
                    return Err(Error::config(
                        "Rule set contains a varint that does not fit in 64 bits",
                    ));
                }
                return Ok(value);
            }
        }
        Err(Error::config(
            "Rule set contains a varint longer than ten bytes",
        ))
    }

    /// A varint count, refused when it cannot possibly fit the remaining bytes.
    ///
    /// This is the guard that keeps a corrupt count such as `u64::MAX` from
    /// turning into a multi-gigabyte allocation attempt: every element a count
    /// introduces consumes at least one byte, so a count larger than the rest of
    /// the buffer is a lie.
    pub fn count(&mut self, element_size_at_least: usize) -> Result<usize> {
        let raw = self.uvarint()?;
        let count = usize::try_from(raw)
            .map_err(|_| Error::config(format!("Rule set declares {raw} elements")))?;
        if count.saturating_mul(element_size_at_least.max(1)) > self.remaining() {
            return Err(Error::config(format!(
                "Rule set declares {count} elements but only {} bytes remain",
                self.remaining()
            )));
        }
        Ok(count)
    }

    /// `count` big-endian `u64`s.
    pub fn u64_slice(&mut self) -> Result<Vec<u64>> {
        let count = self.count(8)?;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(self.u64_be()?);
        }
        Ok(values)
    }

    /// A length-prefixed byte slice.
    pub fn length_prefixed(&mut self) -> Result<&'a [u8]> {
        let len = self.uvarint()?;
        let len = usize::try_from(len)
            .map_err(|_| Error::config(format!("Rule set declares a {len}-byte field")))?;
        self.take(len)
    }

    /// A length-prefixed UTF-8 string.
    pub fn string(&mut self) -> Result<&'a str> {
        let bytes = self.length_prefixed()?;
        core::str::from_utf8(bytes)
            .map_err(|_| Error::config("Rule set contains a non-UTF-8 string"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_scalars_in_the_order_they_were_written() {
        // u8 7, u16 0x0102, u32 0x03040506, u64 0x0708..0F
        let bytes = [7, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.u8().expect("u8"), 7);
        assert_eq!(reader.u16_be().expect("u16"), 0x0102);
        assert_eq!(reader.u32_be().expect("u32"), 0x0304_0506);
        assert_eq!(reader.u64_be().expect("u64"), 0x0708_090A_0B0C_0D0E);
        assert!(reader.is_exhausted());
    }

    #[test]
    fn varints_match_the_reference_encoding() {
        // 300 = 0b1_0010_1100 -> 0xAC 0x02
        let mut reader = Reader::new(&[0xAC, 0x02]);
        assert_eq!(reader.uvarint().expect("varint"), 300);

        let mut reader = Reader::new(&[0x00]);
        assert_eq!(reader.uvarint().expect("varint"), 0);

        // Ten-byte maximum value.
        let max = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];
        let mut reader = Reader::new(&max);
        assert_eq!(reader.uvarint().expect("varint"), u64::MAX);
    }

    #[test]
    fn truncated_and_overlong_inputs_are_errors() {
        let mut reader = Reader::new(&[0x01]);
        assert!(reader.u32_be().is_err());

        let mut reader = Reader::new(&[0x80, 0x80]);
        assert!(reader.uvarint().is_err());

        // An eleventh continuation byte cannot be a u64.
        let mut reader = Reader::new(&[0xFF; 11]);
        assert!(reader.uvarint().is_err());

        // A length prefix that runs past the buffer.
        let mut reader = Reader::new(&[0x08, b'a', b'b']);
        assert!(reader.length_prefixed().is_err());
    }

    /// A hostile count must not become an allocation: `u64::MAX` elements would
    /// ask for terabytes before the first element could be read.
    #[test]
    fn impossible_counts_are_refused_before_allocating() {
        let mut reader = Reader::new(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]);
        assert!(reader.u64_slice().is_err());
    }

    #[test]
    fn length_prefixed_strings_round_trip() {
        let mut reader = Reader::new(&[0x03, b'c', b'n', b'n']);
        assert_eq!(reader.string().expect("string"), "cnn");
        assert!(reader.is_exhausted());
    }
}
