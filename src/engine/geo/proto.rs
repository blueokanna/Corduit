//! Strict Protocol Buffers wire decoding for the Geo databases.
//!
//! `geosite.dat` and `geoip.dat` are protobuf documents with a schema that has
//! not changed since v2ray 4.x ([`routercommon/common.proto`]). They are read on
//! the routing hot path's behalf, so the decoder here is hand-written rather
//! than generated:
//!
//! * it is **zero-copy** — every field borrows the file bytes, so a 4 MiB
//!   `geosite.dat` costs 4 MiB and not 40, and a category that never gets matched
//!   never allocates a single string;
//! * it is **strict** — a truncated length, an overlong varint, field number
//!   zero, an unknown wire type or a protobuf group is a hard error. A decoder
//!   that shrugs at malformed input turns "wrong file" into "some rules silently
//!   never match", which is the single hardest routing bug to find;
//! * it cannot recurse without a bound: [`MAX_DEPTH`] is the budget for the
//!   descent into nested messages, and a database that needs more is not one.
//!
//! [`routercommon/common.proto`]: https://github.com/v2fly/v2ray-core/blob/master/app/router/routercommon/common.proto

use crate::engine::error::{Error, Result};

/// Largest field number protobuf permits (`2^29 - 1`), excluding the reserved
/// `19000..=19999` range that no schema uses for data we read.
const MAX_FIELD_NUMBER: u32 = (1 << 29) - 1;

/// Deepest nesting the Geo databases need: `GeoSiteList.entry[].domain[]`,
/// which is three levels. A message that nests deeper than this is not a Geo
/// database, and refusing it costs nothing.
pub const MAX_DEPTH: usize = 8;

/// Wire type, encoded in the low three bits of a field's tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireType {
    /// Base-128 varint: `int32`, `int64`, `uint32`, `uint64`, `bool`, `enum`.
    Varint,
    /// Eight bytes, little-endian: `fixed64`, `sfixed64`, `double`.
    Fixed64,
    /// Length prefix followed by that many bytes: `string`, `bytes`, messages,
    /// packed repeated scalars.
    LengthDelimited,
    /// Four bytes, little-endian: `fixed32`, `sfixed32`, `float`.
    Fixed32,
}

impl WireType {
    /// Decode the wire type from a tag's low bits.
    ///
    /// Wire types 3 and 4 are protobuf *groups*, removed in proto3 and never
    /// emitted by the encoders that write the Geo databases; accepting them
    /// would mean carrying a deprecated, recursion-prone code path for no file
    /// in existence.
    fn from_low_bits(bits: u8) -> Result<Self> {
        match bits {
            0 => Ok(Self::Varint),
            1 => Ok(Self::Fixed64),
            2 => Ok(Self::LengthDelimited),
            5 => Ok(Self::Fixed32),
            other => Err(Error::config(format!(
                "Geo database is not protobuf: invalid wire type {other}"
            ))),
        }
    }
}

/// One decoded field, borrowing the buffer it was read from.
#[derive(Debug, Clone, Copy)]
pub struct Field<'a> {
    number: u32,
    wire: WireType,
    /// Decoded varint for [`WireType::Varint`], the raw little-endian value for
    /// the fixed widths, `0` otherwise.
    scalar: u64,
    /// Payload for [`WireType::LengthDelimited`], empty otherwise.
    payload: &'a [u8],
}

impl<'a> Field<'a> {
    /// Field number as declared in the schema.
    pub const fn number(&self) -> u32 {
        self.number
    }

    /// Value of a varint field, or of a fixed-width field widened to `u64`.
    pub const fn raw_scalar(&self) -> u64 {
        self.scalar
    }

    /// A varint field as `u32`, refusing values that do not fit.
    ///
    /// The schema's `uint32 prefix` is the only field read this way; a value
    /// above `u32::MAX` means the file was written by something that does not
    /// follow the schema, so it is an error rather than a truncation.
    pub fn varint_u32(&self) -> Result<u32> {
        if self.wire != WireType::Varint {
            return Err(Error::config(format!(
                "Geo database field {} is not a varint",
                self.number
            )));
        }
        u32::try_from(self.scalar).map_err(|_| {
            Error::config(format!(
                "Geo database field {} has an out-of-range value {}",
                self.number, self.scalar
            ))
        })
    }

    /// Enum/unint value of a varint field.
    pub fn varint_u64(&self) -> Result<u64> {
        if self.wire != WireType::Varint {
            return Err(Error::config(format!(
                "Geo database field {} is not a varint",
                self.number
            )));
        }
        Ok(self.scalar)
    }

    /// Payload of a length-delimited field — a `bytes` field.
    pub fn bytes(&self) -> Result<&'a [u8]> {
        if self.wire != WireType::LengthDelimited {
            return Err(Error::config(format!(
                "Geo database field {} is not length-delimited",
                self.number
            )));
        }
        Ok(self.payload)
    }

    /// Payload of a length-delimited field as UTF-8.
    ///
    /// The Geo databases are UTF-8 by construction; a domain that is not is
    /// unusable anyway, and reporting it beats matching against mojibake.
    pub fn string(&self) -> Result<&'a str> {
        let bytes = self.bytes()?;
        core::str::from_utf8(bytes).map_err(|_| {
            Error::config(format!(
                "Geo database field {} is not valid UTF-8",
                self.number
            ))
        })
    }

    /// A nested message, as a decoder over the payload.
    pub fn decoder(&self) -> Result<Decoder<'a>> {
        Ok(Decoder::new(self.bytes()?))
    }
}

/// A cursor over one protobuf message's fields.
#[derive(Debug, Clone)]
pub struct Decoder<'a> {
    buffer: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    /// Start decoding `buffer` as one message.
    pub const fn new(buffer: &'a [u8]) -> Self {
        Self {
            buffer,
            position: 0,
        }
    }

    /// Whether every byte has been consumed.
    pub const fn is_empty(&self) -> bool {
        self.position >= self.buffer.len()
    }

    /// Bytes not yet decoded, for diagnostics.
    pub fn remaining(&self) -> usize {
        self.buffer.len().saturating_sub(self.position)
    }

    /// Read the next field, or `None` at the end of the message.
    pub fn next_field(&mut self) -> Result<Option<Field<'a>>> {
        if self.is_empty() {
            return Ok(None);
        }

        let tag = self.read_varint()?;
        let number = tag >> 3;
        if number == 0 {
            return Err(Error::config(
                "Geo database is not protobuf: field number zero",
            ));
        }
        if number > u64::from(MAX_FIELD_NUMBER) {
            return Err(Error::config(format!(
                "Geo database field number {number} is out of range"
            )));
        }
        let wire = WireType::from_low_bits((tag & 0x7) as u8)?;
        let number = number as u32;

        let mut field = Field {
            number,
            wire,
            scalar: 0,
            payload: &[],
        };
        match wire {
            WireType::Varint => field.scalar = self.read_varint()?,
            WireType::Fixed64 => {
                field.scalar = u64::from_le_bytes(self.read_array::<8>()?);
            }
            WireType::Fixed32 => {
                field.scalar = u64::from(u32::from_le_bytes(self.read_array::<4>()?));
            }
            WireType::LengthDelimited => {
                let length = self.read_varint()?;
                let length = usize::try_from(length).map_err(|_| {
                    Error::config(format!(
                        "Geo database field {number} declares a {length}-byte length"
                    ))
                })?;
                if length > self.remaining() {
                    return Err(Error::config(format!(
                        "Geo database field {number} declares {length} bytes, {} remain",
                        self.remaining()
                    )));
                }
                let start = self.position;
                self.position += length;
                field.payload = &self.buffer[start..start + length];
            }
        }

        Ok(Some(field))
    }

    /// Base-128 varint, the only integer encoding protobuf uses for tags and
    /// lengths.
    ///
    /// Ten bytes is the maximum that can encode a `u64`; an eleventh byte means
    /// the input is not protobuf, and so does a tenth byte carrying bits that do
    /// not fit. Both are errors, never a wrapped value.
    fn read_varint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for shift in 0..10u32 {
            let byte = *self
                .buffer
                .get(self.position)
                .ok_or_else(|| Error::config("Geo database is truncated inside a varint"))?;
            self.position += 1;
            value |= u64::from(byte & 0x7F) << (shift * 7);
            if byte & 0x80 == 0 {
                if shift == 9 && byte > 1 {
                    return Err(Error::config(
                        "Geo database contains a varint that does not fit in 64 bits",
                    ));
                }
                return Ok(value);
            }
        }
        Err(Error::config(
            "Geo database contains a varint longer than ten bytes",
        ))
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self
            .position
            .checked_add(N)
            .filter(|end| *end <= self.buffer.len())
            .ok_or_else(|| Error::config("Geo database is truncated in a fixed-width field"))?;
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buffer[self.position..end]);
        self.position = end;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = &[0x08, 0x2A, 0x12, 0x02, b'h', b'i'];

    #[test]
    fn decodes_a_varint_and_a_string_field() {
        let mut decoder = Decoder::new(SAMPLE);
        let number = decoder.next_field().expect("field").expect("present");
        assert_eq!(number.number(), 1);
        assert_eq!(number.varint_u64().expect("varint"), 42);

        let text = decoder.next_field().expect("field").expect("present");
        assert_eq!(text.number(), 2);
        assert_eq!(text.string().expect("string"), "hi");

        assert!(decoder.next_field().expect("end").is_none());
        assert!(decoder.is_empty());
    }

    /// Unknown fields must be skippable, because a newer writer may add them —
    /// that is the whole point of protobuf's forward compatibility.
    #[test]
    fn skips_fields_it_does_not_know_and_keeps_going() {
        let bytes = &[
            0x1D, 0x04, 0x03, 0x02, 0x01, // field 3, fixed32
            0x21, 1, 2, 3, 4, 5, 6, 7, 8, // field 4, fixed64
            0x08, 0x07, // field 1, varint 7
        ];
        let mut decoder = Decoder::new(bytes);
        let fixed32 = decoder.next_field().expect("field").expect("present");
        assert_eq!(fixed32.number(), 3);
        assert_eq!(fixed32.raw_scalar(), 0x0102_0304);
        let fixed64 = decoder.next_field().expect("field").expect("present");
        assert_eq!(fixed64.number(), 4);
        let last = decoder.next_field().expect("field").expect("present");
        assert_eq!(last.varint_u64().expect("varint"), 7);
    }

    #[test]
    fn rejects_truncated_input_instead_of_guessing() {
        let truncated = &[0x12, 0x04, b'h', b'i'];
        let mut decoder = Decoder::new(truncated);
        assert!(decoder.next_field().is_err());

        let mut decoder = Decoder::new(&[0x80, 0x80, 0x80]);
        assert!(decoder.next_field().is_err());
    }

    #[test]
    fn rejects_values_that_do_not_fit() {
        let mut decoder = Decoder::new(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
        ]);
        assert!(decoder.next_field().is_err());

        let mut decoder = Decoder::new(&[0x00, 0x01]);
        assert!(decoder.next_field().is_err());

        let mut decoder = Decoder::new(&[0x0B]);
        assert!(decoder.next_field().is_err());
    }

    #[test]
    fn a_varint_field_does_not_answer_as_a_string() {
        let mut decoder = Decoder::new(&[0x08, 0x2A]);
        let field = decoder.next_field().expect("field").expect("present");
        assert!(field.string().is_err());
        assert!(field.bytes().is_err());
    }

    #[test]
    fn u32_fields_refuse_overflow() {
        // 0xFFFF_FFFF: four full groups plus the low nibble.
        let mut decoder = Decoder::new(&[0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F]);
        let field = decoder.next_field().expect("field").expect("present");
        assert_eq!(field.varint_u32().expect("fits"), u32::MAX);

        let mut decoder = Decoder::new(&[0x08, 0x80, 0x80, 0x80, 0x80, 0x20]);
        let field = decoder.next_field().expect("field").expect("present");
        assert!(field.varint_u32().is_err());
    }
}
