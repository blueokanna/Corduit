//! Minimal, self-contained MaxMind DB (MMDB) v2 reader.
//!
//! Implements just enough of the binary format to resolve the GeoIP code for an
//! IP address — an ISO 3166-1 alpha-2 country code in a stock GeoLite2 layout,
//! or a provider label (`GOOGLE`, `CLOUDFRONT`, …) in the customized builds
//! profiles ship: metadata parsing, search-tree traversal and
//! map/string/pointer decoding. No third-party parser, no serde, no `unsafe` —
//! every read is bounds-checked so a corrupt database can only yield `None`,
//! never a panic or out-of-bounds access.
//!
//! Wire layout (see <https://maxmind.github.io/MaxMind-DB/>):
//! * file = search tree (nodes of two `record_size`-bit records) + 16-byte
//!   separator + data section + metadata;
//! * metadata is a data-section-format map starting at the **last** occurrence
//!   of `\xab\xcd\xefMaxMind.com`.

use crate::engine::geoip::CountryCode;
use std::cmp::Ordering;
use std::net::IpAddr;

/// Metadata values required to walk the search tree.
#[derive(Debug, Clone, Copy)]
struct Metadata {
    /// 4 or 6.
    ip_version: u16,
    /// 24, 28 or 32 bits per record.
    record_size: u16,
    /// Number of nodes in the search tree.
    node_count: u32,
    /// Bytes occupied by the search tree (`node_count * node_byte_size`).
    search_tree_size: u32,
    /// Bytes per node (`record_size * 2 / 8`).
    node_byte_size: u32,
}

/// A decoded MMDB data value (the subset relevant to GeoIP records).
///
/// The reader constructs values for every MMDB type while walking the data
/// section, but only a few are consulted for country lookups; the rest exist
/// so the parser stays faithful to the wire format and can skip payloads of
/// the correct size.
#[derive(Debug)]
#[allow(dead_code)]
enum DataValue {
    Map(Vec<(String, DataValue)>),
    Array(Vec<DataValue>),
    Str(String),
    Bytes(Vec<u8>),
    U16(u16),
    U32(u32),
    U64(u64),
    F64(f64),
    Bool(bool),
    /// Unsupported / unknown type; carries no payload.
    Null,
}

const MAGIC: &[u8] = b"\xab\xcd\xefMaxMind.com";
/// Search-tree/data-section separator size in bytes.
const DATA_SECTION_SEPARATOR: usize = 16;
/// The spec caps the metadata section (marker included) at 128 KiB, so the
/// marker cannot sit further back than this. Searching the whole file would
/// also walk a data section that may legitimately contain the same bytes.
const METADATA_SEARCH_WINDOW: usize = 128 * 1024;
/// Nesting budget for one decode: every map, array and pointer indirection
/// costs one level. The spec recommends 512; real records stay in the tens and
/// the bound is what keeps a hostile database from exhausting the stack.
const MAX_DEPTH: usize = 128;
/// Value budget for one decode, following the spec's recommendation. It bounds
/// pointer fan-out, where a tiny file can describe a huge structure.
const MAX_DECODED_VALUES: usize = 65_536;
/// Maximum entries decoded into a single map or array. `read_size` can claim up
/// to ~16.8M entries, and the value budget would only charge them one by one
/// after the allocation.
const MAX_CONTAINER_ENTRIES: usize = 65_536;

/// Per-decode accounting for the two resource limits the spec asks a reader to
/// enforce, so neither the nesting depth nor the total value count is unbounded.
#[derive(Default)]
struct DecodeState {
    depth: usize,
    values: usize,
}

/// Decode a pointer field's payload.
///
/// A pointer's control byte is `001SSVVV`, unlike every other type: `SS` selects
/// one of four payload widths and `VVV` carries the value's high bits. The
/// widths are not a uniform shift — the 2- and 3-byte forms add 2 048 and
/// 526 336 so that the four classes tile the 32-bit pointer space without gaps,
/// and the 4-byte form ignores `VVV` entirely. Returns the pointer value and the
/// number of payload bytes it consumed.
fn read_pointer(size_bits: u8, payload: &[u8]) -> Option<(u64, usize)> {
    let class = size_bits >> 3;
    let high = u64::from(size_bits & 0x07);
    match class {
        0 => Some(((high << 8) | u64::from(*payload.first()?), 1)),
        1 => {
            let word = (u64::from(*payload.first()?) << 8) | u64::from(*payload.get(1)?);
            Some((((high << 16) | word) + 2_048, 2))
        }
        2 => {
            let word = (u64::from(*payload.first()?) << 16)
                | (u64::from(*payload.get(1)?) << 8)
                | u64::from(*payload.get(2)?);
            Some((((high << 24) | word) + 526_336, 3))
        }
        _ => {
            let bytes: [u8; 4] = payload.get(..4)?.try_into().ok()?;
            Some((u64::from(u32::from_be_bytes(bytes)), 4))
        }
    }
}

/// A ready-to-query MMDB reader over an in-memory byte blob.
pub struct MmdbReader {
    data: Vec<u8>,
    meta: Metadata,
    /// File offset where the data section begins.
    data_start: usize,
}

impl MmdbReader {
    /// Parse a complete MMDB blob. Fails loudly on an unparseable database,
    /// not on a merely-missing record.
    pub fn open(data: Vec<u8>) -> Result<Self, String> {
        if data.len() < 28 {
            return Err("MMDB: file too small".to_string());
        }
        let search_from = data.len().saturating_sub(METADATA_SEARCH_WINDOW);
        let marker = data[search_from..]
            .windows(MAGIC.len())
            .rposition(|w| w == MAGIC)
            .map(|offset| search_from + offset)
            .ok_or_else(|| "MMDB: metadata marker not found".to_string())?;
        let meta_start = marker + MAGIC.len();

        let reader = Self {
            data,
            meta: Metadata {
                ip_version: 0,
                record_size: 0,
                node_count: 0,
                search_tree_size: 0,
                node_byte_size: 0,
            },
            data_start: 0,
        };

        // Metadata pointers are relative to the byte after the marker, which is
        // where the metadata map itself begins — verified against the bundled
        // GeoLite2 database, whose `languages` array stores "en" as a pointer.
        let (value, _) = reader
            .read_value(meta_start, meta_start, &mut DecodeState::default())
            .ok_or_else(|| "MMDB: metadata is corrupt".to_string())?;

        let DataValue::Map(entries) = value else {
            return Err("MMDB: metadata is not a map".to_string());
        };
        let get = |key: &str| entries.iter().find(|(k, _)| k == key).map(|(_, v)| v);

        let ip_version = reader.u16_of(get("ip_version")).unwrap_or(0);
        let record_size = reader.u16_of(get("record_size")).unwrap_or(0);
        let node_count = reader.u32_of(get("node_count")).unwrap_or(0);

        if ip_version != 4 && ip_version != 6 {
            return Err(format!("MMDB: unsupported ip_version {ip_version}"));
        }
        if !matches!(record_size, 24 | 28 | 32) {
            return Err(format!("MMDB: unsupported record_size {record_size}"));
        }
        let node_byte_size = (record_size as u32) * 2 / 8;
        let search_tree_size = node_count
            .checked_mul(node_byte_size)
            .ok_or("MMDB: tree overflow")?;

        let data_start = search_tree_size as usize + DATA_SECTION_SEPARATOR;
        if data_start > meta_start {
            return Err("MMDB: search tree overlaps metadata".to_string());
        }

        Ok(Self {
            data: reader.data,
            meta: Metadata {
                ip_version,
                record_size,
                node_count,
                search_tree_size,
                node_byte_size,
            },
            data_start,
        })
    }

    // -- metadata helpers ----------------------------------------------------

    fn u16_of(&self, value: Option<&DataValue>) -> Option<u16> {
        match value {
            Some(DataValue::U16(v)) => Some(*v),
            _ => None,
        }
    }

    fn u32_of(&self, value: Option<&DataValue>) -> Option<u32> {
        match value {
            Some(DataValue::U32(v)) => Some(*v),
            _ => None,
        }
    }

    // -- search tree ---------------------------------------------------------

    /// Read one `record_size`-bit record from `node * node_byte_size`.
    ///
    /// `bit` selects the left (0) or right (1) record of the node. All values
    /// are big-endian; 28-bit records split their high nibble into the middle
    /// byte of the 7-byte node.
    #[inline]
    fn read_record(&self, node: u32, bit: u8) -> Option<u32> {
        let base = (node as usize).checked_mul(self.meta.node_byte_size as usize)?;
        let value = match self.meta.record_size {
            24 => {
                // Node = 6 bytes: [left 3][right 3].
                let b0 = *self.data.get(base + if bit == 0 { 0 } else { 3 })?;
                let b1 = *self.data.get(base + if bit == 0 { 1 } else { 4 })?;
                let b2 = *self.data.get(base + if bit == 0 { 2 } else { 5 })?;
                (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2)
            }
            28 => {
                // Node = 7 bytes: [left low24][mid hi4|hi4][right low24].
                let mid = *self.data.get(base + 3)?;
                if bit == 0 {
                    let b0 = *self.data.get(base)?;
                    let b1 = *self.data.get(base + 1)?;
                    let b2 = *self.data.get(base + 2)?;
                    ((u32::from(mid) >> 4) << 24)
                        | (u32::from(b0) << 16)
                        | (u32::from(b1) << 8)
                        | u32::from(b2)
                } else {
                    let b0 = *self.data.get(base + 4)?;
                    let b1 = *self.data.get(base + 5)?;
                    let b2 = *self.data.get(base + 6)?;
                    ((u32::from(mid) & 0x0F) << 24)
                        | (u32::from(b0) << 16)
                        | (u32::from(b1) << 8)
                        | u32::from(b2)
                }
            }
            32 => {
                // Node = 8 bytes: [left 4][right 4].
                let off = base + if bit == 0 { 0 } else { 4 };
                let b0 = *self.data.get(off)?;
                let b1 = *self.data.get(off + 1)?;
                let b2 = *self.data.get(off + 2)?;
                let b3 = *self.data.get(off + 3)?;
                (u32::from(b0) << 24) | (u32::from(b1) << 16) | (u32::from(b2) << 8) | u32::from(b3)
            }
            _ => return None,
        };
        Some(value)
    }

    /// Walk the tree along `bits` (each byte = 8 bits, MSB first).
    ///
    /// Returns the file offset of the data record, or `None` if the address is
    /// not present in the database.
    fn lookup_bits(&self, bits: &[u8]) -> Option<usize> {
        let mut node: u32 = 0;
        for &byte in bits {
            for i in (0..8).rev() {
                let bit = (byte >> i) & 1;
                let record = self.read_record(node, bit)?;
                match record.cmp(&self.meta.node_count) {
                    Ordering::Less => node = record,
                    Ordering::Greater => {
                        // `$offset_in_file = record - node_count + tree_size`.
                        let off = (record - self.meta.node_count) as usize
                            + self.meta.search_tree_size as usize;
                        return Some(off);
                    }
                    // record == node_count: not in database
                    Ordering::Equal => return None,
                }
            }
        }
        None
    }

    /// Resolve an IP to its data-record file offset.
    fn lookup(&self, ip: IpAddr) -> Option<usize> {
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                if self.meta.ip_version == 4 {
                    self.lookup_bits(&octets)
                } else {
                    let mut bits = [0u8; 16];
                    bits[10] = 0xff;
                    bits[11] = 0xff;
                    bits[12..16].copy_from_slice(&octets);
                    self.lookup_bits(&bits)
                }
            }
            IpAddr::V6(v6) => {
                if self.meta.ip_version == 6 {
                    self.lookup_bits(&v6.octets())
                } else {
                    None
                }
            }
        }
    }

    // -- data section --------------------------------------------------------

    /// Read the data-field payload size from a control byte's size bits.
    #[inline]
    fn read_size(&self, size_bits: u8, pos: &mut usize) -> Option<usize> {
        match size_bits {
            0..=28 => Some(size_bits as usize),
            29 => {
                let b = *self.data.get(*pos)? as usize;
                *pos += 1;
                Some(29 + b)
            }
            30 => {
                let hi = *self.data.get(*pos)? as usize;
                let lo = *self.data.get(*pos + 1)? as usize;
                *pos += 2;
                Some(285 + (hi << 8) + lo)
            }
            31 => {
                let a = *self.data.get(*pos)? as usize;
                let b = *self.data.get(*pos + 1)? as usize;
                let c = *self.data.get(*pos + 2)? as usize;
                *pos += 3;
                Some(65_821 + (a << 16) + (b << 8) + c)
            }
            _ => None,
        }
    }

    /// Decode one data field at `offset`, returning `(value, next_offset)`.
    ///
    /// `ptr_base` is the file offset pointers are relative to: the data-section
    /// start for records, or the metadata start for the metadata map. `state`
    /// carries the depth and value budgets that bound a hostile database.
    fn read_value(
        &self,
        offset: usize,
        ptr_base: usize,
        state: &mut DecodeState,
    ) -> Option<(DataValue, usize)> {
        if state.values >= MAX_DECODED_VALUES {
            return None;
        }
        state.values += 1;

        let control = *self.data.get(offset)?;
        let type_bits = control >> 5;
        let size_bits = control & 0x1F;
        let mut pos = offset + 1;

        let ty = if type_bits == 0 {
            let ext = *self.data.get(pos)?;
            pos += 1;
            ext + 7
        } else {
            type_bits
        };

        if ty == 1 {
            let (value, payload_len) = read_pointer(size_bits, self.data.get(pos..)?)?;
            if state.depth >= MAX_DEPTH {
                return None;
            }
            let target = ptr_base.checked_add(usize::try_from(value).ok()?)?;
            if target >= self.data.len() {
                return None;
            }
            state.depth += 1;
            let resolved = self.read_value(target, ptr_base, state);
            state.depth -= 1;
            let (resolved, _) = resolved?;
            return Some((resolved, pos + payload_len));
        }

        let size = self.read_size(size_bits, &mut pos)?;

        if ty == 14 {
            return Some((DataValue::Bool(size == 1), pos));
        }

        if ty == 7 {
            if size > MAX_CONTAINER_ENTRIES || state.depth >= MAX_DEPTH {
                return None;
            }
            state.depth += 1;
            let mut entries = Vec::with_capacity(size);
            let mut p = pos;
            for _ in 0..size {
                let (key, np) = self.read_value(p, ptr_base, state)?;
                let DataValue::Str(key) = key else {
                    return None;
                };
                p = np;
                let (val, np) = self.read_value(p, ptr_base, state)?;
                p = np;
                entries.push((key, val));
            }
            state.depth -= 1;
            return Some((DataValue::Map(entries), p));
        }

        if ty == 11 {
            if size > MAX_CONTAINER_ENTRIES || state.depth >= MAX_DEPTH {
                return None;
            }
            state.depth += 1;
            let mut items = Vec::with_capacity(size);
            let mut p = pos;
            for _ in 0..size {
                let (val, np) = self.read_value(p, ptr_base, state)?;
                p = np;
                items.push(val);
            }
            state.depth -= 1;
            return Some((DataValue::Array(items), p));
        }
        let payload = self.data.get(pos..pos + size)?;
        let end = pos + size;
        let value = match ty {
            2 => DataValue::Str(std::str::from_utf8(payload).ok()?.to_string()),
            3 => DataValue::F64(f64::from_be_bytes(be_uint(payload)?)),
            4 => DataValue::Bytes(payload.to_vec()),
            5 => DataValue::U16(u16::from_be_bytes(be_uint(payload)?)),
            6 => DataValue::U32(u32::from_be_bytes(be_uint(payload)?)),
            9 => DataValue::U64(u64::from_be_bytes(be_uint(payload)?)),
            _ => DataValue::Null,
        };
        Some((value, end))
    }

    /// Resolve the GeoIP code for an IP, if present.
    ///
    /// The value is exactly what the record's `country.iso_code` field carries:
    /// an ISO 3166-1 alpha-2 code in a stock GeoLite2 layout, or a provider
    /// label (`GOOGLE`, `CLOUDFRONT`, …) in the customized builds the mobile
    /// profiles ship. Fields that are empty, non-alphabetic or longer than
    /// [`CountryCode::MAX_LEN`] are reported as absent rather than guessed at.
    pub fn lookup_country(&self, ip: IpAddr) -> Option<CountryCode> {
        let data_off = self.lookup(ip)?;
        let (value, _) = self.read_value(data_off, self.data_start, &mut DecodeState::default())?;
        let DataValue::Map(entries) = value else {
            return None;
        };
        let country = entries.into_iter().find(|(k, _)| k == "country")?.1;
        let DataValue::Map(country_entries) = country else {
            return None;
        };
        let iso = country_entries
            .into_iter()
            .find(|(k, _)| k == "iso_code")?
            .1;
        match iso {
            DataValue::Str(code) => CountryCode::from_bytes(code.as_bytes()),
            _ => None,
        }
    }
}

/// Big-endian unsigned integer held in at most `N` bytes.
///
/// MaxMind's writer emits the shortest form of an integer — this database
/// stores its two-byte `ip_version` as the single byte `06` — so a reader has
/// to zero-extend instead of insisting on the nominal width.
fn be_uint<const N: usize>(payload: &[u8]) -> Option<[u8; N]> {
    if payload.len() > N {
        return None;
    }
    let mut out = [0u8; N];
    out[N - payload.len()..].copy_from_slice(payload);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encoder for the subset of the data format the fixture needs: a control
    /// byte, the extended-type byte when the type needs one, and an in-line
    /// payload size.
    fn field(ty: u8, payload: &[u8]) -> Vec<u8> {
        let size = u8::try_from(payload.len()).expect("fixture payloads stay small");
        assert!(size <= 28, "the fixture only uses in-line sizes");
        let mut out = if ty < 8 {
            vec![(ty << 5) | size]
        } else {
            vec![size, ty - 7]
        };
        out.extend_from_slice(payload);
        out
    }

    fn map(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let count = u8::try_from(entries.len()).expect("fixture maps stay small");
        let mut out = vec![(7u8 << 5) | count];
        for (key, value) in entries {
            out.extend_from_slice(&field(2, key.as_bytes()));
            out.extend_from_slice(value);
        }
        out
    }

    fn metadata(node_count: u32, record_size: u16, ip_version: u16) -> Vec<u8> {
        map(&[
            ("binary_format_major_version", field(5, &2u16.to_be_bytes())),
            ("binary_format_minor_version", field(5, &0u16.to_be_bytes())),
            ("build_epoch", field(9, &0u64.to_be_bytes())),
            ("database_type", field(2, b"VeloGuard-Fixture")),
            ("ip_version", field(5, &ip_version.to_be_bytes())),
            ("node_count", field(6, &node_count.to_be_bytes())),
            ("record_size", field(5, &record_size.to_be_bytes())),
        ])
    }

    /// A hand-built database: an empty search tree, the sixteen-byte separator
    /// and a metadata map. It pins the detail a reader gets wrong when it
    /// decodes from the marker instead of the byte after it.
    #[test]
    fn parses_a_hand_built_database() {
        let mut file = vec![0u8; DATA_SECTION_SEPARATOR];
        file.extend_from_slice(MAGIC);
        file.extend_from_slice(&metadata(0, 24, 6));

        let reader = MmdbReader::open(file).expect("the fixture parses");
        assert_eq!(reader.meta.ip_version, 6);
        assert_eq!(reader.meta.record_size, 24);
        assert_eq!(reader.meta.node_count, 0);
        assert_eq!(reader.data_start, DATA_SECTION_SEPARATOR);
        assert_eq!(reader.lookup_country("8.8.8.8".parse().unwrap()), None);
    }

    /// A file that ends at the marker has no metadata map, and that is
    /// reported instead of accepted with defaults.
    #[test]
    fn rejects_a_file_without_metadata() {
        let mut file = vec![0u8; DATA_SECTION_SEPARATOR];
        file.extend_from_slice(MAGIC);
        assert!(MmdbReader::open(file).is_err());
    }

    /// The real-database check: point `CORDUIT_MMDB_FILE` at a `.mmdb` and
    /// this resolves an address through the whole tree, which no hand-built
    /// fixture can cover. Skipped when the variable is unset, as in CI.
    ///
    /// `223.5.5.5` (AliDNS) resolves to China in every GeoLite2-family
    /// database, so it pins the ISO 3166-1 path; `8.8.8.8` pins the customized
    /// provider labels (`GOOGLE` in the bundled build) that a two-letter-only
    /// reader silently drops.
    #[test]
    fn resolves_through_a_real_database_when_provided() {
        let Ok(path) = std::env::var("CORDUIT_MMDB_FILE") else {
            return;
        };
        let data = std::fs::read(&path).expect("the database file is readable");
        let reader = MmdbReader::open(data).expect("a real Country.mmdb parses");

        assert_eq!(
            reader.lookup_country("223.5.5.5".parse().unwrap()),
            CountryCode::parse("CN")
        );
        let provider = reader
            .lookup_country("8.8.8.8".parse().unwrap())
            .expect("8.8.8.8 is in every GeoLite2-family database");
        assert!(
            provider.as_bytes().iter().all(u8::is_ascii_uppercase),
            "database codes are canonicalized: {provider}"
        );
        assert!(
            provider.as_bytes().len() >= 2,
            "a resolved code is never empty: {provider}"
        );
    }

    /// The pointer table from the spec, including the two biases a reader gets
    /// wrong by reading the five size bits as a plain big-endian length.
    #[test]
    fn pointer_classes_follow_the_spec_table() {
        // Class 0: 11-bit value in one payload byte.
        assert_eq!(read_pointer(0b00000, &[0x1C]), Some((0x1C, 1)));
        assert_eq!(read_pointer(0b00110, &[0x40]), Some(((6 << 8) | 0x40, 1)));
        // Class 1: 19-bit value in two payload bytes, biased by 2 048.
        assert_eq!(
            read_pointer(0b01000, &[0x03, 0xB9]),
            Some((0x3B9 + 2_048, 2))
        );
        assert_eq!(
            read_pointer(0b01111, &[0xFF, 0xFF]),
            Some((((7 << 16) | 0xFFFF) + 2_048, 2))
        );
        // Class 2: 27-bit value in three payload bytes, biased by 526 336.
        assert_eq!(read_pointer(0b10000, &[0, 1, 0]), Some((256 + 526_336, 3)));
        // Class 3: raw 32-bit value; the high bits are ignored.
        assert_eq!(
            read_pointer(0b11000, &[0xDE, 0xAD, 0xBE, 0xEF]),
            Some((0xDEAD_BEEF, 4))
        );
        assert_eq!(
            read_pointer(0b11111, &[0, 0, 0x80, 0x00]),
            Some((0x8000, 4))
        );
        // Truncated payloads are rejected, never read past the buffer.
        assert_eq!(read_pointer(0b01000, &[0x01]), None);
        assert_eq!(read_pointer(0b11000, &[1, 2, 3]), None);
    }
}
