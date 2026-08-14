//! Minimal, self-contained MaxMind DB (MMDB) v2 reader.
//!
//! Implements just enough of the binary format to resolve the GeoIP country
//! ISO 3166-1 alpha-2 code for an IP address: metadata parsing, search-tree
//! traversal and map/string/pointer decoding. No third-party parser, no serde,
//! no `unsafe` — every read is bounds-checked so a corrupt database can only
//! yield `None`, never a panic or out-of-bounds access.
//!
//! Wire layout (see <https://maxmind.github.io/MaxMind-DB/>):
//! * file = search tree (nodes of two `record_size`-bit records) + 16-byte
//!   separator + data section + metadata;
//! * metadata is a data-section-format map starting at the **last** occurrence
//!   of `\xab\xcd\xefMaxMind.com`.

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
/// Maximum pointer-indirection depth while decoding. A hostile database can
/// wire pointers in a cycle; without a bound this would recurse forever.
const MAX_POINTER_DEPTH: usize = 32;
/// Maximum entries decoded into a map or array. `read_size` can claim up to
/// ~16.8M entries; capping here bounds the pre-allocation below.
const MAX_CONTAINER_ENTRIES: usize = 65_536;

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
        // Metadata sits at the *last* occurrence of the magic marker.
        let meta_start = data
            .windows(MAGIC.len())
            .rposition(|w| w == MAGIC)
            .ok_or_else(|| "MMDB: metadata marker not found".to_string())?;

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

        // The metadata is a data-section-format map; pointers inside it are
        // relative to the metadata start.
        let (value, _) = reader
            .read_value(meta_start, meta_start, 0)
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
        let search_tree_size = node_count.checked_mul(node_byte_size).ok_or("MMDB: tree overflow")?;

        // Validate the advertised tree fits inside the file before the data.
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
                (u32::from(b0) << 24)
                    | (u32::from(b1) << 16)
                    | (u32::from(b2) << 8)
                    | u32::from(b3)
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
                if record < self.meta.node_count {
                    node = record;
                } else if record > self.meta.node_count {
                    // `$offset_in_file = record - node_count + tree_size`.
                    let off = (record - self.meta.node_count) as usize
                        + self.meta.search_tree_size as usize;
                    return Some(off);
                } else {
                    return None; // record == node_count: not in database
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
                    // IPv4 lives in `::/96`: walk 96 zero bits then the 32
                    // IPv4 bits (the MaxMind convention, matching libmaxminddb).
                    let mut bits = [0u8; 16];
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
    /// start for records, or the metadata start for the metadata map. `depth`
    /// bounds pointer indirection to stop cycles in a hostile database.
    fn read_value(
        &self,
        offset: usize,
        ptr_base: usize,
        depth: usize,
    ) -> Option<(DataValue, usize)> {
        let control = *self.data.get(offset)?;
        let type_bits = control >> 5;
        let size_bits = control & 0x1F;
        let mut pos = offset + 1;

        let ty = if type_bits == 0 {
            // Extended type: next byte holds `type - 7`.
            let ext = *self.data.get(pos)?;
            pos += 1;
            ext + 7
        } else {
            type_bits
        };

        // Type 1 (pointer) encodes its size differently (001SSVVV).
        if ty == 1 {
            let ptr_size = size_bits >> 3;
            let vvv = u32::from(size_bits & 0x07);
            let value = match ptr_size {
                0 => {
                    let b = u32::from(*self.data.get(pos)?);
                    pos += 1;
                    (vvv << 8) | b
                }
                1 => {
                    let hi = u32::from(*self.data.get(pos)?);
                    let lo = u32::from(*self.data.get(pos + 1)?);
                    pos += 2;
                    2048 + (vvv << 16) + (hi << 8) + lo
                }
                2 => {
                    let a = u32::from(*self.data.get(pos)?);
                    let b = u32::from(*self.data.get(pos + 1)?);
                    let c = u32::from(*self.data.get(pos + 2)?);
                    pos += 3;
                    526_336 + (vvv << 24) + (a << 16) + (b << 8) + c
                }
                3 => {
                    let a = u32::from(*self.data.get(pos)?);
                    let b = u32::from(*self.data.get(pos + 1)?);
                    let c = u32::from(*self.data.get(pos + 2)?);
                    let d = u32::from(*self.data.get(pos + 3)?);
                    pos += 4;
                    (a << 24) + (b << 16) + (c << 8) + d
                }
                _ => return None,
            };
            // Bound pointer indirection: a cycle must not recurse forever.
            if depth >= MAX_POINTER_DEPTH {
                return None;
            }
            let target = ptr_base.checked_add(value as usize)?;
            let (resolved, _) = self.read_value(target, ptr_base, depth + 1)?;
            return Some((resolved, pos));
        }

        let size = self.read_size(size_bits, &mut pos)?;
        let payload = self.data.get(pos..pos + size)?;

        let value = match ty {
            2 => {
                let s = std::str::from_utf8(payload).ok()?;
                DataValue::Str(s.to_string())
            }
            3 => DataValue::F64(f64::from_be_bytes(payload.try_into().ok()?)),
            4 => DataValue::Bytes(payload.to_vec()),
            5 => DataValue::U16(u16::from_be_bytes(payload.try_into().ok()?)),
            6 => DataValue::U32(u32::from_be_bytes(payload.try_into().ok()?)),
            7 => {
                // Map: `size` = number of key/value pairs.
                if size > MAX_CONTAINER_ENTRIES {
                    return None;
                }
                let mut entries = Vec::with_capacity(size);
                let mut p = pos;
                for _ in 0..size {
                    let (key, np) = self.read_value(p, ptr_base, depth)?;
                    let DataValue::Str(key) = key else {
                        return None;
                    };
                    p = np;
                    let (val, np) = self.read_value(p, ptr_base, depth)?;
                    p = np;
                    entries.push((key, val));
                }
                pos = p;
                DataValue::Map(entries)
            }
            8 => {
                // Signed 32-bit integer; not needed for country lookups.
                pos += size;
                DataValue::Null
            }
            9 => DataValue::U64(u64::from_be_bytes(payload.try_into().ok()?)),
            11 => {
                // Array: `size` = number of elements.
                if size > MAX_CONTAINER_ENTRIES {
                    return None;
                }
                let mut items = Vec::with_capacity(size);
                let mut p = pos;
                for _ in 0..size {
                    let (val, np) = self.read_value(p, ptr_base, depth)?;
                    p = np;
                    items.push(val);
                }
                pos = p;
                DataValue::Array(items)
            }
            14 => DataValue::Bool(size == 1),
            _ => {
                // Skip unknown types (double/bytes/u128/float are unused for
                // country lookups): advance past the payload.
                pos += size;
                DataValue::Null
            }
        };
        Some((value, pos))
    }

    /// Resolve the ISO 3166-1 alpha-2 country code for an IP, if present.
    ///
    /// Returns the two raw uppercase bytes — no heap allocation, no UTF-8
    /// round-trip. Country codes are exactly two ASCII letters by spec, so a
    /// packed `[u8; 2]` is the tightest lossless representation.
    pub fn lookup_country(&self, ip: IpAddr) -> Option<[u8; 2]> {
        let data_off = self.lookup(ip)?;
        let (value, _) = self.read_value(data_off, self.data_start, 0)?;
        let DataValue::Map(entries) = value else {
            return None;
        };
        let country = entries.into_iter().find(|(k, _)| k == "country")?.1;
        let DataValue::Map(country_entries) = country else {
            return None;
        };
        let iso = country_entries.into_iter().find(|(k, _)| k == "iso_code")?.1;
        match iso {
            DataValue::Str(code) if code.len() == 2 => {
                let b = code.as_bytes();
                if b[0].is_ascii_alphabetic() && b[1].is_ascii_alphabetic() {
                    Some([b[0].to_ascii_uppercase(), b[1].to_ascii_uppercase()])
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}
