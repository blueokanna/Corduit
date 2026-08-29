//! QPACK (RFC 9204) header-block codec + the HPACK static Huffman code
//! (RFC 7541 Appendix B).
//!
//! Hysteria 2 authenticates over HTTP/3 (`POST /auth`), which means the
//! client must *encode* a QPACK header block for the request and *decode*
//! the QPACK header block of the response. This module provides exactly the
//! surface that needs:
//!
//! * `encode_literal_fields` — emit a QPACK block of never-indexed literal
//!   field lines (no dynamic table, no Huffman on encode; valid QPACK).
//! * `decode_block` — parse a QPACK block: 2-octet prefix, indexed /
//!   literal-with-name-reference / literal-with-literal-name field lines,
//!   with full HPACK Huffman decoding of names and values.
//!
//! Only the *static* table is used. The peer's dynamic table is not
//! maintained: if a block carries a non-zero `Required Insert Count` (or
//! references a dynamic-table entry) it is rejected with an explicit error
//! rather than silently mis-decoded. For a single-shot auth exchange that is
//! always the case in practice, and the failure mode is loud, not wrong.

use std::sync::OnceLock;

/// QPACK / HPACK decode error.
#[derive(Debug)]
pub enum QpackError {
    /// Input ended in the middle of an integer / string.
    Truncated,
    /// Integer or string exceeded the implementation limit.
    Overflow,
    /// The block references the peer's dynamic table, which this client
    /// does not maintain.
    DynamicTableUnsupported,
    /// Unknown static-table index.
    BadIndex(u64),
    /// Invalid HPACK Huffman encoding.
    InvalidHuffman,
    /// Malformed field line prefix or string.
    Protocol(&'static str),
}

impl core::fmt::Display for QpackError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            QpackError::Truncated => write!(f, "truncated QPACK data"),
            QpackError::Overflow => write!(f, "QPACK integer/string overflow"),
            QpackError::DynamicTableUnsupported => {
                write!(f, "QPACK dynamic table is not supported")
            }
            QpackError::BadIndex(i) => write!(f, "QPACK static table index {i} out of range"),
            QpackError::InvalidHuffman => write!(f, "invalid HPACK Huffman encoding"),
            QpackError::Protocol(m) => write!(f, "QPACK protocol error: {m}"),
        }
    }
}

impl core::error::Error for QpackError {}

// ---------------------------------------------------------------------------
// HPACK static table (RFC 7541 Appendix A)
// ---------------------------------------------------------------------------

/// The 61 static-table entries, 1-based index. `(name, value)`.
const STATIC_TABLE: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

fn static_entry(index: u64) -> Result<(&'static str, &'static str), QpackError> {
    if index == 0 || index as usize > STATIC_TABLE.len() {
        return Err(QpackError::BadIndex(index));
    }
    Ok(STATIC_TABLE[index as usize - 1])
}

// ---------------------------------------------------------------------------
// HPACK Huffman code (RFC 7541 Appendix B)
//
// Each entry is `(symbol, code, len)` where `code` is the value aligned to
// the LSB as printed in the RFC (the transmitted bit order is the MSB-first
// reversal over `len` bits).
// ---------------------------------------------------------------------------

const HUFFMAN_CODES: [(u16, u32, u8); 257] = [
    (0, 0x1ff8, 13),
    (1, 0x7fffd8, 23),
    (2, 0xfffffe2, 28),
    (3, 0xfffffe3, 28),
    (4, 0xfffffe4, 28),
    (5, 0xfffffe5, 28),
    (6, 0xfffffe6, 28),
    (7, 0xfffffe7, 28),
    (8, 0xfffffe8, 28),
    (9, 0xffffea, 24),
    (10, 0x3ffffffc, 30),
    (11, 0xfffffe9, 28),
    (12, 0xfffffea, 28),
    (13, 0x3ffffffd, 30),
    (14, 0xfffffeb, 28),
    (15, 0xfffffec, 28),
    (16, 0xfffffed, 28),
    (17, 0xfffffee, 28),
    (18, 0xfffffef, 28),
    (19, 0xfffffff0, 28),
    (20, 0xfffffff1, 28),
    (21, 0xfffffff2, 28),
    (22, 0x3ffffffe, 30),
    (23, 0xfffffff3, 28),
    (24, 0xfffffff4, 28),
    (25, 0xfffffff5, 28),
    (26, 0xfffffff6, 28),
    (27, 0xfffffff7, 28),
    (28, 0xfffffff8, 28),
    (29, 0xfffffff9, 28),
    (30, 0xfffffffa, 28),
    (31, 0xfffffffb, 28),
    (32, 0x14, 6),
    (33, 0x3f8, 10),
    (34, 0x3f9, 10),
    (35, 0xffa, 12),
    (36, 0x1ff9, 13),
    (37, 0x15, 6),
    (38, 0xf8, 8),
    (39, 0x7fa, 11),
    (40, 0x3fa, 10),
    (41, 0x3fb, 10),
    (42, 0xf9, 8),
    (43, 0x7fb, 11),
    (44, 0xfa, 8),
    (45, 0x16, 6),
    (46, 0x17, 6),
    (47, 0x18, 6),
    (48, 0x0, 5),
    (49, 0x1, 5),
    (50, 0x2, 5),
    (51, 0x19, 6),
    (52, 0x1a, 6),
    (53, 0x1b, 6),
    (54, 0x1c, 6),
    (55, 0x1d, 6),
    (56, 0x1e, 6),
    (57, 0x1f, 6),
    (58, 0x5c, 7),
    (59, 0xfb, 8),
    (60, 0x7ffc, 15),
    (61, 0x20, 6),
    (62, 0xffb, 12),
    (63, 0x3fc, 10),
    (64, 0x1ffa, 13),
    (65, 0x21, 6),
    (66, 0x5d, 7),
    (67, 0x5e, 7),
    (68, 0x5f, 7),
    (69, 0x60, 7),
    (70, 0x61, 7),
    (71, 0x62, 7),
    (72, 0x63, 7),
    (73, 0x64, 7),
    (74, 0x65, 7),
    (75, 0x66, 7),
    (76, 0x67, 7),
    (77, 0x68, 7),
    (78, 0x69, 7),
    (79, 0x6a, 7),
    (80, 0x6b, 7),
    (81, 0x6c, 7),
    (82, 0x6d, 7),
    (83, 0x6e, 7),
    (84, 0x6f, 7),
    (85, 0x70, 7),
    (86, 0x71, 7),
    (87, 0x72, 7),
    (88, 0xfc, 8),
    (89, 0x73, 7),
    (90, 0xfd, 8),
    (91, 0x1ffb, 13),
    (92, 0x7fff0, 19),
    (93, 0x1ffc, 13),
    (94, 0x3ffc, 14),
    (95, 0x22, 6),
    (96, 0x7ffd, 15),
    (97, 0x3, 5),
    (98, 0x23, 6),
    (99, 0x4, 5),
    (100, 0x24, 6),
    (101, 0x5, 5),
    (102, 0x25, 6),
    (103, 0x26, 6),
    (104, 0x27, 6),
    (105, 0x6, 5),
    (106, 0x74, 7),
    (107, 0x75, 7),
    (108, 0x28, 6),
    (109, 0x29, 6),
    (110, 0x2a, 6),
    (111, 0x7, 5),
    (112, 0x2b, 6),
    (113, 0x76, 7),
    (114, 0x2c, 6),
    (115, 0x8, 5),
    (116, 0x9, 5),
    (117, 0x2d, 6),
    (118, 0x77, 7),
    (119, 0x78, 7),
    (120, 0x79, 7),
    (121, 0x7a, 7),
    (122, 0x7b, 7),
    (123, 0x7ffe, 15),
    (124, 0x7fc, 11),
    (125, 0x3ffd, 14),
    (126, 0x1ffd, 13),
    (127, 0xffffffc, 28),
    (128, 0xfffe6, 20),
    (129, 0x3fffd2, 22),
    (130, 0xfffe7, 20),
    (131, 0xfffe8, 20),
    (132, 0x3fffd3, 22),
    (133, 0x3fffd4, 22),
    (134, 0x3fffd5, 22),
    (135, 0x7fffd9, 23),
    (136, 0x3fffd6, 22),
    (137, 0x7fffda, 23),
    (138, 0x7fffdb, 23),
    (139, 0x7fffdc, 23),
    (140, 0x7fffdd, 23),
    (141, 0x7fffde, 23),
    (142, 0xffffeb, 24),
    (143, 0x7fffdf, 23),
    (144, 0xffffec, 24),
    (145, 0xffffed, 24),
    (146, 0x3fffd7, 22),
    (147, 0x7fffe0, 23),
    (148, 0xfffffee, 24),
    (149, 0x7fffe1, 23),
    (150, 0x7fffe2, 23),
    (151, 0x7fffe3, 23),
    (152, 0x7fffe4, 23),
    (153, 0x1fffdc, 21),
    (154, 0x3fffd8, 22),
    (155, 0x7fffe5, 23),
    (156, 0x3fffd9, 22),
    (157, 0x7fffe6, 23),
    (158, 0x7fffe7, 23),
    (159, 0xffffef, 24),
    (160, 0x3fffda, 22),
    (161, 0x1fffdd, 21),
    (162, 0xfffe9, 20),
    (163, 0x3fffdb, 22),
    (164, 0x3fffdc, 22),
    (165, 0x7fffe8, 23),
    (166, 0x7fffe9, 23),
    (167, 0x1fffde, 21),
    (168, 0x7fffea, 23),
    (169, 0x3fffdd, 22),
    (170, 0x3fffde, 22),
    (171, 0xfffff0, 24),
    (172, 0x1fffdf, 21),
    (173, 0x3fffdf, 22),
    (174, 0x7fffeb, 23),
    (175, 0x7fffec, 23),
    (176, 0x1fffe0, 21),
    (177, 0x1fffe1, 21),
    (178, 0x3fffe0, 22),
    (179, 0x1fffe2, 21),
    (180, 0x7fffed, 23),
    (181, 0x3fffe1, 22),
    (182, 0x7fffee, 23),
    (183, 0x7fffef, 23),
    (184, 0xfffea, 20),
    (185, 0x3fffe2, 22),
    (186, 0x3fffe3, 22),
    (187, 0x3fffe4, 22),
    (188, 0x7ffff0, 23),
    (189, 0x3fffe5, 22),
    (190, 0x3fffe6, 22),
    (191, 0x7ffff1, 23),
    (192, 0x3ffffe0, 26),
    (193, 0x3ffffe1, 26),
    (194, 0xfffeb, 20),
    (195, 0x7fff1, 19),
    (196, 0x3fffe7, 22),
    (197, 0x7ffff2, 23),
    (198, 0x3fffe8, 22),
    (199, 0x1ffffec, 25),
    (200, 0x3ffffe2, 26),
    (201, 0x3ffffe3, 26),
    (202, 0x3ffffe4, 26),
    (203, 0x7ffffde, 27),
    (204, 0x7ffffdf, 27),
    (205, 0x3ffffe5, 26),
    (206, 0xfffff1, 24),
    (207, 0x1ffffed, 25),
    (208, 0x7fff2, 19),
    (209, 0x1fffe3, 21),
    (210, 0x3ffffe6, 26),
    (211, 0x7ffffe0, 27),
    (212, 0x7ffffe1, 27),
    (213, 0x3ffffe7, 26),
    (214, 0x7ffffe2, 27),
    (215, 0xfffff2, 24),
    (216, 0x1fffe4, 21),
    (217, 0x1fffe5, 21),
    (218, 0x3ffffe8, 26),
    (219, 0x3ffffe9, 26),
    (220, 0xfffffffd, 28),
    (221, 0x7ffffe3, 27),
    (222, 0x7ffffe4, 27),
    (223, 0x7ffffe5, 27),
    (224, 0xfffec, 20),
    (225, 0xfffff3, 24),
    (226, 0xfffed, 20),
    (227, 0x1fffe6, 21),
    (228, 0x3fffe9, 22),
    (229, 0x1fffe7, 21),
    (230, 0x1fffe8, 21),
    (231, 0x7ffff3, 23),
    (232, 0x3fffea, 22),
    (233, 0x3fffeb, 22),
    (234, 0x1ffffee, 25),
    (235, 0x1ffffef, 25),
    (236, 0xfffff4, 24),
    (237, 0xfffff5, 24),
    (238, 0x3ffffea, 26),
    (239, 0x7ffff4, 23),
    (240, 0x3ffffeb, 26),
    (241, 0x7ffffe6, 27),
    (242, 0x3ffffec, 26),
    (243, 0x3ffffed, 26),
    (244, 0x7ffffe7, 27),
    (245, 0x7ffffe8, 27),
    (246, 0x7ffffe9, 27),
    (247, 0x7ffffea, 27),
    (248, 0x7ffffeb, 27),
    (249, 0xfffffffe, 28),
    (250, 0x7ffffec, 27),
    (251, 0x7ffffed, 27),
    (252, 0x7ffffee, 27),
    (253, 0x7ffffef, 27),
    (254, 0x7fffff0, 27),
    (255, 0x3ffffee, 26),
    // EOS (reserved, never decodes to data).
    (256, 0x3fffffff, 30),
];

/// Huffman decode-tree node. `symbol >= 0` marks a leaf; `child0/child1`
/// are node indices (`-1` = absent).
struct HuffNode {
    child0: i32,
    child1: i32,
    symbol: i32,
}

static HUFFMAN_TREE: OnceLock<Vec<HuffNode>> = OnceLock::new();

fn huffman_tree() -> &'static [HuffNode] {
    HUFFMAN_TREE.get_or_init(|| {
        let mut nodes = vec![HuffNode {
            child0: -1,
            child1: -1,
            symbol: -1,
        }];
        for &(symbol, code, len) in HUFFMAN_CODES.iter() {
            let mut node = 0usize;
            // Transmitted bits are MSB-first; `code` is LSB-aligned, so bit
            // `j` of the transmitted sequence is bit `(len - 1 - j)` of code.
            for j in 0..len {
                let bit = ((code >> (len - 1 - j)) & 1) as usize;
                let existing = if bit == 0 {
                    nodes[node].child0
                } else {
                    nodes[node].child1
                };
                node = if existing >= 0 {
                    existing as usize
                } else {
                    let new_idx = nodes.len() as i32;
                    nodes.push(HuffNode {
                        child0: -1,
                        child1: -1,
                        symbol: -1,
                    });
                    if bit == 0 {
                        nodes[node].child0 = new_idx;
                    } else {
                        nodes[node].child1 = new_idx;
                    }
                    new_idx as usize
                };
            }
            nodes[node].symbol = symbol as i32;
        }
        nodes
    })
}

/// Decode an HPACK Huffman string (RFC 7541 §5.2 + Appendix B).
fn huffman_decode(data: &[u8]) -> Result<Vec<u8>, QpackError> {
    let tree = huffman_tree();
    let mut out = Vec::with_capacity(data.len());
    let total_bits = data.len().saturating_mul(8);
    let mut consumed = 0usize;
    let mut node = 0usize;
    // Depth since the last decoded symbol — used for the ≤7-bit padding rule.
    let mut depth = 0usize;
    let mut partial_all_ones = true;

    while consumed < total_bits {
        let byte = data[consumed / 8];
        let bit = (byte >> (7 - (consumed % 8))) & 1;
        consumed += 1;
        depth += 1;
        partial_all_ones &= bit == 1;

        let next = if bit == 0 {
            tree[node].child0
        } else {
            tree[node].child1
        };
        if next < 0 {
            // No branch for this bit: the only valid all-ones fallback is
            // EOS padding at the very end, handled below.
            return Err(QpackError::InvalidHuffman);
        }
        node = next as usize;
        let sym = tree[node].symbol;
        if sym >= 0 {
            if sym == 256 {
                // EOS must never appear inside the string.
                return Err(QpackError::InvalidHuffman);
            }
            out.push(sym as u8);
            node = 0;
            depth = 0;
            partial_all_ones = true;
        }
    }

    if node != 0 {
        // Trailing incomplete code: padding. Must be ≤ 7 bits and be a
        // prefix of EOS (all ones).
        if depth > 7 || !partial_all_ones {
            return Err(QpackError::InvalidHuffman);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Integers and string literals
// ---------------------------------------------------------------------------

/// Read an integer with an `N`-bit prefix (RFC 7541 §5.1).
fn read_int(data: &[u8], pos: &mut usize, prefix: u32) -> Result<u64, QpackError> {
    if *pos >= data.len() {
        return Err(QpackError::Truncated);
    }
    let max = (1u64 << prefix) - 1;
    let first = data[*pos];
    let mut value = (first as u64) & max;
    if value < max {
        *pos += 1;
        return Ok(value);
    }
    let mut shift = 0u32;
    let mut p = *pos + 1;
    loop {
        if p >= data.len() {
            return Err(QpackError::Truncated);
        }
        let b = data[p];
        value = value
            .checked_add(
                (b as u64 & 0x7f)
                    .checked_shl(shift)
                    .ok_or(QpackError::Overflow)?,
            )
            .ok_or(QpackError::Overflow)?;
        shift += 7;
        p += 1;
        if b & 0x80 == 0 {
            break;
        }
        if shift >= 64 {
            return Err(QpackError::Overflow);
        }
    }
    *pos = p;
    Ok(value)
}

/// Append an integer with an `N`-bit prefix onto `base` (the field-line
/// pattern already occupying the high bits of the first octet).
fn write_int(out: &mut Vec<u8>, base: u8, prefix: u32, value: u64) {
    let max = (1u64 << prefix) - 1;
    if value < max {
        out.push(base | value as u8);
        return;
    }
    out.push(base | max as u8);
    let mut v = value - max;
    while v >= 128 {
        out.push((v & 0x7f) as u8 | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Read a string literal (RFC 7541 §5.2): `H` flag + 7-bit length.
fn read_string(data: &[u8], pos: &mut usize) -> Result<Vec<u8>, QpackError> {
    if *pos >= data.len() {
        return Err(QpackError::Truncated);
    }
    let h = data[*pos] & 0x80 != 0;
    let len = read_int(data, pos, 7)? as usize;
    if len > data.len().saturating_sub(*pos) {
        return Err(QpackError::Truncated);
    }
    let raw = &data[*pos..*pos + len];
    *pos += len;
    if h {
        huffman_decode(raw)
    } else {
        Ok(raw.to_vec())
    }
}

/// Append a plain (H=0) string literal.
fn write_string(out: &mut Vec<u8>, bytes: &[u8]) {
    write_int(out, 0x00, 7, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/// Encode a QPACK header block of never-indexed literal field lines.
///
/// This is a valid QPACK block with an empty dynamic table (Required Insert
/// Count = 0, Delta Base = 0) — exactly what an HTTP/3 request needs, and
/// deliberately avoids Huffman so the encoder stays dependency-free.
pub fn encode_literal_fields(fields: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    // QPACK prefix: Required Insert Count (8-bit) = 0, Delta Base (7-bit) = 0.
    out.push(0x00);
    out.push(0x00);
    for &(name, value) in fields {
        // Literal field line with literal name, never indexed:
        // `001 N(=1)` + 4-bit name length, then name, then value string.
        write_int(&mut out, 0x30, 4, name.len() as u64);
        out.extend_from_slice(name);
        write_string(&mut out, value);
    }
    out
}

/// A decoded header field: `(name, value)`.
pub type HeaderField = (Vec<u8>, Vec<u8>);

/// Decode a QPACK header block into `(name, value)` pairs.
///
/// Only the static table is consulted; a non-zero Required Insert Count or a
/// dynamic-table reference is rejected with [`QpackError::DynamicTableUnsupported`].
pub fn decode_block(block: &[u8]) -> Result<Vec<HeaderField>, QpackError> {
    let mut pos = 0usize;

    // QPACK prefix (§4.5.1): Required Insert Count (8-bit) + Delta Base
    // (7-bit, sign bit in bit 7 of the first octet).
    let required_insert_count = read_int(block, &mut pos, 8)?;
    if required_insert_count != 0 {
        return Err(QpackError::DynamicTableUnsupported);
    }
    // Delta Base is irrelevant when the required insert count is zero, but it
    // is still part of the block and must be consumed.
    let _delta_base = read_int(block, &mut pos, 7)?;

    let mut fields = Vec::new();
    while pos < block.len() {
        let b = block[pos];
        if b & 0x80 != 0 {
            // Indexed field line: `1 S Index(6+)`.
            let s = b & 0x40 != 0;
            let index = read_int(block, &mut pos, 6)?;
            if !s {
                return Err(QpackError::DynamicTableUnsupported);
            }
            let (name, value) = static_entry(index)?;
            fields.push((name.as_bytes().to_vec(), value.as_bytes().to_vec()));
        } else if b & 0x40 != 0 {
            // Literal field line with name reference: `01 N S Name Index(4+)`.
            let s = b & 0x10 != 0;
            let index = read_int(block, &mut pos, 4)?;
            if !s {
                return Err(QpackError::DynamicTableUnsupported);
            }
            let (name, _) = static_entry(index)?;
            let value = read_string(block, &mut pos)?;
            fields.push((name.as_bytes().to_vec(), value));
        } else if b & 0x20 != 0 {
            // Literal field line with literal name: `001 N Name Length(4+)`.
            let name = read_string_raw4(block, &mut pos)?;
            let value = read_string(block, &mut pos)?;
            fields.push((name, value));
        } else {
            return Err(QpackError::Protocol("invalid field line prefix"));
        }
    }
    Ok(fields)
}

/// Read the name of a `001 N Name Length(4+)` field line. The name is a
/// string literal whose *first* octet already holds the `001N` pattern, so
/// the length uses a 4-bit prefix instead of the usual 7-bit one.
fn read_string_raw4(data: &[u8], pos: &mut usize) -> Result<Vec<u8>, QpackError> {
    if *pos >= data.len() {
        return Err(QpackError::Truncated);
    }
    let h = data[*pos] & 0x80 != 0;
    let len = read_int(data, pos, 4)? as usize;
    if len > data.len().saturating_sub(*pos) {
        return Err(QpackError::Truncated);
    }
    let raw = &data[*pos..*pos + len];
    *pos += len;
    if h {
        huffman_decode(raw)
    } else {
        Ok(raw.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7541 Appendix C vectors (space-separated hex groups -> bytes).
    fn hd_bytes(hex: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for token in hex.split_whitespace() {
            let hi = u8::from_str_radix(&token[..2], 16).unwrap();
            out.push(hi);
            if token.len() > 2 {
                let lo = u8::from_str_radix(&token[2..], 16).unwrap();
                out.push(lo);
            }
        }
        out
    }

    #[test]
    fn huffman_rfc_c4_vectors() {
        // C.4.1 :authority: www.example.com
        assert_eq!(
            huffman_decode(&hd_bytes("f1e3 c2e5 f23a 6ba0 ab90 f4ff")).unwrap(),
            b"www.example.com"
        );
        // C.4.2 cache-control: no-cache
        assert_eq!(
            huffman_decode(&hd_bytes("a8eb 1064 9cbf")).unwrap(),
            b"no-cache"
        );
        // C.6.1 :status: 302, cache-control: private
        assert_eq!(huffman_decode(&hd_bytes("6402")).unwrap(), b"302");
        assert_eq!(
            huffman_decode(&hd_bytes("aec3 771a 4b")).unwrap(),
            b"private"
        );
        // C.6.3 content-encoding: gzip
        assert_eq!(huffman_decode(&hd_bytes("9bd9 ab")).unwrap(), b"gzip");
    }

    #[test]
    fn huffman_roundtrip_covers_alphabet() {
        let alphabet: Vec<u8> = (0u8..=255).collect();
        // Encode with a straight-forward bit writer using the same table,
        // then decode and compare.
        let mut bits: Vec<u8> = Vec::new();
        for &sym in &alphabet {
            let (_, code, len) = HUFFMAN_CODES[sym as usize];
            for j in 0..len {
                bits.push(((code >> (len - 1 - j)) & 1) as u8);
            }
        }
        // Pad with EOS prefix (ones).
        while !bits.len().is_multiple_of(8) {
            bits.push(1);
        }
        let mut data = Vec::with_capacity(bits.len() / 8);
        for chunk in bits.chunks(8) {
            let mut byte = 0u8;
            for (i, &b) in chunk.iter().enumerate() {
                byte |= b << (7 - i);
            }
            data.push(byte);
        }
        assert_eq!(huffman_decode(&data).unwrap(), alphabet);
    }

    #[test]
    fn huffman_rejects_bad_padding() {
        // "2" is code 00010 (5 bits). Followed by a 1-bit then 0s: the 0 in
        // the padding violates the all-ones EOS-prefix rule.
        // 00010 1 0 00000 -> byte 0b00010100 = 0x14
        assert!(huffman_decode(&[0x14]).is_err());
        // >7 bits of padding: symbol 0 is 13 bits of 11111 1111 1000, then 8
        // more padding bits -> 21 bits total consumed as a partial code.
        // 11111 1111 1000 (0) + 1111 1111 -> error (padding > 7 bits).
        let data = hd_bytes("ff ff"); // first 13 bits = 0x1ff8
        assert!(huffman_decode(&data).is_err());
    }

    #[test]
    fn integer_read_c1_vectors() {
        // C.1.1: 10 with 5-bit prefix.
        let mut pos = 0;
        assert_eq!(read_int(&[0x0a], &mut pos, 5).unwrap(), 10);
        assert_eq!(pos, 1);
        // C.1.2: 1337 with 5-bit prefix: 1f 9a 0a.
        let mut pos = 0;
        assert_eq!(read_int(&[0x1f, 0x9a, 0x0a], &mut pos, 5).unwrap(), 1337);
        assert_eq!(pos, 3);
        // C.1.3: 42 with 8-bit prefix.
        let mut pos = 0;
        assert_eq!(read_int(&[0x2a], &mut pos, 8).unwrap(), 42);
        assert_eq!(pos, 1);
    }

    #[test]
    fn integer_roundtrip() {
        for prefix in [4u32, 5, 6, 7, 8] {
            for value in [
                0u64,
                1,
                14,
                15,
                16,
                126,
                127,
                128,
                255,
                1024,
                u32::MAX as u64,
            ] {
                let mut out = Vec::new();
                write_int(&mut out, 0x00, prefix, value);
                let mut pos = 0;
                let decoded = read_int(&out, &mut pos, prefix).unwrap();
                assert_eq!(decoded, value, "prefix {prefix} value {value}");
                assert_eq!(pos, out.len());
            }
        }
    }

    #[test]
    fn literal_fields_roundtrip() {
        let fields: Vec<(&[u8], &[u8])> = vec![
            (b":method", b"POST"),
            (b":scheme", b"https"),
            (b":authority", b"hysteria"),
            (b":path", b"/auth"),
            (b"hysteria-auth", b"sekret"),
            (b"hysteria-cc-rx", b"0"),
            (b"hysteria-padding", b"0123456789abcdef"),
        ];
        let block = encode_literal_fields(&fields);
        let decoded = decode_block(&block).unwrap();
        assert_eq!(decoded.len(), fields.len());
        for ((n, v), (dn, dv)) in fields.iter().zip(decoded.iter()) {
            assert_eq!(n, &dn.as_slice());
            assert_eq!(v, &dv.as_slice());
        }
    }

    #[test]
    fn decode_handles_static_indexed() {
        // QPACK prefix (0,0) then indexed field line `1 1` + 6-bit index 3
        // (:method: POST): first byte 0b11000011 = 0xC3.
        let block = [0x00, 0x00, 0xC3];
        let decoded = decode_block(&block).unwrap();
        assert_eq!(decoded, vec![(b":method".to_vec(), b"POST".to_vec())]);
    }

    #[test]
    fn decode_rejects_dynamic_references() {
        // Indexed field line with S=0 (dynamic): 0x80 | 1 = 0x81.
        let block = [0x00, 0x00, 0x81];
        assert!(matches!(
            decode_block(&block),
            Err(QpackError::DynamicTableUnsupported)
        ));
        // Non-zero Required Insert Count.
        let block = [0x01, 0x00];
        assert!(matches!(
            decode_block(&block),
            Err(QpackError::DynamicTableUnsupported)
        ));
    }
}
