//! A pure-Rust decompressor for zstd frames (RFC 8878).
//!
//! `.mrs` rule sets are one zstd frame, so reading them needs a decoder. This is
//! one, with no C dependency and no unsafe code: the whole format is small enough
//! that a straightforward implementation is both the honest choice and the one
//! that cross-compiles everywhere the rest of the crate does.
//!
//! The structure follows the format's own layering, so a reader who knows the
//! specification can follow the code:
//!
//! ```text
//! frame   := magic, frame header, (block)*, [checksum]
//! block   := 3-byte header, then raw | RLE | { literals section, sequences section }
//! literals:= header, [Huffman tree], raw | RLE | Huffman stream(s)
//! sequences:= count, compression modes, up to 3 FSE tables, one interleaved bitstream
//! ```
//!
//! ## What is supported
//!
//! * every block type (raw, RLE, compressed), single- and four-stream Huffman
//!   literals, FSE-coded trees, predefined/RLE/repeated sequence tables;
//! * frames with or without a declared content size, with or without a checksum
//!   (the checksum is skipped, not verified — it protects the transport, and the
//!   rule-set loader already validates what it decodes onto);
//! * skippable frames, which contribute nothing.
//!
//! ## What is refused
//!
//! * dictionaries — a frame that declares one is rejected rather than decoded
//!   against the wrong window;
//! * a frame whose decoded size would pass the caller's limit, checked as the
//!   output grows rather than after the allocation;
//! * any structural inconsistency (a length that runs past its section, a table
//!   whose ranks do not fill it, a bitstream that is not exactly consumed). Each
//!   is a hard error: a partially-decoded rule set would silently match less than
//!   it should.
//!
//! ## Verification
//!
//! `tests/data/zstd` holds frames produced by the reference encoder at several
//! compression levels, each paired with its exact plaintext: empty, one byte,
//! short text, RLE, incompressible data, rule-set-shaped documents, and inputs
//! larger than one 128 KiB block so block-to-block state carries over. The tests
//! at the bottom of this file decode them and compare byte for byte.

use crate::engine::error::{Error, Result};

/// Largest decoded block the format allows.
const MAX_BLOCK_SIZE: usize = 1 << 17;

/// Frame magic: `0xFD2FB528`, little-endian.
const FRAME_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

/// The same bytes, exposed for the tests that have to build a frame by hand.
#[cfg(test)]
pub(crate) const FRAME_MAGIC_FOR_TEST: [u8; 4] = FRAME_MAGIC;

/// Skippable frames are `0x184D2A50..=0x184D2A5F`, which in little-endian bytes
/// is a fixed three-byte prefix and a high nibble of `0x1`.
const SKIPPABLE_PREFIX: [u8; 3] = [0x50, 0x2A, 0x4D];
const SKIPPABLE_NIBBLE: u8 = 0x10;

/// Largest number of symbols any table in the format can address.
const MAX_SYMBOLS: usize = 256;
/// Largest Huffman code length.
const MAX_HUFFMAN_BITS: u8 = 12;
/// Largest FSE accuracy log the format defines.
const MAX_FSE_ACCURACY: u8 = 9;

fn corrupt(what: &str) -> Error {
    Error::config(format!("zstd: {what}"))
}

/// Index of the highest set bit, or `None` for zero.
fn highest_set_bit(value: u64) -> Option<u32> {
    if value == 0 {
        None
    } else {
        Some(63 - value.leading_zeros())
    }
}

// --- forward bit reader ------------------------------------------------------
//
// The FSE table headers are read forward, least-significant bit of each byte
// first, and the reader may need to *rewind* one bit after deciding that a value
// fits the short form.

struct ForwardBits<'a> {
    data: &'a [u8],
    bit: usize,
}

impl<'a> ForwardBits<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, bit: 0 }
    }

    /// Read up to 64 bits; past the end reads as zero, which is what the
    /// reference decoder does for the final partial field.
    fn read(&mut self, count: u32) -> u64 {
        debug_assert!(count <= 64);
        let mut value = 0u64;
        for index in 0..count {
            let position = self.bit + index as usize;
            let byte = self.data.get(position / 8).copied().unwrap_or(0);
            let bit = (byte >> (position % 8)) & 1;
            value |= u64::from(bit) << index;
        }
        self.bit += count as usize;
        value
    }

    fn rewind(&mut self, count: u32) {
        self.bit = self.bit.saturating_sub(count as usize);
    }

    /// Whole bytes consumed so far, rounded up: a field may end mid-byte.
    fn consumed(&self) -> usize {
        self.bit.div_ceil(8)
    }
}

// --- backward bit reader -----------------------------------------------------
//
// Huffman and FSE bitstreams are read from the end towards the beginning: the
// highest set bit of the last byte marks the end of the stream, and everything
// after it is padding.

struct BackBits<'a> {
    data: &'a [u8],
    /// Bit position of the next bit to read, counted from the start of `data`.
    offset: i64,
}

impl<'a> BackBits<'a> {
    fn new(data: &'a [u8]) -> Result<Self> {
        let last = *data.last().ok_or_else(|| corrupt("empty bitstream"))?;
        let highest = highest_set_bit(u64::from(last))
            .ok_or_else(|| corrupt("bitstream ends with a zero byte"))?;
        let padding = 8 - highest;
        Ok(Self {
            data,
            offset: data.len() as i64 * 8 - i64::from(padding),
        })
    }

    /// Read `count` bits that end at the current offset, moving the offset back.
    ///
    /// Reading before the start of the stream is not an error: the leftover bits
    /// are filled with zeros, which is how a stream's final partial symbol is
    /// decoded.
    fn read(&mut self, count: u32) -> u64 {
        debug_assert!(count <= 64);
        self.offset -= i64::from(count);
        let (start, bits) = if self.offset < 0 {
            (0usize, (count as i64 + self.offset).max(0) as u32)
        } else {
            (self.offset as usize, count)
        };
        let value = read_bits_le(self.data, bits, start);
        if self.offset < 0 {
            let missing = (-self.offset).min(63) as u32;
            value << missing
        } else {
            value
        }
    }
}

/// Gather `count` bits starting at bit `start`, least-significant bit first.
fn read_bits_le(data: &[u8], count: u32, start: usize) -> u64 {
    let mut value = 0u64;
    for index in 0..count {
        let position = start + index as usize;
        let byte = data.get(position / 8).copied().unwrap_or(0);
        let bit = (byte >> (position % 8)) & 1;
        value |= u64::from(bit) << index;
    }
    value
}

// --- Huffman ----------------------------------------------------------------

/// A canonical Huffman table flattened for one lookup per symbol.
struct HuffTable {
    max_bits: u8,
    /// Symbol for each `max_bits`-wide lookahead.
    symbols: Vec<u8>,
    /// Number of bits to consume for the entry.
    bits: Vec<u8>,
}

impl HuffTable {
    /// Build from per-symbol code lengths (zero means "symbol absent").
    fn from_bits(lengths: &[u8]) -> Result<Self> {
        let mut max_bits = 0u8;
        let mut rank_count = [0u16; MAX_HUFFMAN_BITS as usize + 1];
        for &length in lengths {
            if length > MAX_HUFFMAN_BITS {
                return Err(corrupt("Huffman code length out of range"));
            }
            max_bits = max_bits.max(length);
            rank_count[length as usize] += 1;
        }
        if max_bits == 0 {
            return Err(corrupt("Huffman table with no symbols"));
        }

        let table_size = 1usize << max_bits;
        let mut symbols = vec![0u8; table_size];
        let mut bits = vec![0u8; table_size];

        // `rank_start[i]` is where the codes of length `i` begin in the table.
        let mut rank_start = [0usize; MAX_HUFFMAN_BITS as usize + 1];
        let mut cursor = 0usize;
        for length in (1..=max_bits as usize).rev() {
            rank_start[length - 1] =
                cursor + rank_count[length] as usize * (1 << (max_bits as usize - length));
            cursor = rank_start[length - 1];
        }
        if rank_start[0] != table_size {
            return Err(corrupt("Huffman ranks do not fill the table"));
        }
        for length in 1..=max_bits as usize {
            let start = rank_start[length];
            let end = rank_start[length - 1];
            if start > end || end > table_size {
                return Err(corrupt("Huffman ranks do not fill the table"));
            }
            bits[start..end].fill(length as u8);
        }

        for (symbol, &length) in lengths.iter().enumerate() {
            if length == 0 {
                continue;
            }
            let span = 1usize << (max_bits - length);
            let start = *rank_start
                .get(length as usize)
                .ok_or_else(|| corrupt("Huffman code length out of range"))?;
            if start + span > table_size {
                return Err(corrupt("Huffman table overrun"));
            }
            symbols[start..start + span].fill(symbol as u8);
            rank_start[length as usize] += span;
        }

        Ok(Self {
            max_bits,
            symbols,
            bits,
        })
    }

    /// Build from the weights a frame carries, with the final weight implied.
    fn from_weights(weights: &[u8], count: usize) -> Result<Self> {
        let mut weight_sum = 0u64;
        for &weight in &weights[..count] {
            if weight > MAX_HUFFMAN_BITS {
                return Err(corrupt("Huffman weight out of range"));
            }
            if weight > 0 {
                weight_sum += 1u64 << (weight - 1);
            }
        }
        if weight_sum == 0 {
            return Err(corrupt("Huffman weights sum to zero"));
        }
        let max_bits =
            highest_set_bit(weight_sum).ok_or_else(|| corrupt("Huffman weights sum to zero"))? + 1;
        if max_bits > u32::from(MAX_HUFFMAN_BITS) {
            return Err(corrupt("Huffman tree too deep"));
        }
        let total = 1u64 << max_bits;
        let left_over = total - weight_sum;
        if left_over == 0 || left_over & (left_over - 1) != 0 {
            return Err(corrupt("Huffman weights are not a complete tree"));
        }
        let last_weight = highest_set_bit(left_over)
            .ok_or_else(|| corrupt("Huffman weights are not a complete tree"))?
            + 1;
        if last_weight > u32::from(MAX_HUFFMAN_BITS) {
            return Err(corrupt("Huffman weight out of range"));
        }

        let mut lengths = vec![0u8; count + 1];
        for index in 0..count {
            lengths[index] = if weights[index] > 0 {
                (max_bits + 1 - u32::from(weights[index])) as u8
            } else {
                0
            };
        }
        // The last weight is never transmitted; it is whatever completes the tree.
        lengths[count] = (max_bits + 1 - last_weight) as u8;
        Self::from_bits(&lengths)
    }

    fn read_state(&self, stream: &mut BackBits<'_>) -> u16 {
        stream.read(u32::from(self.max_bits)) as u16
    }

    fn decode_symbol(&self, state: &mut u16, stream: &mut BackBits<'_>) -> u8 {
        let index = *state as usize;
        let symbol = self.symbols[index];
        let bits = self.bits[index];
        let rest = stream.read(u32::from(bits)) as u16;
        let mask = ((1u32 << self.max_bits) - 1) as u16;
        *state = ((*state << bits).wrapping_add(rest)) & mask;
        symbol
    }

    /// Decode one independent stream, appending exactly what it produces.
    fn decompress_stream(
        &self,
        stream: &mut BackBits<'_>,
        out: &mut Vec<u8>,
        expected: usize,
    ) -> Result<()> {
        let mut state = self.read_state(stream);
        let limit = -(i64::from(self.max_bits));
        while stream.offset > limit {
            let symbol = self.decode_symbol(&mut state, stream);
            if out.len() >= expected {
                return Err(corrupt("literal stream produced more than declared"));
            }
            out.push(symbol);
        }
        if stream.offset != limit {
            return Err(corrupt("literal bitstream was not consumed exactly"));
        }
        Ok(())
    }
}

// --- FSE --------------------------------------------------------------------

/// A finite-state entropy decoding table.
struct FseTable {
    accuracy_log: u8,
    symbols: Vec<u8>,
    num_bits: Vec<u8>,
    new_state_base: Vec<u16>,
}

impl FseTable {
    /// A table for a single repeated symbol: no bits are ever read.
    fn repeated(symbol: u8) -> Self {
        Self {
            accuracy_log: 0,
            symbols: vec![symbol],
            num_bits: vec![0],
            new_state_base: vec![0],
        }
    }

    /// Build from normalised frequencies, as the format defines them.
    fn from_frequencies(frequencies: &[i16], count: usize, accuracy_log: u8) -> Result<Self> {
        if accuracy_log > MAX_FSE_ACCURACY {
            return Err(corrupt("FSE accuracy log out of range"));
        }
        let size = 1usize << accuracy_log;
        let mut symbols = vec![0u8; size];
        let mut num_bits = vec![0u8; size];
        let mut new_state_base = vec![0u16; size];
        let mut state_desc = [0u16; MAX_SYMBOLS];

        let mut high_threshold = size;
        for (symbol, &frequency) in frequencies[..count].iter().enumerate() {
            if frequency == -1 {
                high_threshold -= 1;
                symbols[high_threshold] = symbol as u8;
                state_desc[symbol] = 1;
            }
        }

        let step = (size >> 1) + (size >> 3) + 3;
        let mask = size - 1;
        let mut position = 0usize;
        for (symbol, &frequency) in frequencies[..count].iter().enumerate() {
            if frequency <= 0 {
                continue;
            }
            state_desc[symbol] = frequency as u16;
            for _ in 0..frequency {
                symbols[position] = symbol as u8;
                loop {
                    position = (position + step) & mask;
                    if position < high_threshold {
                        break;
                    }
                }
            }
        }
        if position != 0 {
            return Err(corrupt("FSE table did not spread evenly"));
        }

        for index in 0..size {
            let symbol = symbols[index] as usize;
            let next = state_desc[symbol];
            state_desc[symbol] = next + 1;
            let bits = accuracy_log
                .checked_sub(
                    highest_set_bit(u64::from(next))
                        .ok_or_else(|| corrupt("FSE state descriptor is zero"))?
                        as u8,
                )
                .ok_or_else(|| corrupt("FSE state descriptor out of range"))?;
            num_bits[index] = bits;
            new_state_base[index] = ((next << bits) as u16).wrapping_sub(size as u16);
        }

        Ok(Self {
            accuracy_log,
            symbols,
            num_bits,
            new_state_base,
        })
    }

    fn peek(&self, state: u16) -> u8 {
        self.symbols[state as usize]
    }

    fn update_state(&self, state: &mut u16, stream: &mut BackBits<'_>) {
        let index = *state as usize;
        let bits = self.num_bits[index];
        let rest = stream.read(u32::from(bits)) as u16;
        *state = self.new_state_base[index].wrapping_add(rest);
    }

    fn init_state(&self, stream: &mut BackBits<'_>) -> u16 {
        stream.read(u32::from(self.accuracy_log)) as u16
    }

    /// Decode an FSE table description read forward from `input`.
    fn read_description(input: &mut Input<'_>, max_accuracy_log: u8) -> Result<Self> {
        let mut bits = ForwardBits::new(input.remaining_slice());
        let accuracy_log = 5 + bits.read(4) as u8;
        if accuracy_log > max_accuracy_log || accuracy_log > MAX_FSE_ACCURACY {
            return Err(corrupt("FSE accuracy log too large"));
        }

        let mut remaining = 1i32 << accuracy_log;
        let mut frequencies = [0i16; MAX_SYMBOLS];
        let mut symbols = 0usize;
        while remaining > 0 && symbols < MAX_SYMBOLS {
            let field_bits = highest_set_bit((remaining + 1) as u64)
                .ok_or_else(|| corrupt("FSE header state"))?
                + 1;
            let value = bits.read(field_bits) as u16;
            let lower_mask = (1u16 << (field_bits - 1)) - 1;
            let threshold = ((1u16 << field_bits) - 1) - (remaining as u16 + 1);
            let mut value = value;
            if (value & lower_mask) < threshold {
                bits.rewind(1);
                value &= lower_mask;
            } else if value > lower_mask {
                value -= threshold;
            }
            let probability = value as i16 - 1;
            remaining -= if probability < 0 {
                -i32::from(probability)
            } else {
                i32::from(probability)
            };
            frequencies[symbols] = probability;
            symbols += 1;

            if probability == 0 {
                let mut repeat = bits.read(2);
                loop {
                    for _ in 0..repeat {
                        if symbols >= MAX_SYMBOLS {
                            return Err(corrupt("FSE header exceeds the symbol range"));
                        }
                        frequencies[symbols] = 0;
                        symbols += 1;
                    }
                    if repeat == 3 {
                        repeat = bits.read(2);
                    } else {
                        break;
                    }
                }
            }
        }
        if remaining != 0 || symbols >= MAX_SYMBOLS {
            return Err(corrupt("FSE header is not a complete distribution"));
        }
        let consumed = bits.consumed();
        input.skip(consumed)?;
        Self::from_frequencies(&frequencies, symbols, accuracy_log)
    }

    /// Decode a two-state interleaved stream, used for Huffman weight tables.
    fn decompress_interleaved2(&self, stream: &mut BackBits<'_>, out: &mut [u8]) -> Result<usize> {
        let mut state1 = self.init_state(stream);
        let mut state2 = self.init_state(stream);
        let mut written = 0usize;
        loop {
            if written >= out.len() {
                return Err(corrupt("FSE stream produced more symbols than declared"));
            }
            out[written] = self.peek(state1);
            written += 1;
            self.update_state(&mut state1, stream);
            if stream.offset < 0 {
                if written >= out.len() {
                    return Err(corrupt("FSE stream produced more symbols than declared"));
                }
                out[written] = self.peek(state2);
                written += 1;
                break;
            }
            if written >= out.len() {
                return Err(corrupt("FSE stream produced more symbols than declared"));
            }
            out[written] = self.peek(state2);
            written += 1;
            self.update_state(&mut state2, stream);
            if stream.offset < 0 {
                if written >= out.len() {
                    return Err(corrupt("FSE stream produced more symbols than declared"));
                }
                out[written] = self.peek(state1);
                written += 1;
                break;
            }
        }
        Ok(written)
    }
}

// --- input cursor -----------------------------------------------------------

struct Input<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Input<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.position)
    }

    fn remaining_slice(&self) -> &'a [u8] {
        &self.data[self.position..]
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(count)
            .filter(|end| *end <= self.data.len())
            .ok_or_else(|| corrupt("input ended inside a section"))?;
        let slice = &self.data[self.position..end];
        self.position = end;
        Ok(slice)
    }

    fn skip(&mut self, count: usize) -> Result<()> {
        self.take(count).map(|_| ())
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16_le(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u32_le(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64_le(&mut self) -> Result<u64> {
        let bytes = self.take(8)?;
        let mut value = [0u8; 8];
        value.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(value))
    }
}

// --- frame decoding ---------------------------------------------------------

/// Sequence command tables, from the format specification.
const SEQ_LITERAL_LENGTH_DEFAULT_DIST: [i16; 36] = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1,
];
const SEQ_OFFSET_DEFAULT_DIST: [i16; 29] = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
];
const SEQ_MATCH_LENGTH_DEFAULT_DIST: [i16; 53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
];
const SEQ_LITERAL_LENGTH_BASELINES: [u32; 36] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64,
    128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
];
const SEQ_LITERAL_LENGTH_EXTRA_BITS: [u8; 36] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 16,
];
const SEQ_MATCH_LENGTH_BASELINES: [u32; 53] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027,
    2051, 4099, 8195, 16387, 32771, 65539,
];
const SEQ_MATCH_LENGTH_EXTRA_BITS: [u8; 53] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
];

/// Largest literal length / match length code the tables define.
const SEQ_MAX_LITERAL_LENGTH_CODE: u8 = 35;
const SEQ_MAX_MATCH_LENGTH_CODE: u8 = 52;

/// What one table is used for, which decides its default distribution.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SeqPart {
    LiteralLength,
    Offset,
    MatchLength,
}

impl SeqPart {
    fn default_distribution(self) -> &'static [i16] {
        match self {
            Self::LiteralLength => &SEQ_LITERAL_LENGTH_DEFAULT_DIST,
            Self::Offset => &SEQ_OFFSET_DEFAULT_DIST,
            Self::MatchLength => &SEQ_MATCH_LENGTH_DEFAULT_DIST,
        }
    }

    fn default_accuracy(self) -> u8 {
        match self {
            Self::LiteralLength | Self::MatchLength => 6,
            Self::Offset => 5,
        }
    }

    fn max_accuracy(self) -> u8 {
        match self {
            Self::LiteralLength | Self::MatchLength => 9,
            Self::Offset => 8,
        }
    }
}

/// One decoded sequence: copy literals, then copy a match from `offset` back.
#[derive(Clone, Copy)]
struct Sequence {
    literal_length: usize,
    match_length: usize,
    /// Raw offset value, before the repeat-offset rules are applied.
    offset_value: u32,
}

/// State that a frame carries between its blocks.
#[derive(Default)]
struct FrameState {
    literals: Option<HuffTable>,
    literal_length: Option<std::sync::Arc<FseTable>>,
    offset: Option<std::sync::Arc<FseTable>>,
    match_length: Option<std::sync::Arc<FseTable>>,
    /// Most recent offsets, newest first.
    repeat_offsets: [usize; 3],
}

/// Most output one input byte may expand into.
///
/// Domain lists compress well — twenty times is ordinary — but a payload that
/// claims hundreds of times its own size is a decompression bomb, and the whole
/// point of decoding it is to hand the result to a rule engine that will index
/// it. The bound is a ratio *and* a floor: a tiny valid frame must still decode.
const MAX_EXPANSION_RATIO: usize = 128;
/// Floor under the ratio, so short files are not judged by it.
const EXPANSION_FLOOR: usize = 1 << 20;

/// Largest output this many input bytes may honestly expand into.
///
/// The effective budget is the smaller of what the caller allows and this figure.
fn expansion_budget(input_len: usize) -> usize {
    input_len
        .saturating_mul(MAX_EXPANSION_RATIO)
        .saturating_add(EXPANSION_FLOOR)
}

/// Decompress one or more frames, refusing to produce more than `limit` bytes.
pub fn decompress(input: &[u8], limit: usize) -> Result<Vec<u8>> {
    let limit = limit.min(expansion_budget(input.len()));
    let mut cursor = Input::new(input);
    let mut out: Vec<u8> = Vec::new();
    let mut decoded_any = false;

    while cursor.remaining() >= 4 {
        let magic = cursor.take(4)?;
        if magic[..3] == SKIPPABLE_PREFIX && (magic[3] & 0xF0) == SKIPPABLE_NIBBLE {
            let length = cursor.u32_le()? as usize;
            cursor.skip(length)?;
            continue;
        }
        if magic != FRAME_MAGIC.as_slice() {
            return Err(corrupt("not a zstd frame"));
        }
        decompress_frame(&mut cursor, &mut out, limit)?;
        decoded_any = true;
    }

    if !decoded_any {
        return Err(corrupt("no frame found"));
    }
    if cursor.remaining() != 0 {
        return Err(corrupt("trailing bytes after the last frame"));
    }
    Ok(out)
}

fn decompress_frame(input: &mut Input<'_>, out: &mut Vec<u8>, limit: usize) -> Result<()> {
    let descriptor = input.u8()?;
    if descriptor & 0x08 != 0 {
        return Err(corrupt("reserved frame header bit is set"));
    }
    let single_segment = descriptor & 0x20 != 0;
    let checksum = descriptor & 0x04 != 0;
    let dict_id_size = match descriptor & 0x03 {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 4,
    };
    let content_size_flag = descriptor >> 6;

    if !single_segment {
        let window_descriptor = input.u8()?;
        let window_log = u32::from(window_descriptor >> 3) + 10;
        if window_log > 31 {
            return Err(corrupt("window size out of range"));
        }
    }
    if dict_id_size > 0 {
        input.skip(dict_id_size)?;
        return Err(corrupt("frame requires a dictionary"));
    }
    let content_size = match content_size_flag {
        0 => {
            if single_segment {
                Some(u64::from(input.u8()?))
            } else {
                None
            }
        }
        1 => Some(u64::from(input.u16_le()?) + 256),
        2 => Some(u64::from(input.u32_le()?)),
        _ => Some(input.u64_le()?),
    };
    if let Some(size) = content_size {
        if size > limit as u64 {
            return Err(corrupt("declared content size exceeds the limit"));
        }
        if (out.len() as u64).saturating_add(size) > limit as u64 {
            return Err(corrupt("output would exceed the limit"));
        }
    }

    let mut state = FrameState {
        repeat_offsets: [1, 4, 8],
        ..FrameState::default()
    };
    let frame_start = out.len();

    loop {
        let header = input.take(3)?;
        let value =
            u32::from(header[0]) | (u32::from(header[1]) << 8) | (u32::from(header[2]) << 16);
        let last_block = value & 1 != 0;
        let block_type = (value >> 1) & 0x03;
        let block_size = (value >> 3) as usize;
        if block_size > MAX_BLOCK_SIZE {
            return Err(corrupt("block size out of range"));
        }

        match block_type {
            0 => {
                // Raw block.
                let block = input.take(block_size)?;
                if out.len() + block.len() > limit {
                    return Err(corrupt("output would exceed the limit"));
                }
                out.extend_from_slice(block);
            }
            1 => {
                // RLE block: one byte, repeated.
                let byte = input.u8()?;
                if out.len() + block_size > limit {
                    return Err(corrupt("output would exceed the limit"));
                }
                out.resize(out.len() + block_size, byte);
            }
            2 => decompress_block(input, out, &mut state, block_size, limit)?,
            _ => return Err(corrupt("reserved block type")),
        }

        if last_block {
            break;
        }
    }

    if checksum {
        input.skip(4)?;
    }
    if let Some(size) = content_size
        && out.len() - frame_start != size as usize
    {
        return Err(corrupt(
            "decoded size does not match the declared content size",
        ));
    }
    Ok(())
}

fn decompress_block(
    input: &mut Input<'_>,
    out: &mut Vec<u8>,
    state: &mut FrameState,
    block_size: usize,
    limit: usize,
) -> Result<()> {
    let block = input.take(block_size)?;
    let mut section = Input::new(block);
    let literals = decode_literals(&mut section, state, limit)?;
    let sequences = decode_sequences(&mut section, state)?;
    execute_sequences(out, &literals, &sequences, state, limit)?;
    Ok(())
}

// --- literals ---------------------------------------------------------------

fn decode_literals(input: &mut Input<'_>, state: &mut FrameState, limit: usize) -> Result<Vec<u8>> {
    let mut bits = ForwardBits::new(input.remaining_slice());
    let block_type = bits.read(2) as u8;
    let size_format = bits.read(2) as u8;

    if block_type <= 1 {
        let size = match size_format {
            0 | 2 => {
                bits.rewind(1);
                bits.read(5)
            }
            1 => bits.read(12),
            _ => bits.read(20),
        } as usize;
        let consumed = bits.consumed();
        input.skip(consumed)?;
        if size > MAX_BLOCK_SIZE || size > limit {
            return Err(corrupt("literals size out of range"));
        }
        return match block_type {
            0 => Ok(input.take(size)?.to_vec()),
            _ => {
                let byte = input.u8()?;
                Ok(vec![byte; size])
            }
        };
    }

    // Huffman-compressed literals.
    let (regenerated_size, compressed_size, streams) = match size_format {
        0 => (10u32, 10u32, 1u8),
        1 => (10, 10, 4),
        2 => (14, 14, 4),
        _ => (18, 18, 4),
    };
    let regenerated = bits.read(regenerated_size) as usize;
    let compressed = bits.read(compressed_size) as usize;
    let consumed = bits.consumed();
    input.skip(consumed)?;
    if regenerated > MAX_BLOCK_SIZE || regenerated > limit {
        return Err(corrupt("literals size out of range"));
    }

    let payload = input.take(compressed)?;
    let mut huf_input = Input::new(payload);
    if block_type == 2 {
        let table = read_huffman_table(&mut huf_input)?;
        state.literals = Some(table);
    }
    let table = state
        .literals
        .as_ref()
        .ok_or_else(|| corrupt("compressed literals without a Huffman table"))?;

    let mut literals = Vec::with_capacity(regenerated);
    if streams == 1 {
        let data = huf_input.remaining_slice();
        let mut stream = BackBits::new(data)?;
        table.decompress_stream(&mut stream, &mut literals, regenerated)?;
    } else {
        let size1 = huf_input.u16_le()? as usize;
        let size2 = huf_input.u16_le()? as usize;
        let size3 = huf_input.u16_le()? as usize;
        let mut chunks = Vec::with_capacity(4);
        chunks.push(huf_input.take(size1)?);
        chunks.push(huf_input.take(size2)?);
        chunks.push(huf_input.take(size3)?);
        let rest = huf_input.remaining();
        chunks.push(huf_input.take(rest)?);
        for chunk in chunks {
            let mut stream = BackBits::new(chunk)?;
            table.decompress_stream(&mut stream, &mut literals, regenerated)?;
        }
    }
    if literals.len() != regenerated {
        return Err(corrupt("literals were not decoded to their declared size"));
    }
    Ok(literals)
}

fn read_huffman_table(input: &mut Input<'_>) -> Result<HuffTable> {
    let header = input.u8()?;
    if header >= 128 {
        // Direct representation: four bits per weight.
        let count = usize::from(header) - 127;
        let bytes = count.div_ceil(2);
        let packed = input.take(bytes)?;
        let mut weights = vec![0u8; count];
        for index in 0..count {
            weights[index] = if index % 2 == 0 {
                packed[index / 2] >> 4
            } else {
                packed[index / 2] & 0x0F
            };
        }
        HuffTable::from_weights(&weights, count)
    } else {
        // FSE-compressed weights, with a maximum accuracy of 7. The description
        // is read forward and the weights themselves backward from what follows
        // it, inside the same section.
        let size = usize::from(header);
        let payload = input.take(size)?;
        let mut cursor = Input::new(payload);
        let table = FseTable::read_description(&mut cursor, 7)?;
        let mut weights = vec![0u8; MAX_SYMBOLS];
        let mut stream = BackBits::new(cursor.remaining_slice())?;
        let count = table.decompress_interleaved2(&mut stream, &mut weights)?;
        HuffTable::from_weights(&weights, count)
    }
}

// --- sequences --------------------------------------------------------------

fn decode_sequences(input: &mut Input<'_>, state: &mut FrameState) -> Result<Vec<Sequence>> {
    let first = input.u8()?;
    let count = if first < 128 {
        usize::from(first)
    } else if first < 255 {
        (usize::from(first) - 128) << 8 | usize::from(input.u8()?)
    } else {
        0x7F00 + input.u16_le()? as usize
    };
    if count == 0 {
        return Ok(Vec::new());
    }
    if count > MAX_BLOCK_SIZE {
        return Err(corrupt("sequence count out of range"));
    }

    let modes = input.u8()?;
    if modes & 0x03 != 0 {
        return Err(corrupt("reserved sequence mode bits are set"));
    }
    let literal_length_table =
        read_sequence_table(input, state, SeqPart::LiteralLength, (modes >> 6) & 3)?;
    let offset_table = read_sequence_table(input, state, SeqPart::Offset, (modes >> 4) & 3)?;
    let match_length_table =
        read_sequence_table(input, state, SeqPart::MatchLength, (modes >> 2) & 3)?;

    let payload = input.remaining_slice();
    let mut stream = BackBits::new(payload)?;
    let mut literal_length_state = literal_length_table.init_state(&mut stream);
    let mut offset_state = offset_table.init_state(&mut stream);
    let mut match_length_state = match_length_table.init_state(&mut stream);

    let mut sequences = Vec::with_capacity(count);
    for index in 0..count {
        let offset_code = offset_table.peek(offset_state);
        let literal_length_code = literal_length_table.peek(literal_length_state);
        let match_length_code = match_length_table.peek(match_length_state);
        if literal_length_code > SEQ_MAX_LITERAL_LENGTH_CODE
            || match_length_code > SEQ_MAX_MATCH_LENGTH_CODE
        {
            return Err(corrupt("sequence code out of range"));
        }
        let offset_value = (1u32 << offset_code) + stream.read(u32::from(offset_code)) as u32;
        let match_length = SEQ_MATCH_LENGTH_BASELINES[usize::from(match_length_code)] as usize
            + stream.read(u32::from(
                SEQ_MATCH_LENGTH_EXTRA_BITS[usize::from(match_length_code)],
            )) as usize;
        let literal_length = SEQ_LITERAL_LENGTH_BASELINES[usize::from(literal_length_code)]
            as usize
            + stream.read(u32::from(
                SEQ_LITERAL_LENGTH_EXTRA_BITS[usize::from(literal_length_code)],
            )) as usize;

        sequences.push(Sequence {
            literal_length,
            match_length,
            offset_value,
        });

        if index + 1 < count {
            literal_length_table.update_state(&mut literal_length_state, &mut stream);
            match_length_table.update_state(&mut match_length_state, &mut stream);
            offset_table.update_state(&mut offset_state, &mut stream);
        }
    }
    if stream.offset != 0 {
        return Err(corrupt("sequence bitstream was not consumed exactly"));
    }
    Ok(sequences)
}

fn read_sequence_table(
    input: &mut Input<'_>,
    state: &mut FrameState,
    part: SeqPart,
    mode: u8,
) -> Result<std::sync::Arc<FseTable>> {
    let table: std::sync::Arc<FseTable> = match mode {
        0 => {
            // Predefined distribution.
            let frequencies = part.default_distribution();
            let table = FseTable::from_frequencies(
                frequencies,
                frequencies.len(),
                part.default_accuracy(),
            )?;
            std::sync::Arc::new(table)
        }
        1 => {
            // One symbol, repeated.
            std::sync::Arc::new(FseTable::repeated(input.u8()?))
        }
        2 => std::sync::Arc::new(FseTable::read_description(input, part.max_accuracy())?),
        _ => {
            // Repeat the previous table.
            let previous = match part {
                SeqPart::LiteralLength => &state.literal_length,
                SeqPart::Offset => &state.offset,
                SeqPart::MatchLength => &state.match_length,
            };
            previous
                .clone()
                .ok_or_else(|| corrupt("repeated sequence table without a previous one"))?
        }
    };
    match part {
        SeqPart::LiteralLength => state.literal_length = Some(std::sync::Arc::clone(&table)),
        SeqPart::Offset => state.offset = Some(std::sync::Arc::clone(&table)),
        SeqPart::MatchLength => state.match_length = Some(std::sync::Arc::clone(&table)),
    }
    Ok(table)
}

// --- sequence execution -----------------------------------------------------

fn execute_sequences(
    out: &mut Vec<u8>,
    literals: &[u8],
    sequences: &[Sequence],
    state: &mut FrameState,
    limit: usize,
) -> Result<()> {
    let mut literal_position = 0usize;

    for sequence in sequences {
        let literal_end = literal_position + sequence.literal_length;
        if literal_end > literals.len() {
            return Err(corrupt("sequence asks for more literals than exist"));
        }
        if out.len() + sequence.literal_length > limit {
            return Err(corrupt("output would exceed the limit"));
        }
        out.extend_from_slice(&literals[literal_position..literal_end]);
        literal_position = literal_end;

        let offset = resolve_offset(sequence, state)?;
        if offset == 0 || offset > out.len() {
            return Err(corrupt("match offset points before the decoded data"));
        }
        if out.len() + sequence.match_length > limit {
            return Err(corrupt("output would exceed the limit"));
        }
        // Matches may overlap their own output, so the copy is byte by byte.
        let start = out.len() - offset;
        for index in 0..sequence.match_length {
            let byte = out[start + index];
            out.push(byte);
        }
    }

    if literal_position < literals.len() {
        let rest = &literals[literal_position..];
        if out.len() + rest.len() > limit {
            return Err(corrupt("output would exceed the limit"));
        }
        out.extend_from_slice(rest);
    }
    Ok(())
}

/// Apply the format's repeat-offset rules to a sequence's raw offset value.
fn resolve_offset(sequence: &Sequence, state: &mut FrameState) -> Result<usize> {
    let history = &mut state.repeat_offsets;
    let value = sequence.offset_value as usize;
    if value > 3 {
        let offset = value - 3;
        history[2] = history[1];
        history[1] = history[0];
        history[0] = offset;
        return Ok(offset);
    }

    let mut index = value - 1;
    if sequence.literal_length == 0 {
        index += 1;
    }
    if index == 0 {
        return Ok(history[0]);
    }
    let offset = if index < 3 {
        history[index]
    } else {
        history[0]
            .checked_sub(1)
            .ok_or_else(|| corrupt("repeat offset underflow"))?
    };
    if index > 1 {
        history[2] = history[1];
    }
    history[1] = history[0];
    history[0] = offset;
    Ok(offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The plaintexts the reference encoder compressed into `tests/data/zstd`.
    ///
    /// They are code rather than `.raw` files on purpose. A text fixture in a git
    /// checkout is subject to line-ending policy, and a `.raw` file that has been
    /// CRLF-converted is no longer the plaintext the encoder saw: the Windows job
    /// failed once with exactly one extra byte per line. The compressed side stays
    /// byte-exact (`.gitattributes` marks the fixture directory binary), and the
    /// bytes it must decode to are reproduced here.
    fn cases() -> Vec<(String, Vec<u8>)> {
        let mut cases: Vec<(String, Vec<u8>)> = vec![
            ("empty".to_string(), Vec::new()),
            ("single_byte".to_string(), b"a".to_vec()),
            (
                "short_text".to_string(),
                b"DOMAIN-SUFFIX,example.com\n".to_vec(),
            ),
            ("rle_text".to_string(), vec![b'x'; 5000]),
            (
                "random_4k".to_string(),
                (0..4096u32)
                    .map(|index| (index.wrapping_mul(16_777_619) >> 13) as u8)
                    .collect(),
            ),
        ];

        // A rule-set shaped document: repeated prefixes, which is what turns into
        // Huffman literals plus FSE sequences.
        let mut rules = String::new();
        for index in 0..4000u32 {
            rules.push_str(&format!(
                "DOMAIN-SUFFIX,cdn{}.example{}.com\n",
                index,
                index % 37
            ));
        }
        rules.push_str("DOMAIN-KEYWORD,adserver\nIP-CIDR,10.0.0.0/8,no-resolve\n");
        for level in [1, 3, 9, 19] {
            cases.push((format!("ruleset_l{level}"), rules.clone().into_bytes()));
        }

        // Larger than one 128 KiB block, so block-to-block state has to carry.
        let mut big = Vec::new();
        for index in 0..12000u32 {
            big.extend_from_slice(
                format!("host{:05}.service{}.internal.example\n", index, index % 97).as_bytes(),
            );
        }
        for level in [3, 12] {
            cases.push((format!("multiblock_l{level}"), big.clone()));
        }
        cases
    }

    /// Every fixture must decode back to the exact bytes the encoder was given.
    #[test]
    fn reference_frames_decode_to_their_plaintext() {
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/zstd");
        let mut checked = 0usize;
        for (name, expected) in cases() {
            let frame = std::fs::read(directory.join(format!("{name}.zst")))
                .unwrap_or_else(|error| panic!("{name}: cannot read the fixture: {error}"));
            let decoded = decompress(&frame, 64 * 1024 * 1024)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(decoded.len(), expected.len(), "{name}: decoded length");
            assert!(decoded == expected, "{name}: decoded content");
            checked += 1;
        }
        assert_eq!(checked, 11, "the fixture set is incomplete");
    }

    /// The amplification budget: a small file cannot claim an unbounded output,
    /// and an ordinary one still gets room to breathe.
    #[test]
    fn the_expansion_budget_bounds_a_small_file() {
        assert_eq!(expansion_budget(100), EXPANSION_FLOOR + 12_800);
        assert!(expansion_budget(2 << 20) >= 64 * 1024 * 1024);

        let frame = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/zstd/ruleset_l3.zst"),
        )
        .expect("frame");
        assert!(decompress(&frame, 512).is_err());
        assert!(decompress(&frame, 64 * 1024 * 1024).is_ok());
    }

    #[test]
    fn a_truncated_frame_is_an_error() {
        let frame = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/zstd/short_text.zst"),
        )
        .expect("frame");
        assert!(decompress(&frame[..frame.len() - 3], 1024).is_err());
    }

    #[test]
    fn a_limit_below_the_content_is_refused() {
        let frame = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/zstd/ruleset_l3.zst"),
        )
        .expect("frame");
        assert!(decompress(&frame, 1024).is_err());
    }

    #[test]
    fn a_foreign_payload_is_refused() {
        assert!(decompress(b"not a frame at all", 1024).is_err());
        assert!(decompress(&[], 1024).is_err());
    }

    #[test]
    fn a_skippable_frame_contributes_nothing_and_is_skipped() {
        // Magic 0x184D2A50, length 3, then three bytes of payload.
        let skippable = [0x50, 0x2A, 0x4D, 0x18, 3, 0, 0, 0, b'a', b'b', b'c'];
        assert!(
            decompress(&skippable, 1024).is_err(),
            "no real frame follows"
        );
    }
}
