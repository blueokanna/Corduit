//! The compressed domain set shared by `.srs` rule sets and the Geo databases.
//!
//! This is the structure sing-box serialises into a `.srs` file: a trie over
//! *rune-reversed* domain strings, stored as a bit-mapped tree (LOUDS-style)
//! instead of a node per character with 256 child pointers. It answers
//! "is this domain a key, or does it end in one of these suffixes" in one pass
//! over the domain, with two O(1) bitmap operations per byte, in roughly one
//! byte of labels plus one byte of bitmaps per node — an order of magnitude less
//! memory than holding the same category as a `HashSet<String>`, which is what
//! makes a 200 k-entry `category-ads-all` category affordable.
//!
//! ## Encoding
//!
//! Keys are reversed so that every domain under `.com` shares a path prefix; two
//! marker labels carry the matching semantics:
//!
//! | Marker | Byte | Meaning |
//! |---|---|---|
//! | prefix | `\r` | meeting it at any point is a match (suffix wildcard) |
//! | root | `\n` | matches the domain itself and, through a following `.`, any subdomain |
//!
//! A key that is the reversed domain itself (`moc.elpmaxe`) is an exact match; a
//! key of `\n` + the reversed domain (`moc.elpmaxe\n`) is a suffix match. The
//! `.`-boundary check happens in [`DomainMatcher::matches`], so `notexample.com`
//! cannot match the suffix `example.com`.
//!
//! Reading validates the structural invariants the writer guarantees
//! (`nodes == labels + 1`, one label per non-root node). A file that breaks them
//! is rejected instead of indexing outside the label array on the first lookup.

use super::reader::Reader;
use crate::engine::error::{Error, Result};
use std::borrow::Cow;

/// Label that makes its subtree match at any depth.
const PREFIX_LABEL: u8 = b'\r';
/// Label that makes its subtree match the domain itself and its subdomains.
const ROOT_LABEL: u8 = b'\n';

/// One `1` per node, `0` per label, in breadth-first order.
#[derive(Debug, Default, Clone)]
pub struct SuccinctSet {
    /// Node is a terminal for the key spelled by its path.
    leaves: Vec<u64>,
    /// Bit *i* is set when label *i* ends a node's label list.
    label_bitmap: Vec<u64>,
    /// Every node's labels, concatenated in breadth-first node order.
    labels: Vec<u8>,
    /// `ranks[i]` is the number of set bits in `label_bitmap[..i]`; one extra
    /// trailing element holds the total, so `rank(i)` at the end of the bitmap is
    /// the same lookup as anywhere else.
    ranks: Vec<u32>,
    /// Bit position of every 32nd set bit, so `select(i)` starts within 32 ones
    /// of its answer instead of at the beginning.
    selects: Vec<u32>,
}

impl SuccinctSet {
    /// An empty set: it holds no key, and every lookup misses.
    pub fn empty() -> Self {
        Self {
            leaves: Vec::new(),
            label_bitmap: Vec::new(),
            labels: Vec::new(),
            ranks: vec![0],
            selects: Vec::new(),
        }
    }

    /// Build from keys that are already rune-reversed and marker-encoded.
    ///
    /// Sorts and deduplicates: the builder below relies on equal prefixes being
    /// adjacent, and a duplicate key would be indexed past its own end.
    pub fn from_keys(mut keys: Vec<String>) -> Self {
        keys.sort_unstable();
        keys.dedup();
        if keys.is_empty() {
            return Self::empty();
        }

        let mut leaves: Vec<u64> = Vec::new();
        let mut label_bitmap: Vec<u64> = Vec::new();
        let mut labels: Vec<u8> = Vec::new();
        let mut bit = 0usize;
        let mut queue: Vec<(usize, usize, usize)> = vec![(0, keys.len(), 0)];
        let mut head = 0;
        while head < queue.len() {
            let (start, end, depth) = queue[head];
            let mut cursor = start;
            if cursor < end && keys[cursor].len() == depth {
                set_bit(&mut leaves, head);
                cursor += 1;
            }
            while cursor < end {
                let first = cursor;
                let label = keys[first].as_bytes()[depth];
                while cursor < end && keys[cursor].as_bytes()[depth] == label {
                    cursor += 1;
                }
                queue.push((first, cursor, depth + 1));
                labels.push(label);
                set_bit_at(&mut label_bitmap, bit, false);
                bit += 1;
            }
            set_bit_at(&mut label_bitmap, bit, true);
            bit += 1;
            head += 1;
        }

        Self::assemble(leaves, label_bitmap, labels).unwrap_or_else(|| {
            debug_assert!(false, "succinct set builder produced an inconsistent set");
            Self::empty()
        })
    }

    /// Decode the serialised form.
    pub fn read(reader: &mut Reader<'_>) -> Result<Self> {
        let version = reader.u8()?;
        if version != 0 {
            return Err(Error::config(format!(
                "Rule set domain matcher uses unknown encoding version {version}"
            )));
        }
        let leaves = reader.u64_slice()?;
        let label_bitmap = reader.u64_slice()?;
        let label_count = reader.count(1)?;
        let labels = reader.take(label_count)?.to_vec();
        Self::assemble(leaves, label_bitmap, labels).ok_or_else(|| {
            Error::config(
                "Rule set domain matcher is malformed: node and label counts disagree",
            )
        })
    }

    /// Decode the other serialisation of this same tree (`.mrs` version 1).
    ///
    /// Identical three arrays in the identical order; the only differences are
    /// that the lengths are fixed-width big-endian `i64` rather than varints, and
    /// that every length must be at least one — an empty set is not representable
    /// in that container. Reading it here keeps a single implementation of the
    /// rank/select indexes and of the structural validation.
    pub(crate) fn read_wire_v1(reader: &mut Reader<'_>) -> Result<Self> {
        let version = reader.u8()?;
        if version != 1 {
            return Err(Error::config(format!(
                "Rule set domain matcher uses unknown encoding version {version}"
            )));
        }
        let leaves = read_u64_array(reader, "leaves")?;
        let label_bitmap = read_u64_array(reader, "label bitmap")?;
        let label_count = read_positive_i64(reader, "label count")?;
        let labels = reader.take(label_count)?.to_vec();
        Self::assemble(leaves, label_bitmap, labels).ok_or_else(|| {
            Error::config(
                "Rule set domain matcher is malformed: node and label counts disagree",
            )
        })
    }

    /// Whether `domain` is described by this set, using the wildcard walk.
    ///
    /// The key is the domain with its runes reversed, each rune keeping its bytes
    /// in order, then lowercased. Two labels are not characters but operators:
    /// `+` matches the rest of the domain at any depth (a suffix pattern), and
    /// `*` matches one label and is backtracked past if the rest of the walk
    /// fails. Everything else is a literal byte.
    ///
    /// The walk is a faithful port of the reference matcher, including its
    /// backtracking stack and its habit of scanning past a node boundary while
    /// looking for the next dot: a set written by that tool must answer exactly
    /// what the tool answers, quirks included, or a rule set would silently
    /// change meaning when it crossed into this engine.
    pub(crate) fn has_wildcards(&self, domain: &str) -> bool {
        if self.is_empty() {
            return false;
        }

        // Reversal is per rune, so a multi-byte name has to be materialised; an
        // ASCII name — every punycoded hostname — is addressed in place.
        let ascii = domain.is_ascii();
        let mut owned: Vec<u8> = Vec::new();
        if !ascii {
            for character in domain.chars().rev() {
                let mut buffer = [0u8; 4];
                let encoded = character.encode_utf8(&mut buffer);
                for byte in encoded.as_bytes() {
                    owned.push(byte.to_ascii_lowercase());
                }
            }
        }
        let length = if ascii { domain.len() } else { owned.len() };
        let at = |index: usize| -> u8 {
            if ascii {
                domain.as_bytes()[length - 1 - index].to_ascii_lowercase()
            } else {
                owned[index]
            }
        };

        let mut node: u32 = 0;
        let mut bit: u32 = 0;
        let mut index = 0usize;
        // Saved `(bit, index)` of every `*` label met on the current path.
        let mut stack: Vec<(u32, usize)> = Vec::new();

        'restart: while index < length {
            let wanted = at(index);
            loop {
                if self.is_terminator(bit) {
                    let Some((cursor_bit, cursor_index)) = stack.pop() else {
                        return false;
                    };
                    let next_node = self.count_zeros(cursor_bit + 1);
                    let Some(previous) = next_node.checked_sub(1) else {
                        return false;
                    };
                    let Some(position) = self.select(previous) else {
                        return false;
                    };
                    let mut next_bit = position + 1;
                    let mut scan = cursor_index;
                    while scan < length && at(scan) != b'.' {
                        scan += 1;
                    }
                    if scan == length {
                        if self.is_leaf(next_node) {
                            return true;
                        }
                        continue 'restart;
                    }
                    // Walk this node's labels for the step one label down. The
                    // bound is the label array, exactly as the reference does it.
                    loop {
                        let Some(label_index) = next_bit.checked_sub(next_node) else {
                            return false;
                        };
                        let Some(&label) = self.labels.get(label_index as usize) else {
                            return false;
                        };
                        if label == b'.' {
                            bit = next_bit;
                            node = next_node;
                            index = scan;
                            continue 'restart;
                        }
                        next_bit += 1;
                    }
                }
                let Some(&label) = self.label_at(bit, node) else {
                    return false;
                };
                match label {
                    b'+' => return true,
                    b'*' => {
                        stack.push((bit, index));
                    }
                    other if other == wanted => break,
                    _ => {}
                }
                bit += 1;
            }
            node = self.count_zeros(bit + 1);
            let Some(previous) = node.checked_sub(1) else {
                return false;
            };
            let Some(position) = self.select(previous) else {
                return false;
            };
            bit = position + 1;
            index += 1;
        }

        self.is_leaf(node)
    }

    /// Serialise the way the other dialect does, for round-trip tests.
    #[cfg(test)]
    pub(crate) fn write_wire_v1(&self, out: &mut Vec<u8>) {
        out.push(1);
        for values in [&self.leaves, &self.label_bitmap] {
            out.extend_from_slice(&(values.len() as i64).to_be_bytes());
            for value in values {
                out.extend_from_slice(&value.to_be_bytes());
            }
        }
        out.extend_from_slice(&(self.labels.len() as i64).to_be_bytes());
        out.extend_from_slice(&self.labels);
    }

    /// Assemble the structure and its lookup indexes, validating the shape.
    ///
    /// `None` when the parts cannot describe a tree, which only a corrupt file
    /// can produce.
    fn assemble(mut leaves: Vec<u64>, label_bitmap: Vec<u64>, labels: Vec<u8>) -> Option<Self> {
        if label_bitmap.is_empty() {
            return if labels.is_empty() {
                Some(Self::empty())
            } else {
                None
            };
        }

        let mut ones = 0u32;
        let mut last_one = None;
        for (index, word) in label_bitmap.iter().enumerate() {
            ones += word.count_ones();
            if *word != 0 {
                last_one = Some(index * 64 + (63 - word.leading_zeros() as usize));
            }
        }
        let total_bits = last_one.map_or(0, |index| index + 1);
        let zeros = total_bits.saturating_sub(ones as usize);
        if ones as usize != zeros + 1 || labels.len() != zeros {
            return None;
        }

        leaves.resize(ones.div_ceil(64) as usize, 0);
        let ranks = rank_index(&label_bitmap, ones as usize);
        let selects = select_index(&label_bitmap);
        Some(Self {
            leaves,
            label_bitmap,
            labels,
            ranks,
            selects,
        })
    }

    /// Whether the set holds any key.
    pub fn is_empty(&self) -> bool {
        self.label_bitmap.is_empty()
    }

    /// Number of keys stored, which is the number of terminal nodes.
    pub fn len(&self) -> usize {
        self.leaves.iter().map(|word| word.count_ones() as usize).sum()
    }

    /// Bit `index` of `label_bitmap`.
    fn is_terminator(&self, index: u32) -> bool {
        let word = self.label_bitmap.get((index >> 6) as usize);
        word.is_some_and(|word| word & (1u64 << (index & 63)) != 0)
    }

    /// Bit `node` of `leaves`.
    fn is_leaf(&self, node: u32) -> bool {
        let word = self.leaves.get((node >> 6) as usize);
        word.is_some_and(|word| word & (1u64 << (node & 63)) != 0)
    }

    /// Number of set bits in `label_bitmap[..index]`.
    fn rank(&self, index: u32) -> u32 {
        let word = (index >> 6) as usize;
        let Some(base) = self.ranks.get(word).copied() else {
            return self.total_ones();
        };
        let Some(&bits) = self.label_bitmap.get(word) else {
            return base;
        };
        let offset = index & 63;
        let mask = if offset == 0 {
            0
        } else {
            (1u64 << offset) - 1
        };
        base + (bits & mask).count_ones()
    }

    fn total_ones(&self) -> u32 {
        self.ranks.last().copied().unwrap_or(0)
    }

    /// Number of zeros in `label_bitmap[..index]`, which is a node's label
    /// offset.
    fn count_zeros(&self, index: u32) -> u32 {
        index.saturating_sub(self.rank(index))
    }

    /// Bit position of the `index`-th set bit.
    ///
    /// The select index narrows the search to one word — it holds the position of
    /// every 32nd set bit — but that position is not necessarily the first bit of
    /// its word, so the count to skip is the rank of the *word*, not of the
    /// index. Getting that wrong returns a bit a few positions early, which is
    /// exactly the kind of near-miss that makes a domain set match its
    /// neighbouring key instead of its own.
    fn select(&self, index: u32) -> Option<u32> {
        let bucket = (index / 32) as usize;
        let start = *self.selects.get(bucket)?;
        let mut word = (start >> 6) as usize;
        let mut remaining = index.checked_sub(*self.ranks.get(word)?)?;
        loop {
            let bits = *self.label_bitmap.get(word)?;
            let count = bits.count_ones();
            if remaining < count {
                break;
            }
            remaining -= count;
            word += 1;
        }
        let mut bits = self.label_bitmap[word];
        let mut nth = remaining;
        while nth > 0 {
            bits &= bits.wrapping_sub(1);
            if bits == 0 {
                return None;
            }
            nth -= 1;
        }
        Some((word as u32) * 64 + bits.trailing_zeros())
    }

    /// sing-box's `Matcher.has`: walk `key` (a reversed domain) one byte at a
    /// time, following the bitmap to each child node.
    fn has(&self, key: &str) -> bool {
        if self.is_empty() {
            return false;
        }
        let mut node: u32 = 0;
        let mut bit: u32 = 0;

        for character in key.chars().rev() {
            let mut buffer = [0u8; 4];
            let encoded = character.encode_utf8(&mut buffer);
            for &raw in encoded.as_bytes().iter().rev() {
                let wanted = raw.to_ascii_lowercase();
                loop {
                    if self.is_terminator(bit) {
                        return false;
                    }
                    let Some(&label) = self.label_at(bit, node) else {
                        return false;
                    };
                    if label == PREFIX_LABEL {
                        return true;
                    }
                    if label == ROOT_LABEL {
                        let child = self.count_zeros(bit + 1);
                        if wanted == b'.' && self.is_leaf(child) {
                            return true;
                        }
                    }
                    if label == wanted {
                        break;
                    }
                    bit += 1;
                }
                node = self.count_zeros(bit + 1);
                let Some(previous) = node.checked_sub(1) else {
                    return false;
                };
                let Some(position) = self.select(previous) else {
                    return false;
                };
                bit = position + 1;
            }
        }

        if self.is_leaf(node) {
            return true;
        }

        loop {
            if self.is_terminator(bit) {
                return false;
            }
            match self.label_at(bit, node) {
                Some(&PREFIX_LABEL) | Some(&ROOT_LABEL) => return true,
                Some(_) => bit += 1,
                None => return false,
            }
        }
    }

    /// The label `bit` belongs to, given the node currently being scanned.
    pub(crate) fn label_at(&self, bit: u32, node: u32) -> Option<&u8> {
        let index = bit.checked_sub(node)? as usize;
        self.labels.get(index)
    }

    /// Serialise for the round-trip tests and for a future `.srs` writer.
    #[cfg(test)]
    pub(crate) fn write(&self, out: &mut Vec<u8>) {
        out.push(0);
        write_u64_slice(out, &self.leaves);
        write_u64_slice(out, &self.label_bitmap);
        write_uvarint(out, self.labels.len() as u64);
        out.extend_from_slice(&self.labels);
    }
}

#[cfg(test)]
fn write_u64_slice(out: &mut Vec<u8>, values: &[u64]) {
    write_uvarint(out, values.len() as u64);
    for value in values {
        out.extend_from_slice(&value.to_be_bytes());
    }
}

#[cfg(test)]
fn write_uvarint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return;
        }
    }
}

/// Read a positive big-endian `i64` length.
///
/// The container's lengths are signed sixty-four-bit values; zero is refused
/// because the writer never emits an empty array and a zero would describe a set
/// that cannot be walked.
fn read_positive_i64(reader: &mut Reader<'_>, field: &str) -> Result<usize> {
    let raw = reader.u64_be()?;
    if raw == 0 {
        return Err(Error::config(format!(
            "Rule set domain matcher declares an empty {field}"
        )));
    }
    if raw > i64::MAX as u64 {
        return Err(Error::config(format!(
            "Rule set domain matcher declares {raw} {field} entries"
        )));
    }
    usize::try_from(raw)
        .map_err(|_| Error::config(format!("Rule set domain matcher {field} count overflows")))
}

/// Read a counted big-endian `u64` array.
fn read_u64_array(reader: &mut Reader<'_>, field: &str) -> Result<Vec<u64>> {
    let count = read_positive_i64(reader, field)?;
    // Eight bytes per element: a count that cannot fit the remaining bytes is a
    // lie, and this is the check that keeps it from becoming an allocation.
    if count.saturating_mul(8) > reader.remaining() {
        return Err(Error::config(format!(
            "Rule set domain matcher declares {count} {field} entries but only {} bytes remain",
            reader.remaining()
        )));
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(reader.u64_be()?);
    }
    Ok(values)
}

/// Set bit `index` of a growable bitmap.
fn set_bit(bitmap: &mut Vec<u64>, index: usize) {
    set_bit_at(bitmap, index, true);
}

fn set_bit_at(bitmap: &mut Vec<u64>, index: usize, value: bool) {
    let word = index >> 6;
    while word >= bitmap.len() {
        bitmap.push(0);
    }
    if value {
        bitmap[word] |= 1u64 << (index & 63);
    }
}

/// Prefix popcount per word, plus a trailing total.
fn rank_index(bitmap: &[u64], total: usize) -> Vec<u32> {
    let mut ranks = Vec::with_capacity(bitmap.len() + 1);
    let mut running = 0u32;
    for word in bitmap {
        ranks.push(running);
        running += word.count_ones();
    }
    ranks.push(running);
    debug_assert_eq!(running as usize, total);
    ranks
}

/// Bit position of every 32nd set bit.
fn select_index(bitmap: &[u64]) -> Vec<u32> {
    let mut selects = Vec::new();
    let mut seen = 0u32;
    for (word_index, word) in bitmap.iter().enumerate() {
        let mut bits = *word;
        while bits != 0 {
            if seen.is_multiple_of(32) {
                selects.push((word_index as u32) * 64 + bits.trailing_zeros());
            }
            bits &= bits - 1;
            seen += 1;
        }
    }
    selects
}

/// A domain matcher: exact domains and suffix domains over one compressed set.
///
/// This is the matcher a `.srs` domain item holds, and the one the Geo databases
/// build from their `Plain` / `RootDomain` / `Full` entries, so both paths share
/// one implementation and one set of semantics.
#[derive(Debug, Default, Clone)]
pub struct DomainMatcher {
    set: SuccinctSet,
}

impl DomainMatcher {
    /// Build from exact domains and suffix domains, both as written in the file.
    ///
    /// Empty entries and entries holding characters a domain cannot contain are
    /// skipped: they would corrupt the marker encoding, and a rule that cannot be
    /// expressed must not corrupt the rules around it.
    pub fn build<I, S>(exact: I, suffix: S) -> Self
    where
        I: IntoIterator<Item = String>,
        S: IntoIterator<Item = String>,
    {
        let mut keys: Vec<String> = Vec::new();
        for domain in suffix {
            if let Some(domain) = normalize_domain(&domain) {
                let mut key = String::with_capacity(domain.len() + 1);
                key.push(ROOT_LABEL as char);
                key.push_str(&domain);
                keys.push(reverse_domain(&key));
            }
        }
        for domain in exact {
            if let Some(domain) = normalize_domain(&domain) {
                keys.push(reverse_domain(&domain));
            }
        }
        Self {
            set: SuccinctSet::from_keys(keys),
        }
    }

    /// Decode a matcher from a `.srs` stream.
    pub fn read(reader: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            set: SuccinctSet::read(reader)?,
        })
    }

    /// Serialise exactly the way sing-box's writer does, for tests that must
    /// prove this decoder reads the reference layout and not only its own.
    #[cfg(test)]
    pub(crate) fn write_for_test(&self, out: &mut Vec<u8>) {
        self.set.write(out);
    }

    /// Whether the set holds no key at all.
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Number of keys, for diagnostics.
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// Whether `domain` is one of the keys, or ends in one on a label boundary.
    pub fn matches(&self, domain: &str) -> bool {
        match normalize_domain(domain) {
            Some(domain) => self.set.has(&domain),
            None => false,
        }
    }
}

/// Fold a domain to the form the set was built with.
///
/// DNS is ASCII-case-insensitive and a trailing root dot is optional, so both are
/// normalized here; anything else is left exactly as the file wrote it, because
/// changing a domain is how a rule starts matching something it never named.
fn normalize_domain(domain: &str) -> Option<Cow<'_, str>> {
    let trimmed = domain.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return None;
    }
    // A marker byte inside a domain would be read back as a marker.
    if trimmed
        .bytes()
        .any(|byte| byte == ROOT_LABEL || byte == PREFIX_LABEL || byte.is_ascii_control())
    {
        return None;
    }
    if trimmed.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Some(Cow::Owned(trimmed.to_ascii_lowercase()))
    } else {
        Some(Cow::Borrowed(trimmed))
    }
}

/// Reverse a string by `char`, which is what sing-box's `reverseDomain` does.
///
/// A rune-wise reversal keeps every multi-byte character intact, so a UTF-8
/// domain (or an already-punycoded one) round-trips through the encoding.
fn reverse_domain(domain: &str) -> String {
    let mut characters: Vec<char> = domain.chars().collect();
    characters.reverse();
    characters.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matcher(exact: &[&str], suffix: &[&str]) -> DomainMatcher {
        DomainMatcher::build(
            exact.iter().map(|value| value.to_string()),
            suffix.iter().map(|value| value.to_string()),
        )
    }

    #[test]
    fn exact_entries_match_only_themselves() {
        let matcher = matcher(&["www.example.com"], &[]);
        assert!(matcher.matches("www.example.com"));
        assert!(matcher.matches("WWW.EXAMPLE.COM"));
        assert!(matcher.matches("www.example.com."));
        assert!(!matcher.matches("example.com"));
        assert!(!matcher.matches("a.www.example.com"));
        assert!(!matcher.matches("notwww.example.com"));
    }

    #[test]
    fn suffix_entries_match_the_domain_and_its_subdomains() {
        let matcher = matcher(&[], &["example.com"]);
        assert!(matcher.matches("example.com"));
        assert!(matcher.matches("a.example.com"));
        assert!(matcher.matches("a.b.example.com"));
        assert!(!matcher.matches("notexample.com"));
        assert!(!matcher.matches("example.com.evil.net"));
        assert!(!matcher.matches("com"));
    }

    #[test]
    fn a_set_mixing_both_kinds_keeps_them_apart() {
        let matcher = matcher(&["exact.example.com"], &["suffix.example.org"]);
        assert!(matcher.matches("exact.example.com"));
        assert!(!matcher.matches("other.example.com"));
        assert!(matcher.matches("deep.suffix.example.org"));
        assert!(!matcher.matches("suffix.example.org.evil"));
    }

    #[test]
    fn an_empty_matcher_matches_nothing() {
        let matcher = matcher(&[], &[]);
        assert!(matcher.is_empty());
        assert!(!matcher.matches("example.com"));
    }

    #[test]
    fn unusable_entries_are_skipped_without_poisoning_the_set() {
        let matcher = matcher(&["", "  ", "example.com"], &[""]);
        assert!(matcher.matches("example.com"));
        assert_eq!(matcher.len(), 1);
    }

    /// The serialised layout is defined by sing-box, not by this crate. This
    /// hand-assembled file is the smallest possible one: a single key `a`.
    ///
    /// ```text
    /// 00                       encoding version
    /// 01  00..00 02            leaves:  1 word, node 1 set
    /// 01  00..00 06            bitmap:  1 word, bits 1 and 2 set
    /// 01  61                   labels:  1 byte, 'a'
    /// ```
    #[test]
    fn reads_a_hand_assembled_file() {
        let bytes: &[u8] = &[
            0x00, //
            0x01, 0, 0, 0, 0, 0, 0, 0, 0x02, //
            0x01, 0, 0, 0, 0, 0, 0, 0, 0x06, //
            0x01, b'a',
        ];
        let mut reader = Reader::new(bytes);
        let set = SuccinctSet::read(&mut reader).expect("valid set");
        assert!(reader.is_exhausted());
        assert!(set.has("a"));
        assert!(!set.has("b"));
        assert!(!set.has("ab"));
    }

    #[test]
    fn a_round_trip_preserves_every_answer() {
        let matcher = matcher(
            &["cdn.example.com", "api.example.com", "netflix.com"],
            &["example.com", "netflix.net"],
        );
        let mut bytes = Vec::new();
        matcher.set.write(&mut bytes);
        let mut reader = Reader::new(&bytes);
        let decoded = DomainMatcher::read(&mut reader).expect("valid");
        assert!(reader.is_exhausted());

        for domain in [
            "cdn.example.com",
            "api.example.com",
            "x.api.example.com",
            "netflix.com",
            "www.netflix.com",
            "example.com",
            "a.example.com",
            "deep.deeper.example.com",
            "netflix.net",
            "notexample.com",
            "example.com.evil.net",
            "com",
        ] {
            assert_eq!(decoded.matches(domain), matcher.matches(domain), "{domain}");
        }
    }

    #[test]
    fn a_corrupt_file_is_refused() {
        let bytes: &[u8] = &[
            0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x01, 0, 0, 0, 0, 0, 0, 0, 0x0E, 0x01, b'a',
        ];
        let mut reader = Reader::new(bytes);
        assert!(SuccinctSet::read(&mut reader).is_err());
    }

    #[test]
    fn an_unknown_encoding_version_is_refused() {
        let mut reader = Reader::new(&[0x01]);
        assert!(SuccinctSet::read(&mut reader).is_err());
    }

    /// Build a set the way the `.mrs` writer does: keys are reversed domain
    /// patterns, and a pattern's operators survive as labels.
    fn wildcard_set(patterns: &[&str]) -> SuccinctSet {
        SuccinctSet::from_keys(
            patterns
                .iter()
                .map(|pattern| pattern.chars().rev().collect())
                .collect(),
        )
    }

    /// `+.example.com` is the suffix operator: the domain and everything below it.
    #[test]
    fn the_suffix_operator_matches_every_depth_below_it() {
        let set = wildcard_set(&["+.example.com"]);
        assert!(set.has_wildcards("www.example.com"));
        assert!(set.has_wildcards("a.b.example.com"));
        // The bare domain itself is not what `+.` names.
        assert!(!set.has_wildcards("example.com"));
        // Nor is a name that merely ends in the same characters.
        assert!(!set.has_wildcards("notexample.com"));
    }

    /// `*.example.com` is one label of any text, and no more.
    #[test]
    fn the_single_label_operator_matches_exactly_one_label() {
        let set = wildcard_set(&["*.example.com"]);
        assert!(set.has_wildcards("www.example.com"));
        assert!(!set.has_wildcards("a.b.example.com"));
        assert!(!set.has_wildcards("example.com"));
    }

    #[test]
    fn a_plain_key_in_a_wildcard_set_is_exact() {
        let set = wildcard_set(&["example.com", "+.example.org"]);
        assert!(set.has_wildcards("example.com"));
        assert!(!set.has_wildcards("www.example.com"));
        assert!(set.has_wildcards("www.example.org"));
    }

    #[test]
    fn an_empty_wildcard_set_matches_nothing() {
        let set = SuccinctSet::empty();
        assert!(!set.has_wildcards("example.com"));
    }

    #[test]
    fn a_large_set_keeps_every_entry() {
        let suffix: Vec<String> = (0..20_000)
            .map(|index| format!("host{index}.example.com"))
            .collect();
        let matcher = DomainMatcher::build(Vec::new(), suffix);
        assert_eq!(matcher.len(), 20_000);
        for index in [0usize, 1, 9_999, 19_999] {
            assert!(matcher.matches(&format!("host{index}.example.com")));
            assert!(matcher.matches(&format!("sub.host{index}.example.com")));
            assert!(!matcher.matches(&format!("host{index}.example.org")));
        }
        assert!(!matcher.matches("host20000.example.com"));
    }
}
