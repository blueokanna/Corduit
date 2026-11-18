//! The other family's binary rule set (`.mrs`, version 1).
//!
//! A `.mrs` file is **one zstd frame**. The container magic and everything after
//! it live inside the compressed stream, which is why recognising this format
//! cannot be done by peeking at bytes — the file starts with the zstd magic and
//! nothing else.
//!
//! ```text
//! zstd frame → {
//!     "MRS" 0x01            4 bytes, magic + container version
//!     behavior              1 byte: 0 = domain set, 1 = address set
//!     count                 i64 big-endian, entries in the payload
//!     extra length          i64 big-endian, reserved; that many bytes follow
//!     payload               domain set, or address set
//! }
//!
//! domain set  := 0x01, i64 leaves count,  u64 BE × count,
//!                i64 bitmap count,  u64 BE × count,
//!                i64 labels count,  bytes × count
//! address set := 0x01, i64 range count,
//!                (16-byte from, 16-byte to) × count
//! ```
//!
//! The layout above is transcribed from the reference implementation's reader and
//! converter (`rules/provider/mrs_reader.go`, `component/trie/domain_set_bin.go`,
//! `component/cidr/ipcidr_set_bin.go`, tag v1.19.24). An interop format has to name
//! what it interoperates with: these four paragraphs are the whole specification,
//! and anyone can check them against those three files.
//!
//! Only the two behaviors the format's converter emits are defined: a *classical*
//! payload has no binary encoding, so a file claiming one is refused with the
//! byte named rather than guessed at.
//!
//! The domain set is the same compressed tree sing-box ships, but its keys use a
//! different marker vocabulary — `+` for a suffix and `*` for one label of any
//! depth — so it is walked by the wildcard matcher and not by the exact/suffix
//! walker. Addresses are inclusive ranges of sixteen-byte addresses
//! with IPv4 mapped into IPv6, so a v4 range has to be unmapped to compare
//! against a v4 destination.

use super::reader::Reader;
use super::succinct::SuccinctSet;
use super::{DomainCondition, HeadlessRule, MAX_DECODED_BYTES};
use crate::engine::error::{Error, Result};
use crate::engine::geo::ipset::IpRangeSet;
use std::io::Read;
use std::net::{IpAddr, Ipv6Addr};

/// Magic inside the compressed stream: `MRS` plus the container version.
pub const MAGIC: [u8; 4] = [b'M', b'R', b'S', 1];

/// First four bytes of every zstd frame.
///
/// This is the only thing a `.mrs` file shows before it is decompressed, so it is
/// what detection keys on.
pub const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

/// Domain set payload.
const BEHAVIOR_DOMAIN: u8 = 0;
/// Address set payload.
const BEHAVIOR_IP_CIDR: u8 = 1;

/// Decode a `.mrs` payload into one executable rule.
pub fn decode(bytes: &[u8]) -> Result<Vec<HeadlessRule>> {
    if !bytes.starts_with(&ZSTD_MAGIC) {
        return Err(Error::config(
            "Binary rule set does not start with the zstd magic, so it is not a .mrs payload",
        ));
    }
    let payload = inflate(bytes)?;
    parse(&payload)
}

/// Decompress the frame, refusing anything that inflates past the budget.
fn inflate(compressed: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut decoder = zstd::stream::read::Decoder::new(compressed).map_err(|error| {
        Error::config(format!(
            "Binary rule set is not a valid zstd stream: {error}"
        ))
    })?;
    decoder
        .by_ref()
        .take(MAX_DECODED_BYTES as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|error| {
            Error::config(format!(
                "Binary rule set could not be decompressed: {error}"
            ))
        })?;
    if out.len() > MAX_DECODED_BYTES {
        return Err(Error::config(format!(
            "Binary rule set expands past the {} MiB limit",
            MAX_DECODED_BYTES / (1024 * 1024)
        )));
    }
    Ok(out)
}

/// Decode the decompressed container.
fn parse(payload: &[u8]) -> Result<Vec<HeadlessRule>> {
    let mut reader = Reader::new(payload);

    let header = reader.take(4)?;
    if header != MAGIC {
        return Err(Error::config(
            "zstd payload is not an MRS rule set: the inner magic is missing",
        ));
    }

    let behavior = reader.u8()?;
    let count = read_i64(&mut reader, "entry")?;
    if count == 0 {
        return Err(Error::config(
            "Binary rule set declares zero entries; it would match nothing",
        ));
    }

    let extra = read_i64(&mut reader, "reserved")?;
    if extra > 0 {
        reader.take(extra)?;
    }

    let rule = match behavior {
        BEHAVIOR_DOMAIN => {
            let set = SuccinctSet::read_wire_v1(&mut reader)?;
            HeadlessRule {
                domains: Some(DomainCondition::Wildcard(set)),
                ..HeadlessRule::default()
            }
        }
        BEHAVIOR_IP_CIDR => HeadlessRule {
            ip_cidr: Some(read_ip_ranges(&mut reader)?),
            ..HeadlessRule::default()
        },
        other => {
            return Err(Error::config(format!(
                "Binary rule set declares behavior {other}; only a domain set (0) and an address \
                 set (1) have a binary encoding"
            )));
        }
    };

    Ok(vec![rule])
}

/// Read a signed sixty-four-bit count, which is how this container spells every
/// length and count.
fn read_i64(reader: &mut Reader<'_>, field: &str) -> Result<usize> {
    let raw = reader.u64_be()?;
    if raw > i64::MAX as u64 {
        return Err(Error::config(format!(
            "Binary rule set declares a negative or oversized {field} count"
        )));
    }
    usize::try_from(raw).map_err(|_| {
        Error::config(format!(
            "Binary rule set {field} count does not fit this platform"
        ))
    })
}

/// Read the address set: inclusive ranges of sixteen-byte addresses.
fn read_ip_ranges(reader: &mut Reader<'_>) -> Result<IpRangeSet> {
    let version = reader.u8()?;
    if version != 1 {
        return Err(Error::config(format!(
            "Binary rule set address set uses unknown encoding version {version}"
        )));
    }
    let count = read_i64(reader, "range")?;
    if count == 0 {
        return Err(Error::config(
            "Binary rule set address set declares no ranges",
        ));
    }
    if count.saturating_mul(32) > reader.remaining() {
        return Err(Error::config(format!(
            "Binary rule set declares {count} ranges but only {} bytes remain",
            reader.remaining()
        )));
    }

    let mut set = IpRangeSet::new();
    for _ in 0..count {
        let from = read_address(reader)?;
        let to = read_address(reader)?;
        set.insert_range(from, to).map_err(|error| {
            Error::config(format!(
                "Binary rule set address range is unusable: {error}"
            ))
        })?;
    }
    set.finish();
    Ok(set)
}

/// One end of a range: sixteen bytes, with IPv4 carried in its mapped form.
fn read_address(reader: &mut Reader<'_>) -> Result<IpAddr> {
    let bytes = reader.take(16)?;
    let mut octets = [0u8; 16];
    octets.copy_from_slice(bytes);
    let address = Ipv6Addr::from(octets);
    // The writer stores every address as sixteen bytes, so an IPv4 address
    // arrives mapped; unmapping it is what lets a v4 destination compare equal.
    Ok(match address.to_ipv4_mapped() {
        Some(ipv4) => IpAddr::V4(ipv4),
        None => IpAddr::V6(address),
    })
}

/// Serialise a payload the way the format's converter does, for the tests that
/// prove this decoder reads the reference layout and not only its own writer.
#[cfg(test)]
pub(crate) fn encode_for_test(behavior: u8, body: &[u8], count: usize, extra: &[u8]) -> Vec<u8> {
    let mut plain = Vec::new();
    plain.extend_from_slice(&MAGIC);
    plain.push(behavior);
    plain.extend_from_slice(&(count as i64).to_be_bytes());
    plain.extend_from_slice(&(extra.len() as i64).to_be_bytes());
    plain.extend_from_slice(extra);
    plain.extend_from_slice(body);
    zstd::stream::encode_all(plain.as_slice(), 3).expect("zstd encodes in tests")
}

#[cfg(test)]
mod tests {
    use super::super::{RuleSet, RuleSetInput};
    use super::*;

    /// An address set body holding the given inclusive ranges.
    fn address_body(ranges: &[(&str, &str)]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(1);
        body.extend_from_slice(&(ranges.len() as i64).to_be_bytes());
        for (from, to) in ranges {
            for address in [*from, *to] {
                let parsed: IpAddr = address.parse().expect("address");
                body.extend_from_slice(&match parsed {
                    IpAddr::V4(ipv4) => ipv4.to_ipv6_mapped().octets(),
                    IpAddr::V6(ipv6) => ipv6.octets(),
                });
            }
        }
        body
    }

    fn domain_body(matcher: &str) -> Vec<u8> {
        let set = SuccinctSet::from_keys(vec![matcher.chars().rev().collect()]);
        let mut body = Vec::new();
        set.write_wire_v1(&mut body);
        body
    }

    #[test]
    fn decodes_a_domain_set() {
        let payload = encode_for_test(BEHAVIOR_DOMAIN, &domain_body("example.com"), 1, &[]);
        let rules = decode(&payload).expect("decodes");
        assert_eq!(rules.len(), 1);
        let set = RuleSet::new(rules);
        assert!(set.matches(&RuleSetInput {
            domain: Some("example.com"),
            ..RuleSetInput::default()
        }));
        assert!(!set.matches(&RuleSetInput {
            domain: Some("other.example.com"),
            ..RuleSetInput::default()
        }));
        // A domain condition never needs a DNS lookup.
        assert!(!set.wants_dst_ip());
    }

    #[test]
    fn decodes_an_address_set_with_ipv4_stored_as_mapped() {
        let body = address_body(&[
            ("10.0.0.0", "10.255.255.255"),
            ("2001:db8::", "2001:db8::ff"),
        ]);
        let payload = encode_for_test(BEHAVIOR_IP_CIDR, &body, 2, &[]);
        let rules = decode(&payload).expect("decodes");
        let set = RuleSet::new(rules);
        assert!(set.wants_dst_ip());
        assert!(set.matches(&RuleSetInput {
            dst_ip: Some("10.1.2.3".parse().expect("ip")),
            ..RuleSetInput::default()
        }));
        assert!(!set.matches(&RuleSetInput {
            dst_ip: Some("11.1.2.3".parse().expect("ip")),
            ..RuleSetInput::default()
        }));
        assert!(set.matches(&RuleSetInput {
            dst_ip: Some("2001:db8::20".parse().expect("ip")),
            ..RuleSetInput::default()
        }));
    }

    #[test]
    fn an_unresolved_domain_does_not_decide_an_address_set() {
        let body = address_body(&[("10.0.0.0", "10.255.255.255")]);
        let payload = encode_for_test(BEHAVIOR_IP_CIDR, &body, 1, &[]);
        let set = RuleSet::new(decode(&payload).expect("decodes"));
        // The router resolved an answer; `no-resolve` keeps it hidden.
        let resolved = ["10.1.2.3".parse().expect("ip")];
        assert!(!set.matches(&RuleSetInput {
            domain: Some("intranet.example"),
            resolved: &resolved,
            no_resolve: true,
            ..RuleSetInput::default()
        }));
        assert!(set.matches(&RuleSetInput {
            domain: Some("intranet.example"),
            resolved: &resolved,
            ..RuleSetInput::default()
        }));
    }

    #[test]
    fn the_reserved_field_is_skipped() {
        let body = domain_body("example.com");
        let payload = encode_for_test(BEHAVIOR_DOMAIN, &body, 1, &[1, 2, 3, 4]);
        let rules = decode(&payload).expect("decodes");
        assert!(RuleSet::new(rules).matches(&RuleSetInput {
            domain: Some("example.com"),
            ..RuleSetInput::default()
        }));
    }

    #[test]
    fn a_classical_or_unknown_behavior_is_refused_by_number() {
        let payload = encode_for_test(2, &domain_body("example.com"), 1, &[]);
        let error = decode(&payload).expect_err("no binary encoding for classical");
        assert!(error.to_string().contains("behavior 2"), "{error}");
    }

    #[test]
    fn the_container_should_be_zstd_and_should_carry_its_magic() {
        assert!(decode(b"not zstd at all").is_err());

        // A zstd frame without the inner magic is not a rule set.
        let not_mrs = zstd::stream::encode_all(&b"hello"[..], 3).expect("zstd");
        let error = decode(&not_mrs).expect_err("inner magic missing");
        assert!(error.to_string().contains("magic"), "{error}");
    }

    #[test]
    fn an_empty_or_truncated_payload_is_an_error() {
        let body = domain_body("example.com");
        let payload = encode_for_test(BEHAVIOR_DOMAIN, &body, 1, &[]);
        assert!(decode(&payload[..payload.len() - 4]).is_err());

        let empty = encode_for_test(BEHAVIOR_DOMAIN, &domain_body("example.com"), 0, &[]);
        assert!(decode(&empty).is_err());
    }

    #[test]
    fn a_declared_count_larger_than_the_bytes_is_refused() {
        let mut body = Vec::new();
        body.push(1);
        body.extend_from_slice(&9_999_999i64.to_be_bytes());
        let payload = encode_for_test(BEHAVIOR_IP_CIDR, &body, 1, &[]);
        assert!(decode(&payload).is_err());
    }
}
