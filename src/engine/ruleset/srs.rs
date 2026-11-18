//! The sing-box binary rule set (`.srs`).
//!
//! Layout, as written by `sing-box`'s `common/srs` package:
//!
//! ```text
//! "SRS"            3 bytes
//! version          1 byte
//! zlib stream      → a uvarint rule count, then that many rules
//!
//! rule    := u8 kind, then kind 0 = default | kind 1 = logical
//! default := (u8 item, item payload)*, 0xFF, u8 invert
//! logical := u8 mode (0 and, 1 or), uvarint count, rule*, u8 invert
//! ```
//!
//! The domain item is the compressed domain set in [`super::succinct`]; an IP
//! item is a sorted list of inclusive address ranges. Both are decoded here
//! without materialising the intermediate text form the JSON rule set carries,
//! which is why a `.srs` file loads in a fraction of the memory its YAML
//! equivalent needs.
//!
//! ## What is refused, and why
//!
//! A rule set may constrain things this engine does not observe: DNS query
//! types, Wi-Fi SSIDs, Android package names, interface cost. Those items are
//! *recognised* and the set is rejected with the item named. The alternative —
//! dropping the condition — turns a rule that says "ads over Wi-Fi only" into
//! "ads, always", which is a routing decision nobody wrote. Refusing keeps the
//! failure visible at load time, where it costs one line in a log, instead of
//! hiding it in the shape of the traffic.

use super::reader::Reader;
use super::succinct::DomainMatcher;
use super::{
    HeadlessRule, LogicalMode, MAX_DECODED_BYTES, Transport, compile_regex, parse_port_ranges,
};
use crate::engine::error::{Error, Result};
use crate::engine::geo::ipset::IpRangeSet;
use std::io::Read;

/// Magic that starts the file: `SRS`.
pub const MAGIC: [u8; 3] = [0x53, 0x52, 0x53];

/// Oldest format version this decoder reads.
pub const MIN_VERSION: u8 = 1;

/// Newest format version this decoder reads.
///
/// Versions 2 to 5 only *add* item types (AdGuard domains, network conditions,
/// interface addresses, package-name regexes); the framing never changed, which
/// is why one decoder covers all of them and why an unknown item type is the
/// real version check.
pub const MAX_VERSION: u8 = 5;

/// Nesting limit for logical rules, matching the writer's own bound.
const MAX_LOGICAL_DEPTH: usize = 100;

/// Rule kind: a list of conditions.
const RULE_DEFAULT: u8 = 0;
/// Rule kind: `and` / `or` over child rules.
const RULE_LOGICAL: u8 = 1;

/// Terminates a default rule's item list.
const ITEM_FINAL: u8 = 0xFF;

/// Decode a whole `.srs` payload.
pub fn decode(bytes: &[u8]) -> Result<Vec<HeadlessRule>> {
    if bytes.len() < 4 {
        return Err(Error::config(
            "Sing-box rule set is shorter than its four-byte header",
        ));
    }
    if bytes[..3] != MAGIC {
        return Err(Error::config(
            "Sing-box rule set does not start with the 'SRS' magic",
        ));
    }
    let version = bytes[3];
    if !(MIN_VERSION..=MAX_VERSION).contains(&version) {
        return Err(Error::config(format!(
            "Sing-box rule set version {version} is not supported; this build reads versions \
             {MIN_VERSION} to {MAX_VERSION}"
        )));
    }

    let decoded = inflate(&bytes[4..])?;
    let mut reader = Reader::new(&decoded);
    let count = reader.count(1)?;
    let mut rules = Vec::with_capacity(count.min(4096));
    let mut budget = RuleBudget::default();
    for index in 0..count {
        let rule = read_rule(&mut reader, 0, &mut budget).map_err(|error| {
            Error::config(format!(
                "Sing-box rule set (version {version}) rule {index}: {error}"
            ))
        })?;
        rules.push(rule);
    }
    Ok(rules)
}

/// Decompress the body, refusing anything that inflates past the budget.
///
/// The limit is what separates "this file is big" from "this file is a
/// decompression bomb"; a rule set that needs more than
/// [`MAX_DECODED_BYTES`] is not a rule set.
fn inflate(compressed: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut decoder = flate2::read::ZlibDecoder::new(compressed);
    decoder
        .by_ref()
        .take(MAX_DECODED_BYTES as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|error| {
            Error::config(format!(
                "Sing-box rule set body is not a valid zlib stream: {error}"
            ))
        })?;
    if out.len() > MAX_DECODED_BYTES {
        return Err(Error::config(format!(
            "Sing-box rule set expands past the {} MiB limit",
            MAX_DECODED_BYTES / (1024 * 1024)
        )));
    }
    Ok(out)
}

/// Decode one rule, default or logical.
/// How many expensive entries a rule set has spent so far.
///
/// Domains are bounded by the decoded bytes, but a regular expression costs at
/// compile time and a keyword costs a scan per connection, so both are counted
/// against their own ceiling while the file is read rather than after it is built.
#[derive(Default)]
struct RuleBudget {
    regexes: usize,
    keywords: usize,
}

impl RuleBudget {
    fn spend_regexes(&mut self, count: usize) -> Result<()> {
        self.regexes = self.regexes.saturating_add(count);
        if self.regexes > super::MAX_RULE_SET_REGEXES {
            return Err(Error::config(format!(
                "Rule set declares more than {} regular expressions, the ceiling for one set",
                super::MAX_RULE_SET_REGEXES
            )));
        }
        Ok(())
    }

    fn spend_keywords(&mut self, count: usize) -> Result<()> {
        self.keywords = self.keywords.saturating_add(count);
        if self.keywords > super::MAX_RULE_SET_KEYWORDS {
            return Err(Error::config(format!(
                "Rule set declares more than {} domain keywords, the ceiling for one set",
                super::MAX_RULE_SET_KEYWORDS
            )));
        }
        Ok(())
    }
}

fn read_rule(
    reader: &mut Reader<'_>,
    depth: usize,
    budget: &mut RuleBudget,
) -> Result<HeadlessRule> {
    if depth > MAX_LOGICAL_DEPTH {
        return Err(Error::config(format!(
            "Logical rules nest deeper than {MAX_LOGICAL_DEPTH} levels"
        )));
    }
    match reader.u8()? {
        RULE_DEFAULT => read_default_rule(reader, budget),
        RULE_LOGICAL => read_logical_rule(reader, depth, budget),
        other => Err(Error::config(format!(
            "Rule kind {other} is neither a default (0) nor a logical (1) rule"
        ))),
    }
}

/// Decode a default rule: `(item, payload)*`, `0xFF`, invert.
fn read_default_rule(reader: &mut Reader<'_>, budget: &mut RuleBudget) -> Result<HeadlessRule> {
    let mut rule = HeadlessRule::default();
    let mut conditions = 0usize;
    loop {
        let item = reader.u8()?;
        if item == ITEM_FINAL {
            rule.invert = reader.bool()?;
            if conditions == 0 {
                return Err(Error::config(
                    "Rule set rule has no conditions, so it would match every connection",
                ));
            }
            return Ok(rule);
        }
        conditions += 1;
        match item {
            ITEM_NETWORK => {
                rule.network = read_network(reader)?;
            }
            ITEM_DOMAIN => {
                let domains = DomainMatcher::read(reader)?;
                if domains.is_empty() {
                    return Err(Error::config("Rule set domain condition is empty"));
                }
                rule.domains = Some(super::DomainCondition::Marked(domains));
            }
            ITEM_DOMAIN_KEYWORD => {
                rule.domain_keywords = read_strings(reader)?;
                budget.spend_keywords(rule.domain_keywords.len())?;
            }
            ITEM_DOMAIN_REGEX => {
                let patterns = read_strings(reader)?;
                budget.spend_regexes(patterns.len())?;
                for pattern in patterns {
                    rule.domain_regexes.push(compile_regex(&pattern)?);
                }
            }
            ITEM_SOURCE_IP_CIDR => {
                rule.src_ip_cidr = Some(read_ip_set(reader)?);
            }
            ITEM_IP_CIDR => {
                rule.ip_cidr = Some(read_ip_set(reader)?);
            }
            ITEM_SOURCE_PORT => {
                rule.src_ports = read_port_list(reader)?;
            }
            ITEM_SOURCE_PORT_RANGE => {
                rule.src_ports = parse_port_ranges(read_strings(reader)?)?;
            }
            ITEM_PORT => {
                rule.ports = read_port_list(reader)?;
            }
            ITEM_PORT_RANGE => {
                rule.ports = parse_port_ranges(read_strings(reader)?)?;
            }
            ITEM_PROCESS_NAME => {
                rule.process_names = read_strings(reader)?;
            }
            ITEM_PROCESS_PATH => {
                rule.process_paths = read_strings(reader)?;
            }
            ITEM_PROCESS_PATH_REGEX => {
                let patterns = read_strings(reader)?;
                budget.spend_regexes(patterns.len())?;
                for pattern in patterns {
                    rule.process_path_regexes.push(compile_regex(&pattern)?);
                }
            }
            other => {
                return Err(Error::config(format!(
                    "Rule set uses the '{}' condition, which this engine cannot evaluate. \
                     Remove it, or convert the rule set without it, so the remaining conditions \
                     are not silently dropped",
                    item_name(other)
                )));
            }
        }
    }
}

/// Decode a logical rule: `mode`, child count, children, invert.
fn read_logical_rule(
    reader: &mut Reader<'_>,
    depth: usize,
    budget: &mut RuleBudget,
) -> Result<HeadlessRule> {
    let mode = match reader.u8()? {
        0 => LogicalMode::And,
        1 => LogicalMode::Or,
        other => {
            return Err(Error::config(format!(
                "Logical rule mode {other} is neither 'and' (0) nor 'or' (1)"
            )));
        }
    };
    let count = reader.count(1)?;
    if count == 0 {
        return Err(Error::config("Logical rule has no child rules"));
    }
    let mut children = Vec::with_capacity(count.min(64));
    for _ in 0..count {
        children.push(read_rule(reader, depth + 1, budget)?);
    }
    let invert = reader.bool()?;
    Ok(HeadlessRule {
        invert,
        logical: Some((mode, children)),
        ..HeadlessRule::default()
    })
}

/// `network` item: one or more of `tcp` / `udp`.
fn read_network(reader: &mut Reader<'_>) -> Result<Vec<Transport>> {
    let mut networks = Vec::new();
    for value in read_strings(reader)? {
        let transport = Transport::parse(&value).ok_or_else(|| {
            Error::config(format!(
                "Rule set network '{value}' is neither 'tcp' nor 'udp'"
            ))
        })?;
        if !networks.contains(&transport) {
            networks.push(transport);
        }
    }
    if networks.is_empty() {
        return Err(Error::config("Rule set network condition is empty"));
    }
    Ok(networks)
}

/// A length-prefixed list of UTF-8 strings.
fn read_strings(reader: &mut Reader<'_>) -> Result<Vec<Box<str>>> {
    let count = reader.count(1)?;
    let mut values = Vec::with_capacity(count.min(4096));
    for _ in 0..count {
        values.push(reader.string()?.into());
    }
    Ok(values)
}

/// A list of single ports.
fn read_port_list(reader: &mut Reader<'_>) -> Result<Vec<(u16, u16)>> {
    let count = reader.count(2)?;
    let mut ranges = Vec::with_capacity(count.min(4096));
    for _ in 0..count {
        let port = reader.u16_be()?;
        ranges.push((port, port));
    }
    Ok(ranges)
}

/// An address set: version byte `1`, `u64` count, then inclusive ranges.
fn read_ip_set(reader: &mut Reader<'_>) -> Result<IpRangeSet> {
    let version = reader.u8()?;
    if version != 1 {
        return Err(Error::config(format!(
            "Rule set address set uses version {version}; only version 1 is defined"
        )));
    }
    // Eight bytes of big-endian count, not a varint: the reference writer
    // encodes the range count with `encoding/binary`, and every range is two
    // address fields of at least five bytes each.
    let count = reader.u64_be()?;
    if count > (reader.remaining() / 10) as u64 {
        return Err(Error::config(format!(
            "Rule set address set declares {count} ranges but only {} bytes remain",
            reader.remaining()
        )));
    }
    let mut set = IpRangeSet::new();
    for _ in 0..count {
        let from = read_ip_set_bound(reader)?;
        let to = read_ip_set_bound(reader)?;
        set.insert_range(from, to).map_err(|error| {
            Error::config(format!("Rule set address range is unusable: {error}"))
        })?;
    }
    set.finish();
    if set.is_empty() && count > 0 {
        return Err(Error::config("Rule set address set decoded to nothing"));
    }
    Ok(set)
}

/// One end of an address range: a length byte that must be 4 or 16, then that
/// many address bytes.
fn read_ip_set_bound(reader: &mut Reader<'_>) -> Result<std::net::IpAddr> {
    let length = reader.uvarint()?;
    match length {
        4 => {
            let bytes = reader.take(4)?;
            Ok(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                bytes[0], bytes[1], bytes[2], bytes[3],
            )))
        }
        16 => {
            let bytes = reader.take(16)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(bytes);
            Ok(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
        other => Err(Error::config(format!(
            "Rule set address is {other} bytes; addresses are 4 or 16"
        ))),
    }
}

// The item numbers are the ones `sing-box/common/srs` assigns; they are part of
// the file format, so they are named rather than spelled inline.

const ITEM_NETWORK: u8 = 1;
const ITEM_DOMAIN: u8 = 2;
const ITEM_DOMAIN_KEYWORD: u8 = 3;
const ITEM_DOMAIN_REGEX: u8 = 4;
const ITEM_SOURCE_IP_CIDR: u8 = 5;
const ITEM_IP_CIDR: u8 = 6;
const ITEM_SOURCE_PORT: u8 = 7;
const ITEM_SOURCE_PORT_RANGE: u8 = 8;
const ITEM_PORT: u8 = 9;
const ITEM_PORT_RANGE: u8 = 10;
const ITEM_PROCESS_NAME: u8 = 11;
const ITEM_PROCESS_PATH: u8 = 12;
const ITEM_PROCESS_PATH_REGEX: u8 = 17;

/// Human name of an item this decoder does not evaluate, for the refusal.
const fn item_name(item: u8) -> &'static str {
    match item {
        0 => "query_type",
        13 => "package_name",
        14 => "wifi_ssid",
        15 => "wifi_bssid",
        16 => "adguard_domain",
        18 => "network_type",
        19 => "network_is_expensive",
        20 => "network_is_constrained",
        21 => "network_interface_address",
        22 => "default_interface_address",
        23 => "package_name_regex",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::super::{LogicalMode, RuleSetInput};
    use super::*;

    /// Build a payload the way the writer does: header, zlib body.
    fn wrap(version: u8, body: &[u8]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(body).expect("compress");
        let compressed = encoder.finish().expect("finish");
        let mut out = Vec::with_capacity(compressed.len() + 4);
        out.extend_from_slice(&MAGIC);
        out.push(version);
        out.extend_from_slice(&compressed);
        out
    }

    fn uvarint(out: &mut Vec<u8>, mut value: u64) {
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

    fn push_string(out: &mut Vec<u8>, value: &str) {
        uvarint(out, value.len() as u64);
        out.extend_from_slice(value.as_bytes());
    }

    fn finish_default(out: &mut Vec<u8>, invert: bool) {
        out.push(ITEM_FINAL);
        out.push(u8::from(invert));
    }

    /// One domain-suffix rule for `example.com`, built by the reference encoder's
    /// rules: item 2, then the compressed domain set, then the final marker.
    fn domain_rule_payload(domain: &str) -> Vec<u8> {
        let matcher = DomainMatcher::build(std::iter::empty::<String>(), [domain.to_string()]);
        let mut set_bytes = Vec::new();
        matcher.write_for_test(&mut set_bytes);

        let mut body = Vec::new();
        uvarint(&mut body, 1); // one rule
        body.push(RULE_DEFAULT);
        body.push(ITEM_DOMAIN);
        body.extend_from_slice(&set_bytes);
        finish_default(&mut body, false);
        body
    }

    #[test]
    fn decodes_a_domain_suffix_rule() {
        let rules = decode(&wrap(5, &domain_rule_payload("example.com"))).expect("decode");
        assert_eq!(rules.len(), 1);
        let set = super::super::RuleSet::new(rules);
        assert!(set.matches(&RuleSetInput {
            domain: Some("www.example.com"),
            ..RuleSetInput::default()
        }));
        assert!(!set.matches(&RuleSetInput {
            domain: Some("example.org"),
            ..RuleSetInput::default()
        }));
    }

    #[test]
    fn decodes_ip_ranges_ports_and_process_names_together() {
        let mut body = Vec::new();
        uvarint(&mut body, 1);
        body.push(RULE_DEFAULT);

        // ip_cidr: 10.0.0.0/8 as one range.
        body.push(ITEM_IP_CIDR);
        body.push(1);
        body.extend_from_slice(&1u64.to_be_bytes());
        uvarint(&mut body, 4);
        body.extend_from_slice(&[10, 0, 0, 0]);
        uvarint(&mut body, 4);
        body.extend_from_slice(&[10, 255, 255, 255]);

        // port: 443
        body.push(ITEM_PORT);
        uvarint(&mut body, 1);
        body.extend_from_slice(&443u16.to_be_bytes());

        // process_name: qbittorrent
        body.push(ITEM_PROCESS_NAME);
        uvarint(&mut body, 1);
        push_string(&mut body, "qbittorrent.exe");

        finish_default(&mut body, false);

        let rules = decode(&wrap(4, &body)).expect("decode");
        let set = super::super::RuleSet::new(rules);
        let matching = RuleSetInput {
            dst_ip: Some("10.1.2.3".parse().expect("ip")),
            dst_port: Some(443),
            process_name: Some(r"Q:\qBittorrent\qbittorrent.exe"),
            ..RuleSetInput::default()
        };
        assert!(set.matches(&matching));
        // Dropping any one condition drops the whole rule: the conditions of one
        // rule are ANDed.
        assert!(!set.matches(&RuleSetInput {
            dst_ip: None,
            ..matching
        }));
        assert!(!set.matches(&RuleSetInput {
            dst_ip: Some("11.1.2.3".parse().expect("ip")),
            ..matching
        }));
        assert!(set.wants_dst_ip());
    }

    #[test]
    fn decodes_a_logical_rule() {
        let mut body = Vec::new();
        uvarint(&mut body, 1);
        body.push(RULE_LOGICAL);
        body.push(1); // or
        uvarint(&mut body, 2);

        // child 1: DOMAIN-KEYWORD ads
        body.push(RULE_DEFAULT);
        body.push(ITEM_DOMAIN_KEYWORD);
        uvarint(&mut body, 1);
        push_string(&mut body, "ads");
        finish_default(&mut body, false);

        // child 2: PORT 8080
        body.push(RULE_DEFAULT);
        body.push(ITEM_PORT);
        uvarint(&mut body, 1);
        body.extend_from_slice(&8080u16.to_be_bytes());
        finish_default(&mut body, false);

        body.push(0); // invert

        let rules = decode(&wrap(2, &body)).expect("decode");
        assert!(matches!(
            rules[0].logical.as_ref().map(|(mode, _)| *mode),
            Some(LogicalMode::Or)
        ));
        let set = super::super::RuleSet::new(rules);
        assert!(set.matches(&RuleSetInput {
            domain: Some("ads.example.com"),
            ..RuleSetInput::default()
        }));
        assert!(set.matches(&RuleSetInput {
            dst_port: Some(8080),
            ..RuleSetInput::default()
        }));
        assert!(!set.matches(&RuleSetInput {
            dst_port: Some(80),
            ..RuleSetInput::default()
        }));
    }

    #[test]
    fn an_unknown_condition_is_refused_by_name() {
        let mut body = Vec::new();
        uvarint(&mut body, 1);
        body.push(RULE_DEFAULT);
        body.push(14); // wifi_ssid
        uvarint(&mut body, 1);
        push_string(&mut body, "home");
        finish_default(&mut body, false);

        let error = decode(&wrap(3, &body)).expect_err("unsupported item");
        let message = error.to_string();
        assert!(message.contains("wifi_ssid"), "{message}");
    }

    #[test]
    fn a_rule_without_conditions_is_refused() {
        let mut body = Vec::new();
        uvarint(&mut body, 1);
        body.push(RULE_DEFAULT);
        finish_default(&mut body, false);
        assert!(decode(&wrap(1, &body)).is_err());
    }

    #[test]
    fn header_problems_are_reported_before_anything_else() {
        assert!(decode(b"SRS").is_err());
        assert!(decode(b"SRX\x01").is_err());
        assert!(decode(b"SRS\x00").is_err());
        assert!(decode(b"SRS\x09").is_err());
        // Right header, body that is not zlib.
        assert!(decode(b"SRS\x05not zlib at all").is_err());
    }

    #[test]
    fn a_truncated_body_is_an_error_not_a_partial_set() {
        let mut payload = domain_rule_payload("example.com");
        payload.truncate(payload.len() - 6);
        assert!(decode(&wrap(5, &payload)).is_err());
    }

    #[test]
    fn every_version_in_range_is_accepted() {
        for version in MIN_VERSION..=MAX_VERSION {
            let rules = decode(&wrap(version, &domain_rule_payload("example.com")))
                .unwrap_or_else(|error| panic!("version {version}: {error}"));
            assert_eq!(rules.len(), 1, "version {version}");
        }
    }
}
