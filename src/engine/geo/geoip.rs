//! The `geoip.dat` country database (`GEOIP,CN`, `GEOIP,LAN`, …).
//!
//! ```text
//! GeoIPList { repeated GeoIP entry = 1 }
//! GeoIP     { string country_code = 1; repeated CIDR cidr = 2; bool inverse_match = 3 }
//! CIDR      { bytes ip = 1; uint32 prefix = 2 }
//! ```
//!
//! This is the same file v2ray and Mihomo load, and it is the *only* address
//! source available to a profile that ships `geoip.dat` instead of
//! `Country.mmdb` — which is what that side ships. Both are supported; see
//! [`crate::engine::geoip`] for the order they are consulted in.
//!
//! Categories are decoded lazily for the same reason geosite's are: the file
//! carries every country on earth and a profile names a handful. What is held
//! eagerly is the country list — the names an operator can be told about when a
//! `GEOIP` rule names something the database does not have.

use super::ipset::IpRangeSet;
use super::proto::Decoder;
use crate::engine::error::{Error, Result};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::ops::Range;
use std::sync::Arc;

/// One country's position inside the file.
#[derive(Debug)]
struct EntryMeta {
    /// Uppercase country code, e.g. `CN`.
    code: Box<str>,
    /// Byte range of the `GeoIP` message body.
    span: Range<usize>,
}

/// A country decoded into an address set.
#[derive(Debug)]
pub struct CompiledGeoIp {
    code: Box<str>,
    ranges: IpRangeSet,
    /// Whether the database declares the *complement* of these ranges, which is
    /// how some builds express "everything that is not China".
    inverse: bool,
    /// Number of CIDRs decoded, for diagnostics.
    cidr_count: usize,
    /// CIDRs that could not be used, with the reason.
    rejected: Vec<String>,
}

impl CompiledGeoIp {
    /// The country code.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Number of ranges after merging.
    pub fn range_count(&self) -> usize {
        self.ranges.range_count()
    }

    /// Number of CIDRs the category declared.
    pub fn len(&self) -> usize {
        self.cidr_count
    }

    /// Whether the category compiled to nothing usable.
    pub fn is_empty(&self) -> bool {
        self.cidr_count == 0
    }

    /// CIDRs that could not be used.
    pub fn rejected(&self) -> &[String] {
        &self.rejected
    }

    fn compile(code: &str, message: &[u8]) -> Result<Self> {
        let mut ranges = IpRangeSet::new();
        let mut inverse = false;
        let mut cidr_count = 0usize;
        let mut rejected = Vec::new();

        let mut entry = Decoder::new(message);
        while let Some(field) = entry.next_field()? {
            match field.number() {
                2 => {
                    cidr_count += 1;
                    let mut cidr = field.decoder()?;
                    let mut address: Option<Vec<u8>> = None;
                    let mut prefix = 32u32;
                    while let Some(inner) = cidr.next_field()? {
                        match inner.number() {
                            1 => address = Some(inner.bytes()?.to_vec()),
                            2 => prefix = inner.varint_u32()?,
                            _ => {}
                        }
                    }
                    match address {
                        Some(address) if ranges.insert_wire_cidr(&address, prefix) => {}
                        Some(address) => rejected.push(format!(
                            "CIDR with {}-byte address and /{prefix} prefix",
                            address.len()
                        )),
                        None => rejected.push("CIDR without an address".to_string()),
                    }
                }
                3 => inverse = field.varint_u64()? != 0,
                _ => {}
            }
        }
        ranges.finish();

        Ok(Self {
            code: code.into(),
            ranges,
            inverse,
            cidr_count,
            rejected,
        })
    }

    /// Whether `address` is in this country.
    pub fn contains(&self, address: IpAddr) -> bool {
        self.ranges.contains(address) != self.inverse
    }
}

/// A loaded `geoip.dat`.
pub struct GeoIpIndex {
    data: Arc<[u8]>,
    entries: Vec<EntryMeta>,
    by_code: HashMap<Box<str>, u32>,
    compiled: RwLock<HashMap<u32, Arc<CompiledGeoIp>>>,
    /// Codes a rule has asked for that the file does not have, reported once each.
    missing: RwLock<std::collections::HashSet<Box<str>>>,
}

impl core::fmt::Debug for GeoIpIndex {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("GeoIpIndex")
            .field("bytes", &self.data.len())
            .field("countries", &self.entries.len())
            .finish()
    }
}

impl GeoIpIndex {
    /// Whether `bytes` looks like a geoip database, without decoding it.
    pub fn probe(bytes: &[u8]) -> bool {
        let mut outer = Decoder::new(bytes);
        let Ok(Some(entry)) = outer.next_field() else {
            return false;
        };
        if entry.number() != 1 || entry.bytes().is_err() {
            return false;
        }
        let Ok(mut inner) = entry.decoder() else {
            return false;
        };
        let mut has_code = false;
        let mut has_cidr = false;
        while let Ok(Some(field)) = inner.next_field() {
            match field.number() {
                1 if field.string().is_ok() => has_code = true,
                2 => {
                    let Ok(mut cidr) = field.decoder() else {
                        return false;
                    };
                    while let Ok(Some(attribute)) = cidr.next_field() {
                        // A GeoIP CIDR carries raw address bytes at field 1; a
                        // geosite domain carries a string at field 2 instead.
                        if attribute.number() == 1 && attribute.bytes().is_err() {
                            return false;
                        }
                    }
                    has_cidr = true;
                }
                _ => {}
            }
        }
        has_code && has_cidr && !super::geosite::GeoSiteIndex::probe(bytes)
    }

    /// Parse a `geoip.dat` into a country index.
    pub fn open(data: Vec<u8>) -> Result<Self> {
        let data: Arc<[u8]> = Arc::from(data);
        let mut entries = Vec::new();
        let mut by_code = HashMap::new();

        let mut outer = Decoder::new(&data);
        while let Some(field) = outer.next_field()? {
            if field.number() != 1 {
                continue;
            }
            let payload = field.bytes()?;
            let span = span_of(&data, payload);
            let mut entry = field.decoder()?;
            let mut code: Option<Box<str>> = None;
            let mut fallback: Option<Box<str>> = None;
            while let Some(inner) = entry.next_field()? {
                match inner.number() {
                    1 => {
                        if let Ok(value) = inner.string()
                            && !value.trim().is_empty()
                        {
                            code = Some(value.trim().to_ascii_uppercase().into());
                        }
                    }
                    5 => {
                        if let Ok(value) = inner.string()
                            && !value.trim().is_empty()
                        {
                            fallback = Some(value.trim().to_ascii_uppercase().into());
                        }
                    }
                    _ => {}
                }
            }
            let Some(code) = code.or(fallback) else {
                continue;
            };
            let id = entries.len() as u32;
            by_code.insert(code.clone(), id);
            entries.push(EntryMeta { code, span });
        }

        if entries.is_empty() {
            return Err(Error::config("geoip database contains no countries"));
        }

        Ok(Self {
            data,
            entries,
            by_code,
            compiled: RwLock::new(HashMap::new()),
            missing: RwLock::new(std::collections::HashSet::new()),
        })
    }

    /// Number of countries the file declares.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the file declares no country at all.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Country codes, for diagnostics.
    pub fn country_codes(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|entry| entry.code.as_ref())
    }

    /// Whether a country or provider label exists.
    pub fn has_country(&self, code: &str) -> bool {
        self.by_code.contains_key(&normalize_code(code))
    }

    /// Whether `address` belongs to `code`.
    pub fn matches(&self, code: &str, address: IpAddr) -> bool {
        match self.compiled(code) {
            Some(compiled) => compiled.contains(address),
            None => false,
        }
    }

    /// The compiled form of `code`, compiling it on first use.
    pub fn compiled(&self, code: &str) -> Option<Arc<CompiledGeoIp>> {
        let key = normalize_code(code);
        let Some(&id) = self.by_code.get(&key) else {
            if self.missing.write().insert(key.clone()) {
                tracing::warn!(
                    "GeoIP code '{key}' is not in the database ({} countries loaded); the rule \
                     that names it will never match",
                    self.entries.len()
                );
            }
            return None;
        };
        if let Some(compiled) = self.compiled.read().get(&id) {
            return Some(Arc::clone(compiled));
        }

        let meta = self.entries.get(id as usize)?;
        let message = self.data.get(meta.span.clone())?;
        let compiled = match CompiledGeoIp::compile(&meta.code, message) {
            Ok(compiled) => Arc::new(compiled),
            Err(error) => {
                tracing::warn!(
                    "GeoIP country '{}' is unreadable and will not match: {error}",
                    meta.code
                );
                return None;
            }
        };
        if !compiled.rejected.is_empty() {
            tracing::warn!(
                "GeoIP country '{}' compiled {} CIDRs, {} unusable ({}); matches may be incomplete",
                compiled.code,
                compiled.cidr_count,
                compiled.rejected.len(),
                compiled
                    .rejected
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("; ")
            );
        }
        let mut cache = self.compiled.write();
        let entry = cache.entry(id).or_insert_with(|| Arc::clone(&compiled));
        Some(Arc::clone(entry))
    }
}

/// Country codes are compared the way every other rule payload is.
fn normalize_code(code: &str) -> Box<str> {
    code.trim().to_ascii_uppercase().into()
}

fn span_of(data: &[u8], slice: &[u8]) -> Range<usize> {
    let base = data.as_ptr() as usize;
    let start = (slice.as_ptr() as usize).saturating_sub(base);
    start..start.saturating_add(slice.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint(out: &mut Vec<u8>, mut value: u64) {
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

    fn field_varint(out: &mut Vec<u8>, number: u8, value: u64) {
        varint(out, u64::from(number) << 3);
        varint(out, value);
    }

    fn field_bytes(out: &mut Vec<u8>, number: u8, payload: &[u8]) {
        varint(out, (u64::from(number) << 3) | 2);
        varint(out, payload.len() as u64);
        out.extend_from_slice(payload);
    }

    fn cidr(address: &[u8], prefix: u64) -> Vec<u8> {
        let mut out = Vec::new();
        field_bytes(&mut out, 1, address);
        field_varint(&mut out, 2, prefix);
        out
    }

    fn country(code: &str, cidrs: &[Vec<u8>], inverse: bool) -> Vec<u8> {
        let mut out = Vec::new();
        field_bytes(&mut out, 1, code.as_bytes());
        for cidr in cidrs {
            field_bytes(&mut out, 2, cidr);
        }
        if inverse {
            field_varint(&mut out, 3, 1);
        }
        out
    }

    fn database(countries: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for country in countries {
            field_bytes(&mut out, 1, country);
        }
        out
    }

    fn sample() -> Vec<u8> {
        database(&[
            country(
                "CN",
                &[
                    cidr(&[1, 0, 1, 0], 24),
                    cidr(&[36, 0, 0, 0], 8),
                    // IPv6 in the same country.
                    cidr(&[0x24, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 20),
                ],
                false,
            ),
            country("US", &[cidr(&[8, 8, 8, 0], 24)], false),
            country("PRIVATE", &[cidr(&[10, 0, 0, 0], 8)], false),
        ])
    }

    #[test]
    fn reads_countries_and_matches_addresses() {
        let index = GeoIpIndex::open(sample()).expect("database");
        assert_eq!(index.len(), 3);
        assert!(index.has_country("cn"));
        assert!(index.has_country("CN"));

        assert!(index.matches("CN", "1.0.1.7".parse().expect("ip")));
        assert!(!index.matches("CN", "1.0.2.7".parse().expect("ip")));
        assert!(index.matches("cn", "36.1.2.3".parse().expect("ip")));
        assert!(index.matches("CN", "2400::1".parse().expect("ip")));
        assert!(index.matches("US", "8.8.8.8".parse().expect("ip")));
        assert!(!index.matches("US", "1.0.1.7".parse().expect("ip")));
        assert!(index.matches("PRIVATE", "10.1.2.3".parse().expect("ip")));
    }

    #[test]
    fn an_unknown_country_is_a_miss() {
        let index = GeoIpIndex::open(sample()).expect("database");
        assert!(!index.matches("NOPE", "1.0.1.7".parse().expect("ip")));
        assert!(!index.has_country("NOPE"));
    }

    #[test]
    fn an_inverse_category_matches_its_complement() {
        let index = GeoIpIndex::open(database(&[country(
            "NOT-LAN",
            &[cidr(&[10, 0, 0, 0], 8)],
            true,
        )]))
        .expect("database");
        assert!(!index.matches("NOT-LAN", "10.1.2.3".parse().expect("ip")));
        assert!(index.matches("NOT-LAN", "1.1.1.1".parse().expect("ip")));
    }

    #[test]
    fn probing_tells_a_geoip_file_from_a_geosite_file() {
        let geoip = sample();
        assert!(GeoIpIndex::probe(&geoip));
        assert!(!super::super::geosite::GeoSiteIndex::probe(&geoip));
        assert!(!GeoIpIndex::probe(b"payload: []"));
        assert!(!GeoIpIndex::probe(&[]));
    }

    #[test]
    fn unusable_cidrs_are_reported_without_losing_the_rest() {
        let index = GeoIpIndex::open(database(&[country(
            "MIXED",
            &[cidr(&[1, 2, 3, 4], 24), cidr(&[1, 2, 3], 24), cidr(&[1, 2, 3, 4], 40)],
            false,
        )]))
        .expect("database");
        let compiled = index.compiled("MIXED").expect("compiled");
        assert_eq!(compiled.rejected().len(), 2);
        assert!(compiled.contains("1.2.3.4".parse().expect("ip")));
    }

    #[test]
    fn an_empty_database_is_refused() {
        assert!(GeoIpIndex::open(Vec::new()).is_err());
    }

    #[test]
    fn a_compiled_country_is_cached() {
        let index = GeoIpIndex::open(sample()).expect("database");
        let first = index.compiled("CN").expect("compiled");
        let second = index.compiled("cn").expect("compiled");
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(first.range_count(), 3);
    }
}
