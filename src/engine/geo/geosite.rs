//! The `geosite.dat` category database (`geosite:netflix`, `geosite:cn`, …).
//!
//! Both communities this engine has to serve read the same file: the protobuf
//! `GeoSiteList` that v2fly has written since 4.x and that MetaCubeX's
//! `geosite.dat` still is. One `GeoSite` message per category:
//!
//! ```text
//! GeoSiteList { repeated GeoSite entry = 1 }
//! GeoSite     { string country_code = 1; repeated Domain domain = 2 }
//! Domain      { Type type = 1; string value = 2; repeated Attribute attribute = 3 }
//! Domain.Type { Plain = 0; Regex = 1; RootDomain = 2; Full = 3 }
//! ```
//!
//! ## Why categories are compiled lazily
//!
//! A community `geosite.dat` carries a thousand categories and roughly a million
//! domains. Compiling all of them at load time costs several seconds and a few
//! hundred megabytes, and a profile names perhaps a dozen. So the file is parsed
//! once into *spans* — a name and a byte range per category — and a category is
//! decoded into its matcher the first time a rule asks for it, then cached. The
//! retained cost of an unused category is its name and sixteen bytes.
//!
//! ## Matching semantics
//!
//! `Plain` and `RootDomain` are suffix entries (`example.com` matches
//! `a.example.com` but not `notexample.com`), `Full` is exact, and `Regex` is a
//! case-insensitive match over the hostname — the same reading v2ray and Mihomo
//! give them.

use super::proto::Decoder;
use crate::engine::error::{Error, Result};
use crate::engine::ruleset::succinct::DomainMatcher;
use parking_lot::RwLock;
use regex::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use std::collections::HashMap;
use std::ops::Range;
use std::sync::Arc;

/// Domain kinds, as the schema numbers them.
const TYPE_PLAIN: u64 = 0;
const TYPE_REGEX: u64 = 1;
const TYPE_ROOT_DOMAIN: u64 = 2;
const TYPE_FULL: u64 = 3;

/// One category's position inside the file.
#[derive(Debug)]
struct TagMeta {
    /// Category name as written, e.g. `category-ads-all`.
    name: Box<str>,
    /// Byte range of the `GeoSite` message body.
    span: Range<usize>,
}

/// A category decoded into structures that answer a match.
#[derive(Debug)]
pub struct CompiledGeoSite {
    name: Box<str>,
    /// Plain and RootDomain entries, plus Full entries as exact keys.
    domains: DomainMatcher,
    /// Regex entries, when they fit one automaton.
    regex_set: Option<RegexSet>,
    /// Regex entries compiled one by one, used when [`CompiledGeoSite::regex_set`]
    /// could not be built and for diagnostics.
    regexes: Vec<Regex>,
    /// Entries decoded.
    domain_count: usize,
    /// Attribute keys the category declares, sorted and deduplicated.
    attributes: Vec<Box<str>>,
    /// Entries that could not be used, with the reason. Non-empty means the
    /// category is incomplete, which is reported once when it is compiled.
    rejected: Vec<String>,
}

impl CompiledGeoSite {
    /// The category name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Number of entries this category actually holds.
    pub fn len(&self) -> usize {
        self.domain_count
    }

    /// Whether the category compiled to nothing usable.
    pub fn is_empty(&self) -> bool {
        self.domain_count == 0
    }

    /// Compile one `GeoSite` message.
    fn compile(name: &str, message: &[u8]) -> Result<Self> {
        let mut exact: Vec<String> = Vec::new();
        let mut suffix: Vec<String> = Vec::new();
        let mut patterns: Vec<String> = Vec::new();
        let mut attributes: Vec<Box<str>> = Vec::new();
        let mut rejected: Vec<String> = Vec::new();

        let mut entry = Decoder::new(message);
        while let Some(field) = entry.next_field()? {
            if field.number() != 2 {
                continue;
            }

            let mut domain = field.decoder()?;
            let mut kind = TYPE_PLAIN;
            let mut value: Option<String> = None;
            while let Some(inner) = domain.next_field()? {
                match inner.number() {
                    1 => kind = inner.varint_u64()?,
                    2 => value = Some(inner.string()?.to_string()),
                    3 => {
                        let mut attribute = inner.decoder()?;
                        while let Some(attribute_field) = attribute.next_field()? {
                            if attribute_field.number() == 1 {
                                let key = attribute_field.string()?;
                                if !key.is_empty()
                                    && !attributes.iter().any(|known| &**known == key)
                                {
                                    attributes.push(key.into());
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            let Some(value) = value else {
                rejected.push("domain entry without a value".to_string());
                continue;
            };
            let value = value.trim();
            if value.is_empty() {
                rejected.push("empty domain entry".to_string());
                continue;
            }
            match kind {
                TYPE_PLAIN | TYPE_ROOT_DOMAIN => suffix.push(value.to_string()),
                TYPE_FULL => exact.push(value.to_string()),
                TYPE_REGEX => patterns.push(value.to_string()),
                other => rejected.push(format!("domain kind {other} is undefined: {value}")),
            }
        }

        let (regex_set, regexes) = compile_patterns(&patterns, &mut rejected);

        attributes.sort_unstable();
        attributes.dedup();

        let domain_count = exact.len() + suffix.len() + patterns.len();
        Ok(Self {
            name: name.into(),
            domains: DomainMatcher::build(exact, suffix),
            regex_set,
            regexes,
            domain_count,
            attributes,
            rejected,
        })
    }

    /// Whether `domain` belongs to this category.
    pub fn matches(&self, domain: &str) -> bool {
        if !self.domains.is_empty() && self.domains.matches(domain) {
            return true;
        }
        if let Some(set) = &self.regex_set
            && set.is_match(domain)
        {
            return true;
        }
        self.regexes.iter().any(|regex| regex.is_match(domain))
    }

    /// Attribute keys the category declares (`attributes: ["ads"]` in the
    /// database), for diagnostics.
    pub fn attributes(&self) -> &[Box<str>] {
        &self.attributes
    }

    /// Entries that could not be compiled.
    pub fn rejected(&self) -> &[String] {
        &self.rejected
    }
}

/// Compile a category's regular expressions.
///
/// A `RegexSet` is one automaton scanned once per hostname, which is what makes a
/// category with hundreds of expressions affordable; it can only be built when
/// *every* pattern is valid, so a single unusable pattern falls back to the
/// per-pattern list and is reported.
fn compile_patterns(
    patterns: &[String],
    rejected: &mut Vec<String>,
) -> (Option<RegexSet>, Vec<Regex>) {
    if patterns.is_empty() {
        return (None, Vec::new());
    }
    match RegexSetBuilder::new(patterns.iter())
        .case_insensitive(true)
        .build()
    {
        Ok(set) => (Some(set), Vec::new()),
        Err(set_error) => {
            rejected.push(format!("regex set: {set_error}"));
            let mut regexes = Vec::new();
            for pattern in patterns {
                match RegexBuilder::new(pattern).case_insensitive(true).build() {
                    Ok(regex) => regexes.push(regex),
                    Err(error) => rejected.push(format!("regex '{pattern}': {error}")),
                }
            }
            (None, regexes)
        }
    }
}

/// A loaded `geosite.dat`.
pub struct GeoSiteIndex {
    data: Arc<[u8]>,
    tags: Vec<TagMeta>,
    by_name: HashMap<String, u32>,
    compiled: RwLock<HashMap<u32, Arc<CompiledGeoSite>>>,
    /// Categories a rule has asked for that the file does not have. Reported once
    /// each: a typo in a profile must be visible, and repeating it per connection
    /// would bury the log.
    missing: RwLock<std::collections::HashSet<String>>,
}

impl core::fmt::Debug for GeoSiteIndex {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("GeoSiteIndex")
            .field("bytes", &self.data.len())
            .field("categories", &self.tags.len())
            .finish()
    }
}

impl GeoSiteIndex {
    /// Whether `bytes` looks like a geosite database, without decoding it.
    ///
    /// Used for format detection: the file has no magic number, so the only
    /// honest test is whether its outer shape is a list of messages that each
    /// start with a tag name.
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
        let mut has_name = false;
        let mut has_domain = false;
        while let Ok(Some(field)) = inner.next_field() {
            match field.number() {
                1 if field.string().is_ok() => has_name = true,
                2 => {
                    let Ok(mut domain) = field.decoder() else {
                        return false;
                    };
                    while let Ok(Some(attribute)) = domain.next_field() {
                        if attribute.number() == 2 && attribute.string().is_err() {
                            return false;
                        }
                    }
                    has_domain = true;
                }
                _ => {}
            }
        }
        has_name && has_domain
    }

    /// Parse a `geosite.dat` into a category index.
    ///
    /// The file is retained: decoding happens per category, lazily.
    pub fn open(data: Vec<u8>) -> Result<Self> {
        let data: Arc<[u8]> = Arc::from(data);
        let mut tags = Vec::new();
        let mut by_name = HashMap::new();

        let mut outer = Decoder::new(&data);
        while let Some(field) = outer.next_field()? {
            if field.number() != 1 {
                continue;
            }
            let payload = field.bytes()?;
            let span = span_of(&data, payload);
            let mut entry = field.decoder()?;
            let mut name: Option<Box<str>> = None;
            while let Some(inner) = entry.next_field()? {
                if inner.number() == 1
                    && let Ok(value) = inner.string()
                {
                    name = Some(value.into());
                }
            }
            let Some(name) = name else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let id = tags.len() as u32;
            by_name.insert(name.to_ascii_lowercase(), id);
            tags.push(TagMeta { name, span });
        }

        if tags.is_empty() {
            return Err(Error::config("geosite database contains no categories"));
        }

        Ok(Self {
            data,
            tags,
            by_name,
            compiled: RwLock::new(HashMap::new()),
            missing: RwLock::new(std::collections::HashSet::new()),
        })
    }

    /// Number of categories the file declares.
    pub fn len(&self) -> usize {
        self.tags.len()
    }

    /// Whether the file declares no category at all.
    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
    }

    /// Category names, for diagnostics and the RPC surface.
    pub fn tag_names(&self) -> impl Iterator<Item = &str> {
        self.tags.iter().map(|tag| tag.name.as_ref())
    }

    /// Whether a category exists.
    pub fn has_tag(&self, tag: &str) -> bool {
        self.by_name.contains_key(&tag.to_ascii_lowercase())
    }

    /// Whether `domain` belongs to `tag`.
    ///
    /// An unknown category is a miss, and the first miss is reported once: a
    /// profile that says `geosite:netflex` must not look like a rule that simply
    /// never fires.
    pub fn matches(&self, tag: &str, domain: &str) -> bool {
        match self.compiled(tag) {
            Some(compiled) => compiled.matches(domain),
            None => false,
        }
    }

    /// The compiled form of `tag`, compiling it on first use.
    pub fn compiled(&self, tag: &str) -> Option<Arc<CompiledGeoSite>> {
        let key = tag.trim().to_ascii_lowercase();
        let Some(&id) = self.by_name.get(&key) else {
            if self.missing.write().insert(key.clone()) {
                tracing::warn!(
                    "Geosite category '{key}' is not in the database ({} categories loaded); \
                     the rule that names it will never match",
                    self.tags.len()
                );
            }
            return None;
        };
        if let Some(compiled) = self.compiled.read().get(&id) {
            return Some(Arc::clone(compiled));
        }

        let meta = self.tags.get(id as usize)?;
        let message = self.data.get(meta.span.clone())?;
        let compiled = match CompiledGeoSite::compile(&meta.name, message) {
            Ok(compiled) => Arc::new(compiled),
            Err(error) => {
                tracing::warn!(
                    "Geosite category '{}' is unreadable and will not match: {error}",
                    meta.name
                );
                return None;
            }
        };
        if !compiled.rejected.is_empty() {
            tracing::warn!(
                "Geosite category '{}' compiled {} entries, {} unusable ({}); \
                 matches may be incomplete",
                compiled.name,
                compiled.domain_count,
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

/// Byte range of `slice` inside `data`, which must be a subslice of it.
fn span_of(data: &[u8], slice: &[u8]) -> Range<usize> {
    let base = data.as_ptr() as usize;
    let start = (slice.as_ptr() as usize).saturating_sub(base);
    start..start.saturating_add(slice.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal protobuf writers, so the fixtures below can be read by eye.
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

    /// One `Domain` message.
    fn domain(kind: u64, value: &str) -> Vec<u8> {
        let mut out = Vec::new();
        field_varint(&mut out, 1, kind);
        field_bytes(&mut out, 2, value.as_bytes());
        out
    }

    /// One `GeoSite` message.
    fn category(name: &str, domains: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        field_bytes(&mut out, 1, name.as_bytes());
        for domain in domains {
            field_bytes(&mut out, 2, domain);
        }
        out
    }

    /// A whole `GeoSiteList`.
    fn database(categories: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for category in categories {
            field_bytes(&mut out, 1, category);
        }
        out
    }

    fn sample() -> Vec<u8> {
        database(&[
            category(
                "netflix",
                &[
                    domain(TYPE_PLAIN, "netflix.com"),
                    domain(TYPE_ROOT_DOMAIN, "nflxvideo.net"),
                    domain(TYPE_FULL, "fast.com"),
                    domain(TYPE_REGEX, r"^nflx[0-9]+\.example\.net$"),
                ],
            ),
            category("category-ads-all", &[domain(TYPE_PLAIN, "doubleclick.net")]),
        ])
    }

    #[test]
    fn reads_categories_and_their_domains() {
        let index = GeoSiteIndex::open(sample()).expect("database");
        assert_eq!(index.len(), 2);
        assert!(index.has_tag("netflix"));
        assert!(index.has_tag("NETFLIX"));
        assert!(index.has_tag("category-ads-all"));
        assert!(!index.has_tag("netflex"));

        assert!(index.matches("netflix", "www.netflix.com"));
        assert!(index.matches("netflix", "netflix.com"));
        assert!(!index.matches("netflix", "notnetflix.com"));
        // RootDomain entries behave like Plain ones.
        assert!(index.matches("netflix", "ipv4-c001.nflxvideo.net"));
        // Full entries are exact.
        assert!(index.matches("netflix", "fast.com"));
        assert!(!index.matches("netflix", "www.fast.com"));
        // Regex entries match case-insensitively, like every other rule type.
        assert!(index.matches("netflix", "nflx42.example.net"));
        assert!(index.matches("netflix", "NFLX42.EXAMPLE.NET"));
        assert!(!index.matches("netflix", "www.nflx42.example.net"));

        assert!(index.matches("category-ads-all", "ads.doubleclick.net"));
        assert!(!index.matches("category-ads-all", "netflix.com"));
    }

    #[test]
    fn categories_are_independent() {
        let index = GeoSiteIndex::open(sample()).expect("database");
        assert!(!index.matches("category-ads-all", "fast.com"));
        assert!(!index.matches("netflix", "doubleclick.net"));
    }

    #[test]
    fn an_unknown_category_is_a_miss_not_a_panic() {
        let index = GeoSiteIndex::open(sample()).expect("database");
        assert!(!index.matches("netflex", "www.netflix.com"));
        assert!(!index.matches("", "www.netflix.com"));
    }

    #[test]
    fn probing_recognises_the_shape_and_rejects_text() {
        let bytes = sample();
        assert!(GeoSiteIndex::probe(&bytes));
        assert!(!GeoSiteIndex::probe(b"payload:\n  - '+.example.com'\n"));
        assert!(!GeoSiteIndex::probe(b"DOMAIN,example.com\n"));
        assert!(!GeoSiteIndex::probe(b"{\"payload\":[]}"));
        assert!(!GeoSiteIndex::probe(&[]));
    }

    #[test]
    fn an_empty_database_is_refused() {
        assert!(GeoSiteIndex::open(Vec::new()).is_err());
    }

    #[test]
    fn attribute_keys_are_collected() {
        let mut entry = domain(TYPE_PLAIN, "ads.example.com");
        let mut attribute = Vec::new();
        field_bytes(&mut attribute, 1, b"ads");
        field_varint(&mut attribute, 2, 1);
        field_bytes(&mut entry, 3, &attribute);

        let index = GeoSiteIndex::open(database(&[category("ads", &[entry])])).expect("database");
        let compiled = index.compiled("ads").expect("compiled");
        assert_eq!(
            compiled.attributes(),
            &[String::from("ads").into_boxed_str()]
        );
        assert!(compiled.matches("ads.example.com"));
    }

    #[test]
    fn an_unusable_entry_is_reported_and_the_rest_still_works() {
        let index = GeoSiteIndex::open(database(&[category(
            "mixed",
            &[
                domain(TYPE_PLAIN, "good.example.com"),
                domain(TYPE_REGEX, "([unclosed"),
                domain(9, "unknown.example.com"),
            ],
        )]))
        .expect("database");
        let compiled = index.compiled("mixed").expect("compiled");
        assert!(compiled.matches("good.example.com"));
        assert!(!compiled.matches("unknown.example.com"));
        assert!(
            compiled.rejected().len() >= 2,
            "unusable entries are reported: {:?}",
            compiled.rejected()
        );
    }

    #[test]
    fn a_compiled_category_is_cached() {
        let index = GeoSiteIndex::open(sample()).expect("database");
        let first = index.compiled("netflix").expect("compiled");
        let second = index.compiled("Netflix").expect("compiled");
        assert!(Arc::ptr_eq(&first, &second));
    }
}
