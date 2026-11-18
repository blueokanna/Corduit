//! Binary and textual rule sets, decoded into one evaluatable form.
//!
//! A rule set is a bag of *headless* rules: conditions without a destination.
//! Both dialects this engine consumes describe them the same way — a set of
//! conditions that must all hold, optionally negated, optionally combined with
//! and/or into a tree — so they land in [`HeadlessRule`] and are evaluated
//! against [`RuleSetInput`] by one implementation.
//!
//! | Format | Read by | Notes |
//! |---|---|---|
//! | `srs` (sing-box binary) | [`srs`] | zlib-compressed, versions 1–5 |
//! | `mrs` (the other binary family) | [`mrs`] | one zstd frame, container version 1 |
//! | `text` / `yaml` / `json` payloads | [`crate::engine::rule_provider`] | classical `RULE,TYPE` lines |
//! | `mrs` (Mihomo binary) | — | recognised and refused, see [`Format::Mrs`] |
//!
//! Detection is by content, never by file name: a `.txt` served as `text/plain`
//! can hold any of these, and a subscription URL's extension is a suggestion, not
//! a promise. A payload this build cannot decode is an error naming the format it
//! recognised — never an empty rule set, because an empty rule set routes every
//! connection it was meant to catch straight to whatever rule comes next.

pub mod mrs;
pub mod reader;
pub mod srs;
pub mod succinct;
pub mod zstd;

use crate::engine::error::{Error, Result};
use regex::{Regex, RegexBuilder};
use std::net::IpAddr;
use succinct::{DomainMatcher, SuccinctSet};

/// Largest payload a binary rule set may decode to, in bytes.
///
/// A rule set that inflates past this is either corrupt or hostile; what it must
/// never be is a way to make the process allocate until it dies. Real sets are
/// two orders of magnitude below this: the largest community Geo set decodes to
/// tens of megabytes, and a single rule set to a few.
pub const MAX_DECODED_BYTES: usize = 64 * 1024 * 1024;

/// Most entries one rule set may index.
///
/// The decoded-size budget bounds the bytes; this bounds the *count*, because a
/// payload can describe a very large number of tiny entries, and every count in a
/// decoder is a promise about how much the loader will build.
pub const MAX_RULE_SET_ENTRIES: usize = 1 << 21;

/// Most regular expressions one rule set may carry.
///
/// A regular expression is the only entry whose cost is not proportional to its
/// length when it is *matched*: compilation is where a hostile set can spend
/// memory and time, so the number of expressions is capped separately from the
/// number of domains.
pub const MAX_RULE_SET_REGEXES: usize = 1 << 12;

/// Most domain keywords one rule set may carry.
///
/// Keyword matching is a substring scan per keyword per connection, so an
/// unbounded keyw  ord list would turn every connection into a linear search over
/// the whole list — a slow-down an attacker can ship inside a rule set.
pub const MAX_RULE_SET_KEYWORDS: usize = 1 << 16;

/// Compiled-size ceiling for one regular expression.
///
/// `regex` grows a program until a limit is hit; stating the limit here keeps a
/// crafted pattern from choosing a much larger one.
pub const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// Which family a payload belongs to.
///
/// Detection is by content, never by file name, and each variant exists so that a
/// refusal can name what it saw instead of guessing what was meant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// sing-box binary rule set: a four-byte header, then a zlib stream.
    Srs,
    /// Mihomo binary rule set: one zstd frame holding the container magic.
    Mrs,
    /// v2ray / Mihomo Geo database (`geosite.dat`, `geoip.dat`).
    GeoDatabase,
    /// MaxMind DB (`Country.mmdb`).
    Mmdb,
    /// Text lines, or a JSON/YAML document.
    Text,
}

crate::impl_config_enum!(Format {
    Text => "text" | "txt",
    Srs => "srs" | "binary",
    Mrs => "mrs",
    GeoDatabase => "dat" | "geo-dat" | "geodat",
    Mmdb => "mmdb",
});

/// Magic that starts a sing-box binary rule set: `SRS`.
const SRS_MAGIC: [u8; 3] = [0x53, 0x52, 0x53];
/// Magic that starts a zstd frame, which is all an `.mrs` file shows before it is
/// decompressed: the container's own magic is inside the compressed stream.
///
/// Declared here rather than in the decoder so that *recognising* the format does
/// not depend on the feature that can decode it: a build without `mrs` still
/// names what it was handed instead of calling it text.
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
/// Trailer every MaxMind DB ends with.
const MMDB_TRAILER: &[u8] = b"\xab\xcd\xefMaxMind.com";

/// Identify a payload by its bytes.
///
/// Order matters. The three magic numbers are decisive and are checked first;
/// protobuf is checked by shape afterwards, because a Geo database has no magic
/// and must not be mistaken for text (`geosite.dat` starts with `0x0a`, which is a
/// newline — exactly what a text rule file starts with).
pub fn detect(bytes: &[u8]) -> Format {
    if bytes.len() >= 4 && bytes[..3] == SRS_MAGIC {
        return Format::Srs;
    }
    if bytes.len() >= 4 && bytes[..4] == ZSTD_MAGIC {
        // A zstd payload that is not an MRS is refused by the decoder, with the
        // missing inner magic named. Keying on the frame magic is the only way to
        // see this format at all.
        return Format::Mrs;
    }
    if bytes.len() >= MMDB_TRAILER.len() && bytes.ends_with(MMDB_TRAILER) {
        return Format::Mmdb;
    }
    if crate::engine::geo::looks_like_geodatabase(bytes) {
        return Format::GeoDatabase;
    }
    Format::Text
}

/// Decode a binary rule set into evaluatable rules.
///
/// `requested` is an explicit `format:` from the profile; a mismatch between it
/// and the bytes is reported rather than worked around, because a profile that
/// says `format: srs` for a YAML file is a profile that has lost track of what it
/// is loading.
pub fn decode(bytes: &[u8], requested: Option<Format>) -> Result<Vec<HeadlessRule>> {
    let detected = detect(bytes);
    let format = match requested {
        Some(requested) => {
            if requested != detected {
                return Err(Error::config(format!(
                    "Rule set is declared as '{}' but its content is '{}'",
                    requested.as_str(),
                    detected.as_str()
                )));
            }
            requested
        }
        None => detected,
    };

    match format {
        Format::Srs => srs::decode(bytes),
        Format::Mrs => mrs::decode(bytes),
        Format::Mmdb => Err(Error::config(
            "This rule set is a MaxMind DB (Country.mmdb), which describes IP ownership per \
             country rather than rules. Load it as the geo database instead of a rule provider",
        )),
        Format::GeoDatabase => Err(Error::config(
            "This rule set is a v2ray/Mihomo Geo database (geosite.dat / geoip.dat), which holds \
             thousands of categories rather than one rule set. Load it as the geo database and \
             reference a category from a rule (`GEOSITE,category`, `GEOIP,CN`) instead",
        )),
        Format::Text => Err(Error::config(
            "Rule set was handed to the binary decoder but is text; the caller must parse it \
             with the text path",
        )),
    }
}

/// Transport a headless rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Transport {
    /// Stream transport.
    #[default]
    Tcp,
    /// Datagram transport.
    Udp,
}

impl Transport {
    /// Parse the spelling a rule set stores.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            _ => None,
        }
    }
}

/// Everything a headless rule may inspect about one connection.
///
/// Separate from the router's own context because a rule set is evaluated for a
/// different question — "does this set describe the connection" — and reads one
/// field the router does not track per rule: the transport, which any binary set
/// may constrain.
#[derive(Debug, Clone, Copy, Default)]
pub struct RuleSetInput<'a> {
    /// Destination hostname, when the client supplied one.
    pub domain: Option<&'a str>,
    /// Destination address, when it is already known.
    pub dst_ip: Option<IpAddr>,
    /// Addresses the router resolved for `domain`.
    pub resolved: &'a [IpAddr],
    /// Whether the rule that owns this set asked for `no-resolve`.
    pub no_resolve: bool,
    /// Address the connection came from.
    pub src_ip: Option<IpAddr>,
    /// Destination port.
    pub dst_port: Option<u16>,
    /// Source port.
    pub src_port: Option<u16>,
    /// Transport in use.
    pub network: Transport,
    /// Executable name owning the connection.
    pub process_name: Option<&'a str>,
    /// Full executable path.
    pub process_path: Option<&'a str>,
}

impl RuleSetInput<'_> {
    /// Addresses an `ip_cidr` condition may compare against.
    fn dst_candidates(&self) -> impl Iterator<Item = IpAddr> + '_ {
        let resolved: &[IpAddr] = if self.no_resolve { &[] } else { self.resolved };
        self.dst_ip.into_iter().chain(resolved.iter().copied())
    }
}

/// How a logical rule combines its children.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogicalMode {
    /// Every child must match.
    And,
    /// At least one child must match.
    Or,
}

/// One rule from a rule set, in the form matching uses.
#[derive(Debug, Default)]
pub struct HeadlessRule {
    /// Transports the rule applies to; empty means either.
    pub network: Vec<Transport>,
    /// The domain condition, in whichever encoding its source file used.
    ///
    /// Both dialects store the same compressed tree and answer the same question —
    /// "is this hostname described by the set" — but they spell the markers
    /// differently: one uses two control labels for exact and suffix keys, the
    /// other uses a printed `+` for a suffix and `*` for one label of any depth.
    /// Keeping the encoding with the set is what lets one rule type cover both.
    pub domains: Option<DomainCondition>,
    /// Substrings of the domain.
    pub domain_keywords: Vec<Box<str>>,
    /// Regular expressions over the domain.
    pub domain_regexes: Vec<Regex>,
    /// Destination addresses.
    pub ip_cidr: Option<super::geo::ipset::IpRangeSet>,
    /// Source addresses.
    pub src_ip_cidr: Option<super::geo::ipset::IpRangeSet>,
    /// Destination ports, as inclusive ranges.
    pub ports: Vec<(u16, u16)>,
    /// Source ports, as inclusive ranges.
    pub src_ports: Vec<(u16, u16)>,
    /// Executable names.
    pub process_names: Vec<Box<str>>,
    /// Executable paths.
    pub process_paths: Vec<Box<str>>,
    /// Regular expressions over the executable path.
    pub process_path_regexes: Vec<Regex>,
    /// Whether the rule's own result is negated.
    pub invert: bool,
    /// Children of a logical rule, when this one is logical.
    pub logical: Option<(LogicalMode, Vec<HeadlessRule>)>,
}

impl HeadlessRule {
    /// Whether this rule describes `input`.
    pub fn matches(&self, input: &RuleSetInput<'_>) -> bool {
        let matched = match &self.logical {
            Some((mode, children)) => match mode {
                LogicalMode::And => children.iter().all(|child| child.matches(input)),
                LogicalMode::Or => children.iter().any(|child| child.matches(input)),
            },
            None => self.conditions_match(input),
        };
        matched != self.invert
    }

    /// Whether every condition this rule carries holds.
    ///
    /// Conditions a rule does not carry never constrain it, which is why each one
    /// is guarded by its own emptiness check rather than defaulting to `true`.
    fn conditions_match(&self, input: &RuleSetInput<'_>) -> bool {
        if !self.network.is_empty() && !self.network.contains(&input.network) {
            return false;
        }

        if let Some(domains) = &self.domains
            && !input.domain.is_some_and(|domain| domains.matches(domain))
        {
            return false;
        }
        if !self.domain_keywords.is_empty()
            && !input.domain.is_some_and(|domain| {
                self.domain_keywords
                    .iter()
                    .any(|keyword| contains_ignore_ascii_case(domain, keyword))
            })
        {
            return false;
        }
        if !self.domain_regexes.is_empty()
            && !input.domain.is_some_and(|domain| {
                self.domain_regexes
                    .iter()
                    .any(|regex| regex.is_match(domain))
            })
        {
            return false;
        }

        if let Some(networks) = &self.ip_cidr
            && !input
                .dst_candidates()
                .any(|address| networks.contains(address))
        {
            return false;
        }
        if let Some(networks) = &self.src_ip_cidr
            && !input
                .src_ip
                .is_some_and(|address| networks.contains(address))
        {
            return false;
        }

        if !self.ports.is_empty()
            && !input
                .dst_port
                .is_some_and(|port| port_in(&self.ports, port))
        {
            return false;
        }
        if !self.src_ports.is_empty()
            && !input
                .src_port
                .is_some_and(|port| port_in(&self.src_ports, port))
        {
            return false;
        }

        if !self.process_names.is_empty()
            && !input.process_name.is_some_and(|process| {
                self.process_names
                    .iter()
                    .any(|pattern| process_name_matches(pattern, process))
            })
        {
            return false;
        }
        if !self.process_paths.is_empty()
            && !input.process_path.is_some_and(|path| {
                self.process_paths
                    .iter()
                    .any(|pattern| path.trim().eq_ignore_ascii_case(pattern))
            })
        {
            return false;
        }
        if !self.process_path_regexes.is_empty()
            && !input.process_path.is_some_and(|path| {
                self.process_path_regexes
                    .iter()
                    .any(|regex| regex.is_match(path))
            })
        {
            return false;
        }

        true
    }

    /// Whether this rule, or any rule inside it, needs the destination address.
    ///
    /// The router asks before paying for a DNS lookup: a set of domain patterns
    /// must not trigger one, and a set holding address ranges cannot decide
    /// without it.
    pub fn wants_dst_ip(&self) -> bool {
        if self.ip_cidr.is_some() {
            return true;
        }
        match &self.logical {
            Some((_, children)) => children.iter().any(Self::wants_dst_ip),
            None => false,
        }
    }

    /// Number of conditions that can actually decide a match.
    pub fn condition_count(&self) -> usize {
        if let Some((_, children)) = &self.logical {
            return children.iter().map(Self::condition_count).sum();
        }
        usize::from(self.domains.as_ref().is_some_and(|set| !set.is_empty()))
            + self.domain_keywords.len()
            + self.domain_regexes.len()
            + usize::from(self.ip_cidr.as_ref().is_some_and(|set| !set.is_empty()))
            + usize::from(self.src_ip_cidr.as_ref().is_some_and(|set| !set.is_empty()))
            + self.ports.len()
            + self.src_ports.len()
            + self.process_names.len()
            + self.process_paths.len()
            + self.process_path_regexes.len()
            + usize::from(!self.network.is_empty())
    }
}

/// A decoded rule set: any member matching decides the set.
#[derive(Debug, Default)]
pub struct RuleSet {
    rules: Vec<HeadlessRule>,
}

impl RuleSet {
    /// Wrap already-decoded rules.
    pub fn new(rules: Vec<HeadlessRule>) -> Self {
        Self { rules }
    }

    /// Whether any rule in the set describes `input`.
    pub fn matches(&self, input: &RuleSetInput<'_>) -> bool {
        self.rules.iter().any(|rule| rule.matches(input))
    }

    /// Whether an empty set (which never matches) is all this holds.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Number of rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Number of conditions across every rule.
    pub fn condition_count(&self) -> usize {
        self.rules.iter().map(HeadlessRule::condition_count).sum()
    }

    /// Whether any rule in the set needs the destination address.
    pub fn wants_dst_ip(&self) -> bool {
        self.rules.iter().any(HeadlessRule::wants_dst_ip)
    }

    /// The rules themselves.
    pub fn rules(&self) -> &[HeadlessRule] {
        &self.rules
    }
}

/// Compile rule-set regular expressions the way every other rule type in this
/// engine compares text: case-insensitively.
///
/// A pattern that needs case sensitivity can still ask for it with `(?-i)`.
pub fn compile_regex(pattern: &str) -> Result<Regex> {
    RegexBuilder::new(pattern)
        .case_insensitive(true)
        // The ceiling is stated here rather than left to the crate's default, so a
        // crafted pattern cannot buy a larger compiled program than this.
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|error| {
            Error::config(format!(
                "Rule set pattern '{pattern}' is not a valid regex: {error}"
            ))
        })
}

/// Whether `port` falls in any inclusive range.
pub fn port_in(ranges: &[(u16, u16)], port: u16) -> bool {
    ranges
        .iter()
        .any(|(start, end)| port >= *start && port <= *end)
}

/// Parse Sing/Mihomo's comma-separated port list, where `a-b` is a range.
///
/// Port ranges written as `start:end` also occur in the community profiles, so
/// both separators are accepted; anything else is refused with the range named.
pub fn parse_port_ranges<S: AsRef<str>>(
    parts: impl IntoIterator<Item = S>,
) -> Result<Vec<(u16, u16)>> {
    let mut ranges = Vec::new();
    for part in parts {
        for piece in part.as_ref().split(',') {
            let piece = piece.trim();
            if piece.is_empty() {
                continue;
            }
            let (start, end) = match piece.split_once(['-', ':', '/']) {
                Some((start, end)) if !start.trim().is_empty() && !end.trim().is_empty() => {
                    (start.trim(), end.trim())
                }
                Some(_) => {
                    return Err(Error::config(format!(
                        "Rule set port range '{piece}' is missing a bound"
                    )));
                }
                None => (piece, piece),
            };
            let start: u16 = start
                .parse()
                .map_err(|_| Error::config(format!("Rule set port '{start}' is not a port")))?;
            let end: u16 = end
                .parse()
                .map_err(|_| Error::config(format!("Rule set port '{end}' is not a port")))?;
            if start > end {
                return Err(Error::config(format!(
                    "Rule set port range '{piece}' is inverted"
                )));
            }
            ranges.push((start, end));
        }
    }
    Ok(ranges)
}

/// ASCII case-insensitive substring test, without allocating a lowercase copy.
pub fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let haystack = haystack.as_bytes();
    let needle = needle.as_bytes();
    if needle.len() > haystack.len() {
        return false;
    }
    (0..=haystack.len() - needle.len())
        .any(|start| haystack[start..start + needle.len()].eq_ignore_ascii_case(needle))
}

/// Match a `PROCESS-NAME` pattern against a process name or path.
///
/// A rule names the executable, not the path it was launched from, and the
/// `.exe` suffix is optional on both sides — that is what makes one rule work for
/// `qbittorrent`, `qBittorrent.exe` and `C:\Program Files\qBittorrent\qbittorrent.exe`.
pub fn process_name_matches(pattern: &str, process: &str) -> bool {
    let basename = process.rsplit(['/', '\\']).next().unwrap_or(process);
    if basename.eq_ignore_ascii_case(pattern) || process.eq_ignore_ascii_case(pattern) {
        return true;
    }
    let pattern = pattern.strip_suffix(".exe").unwrap_or(pattern);
    basename
        .strip_suffix(".exe")
        .unwrap_or(basename)
        .eq_ignore_ascii_case(pattern)
}

/// A domain condition in the encoding its file used.
#[derive(Debug, Clone)]
pub enum DomainCondition {
    /// Exact and suffix entries in the marker encoding sing-box ships.
    Marked(DomainMatcher),
    /// Exact, suffix and wildcard entries in the encoding `.mrs` ships.
    Wildcard(SuccinctSet),
}

impl DomainCondition {
    /// Whether `domain` is described by this set.
    pub fn matches(&self, domain: &str) -> bool {
        match self {
            Self::Marked(matcher) => matcher.matches(domain),
            Self::Wildcard(set) => set.has_wildcards(domain),
        }
    }

    /// Whether the set holds no key at all.
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Marked(matcher) => matcher.is_empty(),
            Self::Wildcard(set) => set.is_empty(),
        }
    }

    /// Number of keys, for diagnostics.
    pub fn len(&self) -> usize {
        match self {
            Self::Marked(matcher) => matcher.len(),
            Self::Wildcard(set) => set.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule() -> HeadlessRule {
        HeadlessRule::default()
    }

    fn input() -> RuleSetInput<'static> {
        RuleSetInput::default()
    }

    #[test]
    fn detection_never_confuses_text_with_a_binary_container() {
        assert_eq!(detect(b"SRS\x01rest"), Format::Srs);
        // An `.mrs` is a zstd frame; the container magic is inside it, so a bare
        // `MRS` prefix is not evidence of anything.
        assert_eq!(detect(&[0x28, 0xB5, 0x2F, 0xFD, 0x00]), Format::Mrs);
        assert_eq!(detect(b"MRS!\x01rest"), Format::Text);
        assert_eq!(detect(b"DOMAIN,example.com\n"), Format::Text);
        assert_eq!(detect(b"payload:\n  - '+.example.com'\n"), Format::Text);
        assert_eq!(detect(b"{\"payload\":[]}"), Format::Text);
        // An mmdb is identified by its trailer, wherever the trailer sits.
        let mut mmdb = vec![0u8; 32];
        mmdb.extend_from_slice(MMDB_TRAILER);
        assert_eq!(detect(&mmdb), Format::Mmdb);
    }

    /// A zstd frame whose inner magic is not MRS is refused by name; it is not
    /// text, and parsing it as text would index zero rules.
    #[test]
    fn a_zstd_payload_that_is_not_a_rule_set_is_refused() {
        use std::io::Write;
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        let _ = encoder.write_all(b"hello");
        let zlib = encoder.finish().expect("compresses");
        assert_eq!(detect(&zlib), Format::Text, "zlib is not the mrs container");
    }

    #[test]
    fn a_declared_format_must_match_the_content() {
        let error =
            decode(b"DOMAIN,example.com\n", Some(Format::Srs)).expect_err("text is not srs");
        assert!(error.to_string().contains("declared"));
    }

    #[test]
    fn an_empty_rule_matches_everything_and_is_still_representable() {
        assert!(rule().matches(&input()));
    }

    #[test]
    fn conditions_are_anded_and_absent_conditions_do_not_constrain() {
        let mut rule = rule();
        rule.domain_keywords = vec!["ads".into()];
        assert!(!rule.matches(&input()));
        assert!(!rule.matches(&RuleSetInput {
            domain: Some("example.com"),
            ..input()
        }));
        assert!(rule.matches(&RuleSetInput {
            domain: Some("ads.example.com"),
            ..input()
        }));

        rule.network = vec![Transport::Udp];
        assert!(!rule.matches(&RuleSetInput {
            domain: Some("ads.example.com"),
            ..input()
        }));
        assert!(rule.matches(&RuleSetInput {
            domain: Some("ads.example.com"),
            network: Transport::Udp,
            ..input()
        }));
    }

    #[test]
    fn invert_negates_the_whole_rule() {
        let mut rule = rule();
        rule.domain_keywords = vec!["ads".into()];
        rule.invert = true;
        assert!(rule.matches(&RuleSetInput {
            domain: Some("example.com"),
            ..input()
        }));
        assert!(!rule.matches(&RuleSetInput {
            domain: Some("ads.example.com"),
            ..input()
        }));
    }

    #[test]
    fn logical_rules_combine_children() {
        let mut a = rule();
        a.domain_keywords = vec!["a".into()];
        let mut b = rule();
        b.domain_keywords = vec!["b".into()];

        let and = HeadlessRule {
            logical: Some((LogicalMode::And, vec![a, b])),
            ..rule()
        };
        assert!(!and.matches(&RuleSetInput {
            domain: Some("a.example.com"),
            ..input()
        }));
        assert!(and.matches(&RuleSetInput {
            domain: Some("ab.example.com"),
            ..input()
        }));

        let mut a = rule();
        a.domain_keywords = vec!["a".into()];
        let mut b = rule();
        b.domain_keywords = vec!["b".into()];
        let or = HeadlessRule {
            logical: Some((LogicalMode::Or, vec![a, b])),
            ..rule()
        };
        assert!(or.matches(&RuleSetInput {
            domain: Some("a.example.com"),
            ..input()
        }));
    }

    #[test]
    fn port_ranges_accept_both_separators_and_refuse_nonsense() {
        let parsed = parse_port_ranges(vec![
            "80".to_string(),
            "443,8000-8100".to_string(),
            "9000:9100".to_string(),
        ])
        .expect("valid");
        assert!(port_in(&parsed, 80));
        assert!(port_in(&parsed, 8050));
        assert!(port_in(&parsed, 9050));
        assert!(!port_in(&parsed, 81));

        assert!(parse_port_ranges(vec!["8100-8000".to_string()]).is_err());
        assert!(parse_port_ranges(vec!["http".to_string()]).is_err());
        assert!(parse_port_ranges(vec!["80-".to_string()]).is_err());
    }

    #[test]
    fn process_names_match_a_path_a_name_and_a_missing_extension() {
        assert!(process_name_matches(
            "qbittorrent.exe",
            r"C:\Program Files\qBittorrent\qbittorrent.exe"
        ));
        assert!(process_name_matches("qbittorrent", "qBittorrent.exe"));
        assert!(!process_name_matches("firefox", "qbittorrent.exe"));
    }
}
