use crate::engine::error::{Error, Result};
use crate::engine::geo::ipset::IpRangeSet;
use crate::engine::ruleset::succinct::DomainMatcher;
use ipnet::IpNet;
use nextjson::{NsonDeserialize, NsonSerialize};
use parking_lot::RwLock;
use regex::Regex;
use std::borrow::Cow;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleProviderType {
    Http,
    File,
}

crate::impl_config_enum!(RuleProviderType {
    Http => "http",
    File => "file",
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleProviderBehavior {
    Domain,
    IpCidr,
    Classical,
}

crate::impl_config_enum!(RuleProviderBehavior {
    Domain => "domain",
    IpCidr => "ip-cidr" | "ipcidr" | "ip_cidr",
    Classical => "classical",
});

#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct RuleProviderConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub provider_type: RuleProviderType,
    pub behavior: RuleProviderBehavior,
    pub url: Option<String>,
    pub path: Option<String>,
    #[serde(default = "default_interval")]
    pub interval: u64,
}

fn default_interval() -> u64 {
    86400
}

#[derive(Debug, Clone)]
pub enum CompiledRuleEntry {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    DomainRegex(Regex),
    IpCidr(IpNet),
    Classical {
        rule_type: ClassicalRuleType,
        pattern: String,
        regex: Option<Regex>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassicalRuleType {
    Domain,
    DomainSuffix,
    DomainKeyword,
    DomainRegex,
    IpCidr,
    SrcIpCidr,
    ProcessName,
}

/// What a rule set is matched against.
///
/// A struct rather than a parameter list, for the same reason the router uses
/// one: `IP-CIDR` and `SRC-IP-CIDR` are different inputs, and with two adjacent
/// `Option<IpAddr>` parameters a call site cannot tell them apart. That is
/// exactly how `SRC-IP-CIDR` entries came to be matched against the destination
/// address here.
#[derive(Debug, Clone, Copy, Default)]
pub struct RuleMatchInput<'a> {
    /// Destination hostname, when the client supplied one.
    pub domain: Option<&'a str>,
    /// Destination address.
    pub dst_ip: Option<IpAddr>,
    /// Addresses the router resolved for `domain`.
    ///
    /// An `ipcidr`-style set has to see them, for the same reason a `GEOIP`
    /// rule does: a connection that arrives as a domain has no literal
    /// address to match, and a set that exists to describe address ranges
    /// would otherwise never carry the traffic it names.
    pub resolved: &'a [IpAddr],
    /// Whether the rule that carries this input asked for `no-resolve`.
    pub no_resolve: bool,
    /// Address the connection came from.
    pub src_ip: Option<IpAddr>,
    /// Executable name owning the connection.
    pub process_name: Option<&'a str>,
    /// Full executable path, when it is resolvable.
    ///
    /// A `.srs` set may pin a path rather than a name, which the text format
    /// cannot express; the field lives here so both formats are evaluated
    /// against the same input.
    pub process_path: Option<&'a str>,
    /// Transport in use.
    pub network: crate::engine::ruleset::Transport,
    /// Destination port.
    pub dst_port: Option<u16>,
    /// Source port.
    pub src_port: Option<u16>,
}

impl RuleMatchInput<'_> {
    /// Addresses resolved for the domain that an `ip-cidr` entry may compare
    /// against; empty when the rule asked for `no-resolve`.
    fn dst_candidates(&self) -> impl Iterator<Item = IpAddr> + '_ {
        let resolved: &[IpAddr] = if self.no_resolve { &[] } else { self.resolved };
        resolved.iter().copied()
    }

    /// The same connection, described for a binary rule set.
    ///
    /// One input type instead of two keeps the router from describing a
    /// connection twice and then disagreeing with itself about the port.
    fn ruleset_input(&self) -> crate::engine::ruleset::RuleSetInput<'_> {
        crate::engine::ruleset::RuleSetInput {
            domain: self.domain,
            dst_ip: self.dst_ip,
            resolved: self.resolved,
            no_resolve: self.no_resolve,
            src_ip: self.src_ip,
            dst_port: self.dst_port,
            src_port: self.src_port,
            network: self.network,
            process_name: self.process_name,
            process_path: self.process_path,
        }
    }
}

/// Fold ASCII uppercase to lowercase, borrowing when there is nothing to fold.
///
/// Well-formed clients send lowercase hostnames, so the common path allocates
/// nothing; the fallback keeps matching correct for the ones that do not.
/// Only ASCII is folded, which is what `eq_ignore_ascii_case` means and what DNS
/// itself is case-insensitive about.
fn fold_ascii_lower(value: &str) -> Cow<'_, str> {
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Cow::Owned(value.to_ascii_lowercase())
    } else {
        Cow::Borrowed(value)
    }
}

fn folded_box(value: &str) -> Box<str> {
    fold_ascii_lower(value).into_owned().into_boxed_str()
}

/// ASCII case-insensitive substring test, without allocating a lowercase copy of
/// either side.
fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
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

/// A rule set arranged for lookup rather than for storage.
///
/// [`CompiledRuleEntry`] stays as authored so a set can be inspected and
/// reported; this is what matching runs against. Two structures carry the bulk of
/// a real rule set, and both are the compressed forms the rest of the engine
/// already uses: a community set of a hundred thousand suffixes costs roughly an
/// order of magnitude less memory as a compressed domain set than as hash sets of
/// boxed strings, and merged address intervals beat a list of CIDR values on both
/// size and lookup cost.
#[derive(Debug, Default)]
struct RuleIndex {
    /// Exact and suffix domains, in one compressed set.
    domains: DomainMatcher,
    /// Substrings, which have no structure a set can exploit and stay a list.
    keywords: Vec<Box<str>>,
    regexes: Vec<Regex>,
    /// Destination addresses, merged into intervals.
    dst: IpRangeSet,
    /// Source addresses, merged. Kept separate from `dst` because they are
    /// compared against a different address.
    src: IpRangeSet,
    /// Process names, folded.
    process_names: Vec<Box<str>>,
    /// Entries that parsed but could not be indexed, with the reason.
    /// Kept so a bad rule set is a diagnostic rather than a silent no-match.
    rejected: Vec<String>,
}

impl RuleIndex {
    fn compile(entries: &[CompiledRuleEntry]) -> Self {
        let mut exact: Vec<String> = Vec::new();
        let mut suffix: Vec<String> = Vec::new();
        let mut index = Self::default();
        for entry in entries {
            index.add(entry, &mut exact, &mut suffix);
        }
        index.domains = DomainMatcher::build(exact, suffix);
        index.dst.finish();
        index.src.finish();
        index
    }

    fn add(
        &mut self,
        entry: &CompiledRuleEntry,
        exact: &mut Vec<String>,
        suffix: &mut Vec<String>,
    ) {
        match entry {
            CompiledRuleEntry::Domain(pattern) => {
                if !pattern.trim().is_empty() {
                    exact.push(pattern.clone());
                }
            }
            CompiledRuleEntry::DomainSuffix(pattern) => {
                if !pattern.trim().is_empty() {
                    suffix.push(pattern.clone());
                }
            }
            CompiledRuleEntry::DomainKeyword(pattern) => {
                if !pattern.is_empty() {
                    self.keywords.push(folded_box(pattern));
                }
            }
            CompiledRuleEntry::DomainRegex(regex) => self.regexes.push(regex.clone()),
            CompiledRuleEntry::IpCidr(network) => self.dst.insert_net(*network),
            CompiledRuleEntry::Classical {
                rule_type,
                pattern,
                regex,
            } => match rule_type {
                ClassicalRuleType::Domain => {
                    if !pattern.trim().is_empty() {
                        exact.push(pattern.clone());
                    }
                }
                ClassicalRuleType::DomainSuffix => {
                    if !pattern.trim().is_empty() {
                        suffix.push(pattern.clone());
                    }
                }
                ClassicalRuleType::DomainKeyword => {
                    if !pattern.is_empty() {
                        self.keywords.push(folded_box(pattern));
                    }
                }
                ClassicalRuleType::DomainRegex => match regex {
                    Some(regex) => self.regexes.push(regex.clone()),
                    None => self
                        .rejected
                        .push(format!("DOMAIN-REGEX '{pattern}' is not a valid regex")),
                },
                ClassicalRuleType::IpCidr => match pattern.trim().parse::<IpNet>() {
                    Ok(network) => self.dst.insert_net(network),
                    Err(error) => self.rejected.push(format!("IP-CIDR '{pattern}': {error}")),
                },
                ClassicalRuleType::SrcIpCidr => match pattern.trim().parse::<IpNet>() {
                    Ok(network) => self.src.insert_net(network),
                    Err(error) => self
                        .rejected
                        .push(format!("SRC-IP-CIDR '{pattern}': {error}")),
                },
                ClassicalRuleType::ProcessName => {
                    if !pattern.is_empty() {
                        self.process_names.push(folded_box(pattern));
                    }
                }
            },
        }
    }

    /// Entries that can actually decide a match.
    fn matchable_count(&self) -> usize {
        self.domains.len()
            + self.keywords.len()
            + self.regexes.len()
            + self.dst.range_count()
            + self.src.range_count()
            + self.process_names.len()
    }

    /// Whether this set holds any address entry a resolved answer could
    /// decide. The router asks before paying for a lookup.
    fn has_dst_ip_entries(&self) -> bool {
        !self.dst.is_empty()
    }

    /// A bounded description of what could not be indexed.
    fn rejected_summary(&self) -> String {
        const SHOWN: usize = 3;
        let mut summary = self
            .rejected
            .iter()
            .take(SHOWN)
            .cloned()
            .collect::<Vec<_>>()
            .join("; ");
        if self.rejected.len() > SHOWN {
            summary.push_str(&format!(" (+{} more)", self.rejected.len() - SHOWN));
        }
        summary
    }

    fn matches(&self, input: &RuleMatchInput<'_>) -> bool {
        if let Some(domain) = input.domain {
            let domain = domain.trim_end_matches('.');
            if self.domains.matches(domain) {
                return true;
            }
            // Keywords and regexes keep their own folded copy: the compressed
            // set folds internally, and a substring test cannot ask it anything.
            let folded = fold_ascii_lower(domain);
            if self
                .keywords
                .iter()
                .any(|keyword| folded.contains(keyword.as_ref()))
                || self.regexes.iter().any(|regex| regex.is_match(&folded))
            {
                return true;
            }
        }

        if let Some(address) = input.dst_ip
            && self.dst.contains(address)
        {
            return true;
        }

        // Addresses the router resolved for the domain count too, unless the
        // rule opted out with `no-resolve`.
        if !input.no_resolve
            && input
                .resolved
                .iter()
                .any(|address| self.dst.contains(*address))
        {
            return true;
        }

        if let Some(address) = input.src_ip
            && self.src.contains(address)
        {
            return true;
        }

        if let Some(process) = input.process_name {
            let basename = process.rsplit(['/', '\\']).next().unwrap_or(process);
            let basename = fold_ascii_lower(basename);
            let stem = basename.strip_suffix(".exe").unwrap_or(basename.as_ref());
            if self.process_names.iter().any(|pattern| {
                let pattern_stem = pattern.strip_suffix(".exe").unwrap_or(pattern);
                pattern.as_ref() == basename.as_ref() || pattern_stem == stem
            }) {
                return true;
            }
        }

        false
    }
}

/// A provider's payload, compiled for matching.
///
/// Two representations, one owner: a text payload becomes a [`RuleIndex`], a
/// binary payload becomes a [`crate::engine::ruleset::RuleSet`], and either way
/// the provider answers through [`CompiledSet::matches`]. Both are kept because
/// they are not interchangeable — the index has no notion of a transport or a
/// port, and the binary form has no notion of a per-behavior text line — and a
/// provider holds exactly one of them.
#[derive(Debug, Default)]
struct CompiledSet {
    index: RuleIndex,
    rules: crate::engine::ruleset::RuleSet,
}

impl CompiledSet {
    /// Whether any entry from either representation matches.
    fn matches(&self, input: &RuleMatchInput<'_>) -> bool {
        if self.index.matches(input) {
            return true;
        }
        !self.rules.is_empty() && self.rules.matches(&input.ruleset_input())
    }

    /// Entries that can decide a match.
    fn matchable_count(&self) -> usize {
        self.index.matchable_count() + self.rules.condition_count()
    }

    /// Whether an address the router resolved could decide this set.
    fn has_dst_ip_entries(&self) -> bool {
        self.index.has_dst_ip_entries() || self.rules.wants_dst_ip()
    }
}

pub struct RuleProvider {
    config: RuleProviderConfig,
    set: RwLock<CompiledSet>,
    last_update: RwLock<Option<Instant>>,
}

impl RuleProvider {
    pub fn new(config: RuleProviderConfig) -> Self {
        Self {
            config,
            set: RwLock::new(CompiledSet::default()),
            last_update: RwLock::new(None),
        }
    }

    pub fn name(&self) -> &str {
        &self.config.name
    }

    /// The provider's configuration as loaded.
    pub fn config(&self) -> &RuleProviderConfig {
        &self.config
    }

    pub fn behavior(&self) -> RuleProviderBehavior {
        self.config.behavior
    }

    /// Fetch, parse and index the rule set.
    ///
    /// Two failures are told apart because they need different fixes: a source
    /// that parsed into no entries at all (wrong file), and a source whose
    /// entries were all unusable (wrong format). Entries that parse but cannot
    /// be indexed are reported instead of dropped — a rule that silently never
    /// matches is the hardest kind of routing bug to find.
    pub fn load(&self) -> Result<()> {
        let payload = match self.config.provider_type {
            RuleProviderType::File => self.load_from_file()?,
            RuleProviderType::Http => self.load_from_http()?,
        };

        let set = self.compile_payload(&payload)?;
        let indexed = set.matchable_count();
        if indexed == 0 {
            return Err(Error::config(format!(
                "Rule provider '{}' has entries but none of them can decide a match",
                self.config.name
            )));
        }

        *self.set.write() = set;

        *self.last_update.write() = Some(Instant::now());

        tracing::info!(
            "Rule provider '{}' loaded {} rules",
            self.config.name,
            indexed
        );

        Ok(())
    }

    /// Compile a payload into the representation its format calls for.
    ///
    /// The format is decided from the content, never from a file extension: a
    /// subscription URL's suffix is a suggestion, and a `.mrs` provider that was
    /// parsed as text used to yield a rule set that matched nothing at all. A
    /// payload this build cannot decode is an error naming what it recognised.
    fn compile_payload(&self, payload: &[u8]) -> Result<CompiledSet> {
        use crate::engine::ruleset::Format;

        match crate::engine::ruleset::detect(payload) {
            Format::Text => {
                let content = core::str::from_utf8(payload).map_err(|error| {
                    Error::config(format!(
                        "Rule provider '{}' is text but is not valid UTF-8: {error}",
                        self.config.name
                    ))
                })?;
                let entries = self.parse_rules(content)?;
                if entries.is_empty() {
                    return Err(Error::config(format!(
                        "Rule provider '{}' did not contain any supported rules",
                        self.config.name
                    )));
                }
                if entries.len() > crate::engine::ruleset::MAX_RULE_SET_ENTRIES {
                    return Err(Error::config(format!(
                        "Rule provider '{}' declares {} entries, past the {} entry cap; a rule \
                         set that large is not a routing table but a way to exhaust memory",
                        self.config.name,
                        entries.len(),
                        crate::engine::ruleset::MAX_RULE_SET_ENTRIES
                    )));
                }
                let index = RuleIndex::compile(&entries);
                if index.keywords.len() > crate::engine::ruleset::MAX_RULE_SET_KEYWORDS {
                    return Err(Error::config(format!(
                        "Rule provider '{}' declares {} domain keywords, past the {} cap; keyword \
                         matching is a scan per keyword per connection",
                        self.config.name,
                        index.keywords.len(),
                        crate::engine::ruleset::MAX_RULE_SET_KEYWORDS
                    )));
                }
                if index.regexes.len() > crate::engine::ruleset::MAX_RULE_SET_REGEXES {
                    return Err(Error::config(format!(
                        "Rule provider '{}' declares {} regular expressions, past the {} cap; \
                         expressions are the one entry whose cost is set at compile time",
                        self.config.name,
                        index.regexes.len(),
                        crate::engine::ruleset::MAX_RULE_SET_REGEXES
                    )));
                }
                if index.matchable_count() == 0 {
                    return Err(Error::config(format!(
                        "Rule provider '{}' has {} entries but none are usable: {}",
                        self.config.name,
                        entries.len(),
                        index.rejected_summary()
                    )));
                }
                if !index.rejected.is_empty() {
                    tracing::warn!(
                        "Rule provider '{}' indexed {} of {} entries; {} unusable: {}",
                        self.config.name,
                        index.matchable_count(),
                        entries.len(),
                        index.rejected.len(),
                        index.rejected_summary()
                    );
                }
                Ok(CompiledSet {
                    index,
                    rules: crate::engine::ruleset::RuleSet::default(),
                })
            }
            format => {
                let rules = crate::engine::ruleset::decode(payload, Some(format))?;
                if rules.is_empty() {
                    return Err(Error::config(format!(
                        "Rule provider '{}' decoded no rules from a {} payload",
                        self.config.name,
                        format.as_str()
                    )));
                }
                if self.config.behavior != RuleProviderBehavior::Classical {
                    // A binary payload carries its own conditions; `behavior`
                    // only ever described how to read *text* lines.
                    tracing::debug!(
                        "Rule provider '{}' is binary ({}), so its `behavior: {}` is not used",
                        self.config.name,
                        format.as_str(),
                        self.config.behavior.as_str()
                    );
                }
                Ok(CompiledSet {
                    index: RuleIndex::default(),
                    rules: crate::engine::ruleset::RuleSet::new(rules),
                })
            }
        }
    }

    fn load_from_file(&self) -> Result<Vec<u8>> {
        let path = self
            .config
            .path
            .as_ref()
            .ok_or_else(|| Error::config("File rule provider requires 'path' field"))?;

        // Bytes, not text: a `.srs` provider is binary from its first byte.
        std::fs::read(path)
            .map_err(|e| Error::config(format!("Failed to read rule file '{}': {}", path, e)))
    }

    fn load_from_http(&self) -> Result<Vec<u8>> {
        let url = self
            .config
            .url
            .as_ref()
            .ok_or_else(|| Error::config("HTTP rule provider requires 'url' field"))?;

        let cache_path = self.http_cache_path();

        let client = crate::common::HttpClient::new().with_timeout(Duration::from_secs(30));

        let result = client.get(url);

        let response = match result {
            Ok(response) if response.is_success() => response,
            Ok(response) => {
                return self.read_cached_or_error(
                    &cache_path,
                    format!("HTTP request failed with status: {}", response.status()),
                );
            }
            Err(error) => {
                return self.read_cached_or_error(
                    &cache_path,
                    format!("Failed to fetch rules from '{url}': {error}"),
                );
            }
        };

        let content = response.bytes().to_vec();

        if let Some(path) = &cache_path {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(path, &content);
        }

        Ok(content)
    }

    fn http_cache_path(&self) -> Option<PathBuf> {
        let safe_name: String = self
            .config
            .name
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                    character
                } else {
                    '_'
                }
            })
            .collect();
        Some(
            std::env::temp_dir()
                .join("corduit")
                .join("rule-providers")
                .join(format!("{}.rules", safe_name)),
        )
    }

    fn read_cached_or_error(
        &self,
        cache_path: &Option<PathBuf>,
        message: String,
    ) -> Result<Vec<u8>> {
        if let Some(path) = cache_path
            && let Ok(content) = std::fs::read(path)
        {
            tracing::warn!(
                "Using cached rule provider '{}' after refresh failed: {}",
                self.config.name,
                message
            );
            return Ok(content);
        }
        Err(Error::network(message))
    }

    pub fn parse_rules(&self, content: &str) -> Result<Vec<CompiledRuleEntry>> {
        let lines = rule_payload(content)?;
        let mut rules = Vec::with_capacity(lines.len());
        for line in lines {
            match self.config.behavior {
                RuleProviderBehavior::Domain => rules.push(self.parse_domain_entry(&line)),
                RuleProviderBehavior::IpCidr => {
                    let network = line
                        .parse::<IpNet>()
                        .map_err(|_| Error::config(format!("Invalid rule CIDR: {line}")))?;
                    rules.push(CompiledRuleEntry::IpCidr(network));
                }
                RuleProviderBehavior::Classical => {
                    let entry = self.parse_classical_entry(&line).ok_or_else(|| {
                        Error::config(format!("Unsupported classical rule: {line}"))
                    })?;
                    rules.push(entry);
                }
            }
        }
        Ok(rules)
    }

    fn parse_domain_entry(&self, entry: &str) -> CompiledRuleEntry {
        let entry = entry.trim_start_matches('+').trim_start_matches('.');

        if let Some(keyword) = entry.strip_prefix("keyword:") {
            CompiledRuleEntry::DomainKeyword(keyword.to_string())
        } else if let Some(pattern) = entry.strip_prefix("regexp:") {
            if let Ok(regex) = Regex::new(pattern) {
                CompiledRuleEntry::DomainRegex(regex)
            } else {
                CompiledRuleEntry::Domain(entry.to_string())
            }
        } else if let Some(pattern) = entry.strip_prefix("regex:") {
            if let Ok(regex) = Regex::new(pattern) {
                CompiledRuleEntry::DomainRegex(regex)
            } else {
                CompiledRuleEntry::Domain(entry.to_string())
            }
        } else if let Some(domain) = entry.strip_prefix("full:") {
            CompiledRuleEntry::Domain(domain.to_string())
        } else {
            CompiledRuleEntry::DomainSuffix(entry.to_string())
        }
    }

    fn parse_classical_entry(&self, entry: &str) -> Option<CompiledRuleEntry> {
        let mut parts = entry.split(',');
        let rule_type_str = parts.next()?.trim().to_uppercase();
        let pattern = parts.next()?.trim().to_string();
        if pattern.is_empty() {
            return None;
        }

        match rule_type_str.as_str() {
            "DOMAIN" => Some(CompiledRuleEntry::Classical {
                rule_type: ClassicalRuleType::Domain,
                pattern,
                regex: None,
            }),
            "DOMAIN-SUFFIX" => Some(CompiledRuleEntry::Classical {
                rule_type: ClassicalRuleType::DomainSuffix,
                pattern,
                regex: None,
            }),
            "DOMAIN-KEYWORD" => Some(CompiledRuleEntry::Classical {
                rule_type: ClassicalRuleType::DomainKeyword,
                pattern,
                regex: None,
            }),
            "DOMAIN-REGEX" => {
                let regex = Regex::new(&pattern).ok();
                Some(CompiledRuleEntry::Classical {
                    rule_type: ClassicalRuleType::DomainRegex,
                    pattern,
                    regex,
                })
            }
            "IP-CIDR" | "IP-CIDR6" => Some(CompiledRuleEntry::Classical {
                rule_type: ClassicalRuleType::IpCidr,
                pattern,
                regex: None,
            }),
            "SRC-IP-CIDR" => Some(CompiledRuleEntry::Classical {
                rule_type: ClassicalRuleType::SrcIpCidr,
                pattern,
                regex: None,
            }),
            "PROCESS-NAME" => Some(CompiledRuleEntry::Classical {
                rule_type: ClassicalRuleType::ProcessName,
                pattern,
                regex: None,
            }),
            _ => None,
        }
    }

    /// Whether any entry in this set matches.
    ///
    /// Runs against the compiled index: no allocation for a lowercase hostname,
    /// no per-entry lowercasing or `format!`, and no re-parsing of CIDRs.
    pub fn matches(&self, input: &RuleMatchInput<'_>) -> bool {
        self.set.read().matches(input)
    }

    /// Whether one specific entry matches, without going through the index.
    ///
    /// For diagnostics, and for tests that assert what a parsed entry *means*.
    /// The hot path is [`RuleProvider::matches`]; this exists so the meaning of
    /// a single entry can be checked directly instead of inferred from a set.
    pub fn matches_entry(&self, entry: &CompiledRuleEntry, input: &RuleMatchInput<'_>) -> bool {
        match entry {
            CompiledRuleEntry::Domain(pattern) => input
                .domain
                .is_some_and(|domain| domain.trim_end_matches('.').eq_ignore_ascii_case(pattern)),
            CompiledRuleEntry::DomainSuffix(pattern) => input.domain.is_some_and(|domain| {
                let domain = domain.trim_end_matches('.');
                domain.eq_ignore_ascii_case(pattern)
                    || (domain.len() > pattern.len()
                        && domain.as_bytes()[domain.len() - pattern.len() - 1] == b'.'
                        && domain[domain.len() - pattern.len()..].eq_ignore_ascii_case(pattern))
            }),
            CompiledRuleEntry::DomainKeyword(pattern) => input
                .domain
                .is_some_and(|domain| contains_ignore_ascii_case(domain, pattern)),
            CompiledRuleEntry::DomainRegex(regex) => {
                input.domain.is_some_and(|domain| regex.is_match(domain))
            }
            CompiledRuleEntry::IpCidr(network) => input
                .dst_ip
                .into_iter()
                .chain(input.dst_candidates())
                .any(|address| network.contains(&address)),
            CompiledRuleEntry::Classical {
                rule_type,
                pattern,
                regex,
            } => match rule_type {
                ClassicalRuleType::Domain => input.domain.is_some_and(|domain| {
                    domain.trim_end_matches('.').eq_ignore_ascii_case(pattern)
                }),
                ClassicalRuleType::DomainSuffix => input.domain.is_some_and(|domain| {
                    let domain = domain.trim_end_matches('.');
                    domain.eq_ignore_ascii_case(pattern)
                        || (domain.len() > pattern.len()
                            && domain.as_bytes()[domain.len() - pattern.len() - 1] == b'.'
                            && domain[domain.len() - pattern.len()..].eq_ignore_ascii_case(pattern))
                }),
                ClassicalRuleType::DomainKeyword => input
                    .domain
                    .is_some_and(|domain| contains_ignore_ascii_case(domain, pattern)),
                ClassicalRuleType::DomainRegex => match regex {
                    Some(regex) => input.domain.is_some_and(|domain| regex.is_match(domain)),
                    None => false,
                },
                ClassicalRuleType::IpCidr => {
                    pattern.trim().parse::<IpNet>().ok().is_some_and(|network| {
                        input
                            .dst_ip
                            .into_iter()
                            .chain(input.dst_candidates())
                            .any(|address| network.contains(&address))
                    })
                }
                ClassicalRuleType::SrcIpCidr => {
                    pattern.trim().parse::<IpNet>().ok().is_some_and(|network| {
                        input
                            .src_ip
                            .is_some_and(|address| network.contains(&address))
                    })
                }
                ClassicalRuleType::ProcessName => input
                    .process_name
                    .is_some_and(|process| Self::matches_process_name(pattern, process)),
            },
        }
    }

    fn matches_process_name(pattern: &str, process_name: &str) -> bool {
        let process_basename = process_name
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(process_name);
        if process_basename.eq_ignore_ascii_case(pattern) {
            return true;
        }

        let pattern_stem = pattern.strip_suffix(".exe").unwrap_or(pattern);
        let process_stem = process_basename
            .strip_suffix(".exe")
            .unwrap_or(process_basename);
        pattern_stem.eq_ignore_ascii_case(process_stem)
    }

    pub fn update(&self) -> Result<()> {
        self.load()
    }

    pub fn needs_update(&self) -> bool {
        let last_update = self.last_update.read();
        match *last_update {
            Some(time) => time.elapsed() > Duration::from_secs(self.config.interval),
            None => true,
        }
    }

    pub fn update_if_needed(&self) -> Result<bool> {
        if self.needs_update() {
            self.update()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn provider_type(&self) -> RuleProviderType {
        self.config.provider_type
    }

    pub fn interval(&self) -> u64 {
        self.config.interval
    }

    pub fn rule_count(&self) -> usize {
        self.set.read().matchable_count()
    }

    pub fn last_update_time(&self) -> Option<Instant> {
        *self.last_update.read()
    }

    /// Whether this set carries destination-address entries.
    ///
    /// The router uses it to decide whether a domain-only connection warrants
    /// a resolution before this set is evaluated; a set of domain patterns
    /// must not pay for a lookup it cannot use.
    pub fn has_dst_ip_entries(&self) -> bool {
        self.set.read().has_dst_ip_entries()
    }
}

pub struct RuleProviderManager {
    providers: Arc<RwLock<HashMap<String, Arc<RuleProvider>>>>,
}

impl RuleProviderManager {
    pub fn new() -> Self {
        Self {
            providers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn add_provider(&self, config: RuleProviderConfig) -> Result<()> {
        let name = config.name.clone();
        let provider = Arc::new(RuleProvider::new(config));
        provider.load()?;

        let mut providers = self.providers.write();
        providers.insert(name, provider);

        Ok(())
    }

    pub fn remove_provider(&self, name: &str) {
        let mut providers = self.providers.write();
        providers.remove(name);
    }

    pub fn get_provider(&self, name: &str) -> Option<Arc<RuleProvider>> {
        let providers = self.providers.read();
        providers.get(name).cloned()
    }

    pub fn matches(&self, provider_name: &str, input: &RuleMatchInput<'_>) -> bool {
        let providers = self.providers.read();
        if let Some(provider) = providers.get(provider_name) {
            provider.matches(input)
        } else {
            false
        }
    }

    /// Whether the named set carries address entries a resolved answer could
    /// decide. Unknown providers answer `false`, the same default that makes
    /// their rules never match.
    pub fn carries_dst_ip_entries(&self, provider_name: &str) -> bool {
        self.get_provider(provider_name)
            .is_some_and(|provider| provider.has_dst_ip_entries())
    }

    pub fn update_all(&self) -> Vec<Result<bool>> {
        let providers = self.providers.read();
        let mut results = Vec::new();

        for provider in providers.values() {
            results.push(provider.update_if_needed());
        }

        results
    }

    pub fn reload_provider(&self, name: &str) -> Result<()> {
        let providers = self.providers.read();
        if let Some(provider) = providers.get(name) {
            provider.load()
        } else {
            Err(Error::config(format!("Rule provider '{}' not found", name)))
        }
    }

    pub fn get_all_providers(&self) -> Vec<Arc<RuleProvider>> {
        let providers = self.providers.read();
        providers.values().cloned().collect()
    }

    pub fn provider_count(&self) -> usize {
        self.providers.read().len()
    }

    pub fn get_provider_names(&self) -> Vec<String> {
        let providers = self.providers.read();
        providers.keys().cloned().collect()
    }
}

impl Default for RuleProviderManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for RuleProviderManager {
    fn clone(&self) -> Self {
        Self {
            providers: Arc::clone(&self.providers),
        }
    }
}

/// Decode the shared JSON/YAML payload envelope once for every rule behavior.
/// Malformed structured input is an error, never a list of accidental domains.
fn rule_payload(content: &str) -> Result<Vec<Cow<'_, str>>> {
    const MAX_BYTES: usize = 32 * 1024 * 1024;
    if content.len() > MAX_BYTES {
        return Err(Error::config("Rule provider exceeds the 32 MiB limit"));
    }
    let content = content.trim_start_matches('\u{feff}').trim();
    let first = content
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .unwrap_or("");
    let structured = first.starts_with('{')
        || first.starts_with('[')
        || first == "---"
        || content
            .lines()
            .any(|line| line.trim_start().starts_with("payload:"));
    if !structured {
        return Ok(content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with("//"))
            .map(Cow::Borrowed)
            .collect());
    }
    let document: nextjson::Value = nextjson::from_str(content)
        .or_else(|_| nextjson::formats::decode_with(content.as_bytes(), nextjson::formats::Yaml))
        .map_err(|error| Error::config(format!("Invalid rule payload: {error}")))?;
    let nextjson::Value::Object(mut object) = document else {
        return Err(Error::config("Rule document must contain a payload array"));
    };
    let Some(nextjson::Value::Array(payload)) = object.remove("payload") else {
        return Err(Error::config("Rule document must contain a payload array"));
    };
    payload
        .into_iter()
        .map(|entry| match entry {
            nextjson::Value::String(value) if !value.trim().is_empty() => {
                Ok(Cow::Owned(value.trim().to_string()))
            }
            _ => Err(Error::config(
                "Every rule payload entry must be a non-empty string",
            )),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_provider(behavior: RuleProviderBehavior) -> RuleProvider {
        RuleProvider::new(RuleProviderConfig {
            name: "test".to_string(),
            provider_type: RuleProviderType::File,
            behavior,
            url: None,
            path: Some("test.txt".to_string()),
            interval: 86400,
        })
    }

    /// A provider whose index was built from `entries`.
    fn provider_with_entries(entries: Vec<CompiledRuleEntry>) -> RuleProvider {
        let provider = test_provider(RuleProviderBehavior::Classical);
        *provider.set.write() = CompiledSet {
            index: RuleIndex::compile(&entries),
            rules: crate::engine::ruleset::RuleSet::default(),
        };
        provider
    }

    /// A match input carrying only a domain.
    fn domain_input(domain: &str) -> RuleMatchInput<'_> {
        RuleMatchInput {
            domain: Some(domain),
            ..RuleMatchInput::default()
        }
    }

    /// A match input carrying only a destination address.
    fn dst_input(address: &str) -> RuleMatchInput<'static> {
        RuleMatchInput {
            dst_ip: Some(address.parse::<IpAddr>().expect("valid address")),
            ..RuleMatchInput::default()
        }
    }

    /// A match input carrying only a source address.
    fn src_input(address: &str) -> RuleMatchInput<'static> {
        RuleMatchInput {
            src_ip: Some(address.parse::<IpAddr>().expect("valid address")),
            ..RuleMatchInput::default()
        }
    }

    /// A match input carrying only a process name.
    fn process_input(process: &str) -> RuleMatchInput<'_> {
        RuleMatchInput {
            process_name: Some(process),
            ..RuleMatchInput::default()
        }
    }

    #[test]
    fn structured_rule_payloads_are_typed_and_never_fall_back_to_lines() {
        let cidr = test_provider(RuleProviderBehavior::IpCidr);
        assert_eq!(
            cidr.parse_rules("payload:\n  - '10.0.0.0/8'\n  - '2001:db8::/32'\n")
                .unwrap()
                .len(),
            2
        );
        let classical = test_provider(RuleProviderBehavior::Classical);
        assert_eq!(
            classical
                .parse_rules(
                    r#"{"payload":["DOMAIN-SUFFIX,bilibili.com","IP-CIDR,10.0.0.0/8,no-resolve"]}"#
                )
                .unwrap()
                .len(),
            2
        );
        let domain = test_provider(RuleProviderBehavior::Domain);
        for invalid in [
            "payload: [",
            "payload: 42",
            "payload: [123]",
            "{broken",
            "payload: ['']",
        ] {
            assert!(domain.parse_rules(invalid).is_err(), "{invalid}");
        }
        assert!(cidr.parse_rules("payload: ['not-an-ip']").is_err());
    }

    /// The domain payload contract community `payload:` rulesets follow.
    #[test]
    fn community_yaml_payload_covers_video_subdomains_without_suffix_confusion() {
        let provider = test_provider(RuleProviderBehavior::Domain);
        let entries = provider
            .parse_rules("payload:\n  - '+.bilibili.com'\n  - '+.bilivideo.com'\n")
            .unwrap();
        let index = RuleIndex::compile(&entries);
        for domain in [
            "bilibili.com",
            "api.bilibili.com",
            "search.bilibili.com",
            "cdn.bilivideo.com",
        ] {
            assert!(index.matches(&domain_input(domain)), "{domain}");
        }
        for domain in ["notbilibili.com", "bilibili.com.attacker.example"] {
            assert!(!index.matches(&domain_input(domain)), "{domain}");
        }
    }

    #[test]
    fn test_parse_domain_entry_suffix() {
        let provider = RuleProvider::new(RuleProviderConfig {
            name: "test".to_string(),
            provider_type: RuleProviderType::File,
            behavior: RuleProviderBehavior::Domain,
            url: None,
            path: Some("test.txt".to_string()),
            interval: 86400,
        });

        let entry = provider.parse_domain_entry("google.com");
        assert!(matches!(entry, CompiledRuleEntry::DomainSuffix(_)));
    }

    #[test]
    fn test_parse_domain_entry_full() {
        let provider = RuleProvider::new(RuleProviderConfig {
            name: "test".to_string(),
            provider_type: RuleProviderType::File,
            behavior: RuleProviderBehavior::Domain,
            url: None,
            path: Some("test.txt".to_string()),
            interval: 86400,
        });

        let entry = provider.parse_domain_entry("full:www.google.com");
        assert!(matches!(entry, CompiledRuleEntry::Domain(_)));
    }

    #[test]
    fn test_parse_domain_entry_keyword() {
        let provider = RuleProvider::new(RuleProviderConfig {
            name: "test".to_string(),
            provider_type: RuleProviderType::File,
            behavior: RuleProviderBehavior::Domain,
            url: None,
            path: Some("test.txt".to_string()),
            interval: 86400,
        });

        let entry = provider.parse_domain_entry("keyword:google");
        assert!(matches!(entry, CompiledRuleEntry::DomainKeyword(_)));
    }

    #[test]
    fn test_matches_domain_suffix() {
        let provider = RuleProvider::new(RuleProviderConfig {
            name: "test".to_string(),
            provider_type: RuleProviderType::File,
            behavior: RuleProviderBehavior::Domain,
            url: None,
            path: Some("test.txt".to_string()),
            interval: 86400,
        });

        let entry = CompiledRuleEntry::DomainSuffix("google.com".to_string());
        assert!(provider.matches_entry(&entry, &domain_input("www.google.com")));
        assert!(provider.matches_entry(&entry, &domain_input("google.com")));
        assert!(!provider.matches_entry(&entry, &domain_input("notgoogle.com")));
    }

    #[test]
    fn test_matches_ip_cidr() {
        let provider = RuleProvider::new(RuleProviderConfig {
            name: "test".to_string(),
            provider_type: RuleProviderType::File,
            behavior: RuleProviderBehavior::IpCidr,
            url: None,
            path: Some("test.txt".to_string()),
            interval: 86400,
        });

        let network: IpNet = "192.168.0.0/16".parse().unwrap();
        let entry = CompiledRuleEntry::IpCidr(network);

        assert!(provider.matches_entry(&entry, &dst_input("192.168.1.1")));
        assert!(!provider.matches_entry(&entry, &dst_input("10.0.0.1")));
    }

    #[test]
    fn test_classical_process_name_matches_reference_rules() {
        let provider = RuleProvider::new(RuleProviderConfig {
            name: "applications".to_string(),
            provider_type: RuleProviderType::File,
            behavior: RuleProviderBehavior::Classical,
            url: None,
            path: Some("applications.txt".to_string()),
            interval: 86400,
        });

        let entry = provider
            .parse_classical_entry("PROCESS-NAME,qBittorrent.exe")
            .expect("PROCESS-NAME should be supported");

        assert!(provider.matches_entry(
            &entry,
            &process_input(r"C:\Program Files\qBittorrent\qbittorrent.exe")
        ));
        assert!(!provider.matches_entry(&entry, &process_input("firefox.exe")));
    }

    #[test]
    fn test_classical_rule_ignores_trailing_modifiers() {
        let provider = RuleProvider::new(RuleProviderConfig {
            name: "networks".to_string(),
            provider_type: RuleProviderType::File,
            behavior: RuleProviderBehavior::Classical,
            url: None,
            path: Some("networks.txt".to_string()),
            interval: 86400,
        });

        let entry = provider
            .parse_classical_entry("IP-CIDR,10.0.0.0/8,no-resolve")
            .expect("IP-CIDR should be supported");

        assert!(provider.matches_entry(&entry, &dst_input("10.20.30.40")));
    }

    /// The binary path end to end: a `.srs` payload is detected, decoded, and
    /// answers matches through the provider — the same entry point a text
    /// provider uses.
    #[test]
    fn a_sing_box_binary_payload_is_detected_and_matched() {
        use crate::engine::ruleset::succinct::DomainMatcher;
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;

        let matcher =
            DomainMatcher::build(std::iter::empty::<String>(), ["example.com".to_string()]);
        let mut set_bytes = Vec::new();
        matcher.write_for_test(&mut set_bytes);

        let mut body = Vec::new();
        body.push(1); // one rule
        body.push(0); // default rule
        body.push(2); // domain item
        body.extend_from_slice(&set_bytes);
        body.push(0xFF); // final
        body.push(0); // not inverted

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&body).expect("compress");
        let mut payload = Vec::new();
        payload.extend_from_slice(b"SRS");
        payload.push(5);
        payload.extend_from_slice(&encoder.finish().expect("finish"));

        let provider = test_provider(RuleProviderBehavior::Classical);
        let set = provider
            .compile_payload(&payload)
            .expect("a binary payload compiles");
        assert_eq!(set.matchable_count(), 1);
        assert!(set.matches(&domain_input("www.example.com")));
        assert!(set.matches(&domain_input("example.com")));
        assert!(!set.matches(&domain_input("example.org")));
        // A binary set of domains must never trigger a DNS lookup.
        assert!(!set.has_dst_ip_entries());
    }

    /// A rule set that declares more keywords than the ceiling is refused before
    /// it is indexed: keyword matching costs a scan per keyword per connection.
    #[test]
    fn a_payload_past_the_keyword_ceiling_is_refused() {
        let provider = test_provider(RuleProviderBehavior::Classical);
        let mut payload = String::new();
        for index in 0..=crate::engine::ruleset::MAX_RULE_SET_KEYWORDS {
            payload.push_str(&format!("DOMAIN-KEYWORD,word{index}\n"));
        }
        let error = provider
            .compile_payload(payload.as_bytes())
            .expect_err("the ceiling must be enforced");
        assert!(error.to_string().contains("keyword"), "{error}");
    }

    /// The same ceiling applies to the binary container, read from its own count.
    #[test]
    fn a_binary_payload_past_the_entry_ceiling_is_refused() {
        use crate::engine::ruleset::mrs;

        let body = {
            let set = crate::engine::ruleset::succinct::SuccinctSet::from_keys(vec![
                "moc.elpmaxe".to_string(),
            ]);
            let mut body = Vec::new();
            set.write_wire_v1(&mut body);
            body
        };
        let payload = mrs::encode_for_test(
            0,
            &body,
            crate::engine::ruleset::MAX_RULE_SET_ENTRIES + 1,
            &[],
        );
        let provider = test_provider(RuleProviderBehavior::Domain);
        let error = provider
            .compile_payload(&payload)
            .expect_err("the ceiling must be enforced");
        assert!(error.to_string().contains("ceiling"), "{error}");
    }

    /// The `.mrs` container end to end: detected by its zstd frame, decompressed,
    /// decoded, and matched through the provider's normal entry point.
    #[test]
    fn a_binary_mrs_payload_is_detected_and_matched() {
        use crate::engine::ruleset::mrs;
        use crate::engine::ruleset::succinct::SuccinctSet;

        // An exact key: `example.com` and nothing below it.
        let set = SuccinctSet::from_keys(vec!["moc.elpmaxe".to_string()]);
        let mut body = Vec::new();
        set.write_wire_v1(&mut body);
        let payload = mrs::encode_for_test(0, &body, 1, &[]);

        let provider = test_provider(RuleProviderBehavior::Domain);
        let compiled = provider
            .compile_payload(&payload)
            .expect("a binary payload compiles");
        assert_eq!(compiled.matchable_count(), 1);
        assert!(compiled.matches(&domain_input("example.com")));
        assert!(!compiled.matches(&domain_input("www.example.com")));
        assert!(!compiled.has_dst_ip_entries());
    }

    /// An address set, which is the other behavior the container defines.
    #[test]
    fn a_binary_mrs_address_set_matches_by_destination() {
        use crate::engine::ruleset::mrs;

        let mut body = Vec::new();
        body.push(1);
        body.extend_from_slice(&1i64.to_be_bytes());
        for address in ["10.0.0.0", "10.255.255.255"] {
            let ipv4: std::net::Ipv4Addr = address.parse().expect("address");
            body.extend_from_slice(&ipv4.to_ipv6_mapped().octets());
        }
        let payload = mrs::encode_for_test(1, &body, 1, &[]);

        let provider = test_provider(RuleProviderBehavior::IpCidr);
        let compiled = provider
            .compile_payload(&payload)
            .expect("a binary payload compiles");
        assert!(compiled.has_dst_ip_entries());
        assert!(compiled.matches(&RuleMatchInput {
            dst_ip: Some("10.9.8.7".parse().expect("ip")),
            ..RuleMatchInput::default()
        }));
        assert!(!compiled.matches(&RuleMatchInput {
            dst_ip: Some("11.0.0.1".parse().expect("ip")),
            ..RuleMatchInput::default()
        }));
    }

    /// The index and the single-entry path must agree on every input. They use
    /// different mechanisms — hash sets and label walking against a direct scan
    /// — so this is what keeps the two from drifting apart.
    #[test]
    fn the_index_agrees_with_the_single_entry_path() {
        let entries = vec![
            CompiledRuleEntry::Domain("exact.example.com".to_string()),
            CompiledRuleEntry::DomainSuffix("suffix.example.com".to_string()),
            CompiledRuleEntry::DomainKeyword("keyword".to_string()),
            CompiledRuleEntry::DomainRegex(Regex::new(r"^re\..*\.net$").expect("valid regex")),
            CompiledRuleEntry::IpCidr("10.0.0.0/8".parse().expect("valid cidr")),
            CompiledRuleEntry::Classical {
                rule_type: ClassicalRuleType::SrcIpCidr,
                pattern: "192.168.0.0/16".to_string(),
                regex: None,
            },
            CompiledRuleEntry::Classical {
                rule_type: ClassicalRuleType::ProcessName,
                pattern: "qbittorrent.exe".to_string(),
                regex: None,
            },
        ];
        let provider = provider_with_entries(entries.clone());
        let index = RuleIndex::compile(&entries);

        let cases = [
            domain_input("exact.example.com"),
            domain_input("EXACT.EXAMPLE.COM"),
            domain_input("a.suffix.example.com"),
            domain_input("suffix.example.com"),
            domain_input("notsuffix.example.com"),
            domain_input("www.keyword.net"),
            domain_input("re.foo.net"),
            domain_input("re.foo.org"),
            dst_input("10.1.2.3"),
            dst_input("11.1.2.3"),
            src_input("192.168.5.5"),
            src_input("10.1.2.3"),
            process_input(r"C:\Program Files\qBittorrent\qbittorrent.exe"),
            process_input("firefox.exe"),
            RuleMatchInput {
                domain: Some("www.google.com"),
                dst_ip: Some("10.0.0.1".parse().expect("valid")),
                src_ip: Some("192.168.1.1".parse().expect("valid")),
                process_name: Some("chrome"),
                ..RuleMatchInput::default()
            },
        ];

        for case in cases {
            let expected = entries
                .iter()
                .any(|entry| provider.matches_entry(entry, &case));
            assert_eq!(
                index.matches(&case),
                expected,
                "index and direct path disagree on {case:?}"
            );
        }
    }

    /// `SRC-IP-CIDR` compares the source address and `IP-CIDR` the destination.
    /// They used to share one branch that read the destination for both, so a
    /// source rule could never fire.
    #[test]
    fn source_and_destination_cidrs_use_different_addresses() {
        let index = RuleIndex::compile(&[
            CompiledRuleEntry::Classical {
                rule_type: ClassicalRuleType::SrcIpCidr,
                pattern: "192.168.0.0/16".to_string(),
                regex: None,
            },
            CompiledRuleEntry::Classical {
                rule_type: ClassicalRuleType::IpCidr,
                pattern: "10.0.0.0/8".to_string(),
                regex: None,
            },
        ]);

        let case = |src: &str, dst: &str| RuleMatchInput {
            src_ip: Some(src.parse().expect("valid")),
            dst_ip: Some(dst.parse().expect("valid")),
            ..RuleMatchInput::default()
        };

        assert!(index.matches(&case("192.168.1.1", "203.0.113.1")));
        assert!(index.matches(&case("203.0.113.1", "10.1.1.1")));
        assert!(!index.matches(&case("203.0.113.1", "203.0.113.2")));
        // A source address must not satisfy a destination rule.
        assert!(!index.matches(&src_input("10.1.1.1")));
    }

    /// A suffix is a label boundary, not a string tail.
    #[test]
    fn suffix_matching_respects_the_label_boundary() {
        let index =
            RuleIndex::compile(&[CompiledRuleEntry::DomainSuffix("example.com".to_string())]);
        assert!(index.matches(&domain_input("example.com")));
        assert!(index.matches(&domain_input("a.example.com")));
        assert!(index.matches(&domain_input("EXAMPLE.COM")));
        assert!(!index.matches(&domain_input("notexample.com")));
        assert!(!index.matches(&domain_input("example.com.evil.net")));
    }

    /// Unusable entries are reported rather than dropped: a rule that never
    /// matches is invisible otherwise.
    #[test]
    fn unusable_entries_are_reported() {
        let index = RuleIndex::compile(&[
            CompiledRuleEntry::IpCidr("10.0.0.0/8".parse().expect("valid")),
            CompiledRuleEntry::Classical {
                rule_type: ClassicalRuleType::IpCidr,
                pattern: "not-a-cidr".to_string(),
                regex: None,
            },
        ]);
        assert_eq!(index.matchable_count(), 1);
        assert_eq!(index.rejected.len(), 1);
        assert!(index.rejected[0].contains("not-a-cidr"));
    }

    /// Folding must borrow when the hostname is already lowercase, which is what
    /// every well-formed client sends.
    #[test]
    fn folding_borrows_when_there_is_nothing_to_fold() {
        assert!(matches!(fold_ascii_lower("example.com"), Cow::Borrowed(_)));
        assert!(matches!(fold_ascii_lower("Example.com"), Cow::Owned(_)));
    }
}
