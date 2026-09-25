use crate::engine::error::{Error, Result};
use ipnet::IpNet;
use nextjson::{NsonDeserialize, NsonSerialize};
use parking_lot::RwLock;
use regex::Regex;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
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
    /// Address the connection came from.
    pub src_ip: Option<IpAddr>,
    /// Executable name owning the connection.
    pub process_name: Option<&'a str>,
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

/// Whether any configured suffix ends `domain` on a label boundary.
///
/// Walks the domain's own labels — at most one hash probe per label — instead of
/// asking every suffix in the set whether it matches. On a rule set with tens of
/// thousands of suffixes that is the difference between four lookups and fifty
/// thousand comparisons, and it is why suffix-heavy sets are usable at all.
fn suffix_matches(suffixes: &HashSet<Box<str>>, domain: &str) -> bool {
    if suffixes.is_empty() {
        return false;
    }
    let mut rest = domain;
    loop {
        if suffixes.contains(rest) {
            return true;
        }
        match rest.split_once('.') {
            Some((_, tail)) => rest = tail,
            None => return false,
        }
    }
}

/// A rule set arranged for lookup rather than for storage.
///
/// [`CompiledRuleEntry`] stays as authored so a set can be inspected and
/// reported; this is what matching runs against. Every pattern is folded to
/// ASCII lowercase exactly once, here, so the hot path never lowercases,
/// formats or parses anything — the three things the previous linear scan did
/// per entry, per connection.
#[derive(Debug, Default)]
struct RuleIndex {
    /// Fully-qualified domains: one hash probe.
    exact: HashSet<Box<str>>,
    /// Domain suffixes: one probe per label of the queried domain.
    suffixes: HashSet<Box<str>>,
    /// Substrings, which have no structure a set can exploit and stay a list.
    keywords: Vec<Box<str>>,
    regexes: Vec<Regex>,
    /// Destination networks, pre-parsed.
    dst_nets: Vec<IpNet>,
    /// Source networks, pre-parsed. Kept separate from `dst_nets` because they
    /// are compared against a different address.
    src_nets: Vec<IpNet>,
    /// Process names, folded.
    process_names: Vec<Box<str>>,
    /// Entries that parsed but could not be indexed, with the reason.
    /// Kept so a bad rule set is a diagnostic rather than a silent no-match.
    rejected: Vec<String>,
}

impl RuleIndex {
    fn compile(entries: &[CompiledRuleEntry]) -> Self {
        let mut index = Self::default();
        for entry in entries {
            index.add(entry);
        }
        index
    }

    fn add(&mut self, entry: &CompiledRuleEntry) {
        match entry {
            CompiledRuleEntry::Domain(pattern) => {
                if !pattern.is_empty() {
                    self.exact.insert(folded_box(pattern));
                }
            }
            CompiledRuleEntry::DomainSuffix(pattern) => {
                if !pattern.is_empty() {
                    self.suffixes.insert(folded_box(pattern));
                }
            }
            CompiledRuleEntry::DomainKeyword(pattern) => {
                if !pattern.is_empty() {
                    self.keywords.push(folded_box(pattern));
                }
            }
            CompiledRuleEntry::DomainRegex(regex) => self.regexes.push(regex.clone()),
            CompiledRuleEntry::IpCidr(network) => self.dst_nets.push(*network),
            CompiledRuleEntry::Classical {
                rule_type,
                pattern,
                regex,
            } => match rule_type {
                ClassicalRuleType::Domain => {
                    if !pattern.is_empty() {
                        self.exact.insert(folded_box(pattern));
                    }
                }
                ClassicalRuleType::DomainSuffix => {
                    if !pattern.is_empty() {
                        self.suffixes.insert(folded_box(pattern));
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
                    Ok(network) => self.dst_nets.push(network),
                    Err(error) => self.rejected.push(format!("IP-CIDR '{pattern}': {error}")),
                },
                ClassicalRuleType::SrcIpCidr => match pattern.trim().parse::<IpNet>() {
                    Ok(network) => self.src_nets.push(network),
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
        self.exact.len()
            + self.suffixes.len()
            + self.keywords.len()
            + self.regexes.len()
            + self.dst_nets.len()
            + self.src_nets.len()
            + self.process_names.len()
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
            let domain = fold_ascii_lower(domain.trim_end_matches('.'));
            let domain = domain.as_ref();
            if self.exact.contains(domain)
                || suffix_matches(&self.suffixes, domain)
                || self
                    .keywords
                    .iter()
                    .any(|keyword| domain.contains(keyword.as_ref()))
                || self.regexes.iter().any(|regex| regex.is_match(domain))
            {
                return true;
            }
        }

        if let Some(address) = input.dst_ip {
            if self
                .dst_nets
                .iter()
                .any(|network| network.contains(&address))
            {
                return true;
            }
        }

        if let Some(address) = input.src_ip {
            if self
                .src_nets
                .iter()
                .any(|network| network.contains(&address))
            {
                return true;
            }
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

pub struct RuleProvider {
    config: RuleProviderConfig,
    index: RwLock<RuleIndex>,
    last_update: RwLock<Option<Instant>>,
}

impl RuleProvider {
    pub fn new(config: RuleProviderConfig) -> Self {
        Self {
            config,
            index: RwLock::new(RuleIndex::default()),
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
        let content = match self.config.provider_type {
            RuleProviderType::File => self.load_from_file()?,
            RuleProviderType::Http => self.load_from_http()?,
        };

        let entries = self.parse_rules(&content)?;
        if entries.is_empty() {
            return Err(Error::config(format!(
                "Rule provider '{}' did not contain any supported rules",
                self.config.name
            )));
        }

        let index = RuleIndex::compile(&entries);
        let indexed = index.matchable_count();
        if indexed == 0 {
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
                indexed,
                entries.len(),
                index.rejected.len(),
                index.rejected_summary()
            );
        }

        *self.index.write() = index;

        *self.last_update.write() = Some(Instant::now());

        tracing::info!(
            "Rule provider '{}' loaded {} rules",
            self.config.name,
            indexed
        );

        Ok(())
    }

    fn load_from_file(&self) -> Result<String> {
        let path = self
            .config
            .path
            .as_ref()
            .ok_or_else(|| Error::config("File rule provider requires 'path' field"))?;

        std::fs::read_to_string(path)
            .map_err(|e| Error::config(format!("Failed to read rule file '{}': {}", path, e)))
    }

    fn load_from_http(&self) -> Result<String> {
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

        let content = response
            .text()
            .map_err(|e| Error::network(format!("Failed to read response body: {e}")))?;

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
    ) -> Result<String> {
        if let Some(path) = cache_path {
            if let Ok(content) = std::fs::read_to_string(path) {
                tracing::warn!(
                    "Using cached rule provider '{}' after refresh failed: {}",
                    self.config.name,
                    message
                );
                return Ok(content);
            }
        }
        Err(Error::network(message))
    }

    pub fn parse_rules(&self, content: &str) -> Result<Vec<CompiledRuleEntry>> {
        match self.config.behavior {
            RuleProviderBehavior::Domain => self.parse_domain_rules(content),
            RuleProviderBehavior::IpCidr => self.parse_ipcidr_rules(content),
            RuleProviderBehavior::Classical => self.parse_classical_rules(content),
        }
    }

    fn parse_domain_rules(&self, content: &str) -> Result<Vec<CompiledRuleEntry>> {
        let mut rules = Vec::new();

        if let Ok(yaml_content) = nextjson::from_str::<nextjson::Value>(content) {
            if let Some(payload) = yaml_content.get("payload").and_then(|v| v.as_array()) {
                for item in payload {
                    if let Some(domain) = item.as_str() {
                        rules.push(self.parse_domain_entry(domain));
                    }
                }
                return Ok(rules);
            }
        }

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            rules.push(self.parse_domain_entry(line));
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

    fn parse_ipcidr_rules(&self, content: &str) -> Result<Vec<CompiledRuleEntry>> {
        let mut rules = Vec::new();

        if let Ok(yaml_content) = nextjson::from_str::<nextjson::Value>(content) {
            if let Some(payload) = yaml_content.get("payload").and_then(|v| v.as_array()) {
                for item in payload {
                    if let Some(cidr) = item.as_str() {
                        if let Ok(network) = cidr.parse::<IpNet>() {
                            rules.push(CompiledRuleEntry::IpCidr(network));
                        }
                    }
                }
                return Ok(rules);
            }
        }

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            if let Ok(network) = line.parse::<IpNet>() {
                rules.push(CompiledRuleEntry::IpCidr(network));
            }
        }

        Ok(rules)
    }

    fn parse_classical_rules(&self, content: &str) -> Result<Vec<CompiledRuleEntry>> {
        let mut rules = Vec::new();

        if let Ok(yaml_content) = nextjson::from_str::<nextjson::Value>(content) {
            if let Some(payload) = yaml_content.get("payload").and_then(|v| v.as_array()) {
                for item in payload {
                    if let Some(rule_str) = item.as_str() {
                        if let Some(entry) = self.parse_classical_entry(rule_str) {
                            rules.push(entry);
                        }
                    }
                }
                return Ok(rules);
            }
        }

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            if let Some(entry) = self.parse_classical_entry(line) {
                rules.push(entry);
            }
        }

        Ok(rules)
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
        self.index.read().matches(input)
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
                .is_some_and(|address| network.contains(&address)),
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
                            .is_some_and(|address| network.contains(&address))
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
        self.index.read().matchable_count()
    }

    pub fn last_update_time(&self) -> Option<Instant> {
        *self.last_update.read()
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
        *provider.index.write() = RuleIndex::compile(&entries);
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
