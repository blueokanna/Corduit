use crate::common::lru::LruCache;
use crate::engine::config::{Config, Mode, RuleConfig, RuleType};
use crate::engine::error::{Error, Result};
use crate::engine::geoip::{is_local_or_private_ip, CountryMatcher, GeoIpManager};
use crate::engine::rule_provider::RuleProviderConfig;
use crate::engine::rule_provider::RuleProviderManager;
use ipnet::IpNet;
use parking_lot::{Mutex, RwLock};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::sync::RwLock as StdRwLock;
use std::time::{Duration, Instant};

static RUNTIME_PROXY_MODE: AtomicI32 = AtomicI32::new(0);
static RUNTIME_RULE_PROVIDERS: once_cell::sync::Lazy<StdRwLock<Vec<RuleProviderConfig>>> =
    once_cell::sync::Lazy::new(|| StdRwLock::new(Vec::new()));
const DNS_CACHE_CAPACITY: usize = 4096;
const DNS_CACHE_TTL: Duration = Duration::from_secs(300);
const DNS_NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(30);
const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);

/// Runtime proxy mode values.
///
/// Kept as `i32` because they cross the C ABI (see `corduit-lib`); the names
/// below are the single source of truth so the engine never spells magic
/// numbers.
pub mod proxy_mode {
    /// Follow the configured `general.mode`.
    pub const CONFIG: i32 = 0;
    /// Route everything through the proxy group.
    pub const GLOBAL: i32 = 1;
    /// Route everything directly.
    pub const DIRECT: i32 = 2;
    /// Use rule matching.
    pub const RULE: i32 = 3;
}

pub fn set_runtime_proxy_mode(mode: i32) {
    let normalized = match mode {
        proxy_mode::CONFIG | proxy_mode::GLOBAL | proxy_mode::DIRECT | proxy_mode::RULE => mode,
        // Unknown values fall back to the configured mode instead of
        // poisoning the engine with an unhandled state.
        _ => proxy_mode::CONFIG,
    };
    tracing::info!("Setting runtime proxy mode to {}", normalized);
    RUNTIME_PROXY_MODE.store(normalized, Ordering::SeqCst);
}

#[derive(Clone)]
struct CachedResolution {
    addresses: Vec<IpAddr>,
    expires_at: Instant,
}

static DNS_CACHE: once_cell::sync::Lazy<Mutex<LruCache<String, CachedResolution>>> =
    once_cell::sync::Lazy::new(|| {
        Mutex::new(LruCache::new(
            NonZeroUsize::new(DNS_CACHE_CAPACITY).expect("DNS cache capacity must be non-zero"),
        ))
    });

pub fn get_runtime_proxy_mode() -> i32 {
    RUNTIME_PROXY_MODE.load(Ordering::SeqCst)
}

pub fn set_runtime_rule_providers(providers: Vec<RuleProviderConfig>) {
    match RUNTIME_RULE_PROVIDERS.write() {
        Ok(mut configured) => *configured = providers,
        Err(poisoned) => *poisoned.into_inner() = providers,
    }
}

fn runtime_rule_providers() -> Vec<RuleProviderConfig> {
    match RUNTIME_RULE_PROVIDERS.read() {
        Ok(configured) => configured.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

/// Whether two rule provider configs differ in any field that affects the
/// loaded rule set. Unchanged providers are left untouched on reload so their
/// rules keep working while the provider updater refreshes them in place.
fn rule_provider_config_changed(a: &RuleProviderConfig, b: &RuleProviderConfig) -> bool {
    a.provider_type != b.provider_type
        || a.behavior != b.behavior
        || a.url != b.url
        || a.path != b.path
        || a.interval != b.interval
}

pub struct Router {
    config: Arc<RwLock<Config>>,
    rules: RwLock<Vec<CompiledRule>>,
    /// Pre-resolved default outbound tags — no per-request scan of `outbounds`.
    defaults: RwLock<DefaultOutbounds>,
    geoip_manager: Arc<dyn CountryMatcher>,
    /// Arc so the background provider updater can share the same manager.
    rule_provider_manager: Arc<RuleProviderManager>,
}

/// Fallback outbound tags resolved once per configuration, not per request.
#[derive(Debug, Clone)]
struct DefaultOutbounds {
    direct: String,
    global: Option<String>,
    default: String,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    rule_type: RuleType,
    /// Canonical pattern. Domain/process patterns are lowercased once at
    /// compile time so matching never allocates or re-parses.
    pattern: String,
    outbound: String,
    #[allow(dead_code)]
    process_name: Option<String>,
    regex: Option<Regex>,
    /// Pre-parsed CIDR for `IpCidr` / `SrcIpCidr` rules.
    ipnet: Option<IpNet>,
    /// Pre-parsed inclusive port ranges for `SrcPort` / `DstPort` rules.
    port_ranges: Vec<(u16, u16)>,
}

impl Router {
    pub fn new(config: Arc<RwLock<Config>>) -> Result<Self> {
        let rules = Self::compile_rules(&config.read().rules)?;
        let geoip_manager: Arc<dyn CountryMatcher> =
            Arc::new(GeoIpManager::from_embedded_country_database());
        let rule_provider_manager = Arc::new(RuleProviderManager::new());
        let provider_configs = runtime_rule_providers();
        let configured_names: HashSet<&str> = provider_configs
            .iter()
            .map(|provider| provider.name.as_str())
            .collect();
        for provider_name in rules
            .iter()
            .filter(|rule| rule.rule_type == RuleType::RuleSet)
            .map(|rule| rule.pattern.as_str())
        {
            if !configured_names.contains(provider_name) {
                return Err(Error::config(format!(
                    "Rule references missing provider '{provider_name}'"
                )));
            }
        }

        // Load each rule provider synchronously in configuration order. Each
        // provider fetch blocks (file read or bounded HTTP GET), which is
        // fine at startup / reload on a worker thread.
        for provider in provider_configs {
            let provider_name = provider.name.clone();
            rule_provider_manager
                .add_provider(provider)
                .map_err(|error| {
                    Error::config(format!(
                        "Failed to load rule provider '{provider_name}': {error}"
                    ))
                })?;
        }

        let defaults = {
            let config_guard = config.read();
            Self::resolve_default_outbounds(&config_guard)
        };

        Ok(Self {
            config,
            rules: RwLock::new(rules),
            defaults: RwLock::new(defaults),
            geoip_manager,
            rule_provider_manager,
        })
    }

    pub fn load_geoip_database(&self, path: &str) -> Result<()> {
        self.geoip_manager.load_database(path)
    }

    pub fn load_geoip_database_from_bytes(&self, data: Vec<u8>) -> Result<()> {
        self.geoip_manager.load_database_from_bytes(data)
    }

    pub fn rule_provider_manager(&self) -> &RuleProviderManager {
        &self.rule_provider_manager
    }

    /// Shared handle to the rule provider manager (used by the background
    /// provider updater for interval refreshes).
    pub fn rule_provider_manager_arc(&self) -> Arc<RuleProviderManager> {
        Arc::clone(&self.rule_provider_manager)
    }

    pub fn match_outbound(
        &self,
        domain: Option<&str>,
        ip: Option<IpAddr>,
        port: Option<u16>,
        process_name: Option<&str>,
    ) -> String {
        let runtime_mode = get_runtime_proxy_mode();
        let effective_mode = {
            let config = self.config.read();
            match runtime_mode {
                proxy_mode::GLOBAL => Mode::Global,
                proxy_mode::DIRECT => Mode::Direct,
                proxy_mode::RULE => Mode::Rule,
                _ => config.general.mode,
            }
        };
        let (direct_outbound, global_outbound, default_outbound) = {
            let defaults = self.defaults.read();
            (
                defaults.direct.clone(),
                defaults.global.clone(),
                defaults.default.clone(),
            )
        };

        tracing::debug!(
            "Routing request: domain={:?}, ip={:?}, port={:?}, mode={:?}",
            domain,
            ip,
            port,
            effective_mode
        );

        if matches!(effective_mode, Mode::Global) {
            if let Some(outbound) = global_outbound {
                tracing::info!("Global mode: routing to proxy outbound '{}'", outbound);
                return outbound;
            }
            return direct_outbound;
        }

        if matches!(effective_mode, Mode::Direct) {
            tracing::debug!("Direct mode: routing to '{}'", direct_outbound);
            return direct_outbound;
        }

        let rules = self.rules.read();

        // DNS is resolved lazily and cached for the duration of this request.
        // Pure domain-rule configs (the common case, e.g. clash-rules sets)
        // never touch the resolver; only the no-rule China shortcut and
        // geoip/ip-cidr rules that need an IP trigger a lookup — at most once
        // per request, reused across every IP-based rule.
        let mut resolved_ips: Option<Vec<IpAddr>> = None;

        // The mainland-China auto-direct shortcut is a fallback for configs
        // with no rules at all. Once rules are configured (e.g. the clash-rules
        // sets), rules are evaluated strictly in order — Clash semantics — so
        // an explicit rule always wins over the shortcut.
        if rules.is_empty() {
            if Self::is_mainland_china_domain(domain) {
                tracing::info!(
                    "Mainland China domain identified: domain={:?} -> '{}'",
                    domain,
                    direct_outbound
                );
                return direct_outbound;
            }

            if resolved_ips.is_none() {
                resolved_ips = Some(Self::resolve_destination_ips(domain, ip));
            }
            if self.is_mainland_china_ip(resolved_ips.as_deref().unwrap_or(&[])) {
                tracing::info!(
                    "Mainland China destination identified: domain={:?}, ips={:?} -> '{}'",
                    domain,
                    resolved_ips,
                    direct_outbound
                );
                return direct_outbound;
            }
        }

        for rule in rules.iter() {
            let mut matched = self.matches_rule(rule, domain, ip, port, process_name);
            if !matched
                && ip.is_none()
                && matches!(rule.rule_type, RuleType::Geoip | RuleType::IpCidr)
            {
                if resolved_ips.is_none() {
                    resolved_ips = Some(Self::resolve_destination_ips(domain, ip));
                }
                if let Some(resolved_ips) = resolved_ips.as_deref() {
                    for resolved_ip in resolved_ips {
                        if self.matches_rule(rule, domain, Some(*resolved_ip), port, process_name) {
                            matched = true;
                            break;
                        }
                    }
                }
            }
            if matched {
                tracing::info!(
                    "Rule matched: {:?} '{}' -> '{}'",
                    rule.rule_type,
                    rule.pattern,
                    rule.outbound
                );
                return rule.outbound.clone();
            }
        }

        tracing::debug!(
            "No rule matched, using default outbound: {}",
            default_outbound
        );
        default_outbound
    }

    fn is_mainland_china_domain(domain: Option<&str>) -> bool {
        let Some(domain) = domain else {
            return false;
        };
        let normalized = domain.trim().trim_end_matches('.');
        normalized.eq_ignore_ascii_case("cn")
            || normalized
                .get(normalized.len().saturating_sub(3)..)
                .is_some_and(|suffix| suffix.eq_ignore_ascii_case(".cn"))
    }

    fn is_mainland_china_ip(&self, addresses: &[IpAddr]) -> bool {
        for address in addresses {
            if is_local_or_private_ip(*address)
                || self.geoip_manager.matches_country("CN", *address)
            {
                return true;
            }
        }
        false
    }

    fn resolve_destination_ips(domain: Option<&str>, ip: Option<IpAddr>) -> Vec<IpAddr> {
        if let Some(ip) = ip {
            return vec![ip];
        }

        let Some(domain) = domain else {
            return Vec::new();
        };
        let normalized = domain
            .trim()
            .trim_end_matches('.')
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase();
        if normalized.is_empty() {
            return Vec::new();
        }
        if let Ok(ip) = normalized.parse::<IpAddr>() {
            return vec![ip];
        }

        let now = Instant::now();
        {
            let mut cache = DNS_CACHE.lock();
            if let Some(cached) = cache.get(&normalized) {
                if cached.expires_at > now {
                    return cached.addresses.clone();
                }
            }
            cache.pop(&normalized);
        }

        // `resolve_host` runs the system resolver on a dedicated thread so the
        // caller is not stalled for the resolver's full hang time; resolution
        // errors degrade to domain-rule-only matching.
        let addresses =
            match crate::common::socket::resolve_host(&normalized, 0, DNS_LOOKUP_TIMEOUT) {
                Ok(resolved) => {
                    let mut addresses = Vec::new();
                    for socket_address in resolved {
                        let address = socket_address.ip();
                        if !addresses.contains(&address) {
                            addresses.push(address);
                        }
                    }
                    addresses
                }
                Err(error) => {
                    tracing::debug!("Failed to resolve '{}' for routing: {}", normalized, error);
                    Vec::new()
                }
            };
        let ttl = if addresses.is_empty() {
            DNS_NEGATIVE_CACHE_TTL
        } else {
            DNS_CACHE_TTL
        };
        DNS_CACHE.lock().put(
            normalized,
            CachedResolution {
                addresses: addresses.clone(),
                expires_at: now + ttl,
            },
        );
        addresses
    }

    pub fn reload(&self) -> Result<()> {
        let (new_rules, defaults) = {
            let config = self.config.read();
            let new_rules = Self::compile_rules(&config.rules)?;
            let defaults = Self::resolve_default_outbounds(&config);
            (new_rules, defaults)
        };
        {
            let mut rules = self.rules.write();
            *rules = new_rules;
        }
        {
            let mut defaults_guard = self.defaults.write();
            *defaults_guard = defaults;
        }
        self.refresh_rule_providers()?;
        Ok(())
    }

    /// Synchronize the loaded rule providers with the runtime configuration:
    /// remove providers that disappeared, add new ones, and replace providers
    /// whose config changed. Unchanged providers keep their loaded rules and
    /// are refreshed in the background by the provider updater.
    fn refresh_rule_providers(&self) -> Result<()> {
        let desired = runtime_rule_providers();
        let current: HashSet<String> = self
            .rule_provider_manager
            .get_provider_names()
            .into_iter()
            .collect();

        let mut desired_map: HashMap<String, RuleProviderConfig> = HashMap::new();
        for config in desired {
            let name = config.name.clone();
            if desired_map.insert(name.clone(), config).is_some() {
                return Err(Error::config(format!(
                    "Duplicate rule provider name '{name}'"
                )));
            }
        }

        // Remove providers that are no longer configured.
        for name in &current {
            if !desired_map.contains_key(name) {
                self.rule_provider_manager.remove_provider(name);
            }
        }

        // Add new providers and replace changed ones.
        for (name, config) in desired_map {
            match self.rule_provider_manager.get_provider(&name) {
                Some(existing) if !rule_provider_config_changed(existing.config(), &config) => {}
                Some(_) => {
                    self.rule_provider_manager.remove_provider(&name);
                    self.rule_provider_manager.add_provider(config)?;
                }
                None => {
                    self.rule_provider_manager.add_provider(config)?;
                }
            }
        }
        Ok(())
    }

    /// Compute the fallback outbound tags for a given configuration.
    fn resolve_default_outbounds(config: &Config) -> DefaultOutbounds {
        let direct = config
            .outbounds
            .iter()
            .find(|outbound| outbound.outbound_type == crate::engine::config::OutboundType::Direct)
            .map(|outbound| outbound.tag.clone())
            .unwrap_or_else(|| "DIRECT".to_string());
        let global = config
            .outbounds
            .iter()
            .find(|outbound| {
                matches!(
                    outbound.outbound_type,
                    crate::engine::config::OutboundType::Selector
                        | crate::engine::config::OutboundType::Urltest
                        | crate::engine::config::OutboundType::Fallback
                        | crate::engine::config::OutboundType::Loadbalance
                )
            })
            .or_else(|| {
                config.outbounds.iter().find(|outbound| {
                    !matches!(
                        outbound.outbound_type,
                        crate::engine::config::OutboundType::Direct
                            | crate::engine::config::OutboundType::Reject
                    )
                })
            })
            .map(|outbound| outbound.tag.clone());
        let default = config
            .outbounds
            .first()
            .map(|outbound| outbound.tag.clone())
            .unwrap_or_else(|| direct.clone());
        DefaultOutbounds {
            direct,
            global,
            default,
        }
    }

    fn compile_rules(rules: &[RuleConfig]) -> Result<Vec<CompiledRule>> {
        let mut compiled = Vec::with_capacity(rules.len());

        for rule in rules {
            let regex = if rule.rule_type == RuleType::DomainRegex {
                Some(
                    Regex::new(&rule.payload)
                        .map_err(|e| Error::config(format!("Invalid regex pattern: {}", e)))?,
                )
            } else {
                None
            };

            // Pre-parse CIDRs and port ranges so hot-path matching never
            // re-parses strings. Invalid payloads fail loudly at compile time.
            let ipnet = if matches!(rule.rule_type, RuleType::IpCidr | RuleType::SrcIpCidr) {
                Some(rule.payload.parse::<IpNet>().map_err(|e| {
                    Error::config(format!("Invalid CIDR '{}': {}", rule.payload, e))
                })?)
            } else {
                None
            };
            let port_ranges = if matches!(rule.rule_type, RuleType::SrcPort | RuleType::DstPort) {
                Self::compile_port_ranges(&rule.payload)?
            } else {
                Vec::new()
            };

            // Lowercase domain/process patterns once; matching then uses
            // case-insensitive comparisons with zero allocations.
            let pattern = if matches!(
                rule.rule_type,
                RuleType::Domain | RuleType::DomainSuffix | RuleType::DomainKeyword
            ) {
                rule.payload.to_ascii_lowercase()
            } else {
                rule.payload.clone()
            };

            compiled.push(CompiledRule {
                rule_type: rule.rule_type,
                pattern,
                outbound: rule.outbound.clone(),
                process_name: rule.process_name.clone(),
                regex,
                ipnet,
                port_ranges,
            });
        }

        Ok(compiled)
    }

    /// Parse a comma-separated port list / range list into inclusive ranges.
    fn compile_port_ranges(pattern: &str) -> Result<Vec<(u16, u16)>> {
        let mut ranges = Vec::new();
        for part in pattern.split(',') {
            let part = part.trim();
            if part.is_empty() {
                return Err(Error::config("Empty port in port rule"));
            }
            if let Some((start, end)) = part.split_once('-') {
                let start: u16 = start
                    .trim()
                    .parse()
                    .map_err(|_| Error::config(format!("Invalid port '{start}'")))?;
                let end: u16 = end
                    .trim()
                    .parse()
                    .map_err(|_| Error::config(format!("Invalid port '{end}'")))?;
                if start > end {
                    return Err(Error::config(format!("Invalid port range '{part}'")));
                }
                ranges.push((start, end));
            } else {
                let port: u16 = part
                    .parse()
                    .map_err(|_| Error::config(format!("Invalid port '{part}'")))?;
                ranges.push((port, port));
            }
        }
        Ok(ranges)
    }

    fn matches_rule(
        &self,
        rule: &CompiledRule,
        domain: Option<&str>,
        ip: Option<IpAddr>,
        port: Option<u16>,
        process_name: Option<&str>,
    ) -> bool {
        match rule.rule_type {
            RuleType::Domain => domain.is_some_and(|d| d.eq_ignore_ascii_case(&rule.pattern)),
            RuleType::DomainSuffix => {
                domain.is_some_and(|d| Self::matches_domain_suffix(d, &rule.pattern))
            }
            RuleType::DomainKeyword => {
                domain.is_some_and(|d| contains_ignore_case(d, &rule.pattern))
            }
            RuleType::DomainRegex => {
                if let Some(domain) = domain {
                    if let Some(regex) = &rule.regex {
                        regex.is_match(domain)
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            RuleType::IpCidr | RuleType::SrcIpCidr => {
                if let Some(ip) = ip {
                    rule.ipnet.is_some_and(|network| network.contains(&ip))
                } else {
                    false
                }
            }
            RuleType::Geoip => {
                if let Some(ip) = ip {
                    self.geoip_manager.matches_country(&rule.pattern, ip)
                } else {
                    false
                }
            }
            RuleType::SrcPort | RuleType::DstPort => {
                if let Some(port) = port {
                    rule.port_ranges
                        .iter()
                        .any(|(start, end)| port >= *start && port <= *end)
                } else {
                    false
                }
            }
            RuleType::ProcessName => {
                if let Some(process) = process_name {
                    Self::matches_process_name(&rule.pattern, process)
                } else {
                    false
                }
            }
            RuleType::RuleSet => {
                self.rule_provider_manager
                    .matches(&rule.pattern, domain, ip, process_name)
            }
            RuleType::Match => true,
        }
    }

    /// Match a domain against a lowercased suffix pattern (`example.com`),
    /// honoring the dotted boundary so `notexample.com` does not match.
    fn matches_domain_suffix(domain: &str, pattern: &str) -> bool {
        let domain = domain.trim_end_matches('.');
        if domain.eq_ignore_ascii_case(pattern) {
            return true;
        }
        let suffix_len = pattern.len();
        if domain.len() <= suffix_len {
            return false;
        }
        let start = domain.len() - suffix_len;
        domain.as_bytes()[start - 1] == b'.' && domain[start..].eq_ignore_ascii_case(pattern)
    }

    /// Match a process name against a lowercased pattern, checking the full
    /// path, the basename and the `.exe`-stripped variants.
    fn matches_process_name(pattern: &str, process_name: &str) -> bool {
        let process_lower = process_name.to_ascii_lowercase();

        if process_lower == pattern {
            return true;
        }

        if let Some(name) = process_name.rsplit(['/', '\\']).next() {
            if name.eq_ignore_ascii_case(pattern) {
                return true;
            }
        }

        if let Some(name_without_ext) = pattern.strip_suffix(".exe") {
            if process_lower == name_without_ext {
                return true;
            }
            if let Some(proc_name) = process_name.rsplit(['/', '\\']).next() {
                if proc_name.eq_ignore_ascii_case(name_without_ext) {
                    return true;
                }
            }
        }

        if let Some(proc_without_ext) = process_lower.strip_suffix(".exe") {
            if proc_without_ext == pattern {
                return true;
            }
        }

        false
    }

    #[cfg(test)]
    fn matches_cidr(cidr_str: &str, ip: IpAddr) -> bool {
        match cidr_str.parse::<IpNet>() {
            Ok(network) => network.contains(&ip),
            Err(_) => false,
        }
    }

    #[cfg(test)]
    fn matches_port_range(pattern: &str, port: u16) -> bool {
        for part in pattern.split(',') {
            let part = part.trim();
            if part.contains('-') {
                if let Some((start, end)) = part.split_once('-') {
                    if let (Ok(start), Ok(end)) =
                        (start.trim().parse::<u16>(), end.trim().parse::<u16>())
                    {
                        if port >= start && port <= end {
                            return true;
                        }
                    }
                }
            } else if let Ok(single_port) = part.parse::<u16>() {
                if port == single_port {
                    return true;
                }
            }
        }
        false
    }
}

/// Case-insensitive substring search without allocation.
fn contains_ignore_case(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let haystack = haystack.as_bytes();
    let needle = needle.as_bytes();
    if needle.len() > haystack.len() {
        return false;
    }
    let limit = haystack.len() - needle.len();
    (0..=limit).any(|i| haystack[i..i + needle.len()].eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::config::{OutboundConfig, OutboundType};

    /// The runtime proxy mode is a process-global; tests that set it must be
    /// serialized so parallel execution cannot interleave different modes.
    pub(super) static MODE_LOCK: once_cell::sync::Lazy<parking_lot::Mutex<()>> =
        once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(()));
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Deterministic matcher that mimics a real GeoIP database for a small set
    /// of well-known test IPs, so routing tests are independent of any
    /// on-disk `Country.mmdb`.
    struct StubCountryMatcher;

    impl CountryMatcher for StubCountryMatcher {
        fn matches_country(&self, country_code: &str, ip: IpAddr) -> bool {
            let is_cn = matches!(ip, IpAddr::V4(ipv4) if {
                let octets = ipv4.octets();
                octets == [114, 114, 114, 114] || octets == [1, 2, 4, 8]
            });
            is_cn && country_code.eq_ignore_ascii_case("cn")
        }

        fn load_database(&self, _path: &str) -> Result<()> {
            Ok(())
        }

        fn load_database_from_bytes(&self, _data: Vec<u8>) -> Result<()> {
            Ok(())
        }
    }

    fn mainland_routing_test_router() -> Router {
        let config = Config {
            outbounds: vec![
                OutboundConfig {
                    outbound_type: OutboundType::Direct,
                    tag: "bypass".to_string(),
                    server: None,
                    port: None,
                    options: Default::default(),
                },
                OutboundConfig {
                    outbound_type: OutboundType::Socks5,
                    tag: "proxy".to_string(),
                    server: Some("127.0.0.1".to_string()),
                    port: Some(1080),
                    options: Default::default(),
                },
            ],
            rules: vec![RuleConfig {
                rule_type: RuleType::Match,
                payload: String::new(),
                outbound: "proxy".to_string(),
                process_name: None,
            }],
            ..Config::default()
        };
        let rules = Router::compile_rules(&config.rules).unwrap();

        Router {
            config: Arc::new(RwLock::new(config)),
            rules: RwLock::new(rules),
            defaults: RwLock::new(DefaultOutbounds {
                direct: "bypass".to_string(),
                global: Some("proxy".to_string()),
                default: "proxy".to_string(),
            }),
            geoip_manager: Arc::new(StubCountryMatcher),
            rule_provider_manager: Arc::new(RuleProviderManager::new()),
        }
    }

    /// Same topology as `mainland_routing_test_router` but with an empty rule
    /// list, so the no-rule auto-direct fallback can be exercised.
    fn mainland_routing_test_router_no_rules() -> Router {
        let mut router = mainland_routing_test_router();
        router.rules = RwLock::new(Vec::new());
        router
    }

    #[test]
    fn mainland_cn_domain_follows_rule_when_configured() {
        // With rules configured, the explicit MATCH rule wins over the
        // mainland-China auto-direct shortcut (Clash rule-order semantics).
        let _mode_guard = MODE_LOCK.lock();
        set_runtime_proxy_mode(proxy_mode::RULE);
        let router = mainland_routing_test_router();

        let outbound = router.match_outbound(Some("WWW.EXAMPLE.CN."), None, Some(443), None);

        assert_eq!(outbound, "proxy");
    }

    #[test]
    fn mainland_cn_ip_follows_rule_when_configured() {
        let _mode_guard = MODE_LOCK.lock();
        set_runtime_proxy_mode(proxy_mode::RULE);
        let router = mainland_routing_test_router();

        let outbound = router.match_outbound(
            None,
            Some(IpAddr::V4(Ipv4Addr::new(114, 114, 114, 114))),
            Some(53),
            None,
        );

        assert_eq!(outbound, "proxy");
    }

    #[test]
    fn mainland_cn_domain_auto_direct_without_rules() {
        // No rules configured: the auto-direct fallback still applies.
        let _mode_guard = MODE_LOCK.lock();
        set_runtime_proxy_mode(proxy_mode::RULE);
        let router = mainland_routing_test_router_no_rules();

        let outbound = router.match_outbound(Some("www.example.cn"), None, Some(443), None);

        assert_eq!(outbound, "bypass");
    }

    #[test]
    fn mainland_cn_ip_auto_direct_without_rules() {
        let _mode_guard = MODE_LOCK.lock();
        set_runtime_proxy_mode(proxy_mode::RULE);
        let router = mainland_routing_test_router_no_rules();

        let outbound = router.match_outbound(
            None,
            Some(IpAddr::V4(Ipv4Addr::new(114, 114, 114, 114))),
            Some(53),
            None,
        );

        assert_eq!(outbound, "bypass");
    }

    #[test]
    fn foreign_ip_still_uses_configured_proxy_rule() {
        let _mode_guard = MODE_LOCK.lock();
        set_runtime_proxy_mode(proxy_mode::RULE);
        let router = mainland_routing_test_router();

        let outbound = router.match_outbound(
            None,
            Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            Some(53),
            None,
        );

        assert_eq!(outbound, "proxy");
    }

    /// DIRECT + SOCKS5 + a selector group over both. `resolve_default_outbounds`
    /// picks the selector group as the global outbound, so GLOBAL mode must
    /// send every connection through it.
    fn grouped_routing_test_router() -> Router {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "outbounds".to_string(),
            nextjson::Value::Array(vec![
                nextjson::Value::String("DIRECT".to_string()),
                nextjson::Value::String("socks-node".to_string()),
            ]),
        );

        let config = Config {
            general: crate::engine::config::GeneralConfig {
                mode: Mode::Rule,
                ..crate::engine::config::GeneralConfig::default()
            },
            inbounds: vec![crate::engine::config::InboundConfig {
                inbound_type: crate::engine::config::InboundType::Mixed,
                tag: "mixed-in".to_string(),
                listen: "127.0.0.1".to_string(),
                port: 17896,
                options: Default::default(),
            }],
            outbounds: vec![
                OutboundConfig {
                    outbound_type: OutboundType::Direct,
                    tag: "DIRECT".to_string(),
                    server: None,
                    port: None,
                    options: Default::default(),
                },
                OutboundConfig {
                    outbound_type: OutboundType::Socks5,
                    tag: "socks-node".to_string(),
                    server: Some("127.0.0.1".to_string()),
                    port: Some(1080),
                    options: Default::default(),
                },
                OutboundConfig {
                    outbound_type: OutboundType::Selector,
                    tag: "PROXY".to_string(),
                    server: None,
                    port: None,
                    options,
                },
            ],
            rules: vec![RuleConfig {
                rule_type: RuleType::Match,
                payload: String::new(),
                outbound: "DIRECT".to_string(),
                process_name: None,
            }],
            ..Config::default()
        };
        let rules = Router::compile_rules(&config.rules).unwrap();

        Router {
            config: Arc::new(RwLock::new(config)),
            rules: RwLock::new(rules),
            defaults: RwLock::new(DefaultOutbounds {
                direct: "DIRECT".to_string(),
                global: Some("PROXY".to_string()),
                default: "DIRECT".to_string(),
            }),
            geoip_manager: Arc::new(StubCountryMatcher),
            rule_provider_manager: Arc::new(RuleProviderManager::new()),
        }
    }

    #[test]
    fn global_mode_routes_all_traffic_through_proxy_group() {
        // GLOBAL must send every connection (any domain/IP/port) through the
        // proxy group, regardless of the rule table.
        let _mode_guard = MODE_LOCK.lock();
        set_runtime_proxy_mode(proxy_mode::GLOBAL);
        let router = grouped_routing_test_router();

        for (domain, ip) in [
            (Some("example.com"), None),
            (None, Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))),
            (Some("www.example.cn"), None),
            (None, Some(IpAddr::V4(Ipv4Addr::new(114, 114, 114, 114)))),
            (None, None),
        ] {
            let outbound = router.match_outbound(domain, ip, Some(443), None);
            assert_eq!(
                outbound, "PROXY",
                "GLOBAL must route domain={:?} ip={:?} through the proxy group",
                domain, ip
            );
        }
    }

    #[test]
    fn global_mode_uses_first_proxy_when_no_group() {
        // Without a group, GLOBAL falls back to the first non-direct/reject
        // outbound instead of DIRECT.
        let _mode_guard = MODE_LOCK.lock();
        set_runtime_proxy_mode(proxy_mode::GLOBAL);
        let router = mainland_routing_test_router();

        let outbound = router.match_outbound(Some("example.com"), None, Some(443), None);
        assert_eq!(outbound, "proxy");
    }

    #[test]
    fn direct_mode_routes_all_traffic_to_direct() {
        // DIRECT must route everything (even domains matched by rules) to the
        // direct outbound.
        let _mode_guard = MODE_LOCK.lock();
        set_runtime_proxy_mode(proxy_mode::DIRECT);
        let router = grouped_routing_test_router();

        for (domain, ip) in [
            (Some("example.com"), None),
            (None, Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))),
        ] {
            let outbound = router.match_outbound(domain, ip, Some(443), None);
            assert_eq!(outbound, "DIRECT");
        }
    }

    #[test]
    fn config_mode_follows_general_mode() {
        // Runtime mode 0 (CONFIG) falls back to `general.mode`; here it is
        // Rule, so the rule table decides.
        let _mode_guard = MODE_LOCK.lock();
        set_runtime_proxy_mode(proxy_mode::CONFIG);
        let router = grouped_routing_test_router();

        let outbound = router.match_outbound(Some("example.com"), None, Some(443), None);
        assert_eq!(outbound, "DIRECT");
    }

    #[test]
    fn test_matches_cidr_ipv4() {
        assert!(Router::matches_cidr(
            "192.168.0.0/16",
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
        ));
        assert!(Router::matches_cidr(
            "192.168.0.0/16",
            IpAddr::V4(Ipv4Addr::new(192, 168, 255, 255))
        ));
        assert!(!Router::matches_cidr(
            "192.168.0.0/16",
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        ));
    }

    #[test]
    fn test_matches_cidr_ipv6() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert!(Router::matches_cidr("2001:db8::/32", ip));

        let ip2 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 1));
        assert!(!Router::matches_cidr("2001:db8::/32", ip2));
    }

    #[test]
    fn test_matches_port_range_single() {
        assert!(Router::matches_port_range("80", 80));
        assert!(!Router::matches_port_range("80", 443));
    }

    #[test]
    fn test_matches_port_range_range() {
        assert!(Router::matches_port_range("80-443", 80));
        assert!(Router::matches_port_range("80-443", 200));
        assert!(Router::matches_port_range("80-443", 443));
        assert!(!Router::matches_port_range("80-443", 79));
        assert!(!Router::matches_port_range("80-443", 444));
    }

    #[test]
    fn test_matches_port_range_multiple() {
        assert!(Router::matches_port_range("80,443,8080", 80));
        assert!(Router::matches_port_range("80,443,8080", 443));
        assert!(Router::matches_port_range("80,443,8080", 8080));
        assert!(!Router::matches_port_range("80,443,8080", 8081));
    }

    #[test]
    fn test_matches_port_range_mixed() {
        assert!(Router::matches_port_range("80,443-445,8080", 80));
        assert!(Router::matches_port_range("80,443-445,8080", 444));
        assert!(Router::matches_port_range("80,443-445,8080", 8080));
        assert!(!Router::matches_port_range("80,443-445,8080", 446));
    }

    #[test]
    fn test_matches_process_name_exact() {
        assert!(Router::matches_process_name("chrome", "chrome"));
        assert!(Router::matches_process_name("Chrome", "chrome"));
    }

    #[test]
    fn test_matches_process_name_with_path() {
        assert!(Router::matches_process_name("chrome", "/usr/bin/chrome"));
        assert!(Router::matches_process_name(
            "chrome",
            "C:\\Program Files\\chrome"
        ));
    }

    #[test]
    fn test_matches_process_name_with_exe() {
        assert!(Router::matches_process_name("chrome.exe", "chrome"));
        assert!(Router::matches_process_name("chrome", "chrome.exe"));
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn arb_ipv4() -> impl Strategy<Value = Ipv4Addr> {
        (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>())
            .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d))
    }

    #[allow(dead_code)]
    fn arb_ipv6() -> impl Strategy<Value = Ipv6Addr> {
        (
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
        )
            .prop_map(|(a, b, c, d, e, f, g, h)| Ipv6Addr::new(a, b, c, d, e, f, g, h))
    }

    fn arb_domain() -> impl Strategy<Value = String> {
        "[a-z]{1,10}(\\.[a-z]{2,5}){1,3}"
    }

    fn arb_port() -> impl Strategy<Value = u16> {
        1u16..=65535u16
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_domain_exact_match_is_case_insensitive(
            domain in arb_domain()
        ) {
            let lower = domain.to_lowercase();
            let upper = domain.to_uppercase();

            let rule = CompiledRule {
                rule_type: RuleType::Domain,
                pattern: lower.clone(),
                outbound: "proxy".to_string(),
                process_name: None,
                regex: None,
                ipnet: None,
                port_ranges: Vec::new(),
            };

            let router = Router {
                config: std::sync::Arc::new(RwLock::new(Config::default())),
                rules: RwLock::new(vec![rule]),
                defaults: RwLock::new(DefaultOutbounds {
                    direct: "proxy".to_string(),
                    global: None,
                    default: "proxy".to_string(),
                }),
                geoip_manager: Arc::new(GeoIpManager::new()),
                rule_provider_manager: Arc::new(RuleProviderManager::new()),
            };

            let matches_lower = router.matches_rule(
                &router.rules.read()[0],
                Some(&lower),
                None,
                None,
                None,
            );
            let matches_upper = router.matches_rule(
                &router.rules.read()[0],
                Some(&upper),
                None,
                None,
                None,
            );

            prop_assert!(matches_lower);
            prop_assert!(matches_upper);
        }

        #[test]
        fn prop_domain_suffix_matches_subdomain(
            base_domain in "[a-z]{3,8}\\.[a-z]{2,4}",
            subdomain in "[a-z]{1,5}"
        ) {
            let full_domain = format!("{}.{}", subdomain, base_domain);

            let rule = CompiledRule {
                rule_type: RuleType::DomainSuffix,
                pattern: base_domain.clone(),
                outbound: "proxy".to_string(),
                process_name: None,
                regex: None,
                ipnet: None,
                port_ranges: Vec::new(),
            };

            let router = Router {
                config: std::sync::Arc::new(RwLock::new(Config::default())),
                rules: RwLock::new(vec![rule]),
                defaults: RwLock::new(DefaultOutbounds {
                    direct: "proxy".to_string(),
                    global: None,
                    default: "proxy".to_string(),
                }),
                geoip_manager: Arc::new(GeoIpManager::new()),
                rule_provider_manager: Arc::new(RuleProviderManager::new()),
            };

            let matches = router.matches_rule(
                &router.rules.read()[0],
                Some(&full_domain),
                None,
                None,
                None,
            );

            prop_assert!(matches, "Domain suffix {} should match {}", base_domain, full_domain);
        }

        #[test]
        fn prop_domain_keyword_matches_containing_domain(
            keyword in "[a-z]{3,6}",
            prefix in "[a-z]{0,3}",
            suffix in "[a-z]{0,3}\\.[a-z]{2,4}"
        ) {
            let domain = format!("{}{}{}", prefix, keyword, suffix);

            let rule = CompiledRule {
                rule_type: RuleType::DomainKeyword,
                pattern: keyword.clone(),
                outbound: "proxy".to_string(),
                process_name: None,
                regex: None,
                ipnet: None,
                port_ranges: Vec::new(),
            };

            let router = Router {
                config: std::sync::Arc::new(RwLock::new(Config::default())),
                rules: RwLock::new(vec![rule]),
                defaults: RwLock::new(DefaultOutbounds {
                    direct: "proxy".to_string(),
                    global: None,
                    default: "proxy".to_string(),
                }),
                geoip_manager: Arc::new(GeoIpManager::new()),
                rule_provider_manager: Arc::new(RuleProviderManager::new()),
            };

            let matches = router.matches_rule(
                &router.rules.read()[0],
                Some(&domain),
                None,
                None,
                None,
            );

            prop_assert!(matches, "Keyword {} should match domain {}", keyword, domain);
        }

        #[test]
        fn prop_ip_cidr_contains_network_ips(
            base_ip in arb_ipv4(),
            prefix_len in 16u8..=30u8,
            offset in 0u32..256u32
        ) {
            let base_octets = base_ip.octets();
            let base_u32 = u32::from_be_bytes(base_octets);

            let mask = !((1u32 << (32 - prefix_len)) - 1);
            let network_base = base_u32 & mask;

            let network_size = 1u32 << (32 - prefix_len);
            let test_offset = offset % network_size;
            let test_ip_u32 = network_base.wrapping_add(test_offset);
            let test_ip = Ipv4Addr::from(test_ip_u32);

            let network_ip = Ipv4Addr::from(network_base);
            let cidr = format!("{}/{}", network_ip, prefix_len);

            let matches = Router::matches_cidr(&cidr, IpAddr::V4(test_ip));
            prop_assert!(matches, "IP {} should be in CIDR {}", test_ip, cidr);
        }

        #[test]
        fn prop_port_in_range_matches(
            start in 1u16..32000u16,
            range_size in 1u16..1000u16
        ) {
            let end = start.saturating_add(range_size);
            let pattern = format!("{}-{}", start, end);

            for port in start..=end.min(start + 10) {
                prop_assert!(
                    Router::matches_port_range(&pattern, port),
                    "Port {} should match range {}", port, pattern
                );
            }
        }

        #[test]
        fn prop_port_outside_range_does_not_match(
            start in 100u16..32000u16,
            range_size in 10u16..1000u16
        ) {
            let end = start.saturating_add(range_size).min(65534);
            let pattern = format!("{}-{}", start, end);

            if start > 1 {
                prop_assert!(
                    !Router::matches_port_range(&pattern, start - 1),
                    "Port {} should not match range {}", start - 1, pattern
                );
            }

            if end < 65535 {
                prop_assert!(
                    !Router::matches_port_range(&pattern, end + 1),
                    "Port {} should not match range {}", end + 1, pattern
                );
            }
        }

        #[test]
        fn prop_match_rule_always_matches(
            domain in proptest::option::of(arb_domain()),
            ip in proptest::option::of(arb_ipv4().prop_map(IpAddr::V4)),
            port in proptest::option::of(arb_port())
        ) {
            let rule = CompiledRule {
                rule_type: RuleType::Match,
                pattern: String::new(),
                outbound: "proxy".to_string(),
                process_name: None,
                regex: None,
                ipnet: None,
                port_ranges: Vec::new(),
            };

            let router = Router {
                config: std::sync::Arc::new(RwLock::new(Config::default())),
                rules: RwLock::new(vec![rule]),
                defaults: RwLock::new(DefaultOutbounds {
                    direct: "proxy".to_string(),
                    global: None,
                    default: "proxy".to_string(),
                }),
                geoip_manager: Arc::new(GeoIpManager::new()),
                rule_provider_manager: Arc::new(RuleProviderManager::new()),
            };

            let matches = router.matches_rule(
                &router.rules.read()[0],
                domain.as_deref(),
                ip,
                port,
                None,
            );

            prop_assert!(matches, "MATCH rule should always match");
        }

        #[test]
        fn prop_rules_match_in_priority_order(
            domain in "[a-z]{5,10}\\.[a-z]{2,4}"
        ) {
            // This test is about rule priority only. Clear the process-global
            // rule-provider staging so `Router::new` never touches the network
            // (other tests may have staged a real HTTP provider), and pin the
            // runtime mode to CONFIG under the mode lock so parallel mode
            // tests cannot interleave a different mode.
            let _mode_guard = tests::MODE_LOCK.lock();
            set_runtime_proxy_mode(proxy_mode::CONFIG);

            let rules = vec![
                RuleConfig {
                    rule_type: RuleType::Domain,
                    payload: domain.clone(),
                    outbound: "first".to_string(),
                    process_name: None,
                },
                RuleConfig {
                    rule_type: RuleType::DomainSuffix,
                    payload: domain.split('.').next_back().unwrap_or("com").to_string(),
                    outbound: "second".to_string(),
                    process_name: None,
                },
                RuleConfig {
                    rule_type: RuleType::Match,
                    payload: String::new(),
                    outbound: "fallback".to_string(),
                    process_name: None,
                },
            ];

            let config = Config {
                rules: rules.clone(),
                outbounds: vec![
                    crate::engine::config::OutboundConfig {
                        outbound_type: crate::engine::config::OutboundType::Direct,
                        tag: "first".to_string(),
                        server: None,
                        port: None,
                        options: std::collections::HashMap::new(),
                    },
                ],
                ..Default::default()
            };

            let router = Router::new(std::sync::Arc::new(RwLock::new(config))).unwrap();
            let result = router.match_outbound(Some(&domain), None, None, None);

            prop_assert_eq!(result, "first", "First matching rule should be used");
        }
    }
}
