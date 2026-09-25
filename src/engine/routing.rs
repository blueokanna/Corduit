use crate::common::lru::LruCache;
use crate::engine::config::{Config, Mode, RuleConfig, RuleType};
use crate::engine::error::{Error, Result};
use crate::engine::geoip::{is_non_routable, CountryMatcher, GeoIpManager};
use crate::engine::rule_provider::RuleProviderConfig;
use crate::engine::rule_provider::RuleProviderManager;
use ipnet::IpNet;
use parking_lot::{Mutex, RwLock};
use regex::{Regex, RegexBuilder};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
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

/// Nesting limit for `and` / `or` / `not` rules. A cycle is impossible in a
/// tree, but a deeply nested config would otherwise recurse until the stack
/// gives out during compilation.
const MAX_RULE_DEPTH: usize = 8;

/// Transport a connection uses.
///
/// Spelled `tcp` / `udp` in a `network` rule payload, matching the vocabulary
/// the profiles this engine consumes are written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Network {
    /// Stream transport.
    #[default]
    Tcp,
    /// Datagram transport.
    Udp,
}

impl Network {
    fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            other => Err(Error::config(format!(
                "Invalid network '{other}': expected 'tcp' or 'udp'"
            ))),
        }
    }
}

/// Everything a rule may inspect about one connection attempt.
///
/// A struct rather than a parameter list on purpose. While the inputs were
/// positional `Option`s a call site could not tell a source port from a
/// destination port, and `src-port` and `dst-port` were both fed the
/// destination port as a result.
#[derive(Debug, Clone, Copy, Default)]
pub struct RouteRequest<'a> {
    /// Destination hostname, when the client supplied one.
    pub domain: Option<&'a str>,
    /// Destination address, when the client already knows it.
    pub dst_ip: Option<IpAddr>,
    /// Destination port.
    pub dst_port: Option<u16>,
    /// Address the connection originates from.
    pub src_ip: Option<IpAddr>,
    /// Port the connection originates from.
    pub src_port: Option<u16>,
    /// Transport in use.
    pub network: Network,
    /// Executable name owning the connection, when it is resolvable.
    pub process_name: Option<&'a str>,
    /// Full executable path, when it is resolvable.
    pub process_path: Option<&'a str>,
}

/// What one routing decision decided, and how long it took.
#[derive(Debug, Clone)]
pub struct RouteDecision {
    /// Outbound tag the request was routed to.
    pub outbound: String,
    /// Position in the configured rule list of the rule that decided it.
    /// `None` when a routing mode short-circuited the list, or when no rule
    /// matched and the default outbound was used.
    pub rule_index: Option<usize>,
    /// Type of the rule that decided it, when a rule did.
    pub rule_type: Option<RuleType>,
    /// Wall-clock time the decision took.
    pub elapsed: Duration,
}

#[derive(Debug)]
struct CompiledRule {
    rule_type: RuleType,
    /// Canonical pattern. Domain and process patterns are lowercased once at
    /// compile time so matching never allocates or re-parses.
    pattern: String,
    outbound: String,
    regex: Option<Regex>,
    /// Pre-parsed CIDR for `IpCidr` / `SrcIpCidr` rules.
    ipnet: Option<IpNet>,
    /// Pre-parsed inclusive port ranges for `SrcPort` / `DstPort` rules.
    port_ranges: Vec<(u16, u16)>,
    /// Required transport for a `Network` rule.
    network: Option<Network>,
    /// `no-resolve`: never compare against an address the router resolved.
    no_resolve: bool,
    /// Children of `and` / `or` / `not`.
    children: Vec<CompiledRule>,
    /// Connections this rule has decided since it was compiled.
    hits: AtomicU64,
}

impl CompiledRule {
    /// Whether this rule, or a nested one, can only be decided once the
    /// destination address is known.
    ///
    /// The router resolves a domain at most once per request, and only when
    /// this returns `true` somewhere in the rule list — a configuration whose
    /// IP rules are all `no-resolve` never pays for a lookup.
    fn wants_dst_ip(&self) -> bool {
        if self.no_resolve {
            return false;
        }
        match self.rule_type {
            RuleType::IpCidr | RuleType::Geoip => true,
            // A rule set may hold IP entries, but only the provider knows
            // whether it does, and asking it means doing the lookup this
            // predicate exists to avoid. Resolving on the chance that some set
            // contains IP rules would put a system DNS query on every request
            // of every domain-only config, so it stays off: rule-set entries are
            // compared against an address the client actually supplied.
            RuleType::RuleSet | RuleType::Geosite => false,
            // `not` inverts its child, so the child still drives the need.
            RuleType::And | RuleType::Or | RuleType::Not => {
                self.children.iter().any(Self::wants_dst_ip)
            }
            _ => false,
        }
    }

    fn matches_port(&self, port: u16) -> bool {
        self.port_ranges
            .iter()
            .any(|(start, end)| port >= *start && port <= *end)
    }

    /// A rule with every optional field empty, for tests that only care about
    /// the type and the pattern.
    #[cfg(test)]
    fn blank() -> Self {
        Self {
            rule_type: RuleType::Match,
            pattern: String::new(),
            outbound: String::new(),
            regex: None,
            ipnet: None,
            port_ranges: Vec::new(),
            network: None,
            no_resolve: false,
            children: Vec::new(),
            hits: AtomicU64::new(0),
        }
    }
}

/// The inputs a compiled rule is evaluated against.
struct MatchContext<'a> {
    domain: Option<&'a str>,
    dst_ip: Option<IpAddr>,
    /// Addresses the destination domain resolved to. Empty when the request
    /// carried a literal address or when no rule needed a lookup.
    resolved: &'a [IpAddr],
    dst_port: Option<u16>,
    src_ip: Option<IpAddr>,
    src_port: Option<u16>,
    network: Network,
    process_name: Option<&'a str>,
    process_path: Option<&'a str>,
}

impl MatchContext<'_> {
    /// The subset of this context that a rule set matches against.
    fn rule_input(&self) -> crate::engine::rule_provider::RuleMatchInput<'_> {
        crate::engine::rule_provider::RuleMatchInput {
            domain: self.domain,
            dst_ip: self.dst_ip,
            src_ip: self.src_ip,
            process_name: self.process_name,
        }
    }

    /// Addresses an `ip-cidr` / `geoip` rule may compare against.
    ///
    /// A literal destination address always counts; an address the router had
    /// to resolve only counts when the rule did not ask for `no-resolve`.
    fn dst_candidates(&self, no_resolve: bool) -> impl Iterator<Item = IpAddr> + '_ {
        let resolved: &[IpAddr] = if no_resolve { &[] } else { self.resolved };
        self.dst_ip.into_iter().chain(resolved.iter().copied())
    }
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
            .filter(|rule| matches!(rule.rule_type, RuleType::RuleSet | RuleType::Geosite))
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

    /// Decide which outbound serves one connection attempt.
    pub fn route(&self, request: &RouteRequest<'_>) -> RouteDecision {
        let started = Instant::now();
        let (outbound, rule_index, rule_type) = self.decide(request);
        RouteDecision {
            outbound,
            rule_index,
            rule_type,
            elapsed: started.elapsed(),
        }
    }

    /// Decide the outbound tag for one connection attempt.
    ///
    /// Convenience wrapper over [`Router::route`] for callers that only know a
    /// destination. It carries no source address, no transport and no process
    /// information, so rules that need those cannot match.
    pub fn match_outbound(
        &self,
        domain: Option<&str>,
        ip: Option<IpAddr>,
        port: Option<u16>,
        process_name: Option<&str>,
    ) -> String {
        self.route(&RouteRequest {
            domain,
            dst_ip: ip,
            dst_port: port,
            process_name,
            ..RouteRequest::default()
        })
        .outbound
    }

    /// Hit counts per configured rule, in configuration order.
    ///
    /// Read-only view for diagnostics: it answers "is this rule ever reached,
    /// and which rules carry the traffic" without re-reading the config.
    pub fn rule_hits(&self) -> Vec<u64> {
        self.rules
            .read()
            .iter()
            .map(|rule| rule.hits.load(Ordering::Relaxed))
            .collect()
    }

    fn decide(&self, request: &RouteRequest<'_>) -> (String, Option<usize>, Option<RuleType>) {
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
            "Routing request: domain={:?}, dst={:?}:{:?}, src={:?}:{:?}, network={:?}, mode={:?}",
            request.domain,
            request.dst_ip,
            request.dst_port,
            request.src_ip,
            request.src_port,
            request.network,
            effective_mode
        );

        if matches!(effective_mode, Mode::Global) {
            if let Some(outbound) = global_outbound {
                tracing::info!("Global mode: routing to proxy outbound '{}'", outbound);
                return (outbound, None, None);
            }
            return (direct_outbound, None, None);
        }

        if matches!(effective_mode, Mode::Direct) {
            tracing::debug!("Direct mode: routing to '{}'", direct_outbound);
            return (direct_outbound, None, None);
        }

        let rules = self.rules.read();

        // Resolve the destination domain at most once per request, and only
        // when a rule that is allowed to see a resolved address could use one.
        // A literal address needs no lookup, and a config whose IP rules are
        // all `no-resolve` never triggers one.
        let resolved: Vec<IpAddr> = match request.dst_ip {
            Some(address) => vec![address],
            None => {
                let resolution_is_useful =
                    rules.is_empty() || rules.iter().any(CompiledRule::wants_dst_ip);
                if resolution_is_useful {
                    Self::resolve_destination_ips(request.domain, None)
                } else {
                    Vec::new()
                }
            }
        };

        let context = MatchContext {
            domain: request.domain,
            dst_ip: request.dst_ip,
            resolved: &resolved,
            dst_port: request.dst_port,
            src_ip: request.src_ip,
            src_port: request.src_port,
            network: request.network,
            process_name: request.process_name,
            process_path: request.process_path,
        };

        // The mainland-China auto-direct shortcut is a fallback for configs
        // with no rules at all. Once rules are configured they are evaluated
        // strictly in order and the first match wins, so an explicit rule always
        // wins over the shortcut.
        if rules.is_empty() {
            if Self::is_mainland_china_domain(request.domain) {
                tracing::info!(
                    "Mainland China domain identified: domain={:?} -> '{}'",
                    request.domain,
                    direct_outbound
                );
                return (direct_outbound, None, None);
            }

            if self.is_mainland_china_ip(&resolved) {
                tracing::info!(
                    "Mainland China destination identified: domain={:?}, ips={:?} -> '{}'",
                    request.domain,
                    resolved,
                    direct_outbound
                );
                return (direct_outbound, None, None);
            }
        }

        for (index, rule) in rules.iter().enumerate() {
            if self.matches_rule_with(rule, &context) {
                rule.hits.fetch_add(1, Ordering::Relaxed);
                tracing::info!(
                    "Rule matched: #{} {:?} '{}' -> '{}'",
                    index,
                    rule.rule_type,
                    rule.pattern,
                    rule.outbound
                );
                return (rule.outbound.clone(), Some(index), Some(rule.rule_type));
            }
        }

        tracing::debug!(
            "No rule matched, using default outbound: {}",
            default_outbound
        );
        (default_outbound, None, None)
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
            if is_non_routable(*address) || self.geoip_manager.matches_country("CN", *address) {
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

        // The engine's own DNS answers first, then the system resolver, with the
        // lookup bounded by `DNS_LOOKUP_TIMEOUT` either way (see
        // `socket::resolve_host_all`). Resolution errors degrade to
        // domain-rule-only matching.
        let addresses =
            match crate::common::socket::resolve_host_all(&normalized, DNS_LOOKUP_TIMEOUT) {
                Ok(resolved) => resolved,
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

    /// Compile the configured rules into the form the hot path matches against.
    ///
    /// Everything decidable from the payload alone is decided here — regexes,
    /// CIDRs, port ranges, transports — and every nesting level is walked, so an
    /// unusable rule fails at load time instead of on the first connection that
    /// happens to reach it.
    fn compile_rules(rules: &[RuleConfig]) -> Result<Vec<CompiledRule>> {
        let mut compiled = Vec::with_capacity(rules.len());
        for rule in rules {
            compiled.push(Self::compile_rule(rule, 0)?);
        }
        Ok(compiled)
    }

    /// Decode and compile one level of nested rules.
    ///
    /// Children arrive as untyped values because `RuleConfig` cannot hold a
    /// `Vec<RuleConfig>` — see the field's own note. Decoding each level on the
    /// way in keeps nesting depth unbounded.
    fn compile_nested_rules(rules: &[nextjson::Value], depth: usize) -> Result<Vec<CompiledRule>> {
        if depth > MAX_RULE_DEPTH {
            return Err(Error::config(format!(
                "Routing rules nest deeper than {MAX_RULE_DEPTH} levels"
            )));
        }

        let mut compiled = Vec::with_capacity(rules.len());
        for value in rules {
            let rule: RuleConfig = nextjson::from_value(value.clone())
                .map_err(|error| Error::config(format!("Invalid nested routing rule: {error}")))?;
            compiled.push(Self::compile_rule(&rule, depth)?);
        }
        Ok(compiled)
    }

    fn compile_rule(rule: &RuleConfig, depth: usize) -> Result<CompiledRule> {
        let rule_type = rule.rule_type;
        let outbound = rule.outbound.as_str();

        let children = if matches!(rule_type, RuleType::And | RuleType::Or | RuleType::Not) {
            let children = Self::compile_nested_rules(&rule.rules, depth + 1)?;
            match rule_type {
                // A combinator with nothing to combine either always matches
                // or never matches depending on the operator. Both are config
                // mistakes, so refuse instead of guessing which one was meant.
                RuleType::And | RuleType::Or if children.is_empty() => {
                    return Err(Error::config(format!(
                        "{rule_type:?} rule for '{outbound}' has no child rules"
                    )));
                }
                RuleType::Not if children.len() != 1 => {
                    return Err(Error::config(format!(
                        "not rule for '{outbound}' takes exactly one child rule, got {}",
                        children.len()
                    )));
                }
                _ => {}
            }
            children
        } else {
            Vec::new()
        };

        // `match` is the catch-all and the combinators carry their condition in
        // their children, so an empty payload is only wrong anywhere else.
        if !matches!(
            rule_type,
            RuleType::And | RuleType::Or | RuleType::Not | RuleType::Match
        ) && rule.payload.trim().is_empty()
        {
            return Err(Error::config(format!(
                "{rule_type:?} rule for '{outbound}' has an empty payload"
            )));
        }

        let regex = if rule_type == RuleType::DomainRegex {
            // Case-insensitive, because a DNS name is (RFC 1035 §2.3.3) and
            // every sibling rule type here already is: their patterns are
            // lowercased at compile time and their comparisons ignore case. A
            // case-sensitive regex was the one hole in that, and it is the kind
            // that fails silently — `domain-regex:"^ad\."` would miss
            // `Host: AD.example.com`, and the rule would look like it worked.
            //
            // A pattern that genuinely needs case sensitivity can still ask for
            // it with an inline `(?-i)`.
            Some(
                RegexBuilder::new(&rule.payload)
                    .case_insensitive(true)
                    .build()
                    .map_err(|e| Error::config(format!("Invalid regex pattern: {}", e)))?,
            )
        } else {
            None
        };

        // Pre-parse CIDRs and port ranges so hot-path matching never re-parses
        // strings, and so an unusable payload is reported at load time.
        let ipnet =
            if matches!(rule_type, RuleType::IpCidr | RuleType::SrcIpCidr) {
                Some(rule.payload.trim().parse::<IpNet>().map_err(|e| {
                    Error::config(format!("Invalid CIDR '{}': {}", rule.payload, e))
                })?)
            } else {
                None
            };
        let port_ranges = if matches!(rule_type, RuleType::SrcPort | RuleType::DstPort) {
            Self::compile_port_ranges(&rule.payload)?
        } else {
            Vec::new()
        };
        let network = if rule_type == RuleType::Network {
            Some(Network::parse(&rule.payload)?)
        } else {
            None
        };

        // Lowercase domain and process patterns once; matching then compares
        // case-insensitively with zero allocations.
        let pattern = if matches!(
            rule_type,
            RuleType::Domain
                | RuleType::DomainSuffix
                | RuleType::DomainKeyword
                | RuleType::ProcessName
                | RuleType::ProcessPath
        ) {
            rule.payload.trim().to_ascii_lowercase()
        } else {
            rule.payload.clone()
        };

        Ok(CompiledRule {
            rule_type,
            pattern,
            outbound: rule.outbound.clone(),
            regex,
            ipnet,
            port_ranges,
            network,
            no_resolve: rule.no_resolve,
            children,
            hits: AtomicU64::new(0),
        })
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

    fn matches_rule_with(&self, rule: &CompiledRule, context: &MatchContext<'_>) -> bool {
        match rule.rule_type {
            RuleType::Domain => context
                .domain
                .is_some_and(|d| d.trim_end_matches('.').eq_ignore_ascii_case(&rule.pattern)),
            RuleType::DomainSuffix => context
                .domain
                .is_some_and(|d| Self::matches_domain_suffix(d, &rule.pattern)),
            RuleType::DomainKeyword => context
                .domain
                .is_some_and(|d| contains_ignore_case(d, &rule.pattern)),
            RuleType::DomainRegex => match (context.domain, rule.regex.as_ref()) {
                (Some(domain), Some(regex)) => regex.is_match(domain),
                _ => false,
            },
            RuleType::IpCidr => match rule.ipnet {
                Some(network) => context
                    .dst_candidates(rule.no_resolve)
                    .any(|address| network.contains(&address)),
                None => false,
            },
            RuleType::Geoip => context
                .dst_candidates(rule.no_resolve)
                .any(|address| self.geoip_manager.matches_country(&rule.pattern, address)),
            // The source address is the peer address of the inbound
            // connection; it is never something the router resolved.
            RuleType::SrcIpCidr => match (rule.ipnet, context.src_ip) {
                (Some(network), Some(address)) => network.contains(&address),
                _ => false,
            },
            RuleType::DstPort => context.dst_port.is_some_and(|port| rule.matches_port(port)),
            RuleType::SrcPort => context.src_port.is_some_and(|port| rule.matches_port(port)),
            RuleType::ProcessName => context
                .process_name
                .is_some_and(|process| Self::matches_process_name(&rule.pattern, process)),
            RuleType::ProcessPath => context
                .process_path
                .is_some_and(|path| Self::matches_process_path(&rule.pattern, path)),
            RuleType::Network => rule.network == Some(context.network),
            RuleType::RuleSet | RuleType::Geosite => {
                // The provider sees the addresses the client actually supplied.
                // Handing it a resolved one would make the outcome depend on
                // whether some unrelated rule elsewhere in the list happened to
                // request a lookup.
                self.rule_provider_manager
                    .matches(&rule.pattern, &context.rule_input())
            }
            RuleType::And => rule
                .children
                .iter()
                .all(|child| self.matches_rule_with(child, context)),
            RuleType::Or => rule
                .children
                .iter()
                .any(|child| self.matches_rule_with(child, context)),
            // `not` negates the match of its single child.
            RuleType::Not => !rule
                .children
                .iter()
                .any(|child| self.matches_rule_with(child, context)),
            RuleType::Match => true,
        }
    }

    /// Positional adapter for the table and property tests.
    ///
    /// Production callers go through [`Router::route`], which builds a full
    /// [`MatchContext`]. This keeps those tests readable without giving the hot
    /// path a second signature it does not need.
    #[cfg(test)]
    fn matches_rule(
        &self,
        rule: &CompiledRule,
        domain: Option<&str>,
        ip: Option<IpAddr>,
        port: Option<u16>,
        process_name: Option<&str>,
    ) -> bool {
        self.matches_rule_with(
            rule,
            &MatchContext {
                domain,
                dst_ip: ip,
                resolved: &[],
                dst_port: port,
                src_ip: None,
                src_port: None,
                network: Network::Tcp,
                process_name,
                process_path: None,
            },
        )
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

    /// Match a process name against a lowercased pattern.
    ///
    /// Nothing here allocates, and nothing lowercases the process name. The
    /// pattern was lowercased when the rule was compiled, so every comparison is
    /// an ASCII-case-insensitive one against it — the same answer
    /// `process_name.to_ascii_lowercase() == pattern` gives, without building
    /// that string once per process rule per request.
    fn matches_process_name(pattern: &str, process_name: &str) -> bool {
        if process_name.eq_ignore_ascii_case(pattern) {
            return true;
        }

        // A rule means the executable, not the path it was launched from.
        let basename = basename_of(process_name);
        if basename.eq_ignore_ascii_case(pattern) {
            return true;
        }

        // A rule may name the Windows executable with or without its extension,
        // and either side may carry it.
        if let Some(without_ext) = strip_suffix_ignore_case(pattern, ".exe") {
            if process_name.eq_ignore_ascii_case(without_ext)
                || basename.eq_ignore_ascii_case(without_ext)
            {
                return true;
            }
        }
        if let Some(without_ext) = strip_suffix_ignore_case(process_name, ".exe") {
            if without_ext.eq_ignore_ascii_case(pattern) {
                return true;
            }
        }

        false
    }

    /// Match a process path against a lowercased pattern.
    ///
    /// A `process-path` rule pins the executable itself rather than its file
    /// name, so the comparison is an exact, ASCII-case-insensitive match on the
    /// whole path — the same meaning sing-box gives `process_path`.
    fn matches_process_path(pattern: &str, process_path: &str) -> bool {
        let path = process_path.trim();
        !path.is_empty() && !pattern.is_empty() && path.eq_ignore_ascii_case(pattern)
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

/// The part of a path after its last separator.
///
/// A path with no separator is its own basename, which is what a bare process
/// name is.
fn basename_of(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// `text` without a trailing `suffix`, compared without case.
///
/// `None` when it does not end that way — and the byte check is also what keeps
/// the slice on a character boundary, since a non-ASCII tail cannot compare
/// equal to an ASCII suffix anyway.
fn strip_suffix_ignore_case<'a>(text: &'a str, suffix: &str) -> Option<&'a str> {
    let cut = text.len().checked_sub(suffix.len())?;
    if text.is_char_boundary(cut) && text[cut..].eq_ignore_ascii_case(suffix) {
        Some(&text[..cut])
    } else {
        None
    }
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
                ..RuleConfig::default()
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
        // mainland-China auto-direct shortcut: first match in order.
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
                ..RuleConfig::default()
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

    /// The allocation-free comparison must answer exactly what lowering the
    /// process name answered.
    ///
    /// A differential test against the implementation it replaced, because "the
    /// same answer without the allocation" is a claim about *all* inputs and
    /// hand-picked examples only check the ones someone thought of. The pairs
    /// below include the non-ASCII ones, where `to_ascii_lowercase` leaves the
    /// bytes alone and a comparison that folds more than ASCII would quietly
    /// diverge.
    #[test]
    fn process_name_matching_agrees_with_lowercasing() {
        const NAMES: &[&str] = &[
            "",
            "chrome",
            "Chrome",
            "CHROME",
            "chrome.exe",
            "CHROME.EXE",
            "Chrome.Exe",
            "/usr/bin/chrome",
            "/USR/BIN/Chrome",
            "C:\\Program Files\\Chrome.EXE",
            "C:\\Program Files\\chrome",
            "chrome.pif",
            "café",
            "CAFÉ",
            "CAFÉ.EXE",
            "a/b/c",
            "///",
        ];

        // The rule the old body implemented, written out verbatim.
        fn by_lowercasing(pattern: &str, name: &str) -> bool {
            let process_lower = name.to_ascii_lowercase();
            if process_lower == pattern {
                return true;
            }
            if let Some(base) = name.rsplit(['/', '\\']).next() {
                if base.eq_ignore_ascii_case(pattern) {
                    return true;
                }
            }
            if let Some(without_ext) = pattern.strip_suffix(".exe") {
                if process_lower == without_ext {
                    return true;
                }
                if let Some(base) = name.rsplit(['/', '\\']).next() {
                    if base.eq_ignore_ascii_case(without_ext) {
                        return true;
                    }
                }
            }
            if let Some(without_ext) = process_lower.strip_suffix(".exe") {
                if without_ext == pattern {
                    return true;
                }
            }
            false
        }

        for raw_pattern in NAMES {
            // Rules are lowercased when they are compiled, so that is the
            // pattern the matcher actually receives.
            let pattern = raw_pattern.to_ascii_lowercase();
            for name in NAMES {
                assert_eq!(
                    Router::matches_process_name(&pattern, name),
                    by_lowercasing(&pattern, name),
                    "pattern {raw_pattern:?} (as {pattern:?}) against {name:?}"
                );
            }
        }
    }

    /// `domain-regex` is case-insensitive, like every other domain rule.
    ///
    /// A DNS name is case-insensitive (RFC 1035 §2.3.3), so a rule that matched
    /// `ad.example.com` but not `AD.example.com` was the one kind of domain rule
    /// that silently does nothing when the client spells the same name
    /// differently.
    #[test]
    fn domain_regex_matches_regardless_of_case() {
        fn compile(payload: &str) -> CompiledRule {
            let config = Config {
                rules: vec![RuleConfig {
                    rule_type: RuleType::DomainRegex,
                    payload: payload.to_string(),
                    outbound: "proxy".to_string(),
                    process_name: None,
                    ..RuleConfig::default()
                }],
                ..Config::default()
            };
            Router::compile_rules(&config.rules)
                .expect("a valid regex rule")
                .into_iter()
                .next()
                .expect("one compiled rule")
        }

        let rule = compile(r"^ad\.");
        let regex = rule.regex.as_ref().expect("a compiled regex");
        assert!(regex.is_match("ad.example.com"));
        assert!(regex.is_match("AD.example.com"));
        assert!(regex.is_match("Ad.Example.COM"));
        // The pattern still decides what matches; only its case is relaxed.
        assert!(!regex.is_match("ads.example.com"));

        // A pattern that genuinely needs case sensitivity can ask for it.
        let strict = compile(r"(?-i)^AD\.");
        let strict = strict.regex.as_ref().expect("a compiled regex");
        assert!(strict.is_match("AD.example.com"));
        assert!(!strict.is_match("ad.example.com"));
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
                regex: None,
                ipnet: None,
                port_ranges: Vec::new(),
                ..CompiledRule::blank()
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
                regex: None,
                ipnet: None,
                port_ranges: Vec::new(),
                ..CompiledRule::blank()
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
                regex: None,
                ipnet: None,
                port_ranges: Vec::new(),
                ..CompiledRule::blank()
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
                regex: None,
                ipnet: None,
                port_ranges: Vec::new(),
                ..CompiledRule::blank()
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
                    ..RuleConfig::default()
                },
                RuleConfig {
                    rule_type: RuleType::DomainSuffix,
                    payload: domain.split('.').next_back().unwrap_or("com").to_string(),
                    outbound: "second".to_string(),
                    process_name: None,
                    ..RuleConfig::default()
                },
                RuleConfig {
                    rule_type: RuleType::Match,
                    payload: String::new(),
                    outbound: "fallback".to_string(),
                    process_name: None,
                    ..RuleConfig::default()
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
